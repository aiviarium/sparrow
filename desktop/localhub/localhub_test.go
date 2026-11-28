package localhub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/adminiface"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/hub"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/transport/webtransport"
	"github.com/aiviarium/sparrow/go/web"
	"github.com/aiviarium/sparrow/go/websign"
	"github.com/aiviarium/sparrow/go/wire"
)

func TestLocalHubWebTransportAndLocalService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	inst, err := Start(ctx, Config{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer inst.Close()

	// 1. /sparrow/connect requires bearer token and returns WebTransport + WebSocket + certHash.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, inst.Info.BaseURL+"/sparrow/connect", bytes.NewReader([]byte(`{"client":{"hostApi":"3.2.0"}}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+inst.Info.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("/sparrow/connect: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/sparrow/connect status %d: %s", resp.StatusCode, body)
	}
	var connResp struct {
		Ticket    string `json:"ticket"`
		Endpoints struct {
			WebTransport string `json:"webtransport"`
			WebSocket    string `json:"websocket"`
		} `json:"endpoints"`
		ServerCertificateHashes []string `json:"serverCertificateHashes"`
	}
	if err := json.Unmarshal(body, &connResp); err != nil {
		t.Fatalf("decode connect: %v", err)
	}
	if connResp.Ticket == "" || connResp.Endpoints.WebTransport == "" || connResp.Endpoints.WebSocket == "" || len(connResp.ServerCertificateHashes) != 1 {
		t.Fatalf("incomplete connect response: %+v", connResp)
	}

	// 2. Attach an in-process local service with custom annotations.
	fb := nd.NewFacet("desktop", "1.0.0")
	fb.Service("Desktop").Method("ping", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return "local:" + in.(string), nil
	})
	f := fb.MustBuild()
	f.Def.Annotations["app.locality"] = cbor.AppendText(nil, "local")
	if _, err := inst.AttachLocalNode(ctx, "desktop", f); err != nil {
		t.Fatalf("AttachLocalNode: %v", err)
	}

	// 3. Connect a client using the Web Profile ticket over WebTransport.
	cli := nd.New(nd.Options{
		Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, connResp.Ticket)},
	})
	if err := cli.Dial(ctx, connResp.Endpoints.WebTransport, nd.DialOptions{
		CertHashes: [][]byte{mustHex(inst.Info.CertHash)},
	}); err != nil {
		t.Fatalf("client dial WT: %v", err)
	}
	defer cli.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && cli.Session().PeerFacet("desktop") == nil {
		time.Sleep(20 * time.Millisecond)
	}
	pf := cli.Session().PeerFacet("desktop")
	if pf == nil {
		t.Fatal("desktop facet not visible to client")
	}
	if got, err := cbor.NewDecoder(pf.Annotations["app.locality"]).Text(); err != nil || got != "local" {
		t.Fatalf("annotation app.locality = %q, %v", got, err)
	}
	res, err := cli.Call(ctx, "desktop", "ping", "hello")
	if err != nil || res != "local:hello" {
		t.Fatalf("desktop.ping = %v, %v", res, err)
	}
}

func TestLocalHubFederationAndPeerModuleProxyCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Start a "remote" reference hub with WebTransport + HTTP module server.
	remoteDir := t.TempDir()
	remoteMods := filepath.Join(remoteDir, "mods")
	_ = os.MkdirAll(remoteMods, 0o700)
	modBytes := []byte("export default function register() { return 'remote-mod'; }\n")
	modHash := websign.FileHash(modBytes)
	_ = os.WriteFile(filepath.Join(remoteMods, "remote.js"), modBytes, 0o600)

	remoteStore, err := admin.OpenStore(filepath.Join(remoteDir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	remoteHub, err := hub.New(hub.Options{
		Store:     remoteStore,
		Bootstrap: []hub.Credential{{Token: "rem-admin", Principal: "user:admin"}},
		Web:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteHub.Close(time.Second)

	cert, _, err := webtransport.SelfSigned("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	remotePin := hub.PinFor(leaf)

	wtSrv := webtransport.NewServer(webtransport.ServerOptions{
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		CheckOrigin: func(*http.Request) bool { return true },
	})
	wtMux := http.NewServeMux()
	wtMux.Handle("/sparrow/wt", remoteHub.WebTransportHandler(wtSrv))
	wtSrv.WT.H3.Handler = wtMux
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = wtSrv.Serve(udp) }()
	defer func() { _ = wtSrv.Close() }()
	remoteWT := fmt.Sprintf("https://127.0.0.1:%d/sparrow/wt", udp.LocalAddr().(*net.UDPAddr).Port)

	// Remote HTTP server serving WebSocket + /sparrow/mods/
	_, remKey, _ := ed25519.GenerateKey(rand.Reader)
	remWeb, err := web.NewServer(web.ServerOptions{
		Tickets: &web.Tickets{Key: remKey, Audience: remoteWT, Lifetime: 60 * time.Second},
		Auth: &web.StaticTokens{
			SessionLifetime: time.Hour,
			Tokens:          []web.StaticToken{{Token: "rem-web-tok", Principal: "user:alice"}},
		},
		Host:           remoteHub,
		AllowedOrigins: []string{"*"},
		Modules:        &web.ModuleDir{Dir: remoteMods},
	})
	if err != nil {
		t.Fatal(err)
	}
	remHTTPMux := http.NewServeMux()
	remHTTPMux.Handle("/sparrow/ws", remoteHub.WebSocketHandler(func(*http.Request) bool { return true }))
	remWeb.Mount(remHTTPMux)
	remHTTP := httptest.NewServer(remHTTPMux)
	defer remHTTP.Close()
	remWS := "ws" + remHTTP.URL[len("http"):] + "/sparrow/ws"

	// Configure remote hub: node "svc" + peer "desktop-hub".
	remAdmin := nd.New(nd.Options{Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "rem-admin")}})
	if err := remAdmin.Dial(ctx, remWS, nd.DialOptions{}); err != nil {
		t.Fatal(err)
	}
	defer remAdmin.Close()
	ac, err := admin.NewClient(remAdmin.Session(), adminiface.Name)
	if err != nil {
		t.Fatal(err)
	}
	_ = ac.SetSecret(ctx, "svc-sec", []byte("svc-cred"))
	_ = ac.SetSecret(ctx, "peer-sec", []byte("peer-cred"))
	peerTrue := true
	if _, err := ac.Commit(ctx, 0, &admin.Config{
		Nodes: map[string]*admin.NodeConfig{
			"svc":         {Link: admin.DialIn("svc-sec")},
			"desktop-hub": {Link: admin.DialIn("peer-sec"), Peer: &peerTrue},
		},
		Extensions: map[string][]byte{
			hub.PolicyExtension: hub.EncodeGrants([]hub.Grant{
				{Principal: "user:alice", Facet: "svc", Level: hub.LevelUse},
				{Principal: "node:desktop-hub", Facet: "svc", Level: hub.LevelUse},
				{Principal: "peer:desktop-hub/user:local", Facet: "svc", Level: hub.LevelUse},
			}),
		},
	}, 0); err != nil {
		t.Fatal(err)
	}

	// Dial remote "svc" into remote hub, advertising a signed web.modules entry for svc.ui.
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	modRec := websign.Module{
		ID:      "svc.ui",
		Version: "1.0.0",
		Hash:    modHash,
		Fields: map[string]cbor.Raw{
			"id":      cbor.AppendText(nil, "svc.ui"),
			"version": cbor.AppendText(nil, "1.0.0"),
			"hash":    cbor.AppendBytes(nil, modHash),
			"url":     cbor.AppendText(nil, web.FileName(modHash, "js")),
			"deps":    cbor.AppendArrayHead(nil, 0),
			"hostApi": cbor.AppendText(nil, "^3.1"),
		},
	}
	if err := websign.SignModule(&modRec, privKey); err != nil {
		t.Fatal(err)
	}
	modEnc, err := modRec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	modsRaw := append(cbor.AppendArrayHead(nil, 1), modEnc...)
	svcNode := nd.New(nd.Options{Auth: &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, "svc-cred")}})
	sb := nd.NewFacet("svc", "1.0.0")
	sb.Service("Svc").Method("hello", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return "remote:" + in.(string), nil
	})
	svcFacet := sb.MustBuild()
	svcFacet.Def.Annotations["web.modules"] = modsRaw
	if _, err := svcNode.Add(ctx, svcFacet); err != nil {
		t.Fatal(err)
	}
	if err := svcNode.Dial(ctx, remWS, nd.DialOptions{}); err != nil {
		t.Fatal(err)
	}
	defer svcNode.Close()

	// Start our embedded local hub federated with the remote hub over WebTransport!
	localInst, err := Start(ctx, Config{
		RootKeys: []string{hex.EncodeToString(pubKey)},
		Peers: []PeerConfig{{
			ID:            "remote",
			URL:           remoteWT,
			Pin:           hex.EncodeToString(remotePin),
			Credential:    "peer-cred",
			WebBaseURL:    remHTTP.URL,
			WebAuthHeader: "Bearer rem-web-tok",
		}},
	})
	if err != nil {
		t.Fatalf("localhub Start: %v", err)
	}
	defer localInst.Close()

	// Connect client to local hub and call federated remote/svc!
	cli := nd.New(nd.Options{
		Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, localInst.Info.Token)},
	})
	if err := cli.Dial(ctx, localInst.Info.WebSocket, nd.DialOptions{}); err != nil {
		t.Fatalf("client dial local: %v", err)
	}
	defer cli.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && cli.Session().PeerFacet("remote/svc") == nil {
		time.Sleep(25 * time.Millisecond)
	}
	if cli.Session().PeerFacet("remote/svc") == nil {
		t.Fatal("federated facet remote/svc did not appear on local hub")
	}
	res, err := cli.Call(ctx, "remote/svc", "hello", "world")
	if err != nil || res != "remote:world" {
		t.Fatalf("remote/svc.hello = %v, %v", res, err)
	}

	// Verify peer module proxy + offline disk cache: fetch module hosted ONLY on remote hub!
	modURL := localInst.Info.BaseURL + web.FileName(modHash, "js")
	fetchMod := func() (*http.Response, []byte) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, modURL, nil)
		req.Header.Set("Authorization", "Bearer "+localInst.Info.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("fetch module: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, b
	}
	resp, got := fetchMod()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, modBytes) {
		t.Fatalf("proxied module mismatch: status=%d got=%q", resp.StatusCode, got)
	}

	// Shut down remote HTTP server and prove the local disk cache still serves the module offline!
	remHTTP.Close()
	resp2, got2 := fetchMod()
	if resp2.StatusCode != http.StatusOK || !bytes.Equal(got2, modBytes) {
		t.Fatalf("cached module offline mismatch: status=%d got=%q", resp2.StatusCode, got2)
	}
}
