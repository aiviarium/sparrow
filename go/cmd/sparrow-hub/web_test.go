package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	"github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/web"
	"github.com/aiviarium/sparrow-rpc/go/websign"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// webKeys are the TEST-ONLY keys of the signing vectors.
type webKeys struct {
	root      ed25519.PrivateKey
	rootPub   []byte
	stranger  ed25519.PrivateKey // uncertified
	certs     []cbor.Raw
	revoked   cbor.Raw
	verifyNow time.Time
}

func loadWebKeys(t *testing.T) *webKeys {
	f, err := vectors.Load("signing.json")
	if err != nil {
		t.Fatal(err)
	}
	k := &webKeys{}
	for _, v := range f.Vectors {
		switch {
		case v.Name == "key/root-01":
			k.root = ed25519.NewKeyFromSeed(v.Hex("seed"))
			k.rootPub = v.Hex("public_key")
		case v.Name == "key/uncertified-04":
			k.stranger = ed25519.NewKeyFromSeed(v.Hex("seed"))
		case v.Name == "cert/acme" || v.Name == "cert/beta":
			k.certs = append(k.certs, v.Hex("certificate_cbor"))
		case v.Name == "revocation/list-3":
			k.revoked = v.Hex("revocation_cbor")
		}
	}
	return k
}

func moduleEntry(t *testing.T, id, version string, file []byte, key ed25519.PrivateKey) cbor.Raw {
	h := websign.FileHash(file)
	m := &websign.Module{ID: id, Version: version, Hash: h, Fields: map[string]cbor.Raw{
		"id": cbor.AppendText(nil, id), "version": cbor.AppendText(nil, version), "hash": cbor.AppendBytes(nil, h),
		"url": cbor.AppendText(nil, web.FileName(h, "js")), "deps": cbor.AppendArrayHead(nil, 0), "hostApi": cbor.AppendText(nil, "^3.1"),
	}}
	if err := websign.SignModule(m, key); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// webHub starts the sparrow-hub binary with the Web Profile on and two
// examples/echo-node processes: echo, which dials in and ships two client
// modules (one signed by the root key, one by an uncertified key), and
// dialed, which the hub dials.
func webHub(t *testing.T, extra map[string]any) (*hubProc, *webKeys, []byte) {
	dir := t.TempDir()
	k := loadWebKeys(t)
	mods := filepath.Join(dir, "mods")
	_ = os.MkdirAll(mods, 0o755)
	app := []byte("export default function register(host) { return { id: 'echo.ui' }; }\n")
	stray := []byte("export default function register(host) { return { id: 'echo.stray' }; }\n")
	_ = os.WriteFile(filepath.Join(mods, "echo-ui.js"), app, 0o644)
	_ = os.WriteFile(filepath.Join(mods, "echo-stray.js"), stray, 0o644)
	entries := cbor.AppendArrayHead(nil, 2)
	entries = cbor.AppendRaw(entries, moduleEntry(t, "echo.ui", "1.0.0", app, k.root))
	entries = cbor.AppendRaw(entries, moduleEntry(t, "echo.stray", "1.0.0", stray, k.stranger))
	entriesFile := filepath.Join(dir, "echo-modules.cbor")
	_ = os.WriteFile(entriesFile, entries, 0o644)

	cfg := map[string]any{
		"webtransport": "127.0.0.1:0", "websocket": "127.0.0.1:0", "selfSigned": true,
		"dataDir":   filepath.Join(dir, "data"),
		"bootstrap": []map[string]string{{"principal": "user:admin", "credential": "admin-secret"}},
		"tokens":    []map[string]any{{"token": "alice-token", "principal": "user:alice", "groups": []string{"group:eng"}}},
		"web":       map[string]any{"modulesDir": mods, "rootKeys": []string{hex.EncodeToString(k.rootPub)}, "minHostApi": "3.0.0"},
		"log":       "debug", "shutdownGraceMs": 3000, "connectTimeoutMs": 5000,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	b, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(dir, "hub.json"), b, 0o600)
	p := startHub(t, dir)
	if p.addrs.Web == "" {
		t.Fatalf("no web address: %+v", p.addrs)
	}

	_, url, pin := echoListening(t, "dialed", "dial-secret")
	p.admin(t, p.addrs.WebSocket, "set-secret", "dialed-cred", "dial-secret")
	p.admin(t, p.addrs.WebSocket, "set-secret", "echo-cred", "echo-secret")
	webExt := cbor.AppendMapHead(nil, 3)
	webExt = cbor.AppendRaw(cbor.AppendText(webExt, "web.keys"), cbor.AppendRaw(cbor.AppendArrayHead(nil, len(k.certs)), bytes.Join(func() [][]byte {
		out := make([][]byte, len(k.certs))
		for i, c := range k.certs {
			out[i] = c
		}
		return out
	}(), nil)))
	webExt = cbor.AppendRaw(cbor.AppendText(webExt, "web.apply"), cbor.AppendText(nil, "reload"))
	webExt = cbor.AppendRaw(cbor.AppendText(webExt, "web.revoked"), k.revoked)
	webExt, _ = cbor.Canonical(webExt, cbor.Options{})
	doc := map[string]any{
		"nodes": map[string]any{
			"echo":   map[string]any{"link": map[string]any{"credential": "echo-cred"}},
			"dialed": map[string]any{"link": map[string]any{"dial": map[string]any{"url": url, "pin": pin, "credential": "dialed-cred"}}}},
		"extensions": map[string]string{"ref.web": hex.EncodeToString(webExt)},
		"policy":     [][3]string{{"group:eng", "echo", "use"}, {"group:eng", "dialed", "use"}},
	}
	db, _ := json.Marshal(doc)
	docFile := filepath.Join(dir, "doc.json")
	_ = os.WriteFile(docFile, db, 0o600)
	if out := p.admin(t, p.addrs.WebSocket, "commit", "-confirm-within", "10000", "-confirm", docFile); !strings.Contains(out, `"revision": 1`) {
		t.Fatalf("commit: %s", out)
	}
	p.echoDialIn(t, "echo", "echo-secret", "-web-modules", entriesFile)
	// Wait until both nodes are connected, so the schema stays put.
	probe := p.client(t, p.addrs.WebSocket, "alice-token", nil)
	testutil.Eventually(t, 20*time.Second, func() bool {
		s := probe.Session()
		return s != nil && s.PeerFacet("echo") != nil && s.PeerFacet("dialed") != nil
	}, "nodes not listed")
	probe.Close()
	h, _ := hex.DecodeString(p.addrs.CertHash)
	return p, k, h
}

// TestWebEndToEnd runs the built sparrow-hub with the Web Profile and goes
// through what a browser client does, over WebTransport and over
// WebSocket: /connect, a ticket in Hello, calls to the dial-in and the
// dialed node, ticket replay refused, AuthRefresh with a refreshed ticket,
// the schema resource, and module fetch and verification into a snapshot.
func TestWebEndToEnd(t *testing.T) {
	p, keys, certHash := webHub(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	wc := &web.Client{Base: p.addrs.Web, HTTP: pinnedClient(certHash),
		Authorize: func(r *http.Request) { r.Header.Set("Authorization", "Bearer alice-token") }}
	for _, binding := range []string{"webtransport", "websocket"} {
		t.Run(binding, func(t *testing.T) {
			cr, err := wc.Connect(ctx, web.ClientInfo{Name: "go-e2e", Version: "1.0.0", HostAPI: "3.2.0"}, nil)
			if err != nil {
				t.Fatalf("connect: %v\n%s", err, p.logText())
			}
			if cr.Endpoints.WebTransport != p.addrs.WebTransport || cr.Endpoints.WebSocket != p.addrs.WebSocket {
				t.Fatalf("endpoints %+v vs %+v", cr.Endpoints, p.addrs)
			}
			if len(cr.ServerCertificateHashes) != 1 || cr.ServerCertificateHashes[0] != web.EncodeHash(certHash) {
				t.Fatalf("serverCertificateHashes %v", cr.ServerCertificateHashes)
			}
			endpoint := cr.Endpoints.WebTransport
			if binding == "websocket" {
				endpoint = cr.Endpoints.WebSocket
			}
			statuses := make(chan *wire.AuthStatus, 4)
			dial := func(ticket string) (*node.Node, error) {
				n := node.New(node.Options{Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, ticket)},
					Session: func(c *session.Config) {
						c.OnAuthStatus = func(s *session.Session, m *wire.AuthStatus) { statuses <- m }
					}})
				do := node.DialOptions{CertHashes: [][]byte{certHash}, HTTPClient: pinnedClient(certHash)}
				dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
				defer dcancel()
				if err := n.Dial(dctx, endpoint, do); err != nil {
					return nil, err
				}
				t.Cleanup(n.Close)
				return n, nil
			}
			c, err := dial(cr.Ticket)
			if err != nil {
				t.Fatalf("dial with the ticket: %v\n%s", err, p.logText())
			}
			s := c.Session()
			if h, _ := s.PeerSchema().Schema().Hash(); web.EncodeHash(h) != cr.SchemaHash {
				t.Fatalf("the session's schema is not the one /connect named")
			}
			testutil.Eventually(t, 20*time.Second, func() bool {
				return s.PeerFacet("echo") != nil && s.PeerFacet("dialed") != nil
			}, "echo and dialed not listed")
			if v, err := c.Call(ctx, "echo", "echo", "through the web profile"); err != nil || v != "through the web profile" {
				t.Fatalf("echo: %v %v", v, err)
			}
			if v, err := c.Call(ctx, "echo", "whoami", nil); err != nil || v != "user:alice" {
				t.Fatalf("whoami: %v %v", v, err)
			}
			if v, err := c.Call(ctx, "dialed", "reverse", "dialed"); err != nil || v != "delaid" {
				t.Fatalf("dialed: %v %v", v, err)
			}
			// A ticket is single-use.
			if _, err := dial(cr.Ticket); session.Code(err) != status.Unauthenticated {
				t.Fatalf("replayed ticket: %v", err)
			}
			// Refresh: a new ticket for this endpoint, sent in AuthRefresh.
			nt, err := wc.Refresh(ctx, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.RefreshAuth(wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, nt)}); err != nil {
				t.Fatal(err)
			}
			select {
			case m := <-statuses:
				sexp, _ := time.Parse(time.RFC3339, cr.SessionExpiresAt)
				if status.Code(m.Status) != status.OK || m.ExpiresAt == nil || m.ExpiresAt.Sec < sexp.Unix() {
					t.Fatalf("AuthStatus %+v", m)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("no AuthStatus after AuthRefresh")
			}
			if _, err := c.Call(ctx, "echo", "echo", "after refresh"); err != nil {
				t.Fatal(err)
			}
			// The schema resource, checked against the session's hash.
			cur := s.PeerSchema().Schema()
			ch, _ := cur.Hash()
			// The schema may have grown since /connect; ask /connect again
			// for the current hash and fetch that.
			cr2, err := wc.Connect(ctx, web.ClientInfo{Name: "go-e2e", HostAPI: "3.2.0"}, ch)
			if err != nil {
				t.Fatal(err)
			}
			hh, _ := web.DecodeHash(cr2.SchemaHash)
			sc, _, err := wc.Schema(ctx, cr2.SchemaURL, hh)
			if err != nil {
				t.Fatalf("schema: %v", err)
			}
			if !bytes.Equal(hh, ch) {
				t.Fatalf("the schema resource differs from the session's schema")
			}
			// Modules: echo.ui (root-signed) accepted, echo.stray
			// (uncertified key) rejected and reported.
			l := &web.Loader{Roots: [][]byte{keys.rootPub}, HostAPI: "3.2.0"}
			acc, rej := l.Accept(sc)
			if len(acc) != 1 || acc[0].ID() != "echo.ui" || len(rej) != 1 || rej[0].ID != "echo.stray" || rej[0].Reason != string(websign.ReasonUnknownKey) {
				t.Fatalf("accepted %v rejected %v", acc, rej)
			}
			if l.State.Revocation == nil || l.State.Revocation.Seq != 3 {
				t.Fatal("web.revoked not published")
			}
			files := map[string][]byte{}
			for _, e := range acc {
				b, hdr, err := wc.File(ctx, e.URL, e.Hash())
				if err != nil {
					t.Fatalf("module: %v", err)
				}
				if cc := hdr.Get("Cache-Control"); cc != "private, max-age=31536000, immutable" {
					t.Fatalf("Cache-Control %q", cc)
				}
				files[string(e.Hash())] = b
			}
			// A module of another hash is not served.
			if _, _, err := wc.File(ctx, web.FileName(append([]byte{1}, make([]byte, 32)...), "js"), nil); err == nil {
				t.Fatal("unknown module served")
			}
			snap, err := web.NewSnapshot(sc, nil, acc, files, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := snap.Encode(); err != nil {
				t.Fatal(err)
			}
			for _, r := range rej {
				if err := c.Notify(ctx, "sparrow.web", "moduleRejected", []any{r.ID, r.Version, r.Reason}); err != nil {
					t.Fatal(err)
				}
			}
			testutil.Eventually(t, 10*time.Second, func() bool {
				return strings.Contains(p.logText(), "a client rejected a module")
			}, "moduleRejected not logged")
		})
	}
	// A ticket presented to a hub instance it was not issued for is
	// refused: here, a ticket of the right shape signed by another key.
	_, other, _ := ed25519.GenerateKey(nil)
	forged, _, _ := (&web.Tickets{Key: other, Audience: p.addrs.WebTransport}).Issue(&web.Login{Principal: "user:alice", Session: "x", Expires: time.Now().Add(time.Hour)})
	n := node.New(node.Options{Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, forged)}})
	err := n.Dial(ctx, p.addrs.WebTransport, node.DialOptions{CertHashes: [][]byte{certHash}})
	if session.Code(err) != status.Unauthenticated {
		t.Fatalf("forged ticket: %v", err)
	}
	// /connect without a login.
	anon := &web.Client{Base: p.addrs.Web, HTTP: pinnedClient(certHash)}
	if _, err := anon.Connect(ctx, web.ClientInfo{HostAPI: "3.2.0"}, nil); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("anonymous connect: %v", err)
	}
}
