package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/websocket"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// listeningNode is a node the hub dials: it serves WebTransport (https) or
// WebSocket over TLS (wss) and checks the hub's link credential.
type listeningNode struct {
	n        *nd.Node
	url      string
	pin      []byte
	sessions atomic.Int64
	authErrs atomic.Int64
}

func serveNode(t *testing.T, binding string, n *nd.Node, cred string) *listeningNode {
	t.Helper()
	ln := &listeningNode{n: n}
	auth := func(a *wire.Auth) error {
		got, ok := credentialBytes(nilSafe(a))
		if a == nil || a.Scheme != "link" || !ok || string(got) != cred {
			ln.authErrs.Add(1)
			return &session.Error{Code: status.Unauthenticated, Message: "bad hub credential"}
		}
		return nil
	}
	serve := func(c transport.Conn) {
		if err := n.Serve(context.Background(), c, auth); err == nil {
			ln.sessions.Add(1)
		}
	}
	switch binding {
	case "webtransport":
		cert, _, err := webtransport.SelfSigned("127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		ln.pin = PinFor(leaf)
		srv := webtransport.NewServer(webtransport.ServerOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, CheckOrigin: func(*http.Request) bool { return true }})
		mux := http.NewServeMux()
		mux.Handle("/node", srv.Handler(func(c *webtransport.Conn, _ *http.Request) { serve(c) }))
		srv.WT.H3.Handler = mux
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(pc) }()
		t.Cleanup(func() { _ = srv.Close() })
		ln.url = fmt.Sprintf("https://127.0.0.1:%d/node", pc.LocalAddr().(*net.UDPAddr).Port)
	default:
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CheckOrigin: func(*http.Request) bool { return true }})
			if err != nil {
				return
			}
			serve(c)
			<-r.Context().Done()
		}))
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		srv.StartTLS()
		t.Cleanup(srv.Close)
		ln.pin = PinFor(srv.Certificate())
		ln.url = "wss" + strings.TrimPrefix(srv.URL, "https") + "/node"
	}
	return ln
}

func nilSafe(a *wire.Auth) []byte {
	if a == nil {
		return nil
	}
	return a.Credentials
}

func dialConfig(url string, pin []byte, cred string) *admin.NodeConfig {
	return &admin.NodeConfig{Link: admin.Dialed(admin.Dial{URL: url, Pin: pin, Credential: cred})}
}

func TestHubDialsNode(t *testing.T) {
	for _, b := range transports {
		t.Run(b, func(t *testing.T) {
			f := newFixture(t, nil)
			n := nd.New(nd.Options{ID: "remote", Logger: testLogger(t)})
			rec := &recorder{}
			if _, err := n.Add(tctx(t), rec.facet("remote")); err != nil {
				t.Fatal(err)
			}
			ln := serveNode(t, b, n, "hub-secret")
			f.secret("to-remote", "hub-secret")
			f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"remote": dialConfig(ln.url, ln.pin, "to-remote")},
				Extensions: policy(grant("user:alice", "remote", "use"))})
			waitNode(t, f.h, "remote", true)
			cli := f.client(b, aliceToken)
			waitFacet(t, cli, "remote")
			if v, err := cli.Call(tctx(t), "remote", "ping", nil); err != nil || v != "pong" {
				t.Fatalf("%v %v", v, err)
			}
			// The node calls a hub facet back over the same link (the hub is
			// the Sparrow client there): sparrow.hub.admin is not visible to
			// node:remote, so it is not in the node's view.
			if n.Session().PeerFacet("sparrow.hub.admin") != nil {
				t.Fatal("the node sees the admin facet")
			}

			// A wrong pin is refused on every connection: after a commit
			// with another pin, no session reaches the node.
			before := ln.sessions.Load()
			bad := append([]byte{}, ln.pin...)
			bad[0] ^= 0xff
			f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"remote": dialConfig(ln.url, bad, "to-remote")},
				Extensions: policy(grant("user:alice", "remote", "use"))})
			waitNode(t, f.h, "remote", false)
			time.Sleep(500 * time.Millisecond)
			if ln.sessions.Load() != before {
				t.Fatal("a session was established despite the wrong pin")
			}
			testutil.Eventually(t, 10*time.Second, func() bool {
				st := f.h.Admin().NodeStates()["remote"]
				return st.State == admin.Offline && st.Message != nil && strings.Contains(*st.Message, "pin")
			}, "node state %+v", f.h.Admin().NodeStates()["remote"])
			// Calls wait for the connect timeout and then fail with
			// unavailable; the facet stays listed (10.7).
			if cli.Session().PeerFacet("remote") == nil {
				t.Fatal("facet no longer listed")
			}
			start := time.Now()
			_, err := cli.Call(tctx(t), "remote", "ping", nil)
			mustCode(t, err, status.Unavailable)
			if d := time.Since(start); d < 2*time.Second {
				t.Fatalf("failed after %v, before the connect timeout", d)
			}
		})
	}
}

// serveNodeAny serves a node over WebTransport accepting any of creds.
func serveNodeAny(t *testing.T, n *nd.Node, creds ...string) *listeningNode {
	cert, _, err := webtransport.SelfSigned("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ln := &listeningNode{n: n}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	ln.pin = PinFor(leaf)
	srv := webtransport.NewServer(webtransport.ServerOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, CheckOrigin: func(*http.Request) bool { return true }})
	mux := http.NewServeMux()
	mux.Handle("/node", srv.Handler(func(c *webtransport.Conn, _ *http.Request) {
		_ = n.Serve(context.Background(), c, func(a *wire.Auth) error {
			got, _ := credentialBytes(nilSafe(a))
			for _, c := range creds {
				if string(got) == c {
					return nil
				}
			}
			return &session.Error{Code: status.Unauthenticated, Message: "bad hub credential"}
		})
	}))
	srv.WT.H3.Handler = mux
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })
	ln.url = fmt.Sprintf("https://127.0.0.1:%d/node", pc.LocalAddr().(*net.UDPAddr).Port)
	return ln
}
