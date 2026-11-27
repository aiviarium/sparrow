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

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport"
	"github.com/aiviarium/sparrow/go/transport/websocket"
	"github.com/aiviarium/sparrow/go/transport/webtransport"
	"github.com/aiviarium/sparrow/go/wire"
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

// nodeSession returns the session of a node the hub dialed. The hub counts
// the node connected once it has sent Ready; the node has its session only
// once it has received it.
func nodeSession(t *testing.T, n *nd.Node) *session.Session {
	t.Helper()
	var s *session.Session
	testutil.Eventually(t, 10*time.Second, func() bool { s = n.Session(); return s != nil }, "the node has no session")
	return s
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
	t.Parallel()
	for _, b := range transports {
		t.Run(b, func(t *testing.T) {
			t.Parallel()
			clk := testutil.NewFakeClock()
			f := newFixture(t, func(o *Options) { o.Clock = clk })
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
			if nodeSession(t, n).PeerFacet("sparrow.hub.admin") != nil {
				t.Fatal("the node sees the admin facet")
			}

			// A wrong pin is refused on every connection: after a commit
			// with another pin, no session reaches the node.
			testutil.Eventually(t, 10*time.Second, func() bool { return ln.sessions.Load() == 1 }, "the node counted no session")
			before := ln.sessions.Load()
			bad := append([]byte{}, ln.pin...)
			bad[0] ^= 0xff
			f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"remote": dialConfig(ln.url, bad, "to-remote")},
				Extensions: policy(grant("user:alice", "remote", "use"))})
			waitNode(t, f.h, "remote", false)
			testutil.Eventually(t, 10*time.Second, func() bool {
				st := f.h.Admin().NodeStates()["remote"]
				return st.State == admin.Offline && st.Message != nil && strings.Contains(*st.Message, "pin")
			}, "node state %+v", f.h.Admin().NodeStates()["remote"])
			// Several attempts, each refused at the pin.
			testutil.Eventually(t, 10*time.Second, func() bool { return dialAttempts(f.h, "remote") >= 3 }, "the hub does not redial")
			if ln.sessions.Load() != before {
				t.Fatal("a session was established despite the wrong pin")
			}
			// Calls wait for the connect timeout and then fail with
			// unavailable; the facet stays listed (10.7).
			if cli.Session().PeerFacet("remote") == nil {
				t.Fatal("facet no longer listed")
			}
			expectConnectTimeout(t, f, clk, cli, "remote", "remote", "ping", nil)
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

// TestWaitingCallDialsAtOnce: for a node the hub dials, a call that starts
// waiting makes the hub dial at once (10.7), here while the dial loop is
// in a backoff of an hour.
func TestWaitingCallDialsAtOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(o *Options) {
		o.RedialBackoff, o.RedialBackoffMax, o.WaitingRedial = time.Hour, time.Hour, time.Hour
	})
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": f.dialedEcho("echo")}, Extensions: policy(grant("user:alice", "echo", "use"))})
	waitNode(t, f.h, "echo", true)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "echo")
	// The node goes away; the dial loop now waits an hour.
	f.stopEcho("echo", false)
	waitNode(t, f.h, "echo", false)
	testutil.Eventually(t, 10*time.Second, func() bool {
		f.h.mu.Lock()
		defer f.h.mu.Unlock()
		dl := f.h.nodes["echo"].dl
		return dl != nil && !dl.attempting.Load()
	}, "the dial loop does not wait")
	attempts := dialAttempts(f.h, "echo")
	f.restartEcho("echo", false)
	if v, err := cli.Call(tctx(t), "echo", "echo", "at once"); err != nil || v != "at once" {
		t.Fatalf("%v %v", v, err)
	}
	if got := dialAttempts(f.h, "echo"); got != attempts+1 {
		t.Fatalf("%d attempts after the call, want %d", got, attempts+1)
	}
}

// TestWaitingCallDuringAttempt: a call that starts waiting while an
// attempt to dial the node is under way does not start another one
// (10.7); it fails with unavailable at the connect timeout.
func TestWaitingCallDuringAttempt(t *testing.T) {
	t.Parallel()
	clk := testutil.NewFakeClock()
	f := newFixture(t, func(o *Options) {
		o.Clock = clk
		o.DialTimeout = time.Hour
	})
	nc := f.dialedEcho("echo")
	grants := policy(grant("user:alice", "echo", "use"))
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": nc}, Extensions: grants})
	waitNode(t, f.h, "echo", true)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "echo")
	// The node moves to an address where nothing answers: the QUIC
	// handshake of the next attempt hangs. Its facets stay listed (10.7).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	hole := nc.Clone()
	hole.Link.Dial.URL = "https://" + pc.LocalAddr().String() + "/sparrow/node"
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": hole}, Extensions: grants})
	testutil.Eventually(t, 10*time.Second, func() bool {
		f.h.mu.Lock()
		defer f.h.mu.Unlock()
		dl := f.h.nodes["echo"].dl
		return dl != nil && dl.attempting.Load() && dl.attempts.Load() == 1
	}, "no attempt under way")
	done := make(chan error, 1)
	go func() {
		_, err := cli.Call(tctx(t), "echo", "echo", "x")
		done <- err
	}()
	waitWaiting(t, f.h, "echo", 1)
	f.h.mu.Lock()
	dl := f.h.nodes["echo"].dl
	f.h.mu.Unlock()
	if len(dl.kick) != 0 || dl.attempts.Load() != 1 {
		t.Fatalf("the waiting call asked for another attempt (%d queued, %d made)", len(dl.kick), dl.attempts.Load())
	}
	clk.Advance(f.h.o.ConnectTimeout)
	select {
	case err := <-done:
		mustCode(t, err, status.Unavailable)
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not fail at the connect timeout")
	}
}
