package hub

import (
	"net"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/status"
)

// Behaviour of core rev381 (5.5, 10.2, 10.7) and hub-admin rev41.

// TestReconfigurationEndsCallsTheNodeMade: when the configuration
// disables a dial-in node or changes a dialed node's link, the hub ends
// the node's session at once (10.2): the calls the node made through the
// hub end too, cancelled downstream with unavailable, and the node gets
// GoAway(unauthenticated) if it dialed in or GoAway(going_away) if the
// hub dialed it.
func TestReconfigurationEndsCallsTheNodeMade(t *testing.T) {
	t.Parallel()
	for _, dialed := range []bool{false, true} {
		name := "dial-in"
		if dialed {
			name = "dialed"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, nil)
			f.secret("work-1", "work-cred")
			f.secret("acme-1", "acme-cred")
			f.secret("acme-2", "acme-cred-2")
			n := nd.New(nd.Options{ID: "acme", Auth: linkAuth("acme-cred"), Logger: testLogger(t)})
			if _, err := n.Add(tctx(t), blocker("acme", make(chan struct{}, 1), nil)); err != nil {
				t.Fatal(err)
			}
			acme := dialInConfig("acme-1")
			var ln *listeningNode
			if dialed {
				ln = serveNodeAny(t, n, "acme-cred", "acme-cred-2")
				acme = dialConfig(ln.url, ln.pin, "acme-1")
			}
			grants := policy(grant("node:acme", "work", "use"), grant("user:alice", "work", "use"))
			f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"work": dialInConfig("work-1"), "acme": acme}, Extensions: grants})
			w := newWorker(t, f, "websocket", nil)
			if !dialed {
				if err := n.Dial(tctx(t), f.wsURL, nd.DialOptions{}); err != nil {
					t.Fatal(err)
				}
				f.onCleanup(n.Close)
			}
			waitNode(t, f.h, "acme", true)
			waitFacet(t, n, "work")
			s := nodeSession(t, n)
			// A call the node makes on its own, through the hub.
			done := make(chan error, 1)
			go func() {
				_, err := n.Call(tctx(t), "work", "block", nil)
				done <- err
			}()
			<-w.started
			next := acme.Clone()
			if dialed {
				next.Link.Dial.Credential = "acme-2"
			} else {
				next.Enabled = boolp(false)
			}
			f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"work": dialInConfig("work-1"), "acme": next}, Extensions: grants})
			select {
			case cause := <-w.causes:
				mustCode(t, cause, status.Unavailable)
			case <-time.After(10 * time.Second):
				t.Fatal("the call the node made was not cancelled downstream")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("the node's call succeeded")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the node's call did not end")
			}
			select {
			case <-s.Done():
			case <-time.After(10 * time.Second):
				t.Fatal("the node's session did not end")
			}
			want := status.Unauthenticated
			if dialed {
				want = status.GoingAway
			}
			if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != want {
				t.Fatalf("the node got GoAway %v, want %v", g, want)
			}
			if dialed {
				// Redialed under the new configuration (10.2).
				waitNode(t, f.h, "acme", true)
			}
		})
	}
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

// TestAuthRefreshOnNodeLink: AuthRefresh is for client sessions; a hub
// that receives one on a link from a node or a peer hub that dialed in
// closes that session with GoAway(unauthenticated) (5.5).
func TestAuthRefreshOnNodeLink(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("acme-1", "acme-cred")
	f.secret("peer-1", "peer-cred")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1"), "other": peerDialIn("peer-1")}})
	for _, c := range []struct{ id, cred string }{{"acme", "acme-cred"}, {"other", "peer-cred"}} {
		n, err := dialInNode(t, f, "websocket", c.id, c.cred)
		if err != nil {
			t.Fatal(err)
		}
		waitNode(t, f.h, c.id, true)
		s := n.Session()
		if err := s.RefreshAuth(*linkAuth(c.cred)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.Done():
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the session was not closed", c.id)
		}
		if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != status.Unauthenticated {
			t.Fatalf("%s: GoAway %v (%v)", c.id, g, s.Err())
		}
	}
}
