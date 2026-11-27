package hub

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/wire"
)

// How the hub applies a configuration change to a node's session and calls
// (10.2, 10.5, 10.7), and node-link limits.

// blocker is a facet whose wait method runs until released or cancelled.
func blocker(name string, started chan<- struct{}, release <-chan struct{}) *nd.Facet {
	b := nd.NewFacet(name, "1.0.0")
	svc := b.Service("B")
	svc.Method("wait", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		started <- struct{}{}
		select {
		case <-release:
			return "released", nil
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	})
	svc.Method("ping", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) { return "pong", nil })
	return b.MustBuild()
}

// runningCall starts a call to wait and returns its result channel once the
// node has it.
func runningCall(t *testing.T, cli *nd.Node, facet string, started <-chan struct{}) chan error {
	done := make(chan error, 1)
	go func() {
		_, err := cli.Call(tctx(t), facet, "wait", nil)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not reach the node")
	}
	return done
}

// TestReconfigurationEndsSessionAtOnce: a changed link ends the node's
// session at once, without the grace period of 5.6: the running call ends
// with Error(unavailable), the node gets GoAway(going_away) since the hub
// dialed it (GoAway(unauthenticated) goes to a node that
// dialed in), and the hub dials the node anew under the new configuration
// (10.2).
func TestReconfigurationEndsSessionAtOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	started, release := make(chan struct{}, 4), make(chan struct{})
	defer close(release)
	n := nd.New(nd.Options{ID: "remote", Logger: testLogger(t)})
	if _, err := n.Add(tctx(t), blocker("remote", started, release)); err != nil {
		t.Fatal(err)
	}
	ln := serveNodeAny(t, n, "old-secret", "new-secret")
	f.secret("cred-old", "old-secret")
	f.secret("cred-new", "new-secret")
	grants := policy(grant("user:alice", "remote", "use"))
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"remote": dialConfig(ln.url, ln.pin, "cred-old")}, Extensions: grants})
	waitNode(t, f.h, "remote", true)
	first := nodeSession(t, n)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "remote")
	call := runningCall(t, cli, "remote", started)
	start := time.Now()
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"remote": dialConfig(ln.url, ln.pin, "cred-new")}, Extensions: grants})
	select {
	case err := <-call:
		mustCode(t, err, status.Unavailable)
	case <-time.After(10 * time.Second):
		t.Fatal("the running call did not end")
	}
	select {
	case <-first.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("old session not ended")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the session ended after %v: a grace period was given", d)
	}
	if g := first.GoAwayReceived(); g == nil || status.Code(g.Status) != status.GoingAway {
		t.Fatalf("old session got %v", g)
	}
	waitNode(t, f.h, "remote", true)
	if v, err := cli.Call(tctx(t), "remote", "ping", nil); err != nil || v != "pong" {
		t.Fatalf("%v %v", v, err)
	}
}

// TestDisableDialInNode: disabling a dial-in node ends its session at once
// with GoAway(unauthenticated); the running call ends with unavailable,
// its facets are hidden, a call to their ID gets unimplemented, its
// credential is refused with unauthenticated while it is disabled, it is
// reported disabled, and enabling it again lets it dial in.
func TestDisableDialInNode(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	started, release := make(chan struct{}, 4), make(chan struct{})
	defer close(release)
	f.secret("acme-1", "cred-one")
	grants := policy(grant("user:alice", "acme", "use"))
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: grants})
	n, err := dialInNode(t, f, "websocket", "acme", "cred-one", blocker("acme", started, release))
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	cli := f.client("websocket", aliceToken)
	id := waitFacet(t, cli, "acme")
	call := runningCall(t, cli, "acme", started)
	disabled := dialInConfig("acme-1")
	disabled.Enabled = boolp(false)
	rev := f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": disabled}, Extensions: grants})
	mustCode(t, <-call, status.Unavailable)
	s := n.Session()
	if s != nil {
		<-s.Done()
		if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != status.Unauthenticated {
			t.Fatalf("node got %v", g)
		}
	}
	waitNoFacet(t, cli, "acme")
	cc, err := cli.Session().OpenRaw(tctx(t), session.RawRequest{FacetID: id, MethodID: 1}, &session.CallOptions{Flags: new(uint64)})
	if err == nil {
		_, err = cc.ResponseRaw(tctx(t))
	}
	mustCode(t, err, status.Unimplemented)
	_, err = dialInNode(t, f, "websocket", "acme", "cred-one", blocker("acme", started, release))
	mustCode(t, err, status.Unauthenticated)
	if st := f.h.Admin().NodeStates()["acme"]; st.State != admin.Disabled || st.Revision != rev {
		t.Fatalf("state %+v", st)
	}
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: grants})
	if _, err := dialInNode(t, f, "websocket", "acme", "cred-one", blocker("acme", started, release)); err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	// Enabled again, its facets are listed again (relayed in the
	// background after the commit).
	waitFacet(t, cli, "acme")
	if v, err := cli.Call(tctx(t), "acme", "ping", nil); err != nil || v != "pong" {
		t.Fatalf("%v %v", v, err)
	}
}

// TestWaitingCallsForRemovedNode: calls waiting for an offline node fail
// with Error(unimplemented) as soon as the node is removed or disabled
// (10.7), not at the connect timeout.
func TestWaitingCallsForRemovedNode(t *testing.T) {
	t.Parallel()
	for _, remove := range []bool{true, false} {
		f := newFixture(t, func(o *Options) { o.ConnectTimeout = 20 * time.Second })
		f.secret("acme-1", "cred-one")
		grants := policy(grant("user:alice", "acme", "use"))
		f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: grants})
		rec := &recorder{}
		n, err := dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acme"))
		if err != nil {
			t.Fatal(err)
		}
		cli := f.client("websocket", aliceToken)
		waitFacet(t, cli, "acme")
		waitNode(t, f.h, "acme", true)
		n.Close()
		waitNode(t, f.h, "acme", false)
		done := make(chan error, 1)
		go func() {
			_, err := cli.Call(tctx(t), "acme", "ping", nil)
			done <- err
		}()
		waitWaiting(t, f.h, "acme", 1)
		start := time.Now()
		next := &admin.Config{Nodes: map[string]*admin.NodeConfig{}, Extensions: grants}
		if !remove {
			d := dialInConfig("acme-1")
			d.Enabled = boolp(false)
			next.Nodes["acme"] = d
		}
		f.commit(next)
		select {
		case err := <-done:
			mustCode(t, err, status.Unimplemented)
		case <-time.After(10 * time.Second):
			t.Fatal("the waiting call did not fail")
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("failed after %v", d)
		}
	}
}

// TestRemovedNodeDiscardsFacets: removing a node discards its last known
// facets; added again it has none until it connects, and gets new facet
// IDs (10.3, 10.7).
func TestRemovedNodeDiscardsFacets(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	cfg := &admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: policy(grant("user:alice", "acme", "use"))}
	f.commit(cfg)
	rec := &recorder{}
	n, err := dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acme"))
	if err != nil {
		t.Fatal(err)
	}
	cli := f.client("websocket", aliceToken)
	old := waitFacet(t, cli, "acme")
	n.Close()
	waitNode(t, f.h, "acme", false)
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{}})
	waitNoFacet(t, cli, "acme")
	f.commit(cfg)
	if len(f.h.Stats().Nodes["acme"].Listed) != 0 {
		t.Fatal("the re-added node lists its old facets")
	}
	testutil.Never(t, 50*time.Millisecond, func() bool { return cli.Session().PeerFacet("acme") != nil }, "the re-added node's old facets reached the client")
	if _, err := dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acme")); err != nil {
		t.Fatal(err)
	}
	if id := waitFacet(t, cli, "acme"); id == old {
		t.Fatal("the re-added node got its retired facet ID")
	}
}

// TestNodeAtConcurrencyLimit: when the node link is at the node's
// maxConcurrentCalls, the hub answers further calls with
// Error(resource_exhausted) at once and does not queue them (10.2).
func TestNodeAtConcurrencyLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	started, release := make(chan struct{}, 4), make(chan struct{})
	defer close(release)
	f.secret("acme-1", "cred-one")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: policy(grant("user:alice", "acme", "use"))})
	o := nd.Options{Auth: linkAuth("cred-one"), Logger: testLogger(t)}
	o.Params.Set(wire.ParamMaxConcurrentCalls, 1)
	n := nd.New(o)
	if _, err := n.Add(tctx(t), blocker("acme", started, release)); err != nil {
		t.Fatal(err)
	}
	if err := n.Dial(tctx(t), f.wsURL, nd.DialOptions{}); err != nil {
		t.Fatal(err)
	}
	f.onCleanup(n.Close)
	waitNode(t, f.h, "acme", true)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "acme")
	_ = runningCall(t, cli, "acme", started)
	start := time.Now()
	_, err := cli.Call(tctx(t), "acme", "ping", nil)
	mustCode(t, err, status.ResourceExhausted)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("refused after %v: it was queued", d)
	}
}

// TestRefusedFacetsKeepOldSession: a node that dials in again with facets
// that are not a compatible successor is refused, and its old session is
// kept and keeps serving (10.2).
func TestRefusedFacetsKeepOldSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: policy(grant("user:alice", "acme", "use"))})
	rec := &recorder{}
	if _, err := dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acme")); err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "acme")
	// Same name and major, ping now returns a uint: incompatible (6.7).
	b := nd.NewFacet("acme", "1.1.0")
	b.Service("Raw").Method("ping", nd.Unit, nd.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) { return uint64(1), nil })
	second, _ := dialInNode(t, f, "websocket", "acme", "cred-one", b.MustBuild())
	if s := second.Session(); s != nil {
		select {
		case <-s.Done():
		case <-time.After(10 * time.Second):
			t.Fatal("the incompatible session was not refused")
		}
	}
	if v, err := cli.Call(tctx(t), "acme", "ping", nil); err != nil || v != "pong" {
		t.Fatalf("the old session no longer serves: %v %v", v, err)
	}
	if st := f.h.Admin().NodeStates()["acme"]; st.State != admin.Connected {
		t.Fatalf("state %+v", st)
	}
}

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
