package hub

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Behaviour decided in core rev324 (10.2, 10.3, 10.7, 10.8).

// TestUnknownInterfaceRefused: a claim to an interface the hub holds no
// document for is refused like an incompatible update; once the document
// is configured (ref.interfaces), the claim is verified and accepted.
func TestUnknownInterfaceRefused(t *testing.T) {
	t.Parallel()
	r := renderer()
	h := unitHub(t, &admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": {Link: admin.DialIn("x")}}})
	err := h.publish(t, "acme", schemaOf(implFacet(16, "acme.png", r)))
	if session.Code(err) != status.SchemaMismatch {
		t.Fatalf("unknown interface: %v", err)
	}
	rb, _ := r.Encode()
	ifaces := cbor.AppendBytes(cbor.AppendArrayHead(nil, 1), rb)
	h.Apply(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": {Link: admin.DialIn("x")}},
		Extensions: map[string][]byte{InterfacesExtension: ifaces}}, 2)
	if err := h.publish(t, "acme", schemaOf(implFacet(16, "acme.png", r))); err != nil {
		t.Fatal(err)
	}
}

// TestRelayAckLimits: a downstream session that does not ack a relayed
// update in time is closed with GoAway(schema_mismatch): RelayAckTimeout
// (5 s) for a node's update and for the change a superseding session
// brings, PeerRelayAckTimeout (2 s) for an update from a peer hub (10.3).
// The hub's sessions run on a fake clock, so the limits are the defaults.
func TestRelayAckLimits(t *testing.T) {
	t.Parallel()
	sclk := testutil.NewFakeClock()
	f := newFixture(t, func(o *Options) {
		o.Session = func(c *session.Config) { c.Clock = sclk }
	})
	f.secret("acme-1", "cred-one")
	f.secret("peer-1", "peer-cred")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1"), "hub-b": peerDialIn("peer-1")},
		Extensions: policy(grant("user:alice", "*", "use"))})
	n, err := dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "1.0.0", false, false))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := dialInNode(t, f, "websocket", "hub-b", "peer-cred", acmeFacet("remote", "1.0.0", false, false))
	if err != nil {
		t.Fatal(err)
	}
	// stall connects a client that never acks the update putting the
	// facet named facet (in the given version); stalled is signalled when
	// that update arrives, its ack timer armed by then.
	stall := func(facet, version string) (*session.Session, chan struct{}) {
		stalled, release := make(chan struct{}, 1), make(chan struct{})
		c := f.client("websocket", aliceToken, func(o *nd.Options) {
			o.Session = func(c *session.Config) {
				c.OnPeerSchemaUpdate = func(ctx context.Context, s *session.Session, u *session.PeerSchemaUpdate) error {
					for _, op := range u.Delta {
						if op.Op == schema.OpPut && op.Facet.Name == facet && op.Facet.Version == version {
							stalled <- struct{}{}
							select {
							case <-release:
							case <-s.Done():
							}
						}
					}
					return nil
				}
			}
		})
		t.Cleanup(func() { close(release) })
		waitFacet(t, c, "acme")
		waitFacet(t, c, "hub-b/remote")
		return c.Session(), stalled
	}
	// closedAt makes a change and checks that the stalled session is
	// closed at limit, and that the change takes effect (done reports it)
	// only then.
	closedAt := func(s *session.Session, stalled chan struct{}, limit time.Duration, change func() error, done func() bool) {
		t.Helper()
		changed := make(chan error, 1)
		go func() { changed <- change() }()
		select {
		case <-stalled:
		case <-time.After(10 * time.Second):
			t.Fatal("the update was not relayed")
		}
		// The relay's limit is armed (by the update itself, or, when another
		// refresh sent that update first, by the relay joining it).
		testutil.Eventually(t, 10*time.Second, func() bool { return sclk.HasTimer(limit) }, "no %v ack timer", limit)
		sclk.Advance(limit - time.Millisecond)
		select {
		case <-s.Done():
			t.Fatalf("closed before %v: %v", limit, s.Err())
		case <-time.After(20 * time.Millisecond):
		}
		if done() {
			t.Fatal("the change took effect before the stalled session was closed")
		}
		sclk.Advance(time.Millisecond)
		select {
		case <-s.Done():
		case <-time.After(10 * time.Second):
			t.Fatal("the stalled session was not closed")
		}
		if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != status.SchemaMismatch {
			t.Fatalf("closed with %+v (%v)", g, s.Err())
		}
		select {
		case err := <-changed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the change did not return")
		}
		testutil.Eventually(t, 10*time.Second, done, "the change did not take effect")
	}
	// acked reports whether a change made by fn has returned: a node's
	// update returns once the hub has acked it.
	acked := func(fn func() error) (func() error, func() bool) {
		var ok atomic.Bool
		return func() error {
			err := fn()
			ok.Store(err == nil)
			return err
		}, ok.Load
	}
	// A node's update: 5 s.
	c1, st1 := stall("acme.extra", "1.0.0")
	change, done := acked(func() error {
		_, err := n.Add(tctx(t), acmeFacet("acme.extra", "1.0.0", true, false))
		return err
	})
	closedAt(c1, st1, DefaultRelayAckTimeout, change, done)
	// An update relayed from a peer hub: 2 s.
	c2, st2 := stall("hub-b/remote2", "1.0.0")
	change, done = acked(func() error {
		_, err := peer.Add(tctx(t), acmeFacet("remote2", "1.0.0", true, false))
		return err
	})
	closedAt(c2, st2, DefaultPeerRelayAckTimeout, change, done)
	// A superseding session of acme that brings a change: 5 s again.
	c3, st3 := stall("acme", "1.1.0")
	// The new session takes calls only once every session acked or was
	// closed (10.2).
	f.h.mu.Lock()
	old := f.h.nodes["acme"].link
	f.h.mu.Unlock()
	closedAt(c3, st3, DefaultRelayAckTimeout, func() error {
		_, err := dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "1.1.0", true, false))
		return err
	}, func() bool {
		f.h.mu.Lock()
		defer f.h.mu.Unlock()
		l := f.h.nodes["acme"].link
		return l != nil && l != old
	})
}

// fakePeer is a peer hub that dials in and exports one facet.
func fakePeer(t *testing.T, f *fixture, id, cred string, calls *atomic.Int32) *nd.Node {
	b := nd.NewFacet("echo", "1.0.0")
	b.Service("E").Method("echo", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		calls.Add(1)
		v, _ := c.Input()
		return v, nil
	})
	n, err := dialInNode(t, f, "websocket", id, cred, b.MustBuild())
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, id, true)
	return n
}

// TestPeerPrincipalRules (10.8): permission_denied for a named principal
// that starts with peer:, for any call from a peer carrying a context, and
// for forwarding a call acting for a peer: principal to another peer
// (here: hub-c's carol calls node proxy, which calls hub-b/echo with its
// context).
func TestPeerPrincipalRules(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("b-1", "b-cred")
	f.secret("c-1", "c-cred")
	f.secret("proxy-1", "proxy-cred")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"hub-b": peerDialIn("b-1"), "hub-c": peerDialIn("c-1"), "proxy": dialInConfig("proxy-1")},
		Extensions: policy(grant("node:hub-c", "proxy", "use"), grant("peer:hub-c/user:carol", "proxy", "use"),
			grant("peer:hub-c/user:carol", "hub-b/echo", "use"), grant("node:proxy", "hub-b/echo", "use"))})
	var bCalls, cCalls atomic.Int32
	fakePeer(t, f, "hub-b", "b-cred", &bCalls)
	c := fakePeer(t, f, "hub-c", "c-cred", &cCalls)
	newProxyNodeOn(t, f)
	waitFacet(t, c, "proxy")
	ctx := tctx(t)
	call := func(method string, md wire.Metadata) (any, error) {
		cl, err := c.Open(ctx, "proxy", method, "x", &session.CallOptions{Metadata: md})
		if err != nil {
			return nil, err
		}
		return cl.Response(ctx)
	}
	carol := wire.Metadata{}
	carol.SetPrincipal("user:carol")
	// Acting for carol, proxy calls hub-b/echo as itself: allowed.
	if v, err := call("asSelf", carol); err != nil || v != "x" {
		t.Fatalf("as itself: %v %v", v, err)
	}
	before := bCalls.Load()
	// With carol's context the nested call acts for
	// peer:hub-c/user:carol, which is never forwarded to another peer.
	_, err := call("viaContext", carol)
	mustCode(t, err, status.PermissionDenied)
	if bCalls.Load() != before {
		t.Fatal("the refused call reached hub-b")
	}
	// A named principal that already starts with peer:.
	md := wire.Metadata{}
	md.SetPrincipal("peer:hub-x/user:carol")
	_, err = call("asSelf", md)
	mustCode(t, err, status.PermissionDenied)
	// A context from a peer.
	md = wire.Metadata{}
	md.SetContext(make([]byte, 16))
	_, err = call("asSelf", md)
	mustCode(t, err, status.PermissionDenied)
}

// TestNotificationToOfflineNodeDropped (10.7): a notification to a node
// that is offline is dropped, never delivered when it connects.
func TestNotificationToOfflineNodeDropped(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var got []any
	mk := func() *nd.Facet {
		b := nd.NewFacet("acme", "1.0.0")
		b.Service("A").Notification("poke", nd.String, func(ctx context.Context, c *session.ServerCall) error {
			v, _ := c.Input()
			mu.Lock()
			got = append(got, v)
			mu.Unlock()
			return nil
		})
		return b.MustBuild()
	}
	received := func() []any {
		mu.Lock()
		defer mu.Unlock()
		return append([]any{}, got...)
	}
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: policy(grant("user:alice", "acme", "use"))})
	first, err := dialInNode(t, f, "websocket", "acme", "cred-one", mk())
	if err != nil {
		t.Fatal(err)
	}
	cli := f.client("webtransport", aliceToken)
	waitFacet(t, cli, "acme")
	first.Close()
	waitNode(t, f.h, "acme", false) // its last known facets stay listed
	if err := cli.Notify(tctx(t), "acme", "poke", "while offline"); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool { return f.h.Stats().NotificationsDropped == 1 }, "the notification was not dropped")
	if _, err := dialInNode(t, f, "websocket", "acme", "cred-one", mk()); err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	if err := cli.Notify(tctx(t), "acme", "poke", "online"); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool { return len(received()) > 0 }, "notification not delivered while online")
	testutil.Never(t, 50*time.Millisecond, func() bool { return len(received()) > 1 }, "more than one notification delivered: %v", received())
	if r := received(); r[0] != "online" {
		t.Fatalf("a notification sent while the node was offline was delivered: %v", r)
	}
}

func mustEncode(t *testing.T, f interface{ Encode() ([]byte, error) }) []byte {
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWatchReportsEveryNode (hub-admin 4): a new watch begins with the
// Snapshot and one NodeEvent per configured node, and after every applied
// revision the hub sends a NodeEvent for every configured node, changed or
// not, naming that revision.
func TestWatchReportsEveryNode(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("a-1", "a-cred")
	f.secret("b-1", "b-cred")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"a": dialInConfig("a-1"), "b": dialInConfig("b-1")}})
	c, _ := f.adminClient("websocket")
	w, err := c.Watch(tctx(t))
	if err != nil {
		t.Fatal(err)
	}
	e := nextEv(t, w)
	if e.Snapshot == nil || e.Snapshot.Revision != 1 {
		t.Fatalf("first event %+v", e)
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		e := nextEv(t, w)
		if e.Node == nil || e.Node.Revision != 1 {
			t.Fatalf("event %d after the snapshot: %+v", i, e)
		}
		seen[e.Node.Node] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("node events after the snapshot: %v", seen)
	}
	// Revision 2 disables b and leaves a unchanged.
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"a": dialInConfig("a-1"), "b": {Link: admin.DialIn("b-1"), Enabled: boolp(false)}}})
	got := map[string]bool{}
	deadline := time.Now().Add(10 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		e := nextEv(t, w)
		if e.Node != nil && e.Node.Revision == 2 {
			got[e.Node.Node] = true
		}
	}
	if !got["a"] || !got["b"] {
		t.Fatalf("node events for revision 2: %v", got)
	}
}
