package hub

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
)

// acmeFacet builds facet name at version with ping, and optionally hello
// (a method added in a compatible version) and an incompatible ping.
func acmeFacet(name, version string, hello, incompatible bool) *nd.Facet {
	b := nd.NewFacet(name, version)
	svc := b.Service("Acme")
	in := nd.Unit
	if incompatible {
		in = nd.String
	}
	svc.Method("ping", in, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) { return "pong " + version, nil })
	if hello {
		svc.Method("hello", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
			v, _ := c.Input()
			return "hello " + v.(string), nil
		})
	}
	return b.MustBuild()
}

func acmeHub(t *testing.T) *fixture {
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")},
		Extensions: policy(grant("user:alice", "acme", "use"), grant("user:alice", "acme.*", "use"))})
	return f
}

func TestSchemaUpdateRelayedWithAckGating(t *testing.T) {
	t.Parallel()
	f := acmeHub(t)
	n, err := dialInNode(t, f, "webtransport", "acme", "cred-one", acmeFacet("acme", "1.0.0", false, false))
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	// A client that holds back its acknowledgement of the update that
	// adds acme.extra until the test releases it.
	held, release := make(chan struct{}, 1), make(chan struct{})
	slow := f.client("websocket", aliceToken, func(o *nd.Options) {
		o.Session = func(c *session.Config) {
			c.OnPeerSchemaUpdate = func(ctx context.Context, s *session.Session, u *session.PeerSchemaUpdate) error {
				for _, op := range u.Delta {
					if op.Op == schema.OpPut && op.Facet.Name == "acme.extra" {
						held <- struct{}{}
						<-release
					}
				}
				return nil
			}
		}
	})
	fast := f.client("webtransport", aliceToken)
	waitFacet(t, slow, "acme")
	waitFacet(t, fast, "acme")
	added := make(chan error, 1)
	go func() {
		_, err := n.Add(tctx(t), acmeFacet("acme.extra", "1.0.0", true, false))
		added <- err
	}()
	<-held
	// The fast client has the facet, but the hub acknowledges the node
	// only after every client has acknowledged.
	waitFacet(t, fast, "acme.extra")
	testutil.Never(t, 50*time.Millisecond, func() bool { return len(added) > 0 }, "the node was acked before the slow client acked")
	close(release)
	if err := <-added; err != nil {
		t.Fatal(err)
	}
	for _, c := range []*nd.Node{slow, fast} {
		if c.Session().PeerFacet("acme.extra") == nil {
			t.Fatal("a client does not list the new facet although the node was acked")
		}
	}
	if v, err := fast.Call(tctx(t), "acme.extra", "hello", "you"); err != nil || v != "hello you" {
		t.Fatalf("%v %v", v, err)
	}
	// Removing a facet relays a removal.
	if err := n.Remove(tctx(t), "acme.extra"); err != nil {
		t.Fatal(err)
	}
	if fast.Session().PeerFacet("acme.extra") != nil {
		t.Fatal("removed facet still listed after the ack")
	}
}

func TestSupersede(t *testing.T) {
	t.Parallel()
	f := acmeHub(t)
	n1, err := dialInNode(t, f, "webtransport", "acme", "cred-one", acmeFacet("acme", "1.0.0", false, false))
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	cli := f.client("websocket", aliceToken)
	id := waitFacet(t, cli, "acme")
	if v, err := cli.Call(tctx(t), "acme", "ping", nil); err != nil || v != "pong 1.0.0" {
		t.Fatalf("%v %v", v, err)
	}
	s1 := n1.Session()
	// A new session of the same node with a compatible change (an added
	// method) supersedes the old one: the change is relayed first, then
	// the old session gets GoAway(going_away).
	n2, err := dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "1.1.0", true, false))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s1.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("old session not ended")
	}
	if g := s1.GoAwayReceived(); g == nil || status.Code(g.Status) != status.GoingAway {
		t.Fatalf("old session got %v", g)
	}
	if got := waitFacet(t, cli, "acme"); got != id {
		t.Fatalf("facet ID changed %d -> %d within a major version", id, got)
	}
	testutil.Eventually(t, 5*time.Second, func() bool {
		f := cli.Session().PeerFacet("acme")
		return f != nil && f.Version == "1.1.0"
	}, "client has not seen 1.1.0")
	if v, err := cli.Call(tctx(t), "acme", "hello", "x"); err != nil || v != "hello x" {
		t.Fatalf("%v %v", v, err)
	}
	if v, err := cli.Call(tctx(t), "acme", "ping", nil); err != nil || v != "pong 1.1.0" {
		t.Fatalf("calls still go to the old session: %v %v", v, err)
	}
	// An incompatible version within the same major is refused with
	// schema_mismatch, and the current session keeps serving.
	_, err = dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "1.2.0", true, true))
	mustCode(t, err, status.SchemaMismatch)
	if v, err := cli.Call(tctx(t), "acme", "ping", nil); err != nil || v != "pong 1.1.0" {
		t.Fatalf("%v %v", v, err)
	}
	// A new major version is a new facet with a new ID.
	n3, err := dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "2.0.0", false, true))
	if err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool {
		f := cli.Session().PeerFacet("acme")
		return f != nil && f.Version == "2.0.0" && f.ID != id
	}, "no new facet for the new major version")
	_ = n2
	// Mid-session: removing the facet and adding an incompatible one under
	// the same name and major is refused (the hub checks against the last
	// version it listed), closing the session with schema_mismatch.
	if err := n3.Remove(tctx(t), "acme"); err != nil {
		t.Fatal(err)
	}
	s3 := n3.Session()
	_, err = n3.Add(tctx(t), acmeFacet("acme", "2.1.0", false, false))
	if err == nil {
		t.Fatal("incompatible update accepted")
	}
	<-s3.Done()
	if code := session.Code(s3.Err()); code != status.SchemaMismatch {
		t.Fatalf("session ended with %v", s3.Err())
	}
}

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
