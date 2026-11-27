package hub

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
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
	f := acmeHub(t)
	n, err := dialInNode(t, f, "webtransport", "acme", "cred-one", acmeFacet("acme", "1.0.0", false, false))
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	// A client that takes its time to acknowledge schema updates.
	slow := f.client("websocket", aliceToken, func(o *nd.Options) {
		o.Session = func(c *session.Config) {
			c.OnPeerSchemaUpdate = func(ctx context.Context, s *session.Session, u *session.PeerSchemaUpdate) error {
				time.Sleep(400 * time.Millisecond)
				return nil
			}
		}
	})
	fast := f.client("webtransport", aliceToken)
	waitFacet(t, slow, "acme")
	waitFacet(t, fast, "acme")
	start := time.Now()
	if _, err := n.Add(tctx(t), acmeFacet("acme.extra", "1.0.0", true, false)); err != nil {
		t.Fatal(err)
	}
	// The hub acknowledged the node only after every client had
	// acknowledged: when Add returns, both clients already list the facet.
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Fatalf("the node was acked after %v, before the slow client acked", d)
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
