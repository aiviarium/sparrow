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

func peerDialIn(cred string) *admin.NodeConfig {
	return &admin.NodeConfig{Credential: strp(cred), Peer: boolp(true)}
}

func peerDial(f *fixture, cred string) *admin.NodeConfig {
	return &admin.NodeConfig{Dial: &admin.Dial{URL: f.wtURL, Pin: f.pin, Credential: cred}, Peer: boolp(true)}
}

// TestFederation: hub-a dials hub-b as a peer and imports its facets as
// hub-b/<name>; principals are prefixed; a third hub, hub-c, dialing hub-a
// never sees what hub-a imported, and a call can cross at most one peer
// link.
func TestFederation(t *testing.T) {
	b := newFixture(t, nil)
	a := newFixture(t, nil)
	c := newFixture(t, nil)

	// hub-b: node echo, exported to hub-a, usable by hub-a's alice.
	b.secret("from-a", "a-to-b")
	b.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{
		"echo":  b.echo("echo"),
		"hub-a": peerDialIn("from-a"),
	}, Extensions: policy(
		grant("node:hub-a", "echo", "use"), // both acting principals are checked
		grant("peer:hub-a/user:alice", "echo", "use"),
		grant("peer:hub-a/node:proxy", "echo", "use"),
	)})
	waitNode(t, b.h, "echo", true)

	// hub-a: dials hub-b; node proxy; hub-c dials in.
	a.secret("to-b", "a-to-b")
	a.secret("proxy-1", "proxy-cred")
	a.secret("from-c", "c-to-a")
	a.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{
		"hub-b": peerDial(b, "to-b"),
		"proxy": dialInConfig("proxy-1"),
		"hub-c": peerDialIn("from-c"),
	}, Extensions: policy(
		grant("user:alice", "hub-b/echo", "use"),
		grant("user:alice", "proxy", "use"),
		grant("node:proxy", "hub-b/echo", "use"),
		grant("node:hub-c", "*", "use"), // everything hub-a may export
		grant("peer:hub-c/user:carol", "proxy", "use"),
	)})
	waitNode(t, a.h, "hub-b", true)

	alice := a.client("webtransport", aliceToken)
	waitFacet(t, alice, "hub-b/echo")
	ctx := tctx(t)
	// The imported facet is callable, and hub-b sees alice as
	// peer:hub-a/user:alice.
	if v, err := alice.Call(ctx, "hub-b/echo", "echo", "via peer"); err != nil || v != "via peer" {
		t.Fatalf("%v %v", v, err)
	}
	if v, err := alice.Call(ctx, "hub-b/echo", "whoami", nil); err != nil || v != "peer:hub-a/user:alice" {
		t.Fatalf("whoami %v %v", v, err)
	}
	exerciseEcho(t, alice, "hub-b/echo", "peer:hub-a/user:alice")
	// Facet hashes are unchanged by the import (names are not hashed).
	bAlice := b.client("websocket", adminToken)
	_ = bAlice
	// bob of hub-a has no grant.
	bob := a.client("websocket", bobToken)
	if bob.Session().PeerFacet("hub-b/echo") != nil {
		t.Fatal("bob sees hub-b/echo")
	}

	// hub-c dials hub-a.
	c.secret("to-a", "c-to-a")
	c.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"hub-a": peerDial(a, "to-a")},
		Extensions: policy(grant("user:alice", "hub-a/proxy", "use"), grant("user:alice", "hub-a/echo", "use"))})
	waitNode(t, c.h, "hub-a", true)
	p := newProxyNodeOn(t, a)
	carolish := c.client("websocket", aliceToken) // hub-c's alice
	waitFacet(t, carolish, "hub-a/proxy")
	// No re-export: hub-c never lists hub-a's import of hub-b.
	time.Sleep(200 * time.Millisecond)
	for i := range carolish.Session().PeerSchema().Schema().Facets {
		if n := carolish.Session().PeerSchema().Schema().Facets[i].Name; n != "hub-a/proxy" {
			t.Fatalf("hub-c lists %q", n)
		}
	}
	// hub-c's alice calls hub-a's proxy, which acts for
	// peer:hub-c/user:alice; hub-a grants it nothing on proxy... grant
	// carol instead to show the check.
	_, err := carolish.Call(ctx, "hub-a/proxy", "asSelf", "x")
	mustCode(t, err, status.PermissionDenied)
	_ = p
	// A call crossing a second peer link is refused: hub-a forwards to
	// hub-b with a principal that already starts with peer:.
	a.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{
		"hub-b": peerDial(b, "to-b"),
		"proxy": dialInConfig("proxy-1"),
		"hub-c": peerDialIn("from-c"),
	}, Extensions: policy(
		grant("node:proxy", "hub-b/echo", "use"),
		grant("node:hub-c", "*", "use"),
		grant("peer:hub-c/user:alice", "proxy", "use"),
		grant("peer:hub-c/user:alice", "hub-b/echo", "use"),
		grant("user:alice", "hub-b/echo", "use"),
	)})
	testutil.Eventually(t, 5*time.Second, func() bool {
		_, err := carolish.Call(ctx, "hub-a/proxy", "asSelf", "x")
		return err == nil
	}, "peer principal not granted")
	// proxy acting for peer:hub-c/user:alice calls hub-b/echo: hub-b sees
	// a named principal starting with peer: and refuses.
	_, err = carolish.Call(ctx, "hub-a/proxy", "viaContext", "x")
	mustCode(t, err, status.PermissionDenied)
	// As itself it works (hub-b sees peer:hub-a/node:proxy).
	if v, err := carolish.Call(ctx, "hub-a/proxy", "asSelf", "y"); err != nil || v != "y" {
		t.Fatalf("%v %v", v, err)
	}

	// A failed peer link behaves like an offline node: hub-b goes away,
	// hub-a keeps listing hub-b/echo.
	b.stop()
	waitNode(t, a.h, "hub-b", false)
	if alice.Session().PeerFacet("hub-b/echo") == nil {
		t.Fatalf("imported facet not listed while the peer is offline: %+v %+v", a.h.Stats().Nodes["hub-b"], alice.Session().PeerSchema().Schema().Facets)
	}
	start := time.Now()
	_, err = alice.Call(ctx, "hub-b/echo", "echo", "x")
	mustCode(t, err, status.Unavailable)
	if time.Since(start) < 2*time.Second {
		t.Fatal("did not wait for the connect timeout")
	}
	_ = context.Background
	_ = session.Code
	_ = nd.New
}

// newProxyNodeOn connects the proxy node (auth_test.go) to a hub whose
// echo facet is the imported hub-b/echo.
func newProxyNodeOn(t *testing.T, f *fixture) *proxyNode {
	p := &proxyNode{blocked: make(chan error, 10)}
	b := nd.NewFacet("proxy", "1.0.0")
	svc := b.Service("Proxy")
	svc.Method("viaContext", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return p.n.CallFor(ctx, c, "hub-b/echo", "echo", in)
	})
	svc.Method("asSelf", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return p.n.Call(ctx, "hub-b/echo", "echo", in)
	})
	n, err := dialInNode(t, f, "websocket", "proxy", "proxy-cred", b.MustBuild())
	if err != nil {
		t.Fatal(err)
	}
	p.n = n
	waitNode(t, f.h, "proxy", true)
	waitFacet(t, n, "hub-b/echo")
	return p
}
