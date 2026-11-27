package hub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// proxyNode is a dial-in node "proxy" whose methods call facet echo for
// the caller (with the call context), as itself (without one), and with a
// stored or forged context.
type proxyNode struct {
	n       *nd.Node
	mu      sync.Mutex
	saved   []byte
	blocked chan error
}

func newProxyNode(t *testing.T, f *fixture) *proxyNode {
	p := &proxyNode{blocked: make(chan error, 10)}
	b := nd.NewFacet("proxy", "1.0.0")
	svc := b.Service("Proxy")
	svc.Method("viaContext", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return p.n.CallFor(ctx, c, "echo", "echo", in)
	})
	svc.Method("asSelf", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return p.n.Call(ctx, "echo", "echo", in)
	})
	svc.Method("save", nd.Unit, nd.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		cc, _ := c.CallContext()
		p.mu.Lock()
		p.saved = cc
		p.mu.Unlock()
		return nil, nil
	})
	svc.Method("block", nd.Unit, nd.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		<-ctx.Done()
		p.blocked <- context.Cause(ctx)
		return nil, context.Cause(ctx)
	})
	n, err := dialInNode(t, f, "websocket", "proxy", "proxy-cred", b.MustBuild())
	if err != nil {
		t.Fatal(err)
	}
	p.n = n
	waitNode(t, f.h, "proxy", true)
	return p
}

// callWithContext calls echo from the proxy node with a given context.
func (p *proxyNode) callWithContext(ctx context.Context, cc []byte) (any, error) {
	md := wire.Metadata{}
	md.SetContext(cc)
	call, err := p.n.Open(ctx, "echo", "echo", "x", &session.CallOptions{Metadata: md})
	if err != nil {
		return nil, err
	}
	return call.Response(ctx)
}

func authHub(t *testing.T, tune func(*Options), grants ...Grant) *fixture {
	f := newFixture(t, tune)
	f.secret("proxy-1", "proxy-cred")
	f.commitAuth(grants...)
	return f
}

func (f *fixture) commitAuth(grants ...Grant) uint64 {
	return f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{
		"echo":  f.echo("echo"),
		"proxy": dialInConfig("proxy-1"),
	}, Extensions: policy(grants...)})
}

func TestAuthorizationGrants(t *testing.T) {
	t.Parallel()
	f := authHub(t, nil, grant("group:eng", "echo", "view"), grant("user:bob", "echo", "use"))
	waitNode(t, f.h, "echo", true)
	alice := f.client("websocket", aliceToken)
	bob := f.client("webtransport", bobToken)
	carol := f.client("websocket", adminToken) // bootstrap admin: only the admin facet
	waitFacet(t, alice, "echo")
	waitFacet(t, bob, "echo")
	if carol.Session().PeerFacet("echo") != nil || carol.Session().PeerFacet("sparrow.hub.admin") == nil {
		t.Fatal("admin view")
	}
	if alice.Session().PeerFacet("sparrow.hub.admin") != nil {
		t.Fatal("alice sees the admin facet")
	}
	// view lists the facet, but calling needs use (via the group).
	_, err := alice.Call(tctx(t), "echo", "echo", "x")
	mustCode(t, err, status.PermissionDenied)
	if v, err := bob.Call(tctx(t), "echo", "echo", "x"); err != nil || v != "x" {
		t.Fatalf("%v %v", v, err)
	}
	// Upgrading the grant reaches alice's session as authorization change.
	f.commitAuth(grant("group:eng", "echo", "use"), grant("user:bob", "echo", "use"))
	testutil.Eventually(t, 5*time.Second, func() bool {
		_, err := alice.Call(tctx(t), "echo", "echo", "x")
		return err == nil
	}, "alice still denied")
	// Revoking bob removes the facet from his schema with a SchemaUpdate.
	f.commitAuth(grant("group:eng", "echo", "use"))
	waitNoFacet(t, bob, "echo")
	// Calling the ID anyway fails (IDs are not secrets).
	fid := waitFacet(t, alice, "echo")
	call, err := bob.Session().OpenRaw(tctx(t), session.RawRequest{FacetID: fid, MethodID: 0, Input: []byte{0x61, 'x'}}, &session.CallOptions{Flags: new(uint64)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = call.ResponseRaw(tctx(t))
	if c := session.Code(err); c != status.Unimplemented && c != status.PermissionDenied {
		t.Fatalf("got %v", err)
	}
}

func TestContextActingPrincipals(t *testing.T) {
	t.Parallel()
	clk := testutil.NewFakeClock()
	f := authHub(t, func(o *Options) { o.Clock = clk },
		grant("user:alice", "proxy", "use"), grant("user:bob", "proxy", "use"),
		grant("user:alice", "echo", "use"), grant("node:proxy", "echo", "use"))
	waitNode(t, f.h, "echo", true)
	p := newProxyNode(t, f)
	waitFacet(t, p.n, "echo")
	alice := f.client("websocket", aliceToken)
	bob := f.client("webtransport", bobToken)
	waitFacet(t, alice, "proxy")
	waitFacet(t, bob, "proxy")
	ctx := tctx(t)
	// alice and node:proxy are both allowed.
	if v, err := alice.Call(ctx, "proxy", "viaContext", "hi"); err != nil || v != "hi" {
		t.Fatalf("%v %v", v, err)
	}
	// bob is not allowed on echo: the nested call acting for him fails,
	// although node:proxy alone would be allowed.
	_, err := bob.Call(ctx, "proxy", "viaContext", "hi")
	mustCode(t, err, status.PermissionDenied)
	if v, err := bob.Call(ctx, "proxy", "asSelf", "hi"); err != nil || v != "hi" {
		t.Fatalf("as itself: %v %v", v, err)
	}
	// A forged context is refused and never falls back to node:proxy.
	_, err = p.callWithContext(ctx, []byte("0123456789abcdef"))
	mustCode(t, err, status.PermissionDenied)
	// A context stays valid for 2 s after its call ended, then not.
	if _, err := alice.Call(ctx, "proxy", "save", nil); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	saved := p.saved
	p.mu.Unlock()
	if v, err := p.callWithContext(ctx, saved); err != nil || v != "x" {
		t.Fatalf("within the grace period: %v %v", v, err)
	}
	// The hub ends the context once it has relayed the call's end, which
	// may be just after alice has the response.
	testutil.Eventually(t, 5*time.Second, func() bool {
		f.h.mu.Lock()
		defer f.h.mu.Unlock()
		cc := f.h.contexts[string(saved)]
		return cc != nil && !cc.open
	}, "the context was not ended with its call")
	clk.Advance(2100 * time.Millisecond)
	testutil.Eventually(t, 5*time.Second, func() bool {
		_, err := p.callWithContext(ctx, saved)
		return session.Code(err) == status.PermissionDenied
	}, "expired context accepted")
	// Without node:proxy's own grant, even alice's context does not help.
	f.commitAuth(grant("user:alice", "proxy", "use"), grant("user:alice", "echo", "use"))
	waitNoFacet(t, p.n, "echo")
	_, err = alice.Call(ctx, "proxy", "viaContext", "hi")
	if c := session.Code(err); c != status.PermissionDenied && c != status.Unimplemented {
		t.Fatalf("got %v", err)
	}
}

func TestPolicyChangeEndsCalls(t *testing.T) {
	t.Parallel()
	f := authHub(t, nil, grant("user:alice", "proxy", "use"))
	p := newProxyNode(t, f)
	_ = p
	alice := f.client("websocket", aliceToken)
	waitFacet(t, alice, "proxy")
	ctx := tctx(t)
	call, err := alice.Open(ctx, "proxy", "block", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool { return f.h.Stats().ActiveCalls == 1 }, "call not running")
	f.commitAuth() // no grants at all
	_, err = call.Response(ctx)
	mustCode(t, err, status.PermissionDenied)
	select {
	case cause := <-p.blocked:
		mustCode(t, cause, status.PermissionDenied)
	case <-time.After(5 * time.Second):
		t.Fatal("the node's call was not cancelled")
	}
	waitNoFacet(t, alice, "proxy")
}
