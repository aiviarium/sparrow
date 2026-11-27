package hub

import (
	"context"
	"strings"
	"sync"
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

// worker is a dial-in node with methods for the forwarding edge cases.
type worker struct {
	n       *nd.Node
	mu      sync.Mutex
	md      []wire.Metadata
	causes  chan error
	started chan struct{}
}

func newWorker(t *testing.T, f *fixture, binding string, tune func(*nd.Options), extra ...func(*nd.FacetBuilder)) *worker {
	w := &worker{causes: make(chan error, 10), started: make(chan struct{}, 10)}
	b := nd.NewFacet("work", "1.0.0")
	svc := b.Service("Work")
	svc.Method("meta", nd.Unit, nd.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		w.mu.Lock()
		w.md = append(w.md, c.Metadata().Clone())
		w.mu.Unlock()
		return nil, nil
	})
	svc.Method("big", nd.Uint, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return strings.Repeat("x", int(in.(uint64))), nil
	})
	svc.Method("take", nd.String, nd.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return uint64(len(in.(string))), nil
	})
	svc.Method("block", nd.Unit, nd.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		w.started <- struct{}{}
		<-ctx.Done()
		w.causes <- context.Cause(ctx)
		return nil, context.Cause(ctx)
	})
	svc.Notification("note", nd.String, func(ctx context.Context, c *session.ServerCall) error {
		w.mu.Lock()
		w.md = append(w.md, c.Metadata().Clone())
		w.mu.Unlock()
		return nil
	})
	for _, e := range extra {
		e(b)
	}
	o := nd.Options{Auth: linkAuth("work-cred"), Logger: testLogger(t)}
	if tune != nil {
		tune(&o)
	}
	n := nd.New(o)
	if _, err := n.Add(tctx(t), b.MustBuild()); err != nil {
		t.Fatal(err)
	}
	if err := n.Dial(tctx(t), f.url(binding), nd.DialOptions{CertHashes: [][]byte{f.certHash}}); err != nil {
		t.Fatal(err)
	}
	f.onCleanup(n.Close)
	w.n = n
	waitNode(t, f.h, "work", true)
	return w
}

func workHub(t *testing.T, tune func(*Options)) *fixture {
	f := newFixture(t, tune)
	f.secret("work-1", "work-cred")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"work": dialInConfig("work-1")},
		Extensions: policy(grant("user:alice", "work", "use"))})
	return f
}

func TestForwardedMetadata(t *testing.T) {
	f := workHub(t, nil)
	w := newWorker(t, f, "websocket", nil)
	for _, b := range transports {
		cli := f.client(b, aliceToken)
		waitFacet(t, cli, "work")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := cli.Call(ctx, "work", "meta", nil); err != nil {
			t.Fatal(err)
		}
		cancel()
		// Notifications carry the principal but no context (10.5).
		if err := cli.Notify(tctx(t), "work", "note", "n"); err != nil {
			t.Fatal(err)
		}
		testutil.Eventually(t, 5*time.Second, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return len(w.md) == 2 }, "notification not relayed")
		w.mu.Lock()
		call, note := w.md[0], w.md[1]
		w.md = nil
		w.mu.Unlock()
		dl, ok, _ := call.Deadline()
		if !ok || dl > 5000 || dl < 4000 {
			t.Fatalf("%s: deadline %d: lowered by the time spent, never raised", b, dl)
		}
		cr, ok, _ := call.Credit()
		wantCredit := uint64(64 << 10) // the caller's shared-lane default
		if b == "webtransport" {
			wantCredit = 1 << 20 // its leased stream's default
		}
		if !ok || cr > wantCredit {
			t.Fatalf("%s: credit %d > %d", b, cr, wantCredit)
		}
		if p, _, _ := note.Principal(); p != "user:alice" {
			t.Fatalf("notification principal %q", p)
		}
		if _, ok, _ := note.Context(); ok {
			t.Fatal("a notification got a context")
		}
	}
}

func TestMessageTooLarge(t *testing.T) {
	f := workHub(t, nil)
	// The node accepts at most 16 KiB messages.
	newWorker(t, f, "websocket", func(o *nd.Options) { o.Params.Set(wire.ParamMaxMessageSize, 16384) })
	cli := f.client("webtransport", aliceToken, func(o *nd.Options) { o.Params.Set(wire.ParamMaxMessageSize, 16384) })
	waitFacet(t, cli, "work")
	ctx := tctx(t)
	// Caller -> node: the forwarded Request does not fit the node's limit.
	_, err := cli.Call(ctx, "work", "take", strings.Repeat("y", 15000))
	if err != nil {
		t.Fatalf("small enough: %v", err)
	}
	// A 17 KiB request fits the hub (default 1 MiB) but not the node.
	cc, err := cli.Session().Call(ctx, cli.Session().PeerFacet("work").ID, 2, strings.Repeat("y", 17000), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cc.Response(ctx)
	mustCode(t, err, status.MessageTooLarge)
	// Node -> caller: a 20 KiB Response does not fit the client's limit.
	_, err = cli.Call(ctx, "work", "big", uint64(20000))
	mustCode(t, err, status.MessageTooLarge)
	if v, err := cli.Call(ctx, "work", "big", uint64(10)); err != nil || v != strings.Repeat("x", 10) {
		t.Fatalf("%v %v", v, err)
	}
}

func TestLinkDrops(t *testing.T) {
	f := workHub(t, nil)
	w := newWorker(t, f, "webtransport", nil)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "work")
	ctx := tctx(t)
	// The caller goes away: the node's call is cancelled with unavailable.
	c2 := f.client("webtransport", aliceToken)
	waitFacet(t, c2, "work")
	if _, err := c2.Open(ctx, "work", "block", nil, nil); err != nil {
		t.Fatal(err)
	}
	<-w.started
	c2.Session().Close(status.OK, "bye")
	select {
	case cause := <-w.causes:
		mustCode(t, cause, status.Unavailable)
	case <-time.After(10 * time.Second):
		t.Fatal("node call not cancelled")
	}
	// The node goes away: the caller gets unavailable.
	call, err := cli.Open(ctx, "work", "block", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-w.started
	w.n.Session().Close(status.OK, "node crash")
	_, err = call.Response(ctx)
	mustCode(t, err, status.Unavailable)
}

func TestNodeSchemaLimit(t *testing.T) {
	f := workHub(t, nil)
	// A node schema far above 64 KiB is fine between a hub and its nodes
	// (10.2).
	doc := cbor.AppendText(nil, strings.Repeat("documentation ", 8000))
	w := newWorker(t, f, "websocket", nil, func(b *nd.FacetBuilder) {
		b.Annotation("doc", doc)
	})
	_ = w
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "work")
	// A client publishing such a schema is refused.
	big := nd.NewFacet("client.big", "1.0.0").Annotation("doc", doc)
	big.Service("S").Method("m", nd.Unit, nd.Unit, nil)
	n := nd.New(nd.Options{Auth: bearer(aliceToken)})
	if _, err := n.Add(tctx(t), big.MustBuild()); err != nil {
		t.Fatal(err)
	}
	err := n.Dial(tctx(t), f.wsURL, nd.DialOptions{})
	mustCode(t, err, status.InvalidArgument)
}

func TestContextGraceCancelsNested(t *testing.T) {
	clk := testutil.NewFakeClock()
	f := newFixture(t, func(o *Options) { o.Clock = clk })
	f.secret("work-1", "work-cred")
	f.secret("proxy-1", "proxy-cred")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"work": dialInConfig("work-1"), "proxy": dialInConfig("proxy-1")},
		Extensions: policy(grant("user:alice", "proxy", "use"), grant("user:alice", "work", "use"), grant("node:proxy", "work", "use"))})
	w := newWorker(t, f, "websocket", nil)
	nested := make(chan error, 1)
	b := nd.NewFacet("proxy", "1.0.0")
	var p *nd.Node
	b.Service("P").Method("fire", nd.Unit, nd.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		md := wire.Metadata{}
		cc, _ := c.CallContext()
		md.SetContext(cc)
		call, err := p.Open(context.Background(), "work", "block", nil, &session.CallOptions{Metadata: md})
		if err != nil {
			return nil, err
		}
		go func() { _, err := call.Response(context.Background()); nested <- err }()
		<-w.started
		return nil, nil // the parent call ends; the nested one is still running
	})
	var err error
	p, err = dialInNode(t, f, "websocket", "proxy", "proxy-cred", b.MustBuild())
	if err != nil {
		t.Fatal(err)
	}
	waitFacet(t, p, "work")
	cli := f.client("webtransport", aliceToken)
	waitFacet(t, cli, "proxy")
	if _, err := cli.Call(tctx(t), "proxy", "fire", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-nested:
		t.Fatalf("nested call ended within the grace period: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	clk.Advance(2100 * time.Millisecond)
	select {
	case err := <-nested:
		mustCode(t, err, status.PermissionDenied)
	case <-time.After(5 * time.Second):
		t.Fatal("nested call not ended after the grace period")
	}
	select {
	case cause := <-w.causes:
		mustCode(t, cause, status.PermissionDenied)
	case <-time.After(5 * time.Second):
		t.Fatal("the node's nested call was not cancelled")
	}
}

func TestWebFacetStub(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Web = true })
	cli := f.client("websocket", bobToken)
	fc := cli.Session().PeerFacet(schema.WebFacetName)
	if fc == nil || fc.ID != schema.WebFacetID {
		t.Fatal("no facet 1 sparrow.web")
	}
	if err := cli.Notify(tctx(t), schema.WebFacetName, "moduleRejected", []any{"acme.charts", "1.0.0", "hostApi"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if cli.Session().Err() != nil {
		t.Fatal(cli.Session().Err())
	}
}
