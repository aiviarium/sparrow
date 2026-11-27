package session

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func v2Schema() *schema.Schema {
	f := testFacet(tFacet, "test", method(100, "extra", u(schema.TypeString), u(schema.TypeString), 0))
	f.Version = "1.1.0"
	return testSchema("server", f)
}

// countingMux counts dispatched calls.
func countingMux(h *testHandlers, n *atomic.Int64) Handler {
	m := h.mux(tFacet)
	return rawHandler(func(ctx context.Context, c *ServerCall) {
		n.Add(1)
		m.ServeCall(ctx, c)
	})
}

func TestOptimisticMatch(t *testing.T) {
	forBindings(t, func(t *testing.T, b binding) {
		h := newTestHandlers()
		sc := testSchema("server")
		cli, _ := pair(t, b, Config{KnownSchema: sc, Optimistic: true}, Config{Schema: sc, Handler: h.mux(tFacet)})
		ctx := tctx(t)
		// NewClient returned before Welcome; this call goes in the first flight.
		out, err := cli.Unary(ctx, tFacet, mEcho, "early", nil)
		if err != nil || out != "early" {
			t.Fatalf("%v %v", out, err)
		}
		<-cli.Welcomed()
		if w := cli.Welcome(); w.ServerSchema.Kind != wire.OfferUnchanged {
			t.Fatalf("offer %v", w.ServerSchema.Kind)
		}
		// After Welcome, leases become available.
		cc, err := cli.Call(ctx, tFacet, mCount, uint64(2), nil)
		if err != nil {
			t.Fatal(err)
		}
		if b.leases && cc.Shared() {
			t.Fatal("want a lease after Welcome")
		}
		_ = cc.Wait(ctx)
	})
}

func TestOptimisticMismatch(t *testing.T) {
	forBindings(t, func(t *testing.T, b binding) {
		h := newTestHandlers()
		var dispatched atomic.Int64
		var cached []byte
		cc, sc := b.connect(t)
		srvDone := make(chan error, 1)
		sent := make(chan struct{})
		go func() {
			_, err := NewServer(context.Background(), sc, Config{Schema: v2Schema(), Handler: countingMux(h, &dispatched),
				Authenticate: func(ctx context.Context, h *wire.Hello) (string, error) {
					<-sent // the client's first flight is out
					return "", nil
				}})
			srvDone <- err
		}()
		cli, err := NewClient(context.Background(), cc, Config{KnownSchema: testSchema("server"), Optimistic: true,
			OnServerSchema: func(hash []byte, s *schema.Schema, p wire.Params) { cached = hash }})
		if err != nil {
			t.Fatal(err)
		}
		call, err := cli.Call(tctx(t), tFacet, mEcho, "stale", &CallOptions{})
		if err != nil {
			t.Fatal(err)
		}
		close(sent)
		_, err = call.Response(tctx(t))
		var e *Error
		if !errors.As(err, &e) || e.Code != status.SchemaMismatch || !e.NotDispatched {
			t.Fatalf("got %#v", err)
		}
		<-cli.Done()
		if serr := <-srvDone; Code(serr) != status.SchemaMismatch {
			t.Fatalf("server: %v", serr)
		}
		if dispatched.Load() != 0 {
			t.Fatal("a call was dispatched after a mismatch")
		}
		if !bytes.Equal(cached, schemaHash(t, v2Schema())) {
			t.Fatal("the client did not get the new schema for its cache")
		}
		if g := cli.GoAwayReceived(); g == nil || g.RetryAfterMs == nil || *g.RetryAfterMs != 0 {
			t.Fatalf("GoAway %+v", g)
		}
	})
}

func TestOptimisticLimitsBelowDefaults(t *testing.T) {
	cc, sc := mem.Pipe(mem.Options{})
	scfg := Config{Schema: testSchema("server"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxConcurrentCalls, 10)
	go func() { _, _ = NewServer(context.Background(), sc, scfg) }()
	cli, err := NewClient(context.Background(), cc, Config{KnownSchema: testSchema("server"), Optimistic: true})
	if err == nil {
		_, err = cli.Unary(tctx(t), tFacet, mEcho, "x", nil)
		mustCode(t, err, status.FailedPrecondition)
	} else if c := Code(err); c != status.FailedPrecondition && c != status.Unavailable {
		// Under load the server's GoAway can close the connection before
		// the optimistic NewClient returns.
		t.Fatal(err)
	}
	// A client that cached such limits does not try.
	p := wire.Params{}
	p.Set(wire.ParamMaxConcurrentCalls, 10)
	cc2, _ := mem.Pipe(mem.Options{})
	if _, err := NewClient(context.Background(), cc2, Config{KnownSchema: testSchema("server"), Optimistic: true, KnownParams: &p}); err == nil {
		t.Fatal("optimistic start against cached low limits")
	}
}

func TestSchemaOffers(t *testing.T) {
	old := testSchema("server")
	nw := v2Schema()
	h := newTestHandlers()
	for _, tc := range []struct {
		name  string
		known *schema.Schema
		want  wire.OfferKind
		mod   func(*Config)
	}{
		{"full", nil, wire.OfferFull, nil},
		{"unchanged", nw, wire.OfferUnchanged, nil},
		{"delta", old, wire.OfferDelta, func(c *Config) {
			c.SchemaByHash = func(h []byte) *schema.Schema {
				if bytes.Equal(h, schemaHash(t, old)) {
					return old
				}
				return nil
			}
		}},
		{"full-unknown-old", old, wire.OfferFull, nil},
		{"out-of-band", nil, wire.OfferOutOfBand, func(c *Config) {
			c.OfferLocation = func(h []byte) (string, bool) { return "https://example.invalid/schema", true }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scfg := Config{Schema: nw, Handler: h.mux(tFacet)}
			if tc.mod != nil {
				tc.mod(&scfg)
			}
			fetched := false
			ccfg := Config{KnownSchema: tc.known, FetchSchema: func(ctx context.Context, loc string, hash []byte) (*schema.Schema, error) {
				fetched = true
				return nw, nil
			}}
			cli, _ := pair(t, memBinding(), ccfg, scfg)
			if k := cli.Welcome().ServerSchema.Kind; k != tc.want {
				t.Fatalf("offer %v, want %v", k, tc.want)
			}
			if tc.want == wire.OfferOutOfBand && !fetched {
				t.Fatal("not fetched")
			}
			out, err := cli.Unary(tctx(t), tFacet, 100, "v2", nil)
			if err != nil || out != "v2" {
				// extra has no handler: unimplemented proves the schema loaded.
				if Code(err) != status.Unimplemented {
					t.Fatalf("%v %v", out, err)
				}
			}
		})
	}
}

func TestHandshakeRejections(t *testing.T) {
	sc := testSchema("server")
	t.Run("unsupported-version", func(t *testing.T) {
		p, _, ech := rawClient(t, Config{Schema: sc}, mem.Options{})
		p.send(&wire.Hello{Versions: []uint64{7, 9}})
		g := p.expectGoAway()
		if status.Code(g.Status) != status.UnsupportedVersion || len(g.Versions) != 1 || g.Versions[0] != 1 {
			t.Fatalf("got %+v", g)
		}
		mustCode(t, <-ech, status.UnsupportedVersion)
		// And a real client reports it.
		cc, scn := mem.Pipe(mem.Options{})
		go func() { _, _ = NewServer(context.Background(), scn, Config{Schema: sc}) }()
		_, err := NewClient(tctx(t), cc, Config{Versions: []uint64{7}})
		mustCode(t, err, status.UnsupportedVersion)
	})
	t.Run("unauthenticated", func(t *testing.T) {
		cc, scn := mem.Pipe(mem.Options{})
		go func() {
			_, _ = NewServer(context.Background(), scn, Config{Schema: sc, Authenticate: func(ctx context.Context, h *wire.Hello) (string, error) {
				if h.Auth == nil || h.Auth.Scheme != "bearer" {
					return "", errors.New("no ticket")
				}
				return "user:bob", nil
			}})
		}()
		_, err := NewClient(tctx(t), cc, Config{})
		mustCode(t, err, status.Unauthenticated)
	})
	t.Run("principal", func(t *testing.T) {
		auth := &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "ticket")}
		_, srv := pair(t, memBinding(), Config{Auth: auth}, Config{Schema: sc, Authenticate: func(ctx context.Context, h *wire.Hello) (string, error) {
			return "user:bob", nil
		}})
		if srv.Principal() != "user:bob" {
			t.Fatal(srv.Principal())
		}
	})
	t.Run("invalid-params", func(t *testing.T) {
		cc, scn := mem.Pipe(mem.Options{})
		go func() { _, _ = NewServer(context.Background(), scn, Config{Schema: sc}) }()
		cfg := Config{}
		cfg.Params.Set(wire.ParamSharedCredit, 100)
		_, err := NewClient(tctx(t), cc, cfg)
		mustCode(t, err, status.InvalidArgument)
	})
	t.Run("client-schema-too-large", func(t *testing.T) {
		cc, scn := mem.Pipe(mem.Options{})
		go func() { _, _ = NewServer(context.Background(), scn, Config{Schema: sc, MaxClientSchemaSize: 100}) }()
		_, err := NewClient(tctx(t), cc, Config{Schema: testSchema("client", testFacet(20, "cli"))})
		mustCode(t, err, status.InvalidArgument)
	})
	t.Run("client-schema-rejected", func(t *testing.T) {
		cc, scn := mem.Pipe(mem.Options{})
		go func() {
			_, _ = NewServer(context.Background(), scn, Config{Schema: sc, AcceptClientSchema: func(ctx context.Context, p string, s *schema.Schema) error {
				return &Error{Code: status.InvalidArgument, Message: "facet names must start with the node ID"}
			}})
		}()
		_, err := NewClient(tctx(t), cc, Config{Schema: testSchema("client", testFacet(20, "cli"))})
		mustCode(t, err, status.InvalidArgument)
	})
	t.Run("client-schema-bad-hash", func(t *testing.T) {
		p, _, _ := rawClient(t, Config{Schema: sc}, mem.Options{})
		cs := testSchema("client", testFacet(20, "cli"))
		raw, _ := cs.Canonical().Encode()
		p.send(&wire.Hello{Versions: []uint64{1}, ClientSchema: &wire.InlineSchema{Hash: make([]byte, 33), Schema: raw}})
		if g := p.expectGoAway(); status.Code(g.Status) != status.InvalidArgument {
			t.Fatalf("got %+v", g)
		}
	})
	t.Run("first-message-not-hello", func(t *testing.T) {
		p, _, _ := rawClient(t, Config{Schema: sc}, mem.Options{})
		p.send(&wire.Ping{Nonce: 1})
		if g := p.expectGoAway(); status.Code(g.Status) != status.ProtocolError {
			t.Fatalf("got %+v", g)
		}
	})
}

func TestHelloTimeout(t *testing.T) {
	clk := testutil.NewFakeClock()
	_, _, ech := rawClient(t, Config{Schema: testSchema("s"), Clock: clk}, mem.Options{})
	time.Sleep(10 * time.Millisecond)
	clk.Advance(9 * time.Second)
	select {
	case err := <-ech:
		t.Fatalf("closed early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	clk.Advance(2 * time.Second)
	select {
	case err := <-ech:
		mustCode(t, err, status.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("no Hello timeout")
	}
}

// TestPreAuthLimit: the server buffers at most 64 KiB after Hello until the
// credential is verified.
func TestPreAuthLimit(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Authenticate: func(ctx context.Context, h *wire.Hello) (string, error) {
		<-release
		return "", nil
	}}, mem.Options{})
	p.send(hello(nil))
	pad := cbor.AppendText(nil, string(make([]byte, 1000)))
	for i := 0; i < 70; i++ {
		// The server may close as soon as it has more than 64 KiB, before
		// the rest is written.
		if err := p.lane.WriteMessage((&wire.Request{CallID: 0, FacetID: tFacet, MethodID: mNotify, Input: pad}).AppendTo(nil)); err != nil {
			if i < 64 {
				t.Fatalf("send %d: %v", i, err)
			}
			break
		}
	}
	if g := p.expectGoAway(); status.Code(g.Status) != status.ResourceExhausted {
		t.Fatalf("got %+v", g)
	}
}

// TestNotReady: a call on the shared lane before Ready gets not_ready; a
// call on a leased stream before Ready waits for it (5.2).
func TestNotReady(t *testing.T) {
	h := newTestHandlers()
	p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}, mem.Options{})
	p.send(hello(nil))
	w, ok := p.recv().(*wire.Welcome)
	if !ok {
		t.Fatal("no Welcome")
	}
	p.send(reqMsg(2, tFacet, mEcho, cbor.AppendText(nil, "shared")))
	if e, ok := p.recv().(*wire.Error); !ok || status.Code(e.Status) != status.NotReady {
		t.Fatalf("got %#v", e)
	}
	ls, _ := p.conn.OpenStream(context.Background())
	lin := make(chan wire.Message, 10)
	go p.read(ls, lin)
	p.sendOn(ls, reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "leased")))
	select {
	case m := <-lin:
		t.Fatalf("dispatched before Ready: %#v", m)
	case <-time.After(50 * time.Millisecond):
	}
	p.send(&wire.Ready{SchemaHash: w.ServerSchema.Hash})
	if r, ok := recvFrom(t, lin).(*wire.Response); !ok || r.CallID != 4 {
		t.Fatalf("got %#v", r)
	}
}

// TestLeaseBeforeWelcome: a client may not open leased streams before
// Welcome.
func TestLeaseBeforeWelcome(t *testing.T) {
	release := make(chan struct{})
	p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Authenticate: func(ctx context.Context, h *wire.Hello) (string, error) {
		<-release
		return "", nil
	}}, mem.Options{})
	defer close(release)
	p.send(hello(nil))
	ls, _ := p.conn.OpenStream(context.Background())
	p.sendOn(ls, reqMsg(2, tFacet, mEcho, cbor.AppendText(nil, "x")))
	// Authenticate is still running, so Welcome has certainly not gone
	// out whenever the server takes the stream.
	if g := p.expectGoAway(); status.Code(g.Status) != status.ProtocolError {
		t.Fatalf("got %+v", g)
	}
}

// TestProtocolErrors: rule violations outside a call close the session
// with GoAway(protocol_error).
func TestProtocolErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		msgs func(p *rawPeer)
	}{
		{"malformed", func(p *rawPeer) { _ = p.lane.WriteMessage([]byte{0x83, 0x10}) }},
		{"unknown-core-kind", func(p *rawPeer) { _ = p.lane.WriteMessage(cbor.AppendUint(cbor.AppendArrayHead(nil, 1), 40)) }},
		{"wrong-parity", func(p *rawPeer) { p.send(reqMsg(3, tFacet, mEcho, cbor.AppendText(nil, "x"))) }},
		{"duplicate-id", func(p *rawPeer) {
			p.send(reqMsg(2, tFacet, mBlock, nil))
			p.send(reqMsg(2, tFacet, mBlock, nil))
		}},
		{"second-hello", func(p *rawPeer) { p.send(hello(nil)) }},
		{"authstatus-from-client", func(p *rawPeer) { p.send(&wire.AuthStatus{Status: 0}) }},
		{"ack-unknown-epoch", func(p *rawPeer) { p.send(&wire.SchemaAck{Epoch: 5}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandlers()
			p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}, mem.Options{})
			p.handshake(nil)
			tc.msgs(p)
			if g := p.expectGoAway(); status.Code(g.Status) != status.ProtocolError {
				t.Fatalf("got %+v", g)
			}
		})
	}
	t.Run("ignorable-kind", func(t *testing.T) {
		p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}, mem.Options{})
		p.handshake(nil)
		_ = p.lane.WriteMessage(cbor.AppendUint(cbor.AppendArrayHead(nil, 1), 50))
		_ = p.lane.WriteMessage(cbor.AppendUint(cbor.AppendArrayHead(nil, 1), 120))
		p.send(reqMsg(2, tFacet, mEcho, cbor.AppendText(nil, "still here")))
		if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 2 {
			t.Fatalf("got %#v", r)
		}
	})
}

// TestAuthRefresh: AuthRefresh is answered with AuthStatus.
func TestAuthRefresh(t *testing.T) {
	got := make(chan *wire.AuthStatus, 1)
	exp := cbor.Unix(1900000000)
	cli, _ := pair(t, memBinding(), Config{OnAuthStatus: func(s *Session, m *wire.AuthStatus) { got <- m }},
		Config{Schema: testSchema("s"), OnAuthRefresh: func(ctx context.Context, s *Session, a *wire.Auth) (*wire.AuthStatus, error) {
			return &wire.AuthStatus{Status: 0, ExpiresAt: &exp}, nil
		}})
	if err := cli.RefreshAuth(wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "t2")}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if m.ExpiresAt == nil || m.ExpiresAt.Sec != 1900000000 {
			t.Fatalf("%+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no AuthStatus")
	}
}
