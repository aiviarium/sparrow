package session

import (
	"context"
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

// streamForever sends an item every millisecond until cancelled.
func streamForever(ctx context.Context, c *ServerCall) (any, error) {
	for i := uint64(0); ; i++ {
		if err := c.Send(ctx, i); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(time.Millisecond):
		}
	}
}

func TestSchemaUpdateAckGating(t *testing.T) {
	forBindings(t, func(t *testing.T, b binding) {
		f16 := testFacet(tFacet, "test")
		f17 := testFacet(17, "other")
		sc := testSchema("server", f16, f17)
		m := NewMux()
		for _, f := range []uint64{16, 17} {
			m.HandleFunc(f, mWatch, streamForever)
		}
		m.HandleFunc(16, 100, func(ctx context.Context, c *ServerCall) (any, error) { return c.Input() })
		allow := make(chan struct{})
		var hookCalls atomic.Int64
		ccfg := Config{OnPeerSchemaUpdate: func(ctx context.Context, s *Session, u *PeerSchemaUpdate) error {
			hookCalls.Add(1)
			if u.Epoch != 1 || u.New.Epoch() != 1 {
				t.Errorf("epoch %d", u.Epoch)
			}
			<-allow
			return nil
		}}
		cli, srv := pair(t, b, ccfg, Config{Schema: sc, Handler: m})
		ctx := tctx(t)
		var n16, n17 atomic.Int64
		start := func(f uint64, n *atomic.Int64) *ClientCall {
			cc, err := cli.Call(ctx, f, mWatch, uint64(0), &CallOptions{Lane: LaneLeased})
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				for {
					if _, err := cc.Recv(ctx); err != nil {
						return
					}
					n.Add(1)
				}
			}()
			return cc
		}
		c16, c17 := start(16, &n16), start(17, &n17)
		testutil.Eventually(t, 5*time.Second, func() bool { return n16.Load() > 5 && n17.Load() > 5 }, "streams not flowing")

		// Replace facet 16 (a new method); facet 17 is unchanged.
		g16 := testFacet(tFacet, "test", method(100, "extra", u(schema.TypeString), u(schema.TypeString), 0))
		g16.Version = "1.1.0"
		upd, err := srv.UpdateSchema(testSchema("server", g16, f17), SchemaUpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		testutil.Eventually(t, 5*time.Second, func() bool { return hookCalls.Load() == 1 }, "update not received")
		time.Sleep(30 * time.Millisecond)
		a16, a17 := n16.Load(), n17.Load()
		time.Sleep(100 * time.Millisecond)
		if d := n16.Load() - a16; d > 0 {
			t.Fatalf("facet 16 sent %d items before the ack", d)
		}
		if d := n17.Load() - a17; d < 5 {
			t.Fatalf("facet 17 was held back too (%d items)", d)
		}
		// The client already applied the delta and may call the new method.
		if cli.PeerSchema().Epoch() != 1 {
			t.Fatal("peer epoch")
		}
		close(allow)
		if err := upd.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		b16 := n16.Load()
		testutil.Eventually(t, 5*time.Second, func() bool { return n16.Load() > b16+5 }, "facet 16 did not resume")
		out, err := cli.Unary(ctx, 16, 100, "new", nil)
		if err != nil || out != "new" {
			t.Fatalf("%v %v", out, err)
		}
		if st := srv.Stats(); st.LocalEpoch != 1 || st.LocalAcked != 1 {
			t.Fatalf("%+v", st)
		}
		_ = c16.Cancel(status.Cancelled)
		_ = c17.Cancel(status.Cancelled)
	})
}

func TestSchemaUpdateRemoveFacet(t *testing.T) {
	h := newTestHandlers()
	f16, f17 := testFacet(tFacet, "test"), testFacet(17, "other")
	m := h.mux(16)
	h.register(m, 17)
	cli, srv := pair(t, memBinding(), Config{}, Config{Schema: testSchema("s", f16, f17), Handler: m})
	ctx := tctx(t)
	running, err := cli.Call(ctx, 17, mBlock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-h.started
	upd, err := srv.UpdateSchema(testSchema("s", f16), SchemaUpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := upd.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	// New calls to the removed facet fail; the running call finishes.
	flags := uint64(0)
	cc, err := cli.OpenRaw(ctx, RawRequest{FacetID: 17, MethodID: mEcho, Input: cbor.AppendText(nil, "x")}, &CallOptions{Flags: &flags})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := cc.RecvRaw(ctx); err != nil || status.Code(m.Message.(*wire.Error).Status) != status.Unimplemented {
		t.Fatalf("%v %v", m, err)
	}
	close(h.block)
	if _, err := running.Response(ctx); err != nil {
		t.Fatal(err)
	}
	// Re-adding facet 17 under the same name and major version works.
	if _, err := srv.UpdateSchema(testSchema("s", f16, f17), SchemaUpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// An incompatible replacement is refused locally.
	bad := testFacet(tFacet, "test")
	bad.Services[0].Methods[0].Input = u(schema.TypeUint)
	if _, err := srv.UpdateSchema(testSchema("s", bad, f17), SchemaUpdateOptions{}); err == nil {
		t.Fatal("incompatible update accepted")
	}
}

func TestSchemaAckTimeout(t *testing.T) {
	clk := testutil.NewFakeClock()
	block := make(chan struct{})
	defer close(block)
	_, srv := pair(t, memBinding(), Config{OnPeerSchemaUpdate: func(ctx context.Context, s *Session, u *PeerSchemaUpdate) error {
		<-block
		return nil
	}}, Config{Schema: testSchema("s"), Clock: clk})
	f := testFacet(tFacet, "test")
	f.Version = "1.0.1"
	if _, err := srv.UpdateSchema(testSchema("s", f), SchemaUpdateOptions{AckTimeout: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(6 * time.Second)
	testutil.Eventually(t, 5*time.Second, func() bool { return srv.Stats().Closed }, "not closed")
	mustCode(t, srv.Err(), status.SchemaMismatch)
}

func TestSchemaUpdateBadHash(t *testing.T) {
	// A raw server whose SchemaUpdate names the wrong hash.
	cc, sc := mem.Pipe(mem.Options{})
	sch := testSchema("s")
	go func() {
		lane, _ := sc.SharedLane(context.Background())
		p := newRawPeer(t, sc, lane)
		if _, ok := p.recv().(*wire.Hello); !ok {
			return
		}
		raw, _ := sch.Canonical().Encode()
		p.send(&wire.Welcome{Version: 1, SessionID: make([]byte, 16), ServerSchema: wire.SchemaOffer{Kind: wire.OfferFull, Hash: schemaHash(t, sch), Schema: raw}})
		p.recv() // Ready
		f := testFacet(tFacet, "test")
		f.Version = "1.0.1"
		d := schema.Delta{{Op: schema.OpPut, Facet: &f}}
		dr, _ := d.Encode()
		p.send(&wire.SchemaUpdate{Epoch: 1, Hash: make([]byte, 33), Delta: dr})
		p.recv()
	}()
	cli, err := NewClient(tctx(t), cc, Config{})
	if err != nil {
		// The raw server sends the update right after Ready, so the
		// session may already have closed when NewClient checks it.
		mustCode(t, err, status.SchemaMismatch)
		return
	}
	<-cli.Done()
	mustCode(t, cli.Err(), status.SchemaMismatch)
}

// TestClientSchemaUpdate: a client publishes a new facet; the server calls it.
func TestClientSchemaUpdate(t *testing.T) {
	h := newTestHandlers()
	m := h.mux(20)
	h.register(m, 21)
	cs := testSchema("client", testFacet(20, "cli"))
	cli, srv := pair(t, memBinding(), Config{Schema: cs, Handler: m}, Config{Schema: testSchema("s")})
	upd, err := cli.UpdateSchema(testSchema("client", testFacet(20, "cli"), testFacet(21, "cli.more")), SchemaUpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := tctx(t)
	if err := upd.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	out, err := srv.Unary(ctx, 21, mEcho, "hi", nil)
	if err != nil || out != "hi" {
		t.Fatalf("%v %v", out, err)
	}
	if srv.PeerFacet("cli.more") == nil {
		t.Fatal("PeerFacet")
	}
}
