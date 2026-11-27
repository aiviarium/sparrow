package session

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport/mem"
	"github.com/aiviarium/sparrow/go/wire"
)

// Behaviour decided in core rev316.

// TestNotificationWithCallID: a Request with a nonzero call ID for a
// notification method gets Error(invalid_argument); a call-ID-0 Request
// for a method without flag 0x2 is dropped (7.1).
func TestNotificationWithCallID(t *testing.T) {
	t.Parallel()
	h := newTestHandlers()
	p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}, mem.Options{NoLeases: true})
	p.handshake(nil)
	p.send(reqMsg(2, tFacet, mNotify, cbor.AppendText(nil, "x")))
	if e, ok := p.recv().(*wire.Error); !ok || e.CallID != 2 || status.Code(e.Status) != status.InvalidArgument {
		t.Fatalf("got %#v", e)
	}
	p.send(reqMsg(0, tFacet, mEcho, cbor.AppendText(nil, "dropped")))
	p.send(reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "next")))
	if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 4 {
		t.Fatalf("the call-ID-0 echo was not dropped: %#v", r)
	}
}

// TestReadyMismatch: a Ready naming another hash closes the session with
// GoAway(schema_mismatch) (5.2).
func TestReadyMismatch(t *testing.T) {
	t.Parallel()
	p, _, ech := rawClient(t, Config{Schema: testSchema("s")}, mem.Options{})
	p.send(hello(nil))
	if _, ok := p.recv().(*wire.Welcome); !ok {
		t.Fatal("no Welcome")
	}
	p.send(&wire.Ready{SchemaHash: append([]byte{1}, make([]byte, 32)...)})
	if g := p.expectGoAway(); status.Code(g.Status) != status.SchemaMismatch {
		t.Fatalf("got %+v", g)
	}
	if err := <-ech; Code(err) != status.SchemaMismatch {
		t.Fatalf("NewServer: %v", err)
	}
}

// TestCancelAfterCallerHalf: Cancel is valid while the callee's half is
// open even when the caller's half is already finished (7.5); the callee
// answers Error(cancelled).
func TestCancelAfterCallerHalf(t *testing.T) {
	t.Parallel()
	h := newTestHandlers()
	p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}, mem.Options{NoLeases: true})
	p.handshake(nil)
	p.send(reqMsg(2, tFacet, mBlock, nil)) // unary: the Request finishes the caller's half
	select {
	case <-h.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the call was not dispatched")
	}
	p.send(&wire.Cancel{CallID: 2, Status: uint64(status.Cancelled)})
	if e, ok := p.recv().(*wire.Error); !ok || e.CallID != 2 || status.Code(e.Status) != status.Cancelled {
		t.Fatalf("got %#v", e)
	}
}

// TestNoLateClientSchema: a client that sent no client schema cannot
// publish one later (5.4): locally refused, and a SchemaUpdate from such a
// client closes the session.
func TestNoLateClientSchema(t *testing.T) {
	t.Parallel()
	cli, _ := pair(t, memBinding(), Config{}, Config{Schema: testSchema("s")})
	if _, err := cli.UpdateSchema(testSchema("late"), SchemaUpdateOptions{}); err == nil {
		t.Fatal("UpdateSchema succeeded without a client schema in Hello")
	}
	p, _, _ := rawClient(t, Config{Schema: testSchema("s")}, mem.Options{})
	p.handshake(nil)
	p.send(&wire.SchemaUpdate{Epoch: 1, Hash: append([]byte{1}, make([]byte, 32)...), Delta: []byte{0x80}})
	if g := p.expectGoAway(); status.Code(g.Status) != status.SchemaMismatch {
		t.Fatalf("got %+v", g)
	}
}

// TestResetCountsUntilPeerEnd: a leased stream the caller reset stays
// counted until the callee has ended its own direction (4.2 rule 5); a
// peer that never does is uncounted after ResetWait.
func TestResetCountsUntilPeerEnd(t *testing.T) {
	t.Parallel()
	clk := testutil.NewFakeClock()
	cc, sc := mem.Pipe(mem.Options{})
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := NewClient(context.Background(), cc, Config{Clock: clk})
		ch <- res{s, err}
	}()
	lane, _ := sc.SharedLane(context.Background())
	srv := newRawPeer(t, sc, lane)
	if _, ok := srv.recv().(*wire.Hello); !ok {
		t.Fatal("no Hello")
	}
	sch := testSchema("s")
	raw, _ := sch.Canonical().Encode()
	hash := schemaHash(t, sch)
	srv.send(&wire.Welcome{Version: 1, SessionID: make([]byte, 16), ServerSchema: wire.SchemaOffer{Kind: wire.OfferFull, Hash: hash, Schema: raw}})
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	cli := r.s
	t.Cleanup(func() { cli.Close(0, "") })
	if _, ok := srv.recv().(*wire.Ready); !ok {
		t.Fatal("no Ready")
	}
	ctx := tctx(t)
	call, err := cli.Call(ctx, tFacet, mHang, nil, &CallOptions{Lane: LaneLeased})
	if err != nil || call.Shared() {
		t.Fatalf("%v", err)
	}
	ls, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := ls.ReadMessage(); err != nil || b[2] != 0x02 {
		t.Fatalf("request %x %v", b, err)
	}
	// The callee never answers the Cancel and ignores the reset.
	_ = call.Cancel(status.Cancelled)
	clk.Advance(6 * time.Second)
	testutil.Eventually(t, 5*time.Second, call.Done, "call not failed after give-up")
	if _, err := ls.ReadMessage(); err == nil {
		t.Fatal("want the reset")
	}
	testutil.Never(t, 20*time.Millisecond, func() bool { return cli.Stats().PoolOpen != 1 },
		"pool open %d: the stream must stay counted until the peer ends its direction", cli.Stats().PoolOpen)
	clk.Advance(6 * time.Second)
	testutil.Eventually(t, 5*time.Second, func() bool { return cli.Stats().PoolOpen == 0 }, "not uncounted after ResetWait")
}
