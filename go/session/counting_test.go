package session

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport"
	"github.com/aiviarium/sparrow/go/transport/mem"
	"github.com/aiviarium/sparrow/go/wire"
)

// Counting of calls and streams. Calls (7.1, 7.5, 7.6):
// "The caller counts a call until it has both sent its own last message
// and seen the callee's final one. The callee counts a call from its
// Request until it has sent its own final message ... and then forgets
// it: later messages for it are ignored." Streams (4.2 rule 5): a reset
// stream stays counted until both directions have ended.

// earlyRefusal is a mux whose sum (a client stream) fails before reading.
func earlyRefusal() *Mux {
	m := newTestHandlers().mux(tFacet)
	m.HandleFunc(tFacet, mSum, func(ctx context.Context, c *ServerCall) (any, error) {
		return nil, &Error{Code: status.FailedPrecondition, Message: "refused before reading"}
	})
	return m
}

// TestCalleeForgetsAtItsFinalMessage: a callee that finishes first (an
// Error to a client stream) stops counting the call and forgets it at
// once, although the caller's half is still open: the caller's next call,
// which may arrive before the old call's End, is not refused, and the old
// call's later input and End are ignored.
func TestCalleeForgetsAtItsFinalMessage(t *testing.T) {
	t.Parallel()
	scfg := Config{Schema: testSchema("s"), Handler: earlyRefusal()}
	scfg.Params.Set(wire.ParamMaxConcurrentCalls, 1)
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	p.send(reqMsg(2, tFacet, mSum, nil))
	if e, ok := p.recv().(*wire.Error); !ok || e.CallID != 2 || status.Code(e.Status) != status.FailedPrecondition {
		t.Fatalf("got %#v", e)
	}
	testutil.Eventually(t, 5*time.Second, func() bool {
		st := srv.Stats()
		return st.IncomingCalls == 0 && st.OpenCalls == 0
	}, "the callee still tracks call 2: %+v", srv.Stats())
	// The next call, before call 2's End.
	p.send(reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "next")))
	if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 4 {
		t.Fatalf("the next call: %#v", r)
	}
	// Late input and the End of the forgotten call are ignored.
	p.send(&wire.Item{CallID: 2, Value: cbor.AppendUint(nil, 1)})
	p.send(&wire.End{CallID: 2})
	p.send(reqMsg(6, tFacet, mEcho, cbor.AppendText(nil, "still fine")))
	if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 6 {
		t.Fatalf("after the ignored messages: %#v", r)
	}
	if st := srv.Stats(); st.Closed {
		t.Fatal("closed")
	}
}

// TestForgottenCallKeepsStreamUntilCallerEnd: on a leased stream the
// callee that forgot a call still notes when the caller's half finishes,
// since only then is the stream idle (7.1): a Request before the old call's
// End is a protocol error, one after it is served.
func TestForgottenCallKeepsStreamUntilCallerEnd(t *testing.T) {
	t.Parallel()
	for _, endFirst := range []bool{true, false} {
		scfg := Config{Schema: testSchema("s"), Handler: earlyRefusal()}
		p, _, _ := rawClient(t, scfg, mem.Options{})
		p.handshake(nil)
		st, err := p.conn.OpenStream(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		in := make(chan wire.Message, 100)
		go p.read(st, in)
		p.sendOn(st, reqMsg(2, tFacet, mSum, nil))
		if e, ok := recvFrom(t, in).(*wire.Error); !ok || e.CallID != 2 {
			t.Fatalf("got %#v", e)
		}
		if endFirst {
			p.sendOn(st, &wire.End{CallID: 2})
		}
		p.sendOn(st, reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "x")))
		if endFirst {
			if r, ok := recvFrom(t, in).(*wire.Response); !ok || r.CallID != 4 {
				t.Fatalf("after End: %#v", r)
			}
			continue
		}
		if g := p.expectGoAway(); status.Code(g.Status) != status.ProtocolError {
			t.Fatalf("Request before the old End: GoAway %v", g)
		}
	}
}

// TestCallerCountsUntilCalleesFinal: a caller that cancelled a call has
// finished its half, but keeps counting the call until it has seen the
// callee's final message; only then does the next call start.
func TestCallerCountsUntilCalleesFinal(t *testing.T) {
	t.Parallel()
	h := newTestHandlers()
	m := h.mux(tFacet)
	held := make(chan *ServerCall, 1)
	release := make(chan struct{})
	defer close(release)
	// Answers only when the test says so, ignoring the Cancel.
	m.Handle(tFacet, mBlock, rawHandler(func(ctx context.Context, c *ServerCall) {
		held <- c
		<-release
	}))
	cli, _ := stdPair(t, memBinding(), h, func(c, s *Config) {
		s.Handler = m
		s.Params.Set(wire.ParamMaxConcurrentCalls, 1)
	})
	ctx := tctx(t)
	cc, err := cli.Call(ctx, tFacet, mBlock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sc := <-held
	if err := cc.Cancel(status.Cancelled); err != nil {
		t.Fatal(err)
	}
	if n := cli.Stats().OutgoingCalls; n != 1 {
		t.Fatalf("the caller counts %d calls after its Cancel, want 1", n)
	}
	next := make(chan error, 1)
	go func() {
		v, err := cli.Unary(ctx, tFacet, mEcho, "next", nil)
		if err == nil && v != "next" {
			err = Errorf(status.Internal, "reply %v", v)
		}
		next <- err
	}()
	select {
	case err := <-next:
		t.Fatalf("the next call ran before the callee's final message: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	_ = sc.Fail(&Error{Code: status.Cancelled, Message: "cancelled"})
	if err := <-next; err != nil {
		t.Fatal(err)
	}
}

// rawServer runs a client session against a hand-driven server on a mem
// pair, with maxConcurrentCalls 1, and returns the client and the raw
// server's end.
func rawServer(t *testing.T, ccfg Config) (*Session, *mem.Conn, transport.Stream, chan wire.Message) {
	t.Helper()
	cc, sc := mem.Pipe(mem.Options{})
	type res struct {
		s   *Session
		err error
	}
	done := make(chan res, 1)
	go func() {
		s, err := NewClient(context.Background(), cc, ccfg)
		done <- res{s, err}
	}()
	lane, err := sc.SharedLane(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := newRawPeer(t, sc, lane)
	if _, ok := p.recv().(*wire.Hello); !ok {
		t.Fatal("no Hello")
	}
	host := testSchema("s")
	raw, err := host.Canonical().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	w := &wire.Welcome{Version: 1, SessionID: make([]byte, 16), ServerSchema: wire.SchemaOffer{Kind: wire.OfferFull, Hash: schemaHash(t, host), Schema: raw}}
	w.Params.Set(wire.ParamMaxConcurrentCalls, 1)
	p.send(w)
	if _, ok := p.recv().(*wire.Ready); !ok {
		t.Fatal("no Ready")
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { r.s.Close(status.OK, "") })
	return r.s, sc, lane, p.in
}

// TestCallerKeepsResetCallCounted: after resetting a leased stream on an
// unanswered Cancel, the caller counts the call as long as it counts the
// stream (7.5, 4.2 rule 5): until the callee ends its direction, or for
// ResetWait (5 s, here on a fake clock).
func TestCallerKeepsResetCallCounted(t *testing.T) {
	t.Parallel()
	clk := testutil.NewFakeClock()
	cli, sc, _, _ := rawServer(t, Config{Clock: clk})
	ctx := tctx(t)
	cc, err := cli.Call(ctx, tFacet, mBlock, nil, &CallOptions{Lane: LaneLeased})
	if err != nil {
		t.Fatal(err)
	}
	st, err := sc.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() { // the raw callee reads, never answers, never ends its direction
		for {
			if _, err := st.ReadMessage(); err != nil {
				return
			}
		}
	}()
	_ = cc.Cancel(status.Cancelled)
	testutil.Eventually(t, 5*time.Second, func() bool { return clk.HasTimer(DefaultCancelGiveUp) }, "no give-up timer")
	clk.Advance(DefaultCancelGiveUp)
	testutil.Eventually(t, 5*time.Second, cc.Done, "the call did not fail after the unanswered Cancel")
	testutil.Eventually(t, 5*time.Second, func() bool { return clk.HasTimer(DefaultResetWait) }, "no reset-wait timer")
	if n := cli.Stats().OutgoingCalls; n != 1 {
		t.Fatalf("the reset call stopped counting with its stream still counted (%d)", n)
	}
	clk.Advance(DefaultResetWait - time.Millisecond)
	if n := cli.Stats().OutgoingCalls; n != 1 {
		t.Fatalf("uncounted before ResetWait (%d)", n)
	}
	clk.Advance(time.Millisecond)
	testutil.Eventually(t, 5*time.Second, func() bool { return cli.Stats().OutgoingCalls == 0 }, "the call still counts after ResetWait")
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

// TestAcceptorResetSendingOnly: a stream refused for maxStreams is reset in
// the acceptor's sending direction only (4.2 rule 5: RESET_STREAM, never
// STOP_SENDING), so the opener can still write until it has seen the reset
// and ended its own direction; the refused stream is never counted.
func TestAcceptorResetSendingOnly(t *testing.T) {
	t.Parallel()
	scfg := Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxStreams, 1)
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	s1, _ := p.conn.OpenStream(context.Background())
	s2, _ := p.conn.OpenStream(context.Background())
	p.sendOn(s1, reqMsg(2, tFacet, mHang, nil))
	p.sendOn(s2, reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "b")))
	if _, err := s2.ReadMessage(); Code(asResetErr(err)) != status.ResourceExhausted {
		t.Fatalf("second stream: %v", err)
	}
	if err := s2.WriteMessage((&wire.Cancel{CallID: 4}).AppendTo(nil)); err != nil {
		t.Fatalf("the acceptor stopped the opener's direction (STOP_SENDING): %v", err)
	}
	_ = s2.CloseWrite()
	if n := srv.Stats().PeerLeased; n != 1 {
		t.Fatalf("acceptor counts %d streams, want 1", n)
	}
}

// TestAcceptorResetUncountsAtOnce: an acceptor that resets a stream (here
// for an oversized message) stops counting it as soon as it has sent its
// end, before the opener has ended its own direction (4.2 rule 5), and it
// does not stop the opener's direction.
func TestAcceptorResetUncountsAtOnce(t *testing.T) {
	t.Parallel()
	scfg := Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxMessageSize, 16384)
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	s1, _ := p.conn.OpenStream(context.Background())
	p.sendOn(s1, reqMsg(2, tFacet, mHang, nil))
	testutil.Eventually(t, 5*time.Second, func() bool { return srv.Stats().PeerLeased == 1 }, "stream not counted")
	if err := s1.WriteMessage(make([]byte, 20000)); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.ReadMessage(); Code(asResetErr(err)) != status.MessageTooLarge {
		t.Fatalf("want a reset with message_too_large, got %v", err)
	}
	if n := srv.Stats().PeerLeased; n != 0 {
		t.Fatalf("acceptor still counts %d streams after its reset", n)
	}
	if err := s1.WriteMessage((&wire.Cancel{CallID: 2}).AppendTo(nil)); err != nil {
		t.Fatalf("the acceptor stopped the opener's direction (STOP_SENDING): %v", err)
	}
	_ = s1.CloseWrite()
}

// responseGate holds the server's write of a Response, after it has gone
// out, until the server's reader has handled the next message it received.
type responseGate struct {
	transport.Conn
	reads   atomic.Int32
	waitFor atomic.Int32 // 0: no Response held
}

func (g *responseGate) SharedLane(ctx context.Context) (transport.Stream, error) {
	st, err := g.Conn.SharedLane(ctx)
	if err != nil {
		return nil, err
	}
	return &responseGateStream{Stream: st, g: g}, nil
}

type responseGateStream struct {
	transport.Stream
	g *responseGate
}

func (s *responseGateStream) ReadMessage() ([]byte, error) {
	s.g.reads.Add(1)
	return s.Stream.ReadMessage()
}

func (s *responseGateStream) WriteMessage(b []byte) error {
	err := s.Stream.WriteMessage(b)
	if k, _, _ := wire.PeekCall(b); k == wire.KindResponse && s.g.waitFor.Load() == 0 {
		// Wait until the reader has taken the next message and come back
		// for another (it handled the next Request meanwhile).
		target := s.g.reads.Load() + 1
		s.g.waitFor.Store(target)
		testutil.WaitFor(2*time.Second, func() bool { return s.g.reads.Load() >= target })
	}
	return err
}

// TestCalleeUncountsBeforeFinalMessage: with maxConcurrentCalls 1, a
// caller that starts its next call as soon as it has the Response of the
// previous one is within the limit (7.6): the callee must not still count
// the first call while it finishes writing that Response.
func TestCalleeUncountsBeforeFinalMessage(t *testing.T) {
	t.Parallel()
	cc, sc := mem.Pipe(mem.Options{NoLeases: true})
	scfg := Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxConcurrentCalls, 1)
	g := &responseGate{Conn: sc}
	go func() {
		if s, err := NewServer(context.Background(), g, scfg); err == nil {
			t.Cleanup(func() { s.Close(0, "") })
		}
	}()
	lane, err := cc.SharedLane(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := newRawPeer(t, cc, lane)
	p.handshake(nil)
	p.send(reqMsg(2, tFacet, mEcho, cbor.AppendText(nil, "a")))
	if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 2 {
		t.Fatalf("got %#v", r)
	}
	p.send(reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "b")))
	if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 4 {
		t.Fatalf("second call within the limit: got %#v", r)
	}
}
