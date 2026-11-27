package session

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport"
	"github.com/aiviarium/sparrow/go/transport/mem"
	"github.com/aiviarium/sparrow/go/wire"
)

// Call counting and forgetting of core rev377, sections 7.1, 7.5 and 7.6:
// "The caller counts a call until it has both sent its own last message
// and seen the callee's final one. The callee counts a call from its
// Request until it has sent its own final message ... and then forgets
// it: later messages for it are ignored."

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
