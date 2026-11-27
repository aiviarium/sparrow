package session

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Behaviour of core rev347, section 7.6: "The caller counts a call until it
// has both sent its own last message and seen the callee's; the callee
// counts it only until it has sent its own final message".

// TestCalleeUncountsAtItsFinalMessage: a callee that finishes its half
// first (an Error to a client stream) stops counting the call at once,
// although the caller's half is still open, so the caller's next call,
// which may arrive before the old call's End, is not refused.
func TestCalleeUncountsAtItsFinalMessage(t *testing.T) {
	h := newTestHandlers()
	m := h.mux(tFacet)
	m.HandleFunc(tFacet, mSum, func(ctx context.Context, c *ServerCall) (any, error) {
		return nil, &Error{Code: status.FailedPrecondition, Message: "refused before reading"}
	})
	scfg := Config{Schema: testSchema("s"), Handler: m}
	scfg.Params.Set(wire.ParamMaxConcurrentCalls, 1)
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	p.send(reqMsg(2, tFacet, mSum, nil))
	if e, ok := p.recv().(*wire.Error); !ok || e.CallID != 2 || status.Code(e.Status) != status.FailedPrecondition {
		t.Fatalf("got %#v", e)
	}
	if st := srv.Stats(); st.IncomingCalls != 0 || st.CallerHalfOpen != 1 {
		t.Fatalf("after the callee's final message: %+v", st)
	}
	// The next call, before call 2's End.
	p.send(reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "next")))
	if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 4 {
		t.Fatalf("the next call: %#v", r)
	}
	p.send(&wire.End{CallID: 2})
	testutil.Eventually(t, 5*time.Second, func() bool { return srv.Stats().CallerHalfOpen == 0 }, "call 2 not forgotten")
}

// TestCallerCountsUntilCalleesFinal: a caller that cancelled a call has
// finished its half, but keeps counting the call until it has seen the
// callee's final message; only then does the next call start.
func TestCallerCountsUntilCalleesFinal(t *testing.T) {
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

// TestCallerHalfOpenBound: a callee MAY close a session that keeps more
// than twice maxConcurrentCalls calls with the caller's half open, with
// GoAway(resource_exhausted) (7.6). Refused calls count as well: their
// caller still owes its End.
func TestCallerHalfOpenBound(t *testing.T) {
	scfg := Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxConcurrentCalls, 1)
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	p.send(reqMsg(2, tFacet, mSum, nil)) // counted, waits for input
	p.send(reqMsg(4, tFacet, mSum, nil)) // refused: maxConcurrentCalls
	if e, ok := p.recv().(*wire.Error); !ok || e.CallID != 4 || status.Code(e.Status) != status.ResourceExhausted {
		t.Fatalf("got %#v", e)
	}
	if st := srv.Stats(); st.CallerHalfOpen != 2 || st.Closed {
		t.Fatalf("two half-open calls: %+v", st)
	}
	p.send(reqMsg(6, tFacet, mSum, nil)) // a third: more than twice the limit
	if g := p.expectGoAway(); status.Code(g.Status) != status.ResourceExhausted {
		t.Fatalf("GoAway %v", g)
	}
}
