package session

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// ForwardRequest returns the RawRequest that forwards an incoming call to
// another hop (10.5): the given facet ID and metadata, the same method ID,
// and the input copied byte for byte.
func ForwardRequest(in *ServerCall, facetID uint64, md wire.Metadata) RawRequest {
	r := in.Request()
	return RawRequest{FacetID: facetID, MethodID: r.MethodID, Metadata: md, Input: r.Input}
}

// Relay forwards every later message of a call between two hops until
// both halves are finished (10.5): caller messages from in to out, callee
// messages from out to in, each with its call ID rewritten and every other
// byte unchanged. Credit is never relayed: each hop has its own, and
// credit is returned to a sender only after its message was forwarded, so
// per call and direction the relay holds at most the credit it granted
// plus one message. out should be opened with ManualCredit. Relay returns
// once both calls have ended.
//
// If a message is too large for the next hop, both calls end with
// message_too_large; if either side fails (its link dropped, or the callee
// never answered a Cancel), the other gets unavailable (Error toward the
// caller, Cancel toward the callee).
func Relay(ctx context.Context, in *ServerCall, out *ClientCall) error {
	// The handler context ends when the caller cancels, but the relay must
	// still carry the Cancel and the callee's answer: it runs until both
	// calls have ended, which the session guarantees (give-up timers,
	// session close).
	ctx = context.WithoutCancel(ctx)
	in.SetManualCredit(true)
	out.c.mu.Lock()
	out.c.manual = true
	out.c.mu.Unlock()
	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once
	setErr := func(err error) { once.Do(func() { firstErr = err }) }
	wg.Add(2)
	go func() { // caller -> callee
		defer wg.Done()
		for {
			m, err := in.RecvRaw(ctx)
			if err == io.EOF {
				return
			}
			if err != nil {
				setErr(err)
				_ = out.Cancel(relayCode(err))
				return
			}
			err = out.SendRaw(ctx, m.Raw)
			in.Release(m)
			if err != nil {
				if errors.Is(err, ErrHalfClosed) || errors.Is(err, ErrCallEnded) {
					continue // the callee finished first: input is discarded
				}
				setErr(err)
				code := relayCode(err)
				_ = in.Fail(&Error{Code: code, Message: "relay: " + err.Error()})
				_ = out.Cancel(code)
				return
			}
		}
	}()
	go func() { // callee -> caller
		defer wg.Done()
		for {
			m, err := out.RecvRaw(ctx)
			if err == io.EOF {
				return
			}
			if err != nil {
				setErr(err)
				_ = in.Fail(&Error{Code: relayCode(err), Message: "relay: " + err.Error()})
				return
			}
			err = in.SendRaw(ctx, m.Raw)
			out.Release(m)
			if err != nil {
				if errors.Is(err, ErrHalfClosed) || errors.Is(err, ErrCallEnded) {
					continue
				}
				setErr(err)
				code := relayCode(err)
				_ = in.Fail(&Error{Code: code, Message: "relay: " + err.Error()})
				_ = out.Cancel(code)
				return
			}
		}
	}()
	wg.Wait()
	return firstErr
}

// relayCode maps a failure on one hop to the status the other hop gets.
func relayCode(err error) status.Code {
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case status.MessageTooLarge, status.Cancelled, status.DeadlineExceeded:
			return e.Code
		}
	}
	return status.Unavailable
}
