package session

import (
	"context"
	"io"
	"sync"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Msg is one received call message: its kind, its encoding exactly as it
// arrived (call ID as on that hop) and its decoded envelope, whose payload
// fields are views into Raw.
type Msg struct {
	Kind    wire.Kind
	Raw     []byte
	Message wire.Message
	counted uint64
}

// Counted returns the bytes the message counts against credit (7.4).
func (m *Msg) Counted() uint64 { return m.counted }

// call is one call, from either side.
type call struct {
	s      *Session
	id     uint64
	caller bool // this side is the caller
	ln     *lane
	facet  uint64
	method uint64
	def    *schema.Method // method definition from the callee's schema, if known
	codec  *value.Codec   // codec of the callee's facet, if known
	md     wire.Metadata  // request metadata
	req    *wire.Request  // incoming: the request
	reqRaw []byte

	ctx    context.Context
	cancel context.CancelCauseFunc
	stopCx func() bool

	sendMu sync.Mutex // serializes sends, keeping a call's messages ordered

	mu             sync.Mutex
	sig            chan struct{}
	h              halves
	cancelSent     bool
	cancelCode     status.Code
	sendWin        wire.CreditWindow // credit the peer granted us
	recvWin        wire.CreditWindow // credit we granted the peer
	recvInit       uint64
	sendInit       uint64
	unacked        uint64
	manual         bool
	q              []*Msg
	buffered       uint64
	maxBuffered    uint64
	ended          bool   // both halves finished, or the call failed
	removed        bool   // endCall ran
	forgotten      bool   // forgetLocked ran
	localErr       *Error // why the call failed locally, for the application
	gaveUp         bool
	sentTokens     map[uint64]bool
	recvTokens     map[uint64]bool
	autoAnswer     bool
	cancelRecv     bool
	cancelRecvCode status.Code
	counted        bool // counts toward maxConcurrentCalls (7.6; s.mu)
	forgetEarly    bool // callee: forgot the call at its final message, the caller's half still open (7.1)
	giveUpT        Timer
	brokenT        Timer
	deadlineT      Timer

	typed typedState
}

func (c *call) broadcastLocked() {
	if c.sig != nil {
		close(c.sig)
	}
	c.sig = make(chan struct{})
}

func (c *call) waitCh() <-chan struct{} {
	if c.sig == nil {
		c.sig = make(chan struct{})
	}
	return c.sig
}

// peerHalfDone reports whether the peer's half is finished.
func (c *call) peerHalfDoneLocked() bool {
	if c.caller {
		return c.h.calleeDone
	}
	return c.h.callerDone
}

func (c *call) ownHalfDoneLocked() bool {
	if c.caller {
		return c.h.callerDone
	}
	return c.h.calleeDone
}

// deliver handles a message the peer sent on this call. It runs on the
// lane's reader goroutine and never blocks on the application.
func (c *call) deliver(m *Msg) {
	var (
		grant     uint64
		autoErr   *Error
		autoEnd   bool
		ended     bool
		violation string
		cause     *Error
	)
	c.mu.Lock()
	if c.ended {
		forgot := c.forgetEarly
		c.mu.Unlock()
		if forgot && (m.Kind == wire.KindEnd || m.Kind == wire.KindCancel) {
			// The caller's half of a call this callee forgot ends: its
			// stream is idle (7.1). The reader found the call just before
			// it was forgotten.
			c.s.mu.Lock()
			if l := c.ln; l != nil && l.awaitCallerEnd == c.id {
				l.awaitCallerEnd = 0
			}
			c.s.mu.Unlock()
		}
		return
	}
	k := m.Kind
	fromCaller := !c.caller
	if (fromCaller && !isCallerKind(k)) || (!fromCaller && !isCalleeKind(k)) {
		c.mu.Unlock()
		c.violation("a " + k.String() + " in the wrong direction")
		return
	}
	if k == wire.KindCredit {
		c.sendWin.Grant(m.Message.(*wire.Credit).Amount)
		c.broadcastLocked()
		c.mu.Unlock()
		return
	}
	lateCancel := fromCaller && k == wire.KindCancel && !c.cancelRecv && !c.h.calleeDone
	if c.peerHalfDoneLocked() && !lateCancel {
		// Anything after the sender's final message is ignored, except a
		// Cancel, which the caller may send after its half is finished.
		c.mu.Unlock()
		return
	}
	n := m.counted
	if n > 0 {
		if err := c.recvWin.Consume(n); err != nil {
			violation = "sent with no credit left"
		}
	}
	if violation == "" && k == wire.KindBytes {
		tok := m.Message.(*wire.Bytes).Token
		if c.recvTokens == nil {
			c.recvTokens = map[uint64]bool{}
		}
		if !c.recvTokens[tok] {
			if len(c.recvTokens) >= MaxTokens {
				violation = "more than 64 byte tokens in one call"
			}
			c.recvTokens[tok] = true
		}
	}
	if violation != "" {
		c.mu.Unlock()
		c.violation(violation)
		return
	}
	var finishes bool
	if fromCaller {
		finishes = c.h.callerMsg(k)
	} else {
		finishes = c.h.calleeMsg(k)
	}
	switch {
	case fromCaller && c.h.calleeDone:
		// The callee finished first and is forgetting the call: its input
		// is ignored and earns no more credit (7.1).
	case !fromCaller && c.gaveUp:
		// The application stopped listening after an unanswered Cancel.
	default:
		c.q = append(c.q, m)
		c.buffered += n
		if c.buffered > c.maxBuffered {
			c.maxBuffered = c.buffered
		}
	}
	if fromCaller && k == wire.KindCancel {
		code := status.Code(m.Message.(*wire.Cancel).Status)
		if code == status.OK {
			code = status.Cancelled
		}
		c.cancelRecv, c.cancelRecvCode = true, code
		cause = &Error{Code: code, Message: "cancelled by the caller", Remote: true}
		if c.autoAnswer && !c.h.calleeDone {
			autoErr = &Error{Code: code, Message: "cancelled"}
		}
	}
	if !fromCaller && finishes && !c.h.callerDone {
		autoEnd = true
	}
	if c.h.ended() {
		c.ended = true
		ended = true
		// Forget the call (and free its stream) before the application
		// can see the final message, so a next call finds the stream idle.
		c.s.forgetLocked(c)
	}
	c.broadcastLocked()
	c.mu.Unlock()
	if ended {
		c.s.endCall(c)
	}

	if cause != nil && c.cancel != nil {
		c.cancel(cause)
	}
	if grant > 0 {
		c.grant(grant)
	}
	if autoErr != nil {
		go func() { _ = c.sendError(autoErr) }()
	}
	if autoEnd {
		go c.autoEnd()
	}
}

// autoEnd sends End on the caller's behalf after the callee finished first
// (7.1: the caller MUST send End or Cancel next, with no further Item or
// Bytes).
func (c *call) autoEnd() {
	b := (&wire.End{CallID: c.id}).AppendTo(nil)
	_ = c.send(context.Background(), wire.KindEnd, b, 0, false)
}

// violation ends the call after the peer broke a rule inside it (7.4, 8):
// the callee answers Error(protocol_error), the caller sends
// Cancel(protocol_error).
func (c *call) violation(why string) {
	c.s.logf("call %d: protocol error: %s", c.id, why)
	e := &Error{Code: status.ProtocolError, Message: why}
	c.mu.Lock()
	if c.localErr == nil {
		c.localErr = e
	}
	c.broadcastLocked()
	c.mu.Unlock()
	if c.cancel != nil {
		c.cancel(e)
	}
	if c.caller {
		_ = c.sendCancel(status.ProtocolError)
	} else {
		_ = c.sendError(e)
	}
}

// failLocal fails the call for the application and forgets it, as when
// its stream was reset or the session ended.
func (c *call) failLocal(e *Error) {
	c.mu.Lock()
	if c.localErr == nil {
		c.localErr = e
	}
	already := c.ended
	c.ended = true
	c.broadcastLocked()
	c.mu.Unlock()
	if c.cancel != nil {
		c.cancel(e)
	}
	if !already {
		c.s.endCall(c)
	}
}

// send writes one message of this call. It enforces the half rules, the
// schema-ack gate for the callee (6.6 rule 1) and credit (7.4): a counted
// message waits while the remaining credit is zero or negative.
func (c *call) send(ctx context.Context, k wire.Kind, b []byte, n uint64, gate bool) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.mu.Lock()
	if err := c.checkSendLocked(k); err != nil {
		c.mu.Unlock()
		return err
	}
	if gate && !c.caller && c.s.needsAck(c.facet) {
		c.mu.Unlock()
		if err := c.s.waitAck(ctx, c.facet); err != nil {
			return err
		}
		c.mu.Lock()
		if err := c.checkSendLocked(k); err != nil {
			c.mu.Unlock()
			return err
		}
	}
	for n > 0 && !c.sendWin.CanSend() {
		ch := c.waitCh()
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-c.s.done:
			return c.s.closedError()
		}
		c.mu.Lock()
		if err := c.checkSendLocked(k); err != nil {
			c.mu.Unlock()
			return err
		}
	}
	if k == wire.KindBytes {
		tok := tokenOf(b)
		if c.sentTokens == nil {
			c.sentTokens = map[uint64]bool{}
		}
		if !c.sentTokens[tok] {
			if len(c.sentTokens) >= MaxTokens {
				c.mu.Unlock()
				return Errorf(status.ResourceExhausted, "a sender may open at most %d byte tokens per call", MaxTokens)
			}
			c.sentTokens[tok] = true
		}
	}
	if n > 0 {
		_ = c.sendWin.Consume(n)
	}
	if c.caller {
		if k == wire.KindCancel {
			c.cancelSent = true
		}
		c.h.callerMsg(k)
	} else if c.h.calleeMsg(k) {
		// The callee counts a call only until it has sent its own final
		// message, and then forgets it, whether or not the caller's half is
		// still open (7.1, 7.6). It stops counting before the message goes
		// out: the caller frees its slot once it has seen the message (and
		// finished its own half) and may start the next call at once,
		// which can arrive before the old call's End.
		c.s.uncountCall(c)
		if !c.h.callerDone {
			c.forgetEarly = true
			c.s.forgetEarly(c)
		}
	}
	ended := false
	if (c.h.ended() || c.forgetEarly) && !c.ended {
		c.ended = true
		ended = true
	}
	c.broadcastLocked()
	c.mu.Unlock()
	err := c.ln.write(b)
	if ended {
		c.s.endCall(c)
		c.mu.Lock()
		c.broadcastLocked()
		c.mu.Unlock()
	}
	if k == wire.KindCancel && err == nil {
		c.armGiveUp()
	}
	return err
}

func (c *call) checkSendLocked(k wire.Kind) error {
	if c.localErr != nil && k != wire.KindCancel && k != wire.KindError && k != wire.KindEnd {
		return c.localErr
	}
	if c.ended {
		return ErrCallEnded
	}
	if c.caller {
		if !isCallerKind(k) {
			return ErrWrongDirection
		}
		if (k == wire.KindItem || k == wire.KindBytes) && c.h.calleeDone {
			return ErrHalfClosed
		}
		if k == wire.KindCancel && c.cancelSent {
			return ErrHalfClosed
		}
		if !c.h.callerMaySend(k) {
			return ErrHalfClosed
		}
		return nil
	}
	if !isCalleeKind(k) {
		return ErrWrongDirection
	}
	if !c.h.calleeMaySend(k) {
		return ErrHalfClosed
	}
	return nil
}

func tokenOf(b []byte) uint64 {
	d := cbor.NewDecoder(b)
	_, _ = d.ArrayHead()
	_ = d.Skip()
	_ = d.Skip()
	t, _ := d.Uint()
	return t
}

// grant gives the peer n more bytes of credit.
func (c *call) grant(n uint64) {
	if n == 0 {
		return
	}
	c.mu.Lock()
	if c.ended || c.peerHalfDoneLocked() {
		c.mu.Unlock()
		return
	}
	c.recvWin.Grant(n)
	c.mu.Unlock()
	_ = c.ln.write((&wire.Credit{CallID: c.id, Amount: n}).AppendTo(nil))
}

// consumedLocked records that the application took n counted bytes and
// returns the credit to grant now, if any: more credit is granted once
// about half of the window has been consumed (7.4).
func (c *call) consumedLocked(n uint64) uint64 {
	c.buffered -= min(n, c.buffered)
	c.unacked += n
	half := c.recvInit / 2
	if half == 0 {
		half = 1
	}
	if c.unacked >= half && !c.peerHalfDoneLocked() {
		g := c.unacked
		c.unacked = 0
		return g
	}
	return 0
}

// recvRaw returns the next received message (Credit is consumed by the
// session), io.EOF once the peer's half is finished and every message was
// taken, or the error that ended the call.
func (c *call) recvRaw(ctx context.Context) (*Msg, error) {
	c.mu.Lock()
	for {
		if len(c.q) > 0 {
			m := c.q[0]
			c.q[0] = nil
			c.q = c.q[1:]
			var g uint64
			if !c.manual {
				g = c.consumedLocked(m.counted)
			}
			c.mu.Unlock()
			c.grant(g)
			return m, nil
		}
		if c.localErr != nil {
			e := c.localErr
			c.mu.Unlock()
			return nil, e
		}
		peerDone := c.peerHalfDoneLocked()
		if !c.caller && peerDone && !c.cancelRecv && !c.h.calleeDone {
			// The caller may still send Cancel after its half is
			// finished; a relay must see it.
			peerDone = false
		}
		if peerDone || c.ended {
			c.mu.Unlock()
			return nil, io.EOF
		}
		ch := c.waitCh()
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			c.mu.Lock()
			if len(c.q) == 0 {
				c.mu.Unlock()
				return nil, ctx.Err()
			}
			continue
		}
		c.mu.Lock()
	}
}

// release returns the credit of a message taken with manual credit.
func (c *call) release(m *Msg) {
	c.mu.Lock()
	g := c.consumedLocked(m.counted)
	c.mu.Unlock()
	c.grant(g)
}

func (c *call) sendCancel(code status.Code) error {
	c.mu.Lock()
	c.cancelCode = code
	c.mu.Unlock()
	b := (&wire.Cancel{CallID: c.id, Status: uint64(code)}).AppendTo(nil)
	return c.send(context.Background(), wire.KindCancel, b, 0, false)
}

func (c *call) sendError(e *Error) error {
	code := e.Code
	b := (&wire.Error{CallID: c.id, Status: uint64(code), Message: e.Message, Details: e.Details}).AppendTo(nil)
	// Core errors without details carry no IDs of the facet; they need not
	// wait for a schema ack.
	gate := !code.IsCore() || e.Details != nil
	return c.send(context.Background(), wire.KindError, b, 0, gate)
}

// armGiveUp starts the 5 s timer after Cancel (7.5).
func (c *call) armGiveUp() {
	d := dur(c.s.cfg.CancelGiveUp, DefaultCancelGiveUp)
	t := c.s.clock.AfterFunc(d, c.giveUp)
	c.mu.Lock()
	if c.ended || c.h.calleeDone {
		c.mu.Unlock()
		t.Stop()
		return
	}
	c.giveUpT = t
	c.mu.Unlock()
}

// giveUp runs when no final message arrived within CancelGiveUp of Cancel:
// a leased stream is reset (which fails the call), while on the shared lane
// the call keeps counting toward maxConcurrentCalls until its final message
// arrives, and after CancelBroken the session is closed.
func (c *call) giveUp() {
	c.mu.Lock()
	if c.ended || c.h.calleeDone {
		c.mu.Unlock()
		return
	}
	code := c.cancelCode
	if code == status.OK {
		code = status.Cancelled
	}
	c.gaveUp = true
	if c.localErr == nil {
		c.localErr = &Error{Code: code, Message: "no answer to Cancel"}
	}
	c.q = nil
	c.broadcastLocked()
	shared := c.ln.shared
	c.mu.Unlock()
	if !shared {
		c.s.resetLane(c.ln, status.Cancelled, true)
		return
	}
	rest := dur(c.s.cfg.CancelBroken, DefaultCancelBroken) - dur(c.s.cfg.CancelGiveUp, DefaultCancelGiveUp)
	t := c.s.clock.AfterFunc(rest, func() {
		c.mu.Lock()
		done := c.ended || c.h.calleeDone
		c.mu.Unlock()
		if !done {
			c.s.fail(status.ProtocolError, "a Cancel went unanswered for 30 s")
		}
	})
	c.mu.Lock()
	c.brokenT = t
	c.mu.Unlock()
}

// endCall forgets an ended call: its ID, its concurrency slot and its
// leased stream, which becomes idle again (4.2 rule 3).
func (s *Session) endCall(c *call) {
	c.mu.Lock()
	if c.removed {
		c.mu.Unlock()
		return
	}
	c.removed = true
	timers := []Timer{c.giveUpT, c.brokenT, c.deadlineT}
	stop := c.stopCx
	drained := s.forgetLocked(c)
	c.mu.Unlock()
	for _, t := range timers {
		stopTimer(t)
	}
	if stop != nil {
		stop()
	}
	if !c.caller && c.cancel != nil {
		c.cancel(ErrCallEnded)
	}
	if drained {
		s.drained()
	}
}

// forgetEarly drops a call the callee finished while the caller's half is
// still open (c.mu held), before the final message goes out, so that the
// caller's End, which may follow at once, finds the call gone: its ID is
// no longer tracked, later messages for it are ignored, and a leased
// stream is idle only once that End or Cancel has arrived (7.1).
func (s *Session) forgetEarly(c *call) {
	s.mu.Lock()
	if s.calls[c.id] == c {
		delete(s.calls, c.id)
		s.callGoneLocked()
	}
	if l := c.ln; l != nil && !l.shared && l.current == c {
		l.current = nil
		l.awaitCallerEnd = c.id
	}
	s.mu.Unlock()
}

// uncountCall frees the call's concurrency slot (c.mu held).
func (s *Session) uncountCall(c *call) {
	s.mu.Lock()
	s.uncountCallLocked(c)
	s.mu.Unlock()
}

// uncountCallLocked frees the call's concurrency slot (c.mu and s.mu held).
func (s *Session) uncountCallLocked(c *call) {
	if !c.counted {
		return
	}
	c.counted = false
	if c.caller {
		s.outOpen--
		s.signalOutLocked()
	} else {
		s.inOpen--
	}
}

// forgetLocked removes the call from the session's books (c.mu held): its
// ID, its concurrency slot, and its leased stream. It reports whether a
// drain just completed.
func (s *Session) forgetLocked(c *call) bool {
	if c.forgotten {
		return false
	}
	c.forgotten = true
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls[c.id] == c {
		delete(s.calls, c.id)
		s.callGoneLocked()
	}
	if c.ln == nil || c.ln.heldCall != c {
		s.uncountCallLocked(c)
	}
	if c.ln != nil && !c.ln.shared && c.ln.current == c {
		s.releaseLaneLocked(c.ln)
	}
	return s.draining && len(s.calls) == 0
}
