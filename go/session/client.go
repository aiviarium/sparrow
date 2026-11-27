package session

import (
	"context"
	"errors"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/value"
	"github.com/aiviarium/sparrow/go/wire"
)

// LanePolicy chooses where a call runs (4.3).
type LanePolicy int

const (
	// LaneAuto follows the recommended policy: methods flagged shared on
	// the shared lane, everything else on a leased stream when one is idle
	// or can be opened, otherwise the shared lane.
	LaneAuto LanePolicy = iota
	// LaneShared forces the shared lane.
	LaneShared
	// LaneLeased asks for a leased stream; the call still falls back to the
	// shared lane when none is available (unless Config.WaitForLease).
	LaneLeased
)

// CallOptions tune an outgoing call.
type CallOptions struct {
	// Metadata is sent in the Request. A context deadline adds the
	// deadline key unless it is already present.
	Metadata wire.Metadata
	Lane     LanePolicy
	// Credit sets the initial credit for the callee's half (the credit
	// metadata key, 7.2); 0 keeps the default for the stream.
	Credit uint64
	// ManualCredit stops the session from returning credit when a message
	// is taken with RecvRaw; the application calls Release once it has
	// forwarded the message (a hub grants upstream only as it forwards
	// downstream, 10.5).
	ManualCredit bool
	// Flags gives the method flags for a raw call to a method the peer's
	// schema does not list (normally they come from the schema).
	Flags *uint64
	// NoWait fails the call with resource_exhausted (not dispatched) when
	// the peer's maxConcurrentCalls is reached, instead of waiting for a
	// slot (a hub does not queue calls for a node, 10.2).
	NoWait bool
}

// RawRequest is an outgoing Request with its input already encoded.
type RawRequest struct {
	FacetID, MethodID uint64
	Metadata          wire.Metadata
	// Input is copied byte for byte; nil encodes as null.
	Input cbor.Raw
}

// ClientCall is a call this side makes.
type ClientCall struct{ c *call }

// ID returns the call ID on this hop.
func (cc *ClientCall) ID() uint64 { return cc.c.id }

// Shared reports whether the call runs on the shared lane.
func (cc *ClientCall) Shared() bool { return cc.c.ln.shared }

// Method returns the method definition from the peer's schema (nil for a
// raw call to an unlisted method).
func (cc *ClientCall) Method() *schema.Method { return cc.c.def }

// RecvRaw returns the next message from the callee: Headers, Response,
// Item, Progress, Bytes, End or Error, exactly as received. It returns
// io.EOF after the callee's final message, or an *Error if the call failed
// locally (stream reset, session closed, no answer to Cancel).
func (cc *ClientCall) RecvRaw(ctx context.Context) (*Msg, error) { return cc.c.recvRaw(ctx) }

// Release returns the credit of a message taken with RecvRaw under
// ManualCredit.
func (cc *ClientCall) Release(m *Msg) { cc.c.release(m) }

// SendRaw sends an encoded caller message (Item, End, Cancel or Bytes),
// typically relayed from another hop: the call ID is replaced and every
// other byte is kept. Credit messages are not relayed (10.5) and are
// dropped. A Bytes message larger than the peer's maxMessageSize is split
// into chunks; any other oversized message fails with message_too_large.
func (cc *ClientCall) SendRaw(ctx context.Context, b []byte) error { return cc.c.sendRaw(ctx, b) }

// Cancel cancels the call (7.5): it finishes the caller's half, and the
// callee answers with a final message. Without one within CancelGiveUp the
// session gives up.
func (cc *ClientCall) Cancel(code status.Code) error {
	if code == status.OK {
		code = status.Cancelled
	}
	cc.c.mu.Lock()
	if cc.c.localErr == nil {
		cc.c.localErr = &Error{Code: code, Message: "cancelled"}
	}
	cc.c.broadcastLocked()
	cc.c.mu.Unlock()
	return cc.c.sendCancel(code)
}

// MaxBuffered returns the largest number of counted bytes the call held
// unread at any time (for tests of the memory bound, 7.4).
func (cc *ClientCall) MaxBuffered() uint64 {
	cc.c.mu.Lock()
	defer cc.c.mu.Unlock()
	return cc.c.maxBuffered
}

// Done reports whether the call has ended.
func (cc *ClientCall) Done() bool {
	cc.c.mu.Lock()
	defer cc.c.mu.Unlock()
	return cc.c.ended
}

// OpenRaw starts a call whose input is already encoded. The method flags
// come from the peer's schema (or CallOptions.Flags).
func (s *Session) OpenRaw(ctx context.Context, r RawRequest, o *CallOptions) (*ClientCall, error) {
	if o == nil {
		o = &CallOptions{}
	}
	s.mu.Lock()
	f, def := lookupMethod(s.peerSc, r.FacetID, r.MethodID)
	s.mu.Unlock()
	var codec *value.Codec
	if f != nil && def != nil {
		codec, _ = codecFor(&s.codecMu, s.peerCodecs, f)
	}
	c, err := s.open(ctx, r, o, def, codec)
	if err != nil {
		return nil, err
	}
	return &ClientCall{c: c}, nil
}

// Call starts a typed call: input is encoded with the method's input type
// from the peer's schema (nil for a stream or byte-stream input).
func (s *Session) Call(ctx context.Context, facetID, methodID uint64, input any, o *CallOptions) (*ClientCall, error) {
	s.mu.Lock()
	f, def := lookupMethod(s.peerSc, facetID, methodID)
	s.mu.Unlock()
	if def == nil {
		return nil, Errorf(status.Unimplemented, "facet %d has no method %d in the peer's schema", facetID, methodID)
	}
	codec, err := codecFor(&s.codecMu, s.peerCodecs, f)
	if err != nil {
		return nil, err
	}
	in, err := encodeWhole(codec, def.Input, input)
	if err != nil {
		return nil, &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	if o == nil {
		o = &CallOptions{}
	}
	c, err := s.open(ctx, RawRequest{FacetID: facetID, MethodID: methodID, Metadata: o.Metadata, Input: in}, o, def, codec)
	if err != nil {
		return nil, err
	}
	return &ClientCall{c: c}, nil
}

// Unary makes a unary call and returns the decoded output.
func (s *Session) Unary(ctx context.Context, facetID, methodID uint64, input any, o *CallOptions) (any, error) {
	cc, err := s.Call(ctx, facetID, methodID, input, o)
	if err != nil {
		return nil, err
	}
	return cc.Response(ctx)
}

// encodeWhole encodes a method's whole input or output.
func encodeWhole(codec *value.Codec, t schema.TypeRef, v any) (cbor.Raw, error) {
	if t.IsStream() || t.Kind == schema.RefByteStream {
		if v != nil {
			return nil, errors.New("a stream input carries no value in the Request; send Items or Bytes")
		}
		return cbor.Null, nil
	}
	return codec.Encode(t, v)
}

func (s *Session) open(ctx context.Context, r RawRequest, o *CallOptions, def *schema.Method, codec *value.Codec) (*call, error) {
	var flags uint64
	switch {
	case o.Flags != nil:
		flags = *o.Flags
	case def != nil:
		flags = def.Flags
	default:
		return nil, Errorf(status.Unimplemented, "facet %d has no method %d in the peer's schema", r.FacetID, r.MethodID)
	}
	if flags&schema.MethodNotification != 0 {
		return nil, errors.New("session: use Notify for a notification method")
	}
	// A concurrency slot (7.6).
	for {
		s.mu.Lock()
		if s.closed {
			g := s.goAwayRecv
			s.mu.Unlock()
			e := s.closedError().(*Error)
			if g != nil {
				// Report why the peer closed (for example a rejected
				// optimistic start, 5.3), not just that it did.
				e = &Error{Code: status.Code(g.Status), Message: g.Reason, Remote: true}
			}
			e.NotDispatched = true
			return nil, e
		}
		if s.draining {
			s.mu.Unlock()
			return nil, &Error{Code: status.GoingAway, Message: "the session is shutting down", NotDispatched: true}
		}
		if uint64(s.outOpen) < s.peerLimits.MaxConcurrentCalls {
			s.outOpen++
			s.mu.Unlock()
			break
		}
		if o.NoWait {
			s.mu.Unlock()
			return nil, &Error{Code: status.ResourceExhausted, Message: "the peer's maxConcurrentCalls is reached", NotDispatched: true}
		}
		if s.outSig == nil {
			s.outSig = make(chan struct{})
		}
		ch := s.outSig
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, s.closedError()
		}
	}
	releaseSlot := func() {
		s.mu.Lock()
		s.outOpen--
		s.signalOutLocked()
		s.mu.Unlock()
	}
	var ln *lane
	wantLease := o.Lane == LaneLeased || (o.Lane == LaneAuto && flags&schema.MethodShared == 0)
	if wantLease {
		l, err := s.acquireLane(ctx)
		if err != nil {
			releaseSlot()
			return nil, err
		}
		ln = l
	}
	if ln == nil {
		ln = s.shared
	}
	leased := !ln.shared

	md := r.Metadata.Clone()
	if o.Credit > 0 {
		md.SetCredit(o.Credit)
	}
	if dl, ok := ctx.Deadline(); ok {
		if _, has := md[wire.SigilKey(wire.KeyDeadline)]; !has {
			ms := time.Until(dl).Milliseconds()
			if ms <= 0 {
				releaseSlot()
				if leased {
					s.mu.Lock()
					s.releaseLaneLocked(ln)
					s.mu.Unlock()
				}
				return nil, &Error{Code: status.DeadlineExceeded, Message: "the deadline has passed"}
			}
			md.SetDeadline(uint64(ms))
		}
	}
	s.mu.Lock()
	peerL, localL := s.peerLimits, s.localLimits
	s.mu.Unlock()
	recvInit := wire.InitialCredit(localL, leased, nil)
	if v, ok, err := md.Credit(); err == nil && ok {
		recvInit = v
	}
	c := &call{s: s, caller: true, ln: ln, facet: r.FacetID, method: r.MethodID, def: def, codec: codec,
		md: md, manual: o.ManualCredit, counted: true, recvInit: recvInit}
	c.h = newHalves(flags)
	c.sendWin = *wire.NewCreditWindow(wire.InitialCredit(peerL, leased, nil))
	c.recvWin = *wire.NewCreditWindow(recvInit)
	c.h.request()

	c.sendMu.Lock()
	err := ln.writeRequest(func() []byte {
		s.mu.Lock()
		c.id = s.nextID
		s.nextID += 2
		s.calls[c.id] = c
		if leased {
			ln.current = c
		}
		s.mu.Unlock()
		return (&wire.Request{CallID: c.id, FacetID: r.FacetID, MethodID: r.MethodID, Metadata: md, Input: r.Input}).AppendTo(nil)
	})
	c.sendMu.Unlock()
	if err != nil {
		e := asError(err)
		if e.Code == status.Unavailable {
			if g, nd := s.peerGoAway(); g != nil {
				// The peer had closed the session: report why (for example
				// a rejected optimistic start, 5.3), not the failed write.
				e = &Error{Code: status.Code(g.Status), Message: g.Reason, Remote: true, NotDispatched: nd}
			}
		}
		if c.id == 0 {
			// Never sent.
			e = &Error{Code: e.Code, Message: e.Message, NotDispatched: true}
			if leased {
				s.mu.Lock()
				s.releaseLaneLocked(ln)
				s.mu.Unlock()
			}
		}
		c.failLocal(e)
		return nil, e
	}
	if ctx.Done() != nil {
		stop := context.AfterFunc(ctx, func() { c.ctxDone(ctx) })
		c.mu.Lock()
		c.stopCx = stop
		removed := c.removed
		c.mu.Unlock()
		if removed {
			stop()
		}
	}
	return c, nil
}

// writeRequest writes a Request whose call ID is assigned while the lane's
// write lock is held, so IDs go out in increasing order on each stream.
func (l *lane) writeRequest(gen func() []byte) error {
	s := l.s
	if l.shared && s.role == wire.Client {
		if err := s.preWelcomeBudget(64); err != nil {
			return err
		}
	}
	l.wmu.Lock()
	b := gen()
	if max := s.peerLimitsSnapshot().MaxMessageSize; uint64(len(b)) > max {
		l.wmu.Unlock()
		return &Error{Code: status.MessageTooLarge, Message: "Request exceeds the peer's maxMessageSize"}
	}
	err := l.st.WriteMessage(b)
	l.wmu.Unlock()
	if err != nil {
		if l.shared {
			s.lost(err)
		} else {
			s.laneBroken(l, err)
		}
		return s.wrapTransportErr(err)
	}
	if l.shared {
		s.lastSend.Store(s.clock.Now().UnixNano())
	}
	return nil
}

// ctxDone cancels the call when its context ends first (7.5: the caller
// MAY send Cancel(deadline_exceeded) when its own timer fires).
func (c *call) ctxDone(ctx context.Context) {
	code := status.Cancelled
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		code = status.DeadlineExceeded
	}
	c.mu.Lock()
	if c.ended || c.h.calleeDone || c.cancelSent {
		c.mu.Unlock()
		return
	}
	if c.localErr == nil {
		c.localErr = &Error{Code: code, Message: ctx.Err().Error()}
	}
	c.broadcastLocked()
	c.mu.Unlock()
	_ = c.sendCancel(code)
}

func (c *call) sendRaw(ctx context.Context, b []byte) error {
	kind, _, err := wire.PeekCall(b)
	if err != nil {
		return err
	}
	switch {
	case kind == wire.KindCredit:
		return nil
	case kind == wire.KindRequest:
		return errors.New("session: a Request cannot be sent with SendRaw")
	case !kind.IsCall():
		return ErrWrongDirection
	}
	nb, err := wire.RewriteCallID(b, c.id)
	if err != nil {
		return err
	}
	max := c.s.peerLimitsSnapshot().MaxMessageSize
	if uint64(len(nb)) > max {
		if kind != wire.KindBytes {
			return &Error{Code: status.MessageTooLarge, Message: "message exceeds the next hop's maxMessageSize"}
		}
		m, err := wire.Decode(nb)
		if err != nil {
			return err
		}
		bm := m.(*wire.Bytes)
		return c.sendBytes(ctx, bm.Token, bm.Data, bm.Fin)
	}
	n, err := wire.CountedBytesRaw(nb)
	if err != nil {
		return err
	}
	return c.send(ctx, kind, nb, n, true)
}

// chunkSize is the largest Bytes chunk for this call's stream (7.8).
func (c *call) chunkSize() int {
	max := int(c.s.peerLimitsSnapshot().MaxMessageSize) - 32
	n := LeaseChunk
	if c.ln.shared {
		n = SharedChunk
	}
	if n > max {
		n = max
	}
	if n < 1 {
		n = 1
	}
	return n
}

// sendBytes sends data for a token in chunks; fin marks the last.
func (c *call) sendBytes(ctx context.Context, tok uint64, data []byte, fin bool) error {
	size := c.chunkSize()
	for {
		chunk := data
		if len(chunk) > size {
			chunk = chunk[:size]
		}
		data = data[len(chunk):]
		last := fin && len(data) == 0
		b := (&wire.Bytes{CallID: c.id, Token: tok, Data: chunk, Fin: last}).AppendTo(nil)
		if err := c.send(ctx, wire.KindBytes, b, uint64(len(chunk)), true); err != nil {
			return err
		}
		if len(data) == 0 {
			return nil
		}
	}
}

// Notify sends a notification (call ID 0, shared lane, best-effort, 7.3).
func (s *Session) Notify(ctx context.Context, facetID, methodID uint64, input any) error {
	s.mu.Lock()
	f, def := lookupMethod(s.peerSc, facetID, methodID)
	s.mu.Unlock()
	if def == nil {
		return Errorf(status.Unimplemented, "facet %d has no method %d in the peer's schema", facetID, methodID)
	}
	if !def.IsNotification() {
		return Errorf(status.InvalidArgument, "method %d is not a notification", methodID)
	}
	codec, err := codecFor(&s.codecMu, s.peerCodecs, f)
	if err != nil {
		return err
	}
	in, err := codec.Encode(def.Input, input)
	if err != nil {
		return &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return s.NotifyRaw(RawRequest{FacetID: facetID, MethodID: methodID, Input: in})
}

// NotifyRaw sends a notification with an encoded input.
func (s *Session) NotifyRaw(r RawRequest) error {
	s.mu.Lock()
	closed, draining := s.closed, s.draining
	s.mu.Unlock()
	if closed {
		return s.closedError()
	}
	if draining {
		return &Error{Code: status.GoingAway, Message: "the session is shutting down"}
	}
	b := (&wire.Request{CallID: wire.NotificationID, FacetID: r.FacetID, MethodID: r.MethodID, Metadata: r.Metadata, Input: r.Input}).AppendTo(nil)
	return s.shared.write(b)
}
