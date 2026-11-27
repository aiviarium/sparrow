package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Handler serves incoming calls. ServeCall runs in its own goroutine per
// call; it must finish the callee's half (Respond, End or Fail, or the raw
// equivalents). If it returns without doing so the session answers
// Error(internal). For a notification there is nothing to answer.
type Handler interface {
	ServeCall(ctx context.Context, call *ServerCall)
}

// HandlerFunc is a typed handler. Its result finishes the call: an error
// becomes Error (the code of an *Error, or cancelled / deadline_exceeded /
// unknown); otherwise a method whose output is a stream or byte stream gets
// End, and any other method gets Response(output) (then End if the method
// has flag 0x10, for byte tokens in the output). A typed handler's Cancel
// and deadline are answered by the session at once; its context is
// cancelled.
type HandlerFunc func(ctx context.Context, call *ServerCall) (any, error)

// ServeCall implements Handler.
func (f HandlerFunc) ServeCall(ctx context.Context, sc *ServerCall) {
	sc.c.enableAutoAnswer()
	out, err := f(ctx, sc)
	if sc.Notification() {
		return
	}
	if err != nil {
		_ = sc.Fail(err)
		return
	}
	def := sc.c.def
	if def == nil {
		_ = sc.Fail(Errorf(status.Unimplemented, "no such method"))
		return
	}
	if def.Output.IsStream() || def.Output.Kind == schema.RefByteStream {
		_ = sc.End(nil)
		return
	}
	sc.c.mu.Lock()
	responded := sc.c.typed.responded
	sc.c.mu.Unlock()
	if !responded {
		if err := sc.Respond(ctx, out); err != nil {
			if e, ok := err.(*Error); ok && e.Code == status.InvalidArgument {
				_ = sc.Fail(&Error{Code: status.Internal, Message: "cannot encode the output: " + e.Message})
			}
			return
		}
	}
	if def.OutputEnds() {
		_ = sc.End(nil)
	}
}

// ServerCall is a call the peer made to this side.
type ServerCall struct{ c *call }

// ID returns the call ID (0 for a notification).
func (sc *ServerCall) ID() uint64 { return sc.c.id }

// FacetID returns the facet the call names.
func (sc *ServerCall) FacetID() uint64 { return sc.c.facet }

// MethodID returns the method the call names.
func (sc *ServerCall) MethodID() uint64 { return sc.c.method }

// Method returns the method definition from this side's schema.
func (sc *ServerCall) Method() *schema.Method { return sc.c.def }

// Codec returns the value codec of the method's facet.
func (sc *ServerCall) Codec() *value.Codec { return sc.c.codec }

// Notification reports whether the call is a notification (call ID 0).
func (sc *ServerCall) Notification() bool { return sc.c.id == wire.NotificationID }

// Shared reports whether the call runs on the shared lane.
func (sc *ServerCall) Shared() bool { return sc.c.ln.shared }

// Request returns the Request as received; its Input and Metadata values
// are raw views, ready to forward byte for byte.
func (sc *ServerCall) Request() *wire.Request { return sc.c.req }

// RequestRaw returns the encoded Request as received.
func (sc *ServerCall) RequestRaw() []byte { return sc.c.reqRaw }

// Metadata returns the Request metadata.
func (sc *ServerCall) Metadata() wire.Metadata { return sc.c.md }

// Principal returns the principal metadata key (10.6). Honour it only on
// an authenticated link to a hub.
func (sc *ServerCall) Principal() (string, bool) {
	p, ok, err := sc.c.md.Principal()
	return p, ok && err == nil
}

// CallContext returns the context metadata key (10.6).
func (sc *ServerCall) CallContext() ([]byte, bool) {
	b, ok, err := sc.c.md.Context()
	return b, ok && err == nil
}

// Session returns the session the call arrived on.
func (sc *ServerCall) Session() *Session { return sc.c.s }

// Deadline returns when the caller's deadline passes, if it set one.
func (sc *ServerCall) Deadline() (time.Time, bool) {
	sc.c.mu.Lock()
	defer sc.c.mu.Unlock()
	return sc.c.typed.deadline, !sc.c.typed.deadline.IsZero()
}

// CallerCredit returns the initial credit the caller granted for the
// callee's half: its credit metadata key, or the default for its stream. A
// hub forwarding the call may set credit no higher than this (10.5).
func (sc *ServerCall) CallerCredit() uint64 { return sc.c.sendInit }

// SetManualCredit makes RecvRaw leave credit to Release (10.5).
func (sc *ServerCall) SetManualCredit(on bool) {
	sc.c.mu.Lock()
	sc.c.manual = on
	sc.c.mu.Unlock()
}

// RecvRaw returns the next message from the caller: Item, Bytes, End or
// Cancel, exactly as received; io.EOF once the caller's half is finished.
func (sc *ServerCall) RecvRaw(ctx context.Context) (*Msg, error) { return sc.c.recvRaw(ctx) }

// Release returns the credit of a message taken under manual credit.
func (sc *ServerCall) Release(m *Msg) { sc.c.release(m) }

// SendRaw sends an encoded callee message (Response, Item, End, Error,
// Progress, Headers or Bytes), replacing its call ID; see
// ClientCall.SendRaw.
func (sc *ServerCall) SendRaw(ctx context.Context, b []byte) error { return sc.c.sendRaw(ctx, b) }

// Fail finishes the call with Error.
func (sc *ServerCall) Fail(err error) error {
	e := asError(err)
	if e.Code == status.OK {
		e = &Error{Code: status.Unknown, Message: e.Message}
	}
	return sc.c.sendError(e)
}

// Respond sends Response(output), encoded with the method's output type.
func (sc *ServerCall) Respond(ctx context.Context, output any) error {
	c := sc.c
	if c.codec == nil || c.def == nil {
		return Errorf(status.Unimplemented, "no method definition")
	}
	raw, err := encodeWhole(c.codec, c.def.Output, output)
	if err != nil {
		return &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return sc.RespondRaw(ctx, raw)
}

// RespondRaw sends Response with an encoded output.
func (sc *ServerCall) RespondRaw(ctx context.Context, output cbor.Raw) error {
	c := sc.c
	b := (&wire.Response{CallID: c.id, Output: output}).AppendTo(nil)
	if err := c.send(ctx, wire.KindResponse, b, 0, true); err != nil {
		return err
	}
	c.mu.Lock()
	c.typed.responded = true
	c.mu.Unlock()
	return nil
}

// End finishes the callee's half with End (methods with flag 0x10).
func (sc *ServerCall) End(trailers wire.Metadata) error {
	b := (&wire.End{CallID: sc.c.id, Trailers: trailers}).AppendTo(nil)
	return sc.c.send(context.Background(), wire.KindEnd, b, 0, true)
}

// SendHeaders sends Headers (before the first Item or Bytes).
func (sc *ServerCall) SendHeaders(md wire.Metadata) error {
	b := (&wire.Headers{CallID: sc.c.id, Metadata: md}).AppendTo(nil)
	return sc.c.send(context.Background(), wire.KindHeaders, b, 0, true)
}

// Progress sends Progress (counted against credit).
func (sc *ServerCall) Progress(ctx context.Context, done uint64, total *uint64, note *string) error {
	b := (&wire.Progress{CallID: sc.c.id, Done: done, Total: total, Note: note}).AppendTo(nil)
	return sc.c.send(ctx, wire.KindProgress, b, uint64(len(b)), true)
}

// Send sends one output stream element.
func (sc *ServerCall) Send(ctx context.Context, v any) error {
	c := sc.c
	if c.def == nil || !c.def.Output.IsStream() {
		return Errorf(status.Internal, "the method's output is not a stream")
	}
	raw, err := c.codec.Encode(*c.def.Output.Elem, v)
	if err != nil {
		return &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return c.sendItem(ctx, raw)
}

// Input decodes the Request input (nil for a stream or byte-stream input).
func (sc *ServerCall) Input() (any, error) {
	c := sc.c
	if c.def == nil || c.codec == nil {
		return nil, Errorf(status.Unimplemented, "no method definition")
	}
	if c.def.Input.IsStream() || c.def.Input.Kind == schema.RefByteStream {
		return nil, nil
	}
	v, err := c.codec.Decode(c.def.Input, c.req.Input)
	if err != nil {
		return nil, &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return v, nil
}

// Recv returns the next input stream element; io.EOF after End.
func (sc *ServerCall) Recv(ctx context.Context) (any, error) { return sc.c.recvItem(ctx) }

// Reader returns the reader for an input byte token (0 for an input of
// exactly [4]).
func (sc *ServerCall) Reader(token uint64) *ByteReader { return &ByteReader{c: sc.c, tok: token} }

// Writer returns a writer for an output byte token (0 for an output of
// exactly [4]); Close sends the final chunk.
func (sc *ServerCall) Writer(ctx context.Context, token uint64) *ByteWriter {
	return &ByteWriter{c: sc.c, tok: token, ctx: ctx}
}

func (c *call) enableAutoAnswer() {
	c.mu.Lock()
	c.autoAnswer = true
	cancelled := c.h.callerDone && c.cancelRecv
	open := !c.h.calleeDone
	code := c.cancelRecvCode
	c.mu.Unlock()
	if cancelled && open {
		go func() { _ = c.sendError(&Error{Code: code, Message: "cancelled"}) }()
	}
}

// deadlineExpired answers Error(deadline_exceeded) when the caller's
// deadline passes (7.5).
func (c *call) deadlineExpired() {
	c.mu.Lock()
	open := !c.h.calleeDone && !c.ended
	c.mu.Unlock()
	e := &Error{Code: status.DeadlineExceeded, Message: "deadline exceeded"}
	if c.cancel != nil {
		c.cancel(e)
	}
	if open {
		_ = c.sendError(e)
	}
}

// onRequest handles a Request (reader goroutine).
func (s *Session) onRequest(l *lane, r *wire.Request, b []byte) {
	s.mu.Lock()
	if s.closed || (s.role == wire.Server && s.goAwaySent != nil && !s.readyDone) {
		// An optimistic start that was rejected dispatches nothing (5.3).
		s.mu.Unlock()
		return
	}
	localSc := s.localSc
	flags := s.methodFlags[[2]uint64{r.FacetID, r.MethodID}]
	peerL, localL := s.peerLimits, s.localLimits
	s.mu.Unlock()
	f, def := lookupMethod(localSc, r.FacetID, r.MethodID)
	if def != nil {
		flags = def.Flags
	}
	if r.CallID == wire.NotificationID {
		s.onNotification(l, r, b, f, def)
		return
	}
	if wire.CallerOf(r.CallID) == s.role {
		s.fail(status.ProtocolError, "Request with a call ID of this side's parity")
		return
	}
	if l.opened {
		s.fail(status.ProtocolError, "Request on a leased stream this side opened")
		return
	}
	if !l.shared {
		s.mu.Lock()
		cur := l.current
		awaiting := l.awaitCallerEnd != 0
		s.mu.Unlock()
		if awaiting {
			s.fail(status.ProtocolError, "Request on a leased stream that is not idle (both halves of its last call finished, 7.1)")
			return
		}
		if cur != nil {
			cur.mu.Lock()
			busy := !cur.ended
			cur.mu.Unlock()
			if busy {
				s.fail(status.ProtocolError, "Request on a leased stream that is not idle (both halves of its last call finished, 7.1)")
				return
			}
		}
	}
	leased := !l.shared
	var override *uint64
	if v, ok, err := r.Metadata.Credit(); err == nil && ok {
		override = &v
	}
	recvInit := wire.InitialCredit(localL, leased, nil)
	c := &call{s: s, id: r.CallID, ln: l, facet: r.FacetID, method: r.MethodID, def: def,
		md: r.Metadata, req: r, reqRaw: b, recvInit: recvInit}
	c.h = newHalves(flags)
	c.h.request()
	c.sendInit = wire.InitialCredit(peerL, leased, override)
	c.sendWin = *wire.NewCreditWindow(c.sendInit)
	c.recvWin = *wire.NewCreditWindow(recvInit)
	if f != nil && def != nil {
		c.codec, _ = codecFor(&s.codecMu, s.localCodecs, f)
	}

	// The call's context is ready before the call is published in s.calls,
	// where the session's end may fail it at once.
	var deadlineIn time.Duration
	hasDeadline := false
	ctx, cancel := context.WithCancelCause(s.ctx)
	if ms, ok, err := r.Metadata.Deadline(); err == nil && ok {
		d := time.Duration(ms) * time.Millisecond
		c.typed.deadline = s.clock.Now().Add(d)
		if _, real := s.clock.(RealClock); real {
			var cancel2 context.CancelFunc
			ctx, cancel2 = context.WithDeadlineCause(ctx, time.Now().Add(d), &Error{Code: status.DeadlineExceeded, Message: "deadline exceeded"})
			inner := cancel
			cancel = func(e error) { inner(e); cancel2() }
		}
		deadlineIn = d
		hasDeadline = true
	}
	c.ctx, c.cancel = ctx, cancel
	s.mu.Lock()
	if _, dup := s.calls[r.CallID]; dup {
		s.mu.Unlock()
		cancel(nil)
		s.fail(status.ProtocolError, "Request for a call ID that is open")
		return
	}
	s.calls[r.CallID] = c
	if leased {
		l.current = c
	}
	var reject *Error
	switch {
	case s.role == wire.Server && !s.readyDone && l.shared:
		reject = &Error{Code: status.NotReady, Message: "call before Ready"}
	case s.draining:
		reject = &Error{Code: status.GoingAway, Message: "the session is shutting down"}
	case def == nil:
		reject = &Error{Code: status.Unimplemented, Message: fmt.Sprintf("facet %d has no method %d", r.FacetID, r.MethodID)}
	case def.IsNotification():
		// 7.1: a Request with a nonzero call ID for a notification method.
		reject = &Error{Code: status.InvalidArgument, Message: fmt.Sprintf("method %d of facet %d is a notification; send it with call ID 0", r.MethodID, r.FacetID)}
	case uint64(s.inOpen) >= localL.MaxConcurrentCalls:
		reject = &Error{Code: status.ResourceExhausted, Message: "maxConcurrentCalls reached"}
	default:
		s.inOpen++
		c.counted = true
	}
	held := s.role == wire.Server && !s.readyDone
	s.mu.Unlock()
	if hasDeadline {
		tm := s.clock.AfterFunc(deadlineIn, c.deadlineExpired)
		c.mu.Lock()
		if c.removed {
			tm.Stop() // ended meanwhile (the session closed)
		} else {
			c.deadlineT = tm
		}
		c.mu.Unlock()
	}
	if reject != nil {
		_ = c.sendError(reject)
		return
	}
	go s.serve(c, held)
}

func (s *Session) serve(c *call, held bool) {
	if held {
		select {
		case <-s.readyCh:
		case <-s.done:
			return
		}
	}
	sc := &ServerCall{c: c}
	defer func() {
		if r := recover(); r != nil {
			s.logf("handler panic: %v", r)
			_ = c.sendError(&Error{Code: status.Internal, Message: "handler panic"})
			return
		}
		c.mu.Lock()
		open := !c.h.calleeDone && !c.ended
		c.mu.Unlock()
		if open {
			_ = c.sendError(&Error{Code: status.Internal, Message: "the handler returned without answering"})
		}
	}()
	if s.cfg.Handler == nil {
		_ = c.sendError(&Error{Code: status.Unimplemented, Message: "no handler"})
		return
	}
	s.cfg.Handler.ServeCall(c.ctx, sc)
}

func (s *Session) onNotification(l *lane, r *wire.Request, b []byte, f *schema.Facet, def *schema.Method) {
	if !l.shared {
		s.fail(status.ProtocolError, "notification on a leased stream")
		return
	}
	s.mu.Lock()
	drop := (s.role == wire.Server && !s.readyDone) || s.draining
	s.mu.Unlock()
	if drop || def == nil || !def.IsNotification() || s.cfg.Handler == nil {
		return
	}
	select {
	case s.notifySem <- struct{}{}:
	default:
		s.logf("dropped a notification: too many in flight")
		return
	}
	c := &call{s: s, id: 0, ln: l, facet: r.FacetID, method: r.MethodID, def: def, md: r.Metadata, req: r, reqRaw: b, ended: true, removed: true}
	c.h = halves{callerDone: true, calleeDone: true}
	if f != nil {
		c.codec, _ = codecFor(&s.codecMu, s.localCodecs, f)
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	c.ctx, c.cancel = ctx, cancel
	go func() {
		defer func() {
			<-s.notifySem
			cancel(nil)
			if r := recover(); r != nil {
				s.logf("notification handler panic: %v", r)
			}
		}()
		s.cfg.Handler.ServeCall(ctx, &ServerCall{c: c})
	}()
}

// Mux routes incoming calls by facet and method. Typed handlers are
// registered per method, raw handlers per facet (a hub forwards whole
// facets), and a fallback takes the rest.
type Mux struct {
	mu       sync.RWMutex
	methods  map[[2]uint64]Handler
	facets   map[uint64]Handler
	fallback Handler
}

// NewMux returns an empty Mux.
func NewMux() *Mux {
	return &Mux{methods: map[[2]uint64]Handler{}, facets: map[uint64]Handler{}}
}

// Handle registers a handler for one method.
func (m *Mux) Handle(facet, method uint64, h Handler) {
	m.mu.Lock()
	m.methods[[2]uint64{facet, method}] = h
	m.mu.Unlock()
}

// HandleFunc registers a typed handler for one method.
func (m *Mux) HandleFunc(facet, method uint64, f HandlerFunc) { m.Handle(facet, method, f) }

// HandleFacet registers a handler for every method of a facet without a
// method handler of its own.
func (m *Mux) HandleFacet(facet uint64, h Handler) {
	m.mu.Lock()
	m.facets[facet] = h
	m.mu.Unlock()
}

// HandleFallback registers the handler for everything else.
func (m *Mux) HandleFallback(h Handler) {
	m.mu.Lock()
	m.fallback = h
	m.mu.Unlock()
}

// RemoveFacet drops every handler of a facet.
func (m *Mux) RemoveFacet(facet uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.facets, facet)
	for k := range m.methods {
		if k[0] == facet {
			delete(m.methods, k)
		}
	}
}

// ServeCall implements Handler.
func (m *Mux) ServeCall(ctx context.Context, sc *ServerCall) {
	m.mu.RLock()
	h := m.methods[[2]uint64{sc.FacetID(), sc.MethodID()}]
	if h == nil {
		h = m.facets[sc.FacetID()]
	}
	if h == nil {
		h = m.fallback
	}
	m.mu.RUnlock()
	if h == nil {
		if !sc.Notification() {
			_ = sc.Fail(Errorf(status.Unimplemented, "no handler for facet %d method %d", sc.FacetID(), sc.MethodID()))
		}
		return
	}
	h.ServeCall(ctx, sc)
}
