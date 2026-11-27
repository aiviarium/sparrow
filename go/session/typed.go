package session

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// typedState is the typed view of a call's received messages. The typed
// API moves every queued raw message into it (pump); a message's credit is
// returned only when the application takes its data.
type typedState struct {
	items     []*Msg
	tokens    map[uint64]*tokenBuf
	headers   wire.Metadata
	hasHdrs   bool
	trailers  wire.Metadata
	response  *Msg
	final     *Error // Error from the peer
	peerEnded bool   // End, Error, Cancel or Response(final) seen
	progress  *wire.Progress
	responded bool
	deadline  time.Time
}

type tokenBuf struct {
	data []byte
	fin  bool
}

// pumpLocked moves queued messages into the typed state and returns credit
// to grant for messages consumed on the spot.
func (c *call) pumpLocked() uint64 {
	var g uint64
	t := &c.typed
	for _, m := range c.q {
		switch x := m.Message.(type) {
		case *wire.Item:
			t.items = append(t.items, m)
		case *wire.Bytes:
			if t.tokens == nil {
				t.tokens = map[uint64]*tokenBuf{}
			}
			tb := t.tokens[x.Token]
			if tb == nil {
				tb = &tokenBuf{}
				t.tokens[x.Token] = tb
			}
			if !tb.fin {
				tb.data = append(tb.data, x.Data...)
				tb.fin = x.Fin
			} else {
				g += c.consumedLocked(m.counted)
			}
		case *wire.Headers:
			t.headers, t.hasHdrs = x.Metadata, true
		case *wire.Progress:
			t.progress = x
			g += c.consumedLocked(m.counted)
		case *wire.Response:
			t.response = m
			if c.def == nil || !c.def.OutputEnds() {
				t.peerEnded = true
			}
		case *wire.End:
			t.trailers = x.Trailers
			t.peerEnded = true
		case *wire.Error:
			t.final = &Error{Code: status.Code(x.Status), Message: x.Message, Details: x.Details, Remote: true}
			t.peerEnded = true
		case *wire.Cancel:
			t.final = &Error{Code: status.Code(x.Status), Message: "cancelled by the caller", Remote: true}
			t.peerEnded = true
		}
	}
	for i := range c.q {
		c.q[i] = nil
	}
	c.q = c.q[:0]
	return g
}

// waitTyped waits until cond holds (under c.mu, after pumping) or the call
// fails. It returns with c.mu held on success.
func (c *call) waitTyped(ctx context.Context, cond func() bool) error {
	for {
		g := c.pumpLocked()
		if g > 0 {
			c.mu.Unlock()
			c.grant(g)
			c.mu.Lock()
			continue
		}
		if cond() {
			return nil
		}
		if c.localErr != nil && !c.typed.peerEnded {
			e := c.localErr
			c.mu.Unlock()
			return e
		}
		if c.typed.peerEnded || c.peerHalfDoneLocked() || c.ended {
			return io.EOF
		}
		ch := c.waitCh()
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			c.mu.Lock()
			if len(c.q) == 0 {
				c.mu.Unlock()
				return ctx.Err()
			}
			continue
		}
		c.mu.Lock()
	}
}

func (c *call) itemType() (schema.TypeRef, bool) {
	if c.def == nil {
		return schema.TypeRef{}, false
	}
	t := c.def.Input
	if c.caller {
		t = c.def.Output
	}
	if !t.IsStream() {
		return schema.TypeRef{}, false
	}
	return *t.Elem, true
}

// recvItem returns the next stream element, decoded.
func (c *call) recvItem(ctx context.Context) (any, error) {
	c.mu.Lock()
	err := c.waitTyped(ctx, func() bool { return len(c.typed.items) > 0 })
	if err == io.EOF {
		defer c.mu.Unlock()
		if f := c.typed.final; f != nil {
			return nil, f
		}
		if c.localErr != nil {
			return nil, c.localErr
		}
		return nil, io.EOF
	}
	if err != nil {
		return nil, err
	}
	m := c.typed.items[0]
	c.typed.items[0] = nil
	c.typed.items = c.typed.items[1:]
	g := c.consumedLocked(m.counted)
	c.mu.Unlock()
	c.grant(g)
	t, ok := c.itemType()
	if !ok || c.codec == nil {
		return nil, Errorf(status.Internal, "the method has no stream of values in this direction")
	}
	v, err := c.codec.Decode(t, m.Message.(*wire.Item).Value)
	if err != nil {
		return nil, &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return v, nil
}

// sendItem sends an encoded stream element.
func (c *call) sendItem(ctx context.Context, raw cbor.Raw) error {
	b := (&wire.Item{CallID: c.id, Value: raw}).AppendTo(nil)
	return c.send(ctx, wire.KindItem, b, uint64(len(b)), true)
}

// ---------------------------------------------------------------------------
// Typed client API
// ---------------------------------------------------------------------------

// Send sends one input stream element (client or bidi stream).
func (cc *ClientCall) Send(ctx context.Context, v any) error {
	c := cc.c
	if c.def == nil || !c.def.Input.IsStream() {
		return Errorf(status.Internal, "the method's input is not a stream")
	}
	raw, err := c.codec.Encode(*c.def.Input.Elem, v)
	if err != nil {
		return &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return c.sendItem(ctx, raw)
}

// SendRawItem sends one input stream element already encoded.
func (cc *ClientCall) SendRawItem(ctx context.Context, raw cbor.Raw) error {
	return cc.c.sendItem(ctx, raw)
}

// CloseSend finishes the caller's half with End (methods with flag 0x8).
// When the callee finished first (an upload answered as soon as its last
// chunk arrived), the session has already sent End on the caller's behalf
// (7.1) and CloseSend returns nil: the half is finished either way.
func (cc *ClientCall) CloseSend(trailers wire.Metadata) error {
	c := cc.c
	b := (&wire.End{CallID: c.id, Trailers: trailers}).AppendTo(nil)
	err := c.send(context.Background(), wire.KindEnd, b, 0, false)
	if errors.Is(err, ErrCallEnded) || errors.Is(err, ErrHalfClosed) {
		c.mu.Lock()
		behalf := c.h.calleeDone && c.localErr == nil
		c.mu.Unlock()
		if behalf {
			return nil
		}
	}
	return err
}

// Recv returns the next output stream element; io.EOF after End, or the
// callee's *Error.
func (cc *ClientCall) Recv(ctx context.Context) (any, error) { return cc.c.recvItem(ctx) }

// Response waits for the unary result and decodes it. For a method with
// flag 0x10 (byte tokens in the output) it returns as soon as the Response
// arrives; read the tokens with Reader and call Wait for the End.
func (cc *ClientCall) Response(ctx context.Context) (any, error) {
	raw, err := cc.ResponseRaw(ctx)
	if err != nil {
		return nil, err
	}
	c := cc.c
	if c.def == nil || c.codec == nil {
		return raw, nil
	}
	v, err := c.codec.Decode(c.def.Output, raw)
	if err != nil {
		return nil, &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return v, nil
}

// ResponseRaw waits for the Response and returns its encoded output.
func (cc *ClientCall) ResponseRaw(ctx context.Context) (cbor.Raw, error) {
	c := cc.c
	c.mu.Lock()
	err := c.waitTyped(ctx, func() bool { return c.typed.response != nil })
	if err == io.EOF {
		defer c.mu.Unlock()
		if f := c.typed.final; f != nil {
			return nil, f
		}
		if c.localErr != nil {
			return nil, c.localErr
		}
		return nil, Errorf(status.ProtocolError, "the call ended without a Response")
	}
	if err != nil {
		return nil, err
	}
	m := c.typed.response
	c.mu.Unlock()
	return m.Message.(*wire.Response).Output, nil
}

// Headers waits for Headers or the first data and returns the headers (nil
// if the callee sent none).
func (cc *ClientCall) Headers(ctx context.Context) (wire.Metadata, error) {
	c := cc.c
	c.mu.Lock()
	err := c.waitTyped(ctx, func() bool {
		return c.typed.hasHdrs || len(c.typed.items) > 0 || len(c.typed.tokens) > 0 || c.typed.response != nil
	})
	if err != nil && err != io.EOF {
		return nil, err
	}
	defer c.mu.Unlock()
	return c.typed.headers, nil
}

// Wait waits for the callee's final message: nil after End or Response,
// the *Error otherwise. Unread items and bytes are discarded.
func (cc *ClientCall) Wait(ctx context.Context) error {
	c := cc.c
	c.mu.Lock()
	err := c.waitTyped(ctx, func() bool {
		var g uint64
		for _, m := range c.typed.items {
			g += c.consumedLocked(m.counted)
		}
		c.typed.items = nil
		for _, tb := range c.typed.tokens {
			g += c.consumedLocked(uint64(len(tb.data)))
			tb.data = nil
		}
		if g > 0 {
			go c.grant(g)
		}
		return c.typed.peerEnded
	})
	if err != nil && err != io.EOF {
		return err
	}
	defer c.mu.Unlock()
	if c.typed.final != nil {
		return c.typed.final
	}
	if c.localErr != nil && !c.typed.peerEnded {
		return c.localErr
	}
	return nil
}

// Trailers returns the End trailers, once End has arrived.
func (cc *ClientCall) Trailers() wire.Metadata {
	cc.c.mu.Lock()
	defer cc.c.mu.Unlock()
	return cc.c.typed.trailers
}

// LastProgress returns the latest Progress received, if any.
func (cc *ClientCall) LastProgress() *wire.Progress {
	cc.c.mu.Lock()
	defer cc.c.mu.Unlock()
	cc.c.pumpLocked()
	return cc.c.typed.progress
}

// Reader returns the reader for an output byte token.
func (cc *ClientCall) Reader(token uint64) *ByteReader { return &ByteReader{c: cc.c, tok: token} }

// Writer returns a writer for an input byte token; Close sends the final
// chunk. Then call CloseSend.
func (cc *ClientCall) Writer(ctx context.Context, token uint64) *ByteWriter {
	return &ByteWriter{c: cc.c, tok: token, ctx: ctx}
}

// ---------------------------------------------------------------------------
// Byte streams (7.8)
// ---------------------------------------------------------------------------

// ByteReader reads the data of one byte token. Read returns io.EOF after
// the chunk with fin, and an *Error with data_loss if the sender's half
// finished first (the token was cut off or never sent).
type ByteReader struct {
	c   *call
	tok uint64
}

// Read implements io.Reader.
func (r *ByteReader) Read(p []byte) (int, error) {
	return r.ReadContext(context.Background(), p)
}

// ReadContext is Read with a context.
func (r *ByteReader) ReadContext(ctx context.Context, p []byte) (int, error) {
	c := r.c
	c.mu.Lock()
	var tb *tokenBuf
	err := c.waitTyped(ctx, func() bool {
		tb = c.typed.tokens[r.tok]
		return tb != nil && (len(tb.data) > 0 || tb.fin)
	})
	if err == io.EOF {
		defer c.mu.Unlock()
		if c.localErr != nil && c.typed.final == nil {
			return 0, c.localErr
		}
		if c.typed.final != nil {
			return 0, c.typed.final
		}
		return 0, &Error{Code: status.DataLoss, Message: "byte token cut off"}
	}
	if err != nil {
		return 0, err
	}
	if len(tb.data) == 0 && tb.fin {
		c.mu.Unlock()
		return 0, io.EOF
	}
	n := copy(p, tb.data)
	tb.data = tb.data[n:]
	if len(tb.data) == 0 {
		tb.data = nil
	}
	g := c.consumedLocked(uint64(n))
	c.mu.Unlock()
	c.grant(g)
	return n, nil
}

// ByteWriter writes the data of one byte token in chunks (16 KiB on the
// shared lane, larger on a leased stream).
type ByteWriter struct {
	c      *call
	tok    uint64
	ctx    context.Context
	closed bool
}

// Write sends p as one or more Bytes chunks, waiting for credit.
func (w *ByteWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrHalfClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.c.sendBytes(w.ctx, w.tok, p, false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends the final (empty) chunk with fin.
func (w *ByteWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.c.sendBytes(w.ctx, w.tok, nil, true)
}

// WriteAll sends data with fin on the last chunk.
func (w *ByteWriter) WriteAll(data []byte) error {
	if w.closed {
		return ErrHalfClosed
	}
	w.closed = true
	return w.c.sendBytes(w.ctx, w.tok, data, true)
}
