// Package transport defines the stream abstraction a Sparrow session runs
// on (sections 4.1 and 4.4) and the errors bindings report. The bindings
// live in subpackages:
//
//   - webtransport: WebTransport over HTTP/3 (4.5), shared lane plus leased
//     streams;
//   - websocket: one Sparrow message per binary WebSocket message (4.6),
//     shared lane only;
//   - mem: an in-memory binding with leased streams, for tests.
//
// A binding moves whole messages. It handles stream headers (0x00 shared
// lane, 0x01 leased) and framing, and enforces the read limit
// (maxMessageSize) before buffering a message. Everything else, including
// the maxStreams counting rule of 4.2, is the session's job.
package transport

import (
	"context"
	"errors"
	"fmt"

	"github.com/aiviarium/sparrow-rpc/go/status"
)

// Stream is one ordered, bidirectional message stream: the shared lane or
// a leased stream.
//
// ReadMessage may be called from one goroutine at a time, and WriteMessage
// from one goroutine at a time (the session serializes writes per stream);
// the two may run concurrently with each other and with CloseWrite and
// Reset.
type Stream interface {
	// ReadMessage returns the next whole message; the caller owns the
	// slice. It returns io.EOF once the peer has finished its direction,
	// a *ResetError if the peer reset the stream, a *wire.TooLargeError
	// for a message above the read limit, and ErrClosed (or a
	// *CloseError) once the connection is gone.
	ReadMessage() ([]byte, error)
	// WriteMessage writes one message (and the stream header first, on a
	// stream this side opened).
	WriteMessage(msg []byte) error
	// CloseWrite finishes the local direction after everything written so
	// far has been sent.
	CloseWrite() error
	// Reset aborts both directions of the stream, carrying a core status
	// code to the peer where the binding can (WebTransport).
	Reset(code status.Code)
}

// WriteResetter is implemented by streams that can abort only their sending
// direction and keep reading. A session uses it on a leased stream it
// resets, so it can count the stream until it has seen the end of the
// peer's direction too (4.2 rule 5).
type WriteResetter interface {
	ResetWrite(code status.Code)
}

// Conn is one transport connection carrying one session.
type Conn interface {
	// Leases reports whether the binding has leased streams. Without them
	// every call runs on the shared lane and maxStreams does not apply.
	Leases() bool
	// SharedLane returns the shared lane. On the client side the first call
	// opens it; on the server side it waits until the client has opened it.
	// It returns the same stream on every call.
	SharedLane(ctx context.Context) (Stream, error)
	// OpenStream opens a leased stream (header 0x01). It returns
	// ErrNoLeases on a binding without leased streams.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream returns the next leased stream the peer opened.
	AcceptStream(ctx context.Context) (Stream, error)
	// SetReadLimit sets the largest message ReadMessage accepts on every
	// stream of the connection (the receiver's own maxMessageSize).
	SetReadLimit(n uint64)
	// Close ends the connection. On WebTransport the code and reason
	// travel in the session close; on WebSocket in the close frame (1000
	// or 4000+code); on a pipe they are not sent (only GoAway carries
	// them). Close is idempotent.
	Close(code status.Code, reason string) error
	// Done is closed when the connection has ended, by either side.
	Done() <-chan struct{}
	// Err returns why the connection ended (a *CloseError where the
	// binding knows the code), or nil while it is open.
	Err() error
}

// ErrNoLeases is returned by OpenStream on a binding with no leased
// streams.
var ErrNoLeases = errors.New("transport: this binding has no leased streams")

// ErrClosed is returned by stream operations after the connection closed.
var ErrClosed = errors.New("transport: connection closed")

// ResetError reports a stream reset, with the core status code it carried.
type ResetError struct {
	Code   status.Code
	Remote bool
}

func (e *ResetError) Error() string {
	who := "locally"
	if e.Remote {
		who = "by the peer"
	}
	return fmt.Sprintf("transport: stream reset %s with %v", who, e.Code)
}

// CloseError reports how a connection ended.
type CloseError struct {
	Code   status.Code
	Reason string
	Remote bool
}

func (e *CloseError) Error() string {
	who := "locally"
	if e.Remote {
		who = "by the peer"
	}
	if e.Reason == "" {
		return fmt.Sprintf("transport: connection closed %s with %v", who, e.Code)
	}
	return fmt.Sprintf("transport: connection closed %s with %v: %s", who, e.Code, e.Reason)
}

// Is makes errors.Is(err, ErrClosed) true for a CloseError.
func (e *CloseError) Is(target error) bool { return target == ErrClosed }

// ProtocolError is reported (as the connection's close reason) when the
// peer broke a stream-level rule of section 4.1, such as a bad stream
// header or a second shared lane.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "transport: protocol error: " + e.Msg }
