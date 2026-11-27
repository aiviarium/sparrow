// Package pipe is the Sparrow pipe binding (section 4.7): one ordered byte
// stream, such as a child process's standard input and output, a unix
// socket or an SSH channel. There is a shared lane and nothing else; each
// message is preceded by its length as a QUIC varint, with no stream header.
// Closing the byte stream ends the session; status and reason travel only in
// GoAway.
package pipe

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Conn is a pipe connection.
type Conn struct {
	r      io.Reader
	w      io.Writer
	closeW func() error
	closeA func() error

	limit  atomic.Uint64
	fr     *wire.FrameReader
	fw     *wire.FrameWriter
	lane   *stream
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	err    error
	wOnce  sync.Once
	wErr   error
	closed atomic.Bool
}

// New returns a pipe connection over rwc. Closing the connection closes rwc.
// If rwc has a CloseWrite method (unix and TCP sockets), CloseWrite on the
// shared lane uses it.
func New(rwc io.ReadWriteCloser) *Conn {
	closeW := rwc.Close
	if cw, ok := rwc.(interface{ CloseWrite() error }); ok {
		closeW = cw.CloseWrite
	}
	return newConn(rwc, rwc, closeW, rwc.Close)
}

// NewSplit returns a pipe connection reading from r and writing to w, such
// as the two pipes of a child process. Closing the connection closes both.
func NewSplit(r io.ReadCloser, w io.WriteCloser) *Conn {
	return newConn(r, w, w.Close, func() error {
		e1 := w.Close()
		e2 := r.Close()
		if e1 != nil {
			return e1
		}
		return e2
	})
}

// Stdio returns a pipe connection on this process's standard input and
// output, for a process whose parent speaks Sparrow to it (the started
// process is the Sparrow client, 4.7). Nothing else may write to standard
// output afterwards. A hub never starts nodes (10.2); this is for other
// supervisors and tools.
func Stdio() *Conn { return NewSplit(os.Stdin, os.Stdout) }

// Spawn starts cmd with a pipe connection on its standard input and output.
// cmd.Stderr is left as configured; it is not part of the protocol. The
// returned connection is the starting side's end (the Sparrow server, 4.7).
// Close does not wait for the process; use cmd.Wait.
func Spawn(cmd *exec.Cmd) (*Conn, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return NewSplit(stdout, stdin), nil
}

func newConn(r io.Reader, w io.Writer, closeW, closeA func() error) *Conn {
	c := &Conn{r: r, w: w, closeW: closeW, closeA: closeA, done: make(chan struct{})}
	c.limit.Store(wire.DefaultMaxMessageSize)
	c.fr = wire.NewFrameReader(r, wire.DefaultMaxMessageSize)
	c.fw = wire.NewFrameWriter(w)
	c.lane = &stream{c: c}
	return c
}

// Leases is false: a pipe has only the shared lane.
func (c *Conn) Leases() bool { return false }

// SharedLane returns the single stream.
func (c *Conn) SharedLane(ctx context.Context) (transport.Stream, error) {
	if c.closed.Load() {
		return nil, transport.ErrClosed
	}
	return c.lane, nil
}

// OpenStream returns transport.ErrNoLeases.
func (c *Conn) OpenStream(context.Context) (transport.Stream, error) {
	return nil, transport.ErrNoLeases
}

// AcceptStream blocks until the connection closes.
func (c *Conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, transport.ErrClosed
	}
}

// SetReadLimit sets maxMessageSize for reading.
func (c *Conn) SetReadLimit(n uint64) { c.limit.Store(n) }

// Linger is how long Close waits, after finishing its own direction, for
// the peer to finish its own (5.6).
var Linger = 2 * time.Second

// Close closes the byte stream. The code and reason are not transmitted.
// It first finishes this side's direction and waits up to Linger for the
// peer to finish its own (seen by the reader), so messages in flight are
// not lost (5.6); a protocol_error closes at once.
func (c *Conn) Close(code status.Code, reason string) error {
	if !c.closed.Load() && code != status.ProtocolError {
		_ = c.lane.CloseWrite()
		t := time.NewTimer(Linger)
		select {
		case <-c.done:
		case <-t.C:
		}
		t.Stop()
	}
	return c.finish(&transport.CloseError{Code: code, Reason: reason}, true)
}

func (c *Conn) finish(err error, local bool) error {
	var cerr error
	c.once.Do(func() {
		c.closed.Store(true)
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		if local {
			cerr = c.closeA()
		} else {
			_ = c.closeA()
		}
		close(c.done)
	})
	return cerr
}

// Done is closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns why the connection ended.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

type stream struct {
	c  *Conn
	wm sync.Mutex
}

func (s *stream) ReadMessage() ([]byte, error) {
	s.c.fr.Max = s.c.limit.Load()
	b, err := s.c.fr.ReadFrame()
	if err == nil {
		return b, nil
	}
	if s.c.closed.Load() {
		return nil, transport.ErrClosed
	}
	var tl *wire.TooLargeError
	if errors.As(err, &tl) || errors.Is(err, wire.ErrEmptyFrame) {
		return nil, err
	}
	if err == io.EOF {
		// The peer closed the byte stream: the session ends.
		_ = s.c.finish(&transport.CloseError{Code: status.Unavailable, Reason: "pipe closed by the peer", Remote: true}, false)
		return nil, io.EOF
	}
	_ = s.c.finish(&transport.CloseError{Code: status.Unavailable, Reason: err.Error(), Remote: true}, false)
	return nil, err
}

func (s *stream) WriteMessage(msg []byte) error {
	s.wm.Lock()
	defer s.wm.Unlock()
	if s.c.closed.Load() {
		return transport.ErrClosed
	}
	if err := s.c.fw.WriteFrame(msg); err != nil {
		if s.c.closed.Load() {
			return transport.ErrClosed
		}
		return err
	}
	return nil
}

func (s *stream) CloseWrite() error {
	s.c.wOnce.Do(func() { s.c.wErr = s.c.closeW() })
	return s.c.wErr
}

func (s *stream) Reset(code status.Code) { _ = s.c.Close(code, "shared lane reset") }
