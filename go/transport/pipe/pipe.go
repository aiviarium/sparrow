// Package pipe is the Sparrow pipe binding (core section 4.7): one ordered
// byte stream between peers on one machine, such as a child process's
// standard input and output, a unix socket or an SSH channel. There is a
// shared lane and nothing else; each message is preceded by its length as
// a QUIC varint, with no stream header, and maxMessageSize is checked on
// that length before the body is read. The side that sends Hello is the
// client; a started process is the client, on its standard input and
// output. Closing the byte stream ends the session; status and reason
// travel only in GoAway. Standard error is not part of the protocol.
//
// The binding is optional and a hub never uses it (it never starts
// processes, 10.2); it is for supervisors and tools that run Sparrow
// peers as child processes.
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

	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport"
	"github.com/aiviarium/sparrow/go/wire"
)

// DefaultLinger is how long Close waits, after finishing this side's
// direction, for the peer to finish its own (5.6).
const DefaultLinger = 2 * time.Second

// DefaultKillAfter is how long a spawned process may take to exit after
// the connection ended (its standard input is closed) before it is killed.
const DefaultKillAfter = 5 * time.Second

// Options configure a pipe connection; nil means the defaults.
type Options struct {
	// Linger overrides DefaultLinger.
	Linger time.Duration
	// KillAfter overrides DefaultKillAfter (Spawn only).
	KillAfter time.Duration
}

func (o *Options) linger() time.Duration {
	if o == nil || o.Linger <= 0 {
		return DefaultLinger
	}
	return o.Linger
}

func (o *Options) killAfter() time.Duration {
	if o == nil || o.KillAfter <= 0 {
		return DefaultKillAfter
	}
	return o.KillAfter
}

// Conn is a pipe connection. It implements transport.Conn.
type Conn struct {
	closeW func() error
	closeA func() error
	linger time.Duration

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

	// Set by Spawn.
	cmd       *exec.Cmd
	killAfter time.Duration
	exited    chan struct{}
	waitErr   error
}

// New returns a pipe connection over rwc. Closing the connection closes
// rwc. If rwc has a CloseWrite method (unix and TCP sockets), finishing
// this side's direction uses it. Closing rwc must unblock a Write in
// progress, as it does for os pipes and net.Conn.
func New(rwc io.ReadWriteCloser, o *Options) *Conn {
	closeW := rwc.Close
	if cw, ok := rwc.(interface{ CloseWrite() error }); ok {
		closeW = cw.CloseWrite
	}
	return newConn(rwc, rwc, closeW, rwc.Close, o)
}

// NewSplit returns a pipe connection reading from r and writing to w, such
// as the two pipes of a child process. Closing the connection closes both.
func NewSplit(r io.ReadCloser, w io.WriteCloser, o *Options) *Conn {
	return newConn(r, w, w.Close, func() error {
		e1 := w.Close()
		e2 := r.Close()
		if e1 != nil {
			return e1
		}
		return e2
	}, o)
}

// Stdio returns a pipe connection on this process's standard input and
// output, for a process whose parent speaks Sparrow to it (the started
// process is the Sparrow client, 4.7). Nothing else may write to standard
// output afterwards.
func Stdio(o *Options) *Conn { return NewSplit(os.Stdin, os.Stdout, o) }

// Spawn starts cmd with a pipe connection on its standard input and output.
// cmd.Stderr is left as configured; it is not part of the protocol. The
// returned connection is the starting side's end (the Sparrow server, 4.7).
//
// The connection reaps the process: once the connection has ended (by
// Close, or because the process closed its output or died) it waits for
// the process to exit, kills it if it has not exited KillAfter later, and
// collects its exit status, which Wait returns. Do not call cmd.Wait
// yourself: it closes the output pipe and could drop messages not yet
// read. If cmd.WaitDelay is zero it is set to KillAfter, so a grandchild
// that keeps standard error open cannot hold the reaping.
func Spawn(cmd *exec.Cmd, o *Options) (*Conn, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = o.killAfter()
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := NewSplit(stdout, stdin, o)
	c.cmd = cmd
	c.killAfter = o.killAfter()
	c.exited = make(chan struct{})
	return c, nil
}

func newConn(r io.Reader, w io.Writer, closeW, closeA func() error, o *Options) *Conn {
	c := &Conn{closeW: closeW, closeA: closeA, linger: o.linger(), done: make(chan struct{})}
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

// Close closes the byte stream. The code and reason are not transmitted.
// It first finishes this side's direction, after any message being
// written, and waits up to Linger for the peer to finish its own (seen by
// the reader), so messages in flight are not lost (5.6); a protocol_error
// closes at once. Close is idempotent; it does not wait for a spawned
// process (see Wait).
func (c *Conn) Close(code status.Code, reason string) error {
	cerr := &transport.CloseError{Code: code, Reason: reason}
	if c.closed.Load() || code == status.ProtocolError {
		return c.finish(cerr, true)
	}
	// CloseWrite waits for a write in progress, which a stalled peer may
	// block: the linger bounds the wait, and finish unblocks the write.
	cw := make(chan struct{})
	go func() {
		_ = c.lane.CloseWrite()
		close(cw)
	}()
	t := time.NewTimer(c.linger)
	select {
	case <-c.done:
	case <-t.C:
	}
	t.Stop()
	err := c.finish(cerr, true)
	<-cw
	return err
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
		if c.cmd != nil {
			go c.reap()
		}
		close(c.done)
	})
	return cerr
}

// reap waits for the spawned process after the connection ended (its
// standard input is closed by then), killing it after killAfter.
func (c *Conn) reap() {
	waited := make(chan error, 1)
	go func() { waited <- c.cmd.Wait() }()
	t := time.NewTimer(c.killAfter)
	var err error
	select {
	case err = <-waited:
	case <-t.C:
		_ = c.cmd.Process.Kill()
		err = <-waited
	}
	t.Stop()
	c.waitErr = err
	close(c.exited)
}

// Wait waits until the connection has ended and, for a connection from
// Spawn, the process has exited and been reaped, and returns the process's
// exit error as exec.Cmd.Wait reports it (nil for other connections).
func (c *Conn) Wait() error {
	<-c.done
	if c.exited == nil {
		return nil
	}
	<-c.exited
	return c.waitErr
}

// Exited is closed once a spawned process has exited and been reaped; for
// other connections it is Done.
func (c *Conn) Exited() <-chan struct{} {
	if c.exited == nil {
		return c.done
	}
	return c.exited
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

// ReadMessage reads the next frame. The length prefix is checked against
// the read limit before any of the body is read, and the buffer grows with
// the bytes that arrive (wire.FrameReader).
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

// CloseWrite finishes this side's direction after the message being
// written, if any.
func (s *stream) CloseWrite() error {
	s.wm.Lock()
	defer s.wm.Unlock()
	s.c.wOnce.Do(func() { s.c.wErr = s.c.closeW() })
	return s.c.wErr
}

// Reset ends the connection: the pipe has only the shared lane, and the
// end of the shared lane ends the session.
func (s *stream) Reset(code status.Code) { _ = s.c.Close(code, "shared lane reset") }
