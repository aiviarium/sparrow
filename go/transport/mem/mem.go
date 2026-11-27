// Package mem is an in-memory transport binding with a shared lane and
// leased streams, for tests. It behaves like WebTransport at the message
// level: streams are opened by either side, finish each direction on its
// own, and resets carry a core status code. Messages are delivered in
// order per stream; nothing is lost on Close (queued messages are still
// read before the close is reported).
package mem

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Options tune a pair.
type Options struct {
	// NoLeases makes the pair behave like a WebSocket or pipe: shared lane
	// only.
	NoLeases bool
}

// Pipe returns the client and server ends of an in-memory connection.
func Pipe(o Options) (client, server *Conn) {
	shared := &link{}
	client = &Conn{role: wire.Client, opts: o, done: make(chan struct{}), sharedReady: make(chan struct{})}
	server = &Conn{role: wire.Server, opts: o, done: make(chan struct{}), sharedReady: make(chan struct{})}
	client.peer, server.peer = server, client
	client.shared, server.shared = shared, shared
	for _, c := range []*Conn{client, server} {
		c.limit.Store(wire.DefaultMaxMessageSize)
		c.acceptCond = sync.NewCond(&c.mu)
		c.ctx, c.cancel = context.WithCancel(context.Background())
	}
	return client, server
}

// Conn is one end.
type Conn struct {
	role        wire.Role
	opts        Options
	peer        *Conn
	shared      *link
	sharedOnce  sync.Once
	sharedReady chan struct{}
	sharedEnd   *end
	limit       atomic.Uint64

	mu         sync.Mutex
	acceptCond *sync.Cond
	accept     []*end
	err        error
	done       chan struct{}
	closed     bool
	ctx        context.Context
	cancel     context.CancelFunc

	// Opened counts streams this side opened (for tests).
	Opened atomic.Int64
}

type link struct{}

// queue is one direction of a stream.
type queue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	msgs   [][]byte
	fin    bool
	reset  *transport.ResetError // set by the writer side's reset
	stopRd *transport.ResetError // set when the reader reset (writes fail)
}

func newQueue() *queue { q := &queue{}; q.cond = sync.NewCond(&q.mu); return q }

// end is one side's view of a stream.
type end struct {
	c   *Conn
	in  *queue // peer -> us
	out *queue // us -> peer
}

func newPair(a, b *Conn) (*end, *end) {
	ab, ba := newQueue(), newQueue()
	return &end{c: a, in: ba, out: ab}, &end{c: b, in: ab, out: ba}
}

// Leases reports whether leased streams are available.
func (c *Conn) Leases() bool { return !c.opts.NoLeases }

// SharedLane opens (client) or waits for (server) the shared lane.
func (c *Conn) SharedLane(ctx context.Context) (transport.Stream, error) {
	if c.role == wire.Client {
		c.sharedOnce.Do(func() {
			a, b := newPair(c, c.peer)
			c.sharedEnd = a
			c.peer.sharedEnd = b
			close(c.sharedReady)
			close(c.peer.sharedReady)
		})
		return c.sharedEnd, nil
	}
	select {
	case <-c.sharedReady:
		return c.sharedEnd, nil
	case <-c.done:
		return nil, transport.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// OpenStream opens a leased stream.
func (c *Conn) OpenStream(ctx context.Context) (transport.Stream, error) {
	if c.opts.NoLeases {
		return nil, transport.ErrNoLeases
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, transport.ErrClosed
	}
	a, b := newPair(c, c.peer)
	p := c.peer
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, transport.ErrClosed
	}
	p.accept = append(p.accept, b)
	p.acceptCond.Broadcast()
	p.mu.Unlock()
	c.Opened.Add(1)
	return a, nil
}

// AcceptStream waits for a leased stream the peer opened.
func (c *Conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	if c.opts.NoLeases {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.done:
			return nil, transport.ErrClosed
		}
	}
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		c.acceptCond.Broadcast()
		c.mu.Unlock()
	})
	defer stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.accept) == 0 {
		if c.closed {
			return nil, transport.ErrClosed
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c.acceptCond.Wait()
	}
	e := c.accept[0]
	c.accept = c.accept[1:]
	return e, nil
}

// SetReadLimit sets maxMessageSize for reading.
func (c *Conn) SetReadLimit(n uint64) { c.limit.Store(n) }

// Close closes both ends.
func (c *Conn) Close(code status.Code, reason string) error {
	c.finish(&transport.CloseError{Code: code, Reason: reason})
	c.peer.finish(&transport.CloseError{Code: code, Reason: reason, Remote: true})
	return nil
}

func (c *Conn) finish(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = err
	c.acceptCond.Broadcast()
	c.mu.Unlock()
	close(c.done)
	c.cancel()
}

// Done is closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns the close error.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (e *end) ReadMessage() ([]byte, error) {
	q := e.in
	stop := context.AfterFunc(contextOf(e.c), func() {
		q.mu.Lock()
		q.cond.Broadcast()
		q.mu.Unlock()
	})
	defer stop()
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if len(q.msgs) > 0 {
			m := q.msgs[0]
			q.msgs = q.msgs[1:]
			if lim := e.c.limit.Load(); uint64(len(m)) > lim {
				return nil, &wire.TooLargeError{Size: uint64(len(m)), Max: lim}
			}
			return m, nil
		}
		if q.reset != nil {
			return nil, q.reset
		}
		if q.fin {
			return nil, io.EOF
		}
		if e.c.isClosed() {
			if err := e.c.Err(); err != nil {
				return nil, err
			}
			return nil, transport.ErrClosed
		}
		q.cond.Wait()
	}
}

func (e *end) WriteMessage(msg []byte) error {
	if e.c.isClosed() {
		return transport.ErrClosed
	}
	q := e.out
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stopRd != nil {
		return q.stopRd
	}
	if q.reset != nil {
		return q.reset
	}
	if q.fin {
		return errors.New("mem: write after CloseWrite")
	}
	q.msgs = append(q.msgs, append([]byte(nil), msg...))
	q.cond.Broadcast()
	return nil
}

func (e *end) CloseWrite() error {
	q := e.out
	q.mu.Lock()
	defer q.mu.Unlock()
	q.fin = true
	q.cond.Broadcast()
	return nil
}

// ResetWrite aborts only the sending direction: the peer reads a remote
// reset, and this side keeps reading.
func (e *end) ResetWrite(code status.Code) {
	q := e.out
	q.mu.Lock()
	if !q.fin || len(q.msgs) > 0 {
		q.msgs = nil
	}
	if q.reset == nil {
		q.reset = &transport.ResetError{Code: code, Remote: true}
	}
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (e *end) Reset(code status.Code) {
	// Our sending direction: the peer reads a remote reset.
	q := e.out
	q.mu.Lock()
	if !q.fin || len(q.msgs) > 0 {
		q.msgs = nil
	}
	if q.reset == nil {
		q.reset = &transport.ResetError{Code: code, Remote: true}
	}
	q.cond.Broadcast()
	q.mu.Unlock()
	// Our receiving direction: local reads fail, the peer's writes fail.
	q = e.in
	q.mu.Lock()
	q.msgs = nil
	if q.stopRd == nil {
		q.stopRd = &transport.ResetError{Code: code, Remote: true}
	}
	if q.reset == nil {
		q.reset = &transport.ResetError{Code: code}
	}
	q.cond.Broadcast()
	q.mu.Unlock()
}

// contextOf returns a context cancelled when the connection closes.
func contextOf(c *Conn) context.Context { return c.ctx }
