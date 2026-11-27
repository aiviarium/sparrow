// Package websocket is the Sparrow WebSocket binding (section 4.6), the
// fallback when WebTransport is unavailable. The client connects with
// subprotocol sparrow.v1; each binary WebSocket message carries exactly one
// Sparrow message with no length prefix and no stream header. There is a
// shared lane and nothing else. The close frame carries 1000 for ok and
// 4000 + the core status code otherwise, with a reason of at most 123 bytes.
package websocket

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	ws "github.com/coder/websocket"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Subprotocol is the WebSocket subprotocol of this protocol version.
const Subprotocol = "sparrow.v1"

// AcceptOptions configure the server side.
type AcceptOptions struct {
	// CheckOrigin decides whether the upgrade request's Origin is allowed.
	// Servers MUST check Origin (4.6). If nil, the request is allowed only
	// when it has no Origin header or the Origin's host equals the request
	// host, or matches one of OriginPatterns.
	CheckOrigin func(r *http.Request) bool
	// OriginPatterns are extra host patterns (path.Match syntax) allowed by
	// the default origin check.
	OriginPatterns []string
}

// Accept upgrades an HTTP request to a Sparrow WebSocket connection (the
// server end). On failure it has written an HTTP error to w.
func Accept(w http.ResponseWriter, r *http.Request, o *AcceptOptions) (*Conn, error) {
	if o == nil {
		o = &AcceptOptions{}
	}
	opts := &ws.AcceptOptions{Subprotocols: []string{Subprotocol}, OriginPatterns: o.OriginPatterns}
	if o.CheckOrigin != nil {
		if !o.CheckOrigin(r) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return nil, errors.New("websocket: origin not allowed")
		}
		opts.InsecureSkipVerify = true // checked above
	}
	if !offersSubprotocol(r) {
		http.Error(w, "subprotocol "+Subprotocol+" required", http.StatusBadRequest)
		return nil, errors.New("websocket: client did not offer " + Subprotocol)
	}
	c, err := ws.Accept(w, r, opts)
	if err != nil {
		return nil, err
	}
	return newConn(c), nil
}

func offersSubprotocol(r *http.Request) bool {
	for _, h := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(h, ",") {
			if strings.TrimSpace(p) == Subprotocol {
				return true
			}
		}
	}
	return false
}

// DialOptions configure the client side.
type DialOptions struct {
	HTTPClient *http.Client
	Header     http.Header
}

// Dial connects to a Sparrow WebSocket endpoint (ws:// or wss://).
func Dial(ctx context.Context, u string, o *DialOptions) (*Conn, error) {
	if o == nil {
		o = &DialOptions{}
	}
	if _, err := url.Parse(u); err != nil {
		return nil, err
	}
	c, _, err := ws.Dial(ctx, u, &ws.DialOptions{
		HTTPClient:   o.HTTPClient,
		HTTPHeader:   o.Header,
		Subprotocols: []string{Subprotocol},
	})
	if err != nil {
		return nil, err
	}
	if c.Subprotocol() != Subprotocol {
		c.Close(ws.StatusProtocolError, "subprotocol "+Subprotocol+" required")
		return nil, fmt.Errorf("websocket: server chose subprotocol %q, want %q", c.Subprotocol(), Subprotocol)
	}
	return newConn(c), nil
}

// Conn is a Sparrow WebSocket connection.
type Conn struct {
	c      *ws.Conn
	ctx    context.Context
	cancel context.CancelFunc
	limit  atomic.Uint64
	lane   *stream

	mu        sync.Mutex
	err       error
	done      chan struct{}
	closeOnce sync.Once
}

func newConn(c *ws.Conn) *Conn {
	c.SetReadLimit(-1) // enforced by ReadMessage, as maxMessageSize
	ctx, cancel := context.WithCancel(context.Background())
	k := &Conn{c: c, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	k.limit.Store(wire.DefaultMaxMessageSize)
	k.lane = &stream{k: k}
	return k
}

// Underlying returns the WebSocket connection.
func (k *Conn) Underlying() *ws.Conn { return k.c }

// Leases is false: WebSocket has only the shared lane.
func (k *Conn) Leases() bool { return false }

// SharedLane returns the connection's single stream.
func (k *Conn) SharedLane(context.Context) (transport.Stream, error) {
	select {
	case <-k.done:
		return nil, transport.ErrClosed
	default:
	}
	return k.lane, nil
}

// OpenStream returns transport.ErrNoLeases.
func (k *Conn) OpenStream(context.Context) (transport.Stream, error) {
	return nil, transport.ErrNoLeases
}

// AcceptStream blocks until the connection closes.
func (k *Conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-k.done:
		return nil, transport.ErrClosed
	}
}

// SetReadLimit sets maxMessageSize, applied to the WebSocket message size.
func (k *Conn) SetReadLimit(n uint64) { k.limit.Store(n) }

// Close performs the close handshake with 1000 (ok) or 4000+code and a
// reason shortened to 123 bytes.
func (k *Conn) Close(code status.Code, reason string) error {
	wsCode, err := status.WebSocketCloseCode(code)
	if err != nil {
		wsCode, _ = status.WebSocketCloseCode(status.Internal)
	}
	reason = status.TruncateReason(reason, status.MaxWebSocketReason)
	var cerr error
	k.closeOnce.Do(func() {
		k.setErr(&transport.CloseError{Code: code, Reason: reason})
		k.cancel()
		cerr = k.c.Close(ws.StatusCode(wsCode), reason)
		close(k.done)
	})
	return cerr
}

func (k *Conn) remoteClosed(err error) {
	ce := &transport.CloseError{Code: status.Unavailable, Reason: err.Error(), Remote: true}
	var wce ws.CloseError
	if errors.As(err, &wce) {
		ce.Reason = wce.Reason
		if c, ok := status.FromWebSocketCloseCode(int(wce.Code)); ok {
			ce.Code = c
		}
	}
	k.closeOnce.Do(func() {
		k.setErr(ce)
		k.cancel()
		_ = k.c.CloseNow()
		close(k.done)
	})
}

func (k *Conn) setErr(e error) {
	k.mu.Lock()
	if k.err == nil {
		k.err = e
	}
	k.mu.Unlock()
}

// Done is closed when the connection ends.
func (k *Conn) Done() <-chan struct{} { return k.done }

// Err returns how the connection ended.
func (k *Conn) Err() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.err
}

type stream struct{ k *Conn }

func (s *stream) ReadMessage() ([]byte, error) {
	typ, r, err := s.k.c.Reader(s.k.ctx)
	if err != nil {
		select {
		case <-s.k.done:
			if e := s.k.Err(); e != nil {
				return nil, e
			}
			return nil, transport.ErrClosed
		default:
		}
		s.k.remoteClosed(err)
		return nil, s.k.Err()
	}
	max := s.k.limit.Load()
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, int64(max)+1))
	if err != nil {
		s.k.remoteClosed(err)
		return nil, s.k.Err()
	}
	if uint64(n) > max {
		return nil, &wire.TooLargeError{Size: uint64(n), Max: max}
	}
	if typ != ws.MessageBinary {
		return nil, &transport.ProtocolError{Msg: "text WebSocket message"}
	}
	if n == 0 {
		return nil, wire.ErrEmptyFrame
	}
	return buf.Bytes(), nil
}

func (s *stream) WriteMessage(msg []byte) error {
	if err := s.k.c.Write(s.k.ctx, ws.MessageBinary, msg); err != nil {
		select {
		case <-s.k.done:
			return transport.ErrClosed
		default:
		}
		// A failed write leaves the WebSocket unusable: the connection is
		// gone (closed by the peer, locally or by the network), even if the
		// reader has not seen the close yet.
		return fmt.Errorf("%w: %v", transport.ErrClosed, err)
	}
	return nil
}

// CloseWrite is not available on a WebSocket; finishing the shared lane
// ends the session, so the session closes the connection instead.
func (s *stream) CloseWrite() error { return nil }

func (s *stream) Reset(code status.Code) { _ = s.k.Close(code, "shared lane reset") }
