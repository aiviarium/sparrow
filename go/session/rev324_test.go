package session

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Behaviour decided in core rev324.

// TestAcceptorResetSendingOnly: a stream refused for maxStreams is reset in
// the acceptor's sending direction only (4.2 rule 5: RESET_STREAM, never
// STOP_SENDING), so the opener can still write until it has seen the reset
// and ended its own direction; the refused stream is never counted.
func TestAcceptorResetSendingOnly(t *testing.T) {
	scfg := Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxStreams, 1)
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	s1, _ := p.conn.OpenStream(context.Background())
	s2, _ := p.conn.OpenStream(context.Background())
	p.sendOn(s1, reqMsg(2, tFacet, mHang, nil))
	p.sendOn(s2, reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "b")))
	if _, err := s2.ReadMessage(); Code(asResetErr(err)) != status.ResourceExhausted {
		t.Fatalf("second stream: %v", err)
	}
	if err := s2.WriteMessage((&wire.Cancel{CallID: 4}).AppendTo(nil)); err != nil {
		t.Fatalf("the acceptor stopped the opener's direction (STOP_SENDING): %v", err)
	}
	_ = s2.CloseWrite()
	if n := srv.Stats().PeerLeased; n != 1 {
		t.Fatalf("acceptor counts %d streams, want 1", n)
	}
}

// TestAcceptorResetUncountsAtOnce: an acceptor that resets a stream (here
// for an oversized message) stops counting it as soon as it has sent its
// end, before the opener has ended its own direction (4.2 rule 5), and it
// does not stop the opener's direction.
func TestAcceptorResetUncountsAtOnce(t *testing.T) {
	scfg := Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxMessageSize, 16384)
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	s1, _ := p.conn.OpenStream(context.Background())
	p.sendOn(s1, reqMsg(2, tFacet, mHang, nil))
	testutil.Eventually(t, 5*time.Second, func() bool { return srv.Stats().PeerLeased == 1 }, "stream not counted")
	if err := s1.WriteMessage(make([]byte, 20000)); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.ReadMessage(); Code(asResetErr(err)) != status.MessageTooLarge {
		t.Fatalf("want a reset with message_too_large, got %v", err)
	}
	if n := srv.Stats().PeerLeased; n != 0 {
		t.Fatalf("acceptor still counts %d streams after its reset", n)
	}
	if err := s1.WriteMessage((&wire.Cancel{CallID: 2}).AppendTo(nil)); err != nil {
		t.Fatalf("the acceptor stopped the opener's direction (STOP_SENDING): %v", err)
	}
	_ = s1.CloseWrite()
}

// welcomeGate holds the server's first shared-lane write (Welcome) back,
// after it has gone out, until the session has taken a leased stream from
// the connection: the client has Welcome and opens a stream while the
// server's write has not returned yet.
type welcomeGate struct {
	transport.Conn
	once    sync.Once
	accepts atomic.Int32
	release chan struct{}
}

func (g *welcomeGate) SharedLane(ctx context.Context) (transport.Stream, error) {
	st, err := g.Conn.SharedLane(ctx)
	if err != nil {
		return nil, err
	}
	return &welcomeGateStream{Stream: st, g: g}, nil
}

func (g *welcomeGate) AcceptStream(ctx context.Context) (transport.Stream, error) {
	if g.accepts.Add(1) == 2 {
		// The session has handled the first leased stream.
		close(g.release)
	}
	return g.Conn.AcceptStream(ctx)
}

type welcomeGateStream struct {
	transport.Stream
	g     *welcomeGate
	first atomic.Bool
}

func (s *welcomeGateStream) WriteMessage(b []byte) error {
	err := s.Stream.WriteMessage(b)
	if s.first.CompareAndSwap(false, true) {
		select {
		case <-s.g.release:
		case <-time.After(5 * time.Second):
		}
	}
	return err
}

// TestLeasedStreamBeforeWelcomeWriteReturns: a client that has Welcome may
// open a leased stream at once (5.3), even before the server's write of
// Welcome has returned; the server must not take that stream for one
// opened before Welcome and fail the session with protocol_error.
func TestLeasedStreamBeforeWelcomeWriteReturns(t *testing.T) {
	cc, sc := mem.Pipe(mem.Options{})
	g := &welcomeGate{Conn: sc, release: make(chan struct{})}
	h := newTestHandlers()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		s   *Session
		err error
	}
	sch := make(chan result, 1)
	go func() {
		s, err := NewServer(ctx, g, Config{Schema: testSchema("server"), Handler: h.mux(tFacet)})
		sch <- result{s, err}
	}()
	cli, err := NewClient(ctx, cc, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close(status.OK, "test done")
	out, err := cli.Unary(ctx, tFacet, mEcho, "hello", &CallOptions{Lane: LaneLeased})
	if err != nil || out != "hello" {
		t.Fatalf("leased call on a fresh session: %v %v", out, err)
	}
	r := <-sch
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	r.s.Close(status.OK, "test done")
}
