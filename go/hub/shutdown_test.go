package hub

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
)

// readyGate holds the client's second shared-lane message (Ready) back from
// the hub until the hub is closing.
type readyGate struct {
	transport.Conn
	release func() bool
}

func (g *readyGate) SharedLane(ctx context.Context) (transport.Stream, error) {
	st, err := g.Conn.SharedLane(ctx)
	if err != nil {
		return nil, err
	}
	return &readyGateStream{Stream: st, g: g}, nil
}

type readyGateStream struct {
	transport.Stream
	g *readyGate
	n atomic.Int32
}

func (s *readyGateStream) ReadMessage() ([]byte, error) {
	b, err := s.Stream.ReadMessage()
	if err == nil && s.n.Add(1) == 2 {
		deadline := time.Now().Add(5 * time.Second)
		for !s.g.release() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	return b, err
}

// TestCloseDuringHandshake: a client whose Ready has not been processed
// when the hub starts shutting down still gets GoAway(going_away) and its
// session ends; Close waits for it like for any other session (5.6).
func TestCloseDuringHandshake(t *testing.T) {
	f := newFixture(t, nil)
	cc, sc := mem.Pipe(mem.Options{})
	go f.h.ServeConn(context.Background(), &readyGate{Conn: sc, release: f.h.closing})
	ctx := tctx(t)
	cli, err := session.NewClient(ctx, cc, session.Config{Auth: bearer(aliceToken)})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { f.h.Close(3 * time.Second); close(closed) }()
	select {
	case <-cli.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client session not ended")
	}
	if g := cli.GoAwayReceived(); g == nil || status.Code(g.Status) != status.GoingAway {
		t.Fatalf("client got %v", g)
	}
	<-closed
}

// TestCloseWaitsForTransports: Close returns only once each connection has
// finished closing, so GoAway has reached the client: a program that exits
// right after Close must not leave the client waiting for its idle timeout
// (the WebTransport binding finishes the shared lane and waits for the
// peer's finish after GoAway, 4.5 and 5.6).
func TestCloseWaitsForTransports(t *testing.T) {
	for _, b := range []string{"webtransport", "websocket"} {
		t.Run(b, func(t *testing.T) {
			f := newFixture(t, nil)
			cli := f.client(b, aliceToken)
			s := cli.Session()
			f.h.Close(3 * time.Second)
			if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != status.GoingAway {
				t.Fatalf("Close returned before the client had GoAway: %v", g)
			}
		})
	}
}

// TestEndLoginSessionDuringHandshake: logging out ends a session of that
// login session even while the hub has not yet processed its Ready (the
// client already considers it open).
func TestEndLoginSessionDuringHandshake(t *testing.T) {
	clk := testutil.NewFakeClock()
	f := newFixture(t, func(o *Options) {
		o.Clock = clk
		o.Authenticate = ticketAuth
	})
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{}})
	var ended atomic.Bool
	cc, sc := mem.Pipe(mem.Options{})
	go f.h.ServeConn(context.Background(), &readyGate{Conn: sc, release: ended.Load})
	ctx := tctx(t)
	cli, err := session.NewClient(ctx, cc, session.Config{Auth: testTicket("user:alice", "sid-9", clk.Now().Add(5*time.Minute))})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close(status.OK, "test done")
	if n := f.h.EndLoginSession("sid-9"); n != 1 {
		t.Fatalf("EndLoginSession found %d sessions", n)
	}
	ended.Store(true)
	select {
	case <-cli.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client session not ended")
	}
	if g := cli.GoAwayReceived(); g == nil || status.Code(g.Status) != status.Unauthenticated {
		t.Fatalf("client got %v", g)
	}
}
