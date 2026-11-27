package session

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func quiet(t *testing.T, sessions ...*Session) {
	t.Helper()
	testutil.Eventually(t, 5*time.Second, func() bool {
		for _, s := range sessions {
			if s.Stats().OpenCalls != 0 {
				return false
			}
		}
		return true
	}, "calls still open: %+v", sessions[0].Stats())
}

func TestCancelShapes(t *testing.T) {
	forBindings(t, func(t *testing.T, b binding) {
		h := newTestHandlers()
		cli, srv := stdPair(t, b, h, nil)
		ctx := tctx(t)
		check := func(t *testing.T) {
			t.Helper()
			quiet(t, cli, srv)
			if b.leases {
				st := cli.Stats()
				if st.PoolIdle != st.PoolOpen {
					t.Fatalf("leased streams not back in the pool: %+v", st)
				}
			}
		}

		t.Run("unary", func(t *testing.T) {
			cctx, cancel := context.WithCancel(ctx)
			cc, err := cli.Call(cctx, tFacet, mSlow, uint64(60000), nil)
			if err != nil {
				t.Fatal(err)
			}
			<-h.started
			cancel()
			_, err = cc.Response(ctx)
			mustCode(t, err, status.Cancelled)
			check(t)
		})
		t.Run("server-stream", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mWatch, uint64(3), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !cc.Shared() {
				t.Fatal("a method flagged shared runs on the shared lane")
			}
			for i := 0; i < 3; i++ {
				if _, err := cc.Recv(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := cc.Cancel(status.Cancelled); err != nil {
				t.Fatal(err)
			}
			_, err = cc.Recv(ctx)
			mustCode(t, err, status.Cancelled)
			check(t)
		})
		t.Run("client-stream", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mSum, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 10; i++ {
				_ = cc.Send(ctx, uint64(i))
			}
			_ = cc.Cancel(status.Cancelled)
			if err := cc.Send(ctx, uint64(1)); err == nil {
				t.Fatal("send after Cancel succeeded")
			}
			check(t)
		})
		t.Run("bidi", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mChat, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = cc.Send(ctx, "a")
			if _, err := cc.Recv(ctx); err != nil {
				t.Fatal(err)
			}
			_ = cc.Cancel(status.Cancelled)
			check(t)
		})
		t.Run("upload", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mUpload, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = cc.Writer(ctx, 0).Write(make([]byte, 50000))
			_ = cc.Cancel(status.Cancelled)
			check(t)
		})
		t.Run("download", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mDownload, uint64(64<<20), nil)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1000)
			if _, err := io.ReadFull(cc.Reader(0), buf); err != nil {
				t.Fatal(err)
			}
			_ = cc.Cancel(status.Cancelled)
			_, err = io.ReadAll(cc.Reader(0))
			mustCode(t, err, status.Cancelled)
			check(t)
		})
		t.Run("deadline", func(t *testing.T) {
			dctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			_, err := cli.Unary(dctx, tFacet, mSlow, uint64(60000), nil)
			mustCode(t, err, status.DeadlineExceeded)
			<-h.started
			check(t)
		})
	})
}

// TestCalleeDeadline: the callee answers Error(deadline_exceeded) when the
// deadline in the metadata passes (fake clock).
func TestCalleeDeadline(t *testing.T) {
	clk := testutil.NewFakeClock()
	h := newTestHandlers()
	cli, _ := stdPair(t, memBinding(), h, func(c, s *Config) {
		s.Clock = clk
	})
	ctx := tctx(t)
	md := wire.Metadata{}
	md.SetDeadline(1000)
	cc, err := cli.Call(ctx, tFacet, mSlow, uint64(600000), &CallOptions{Metadata: md})
	if err != nil {
		t.Fatal(err)
	}
	<-h.started
	clk.Advance(999 * time.Millisecond)
	select {
	case <-time.After(50 * time.Millisecond):
	default:
	}
	if cc.Done() {
		t.Fatal("call ended before the deadline")
	}
	clk.Advance(2 * time.Millisecond)
	_, err = cc.Response(ctx)
	mustCode(t, err, status.DeadlineExceeded)
}

// TestCancelGiveUpLeased: a callee that never answers Cancel; after 5 s the
// caller resets the leased stream, which fails the call and leaves the pool.
func TestCancelGiveUpLeased(t *testing.T) {
	clk := testutil.NewFakeClock()
	h := newTestHandlers()
	cli, srv := stdPair(t, memBinding(), h, func(c, s *Config) {
		c.Clock = clk
		c.Params.Set(wire.ParamIdleTimeoutMs, 3600000)
		s.Params.Set(wire.ParamIdleTimeoutMs, 3600000)
	})
	ctx := tctx(t)
	cc, err := cli.Call(ctx, tFacet, mHang, nil, &CallOptions{Lane: LaneLeased})
	if err != nil {
		t.Fatal(err)
	}
	if cc.Shared() {
		t.Fatal("want a leased stream")
	}
	<-h.hangSeen
	_ = cc.Cancel(status.Cancelled)
	clk.Advance(4 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if cc.Done() {
		t.Fatal("gave up too early")
	}
	clk.Advance(2 * time.Second)
	testutil.Eventually(t, 5*time.Second, cc.Done, "call not failed after give-up")
	_, err = cc.RecvRaw(ctx)
	mustCode(t, err, status.Cancelled)
	if st := cli.Stats(); st.OutgoingCalls != 0 || st.PoolIdle != 0 {
		t.Fatalf("stats after give-up: %+v", st)
	}
	// The server saw the reset and dropped the call and the stream.
	testutil.Eventually(t, 5*time.Second, func() bool { st := srv.Stats(); return st.OpenCalls == 0 && st.PeerLeased == 0 }, "server: %+v", srv.Stats())
	// The reset stream stays counted for ResetHold, then is released.
	clk.Advance(2 * time.Second)
	testutil.Eventually(t, 5*time.Second, func() bool { return cli.Stats().PoolOpen == 0 }, "pool: %+v", cli.Stats())
}

// TestCancelGiveUpShared: on the shared lane the call keeps counting and
// after 30 s the session closes with GoAway(protocol_error).
func TestCancelGiveUpShared(t *testing.T) {
	clk := testutil.NewFakeClock()
	h := newTestHandlers()
	cli, srv := stdPair(t, memBinding(), h, func(c, s *Config) {
		c.Clock = clk
		c.Params.Set(wire.ParamIdleTimeoutMs, 3600000)
		s.Params.Set(wire.ParamIdleTimeoutMs, 3600000)
	})
	ctx := tctx(t)
	cc, err := cli.Call(ctx, tFacet, mHang, nil, &CallOptions{Lane: LaneShared})
	if err != nil {
		t.Fatal(err)
	}
	<-h.hangSeen
	_ = cc.Cancel(status.Cancelled)
	clk.Advance(6 * time.Second)
	testutil.Eventually(t, 5*time.Second, func() bool {
		_, err := cc.RecvRaw(ctx)
		return Code(err) == status.Cancelled
	}, "the application sees the give-up")
	if st := cli.Stats(); st.OutgoingCalls != 1 {
		t.Fatalf("the call must keep counting: %+v", st)
	}
	clk.Advance(25 * time.Second)
	testutil.Eventually(t, 5*time.Second, func() bool { return cli.Stats().Closed }, "session not closed")
	mustCode(t, cli.Err(), status.ProtocolError)
	<-srv.Done()
	if g := srv.GoAwayReceived(); g == nil || status.Code(g.Status) != status.ProtocolError {
		t.Fatalf("server got GoAway %v", g)
	}
}

// TestCancelAnsweredLate: a late final message after give-up on the shared
// lane releases the slot.
func TestCancelAnsweredLate(t *testing.T) {
	clk := testutil.NewFakeClock()
	release := make(chan struct{})
	m := NewMux()
	m.Handle(tFacet, mHang, rawHandler(func(ctx context.Context, c *ServerCall) {
		<-release
		_ = c.Fail(&Error{Code: status.Cancelled})
	}))
	cli, _ := pair(t, memBinding(), Config{Clock: clk}, Config{Schema: testSchema("s"), Handler: m})
	ctx := tctx(t)
	cc, err := cli.Call(ctx, tFacet, mHang, nil, &CallOptions{Lane: LaneShared})
	if err != nil {
		t.Fatal(err)
	}
	_ = cc.Cancel(status.Cancelled)
	clk.Advance(6 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if cli.Stats().OutgoingCalls != 1 {
		t.Fatal("slot released too early")
	}
	close(release)
	testutil.Eventually(t, 5*time.Second, func() bool { return cli.Stats().OutgoingCalls == 0 }, "slot not released")
	if cli.Stats().Closed {
		t.Fatal("session closed")
	}
}
