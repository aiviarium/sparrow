package session

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// TestCreditBackPressure: a fast sender and a slow reader; the receiver
// never buffers more than its credit plus one message (7.4).
func TestCreditBackPressure(t *testing.T) {
	t.Parallel()
	forBindings(t, func(t *testing.T, b binding) {
		h := newTestHandlers()
		cli, _ := stdPair(t, b, h, nil)
		ctx := tctx(t)
		for _, tc := range []struct {
			name   string
			opts   *CallOptions
			credit uint64
		}{
			{"default", &CallOptions{}, 0},
			{"credit-metadata", &CallOptions{Credit: 20000}, 20000},
			{"shared", &CallOptions{Lane: LaneShared}, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				const n, size = 300, 30000 // ~9 MB
				cc, err := cli.Call(ctx, tFacet, mBig, []any{uint64(n), uint64(size)}, tc.opts)
				if err != nil {
					t.Fatal(err)
				}
				window := tc.credit
				if window == 0 {
					l := cli.LocalLimits()
					window = l.LeaseCredit
					if cc.Shared() {
						window = l.SharedCredit
					}
				}
				for i := 0; i < n; i++ {
					v, err := cc.Recv(ctx)
					if err != nil {
						t.Fatalf("item %d: %v", i, err)
					}
					if len(v.([]byte)) != size {
						t.Fatal("bad item")
					}
					if i%50 == 0 {
						time.Sleep(5 * time.Millisecond) // a slow reader
					}
				}
				if _, err := cc.Recv(ctx); err != io.EOF {
					t.Fatalf("want EOF: %v", err)
				}
				if mb := cc.MaxBuffered(); mb > window+size+64 {
					t.Fatalf("buffered %d bytes, credit %d + one message", mb, window)
				} else {
					t.Logf("max buffered %d (window %d)", mb, window)
				}
			})
		}
	})
}

// TestCreditViolation: a raw peer that ignores credit gets
// Error(protocol_error) for that call; the session stays open.
func TestCreditViolation(t *testing.T) {
	t.Parallel()
	m := NewMux()
	m.HandleFunc(tFacet, mSum, func(ctx context.Context, c *ServerCall) (any, error) {
		<-ctx.Done() // never reads its input
		return nil, context.Cause(ctx)
	})
	scfg := Config{Schema: testSchema("s"), Handler: m}
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	p.send(&wire.Request{CallID: 2, FacetID: tFacet, MethodID: mSum, Input: cbor.Null})
	// Each Item counts 4 bytes; 20000 of them exceed the 64 KiB window.
	big := cbor.AppendUint(nil, 1)
	for i := 0; i < 20000; i++ {
		p.send(&wire.Item{CallID: 2, Value: big})
	}
	for {
		m := p.recv()
		if e, ok := m.(*wire.Error); ok {
			if status.Code(e.Status) != status.ProtocolError {
				t.Fatalf("got %v", e)
			}
			break
		}
	}
	p.send(&wire.End{CallID: 2})
	testutil.Eventually(t, 5*time.Second, func() bool { return srv.Stats().OpenCalls == 0 }, "call still open")
	if srv.Stats().Closed {
		t.Fatal("session closed")
	}
}

// TestConcurrencyLimit: a client waits for a slot when the server's
// maxConcurrentCalls is reached.
func TestConcurrencyLimit(t *testing.T) {
	t.Parallel()
	h := newTestHandlers()
	cli, srv := stdPair(t, memBinding(), h, func(c, s *Config) {
		s.Params.Set(wire.ParamMaxConcurrentCalls, 2)
	})
	ctx := tctx(t)
	var calls []*ClientCall
	for i := 0; i < 2; i++ {
		cc, err := cli.Call(ctx, tFacet, mBlock, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		calls = append(calls, cc)
		<-h.started
	}
	third := make(chan *ClientCall, 1)
	go func() {
		cc, err := cli.Call(ctx, tFacet, mBlock, nil, nil)
		if err != nil {
			t.Error(err)
		}
		third <- cc
	}()
	select {
	case <-third:
		t.Fatal("the third call started beyond maxConcurrentCalls")
	case <-time.After(100 * time.Millisecond):
	}
	if st := srv.Stats(); st.IncomingCalls != 2 {
		t.Fatalf("server has %d calls", st.IncomingCalls)
	}
	close(h.block)
	cc := <-third
	for _, c := range append(calls, cc) {
		if _, err := c.Response(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// TestConcurrencyLimitEnforced: a raw peer that goes beyond the limit gets
// Error(resource_exhausted).
func TestConcurrencyLimitEnforced(t *testing.T) {
	t.Parallel()
	h := newTestHandlers()
	scfg := Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxConcurrentCalls, 2)
	p, _, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	for id := uint64(2); id <= 6; id += 2 {
		p.send(reqMsg(id, tFacet, mBlock, nil))
	}
	m := p.recv()
	e, ok := m.(*wire.Error)
	if !ok || e.CallID != 6 || status.Code(e.Status) != status.ResourceExhausted {
		t.Fatalf("got %#v", m)
	}
	close(h.block)
	for i := 0; i < 2; i++ {
		if r, ok := p.recv().(*wire.Response); !ok || (r.CallID != 2 && r.CallID != 4) {
			t.Fatalf("got %#v", r)
		}
	}
}

// TestLeaseReuse: sequential calls reuse one leased stream.
func TestLeaseReuse(t *testing.T) {
	t.Parallel()
	cc, sc := mem.Pipe(mem.Options{})
	h := newTestHandlers()
	cli, srv := pairOn(t, cc, sc, Config{}, Config{Schema: testSchema("s"), Handler: h.mux(tFacet)})
	ctx := tctx(t)
	for i := 0; i < 30; i++ {
		if _, err := cli.Unary(ctx, tFacet, mEcho, "x", nil); err != nil {
			t.Fatal(err)
		}
		cs, err := cli.Call(ctx, tFacet, mCount, uint64(3), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := cc.Opened.Load(); n != 1 {
		t.Fatalf("opened %d streams for sequential calls", n)
	}
	if st := srv.Stats(); st.PeerLeased != 1 {
		t.Fatalf("server counts %d streams", st.PeerLeased)
	}
}

// TestLeaseShrink: idle streams are closed after LeaseIdle, keeping
// KeepIdle; both sides stop counting them.
func TestLeaseShrink(t *testing.T) {
	t.Parallel()
	for _, keep := range []int{-1, 2} {
		clk := testutil.NewFakeClock()
		cc, sc := mem.Pipe(mem.Options{})
		h := newTestHandlers()
		// The idle timeout is out of the way: the client's clock jumps
		// 32 s, which no Ping answered in real time could keep up with.
		ccfg := Config{Clock: clk, KeepIdle: keep}
		ccfg.Params.Set(wire.ParamIdleTimeoutMs, 3600000)
		scfg := Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}
		scfg.Params.Set(wire.ParamIdleTimeoutMs, 3600000)
		cli, srv := pairOn(t, cc, sc, ccfg, scfg)
		ctx := tctx(t)
		var calls []*ClientCall
		for i := 0; i < 4; i++ {
			c, err := cli.Call(ctx, tFacet, mBlock, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			<-h.started
			calls = append(calls, c)
		}
		close(h.block)
		for _, c := range calls {
			if _, err := c.Response(ctx); err != nil {
				t.Fatal(err)
			}
		}
		testutil.Eventually(t, 5*time.Second, func() bool { st := cli.Stats(); return st.PoolIdle == 4 && st.PoolOpen == 4 }, "%+v", cli.Stats())
		clk.Advance(16 * time.Second)
		clk.Advance(16 * time.Second)
		want := 0
		if keep > 0 {
			want = keep
		}
		testutil.Eventually(t, 5*time.Second, func() bool {
			return cli.Stats().PoolOpen == want && srv.Stats().PeerLeased == want
		}, "keep %d: client %+v server %+v", keep, cli.Stats(), srv.Stats())
		// The pool still works afterwards.
		if _, err := cli.Unary(ctx, tFacet, mEcho, "again", nil); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPoolExhausted: with every allowed stream leased, calls fall back to
// the shared lane (4.2 rule 6), or wait with WaitForLease.
func TestPoolExhausted(t *testing.T) {
	t.Parallel()
	for _, wait := range []bool{false, true} {
		h := newTestHandlers()
		cli, srv := stdPair(t, memBinding(), h, func(c, s *Config) {
			s.Params.Set(wire.ParamMaxStreams, 1)
			c.WaitForLease = wait
		})
		ctx := tctx(t)
		first, err := cli.Call(ctx, tFacet, mBlock, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		<-h.started
		if first.Shared() {
			t.Fatal("first call should be leased")
		}
		if !wait {
			second, err := cli.Call(ctx, tFacet, mBlock, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			<-h.started
			if !second.Shared() {
				t.Fatal("second call should fall back to the shared lane")
			}
			// Byte data may fall back too.
			up, err := cli.Call(ctx, tFacet, mUpload, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !up.Shared() {
				t.Fatal("upload should fall back")
			}
			_ = up.Writer(ctx, 0).WriteAll(make([]byte, 200000))
			_ = up.CloseSend(nil)
			if v, err := up.Response(ctx); err != nil || v != uint64(200000) {
				t.Fatalf("%v %v", v, err)
			}
			close(h.block)
			_, _ = second.Response(ctx)
		} else {
			got := make(chan *ClientCall, 1)
			go func() {
				c, err := cli.Call(ctx, tFacet, mEcho, "w", nil)
				if err != nil {
					t.Error(err)
				}
				got <- c
			}()
			select {
			case <-got:
				t.Fatal("call did not wait for a lease")
			case <-time.After(50 * time.Millisecond):
			}
			close(h.block)
			c := <-got
			if c.Shared() {
				t.Fatal("should have waited for the leased stream")
			}
			_, _ = c.Response(ctx)
		}
		_, _ = first.Response(ctx)
		if st := srv.Stats(); st.PeerLeased > 1 {
			t.Fatalf("peer opened %d streams, limit 1", st.PeerLeased)
		}
	}
}

// TestMaxStreamsEnforced: a peer that opens more leased streams than
// allowed gets the extra ones reset with resource_exhausted.
func TestMaxStreamsEnforced(t *testing.T) {
	t.Parallel()
	scfg := Config{Schema: testSchema("s"), Handler: newTestHandlers().mux(tFacet)}
	scfg.Params.Set(wire.ParamMaxStreams, 1)
	p, _, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	s1, _ := p.conn.OpenStream(context.Background())
	s2, _ := p.conn.OpenStream(context.Background())
	p.sendOn(s1, reqMsg(2, tFacet, mEcho, cbor.AppendText(nil, "a")))
	p.sendOn(s2, reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "b")))
	b, err := s1.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := wire.Decode(b); m.(*wire.Response).CallID != 2 {
		t.Fatal("bad response")
	}
	_, err = s2.ReadMessage()
	if re, ok := err.(interface{ Error() string }); !ok || Code(asResetErr(err)) != status.ResourceExhausted {
		t.Fatalf("second stream: %v", re)
	}
}

// TestGoAwayDrain: GoAway lets running calls finish, refuses new ones and
// then closes the session (5.6).
func TestGoAwayDrain(t *testing.T) {
	t.Parallel()
	forBindings(t, func(t *testing.T, b binding) {
		h := newTestHandlers()
		cli, srv := stdPair(t, b, h, nil)
		ctx := tctx(t)
		running, err := cli.Call(ctx, tFacet, mBlock, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		<-h.started
		retry := uint64(1500)
		srv.GoAway(status.GoingAway, "deploy", &retry)
		testutil.Eventually(t, 5*time.Second, func() bool { return cli.GoAwayReceived() != nil }, "no GoAway")
		if g := cli.GoAwayReceived(); *g.RetryAfterMs != 1500 || g.Reason != "deploy" {
			t.Fatalf("GoAway %+v", g)
		}
		_, err = cli.Unary(ctx, tFacet, mEcho, "x", nil)
		mustCode(t, err, status.GoingAway)
		select {
		case <-cli.Done():
			t.Fatal("closed with a call running")
		default:
		}
		close(h.block)
		if _, err := running.Response(ctx); err != nil {
			t.Fatalf("running call: %v", err)
		}
		select {
		case <-cli.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("not closed after the drain")
		}
		<-srv.Done()
		mustCode(t, cli.Err(), status.GoingAway)
	})
}

// TestGoAwayCrossingRequest: a Request that crosses GoAway is answered
// with Error(going_away).
func TestGoAwayCrossingRequest(t *testing.T) {
	t.Parallel()
	h := newTestHandlers()
	scfg := Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	p.send(reqMsg(2, tFacet, mBlock, nil))
	<-h.started
	srv.GoAway(status.GoingAway, "bye", nil)
	if g := p.expectGoAway(); status.Code(g.Status) != status.GoingAway {
		t.Fatalf("got %v", g)
	}
	p.send(reqMsg(4, tFacet, mEcho, cbor.AppendText(nil, "late")))
	if e, ok := p.recv().(*wire.Error); !ok || e.CallID != 4 || status.Code(e.Status) != status.GoingAway {
		t.Fatalf("got %#v", e)
	}
	close(h.block)
	if r, ok := p.recv().(*wire.Response); !ok || r.CallID != 2 {
		t.Fatalf("got %#v", r)
	}
	<-srv.Done()
}

// TestIdleTimeout: a peer that sends nothing is pinged at half the idle
// timeout and dropped at the full timeout; two live peers stay connected.
func TestIdleTimeout(t *testing.T) {
	t.Parallel()
	clk := testutil.NewFakeClock()
	scfg := Config{Schema: testSchema("s"), Clock: clk}
	p, sch, _ := rawClient(t, scfg, mem.Options{})
	p.handshake(nil)
	srv := <-sch
	// The idle check re-arms itself each time it runs, in its own
	// goroutine: the clock moves in steps, each once the next check is
	// armed, so no check is skipped.
	advance := func(d time.Duration) {
		for step := 500 * time.Millisecond; d > 0; d -= step {
			testutil.Eventually(t, 5*time.Second, func() bool { return clk.Pending() > 0 || srv.Stats().Closed }, "the idle check is not armed")
			clk.Advance(step)
		}
	}
	advance(16 * time.Second)
	for pinged := false; !pinged; {
		select {
		case m := <-p.in:
			_, pinged = m.(*wire.Ping)
		case <-time.After(10 * time.Second):
			t.Fatal("no Ping at half the idle timeout")
		}
	}
	advance(8 * time.Second)
	if srv.Stats().Closed {
		t.Fatal("closed too early")
	}
	advance(8 * time.Second)
	testutil.Eventually(t, 5*time.Second, func() bool { return srv.Stats().Closed }, "not closed")
	mustCode(t, srv.Err(), status.Unavailable)

	// Two real sessions on one fake clock answer each other's pings.
	clk2 := testutil.NewFakeClock()
	cli, srv2 := stdPair(t, memBinding(), newTestHandlers(), func(c, s *Config) {
		c.Clock, s.Clock = clk2, clk2
	})
	pinging := func(s *Session) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.pingSent
	}
	for i := 0; i < 40; i++ {
		clk2.Advance(2500 * time.Millisecond)
		// Each Ping sent is answered before the clock moves on.
		testutil.Eventually(t, 5*time.Second, func() bool { return !pinging(cli) && !pinging(srv2) }, "a Ping is not answered")
	}
	if cli.Stats().Closed || srv2.Stats().Closed {
		t.Fatalf("live sessions closed: %v %v", cli.Err(), srv2.Err())
	}
}

// TestNotificationsBestEffort: notifications beyond what the callee can
// handle are dropped, not queued without bound, and never answered.
func TestNotificationsBestEffort(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	got := 0
	release := make(chan struct{})
	m := NewMux()
	m.HandleFunc(tFacet, mEcho, func(ctx context.Context, c *ServerCall) (any, error) { return c.Input() })
	m.HandleFunc(tFacet, mNotify, func(ctx context.Context, c *ServerCall) (any, error) {
		<-release
		mu.Lock()
		got++
		mu.Unlock()
		return nil, nil
	})
	cli, _ := pair(t, memBinding(), Config{}, Config{Schema: testSchema("s"), Handler: m})
	ctx := tctx(t)
	for i := 0; i < 500; i++ {
		if err := cli.Notify(ctx, tFacet, mNotify, "n"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cli.Unary(ctx, tFacet, mEcho, "sync", &CallOptions{Lane: LaneShared}); err != nil {
		t.Fatal(err)
	}
	close(release)
	handled := func() int {
		mu.Lock()
		defer mu.Unlock()
		return got
	}
	testutil.Eventually(t, 5*time.Second, func() bool { return handled() >= MaxNotificationHandlers }, "handled %d notifications, want %d", handled(), MaxNotificationHandlers)
	testutil.Never(t, 20*time.Millisecond, func() bool { return handled() > MaxNotificationHandlers }, "handled %d notifications, want %d", handled(), MaxNotificationHandlers)
}
