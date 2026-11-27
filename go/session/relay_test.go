package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// recConn records every message read and written on a connection.
type recConn struct {
	transport.Conn
	mu      sync.Mutex
	read    [][]byte
	written [][]byte
}

type recStream struct {
	transport.Stream
	c *recConn
}

func (c *recConn) wrap(s transport.Stream, err error) (transport.Stream, error) {
	if err != nil {
		return nil, err
	}
	return &recStream{Stream: s, c: c}, nil
}

func (c *recConn) SharedLane(ctx context.Context) (transport.Stream, error) {
	return c.wrap(c.Conn.SharedLane(ctx))
}
func (c *recConn) OpenStream(ctx context.Context) (transport.Stream, error) {
	return c.wrap(c.Conn.OpenStream(ctx))
}
func (c *recConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return c.wrap(c.Conn.AcceptStream(ctx))
}

func (s *recStream) ReadMessage() ([]byte, error) {
	b, err := s.Stream.ReadMessage()
	if err == nil {
		s.c.mu.Lock()
		s.c.read = append(s.c.read, append([]byte(nil), b...))
		s.c.mu.Unlock()
	}
	return b, err
}

func (s *recStream) WriteMessage(b []byte) error {
	s.c.mu.Lock()
	s.c.written = append(s.c.written, append([]byte(nil), b...))
	s.c.mu.Unlock()
	return s.Stream.WriteMessage(b)
}

// callMessages returns the messages of one call (by call ID) in order,
// without Credit, normalized to call ID 0. Requests are reduced to method
// ID and input.
func callMessages(t testing.TB, msgs [][]byte, id uint64) []string {
	var out []string
	for _, b := range msgs {
		k, cid, err := wire.PeekCall(b)
		if err != nil || !k.IsCall() || cid != id || k == wire.KindCredit {
			continue
		}
		if k == wire.KindRequest {
			m, _ := wire.Decode(b)
			r := m.(*wire.Request)
			out = append(out, fmt.Sprintf("Request m=%d input=%x", r.MethodID, []byte(r.Input)))
			continue
		}
		nb, err := wire.RewriteCallID(b, 0)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%x", nb))
	}
	return out
}

func firstRequest(msgs [][]byte, method uint64) (*wire.Request, bool) {
	for _, b := range msgs {
		if k, _, _ := wire.PeekCall(b); k != wire.KindRequest {
			continue
		}
		m, _ := wire.Decode(b)
		if r := m.(*wire.Request); r.MethodID == method {
			return r, true
		}
	}
	return nil, false
}

// miniHub forwards calls to hub facet 40 to node facet 16, rewriting only
// envelopes.
type miniHub struct {
	down *Session
	mu   sync.Mutex
	ins  []*ServerCall
	outs []*ClientCall
}

const hubFacet = 40

func (h *miniHub) ServeCall(ctx context.Context, in *ServerCall) {
	md := in.Metadata().Clone()
	md.SetPrincipal("user:alice")
	md.SetContext(bytes.Repeat([]byte{7}, 16))
	if in.Notification() {
		md.Delete(wire.SigilKey(wire.KeyContext))
		_ = h.down.NotifyRaw(ForwardRequest(in, tFacet, md))
		return
	}
	out, err := h.down.OpenRaw(context.WithoutCancel(ctx), ForwardRequest(in, tFacet, md), &CallOptions{ManualCredit: true})
	if err != nil {
		_ = in.Fail(err)
		return
	}
	h.mu.Lock()
	h.ins, h.outs = append(h.ins, in), append(h.outs, out)
	h.mu.Unlock()
	_ = Relay(ctx, in, out)
}

type relaySetup struct {
	cli, hubUp, hubDown, node *Session
	cliConn, nodeConn         *recConn
	hub                       *miniHub
	h                         *testHandlers
}

func newRelay(t *testing.T, up, down binding) *relaySetup {
	r := &relaySetup{h: newTestHandlers()}
	// hub -> node
	dc, ds := down.connect(t)
	r.nodeConn = &recConn{Conn: ds}
	nodeMux := r.h.mux(tFacet)
	var nodeSess *Session
	r.hubDown, nodeSess = pairOn(t, dc, r.nodeConn, Config{}, Config{Schema: testSchema("node"), Handler: nodeMux})
	r.node = nodeSess
	r.hub = &miniHub{down: r.hubDown}
	// client -> hub: the hub publishes the node's facet as facet 40.
	f := testFacet(hubFacet, "test")
	uc, us := up.connect(t)
	r.cliConn = &recConn{Conn: uc}
	r.cli, r.hubUp = pairOn(t, r.cliConn, us, Config{}, Config{Schema: testSchema("hub", f), Handler: r.hub})
	return r
}

// check compares the client's messages for its call with the node's for
// the forwarded call, in both directions.
// The last messages may still be on their way when the calls are no
// longer counted (the End a relay sends on the caller's behalf, 10.5), so
// it compares until both sides agree or 5 s pass.
func (r *relaySetup) check(t *testing.T, clientID uint64, method uint64) {
	t.Helper()
	var last string
	if testutil.WaitFor(5*time.Second, func() bool { last = r.compare(t, clientID, method); return last == "" }) {
		return
	}
	t.Fatal(last)
}

// compare returns how the two hops differ, or "".
func (r *relaySetup) compare(t *testing.T, clientID uint64, method uint64) string {
	r.cliConn.mu.Lock()
	cw, cr := append([][]byte(nil), r.cliConn.written...), append([][]byte(nil), r.cliConn.read...)
	r.cliConn.mu.Unlock()
	r.nodeConn.mu.Lock()
	nr, nw := append([][]byte(nil), r.nodeConn.read...), append([][]byte(nil), r.nodeConn.written...)
	r.nodeConn.mu.Unlock()
	// Find the node-side call ID: the last Request for the method.
	var nodeID uint64
	for _, b := range nr {
		if k, id, _ := wire.PeekCall(b); k == wire.KindRequest {
			m, _ := wire.Decode(b)
			if m.(*wire.Request).MethodID == method {
				nodeID = id
			}
		}
	}
	if nodeID == 0 {
		return "the node never saw the call"
	}
	up, down := callMessages(t, cw, clientID), callMessages(t, nr, nodeID)
	if !equalStrings(up, down) {
		return fmt.Sprintf("caller -> callee differs:\nclient wrote %d messages\nnode read   %d messages\n%v\n%v", len(up), len(down), head(up), head(down))
	}
	up, down = callMessages(t, nw, nodeID), callMessages(t, cr, clientID)
	if !equalStrings(up, down) {
		return fmt.Sprintf("callee -> caller differs:\nnode wrote  %d messages\nclient read %d messages\n%v\n%v", len(up), len(down), head(up), head(down))
	}
	// The forwarded Request carries the hub's principal and context.
	for _, b := range nr {
		if k, id, _ := wire.PeekCall(b); k == wire.KindRequest && id == nodeID {
			m, _ := wire.Decode(b)
			rq := m.(*wire.Request)
			if p, ok, _ := rq.Metadata.Principal(); !ok || p != "user:alice" {
				t.Fatal("principal not set by the hub")
			}
			if rq.FacetID != tFacet {
				t.Fatal("facet ID not rewritten")
			}
		}
	}
	return ""
}

func head(xs []string) []string {
	var out []string
	for _, x := range xs {
		if len(x) > 80 {
			x = x[:80] + "..."
		}
		out = append(out, x)
		if len(out) == 6 {
			break
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRelay(t *testing.T) {
	t.Parallel()
	combos := [][2]binding{
		{wsBinding(), wsBinding()},
		{wtBinding(), memBinding()},
		{memBinding(), wtBinding()},
		{memBinding(), wsBinding()},
	}
	for _, cb := range combos {
		t.Run(cb[0].name+"->"+cb[1].name, func(t *testing.T) {
			t.Parallel()
			r := newRelay(t, cb[0], cb[1])
			ctx := tctx(t)
			cli := r.cli

			t.Run("unary", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mEcho, "through the hub", nil)
				if err != nil {
					t.Fatal(err)
				}
				out, err := cc.Response(ctx)
				if err != nil || out != "through the hub" {
					t.Fatalf("%v %v", out, err)
				}
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mEcho)
			})
			t.Run("server-stream-credit", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mBig, []any{uint64(200), uint64(20000)}, &CallOptions{Credit: 50000})
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 200; i++ {
					if _, err := cc.Recv(ctx); err != nil {
						t.Fatal(err)
					}
					if i%40 == 0 {
						time.Sleep(10 * time.Millisecond)
					}
				}
				if err := cc.Wait(ctx); err != nil {
					t.Fatal(err)
				}
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mBig)
				// Per hop, the hub holds at most its granted credit plus one
				// message for the call.
				r.hub.mu.Lock()
				out := r.hub.outs[len(r.hub.outs)-1]
				r.hub.mu.Unlock()
				if mb := out.MaxBuffered(); mb > 50000+20100 {
					t.Fatalf("hub buffered %d bytes downstream", mb)
				}
				if mb := cc.MaxBuffered(); mb > 50000+20100 {
					t.Fatalf("client buffered %d bytes", mb)
				}
			})
			t.Run("client-stream", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mSum, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 500; i++ {
					_ = cc.Send(ctx, uint64(i))
				}
				_ = cc.CloseSend(nil)
				if out, err := cc.Response(ctx); err != nil || out != uint64(124750) {
					t.Fatalf("%v %v", out, err)
				}
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mSum)
			})
			t.Run("bidi", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mChat, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 20; i++ {
					_ = cc.Send(ctx, "m")
					if v, err := cc.Recv(ctx); err != nil || v != "re: m" {
						t.Fatalf("%v %v", v, err)
					}
				}
				_ = cc.CloseSend(nil)
				if _, err := cc.Recv(ctx); err != io.EOF {
					t.Fatal(err)
				}
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mChat)
			})
			t.Run("upload-download", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mUpload, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				_ = cc.Writer(ctx, 0).WriteAll(bytes.Repeat([]byte{1, 2, 3}, 300000))
				_ = cc.CloseSend(nil)
				if out, err := cc.Response(ctx); err != nil || out != uint64(900000) {
					t.Fatalf("%v %v", out, err)
				}
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mUpload)
				dc, err := cli.Call(ctx, hubFacet, mDownload, uint64(1<<20), nil)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(dc.Reader(0))
				if err != nil || len(data) != 1<<20 {
					t.Fatalf("%d %v", len(data), err)
				}
				_ = dc.Wait(ctx)
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, dc.ID(), mDownload)
			})
			t.Run("referenced-tokens", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mAttach, value.Struct{0: "f", 1: value.Token(9)}, nil)
				if err != nil {
					t.Fatal(err)
				}
				_ = cc.Writer(ctx, 9).WriteAll(make([]byte, 40000))
				_ = cc.CloseSend(nil)
				if out, err := cc.Response(ctx); err != nil || out != uint64(40001) {
					t.Fatalf("%v %v", out, err)
				}
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mAttach)
			})
			t.Run("error", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mFail, "relayed", nil)
				if err != nil {
					t.Fatal(err)
				}
				_, err = cc.Response(ctx)
				if e, ok := err.(*Error); !ok || e.Code != errApp || e.Message != "relayed" {
					t.Fatalf("%#v", err)
				}
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mFail)
			})
			t.Run("cancel", func(t *testing.T) {
				cctx, cancel := context.WithCancel(ctx)
				cc, err := cli.Call(cctx, hubFacet, mSlow, uint64(60000), nil)
				if err != nil {
					t.Fatal(err)
				}
				<-r.h.started
				cancel()
				_, err = cc.Response(ctx)
				mustCode(t, err, status.Cancelled)
				quiet(t, cli, r.hubUp, r.hubDown, r.node)
				r.check(t, cc.ID(), mSlow)
				r.h.mu.Lock()
				n := r.h.cancels
				r.h.mu.Unlock()
				if n == 0 {
					t.Fatal("the node never saw the cancellation")
				}
			})
			t.Run("notification", func(t *testing.T) {
				if err := cli.Notify(ctx, hubFacet, mNotify, "via hub"); err != nil {
					t.Fatal(err)
				}
				select {
				case v := <-r.h.notified:
					if v != "via hub" {
						t.Fatal(v)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("notification not relayed")
				}
				r.nodeConn.mu.Lock()
				rq, ok := firstRequest(r.nodeConn.read, mNotify)
				r.nodeConn.mu.Unlock()
				if !ok || rq.CallID != 0 {
					t.Fatal("not relayed as a notification")
				}
				if _, has, _ := rq.Metadata.Context(); has {
					t.Fatal("a forwarded notification carries no context")
				}
			})
			t.Run("node-link-drops", func(t *testing.T) {
				cc, err := cli.Call(ctx, hubFacet, mBlock, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				<-r.h.started
				r.node.Close(status.Unavailable, "node crashed")
				_, err = cc.Response(ctx)
				mustCode(t, err, status.Unavailable)
				testutil.Eventually(t, 5*time.Second, func() bool { return r.hubUp.Stats().OpenCalls == 0 }, "hub call still open")
			})
		})
	}
}

var _ = schema.Format
