package netsimtest

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/hub"
	"github.com/aiviarium/sparrow/go/internal/netsim"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/wire"
)

var lossy = netsim.Faults{Drop: 0.03, Duplicate: 0.02, Reorder: 0.03, Latency: time.Millisecond, Jitter: time.Millisecond}

// TestLossyWebTransport: with 3% loss, duplicates, reordering and a few ms
// of jitter on both the client's and the node's link, every kind of call
// through the hub completes with the right result (QUIC recovers), credit
// back-pressure holds, and cancel and deadlines reach the node.
func TestLossyWebTransport(t *testing.T) {
	t.Parallel()
	seed := netsim.Seed(t)
	e := newEnv(t, nil)
	np := netsim.NewUDPProxy(t, e.udpAddr, seed)
	cp := netsim.NewUDPProxy(t, e.udpAddr, seed+1)
	np.SetFaults(lossy)
	cp.SetFaults(lossy)
	w := e.startWorker(wtURL(np.Addr()))
	cli := e.dial(wtURL(cp.Addr()), aliceToken)
	waitFacet(t, cli)
	exercise(t, cli, w, 128<<10)
	// a schema update relayed over both lossy links (10.3)
	b := nd.NewFacet("work.extra", "1.0.0")
	b.Service("Extra").Method("ping", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) { return "pong", nil })
	if _, err := w.n.Add(tctx(t), b.MustBuild()); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool { return cli.Session().PeerFacet("work.extra") != nil }, "update not relayed")
	if v, err := cli.Call(tctx(t), "work.extra", "ping", nil); err != nil || v != "pong" {
		t.Fatalf("new facet: %v %v", v, err)
	}
	e.waitIdle(cli, w.n)
	for _, p := range []*netsim.UDPProxy{np, cp} {
		if st := p.Stats(); st.Dropped == 0 || st.Duplicated == 0 || st.Reordered == 0 {
			t.Fatalf("faults not applied: %+v", st)
		}
	}
	t.Logf("node link %+v, client link %+v", np.Stats(), cp.Stats())
}

// TestDeadLinkWebTransport: the node's link goes dead (every packet lost)
// in the middle of a call. The hub notices through the QUIC idle timeout:
// the running call ends with unavailable, the node is offline but its
// facet stays listed, a new call waits for it and a notification to it is
// dropped (10.7). When the link comes back the node dials in again by
// itself, the waiting call is served, and the hub counts no call left.
func TestDeadLinkWebTransport(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	np := netsim.NewUDPProxy(t, e.udpAddr, netsim.Seed(t))
	w := e.startWorker(wtURL(np.Addr()))
	cli := e.dial(wsURL(e.tcpAddr), aliceToken)
	waitFacet(t, cli)
	ctx := tctx(t)
	if v, err := cli.Call(ctx, "work", "echo", "before"); err != nil || v != "before" {
		t.Fatalf("%v %v", v, err)
	}
	running := make(chan error, 1)
	go func() { _, err := cli.Call(ctx, "work", "block", nil); running <- err }()
	<-w.started
	np.SetBlackHole(true)
	select {
	case err := <-running:
		if session.Code(err) != status.Unavailable {
			t.Fatalf("call on the dead link: %v, want unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call on the dead link never ended")
	}
	e.waitNode(false)
	if cli.Session().PeerFacet("work") == nil {
		t.Fatal("an offline node's facet must stay listed (10.7)")
	}
	dropped := e.h.Stats().NotificationsDropped
	if err := cli.Notify(ctx, "work", "note", "lost"); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool { return e.h.Stats().NotificationsDropped == dropped+1 }, "notification to an offline node not dropped")
	waited := make(chan error, 1)
	go func() {
		v, err := cli.Call(ctx, "work", "echo", "waited")
		if err == nil && v != "waited" {
			err = io.ErrUnexpectedEOF
		}
		waited <- err
	}()
	testutil.Never(t, 100*time.Millisecond, func() bool { return len(waited) > 0 }, "the call did not wait for the offline node")
	np.SetBlackHole(false)
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("waiting call: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("the waiting call was not served after the node came back")
	}
	e.waitNode(true)
	select {
	case err := <-w.ended: // the blocked handler ended with its session
		if session.Code(err) != status.Unavailable {
			t.Fatalf("the node's handler ended with %v, want Unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the node's handler outlived its session")
	}
	select {
	case n := <-w.notes:
		t.Fatalf("a notification sent while offline arrived: %q", n)
	default:
	}
	e.waitIdle(cli, w.n)
}

// TestOneWayDeadLink: only the packets from the hub to the node are lost
// (the node still reaches the hub). The node notices through its QUIC idle
// timeout, then the hub (no more keep-alives); a call made meanwhile waits,
// and once the link heals the node dials in again and serves it.
func TestOneWayDeadLink(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	np := netsim.NewUDPProxy(t, e.udpAddr, netsim.Seed(t))
	w := e.startWorker(wtURL(np.Addr()))
	cli := e.dial(wsURL(e.tcpAddr), aliceToken)
	waitFacet(t, cli)
	ctx := tctx(t)
	first := w.n.Session()
	np.SetFaultsDir(netsim.FromTarget, netsim.Faults{BlackHole: true})
	select {
	case <-first.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the node never noticed the dead link")
	}
	e.waitNode(false)
	waited := make(chan error, 1)
	go func() { _, err := cli.Call(ctx, "work", "echo", "w"); waited <- err }()
	testutil.Never(t, 50*time.Millisecond, func() bool { return len(waited) > 0 }, "the call did not wait for the offline node")
	np.SetFaultsDir(netsim.FromTarget, netsim.Faults{})
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("waiting call: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("the waiting call was not served after the link healed")
	}
	e.waitIdle(cli, w.n)
}

// TestDeadLinkDialedNode: the link to a node the hub dials (WebTransport,
// SPKI pin) goes dead. The hub notices through the QUIC idle timeout, the
// running call ends with unavailable, a new call makes the hub redial
// while it waits, and once the link is back the hub reaches the node again
// and serves the waiting call.
func TestDeadLinkDialedNode(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *hub.Options) { o.DialQUICConfig = fastQUIC() })
	w, addr, pin := e.listenWorker()
	np := netsim.NewUDPProxy(t, addr, netsim.Seed(t))
	e.commit(&admin.NodeConfig{Link: admin.Dialed(admin.Dial{URL: "https://" + np.Addr() + "/node", Pin: pin, Credential: "work-link"})})
	e.waitNode(true)
	cli := e.dial(wsURL(e.tcpAddr), aliceToken)
	waitFacet(t, cli)
	ctx := tctx(t)
	running := make(chan error, 1)
	go func() { _, err := cli.Call(ctx, "work", "block", nil); running <- err }()
	<-w.started
	np.SetBlackHole(true)
	select {
	case err := <-running:
		if session.Code(err) != status.Unavailable {
			t.Fatalf("call on the dead link: %v, want unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call on the dead link never ended")
	}
	e.waitNode(false)
	waited := make(chan error, 1)
	go func() {
		v, err := cli.Call(ctx, "work", "echo", "waited")
		if err == nil && v != "waited" {
			err = io.ErrUnexpectedEOF
		}
		waited <- err
	}()
	testutil.Never(t, 100*time.Millisecond, func() bool { return len(waited) > 0 }, "the call did not wait for the offline node")
	np.SetBlackHole(false)
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("waiting call: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("the waiting call was not served after the link came back")
	}
	select {
	case err := <-w.ended:
		if session.Code(err) != status.Unavailable {
			t.Fatalf("the node's handler ended with %v, want unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the node's handler outlived its session")
	}
	e.waitIdle(cli, w.n)
}

// TestNATRebinding: the node's NAT mapping changes in the middle of a
// download (its packets arrive from a new port). The call completes on the
// same session (QUIC migrates), or the node reconnects and the call fails
// as unavailable; either way the next calls work and nothing hangs.
func TestNATRebinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	np := netsim.NewUDPProxy(t, e.udpAddr, netsim.Seed(t))
	w := e.startWorker(wtURL(np.Addr()))
	cli := e.dial(wtURL(e.udpAddr), aliceToken)
	waitFacet(t, cli)
	ctx := tctx(t)
	before := w.n.Session()
	cc, err := cli.Open(ctx, "work", "download", uint64(2<<20), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := cc.Reader(0)
	buf := make([]byte, 64<<10)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	np.Rebind()
	rest, err := io.ReadAll(r)
	switch {
	case err == nil:
		if len(rest)+len(buf) != 2<<20 {
			t.Fatalf("download: %d bytes", len(rest)+len(buf))
		}
		t.Logf("the call survived the rebinding (same session: %v)", w.n.Session() == before)
	case session.Code(err) == status.Unavailable:
		t.Logf("the node's session ended with the rebinding: %v", err)
	default:
		t.Fatalf("download across the rebinding: %v", err)
	}
	e.waitNode(true)
	testutil.Eventually(t, 5*time.Second, func() bool {
		v, err := cli.Call(ctx, "work", "echo", "after")
		return err == nil && v == "after"
	}, "no call works after the rebinding")
	e.waitIdle(cli, w.n)
}

// TestChoppyWebSocket: every TCP write of both links is cut into pieces of
// 1-7 bytes, some delayed, so frames and messages arrive split everywhere;
// every kind of call completes.
func TestChoppyWebSocket(t *testing.T) {
	t.Parallel()
	seed := netsim.Seed(t)
	e := newEnv(t, nil)
	f := netsim.TCPFaults{MaxChunk: 7, ChunkDelay: 50 * time.Microsecond, ChunkJitter: 200 * time.Microsecond, DelayRate: 0.01}
	np := netsim.NewTCPProxy(t, e.tcpAddr, seed)
	cp := netsim.NewTCPProxy(t, e.tcpAddr, seed+1)
	np.SetFaults(f)
	cp.SetFaults(f)
	w := e.startWorker(wsURL(np.Addr()))
	cli := e.dial(wsURL(cp.Addr()), aliceToken)
	waitFacet(t, cli)
	exercise(t, cli, w, 80<<10)
	e.waitIdle(cli, w.n)
}

// TestWebSocketResetMidMessage: the node's TCP connection is reset in the
// middle of a large message it sends (a download through the hub). The
// caller's call fails with unavailable at once, the hub counts no call
// left, the node dials in again and serves the next call. Then the
// caller's own connection is reset in the middle of an upload: the node's
// handler is cancelled, and the hub again counts nothing.
func TestWebSocketResetMidMessage(t *testing.T) {
	t.Parallel()
	seed := netsim.Seed(t)
	e := newEnv(t, nil)
	np := netsim.NewTCPProxy(t, e.tcpAddr, seed)
	w := e.startWorker(wsURL(np.Addr()))
	cp := netsim.NewTCPProxy(t, e.tcpAddr, seed+1)
	cli := e.dial(wsURL(cp.Addr()), aliceToken)
	waitFacet(t, cli)
	ctx := tctx(t)

	np.SetFaults(netsim.TCPFaults{ResetAfter: 100_000 + int64(seed%20_000)})
	cc, err := cli.Open(ctx, "work", "download", uint64(1<<20), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(cc.Reader(0))
	if session.Code(err) != status.Unavailable {
		t.Fatalf("download across a reset: %v, want unavailable", err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool { return np.Resets() >= 1 }, "no reset")
	np.SetFaults(netsim.TCPFaults{})
	e.waitNode(true)
	testutil.Eventually(t, 5*time.Second, func() bool {
		v, err := cli.Call(ctx, "work", "echo", "again")
		return err == nil && v == "again"
	}, "the node did not come back")
	e.waitIdle(cli, w.n)

	// the caller's link resets in the middle of an upload
	up, err := cli.Open(ctx, "work", "upload", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() {
		wr := up.Writer(ctx, 0)
		ended <- wr.WriteAll(pattern(4 << 20))
	}()
	testutil.Eventually(t, 5*time.Second, func() bool { return e.h.Stats().ActiveCalls == 1 }, "upload not running")
	cp.SetFaults(netsim.TCPFaults{ResetAfter: 1})
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("the upload finished across a reset")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the upload never noticed the reset")
	}
	if _, err := up.Response(ctx); session.Code(err) != status.Unavailable {
		t.Fatalf("upload response: %v, want unavailable", err)
	}
	e.waitIdle(w.n)
	cp.SetFaults(netsim.TCPFaults{})

	// a new client's link resets in the middle of a download it receives
	cli2 := e.dial(wsURL(cp.Addr()), aliceToken)
	waitFacet(t, cli2)
	cp.SetFaults(netsim.TCPFaults{ResetAfter: 200_000})
	dl, err := cli2.Open(ctx, "work", "download", uint64(4<<20), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(dl.Reader(0)); session.Code(err) != status.Unavailable {
		t.Fatalf("download across a reset: %v, want unavailable", err)
	}
	e.waitIdle(w.n)
	cp.SetFaults(netsim.TCPFaults{})
	cli3 := e.dial(wsURL(cp.Addr()), aliceToken)
	waitFacet(t, cli3)
	if v, err := cli3.Call(ctx, "work", "echo", "fine"); err != nil || v != "fine" {
		t.Fatalf("after the resets: %v %v", v, err)
	}
	e.waitIdle(cli3, w.n)
}

// TestWebSocketStall: the client's TCP link stalls for longer than the
// session's idle timeout (idleTimeoutMs, the smaller of both peers'): both
// ends close the session, a call in flight fails with unavailable, and the
// hub forgets the call. A stall shorter than the timeout is only a delay.
func TestWebSocketStall(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	w := e.startWorker(wsURL(e.tcpAddr))
	cp := netsim.NewTCPProxy(t, e.tcpAddr, netsim.Seed(t))
	cli := e.dial(wsURL(cp.Addr()), aliceToken, func(o *nd.Options) {
		next := o.Session
		o.Session = func(c *session.Config) {
			next(c)
			c.Params.Set(wire.ParamIdleTimeoutMs, 800)
		}
	})
	waitFacet(t, cli)
	ctx := tctx(t)
	// short stall: a delay
	cp.Stall()
	short := make(chan error, 1)
	go func() { _, err := cli.Call(ctx, "work", "echo", "delayed"); short <- err }()
	testutil.Never(t, 150*time.Millisecond, func() bool { return len(short) > 0 }, "a call crossed a stalled link")
	cp.Resume()
	if err := <-short; err != nil {
		t.Fatalf("call across a short stall: %v", err)
	}
	// long stall: the session dies of idleness
	running := make(chan error, 1)
	go func() { _, err := cli.Call(ctx, "work", "block", nil); running <- err }()
	<-w.started
	cp.Stall()
	select {
	case err := <-running:
		if session.Code(err) != status.Unavailable {
			t.Fatalf("call on a stalled link: %v, want unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled session never timed out")
	}
	select {
	case err := <-w.ended:
		if session.Code(err) != status.Unavailable {
			t.Fatalf("the node's handler ended with %v, want Unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the node's handler was not cancelled")
	}
	cp.Resume()
	e.waitIdle(cli, w.n)
}

// TestWebSocketResetDuringHandshake resets a client's connection after
// every few bytes of the HTTP upgrade, Hello, Welcome and Ready in turn:
// each dial fails or yields a session, nothing hangs, and the hub forgets
// every session it started.
func TestWebSocketResetDuringHandshake(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	w := e.startWorker(wsURL(e.tcpAddr))
	cp := netsim.NewTCPProxy(t, e.tcpAddr, netsim.Seed(t))
	base := e.h.Stats().Sessions
	for k := int64(1); k < 1400; k += 23 {
		cp.SetFaults(netsim.TCPFaults{ResetAfter: k})
		n := nd.New(nd.Options{Auth: bearer(aliceToken), Logger: logger(t), Session: fastSession})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := n.Dial(ctx, wsURL(cp.Addr()), e.dialOptions()); err == nil {
			_, _ = n.Call(ctx, "work", "echo", "x")
			n.Close()
		} else if ctx.Err() != nil {
			t.Fatalf("reset after %d bytes: the dial hung: %v", k, err)
		}
		cancel()
		testutil.Eventually(t, 3*time.Second, func() bool { return e.h.Stats().Sessions == base },
			"reset after %d bytes: the hub keeps a session", k)
	}
	e.waitIdle(w.n)
}
