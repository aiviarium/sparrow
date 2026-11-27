package netsimtest

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/internal/netsim"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport/pipe"
	"github.com/aiviarium/sparrow/go/wire"
)

// The pipe binding (4.7) through the same faults: the node "work" and the
// client reach the hub over byte streams (TCP here, as a unix socket
// would be), and node "work" also runs as a child process on its standard
// input and output.

// TestChoppyPipe: every write of both pipe links is cut into pieces of 1-7
// bytes, some delayed, so length prefixes and messages arrive split
// everywhere; every kind of call completes.
func TestChoppyPipe(t *testing.T) {
	t.Parallel()
	seed := netsim.Seed(t)
	e := newEnv(t, nil)
	f := netsim.TCPFaults{MaxChunk: 7, ChunkDelay: 50 * time.Microsecond, ChunkJitter: 200 * time.Microsecond, DelayRate: 0.01}
	np := netsim.NewTCPProxy(t, e.pipeAddr, seed)
	cp := netsim.NewTCPProxy(t, e.pipeAddr, seed+1)
	np.SetFaults(f)
	cp.SetFaults(f)
	w := e.startPipeWorker(np.Addr())
	cli := e.dialPipeClient(cp.Addr(), aliceToken)
	waitFacet(t, cli)
	exercise(t, cli, w, 80<<10)
	e.waitIdle(cli, w.n)
}

// TestPipeResetMidMessage: the node's byte stream breaks in the middle of
// a large message it sends: the caller's call fails with unavailable, the
// hub counts no call, and the node connects again and serves the next
// call. Then the caller's own stream breaks in the middle of an upload:
// the node's handler is cancelled and nothing stays counted.
func TestPipeResetMidMessage(t *testing.T) {
	t.Parallel()
	seed := netsim.Seed(t)
	e := newEnv(t, nil)
	np := netsim.NewTCPProxy(t, e.pipeAddr, seed)
	w := e.startPipeWorker(np.Addr())
	cp := netsim.NewTCPProxy(t, e.pipeAddr, seed+1)
	cli := e.dialPipeClient(cp.Addr(), aliceToken)
	waitFacet(t, cli)
	ctx := tctx(t)

	np.SetFaults(netsim.TCPFaults{ResetAfter: 100_000 + int64(seed%20_000)})
	cc, err := cli.Open(ctx, "work", "download", uint64(1<<20), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(cc.Reader(0)); session.Code(err) != status.Unavailable {
		t.Fatalf("download across a reset: %v, want unavailable", err)
	}
	np.SetFaults(netsim.TCPFaults{})
	e.waitNode(true)
	testutil.Eventually(t, 5*time.Second, func() bool {
		v, err := cli.Call(ctx, "work", "echo", "again")
		return err == nil && v == "again"
	}, "the node did not come back")
	e.waitIdle(cli, w.n)

	up, err := cli.Open(ctx, "work", "upload", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- up.Writer(ctx, 0).WriteAll(pattern(4 << 20)) }()
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
}

// TestPipeStall: the client's byte stream stalls. A stall shorter than the
// idle timeout is only a delay; a longer one ends the session on both
// sides, the call in flight fails with unavailable and the node's handler
// is cancelled.
func TestPipeStall(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	w := e.startPipeWorker(e.pipeAddr)
	cp := netsim.NewTCPProxy(t, e.pipeAddr, netsim.Seed(t))
	cli := e.dialPipeClient(cp.Addr(), aliceToken, func(o *nd.Options) {
		next := o.Session
		o.Session = func(c *session.Config) {
			next(c)
			c.Params.Set(wire.ParamIdleTimeoutMs, 800)
		}
	})
	waitFacet(t, cli)
	ctx := tctx(t)
	cp.Stall()
	short := make(chan error, 1)
	go func() { _, err := cli.Call(ctx, "work", "echo", "delayed"); short <- err }()
	testutil.Never(t, 150*time.Millisecond, func() bool { return len(short) > 0 }, "a call crossed a stalled link")
	cp.Resume()
	if err := <-short; err != nil {
		t.Fatalf("call across a short stall: %v", err)
	}
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

// TestPipeClosedMidMessage: a peer closes its byte stream in the middle of
// a message, in the handshake and after it: the hub ends the session at
// once and keeps nothing.
func TestPipeClosedMidMessage(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	w := e.startPipeWorker(e.pipeAddr)
	base := e.h.Stats().Sessions
	hello := (&wire.Hello{Versions: []uint64{1}, Auth: bearer(aliceToken)}).AppendTo(nil)
	frame := wire.AppendFrame(nil, hello)
	for cut := 1; cut < len(frame); cut += 3 {
		c, err := net.Dial("tcp", e.pipeAddr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(frame[:cut])
		_ = c.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, c) // the hub closes its side too
		_ = c.Close()
		testutil.Eventually(t, 3*time.Second, func() bool { return e.h.Stats().Sessions == base },
			"cut after %d bytes of Hello: the hub keeps a session", cut)
	}
	// An established client closes its stream in the middle of a
	// Request: the call never reaches the node, both sessions end, and
	// the caller's call fails with unavailable.
	tc, err := net.Dial("tcp", e.pipeAddr)
	if err != nil {
		t.Fatal(err)
	}
	cut := &cutConn{TCPConn: tc.(*net.TCPConn)}
	n := nd.New(nd.Options{Auth: bearer(aliceToken), Logger: logger(t), Session: fastSession})
	ctx := tctx(t)
	if err := n.Connect(ctx, pipe.New(cut, pipeOpts), false); err != nil {
		t.Fatal(err)
	}
	waitFacet(t, n)
	cut.armed.Store(true)
	if _, err := n.Call(ctx, "work", "echo", strings.Repeat("x", 1000)); session.Code(err) != status.Unavailable {
		t.Fatalf("call cut mid-Request: %v, want unavailable", err)
	}
	testutil.Eventually(t, 3*time.Second, func() bool { return e.h.Stats().Sessions == base }, "the hub keeps the cut session")
	if len(w.started) != 0 {
		t.Fatal("a cut Request reached the node")
	}
	e.waitIdle(w.n)
}

// cutConn writes only the first half of a write once armed, and then
// finishes its direction: the stream ends in the middle of a message.
type cutConn struct {
	*net.TCPConn
	armed atomic.Bool
}

func (c *cutConn) Write(p []byte) (int, error) {
	if !c.armed.Load() || len(p) < 2 {
		return c.TCPConn.Write(p)
	}
	_, _ = c.TCPConn.Write(p[:len(p)/2])
	_ = c.TCPConn.CloseWrite()
	return len(p), nil
}

// spawnWorker starts the test binary as node "work", a child process on
// whose standard input and output the hub runs the node's link. The hub
// never starts processes itself (10.2): the test is the supervisor here.
func (e *env) spawnWorker() (*pipe.Conn, *exec.Cmd, chan string) {
	e.t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	lines := make(chan string, 64)
	cmd.Stderr = lineWriter(lines)
	conn, err := pipe.Spawn(cmd, pipeOpts)
	if err != nil {
		e.t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		e.h.ServeConn(context.Background(), conn)
	}()
	e.t.Cleanup(func() {
		_ = conn.Close(status.GoingAway, "test over")
		_ = conn.Wait()
		<-served
	})
	e.waitNode(true)
	return conn, cmd, lines
}

// lineWriter sends each line written to it to ch (dropping lines when ch
// is full).
type lineWriter chan string

func (w lineWriter) Write(p []byte) (int, error) {
	for _, l := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		select {
		case w <- l:
		default:
		}
	}
	return len(p), nil
}

func waitLine(t *testing.T, lines chan string, want string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case l := <-lines:
			if l == want {
				return
			}
		case <-deadline:
			t.Fatalf("the child never printed %q", want)
		}
	}
}

// TestPipeChildDies: node "work" runs as a child process on its standard
// input and output. Every kind of call works; when the process dies in the
// middle of a call, and again in the middle of a download, the caller's
// call fails with unavailable at once, nothing stays counted, the node is
// offline, and the process is reaped with its exit status.
func TestPipeChildDies(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	conn, cmd, lines := e.spawnWorker()
	cli := e.dial(wsURL(e.tcpAddr), aliceToken)
	waitFacet(t, cli)
	ctx := tctx(t)
	for _, s := range []string{"a", strings.Repeat("b", 100_000)} {
		if v, err := cli.Call(ctx, "work", "echo", s); err != nil || v != s {
			t.Fatalf("echo through the child: %v", err)
		}
	}
	running := make(chan error, 1)
	go func() { _, err := cli.Call(ctx, "work", "block", nil); running <- err }()
	waitLine(t, lines, "started")
	_ = cmd.Process.Kill()
	select {
	case err := <-running:
		if session.Code(err) != status.Unavailable {
			t.Fatalf("call to a dead child: %v, want unavailable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call outlived the child")
	}
	if err := conn.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("the child's exit: %v, want killed", err)
	}
	e.waitNode(false)
	e.waitIdle(cli)

	// A new child dies in the middle of a download it sends.
	conn2, cmd2, _ := e.spawnWorker()
	cc, err := cli.Open(ctx, "work", "download", uint64(8<<20), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := cc.Reader(0)
	buf := make([]byte, 64<<10)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("download from the child: %v", err)
	}
	_ = cmd2.Process.Kill()
	if _, err := io.ReadAll(r); session.Code(err) != status.Unavailable {
		t.Fatalf("download from a dead child: %v, want unavailable", err)
	}
	_ = conn2.Wait()
	e.waitNode(false)
	e.waitIdle(cli)
}
