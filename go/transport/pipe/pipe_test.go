package pipe

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/internal/fuzzseed"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport"
	"github.com/aiviarium/sparrow/go/wire"
)

var fast = &Options{Linger: 100 * time.Millisecond, KillAfter: 5 * time.Second}

// impatient kills a child 300 ms after the connection ended.
var impatient = &Options{Linger: 100 * time.Millisecond, KillAfter: 300 * time.Millisecond}

// The test binary doubles as the child process of the Spawn tests.
const childEnv = "PIPE_TEST_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
	case "echo": // echoes every message until its input ends, then exits 0
		c := Stdio(nil)
		lane, _ := c.SharedLane(nil)
		for {
			b, err := lane.ReadMessage()
			if err != nil {
				os.Exit(0)
			}
			if err := lane.WriteMessage(b); err != nil {
				os.Exit(1)
			}
		}
	case "exit3": // reads one message and exits 3
		lane, _ := Stdio(nil).SharedLane(nil)
		_, _ = lane.ReadMessage()
		os.Exit(3)
	case "stubborn": // ignores the end of its input
		_, _ = io.Copy(io.Discard, os.Stdin)
		time.Sleep(time.Minute)
		os.Exit(0)
	default:
		os.Exit(2)
	}
	flag.Parse()
	fuzzing := flag.Lookup("test.fuzz").Value.String() != ""
	before := runtime.NumGoroutine()
	code := m.Run()
	if code == 0 && !fuzzing && !testutil.WaitFor(5*time.Second, func() bool { return runtime.NumGoroutine() <= before }) {
		buf := make([]byte, 1<<20)
		fmt.Fprintf(os.Stderr, "leaked goroutines: %d before, %d after\n%s", before, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
		code = 1
	}
	os.Exit(code)
}

func child(t *testing.T, mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+mode)
	cmd.Stderr = os.Stderr
	return cmd
}

func TestFraming(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	c := New(b, fast)
	defer c.Close(status.ProtocolError, "")
	lane, _ := c.SharedLane(nil)
	go func() {
		// A non-shortest length prefix (2-byte form of 3) is accepted.
		_, _ = a.Write([]byte{0x40, 0x03, 0x82, 0x01, 0x02})
		_, _ = a.Write(wire.AppendFrame(nil, bytes.Repeat([]byte{1}, 70000)))
		_ = a.Close()
	}()
	m, err := lane.ReadMessage()
	if err != nil || !bytes.Equal(m, []byte{0x82, 0x01, 0x02}) {
		t.Fatalf("%x %v", m, err)
	}
	c.SetReadLimit(1000)
	var tl *wire.TooLargeError
	if _, err := lane.ReadMessage(); !errors.As(err, &tl) || tl.Size != 70000 {
		t.Fatalf("got %v", err)
	}
}

// TestLimitBeforeBody: a length prefix above the limit is refused as soon
// as the prefix is read, before any of the body exists.
func TestLimitBeforeBody(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	c := New(b, fast)
	defer c.Close(status.ProtocolError, "")
	defer a.Close()
	c.SetReadLimit(16384)
	lane, _ := c.SharedLane(nil)
	go func() { _, _ = a.Write([]byte{0xc0, 0, 0, 0, 0x40, 0, 0, 0}) }() // 2^30, no body follows
	var tl *wire.TooLargeError
	if _, err := lane.ReadMessage(); !errors.As(err, &tl) {
		t.Fatalf("got %v", err)
	}
}

func TestEmptyFrame(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	c := New(b, fast)
	defer c.Close(status.ProtocolError, "")
	defer a.Close()
	lane, _ := c.SharedLane(nil)
	go func() { _, _ = a.Write([]byte{0x00}) }()
	if _, err := lane.ReadMessage(); !errors.Is(err, wire.ErrEmptyFrame) {
		t.Fatalf("got %v", err)
	}
}

// TestChoppedWrites: a frame that arrives one to seven bytes at a time is
// read whole.
func TestChoppedWrites(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	c := New(b, fast)
	defer c.Close(status.ProtocolError, "")
	lane, _ := c.SharedLane(nil)
	msgs := [][]byte{{0xf6}, bytes.Repeat([]byte{7}, 300), bytes.Repeat([]byte{9}, 70000)}
	go func() {
		var all []byte
		for _, m := range msgs {
			all = wire.AppendFrame(all, m)
		}
		for i, k := 0, 1; i < len(all); i, k = i+k, k%7+1 {
			_, _ = a.Write(all[i:min(i+k, len(all))])
		}
		_ = a.Close()
	}()
	for _, want := range msgs {
		if got, err := lane.ReadMessage(); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("got %d bytes, %v", len(got), err)
		}
	}
	if _, err := lane.ReadMessage(); err != io.EOF {
		t.Fatalf("got %v", err)
	}
}

// TestClosedMidMessage: the stream ending inside a frame ends the
// connection with unavailable.
func TestClosedMidMessage(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	c := New(b, fast)
	lane, _ := c.SharedLane(nil)
	go func() {
		_, _ = a.Write(wire.AppendFrame(nil, bytes.Repeat([]byte{1}, 100))[:50])
		_ = a.Close()
	}()
	if _, err := lane.ReadMessage(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
	<-c.Done()
	var ce *transport.CloseError
	if !errors.As(c.Err(), &ce) || ce.Code != status.Unavailable || !ce.Remote {
		t.Fatalf("Err() = %v", c.Err())
	}
	if _, err := c.SharedLane(nil); err != transport.ErrClosed {
		t.Fatalf("SharedLane after the end: %v", err)
	}
}

func TestEOF(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	c := New(b, fast)
	lane, _ := c.SharedLane(nil)
	go func() {
		_, _ = a.Write(wire.AppendFrame(nil, []byte{0xf6}))
		_ = a.Close()
	}()
	if m, err := lane.ReadMessage(); err != nil || m[0] != 0xf6 {
		t.Fatalf("%x %v", m, err)
	}
	if _, err := lane.ReadMessage(); err != io.EOF {
		t.Fatalf("got %v", err)
	}
	<-c.Done()
	if c.Leases() {
		t.Fatal("a pipe has no leased streams")
	}
	if _, err := c.OpenStream(nil); err != transport.ErrNoLeases {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

// TestCloseLingers: Close finishes this side's direction, so the peer
// reads every message and then the end, and returns once the peer has
// finished its own direction (well before Linger).
func TestCloseLingers(t *testing.T) {
	t.Parallel()
	x, y := net.Pipe()
	a, b := New(x, &Options{Linger: 10 * time.Second}), New(y, fast)
	la, _ := a.SharedLane(nil)
	lb, _ := b.SharedLane(nil)
	go func() {
		// b reads a's message and the end of a's direction, then closes.
		for {
			if _, err := lb.ReadMessage(); err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			if _, err := la.ReadMessage(); err != nil {
				return
			}
		}
	}()
	if err := la.WriteMessage([]byte{0xf6}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = a.Close(status.OK, "bye")
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %v", d)
	}
	<-b.Done()
	if err := la.WriteMessage([]byte{0xf6}); err != transport.ErrClosed {
		t.Fatalf("write after Close: %v", err)
	}
}

// TestCloseStalledPeer: a peer that reads nothing blocks a write in
// progress; Close still returns after Linger and unblocks the writer.
func TestCloseStalledPeer(t *testing.T) {
	t.Parallel()
	x, y := net.Pipe() // unbuffered: every write waits for a reader
	defer y.Close()
	c := New(x, fast)
	lane, _ := c.SharedLane(nil)
	wrote := make(chan error, 1)
	go func() { wrote <- lane.WriteMessage(bytes.Repeat([]byte{1}, 1000)) }()
	done := make(chan struct{})
	go func() {
		_ = c.Close(status.OK, "")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung on a stalled peer")
	}
	if err := <-wrote; err == nil {
		t.Fatal("the stalled write succeeded")
	}
}

// TestSpawn: the child is the other end; when its input ends it exits,
// and Wait reaps it and reports its status.
func TestSpawn(t *testing.T) {
	t.Parallel()
	c, err := Spawn(child(t, "echo"), fast)
	if err != nil {
		t.Fatal(err)
	}
	lane, _ := c.SharedLane(nil)
	for _, m := range [][]byte{{0xf6}, bytes.Repeat([]byte{3}, 100_000)} {
		if err := lane.WriteMessage(m); err != nil {
			t.Fatal(err)
		}
		if got, err := lane.ReadMessage(); err != nil || !bytes.Equal(got, m) {
			t.Fatalf("echo: %d bytes, %v", len(got), err)
		}
	}
	go func() {
		for {
			if _, err := lane.ReadMessage(); err != nil {
				return
			}
		}
	}()
	_ = c.Close(status.OK, "")
	if err := c.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	select {
	case <-c.Exited():
	default:
		t.Fatal("Exited not closed after Wait")
	}
}

// TestSpawnChildExits: a child that exits ends the connection (the reader
// sees the end of its output) and Wait reports the exit status.
func TestSpawnChildExits(t *testing.T) {
	t.Parallel()
	c, err := Spawn(child(t, "exit3"), fast)
	if err != nil {
		t.Fatal(err)
	}
	lane, _ := c.SharedLane(nil)
	_ = lane.WriteMessage([]byte{0xf6})
	if _, err := lane.ReadMessage(); err != io.EOF {
		t.Fatalf("read from an exited child: %v", err)
	}
	var ee *exec.ExitError
	if err := c.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("Wait: %v, want exit status 3", err)
	}
	var ce *transport.CloseError
	if !errors.As(c.Err(), &ce) || ce.Code != status.Unavailable {
		t.Fatalf("Err() = %v", c.Err())
	}
}

// TestSpawnKillsStubbornChild: a child that does not exit when its input
// ends is killed KillAfter later and reaped.
func TestSpawnKillsStubbornChild(t *testing.T) {
	t.Parallel()
	c, err := Spawn(child(t, "stubborn"), impatient)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.Close(status.ProtocolError, "")
	err = c.Wait()
	if err == nil || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("Wait: %v, want killed", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("reaping took %v", d)
	}
}

// FuzzConn feeds arbitrary bytes to a pipe connection with a 64 KiB read
// limit: it returns messages within the limit and then io.EOF, a
// truncation, a TooLargeError or ErrEmptyFrame; it never panics, and the
// messages re-framed in shortest form take no more bytes than the input.
func FuzzConn(f *testing.F) {
	for _, s := range fuzzseed.Hex("framing.json", "calls.json") {
		f.Add(wire.AppendFrame(nil, s))
	}
	f.Add([]byte{0x40, 0x03, 0x82, 0x01, 0x02})
	f.Add([]byte{0xc0, 0, 0, 0, 0x40, 0, 0, 0})
	f.Add([]byte{0x00})
	f.Add([]byte{0x7f})
	f.Fuzz(func(t *testing.T, in []byte) {
		c := New(nopCloser{bytes.NewReader(in)}, fast)
		c.SetReadLimit(1 << 16)
		lane, _ := c.SharedLane(nil)
		var reframed []byte
		for i := 0; ; i++ {
			m, err := lane.ReadMessage()
			if err != nil {
				var tl *wire.TooLargeError
				switch {
				case err == io.EOF, errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, wire.ErrEmptyFrame), errors.As(err, &tl):
				default:
					t.Fatalf("unexpected error %v", err)
				}
				break
			}
			if len(m) == 0 || len(m) > 1<<16 {
				t.Fatalf("message of %d bytes", len(m))
			}
			reframed = wire.AppendFrame(reframed, m)
		}
		if len(reframed) > len(in) {
			t.Fatalf("re-framed %d bytes from %d", len(reframed), len(in))
		}
		_ = c.Close(status.ProtocolError, "")
	})
}

type nopCloser struct{ io.Reader }

func (nopCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopCloser) Close() error                { return nil }
