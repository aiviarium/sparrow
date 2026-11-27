package netsimtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/hub"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport/pipe"
	"github.com/aiviarium/sparrow/go/transport/webtransport"
	"github.com/aiviarium/sparrow/go/wire"
)

const (
	adminToken = "admin-token"
	aliceToken = "alice-token"
	workCred   = "work-cred"
)

// fastQUIC detects a dead link within 0.7 s (quic-go defaults to 30 s): both
// ends must set it, as the idle timeout is the smaller of the two.
func fastQUIC() *quic.Config {
	return &quic.Config{MaxIdleTimeout: 700 * time.Millisecond, KeepAlivePeriod: 150 * time.Millisecond,
		HandshakeIdleTimeout: 500 * time.Millisecond}
}

func logger(t *testing.T) *slog.Logger {
	if os.Getenv("NETSIM_LOG") == "" {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// fastSession shortens the waits a closing session makes for messages in
// flight; on a lossy link they still arrive well within them.
func fastSession(c *session.Config) {
	c.Linger, c.GoAwayWait = 150*time.Millisecond, 150*time.Millisecond
}

// env is an in-process hub on real WebTransport (UDP) and WebSocket (TCP)
// listeners, with a dial-in node "work" configured.
type env struct {
	t        *testing.T
	h        *hub.Hub
	udpAddr  string // the hub's WebTransport listener
	tcpAddr  string // the hub's WebSocket listener
	pipeAddr string // a TCP listener whose connections the hub runs as pipe links (4.7)
	certHash []byte
}

// pipeOpts are the pipe binding's options in these tests.
var pipeOpts = &pipe.Options{Linger: 150 * time.Millisecond, KillAfter: 2 * time.Second}

func newEnv(t *testing.T, tune func(*hub.Options)) *env {
	t.Helper()
	store, err := admin.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o := hub.Options{
		Store:            store,
		Bootstrap:        []hub.Credential{{Token: adminToken, Principal: "user:admin"}},
		Tokens:           []hub.Credential{{Token: aliceToken, Principal: "user:alice"}},
		Logger:           logger(t),
		ConnectTimeout:   5 * time.Second,
		RedialBackoff:    5 * time.Millisecond,
		RedialBackoffMax: 50 * time.Millisecond,
		WaitingRedial:    5 * time.Millisecond,
		DialTimeout:      500 * time.Millisecond,
		TransportLinger:  300 * time.Millisecond,
		ContextGrace:     50 * time.Millisecond,
		Session:          fastSession,
	}
	if tune != nil {
		tune(&o)
	}
	h, err := hub.New(o)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, h: h}
	cert, hash, err := webtransport.SelfSigned("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	e.certHash = hash
	srv := webtransport.NewServer(webtransport.ServerOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		CheckOrigin: func(*http.Request) bool { return true }, QUICConfig: fastQUIC(), Linger: 150 * time.Millisecond})
	mux := http.NewServeMux()
	mux.Handle("/sparrow/wt", h.WebTransportHandler(srv))
	srv.WT.H3.Handler = mux
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	e.udpAddr = pc.LocalAddr().String()
	ws := httptest.NewServer(h.WebSocketHandler(func(*http.Request) bool { return true }))
	e.tcpAddr = ws.Listener.Addr().String()
	// The pipe binding over TCP: each accepted connection is one byte
	// stream the hub serves (as it would a unix socket). The hub never
	// starts processes; a test that does hands the hub the process's pipe.
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.pipeAddr = pl.Addr().String()
	var pipes sync.WaitGroup
	pipes.Add(1)
	go func() {
		defer pipes.Done()
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			pipes.Add(1)
			go func() {
				defer pipes.Done()
				h.ServeConn(context.Background(), pipe.New(c, pipeOpts))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = pl.Close()
		h.Close(2 * time.Second)
		ws.Close()
		_ = srv.Close()
		pipes.Wait()
	})
	e.commit(&admin.NodeConfig{Link: admin.DialIn("work-link")})
	return e
}

// commit stores workCred as the secret "work-link" (the first time) and
// commits a document with node "work" linked by nc; alice may use it.
func (e *env) commit(nc *admin.NodeConfig) {
	e.t.Helper()
	a := e.dial("ws://"+e.tcpAddr, adminToken)
	defer a.Close()
	ac, err := admin.NewClient(a.Session(), "")
	if err != nil {
		e.t.Fatal(err)
	}
	ctx := tctx(e.t)
	if err := ac.SetSecret(ctx, "work-link", []byte(workCred)); err != nil && session.Code(err) != status.AlreadyExists {
		e.t.Fatal(err)
	}
	snap, err := ac.Get(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	grants := hub.EncodeGrants([]hub.Grant{{Principal: "user:alice", Facet: "work", Level: hub.LevelUse},
		{Principal: "user:alice", Facet: "work.*", Level: hub.LevelUse}})
	if _, err := ac.Commit(ctx, snap.Revision, &admin.Config{Nodes: map[string]*admin.NodeConfig{"work": nc},
		Extensions: map[string][]byte{hub.PolicyExtension: grants}}, 0); err != nil {
		e.t.Fatalf("commit: %v %v", err, admin.ProblemsOf(err))
	}
}

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func bearer(tok string) *wire.Auth {
	return &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, tok)}
}

func (e *env) dialOptions() nd.DialOptions {
	return nd.DialOptions{CertHashes: [][]byte{e.certHash}, QUICConfig: fastQUIC(),
		Backoff: 5 * time.Millisecond, BackoffMax: 50 * time.Millisecond, AttemptTimeout: time.Second}
}

// dial connects a client with a bearer token to url (https:// through
// WebTransport, ws:// through WebSocket).
func (e *env) dial(url, token string, tune ...func(*nd.Options)) *nd.Node {
	e.t.Helper()
	o := nd.Options{Auth: bearer(token), Logger: logger(e.t), Session: fastSession}
	for _, f := range tune {
		f(&o)
	}
	n := nd.New(o)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Dial(ctx, url, e.dialOptions()); err != nil {
		e.t.Fatalf("dial %s: %v", url, err)
	}
	e.t.Cleanup(n.Close)
	return n
}

func wtURL(addr string) string { return "https://" + addr + "/sparrow/wt" }
func wsURL(addr string) string { return "ws://" + addr }

// worker is the node "work": unary, streams in both directions, byte
// streams, and a call that blocks until cancelled.
type worker struct {
	n       *nd.Node
	started chan struct{}
	ended   chan error // why a blocked call ended
	notes   chan string
}

func workFacet(w *worker) *nd.Facet {
	b := nd.NewFacet("work", "1.0.0")
	svc := b.Service("Work")
	svc.Method("echo", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) { return c.Input() })
	svc.Method("count", nd.Uint, nd.Stream(nd.Uint), func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		for i := uint64(0); i < in.(uint64); i++ {
			if err := c.Send(ctx, i); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	svc.Method("sum", nd.Stream(nd.Uint), nd.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		var sum uint64
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return sum, nil
			}
			if err != nil {
				return nil, err
			}
			sum += v.(uint64)
		}
	})
	svc.Method("chat", nd.Stream(nd.String), nd.Stream(nd.String), func(ctx context.Context, c *session.ServerCall) (any, error) {
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			if err := c.Send(ctx, "re: "+v.(string)); err != nil {
				return nil, err
			}
		}
	})
	svc.Method("upload", nd.ByteStream(), nd.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		h := uint64(0)
		buf := make([]byte, 8192)
		r := c.Reader(0)
		for {
			k, err := r.Read(buf)
			for _, x := range buf[:k] {
				h = h*31 + uint64(x)
			}
			if err == io.EOF {
				return h, nil
			}
			if err != nil {
				return nil, err
			}
		}
	})
	svc.Method("download", nd.Uint, nd.ByteStream(), func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		w := c.Writer(ctx, 0)
		if err := w.WriteAll(pattern(int(in.(uint64)))); err != nil {
			return nil, err
		}
		return nil, w.Close()
	})
	svc.Method("block", nd.Unit, nd.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		w.started <- struct{}{}
		<-ctx.Done()
		w.ended <- context.Cause(ctx)
		return nil, context.Cause(ctx)
	})
	svc.Notification("note", nd.String, func(ctx context.Context, c *session.ServerCall) error {
		in, _ := c.Input()
		w.notes <- in.(string)
		return nil
	})
	return b.MustBuild()
}

// pattern is n deterministic bytes.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func hashOf(b []byte) uint64 {
	h := uint64(0)
	for _, x := range b {
		h = h*31 + uint64(x)
	}
	return h
}

// startWorker runs node "work", dialing in to url and redialing whenever
// its session ends, until the test ends.
func (e *env) startWorker(url string) *worker {
	e.t.Helper()
	w := &worker{started: make(chan struct{}, 16), ended: make(chan error, 16), notes: make(chan string, 64)}
	w.n = nd.New(nd.Options{Auth: &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, workCred)}, Logger: logger(e.t), Session: fastSession})
	if _, err := w.n.Add(tctx(e.t), workFacet(w)); err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.n.RunDial(ctx, url, e.dialOptions())
	}()
	e.t.Cleanup(func() {
		cancel()
		<-done
		w.n.Close()
	})
	e.waitNode(true)
	return w
}

func newWorker(t *testing.T, o nd.Options) *worker {
	w := &worker{started: make(chan struct{}, 16), ended: make(chan error, 16), notes: make(chan string, 64)}
	w.n = nd.New(o)
	if _, err := w.n.Add(tctx(t), workFacet(w)); err != nil {
		t.Fatal(err)
	}
	return w
}

// workLink is how node "work" authenticates to the hub.
func workLink() *wire.Auth {
	return &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, workCred)}
}

// startPipeWorker runs node "work" over the pipe binding: it connects to
// addr over TCP (the hub's pipe listener, or a proxy in front of it) and
// reconnects whenever its session ends, until the test ends.
func (e *env) startPipeWorker(addr string) *worker {
	e.t.Helper()
	w := newWorker(e.t, nd.Options{Auth: workLink(), Logger: logger(e.t), Session: fastSession})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if c, err := dialPipe(ctx, addr); err == nil {
				actx, acancel := context.WithTimeout(ctx, time.Second)
				err := w.n.Connect(actx, c, true)
				acancel()
				if err == nil {
					_ = w.n.Wait(ctx)
					if s := w.n.Session(); s != nil {
						s.Close(status.OK, "reconnecting")
					}
				}
				_ = c.Close(status.OK, "")
			}
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	e.t.Cleanup(func() {
		cancel()
		<-done
		w.n.Close()
	})
	e.waitNode(true)
	return w
}

// dialPipe opens a pipe connection over TCP to addr.
func dialPipe(ctx context.Context, addr string) (*pipe.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return pipe.New(c, pipeOpts), nil
}

// dialPipeClient connects a client with a bearer token over the pipe
// binding to addr.
func (e *env) dialPipeClient(addr, token string, tune ...func(*nd.Options)) *nd.Node {
	e.t.Helper()
	o := nd.Options{Auth: bearer(token), Logger: logger(e.t), Session: fastSession}
	for _, f := range tune {
		f(&o)
	}
	n := nd.New(o)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialPipe(ctx, addr)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := n.Connect(ctx, c, false); err != nil {
		e.t.Fatalf("pipe client to %s: %v", addr, err)
	}
	e.t.Cleanup(n.Close)
	return n
}

// listenWorker runs node "work" as a WebTransport server the hub dials,
// accepting the hub's link credential workCred. It returns the worker, the
// node's UDP address and its SPKI pin.
func (e *env) listenWorker() (*worker, string, []byte) {
	e.t.Helper()
	w := &worker{started: make(chan struct{}, 16), ended: make(chan error, 16), notes: make(chan string, 64)}
	w.n = nd.New(nd.Options{ID: "work", Logger: logger(e.t), Session: fastSession})
	if _, err := w.n.Add(tctx(e.t), workFacet(w)); err != nil {
		e.t.Fatal(err)
	}
	cert, _, err := webtransport.SelfSigned("127.0.0.1")
	if err != nil {
		e.t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	srv := webtransport.NewServer(webtransport.ServerOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		CheckOrigin: func(*http.Request) bool { return true }, QUICConfig: fastQUIC(), Linger: 150 * time.Millisecond})
	mux := http.NewServeMux()
	mux.Handle("/node", srv.Handler(func(c *webtransport.Conn, _ *http.Request) {
		_ = w.n.Serve(context.Background(), c, func(a *wire.Auth) error {
			if a != nil && a.Scheme == "link" {
				if s, err := cbor.NewDecoder(a.Credentials).Text(); err == nil && s == workCred {
					return nil
				}
			}
			return &session.Error{Code: status.Unauthenticated, Message: "bad hub credential"}
		})
	}))
	srv.WT.H3.Handler = mux
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	e.t.Cleanup(func() {
		w.n.Close()
		_ = srv.Close()
	})
	return w, pc.LocalAddr().String(), hub.PinFor(leaf)
}

func (e *env) waitNode(connected bool) {
	e.t.Helper()
	testutil.Eventually(e.t, 10*time.Second, func() bool {
		st, ok := e.h.Stats().Nodes["work"]
		return ok && st.Connected == connected
	}, "node work connected != %v", connected)
}

// nodeSession waits for the node's current session. A node that dials in
// records its session only once its own handshake call returns, which can
// be after the hub already lists its facets to clients.
func nodeSession(t *testing.T, n *nd.Node) *session.Session {
	t.Helper()
	var s *session.Session
	testutil.Eventually(t, 10*time.Second, func() bool { s = n.Session(); return s != nil }, "the node has no session")
	return s
}

// waitFacet waits until a client lists the work facet.
func waitFacet(t *testing.T, n *nd.Node) {
	t.Helper()
	testutil.Eventually(t, 10*time.Second, func() bool {
		s := n.Session()
		return s != nil && s.PeerFacet("work") != nil
	}, "facet work not listed")
}

// waitIdle waits until the hub runs no call and holds no call context,
// and no session (the hub's, and those of the given nodes) counts a call:
// calls ended by a fault must not stay counted toward maxConcurrentCalls.
func (e *env) waitIdle(nodes ...*nd.Node) {
	e.t.Helper()
	var why string
	testutil.Eventually(e.t, 5*time.Second, func() bool {
		st := e.h.Stats()
		if st.ActiveCalls != 0 || st.Contexts != 0 {
			why = fmt.Sprintf("hub %+v", st)
			return false
		}
		var ss []*session.Session
		for _, l := range e.h.Sessions() {
			ss = append(ss, l...)
		}
		for _, n := range nodes {
			if s := n.Session(); s != nil {
				ss = append(ss, s)
			}
		}
		for _, s := range ss {
			if st := s.Stats(); !st.Closed && (st.OpenCalls != 0 || st.OutgoingCalls != 0 || st.IncomingCalls != 0) {
				why = fmt.Sprintf("session of %q: %+v %+v", s.Principal(), st, s.Calls())
				return false
			}
		}
		return true
	}, "calls still counted: %s", lazy(func() string { return why }))
}

// lazy formats when printed.
type lazy func() string

func (l lazy) String() string { return l() }

// exercise runs every kind of call through the hub and checks the results:
// unary, server stream, client stream, bidi stream, byte streams both ways
// (larger than the credit windows, so back-pressure is exercised), cancel
// and a deadline.
func exercise(t *testing.T, cli *nd.Node, w *worker, size int) {
	t.Helper()
	ctx := tctx(t)
	for i := 0; i < 5; i++ {
		s := fmt.Sprintf("hello %d", i)
		if v, err := cli.Call(ctx, "work", "echo", s); err != nil || v != s {
			t.Fatalf("echo: %v %v", v, err)
		}
	}
	// server stream with a small credit window: back-pressure
	cc, err := cli.Open(ctx, "work", "count", uint64(200), &session.CallOptions{Credit: 64})
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 200; i++ {
		v, err := cc.Recv(ctx)
		if err != nil || v != i {
			t.Fatalf("count item %d: %v %v", i, v, err)
		}
	}
	if _, err := cc.Recv(ctx); err != io.EOF {
		t.Fatalf("count end: %v", err)
	}
	// client stream
	cc, err = cli.Open(ctx, "work", "sum", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(0)
	for i := uint64(1); i <= 200; i++ {
		if err := cc.Send(ctx, i); err != nil {
			t.Fatal(err)
		}
		want += i
	}
	if err := cc.CloseSend(nil); err != nil {
		t.Fatal(err)
	}
	if v, err := cc.Response(ctx); err != nil || v != want {
		t.Fatalf("sum %v %v, want %d", v, err, want)
	}
	// bidi stream
	cc, err = cli.Open(ctx, "work", "chat", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := cc.Send(ctx, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
		if v, err := cc.Recv(ctx); err != nil || v != "re: "+fmt.Sprint(i) {
			t.Fatalf("chat %d: %v %v", i, v, err)
		}
	}
	_ = cc.CloseSend(nil)
	if _, err := cc.Recv(ctx); err != io.EOF {
		t.Fatalf("chat end: %v", err)
	}
	// bytes up (bigger than the 64 KiB shared credit: back-pressure)
	data := pattern(size)
	cc, err = cli.Open(ctx, "work", "upload", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wr := cc.Writer(ctx, 0)
	if err := wr.WriteAll(data); err != nil {
		t.Fatal(err)
	}
	if err := wr.Close(); err != nil {
		t.Fatal(err)
	}
	if v, err := cc.Response(ctx); err != nil || v != hashOf(data) {
		t.Fatalf("upload: %v %v", v, err)
	}
	// bytes down
	cc, err = cli.Open(ctx, "work", "download", uint64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(cc.Reader(0))
	if err != nil || hashOf(got) != hashOf(data) || len(got) != len(data) {
		t.Fatalf("download: %d bytes, %v", len(got), err)
	}
	// cancel: the node's handler sees it
	cc, err = cli.Open(ctx, "work", "block", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-w.started
	if err := cc.Cancel(status.Cancelled); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-w.ended:
		if session.Code(err) != status.Cancelled {
			t.Fatalf("the node's handler ended with %v, want Cancelled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the node never saw the cancel")
	}
	// deadline: the caller gives up, the node's handler is cancelled
	dctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = cli.Call(dctx, "work", "block", nil)
	cancel()
	if session.Code(err) != status.DeadlineExceeded {
		t.Fatalf("deadline: %v (%d)", err, session.Code(err))
	}
	<-w.started
	select {
	case err := <-w.ended:
		if session.Code(err) != status.DeadlineExceeded {
			t.Fatalf("the node's handler ended with %v, want DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the node's handler outlived the deadline")
	}
}

// TestMain checks, once every test has finished, that the goroutines the
// tests started are gone (hub, sessions, transports, proxies): the count
// returns to what it was before, with a little slack for the runtime.
func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		os.Exit(runChild())
	}
	before := runtime.NumGoroutine()
	code := m.Run()
	if code == 0 && !testutil.WaitFor(5*time.Second, func() bool { return runtime.NumGoroutine() <= before+2 }) {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		fmt.Fprintf(os.Stderr, "leaked goroutines: %d before the tests, %d after\n%s", before, runtime.NumGoroutine(), buf[:n])
		code = 1
	}
	os.Exit(code)
}

// childEnv makes the test binary run as node "work" on its standard input
// and output (the started process is the client, 4.7), for the tests that
// start it as a child process.
const childEnv = "NETSIM_PIPE_CHILD"

// runChild is the child process: node "work" over pipe.Stdio, until the
// session ends.
func runChild() int {
	w := &worker{started: make(chan struct{}, 16), ended: make(chan error, 16), notes: make(chan string, 64)}
	w.n = nd.New(nd.Options{Auth: workLink(), Session: fastSession})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := w.n.Add(ctx, workFacet(w)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := w.n.Connect(ctx, pipe.Stdio(pipeOpts), true); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	go func() {
		for range w.started {
			fmt.Fprintln(os.Stderr, "started") // the parent waits for this line
		}
	}()
	_ = w.n.Wait(ctx)
	return 0
}
