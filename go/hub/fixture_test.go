package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport/webtransport"
	"github.com/aiviarium/sparrow/go/wire"
)

var echoBin string

func TestMain(m *testing.M) {
	flag.Parse()
	if fuzzing() {
		os.Exit(m.Run()) // fuzz targets need no echo-node binary
	}
	dir, err := os.MkdirTemp("", "hubtest")
	if err != nil {
		panic(err)
	}
	echoBin = filepath.Join(dir, "echo-node")
	if out, err := exec.Command("go", "build", "-o", echoBin, "../examples/echo-node").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build echo-node: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// fuzzing reports whether this process fuzzes (go test -fuzz, or one of
// its workers) rather than runs tests.
func fuzzing() bool {
	for _, name := range []string{"test.fuzz", "test.fuzzworker"} {
		if f := flag.Lookup(name); f != nil && f.Value.String() != "" && f.Value.String() != "false" {
			return true
		}
	}
	return false
}

const (
	adminToken = "admin-token"
	aliceToken = "alice-token"
	bobToken   = "bob-token"
)

// fixture is an in-process hub behind WebTransport and WebSocket
// listeners.
type fixture struct {
	t        *testing.T
	dir      string
	h        *Hub
	opts     Options
	wtURL    string
	wsURL    string
	certHash []byte
	pin      []byte // SPKI pin of the WebTransport listener
	wsAddr   string // TCP address of the plain WebSocket listener
	closers  []func()
	mu       sync.Mutex
	echoes   map[string]*echoNode // echo-node processes (echo, dialedEcho)
}

type testLogWriter struct {
	t    *testing.T
	mu   sync.Mutex
	done bool
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.done && os.Getenv("HUB_TEST_LOG") != "" {
		w.t.Log(strings.TrimRight(string(p), "\n"))
	}
	return len(p), nil
}

func testLogger(t *testing.T) *slog.Logger {
	w := &testLogWriter{t: t}
	t.Cleanup(func() { w.mu.Lock(); w.done = true; w.mu.Unlock() })
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func baseOptions(t *testing.T, dir string) Options {
	store, err := admin.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Store:     store,
		Bootstrap: []Credential{{Token: adminToken, Principal: "user:admin"}},
		Tokens: []Credential{
			{Token: aliceToken, Principal: "user:alice", Groups: []string{"group:eng"}},
			{Token: bobToken, Principal: "user:bob"},
		},
		Logger:         testLogger(t),
		ConnectTimeout: 3 * time.Second,
		// Redial quickly: a test waits for the hub to reach a node that
		// came back, not for a production backoff.
		RedialBackoff:    5 * time.Millisecond,
		RedialBackoffMax: 50 * time.Millisecond,
		WaitingRedial:    5 * time.Millisecond,
		// A node that is not listening is noticed by the QUIC handshake
		// timeout (5 s); attempts on localhost take milliseconds.
		DialTimeout: 500 * time.Millisecond,
	}
}

// testLinger replaces the session's DefaultLinger (1 s) and GoAwayWait
// (2 s) in tests: the messages that precede the end of a connection on
// localhost arrive well within it.
const testLinger = 200 * time.Millisecond

// fastSession shortens the wall-clock waits of a session that the tests do
// not assert on; a test's own Session hook runs after it.
func fastSession(next func(*session.Config)) func(*session.Config) {
	return func(c *session.Config) {
		c.Linger, c.GoAwayWait = testLinger, testLinger
		if next != nil {
			next(c)
		}
	}
}

// echoTimingArgs make an echo-node process redial and shut down quickly.
var echoTimingArgs = []string{"-backoff", "5ms", "-backoff-max", "50ms", "-attempt-timeout", "2s", "-linger", testLinger.String()}

func newFixture(t *testing.T, tune func(*Options)) *fixture {
	dir := t.TempDir()
	return startFixture(t, dir, tune)
}

func startFixture(t *testing.T, dir string, tune func(*Options)) *fixture {
	return startFixtureOn(t, dir, "", tune)
}

// startFixtureOn is startFixture with the plain WebSocket listener on a
// given address ("" for any), so that a restarted hub is found again by
// nodes that dial in.
func startFixtureOn(t *testing.T, dir, wsAddr string, tune func(*Options)) *fixture {
	o := baseOptions(t, dir)
	if tune != nil {
		tune(&o)
	}
	o.Session = fastSession(o.Session)
	h, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, dir: dir, h: h, opts: o, echoes: map[string]*echoNode{}}
	cert, hash, err := webtransport.SelfSigned("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	f.certHash = hash
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	f.pin = PinFor(leaf)
	srv := webtransport.NewServer(webtransport.ServerOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, CheckOrigin: func(*http.Request) bool { return true }})
	mux := http.NewServeMux()
	mux.Handle("/sparrow/wt", h.WebTransportHandler(srv))
	srv.WT.H3.Handler = mux
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	f.wtURL = fmt.Sprintf("https://127.0.0.1:%d/sparrow/wt", pc.LocalAddr().(*net.UDPAddr).Port)
	ws := httptest.NewUnstartedServer(h.WebSocketHandler(func(*http.Request) bool { return true }))
	if wsAddr != "" {
		var l net.Listener
		// The old hub's port may take a moment to become free.
		testutil.Eventually(t, 10*time.Second, func() bool {
			var err error
			l, err = net.Listen("tcp", wsAddr)
			return err == nil
		}, "cannot listen on %s again", wsAddr)
		ws.Listener.Close()
		ws.Listener = l
	}
	ws.Start()
	f.wsAddr = ws.Listener.Addr().String()
	f.wsURL = "ws" + strings.TrimPrefix(ws.URL, "http")
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		h.Close(5 * time.Second)
		ws.Close()
		_ = srv.Close()
	}
	f.closers = append(f.closers, stop)
	t.Cleanup(func() {
		f.mu.Lock()
		cs := f.closers
		f.mu.Unlock()
		for i := len(cs) - 1; i >= 0; i-- {
			cs[i]()
		}
	})
	return f
}

// stop shuts the hub down (for restart tests).
func (f *fixture) stop() { f.closers[0]() }

func (f *fixture) onCleanup(fn func()) {
	f.mu.Lock()
	f.closers = append(f.closers, fn)
	f.mu.Unlock()
}

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func bearer(tok string) *wire.Auth {
	return &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, tok)}
}

func linkAuth(cred string) *wire.Auth {
	return &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, cred)}
}

// transports is the list of client bindings the integration tests use.
var transports = []string{"webtransport", "websocket"}

func (f *fixture) url(binding string) string {
	if binding == "websocket" {
		return f.wsURL
	}
	return f.wtURL
}

// client connects a node-library client with a bearer token.
func (f *fixture) client(binding, token string, tune ...func(*nd.Options)) *nd.Node {
	f.t.Helper()
	o := nd.Options{Auth: bearer(token), Logger: testLogger(f.t)}
	for _, fn := range tune {
		fn(&o)
	}
	o.Session = fastSession(o.Session)
	n := nd.New(o)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := n.Dial(ctx, f.url(binding), nd.DialOptions{CertHashes: [][]byte{f.certHash}}); err != nil {
		f.t.Fatalf("client dial (%s): %v", binding, err)
	}
	f.onCleanup(n.Close)
	return n
}

// adminClient returns an admin client over a bootstrap-admin session.
func (f *fixture) adminClient(binding string) (*admin.Client, *nd.Node) {
	f.t.Helper()
	n := f.client(binding, adminToken)
	c, err := admin.NewClient(n.Session(), "")
	if err != nil {
		f.t.Fatal(err)
	}
	return c, n
}

// commit commits a document against the current revision.
func (f *fixture) commit(cfg *admin.Config) uint64 {
	f.t.Helper()
	c, _ := f.adminClient("websocket")
	ctx := tctx(f.t)
	snap, err := c.Get(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	rev, err := c.Commit(ctx, snap.Revision, cfg, 0)
	if err != nil {
		f.t.Fatalf("commit: %v %v", err, admin.ProblemsOf(err))
	}
	f.startEchoes()
	return rev
}

func (f *fixture) secret(name, value string) {
	f.t.Helper()
	c, _ := f.adminClient("websocket")
	if err := c.SetSecret(tctx(f.t), name, []byte(value)); err != nil {
		f.t.Fatal(err)
	}
}

// echoNode is an examples/echo-node process: it dials in (echo) or waits
// to be dialed (dialedEcho). The hub never starts it.
type echoNode struct {
	id, cred string
	hub      string // the URL it dials in to; "" for the WebSocket listener
	args     []string
	nc       *admin.NodeConfig
	p        *testutil.Proc
	url      string // dialedEcho: where it listens
	pin      []byte
	keyFile  string
}

// echo returns the configuration of a dial-in node id run by examples/
// echo-node as a separate process over WebSocket (-hub). Its credential is
// stored now as the secret "<id>-link"; the process starts after the next
// f.commit (or f.startEchoes), so its first attempt is accepted. Asking
// again for the same id returns the same node.
func (f *fixture) echo(id string, extra ...string) *admin.NodeConfig {
	f.t.Helper()
	if e := f.echoes[id]; e != nil {
		return e.nc.Clone()
	}
	e := &echoNode{id: id, cred: "cred-of-" + id, args: extra}
	f.storeSecret(id+"-link", e.cred)
	e.nc = &admin.NodeConfig{Link: admin.DialIn(id + "-link")}
	f.echoes[id] = e
	return e.nc.Clone()
}

// echoWT is echo for a node that dials in over WebTransport and checks the
// hub's SPKI pin (-hub-pin).
func (f *fixture) echoWT(id string) *admin.NodeConfig {
	f.t.Helper()
	nc := f.echo(id, "-hub-pin", hex.EncodeToString(f.pin))
	f.echoes[id].hub = f.wtURL
	return nc
}

// storeSecret stores a secret, which may already be stored (with the same
// value) from before a restart.
func (f *fixture) storeSecret(name, value string) {
	f.t.Helper()
	c, _ := f.adminClient("websocket")
	if err := c.SetSecret(tctx(f.t), name, []byte(value)); err != nil && session.Code(err) != status.AlreadyExists {
		f.t.Fatal(err)
	}
}

// startEchoes starts the dial-in echo processes not yet running.
func (f *fixture) startEchoes() {
	for _, e := range f.echoes {
		if e.p == nil && e.url == "" {
			f.runEcho(e)
		}
	}
}

func (f *fixture) runEcho(e *echoNode) {
	url := e.hub
	if url == "" {
		url = f.wsURL
	}
	args := append(append([]string{"-id", e.id, "-hub", url, "-credential", e.cred}, echoTimingArgs...), e.args...)
	e.p = testutil.StartProc(f.t, "echo-node "+e.id, echoBin, args...)
}

// restartEcho stops (or with crash, kills) an echo process and starts it
// again with the same identity, key and address.
func (f *fixture) restartEcho(id string, crash bool) {
	f.t.Helper()
	e := f.echoes[id]
	f.stopEcho(id, crash)
	if e.url == "" {
		f.runEcho(e)
		return
	}
	f.listenEcho(e, strings.TrimSuffix(strings.TrimPrefix(e.url, "https://"), "/sparrow/node"))
}

// stopEcho ends an echo process: SIGTERM (it closes its session with
// GoAway), or with crash SIGKILL.
func (f *fixture) stopEcho(id string, crash bool) {
	e := f.echoes[id]
	if e.p == nil {
		return
	}
	if crash {
		e.p.Kill()
	} else {
		_ = e.p.Stop()
	}
	e.p = nil
}

// dialedEcho starts examples/echo-node as a separate process listening
// for WebTransport (-listen), and returns the configuration of a node the
// hub dials at its URL and SPKI pin, presenting the secret "<id>-link".
func (f *fixture) dialedEcho(id string, extra ...string) *admin.NodeConfig {
	f.t.Helper()
	e := &echoNode{id: id, cred: "dial-cred-of-" + id, args: extra, keyFile: filepath.Join(f.t.TempDir(), id+".key")}
	f.storeSecret(id+"-link", e.cred)
	f.listenEcho(e, "127.0.0.1:0")
	e.nc = &admin.NodeConfig{Link: admin.Dialed(admin.Dial{URL: e.url, Pin: e.pin, Credential: id + "-link"})}
	f.echoes[id] = e
	return e.nc.Clone()
}

func (f *fixture) listenEcho(e *echoNode, addr string) {
	f.t.Helper()
	args := append(append([]string{"-id", e.id, "-listen", addr, "-credential", e.cred, "-key-file", e.keyFile}, echoTimingArgs...), e.args...)
	var line string
	// A restart on the same port may find it still in use for a moment.
	for i := 0; ; i++ {
		e.p = testutil.StartProc(f.t, "echo-node "+e.id, echoBin, args...)
		var err error
		if line, err = e.p.Line(15 * time.Second); err == nil {
			break
		}
		if i == 20 {
			f.t.Fatalf("echo-node %s does not listen: %v\n%s", e.id, err, e.p.Log())
		}
		_ = e.p.Stop()
		time.Sleep(20 * time.Millisecond) // retry pacing while the port is released
	}
	var a struct{ WebTransport, Pin string }
	if err := json.Unmarshal([]byte(line), &a); err != nil {
		f.t.Fatalf("echo-node output %q: %v", line, err)
	}
	e.url = a.WebTransport
	e.pin, _ = hex.DecodeString(a.Pin)
}

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }

func policy(gs ...Grant) map[string][]byte {
	return map[string][]byte{PolicyExtension: EncodeGrants(gs)}
}

func grant(p, f, l string) Grant {
	lv, err := ParseLevel(l)
	if err != nil {
		panic(err)
	}
	return Grant{Principal: p, Facet: f, Level: lv}
}

// waitFacet waits until a client's schema lists a facet.
func waitFacet(t *testing.T, n *nd.Node, name string) uint64 {
	t.Helper()
	var id uint64
	testutil.Eventually(t, 15*time.Second, func() bool {
		s := n.Session()
		if s == nil {
			return false
		}
		f := s.PeerFacet(name)
		if f == nil {
			return false
		}
		id = f.ID
		return true
	}, "facet %q never appeared", name)
	return id
}

func waitNoFacet(t *testing.T, n *nd.Node, name string) {
	t.Helper()
	testutil.Eventually(t, 15*time.Second, func() bool {
		s := n.Session()
		return s != nil && s.PeerFacet(name) == nil
	}, "facet %q still listed", name)
}

func waitNode(t *testing.T, h *Hub, id string, connected bool) {
	t.Helper()
	testutil.Eventually(t, 20*time.Second, func() bool {
		st, ok := h.Stats().Nodes[id]
		return ok && st.Connected == connected
	}, "node %s connected != %v: %+v", id, connected, h.Stats().Nodes[id])
}

func mustCode(t *testing.T, err error, want any) {
	t.Helper()
	if got := session.Code(err); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
}

var _ = io.EOF

// waitWaiting waits until at least n calls wait for node id to connect
// (10.7). Their connect-timeout timers are armed by then.
func waitWaiting(t *testing.T, h *Hub, id string, n int32) {
	t.Helper()
	testutil.Eventually(t, 10*time.Second, func() bool {
		h.mu.Lock()
		nd := h.nodes[id]
		h.mu.Unlock()
		return nd != nil && nd.waiting.Load() >= n
	}, "fewer than %d calls wait for node %s", n, id)
}

// dialAttempts is the number of attempts the dial loop of node id has made
// (0 without a dial loop).
func dialAttempts(h *Hub, id string) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n := h.nodes[id]; n != nil && n.dl != nil {
		return n.dl.attempts.Load()
	}
	return 0
}

// expectConnectTimeout calls an offline node on a hub that runs on the
// fake clock clk and checks that the call fails with unavailable when, and
// not before, the connect timeout passes (10.7).
func expectConnectTimeout(t *testing.T, f *fixture, clk *testutil.FakeClock, cli *nd.Node, nodeID, facet, method string, in any) {
	t.Helper()
	before := int32(0)
	f.h.mu.Lock()
	if n := f.h.nodes[nodeID]; n != nil {
		before = n.waiting.Load()
	}
	f.h.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := cli.Call(tctx(t), facet, method, in)
		done <- err
	}()
	waitWaiting(t, f.h, nodeID, before+1)
	clk.Advance(f.h.o.ConnectTimeout - time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("the call ended before the connect timeout: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	clk.Advance(time.Millisecond)
	select {
	case err := <-done:
		mustCode(t, err, status.Unavailable)
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not fail at the connect timeout")
	}
}
