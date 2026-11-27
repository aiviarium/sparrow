package hub

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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

var echoBin string

func TestMain(m *testing.M) {
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
	closers  []func()
	mu       sync.Mutex
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
		Logger:       testLogger(t),
		StartTimeout: 3 * time.Second,
	}
}

func newFixture(t *testing.T, tune func(*Options)) *fixture {
	dir := t.TempDir()
	return startFixture(t, dir, tune)
}

func startFixture(t *testing.T, dir string, tune func(*Options)) *fixture {
	o := baseOptions(t, dir)
	if tune != nil {
		tune(&o)
	}
	h, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, dir: dir, h: h, opts: o}
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
	ws := httptest.NewServer(h.WebSocketHandler(func(*http.Request) bool { return true }))
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
	return rev
}

func (f *fixture) secret(name, value string) {
	f.t.Helper()
	c, _ := f.adminClient("websocket")
	if err := c.SetSecret(tctx(f.t), name, []byte(value)); err != nil {
		f.t.Fatal(err)
	}
}

func spawnEcho(id string, extra ...string) *admin.NodeConfig {
	cmd := append([]string{echoBin, "-id", id}, extra...)
	return &admin.NodeConfig{Start: &admin.Start{Spawn: &admin.Spawn{Command: cmd}}}
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
