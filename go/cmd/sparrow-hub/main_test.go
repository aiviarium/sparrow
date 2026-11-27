package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

var bins = map[string]string{}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sparrow-hub-test")
	if err != nil {
		panic(err)
	}
	for name, pkg := range map[string]string{"sparrow-hub": ".", "sparrow-admin": "../sparrow-admin", "echo-node": "../../examples/echo-node"} {
		bins[name] = filepath.Join(dir, name)
		if out, err := exec.Command("go", "build", "-o", bins[name], pkg).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", name, err, out)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type hubProc struct {
	t     *testing.T
	cmd   *exec.Cmd
	addrs Addrs
	log   *bytes.Buffer
	lw    *lockedWriter
	done  chan error
}

// logText returns the hub's log so far.
func (p *hubProc) logText() string {
	p.lw.mu.lock()
	defer p.lw.mu.unlock()
	return p.log.String()
}

func writeConfig(t *testing.T, dir string) string {
	cfg := map[string]any{
		"webtransport": "127.0.0.1:0", "websocket": "127.0.0.1:0", "selfSigned": true,
		"dataDir":   filepath.Join(dir, "data"),
		"bootstrap": []map[string]string{{"principal": "user:admin", "credential": "admin-secret"}},
		"tokens":    []map[string]any{{"token": "alice-token", "principal": "user:alice", "groups": []string{"group:eng"}}},
		"log":       "debug", "shutdownGraceMs": 3000, "connectTimeoutMs": 15000,
		// Redial within milliseconds: the test waits for nodes that come
		// back, not for production backoffs.
		"redialBackoffMs": 5, "redialBackoffMaxMs": 50,
	}
	b, _ := json.Marshal(cfg)
	p := filepath.Join(dir, "hub.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func startHub(t *testing.T, dir string) *hubProc {
	t.Helper()
	cfg := filepath.Join(dir, "hub.json")
	if _, err := os.Stat(cfg); err != nil {
		cfg = writeConfig(t, dir)
	}
	addrFile := filepath.Join(dir, "addrs.json")
	_ = os.Remove(addrFile)
	cmd := exec.Command(bins["sparrow-hub"], "-config", cfg, "-addr-file", addrFile)
	p := &hubProc{t: t, cmd: cmd, log: &bytes.Buffer{}, done: make(chan error, 1)}
	p.lw = &lockedWriter{w: p.log}
	cmd.Stderr = p.lw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() { p.stop() })
	testutil.Eventually(t, 15*time.Second, func() bool {
		b, err := os.ReadFile(addrFile)
		return err == nil && json.Unmarshal(b, &p.addrs) == nil
	}, "hub not ready")
	return p
}

type lockedWriter struct {
	w  io.Writer
	mu chanMutex
}

type chanMutex struct{ m sync.Mutex }

func (m *chanMutex) lock()   { m.m.Lock() }
func (m *chanMutex) unlock() { m.m.Unlock() }

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.lock()
	defer l.mu.unlock()
	return l.w.Write(b)
}

// stop sends SIGTERM and waits for a graceful exit.
func (p *hubProc) stop() error {
	if p.cmd.ProcessState != nil {
		return nil
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-p.done:
		p.done <- err
		return err
	case <-time.After(20 * time.Second):
		_ = p.cmd.Process.Kill()
		p.t.Errorf("hub did not exit; log:\n%s", p.logText())
		return fmt.Errorf("killed")
	}
}

func (p *hubProc) admin(t *testing.T, url string, args ...string) string {
	t.Helper()
	all := append([]string{"-url", url, "-token", "admin-secret", "-cert-hash", p.addrs.CertHash}, args...)
	out, err := exec.Command(bins["sparrow-admin"], all...).CombinedOutput()
	if err != nil {
		t.Fatalf("sparrow-admin %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (p *hubProc) client(t *testing.T, url, token string, known *session.Config) *node.Node {
	t.Helper()
	h, _ := hex.DecodeString(p.addrs.CertHash)
	o := node.Options{Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, token)}}
	if known != nil {
		o.Session = func(c *session.Config) { c.KnownSchema = known.KnownSchema }
	}
	n := node.New(o)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	do := node.DialOptions{CertHashes: [][]byte{h}}
	if strings.HasPrefix(url, "wss://") {
		do.HTTPClient = pinnedClient(h)
	}
	if err := n.Dial(ctx, url, do); err != nil {
		t.Fatalf("dial %s: %v\n%s", url, err, p.logText())
	}
	return n
}

// echoDialIn starts examples/echo-node as its own process, dialing in to
// the hub over WebTransport with the hub's SPKI pin and the given link
// credential; it redials whenever its session ends.
func (p *hubProc) echoDialIn(t *testing.T, id, cred string, extra ...string) *testutil.Proc {
	t.Helper()
	args := append([]string{"-id", id, "-hub", p.addrs.WebTransport, "-hub-pin", p.addrs.Pin, "-credential", cred, "-backoff", "5ms", "-backoff-max", "50ms", "-attempt-timeout", "2s"}, extra...)
	return testutil.StartProc(t, "echo-node "+id, bins["echo-node"], args...)
}

// echoListening starts examples/echo-node as its own process waiting to be
// dialed over WebTransport by a hub presenting cred, and returns the URL
// and SPKI pin (hex) it printed.
func echoListening(t *testing.T, id, cred string) (*testutil.Proc, string, string) {
	t.Helper()
	pr := testutil.StartProc(t, "echo-node "+id, bins["echo-node"], "-id", id, "-listen", "127.0.0.1:0", "-credential", cred)
	line, err := pr.Line(15 * time.Second)
	if err != nil {
		t.Fatalf("%v\n%s", err, pr.Log())
	}
	var a struct{ WebTransport, Pin string }
	if err := json.Unmarshal([]byte(line), &a); err != nil || a.WebTransport == "" || len(a.Pin) != 64 {
		t.Fatalf("echo-node printed %q: %v", line, err)
	}
	return pr, a.WebTransport, a.Pin
}

// keepPorts rewrites the static file so that a restarted hub listens where
// this one does: a node that dials in then finds it again by itself.
func keepPorts(t *testing.T, dir string, a Addrs) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(b, &cfg)
	for key, u := range map[string]string{"webtransport": a.WebTransport, "websocket": a.WebSocket} {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		cfg[key] = pu.Host
	}
	b, _ = json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "hub.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestBinary drives the built programs as separate processes: the hub,
// sparrow-admin, and examples/echo-node twice, once dialing in (echo) and
// once waiting to be dialed (echo-dialed). It covers validate, commit and
// confirm, secrets, calls through both nodes over both bindings, graceful
// shutdown, a restart on the same data directory (the dial-in node
// reconnects by itself and serves a call that waited for it; the hub
// redials the other) and watch.
func TestBinary(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := startHub(t, dir)
	keepPorts(t, dir, p.addrs)
	dialed, dialURL, dialPin := echoListening(t, "echo-dialed", "hub-to-dialed")
	p.admin(t, p.addrs.WebSocket, "set-secret", "echo-link", "echo-to-hub")
	p.admin(t, p.addrs.WebSocket, "set-secret", "dialed-link", "hub-to-dialed")
	doc := fmt.Sprintf(`{"nodes": {"echo": {"link": {"credential": "echo-link"}}, "echo-dialed": {"link": {"dial": {"url": %q, "pin": %q, "credential": "dialed-link"}}}},
		"policy": [["group:eng", "echo", "use"], ["group:eng", "echo-dialed", "use"]]}`, dialURL, dialPin)
	docFile := filepath.Join(dir, "doc.json")
	_ = os.WriteFile(docFile, []byte(doc), 0o600)
	if out := p.admin(t, p.addrs.WebSocket, "validate", docFile); strings.TrimSpace(out) != "[]" {
		t.Fatalf("validate: %s", out)
	}
	out := p.admin(t, p.addrs.WebTransport, "commit", "-confirm-within", "10000", "-confirm", docFile)
	if !strings.Contains(out, `"revision": 1`) {
		t.Fatalf("commit: %s", out)
	}
	dialIn := p.echoDialIn(t, "echo", "echo-to-hub")
	if out := p.admin(t, p.addrs.WebSocket, "get"); !strings.Contains(out, `"state": "confirmed"`) || !strings.Contains(out, `"revision": 1`) {
		t.Fatalf("get: %s", out)
	}
	p.admin(t, p.addrs.WebSocket, "set-secret", "s1", "value")
	if out := p.admin(t, p.addrs.WebSocket, "list-secrets"); !strings.Contains(out, "s1") || strings.Contains(out, "value") {
		t.Fatalf("list-secrets: %s", out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cached *session.Config
	for _, url := range []string{p.addrs.WebTransport, p.addrs.WebSocket} {
		c := p.client(t, url, "alice-token", nil)
		for _, facet := range []string{"echo", "echo-dialed"} {
			testutil.Eventually(t, 15*time.Second, func() bool { return c.Session().PeerFacet(facet) != nil }, "no %s facet", facet)
			if v, err := c.Call(ctx, facet, "echo", "through the binary"); err != nil || v != "through the binary" {
				t.Fatalf("%s: %v %v", facet, v, err)
			}
			cs, err := c.Open(ctx, facet, "count", uint64(10), nil)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for {
				if _, err := cs.Recv(ctx); err != nil {
					break
				}
				n++
			}
			if n != 10 {
				t.Fatalf("%s: count %d", facet, n)
			}
			if v, err := c.Call(ctx, facet, "whoami", nil); err != nil || v != "user:alice" {
				t.Fatalf("%s: whoami %v %v", facet, v, err)
			}
		}
		cached = &session.Config{KnownSchema: c.Session().PeerSchema().Schema()}
		c.Close()
	}
	// Graceful shutdown: a connected client gets GoAway(going_away).
	live := p.client(t, p.addrs.WebTransport, "alice-token", nil)
	if err := p.stop(); err != nil {
		t.Fatalf("exit: %v\n%s", err, p.logText())
	}
	s := live.Session()
	if s != nil {
		select {
		case <-s.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("client session not ended")
		}
		if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != status.GoingAway {
			t.Fatalf("client got %v", g)
		}
	}
	// Restart: everything persisted; the cached schema is still current,
	// since both nodes' last known facets are listed while they are
	// offline. The call to echo waits (connectTimeoutMs) until the node,
	// redialing with backoff, is back; the hub redials echo-dialed.
	p2 := startHub(t, dir)
	if p2.addrs.Pin != p.addrs.Pin || p2.addrs.WebTransport != p.addrs.WebTransport {
		t.Fatalf("restarted hub at %+v, was %+v", p2.addrs, p.addrs)
	}
	if out := p2.admin(t, p2.addrs.WebSocket, "get"); !strings.Contains(out, `"revision": 1`) || !strings.Contains(out, `"echo-link"`) {
		t.Fatalf("after restart: %s", out)
	}
	c := p2.client(t, p2.addrs.WebSocket, "alice-token", cached)
	if k := c.Session().Welcome().ServerSchema.Kind; k != wire.OfferUnchanged {
		t.Fatalf("offer %v after restart, want Unchanged", k)
	}
	for _, facet := range []string{"echo", "echo-dialed"} {
		if v, err := c.Call(ctx, facet, "echo", "again"); err != nil || v != "again" {
			t.Fatalf("%s: %v %v\n%s", facet, v, err, p2.logText())
		}
	}
	c.Close()
	// watch prints the snapshot first.
	w := exec.Command(bins["sparrow-admin"], "-url", p2.addrs.WebTransport, "-token", "admin-secret", "-cert-hash", p2.addrs.CertHash, "watch")
	wf, _ := os.Create(filepath.Join(dir, "watch.out"))
	w.Stdout = wf
	w.Stderr = wf
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	read := func() string { b, _ := os.ReadFile(wf.Name()); return string(b) }
	exited := make(chan error, 1)
	go func() { exited <- w.Wait() }()
	// The output is read when the wait ends (not when it starts), and a
	// watch that exits early (an error) fails at once with what it printed.
	deadline := time.After(30 * time.Second)
	for !strings.Contains(read(), `"node":"echo"`) {
		select {
		case err := <-exited:
			if !strings.Contains(read(), `"node":"echo"`) {
				t.Fatalf("watch exited (%v): %q", err, read())
			}
			exited <- err
		case <-deadline:
			_ = w.Process.Kill()
			t.Fatalf("watch output after 30 s: %q", read())
		case <-time.After(20 * time.Millisecond):
		}
	}
	_ = w.Process.Signal(os.Interrupt)
	<-exited
	wf.Close()
	if !strings.HasPrefix(read(), `{"snapshot"`) {
		t.Fatalf("watch: %s", read())
	}
	// The nodes stop while the hub still runs, so their GoAway is answered
	// (a node whose hub is gone waits out the WebTransport linger).
	for _, pr := range []*testutil.Proc{dialIn, dialed} {
		if err := pr.Stop(); err != nil {
			t.Errorf("%s: %v\n%s", pr.Name, err, pr.Log())
		}
	}
}

func pinnedClient(hash []byte) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fmt.Errorf("no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if !bytes.Equal(sum[:], hash) {
				return fmt.Errorf("certificate hash mismatch")
			}
			return nil
		},
	}}}
}

// TestRunInProcess runs the program's Run in this process: plain-ws
// WebSocket plus WebTransport, and shutdown on cancel.
func TestRunInProcess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := &Config{WebTransport: "127.0.0.1:0", WebSocket: "127.0.0.1:0", WebSocketPlain: true, SelfSigned: true, DataDir: dir}
	cfg.Bootstrap = append(cfg.Bootstrap, struct {
		Principal      string `json:"principal"`
		Credential     string `json:"credential"`
		CredentialFile string `json:"credentialFile"`
	}{Principal: "user:admin", Credential: "adm"})
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan Addrs, 1)
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, newLogger("error"), func(a Addrs) { ready <- a }) }()
	var a Addrs
	select {
	case a = <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.WebSocket, "ws://") || !strings.HasPrefix(a.WebTransport, "https://") || len(a.Pin) != 64 {
		t.Fatalf("%+v", a)
	}
	p := &hubProc{t: t, addrs: a, log: &bytes.Buffer{}}
	c := p.client(t, a.WebSocket, "adm", nil)
	if c.Session().PeerFacet("sparrow.hub.admin") == nil {
		t.Fatal("no admin facet")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return")
	}
	if g := c.Session(); g != nil {
		select {
		case <-g.Done():
		case <-time.After(10 * time.Second):
			t.Fatal("client session not ended after Run returned")
		}
		if ga := g.GoAwayReceived(); ga == nil || status.Code(ga.Status) != status.GoingAway {
			t.Fatalf("client got %v", ga)
		}
	}
}
