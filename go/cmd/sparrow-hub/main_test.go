package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	done  chan error
}

func writeConfig(t *testing.T, dir string) string {
	cfg := map[string]any{
		"webtransport": "127.0.0.1:0", "websocket": "127.0.0.1:0", "selfSigned": true,
		"dataDir":   filepath.Join(dir, "data"),
		"bootstrap": []map[string]string{{"principal": "user:admin", "credential": "admin-secret"}},
		"tokens":    []map[string]any{{"token": "alice-token", "principal": "user:alice", "groups": []string{"group:eng"}}},
		"log":       "debug", "shutdownGraceMs": 3000, "startTimeoutMs": 3000,
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
	cmd.Stderr = &lockedWriter{w: p.log}
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

type chanMutex struct{ ch chan struct{} }

func (m *chanMutex) lock() {
	if m.ch == nil {
		m.ch = make(chan struct{}, 1)
	}
	m.ch <- struct{}{}
}
func (m *chanMutex) unlock() { <-m.ch }

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
		p.t.Errorf("hub did not exit; log:\n%s", p.log.String())
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
		t.Fatalf("dial %s: %v\n%s", url, err, p.log.String())
	}
	return n
}

func TestBinary(t *testing.T) {
	dir := t.TempDir()
	p := startHub(t, dir)
	doc := fmt.Sprintf(`{"nodes": {"echo": {"spawn": {"command": [%q, "-id", "echo"]}}}, "policy": [["group:eng", "echo", "use"]]}`, bins["echo-node"])
	docFile := filepath.Join(dir, "doc.json")
	_ = os.WriteFile(docFile, []byte(doc), 0o600)
	if out := p.admin(t, p.addrs.WebSocket, "validate", docFile); strings.TrimSpace(out) != "[]" {
		t.Fatalf("validate: %s", out)
	}
	out := p.admin(t, p.addrs.WebTransport, "commit", "-confirm-within", "10000", "-confirm", docFile)
	if !strings.Contains(out, `"revision": 1`) {
		t.Fatalf("commit: %s", out)
	}
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
		testutil.Eventually(t, 15*time.Second, func() bool { return c.Session().PeerFacet("echo") != nil }, "no echo facet")
		if v, err := c.Call(ctx, "echo", "echo", "through the binary"); err != nil || v != "through the binary" {
			t.Fatalf("%v %v", v, err)
		}
		cs, err := c.Open(ctx, "echo", "count", uint64(10), nil)
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
			t.Fatalf("count %d", n)
		}
		if v, err := c.Call(ctx, "echo", "whoami", nil); err != nil || v != "user:alice" {
			t.Fatalf("whoami %v %v", v, err)
		}
		cached = &session.Config{KnownSchema: c.Session().PeerSchema().Schema()}
		c.Close()
	}
	// Graceful shutdown: a connected client gets GoAway(going_away).
	live := p.client(t, p.addrs.WebTransport, "alice-token", nil)
	if err := p.stop(); err != nil {
		t.Fatalf("exit: %v\n%s", err, p.log.String())
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
	// Restart: everything persisted; the cached schema is still current.
	p2 := startHub(t, dir)
	if out := p2.admin(t, p2.addrs.WebSocket, "get"); !strings.Contains(out, `"revision": 1`) || !strings.Contains(out, "echo-node") {
		t.Fatalf("after restart: %s", out)
	}
	c := p2.client(t, p2.addrs.WebSocket, "alice-token", cached)
	if k := c.Session().Welcome().ServerSchema.Kind; k != wire.OfferUnchanged {
		t.Fatalf("offer %v after restart, want Unchanged", k)
	}
	if v, err := c.Call(ctx, "echo", "echo", "again"); err != nil || v != "again" {
		t.Fatalf("%v %v", v, err)
	}
	c.Close()
	// watch prints the snapshot first.
	w := exec.Command(bins["sparrow-admin"], "-url", p2.addrs.WebTransport, "-token", "admin-secret", "-cert-hash", p2.addrs.CertHash, "watch")
	wf, _ := os.Create(filepath.Join(dir, "watch.out"))
	w.Stdout = wf
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	read := func() string { b, _ := os.ReadFile(wf.Name()); return string(b) }
	testutil.Eventually(t, 10*time.Second, func() bool { return strings.Contains(read(), `"node":"echo"`) }, "watch output %q", read())
	_ = w.Process.Signal(os.Interrupt)
	_ = w.Wait()
	wf.Close()
	if !strings.HasPrefix(read(), `{"snapshot"`) {
		t.Fatalf("watch: %s", read())
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
