package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestBrowser runs e2e/browser/client.html in headless Chromium
// (Playwright) against the sparrow-hub binary: /connect, then a
// WebTransport session pinned with serverCertificateHashes and a
// WebSocket session, each with Hello / Welcome / Ready and one unary call
// to the echo node, which dials in. Set SPARROW_BROWSER=1 to run it
// (e2e/browser/run.sh does).
func TestBrowser(t *testing.T) {
	if os.Getenv("SPARROW_BROWSER") == "" {
		t.Skip("set SPARROW_BROWSER=1 to run the browser test")
	}
	// The page is served on the hub's TCP origin; WebTransport runs on its
	// UDP port, a different origin, so allow every Origin here.
	p, _, _ := webHub(t, map[string]any{"allowedOrigins": []string{"*"}})
	script, _ := filepath.Abs("../../../e2e/browser/run.cjs")
	cmd := exec.Command("node", script, p.addrs.Web, "alice-token")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("node: %v\n%s\n%s", err, out.String(), errb.String())
		}
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("browser run timed out\n%s", errb.String())
	}
	var res struct {
		Browser               string `json:"browser"`
		Error                 string `json:"error"`
		WebTransportAvailable bool   `json:"webTransportAvailable"`
		Console               []string
		WebTransport          struct {
			OK     bool     `json:"ok"`
			Output any      `json:"output"`
			Error  string   `json:"error"`
			Log    []string `json:"log"`
		} `json:"webtransport"`
		WebSocket struct {
			OK     bool     `json:"ok"`
			Output any      `json:"output"`
			Error  string   `json:"error"`
			Log    []string `json:"log"`
		} `json:"websocket"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("result %q: %v\n%s", out.String(), err, errb.String())
	}
	t.Logf("Chromium %s: %s", res.Browser, out.String())
	if res.Error != "" {
		t.Fatalf("browser: %s", res.Error)
	}
	if !res.WebSocket.OK || res.WebSocket.Output != "hello from the browser" {
		t.Errorf("WebSocket session: %+v\nhub log:\n%s", res.WebSocket, p.logText())
	}
	if !res.WebTransport.OK || res.WebTransport.Output != "hello from the browser" {
		t.Errorf("WebTransport session (available %v): %+v\nhub log:\n%s", res.WebTransportAvailable, res.WebTransport, p.logText())
	}
}
