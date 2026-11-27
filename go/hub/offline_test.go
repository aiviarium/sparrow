package hub

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport/pipe"
)

// echoFacetDoc runs the echo node once and returns its facet document.
func echoFacetDoc(t *testing.T, id string) []byte {
	t.Helper()
	cmd := exec.Command(echoBin, "-id", id)
	conn, err := pipe.Spawn(cmd)
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.NewServer(tctx(t), conn, session.Config{MaxClientSchemaSize: -1})
	if err != nil {
		t.Fatal(err)
	}
	f := s.PeerSchema().Schema().Facets[0]
	s.Close(status.OK, "done")
	_ = cmd.Wait()
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLazyStartFromConfiguredFacets(t *testing.T) {
	f := newFixture(t, nil)
	c, _ := f.adminClient("websocket")
	key, err := c.PutFacet(tctx(t), echoFacetDoc(t, "echo"))
	if err != nil {
		t.Fatal(err)
	}
	nc := spawnEcho("echo")
	nc.Facets = [][]byte{key}
	nc.Extensions = map[string][]byte{LazyExtension: {0xf5}}
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": nc}, Extensions: policy(grant("user:alice", "echo", "use"))})
	cli := f.client("webtransport", aliceToken)
	// Listed from the document before the node was ever seen (10.7).
	waitFacet(t, cli, "echo")
	time.Sleep(200 * time.Millisecond)
	if f.h.Stats().Nodes["echo"].Connected {
		t.Fatal("a lazy node started before its first call")
	}
	// The first call starts it and waits for it.
	if v, err := cli.Call(tctx(t), "echo", "echo", "first"); err != nil || v != "first" {
		t.Fatalf("%v %v", v, err)
	}
	if !f.h.Stats().Nodes["echo"].Connected {
		t.Fatal("not connected")
	}
}

func TestOfflineDialInNode(t *testing.T) {
	f := acmeHub(t)
	n, err := dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "1.0.0", false, false))
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	cli := f.client("webtransport", aliceToken)
	id := waitFacet(t, cli, "acme")
	n.Close()
	waitNode(t, f.h, "acme", false)
	// The facets stay listed while the node is offline.
	if fc := cli.Session().PeerFacet("acme"); fc == nil || fc.ID != id {
		t.Fatal("facet not listed while offline")
	}
	// A call waits; the node connecting within the start timeout serves it.
	done := make(chan error, 1)
	go func() {
		v, err := cli.Call(tctx(t), "acme", "ping", nil)
		if err == nil && v != "pong 1.0.0" {
			err = &session.Error{Code: status.Internal, Message: "wrong reply"}
		}
		done <- err
	}()
	time.Sleep(500 * time.Millisecond)
	if _, err := dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "1.0.0", false, false)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCrashingNodeFails(t *testing.T) {
	f := newFixture(t, nil)
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{
		"broken": {Start: &admin.Start{Spawn: &admin.Spawn{Command: []string{"/bin/sh", "-c", "exit 3"}}}},
	}})
	testutil.Eventually(t, 30*time.Second, func() bool {
		return f.h.Admin().NodeStates()["broken"].State == admin.Failed
	}, "node not marked failed: %+v", f.h.Admin().NodeStates()["broken"])
	msg := f.h.Admin().NodeStates()["broken"].Message
	if msg == nil || !strings.Contains(*msg, "5 crashes") {
		t.Fatalf("message %v", msg)
	}
}

// TestSpawnRestartOnConfigChange: changing how a node starts stops the old
// process before the new one starts (10.7), and env values from secrets
// reach the process.
func TestSpawnRestartOnConfigChange(t *testing.T) {
	f := newFixture(t, nil)
	f.secret("motd", "from-a-secret")
	nc := spawnEcho("echo")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": nc}, Extensions: policy(grant("user:alice", "echo", "use"))})
	waitNode(t, f.h, "echo", true)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "echo")
	var first *session.Session
	for _, ss := range f.h.Sessions()["node:echo"] {
		first = ss
	}
	out := t.TempDir() + "/env"
	nc2 := &admin.NodeConfig{Start: &admin.Start{Spawn: &admin.Spawn{
		Command: []string{"/bin/sh", "-c", `printf '%s %s' "$MOTD" "$PLAIN" > ` + out + `; exec ` + echoBin + ` -id echo`},
		Env:     map[string]admin.EnvValue{"MOTD": {Secret: true, Value: "motd"}, "PLAIN": {Value: "x"}},
	}}}
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": nc2}, Extensions: policy(grant("user:alice", "echo", "use"))})
	select {
	case <-first.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("old process not stopped")
	}
	waitNode(t, f.h, "echo", true)
	if n := len(f.h.Sessions()["node:echo"]); n != 1 {
		t.Fatalf("%d node sessions: the node runs twice", n)
	}
	if v, err := cli.Call(tctx(t), "echo", "echo", "again"); err != nil || v != "again" {
		t.Fatalf("%v %v", v, err)
	}
	if b, err := os.ReadFile(out); err != nil || string(b) != "from-a-secret x" {
		t.Fatalf("environment %q %v", b, err)
	}
	_ = context.Background
	_ = schema.Format
}
