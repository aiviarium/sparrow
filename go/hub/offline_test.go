package hub

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
)

// TestNeverSeenNodeHasNoFacets: a configured node that has never connected
// lists no facets (10.7); once an outside system starts it and it dials in,
// its facets appear.
func TestNeverSeenNodeHasNoFacets(t *testing.T) {
	f := newFixture(t, nil)
	c, _ := f.adminClient("websocket")
	ctx := tctx(t)
	nc := f.echo("echo")
	snap, _ := c.Get(ctx)
	// Committed directly, so the echo process is not started yet.
	if _, err := c.Commit(ctx, snap.Revision, &admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": nc}, Extensions: policy(grant("user:alice", "echo", "use"))}, 0); err != nil {
		t.Fatal(err)
	}
	cli := f.client("webtransport", aliceToken)
	time.Sleep(200 * time.Millisecond)
	if cli.Session().PeerFacet("echo") != nil || len(f.h.Stats().Nodes["echo"].Listed) != 0 {
		t.Fatal("a node never seen lists facets")
	}
	f.startEchoes()
	waitFacet(t, cli, "echo")
	if v, err := cli.Call(ctx, "echo", "echo", "first"); err != nil || v != "first" {
		t.Fatalf("%v %v", v, err)
	}
}

// TestOfflineEchoProcesses: a node process that goes away (a dial-in node
// killed, a dialed node stopped) is offline; a call made meanwhile waits,
// and the node coming back within the connect timeout serves it: the
// dial-in node by dialing in again, the dialed node because the hub keeps
// redialing it.
func TestOfflineEchoProcesses(t *testing.T) {
	f := newFixture(t, nil)
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{
		"echo":        f.echo("echo"),
		"echo-dialed": f.dialedEcho("echo-dialed"),
	}, Extensions: policy(grant("user:alice", "*", "use"))})
	cli := f.client("websocket", aliceToken)
	for _, c := range []struct {
		id    string
		crash bool
	}{{"echo", true}, {"echo-dialed", false}} {
		t.Run(c.id, func(t *testing.T) {
			waitNode(t, f.h, c.id, true)
			fid := waitFacet(t, cli, c.id)
			// A dialed node that is killed is noticed only by the QUIC idle
			// timeout; stopped, it ends its session with GoAway.
			f.stopEcho(c.id, c.crash)
			waitNode(t, f.h, c.id, false)
			if fc := cli.Session().PeerFacet(c.id); fc == nil || fc.ID != fid {
				t.Fatal("facet not listed while offline")
			}
			done := make(chan error, 1)
			go func() {
				v, err := cli.Call(tctx(t), c.id, "echo", "waited")
				if err == nil && v != "waited" {
					err = fmt.Errorf("reply %v", v)
				}
				done <- err
			}()
			time.Sleep(500 * time.Millisecond)
			f.restartEcho(c.id, false)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if st := f.h.Admin().NodeStates()[c.id]; st.State != admin.Connected {
				t.Fatalf("state %v", st.State)
			}
		})
	}
	// A call to a node that stays away fails with unavailable after the
	// connect timeout (3 s here).
	f.stopEcho("echo", false)
	waitNode(t, f.h, "echo", false)
	start := time.Now()
	_, err := cli.Call(tctx(t), "echo", "echo", "nobody")
	mustCode(t, err, status.Unavailable)
	if d := time.Since(start); d < 2500*time.Millisecond || d > 10*time.Second {
		t.Fatalf("failed after %v, want about the 3 s connect timeout", d)
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
	// A call waits; the node connecting within the connect timeout serves it.
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

// TestDialedNodeRedials: a dialed node that is not there yet is offline
// with the reason; once it listens, the hub's redialing (with backoff)
// reaches it without any call or commit.
func TestDialedNodeRedials(t *testing.T) {
	f := newFixture(t, nil)
	nc := f.dialedEcho("late")
	f.stopEcho("late", false)
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"late": nc}})
	testutil.Eventually(t, 15*time.Second, func() bool {
		st := f.h.Admin().NodeStates()["late"]
		return st.State == admin.Offline && st.Message != nil && *st.Message != "" && !strings.HasPrefix(*st.Message, "dialing")
	}, "no dial failure reported: %+v", f.h.Admin().NodeStates()["late"])
	f.restartEcho("late", false)
	waitNode(t, f.h, "late", true)
}
