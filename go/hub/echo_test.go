package hub

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
)

// exerciseEcho makes every call shape of the echo node through the hub.
func exerciseEcho(t *testing.T, cli *nd.Node, facet, principal string) {
	t.Helper()
	ctx := tctx(t)
	if v, err := cli.Call(ctx, facet, "echo", "hello"); err != nil || v != "hello" {
		t.Fatalf("echo: %v %v", v, err)
	}
	if v, err := cli.Call(ctx, facet, "reverse", "sparrow"); err != nil || v != "worraps" {
		t.Fatalf("reverse: %v %v", v, err)
	}
	// Server stream.
	cs, err := cli.Open(ctx, facet, "count", uint64(50), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []uint64
	for {
		v, err := cs.Recv(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		got = append(got, v.(uint64))
	}
	if len(got) != 50 || got[49] != 50 {
		t.Fatalf("count: %v", got)
	}
	// Client stream.
	ss, err := cli.Open(ctx, facet, "sum", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 100; i++ {
		if err := ss.Send(ctx, i); err != nil {
			t.Fatal(err)
		}
	}
	_ = ss.CloseSend(nil)
	if v, err := ss.Response(ctx); err != nil || v != uint64(5050) {
		t.Fatalf("sum: %v %v", v, err)
	}
	// Bidi stream.
	ch, err := cli.Open(ctx, facet, "chat", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"a", "bb", "ccc"} {
		if err := ch.Send(ctx, w); err != nil {
			t.Fatal(err)
		}
		v, err := ch.Recv(ctx)
		if err != nil || v != w {
			t.Fatalf("chat: %v %v", v, err)
		}
	}
	_ = ch.CloseSend(nil)
	if _, err := ch.Recv(ctx); err != io.EOF {
		t.Fatalf("chat end: %v", err)
	}
	// Upload: more than any credit window, so credit flows on both hops.
	up, err := cli.Open(ctx, facet, "upload", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("0123456789abcdef"), 300<<10/16)
	w := up.Writer(ctx, 0)
	if err := w.WriteAll(data); err != nil {
		t.Fatal(err)
	}
	if v, err := up.Response(ctx); err != nil || v != uint64(len(data)) {
		t.Fatalf("upload: %v %v", v, err)
	}
	// Download.
	dl, err := cli.Open(ctx, facet, "download", uint64(500<<10), nil)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(dl.Reader(0))
	if err != nil || len(all) != 500<<10 || !strings.HasPrefix(string(all), "sparrow!") {
		t.Fatalf("download: %d %v", len(all), err)
	}
	if v, err := cli.Call(ctx, facet, "whoami", nil); err != nil || v != principal {
		t.Fatalf("whoami: %v %v", v, err)
	}
	// An application error passes through with its facet's sigil.
	_, err = cli.Call(ctx, facet, "fail", "boom")
	var e *session.Error
	if !asErr(err, &e) || e.Code < 64 || e.Message != "boom" {
		t.Fatalf("fail: %v", err)
	}
	if err := cli.Notify(ctx, facet, "log", "a notification"); err != nil {
		t.Fatal(err)
	}
}

func asErr(err error, e **session.Error) bool {
	x, ok := err.(*session.Error)
	if ok {
		*e = x
	}
	return ok
}

// TestEchoAllShapes: every call shape through the hub to examples/echo-node
// running as its own process, linked each way a node can be (10.2): dialing
// in over WebSocket, dialing in over WebTransport with the hub's key pinned,
// and dialed by the hub over WebTransport at its URL and SPKI pin.
func TestEchoAllShapes(t *testing.T) {
	f := newFixture(t, nil)
	ids := []string{"echo", "echo-wt", "echo-dialed"}
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{
		"echo":        f.echo("echo"),
		"echo-wt":     f.echoWT("echo-wt"),
		"echo-dialed": f.dialedEcho("echo-dialed"),
	}, Extensions: policy(grant("user:alice", "echo", "use"), grant("user:alice", "echo-wt", "use"), grant("user:alice", "echo-dialed", "use"))})
	for _, id := range ids {
		waitNode(t, f.h, id, true)
	}
	for _, b := range transports {
		for _, id := range ids {
			t.Run(b+"/"+id, func(t *testing.T) {
				cli := f.client(b, aliceToken)
				waitFacet(t, cli, id)
				exerciseEcho(t, cli, id, "user:alice")
			})
		}
	}
	// bob has no grant: the facet is not in his schema, and calling its ID
	// anyway is refused.
	bob := f.client("websocket", bobToken)
	if bob.Session().PeerFacet("echo") != nil {
		t.Fatal("bob sees echo")
	}
	alice := f.client("websocket", aliceToken)
	id := waitFacet(t, alice, "echo")
	cc, err := bob.Session().OpenRaw(tctx(t), session.RawRequest{FacetID: id, MethodID: 0, Input: []byte{0x61, 0x78}}, nil)
	if err == nil {
		_, err = cc.ResponseRaw(tctx(t))
	}
	if c := session.Code(err); c != status.PermissionDenied && c != status.Unimplemented {
		t.Fatalf("bob called echo: %v", err)
	}
}
