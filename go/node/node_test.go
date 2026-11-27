package node

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/transport/websocket"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func facetID(t *testing.T, s *session.Session, name string) uint64 {
	t.Helper()
	f := s.PeerFacet(name)
	if f == nil {
		t.Fatalf("peer has no facet %q", name)
	}
	return f.ID
}

func methodID(t *testing.T, s *session.Session, facet, method string) (uint64, uint64) {
	t.Helper()
	f := s.PeerFacet(facet)
	if f == nil {
		t.Fatalf("no facet %q", facet)
	}
	m, err := MethodByName(f, method)
	if err != nil {
		t.Fatal(err)
	}
	return f.ID, m.ID
}

func greeter(t *testing.T, name, version string, extra bool) *Facet {
	b := NewFacet(name, version)
	person := b.Struct("Person", Field("name", String), OptionalField("age", Uint))
	color, values := b.Enum("Color", "red", "green")
	_ = values
	svc := b.Service("Greeter")
	svc.Method("greet", person, String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		st := in.(value.Struct)
		return "hello " + st[0].(string), nil
	})
	svc.Method("favorite", Unit, color, func(ctx context.Context, c *session.ServerCall) (any, error) {
		return uint64(64), nil
	})
	if extra {
		svc.Method("bye", String, String, func(ctx context.Context, c *session.ServerCall) (any, error) {
			in, _ := c.Input()
			return "bye " + in.(string), nil
		})
	}
	f, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestNodePublish: a node publishes facets while connected; the hub side
// sees each change after its SchemaUpdate.
func TestNodePublish(t *testing.T) {
	cc, sc := mem.Pipe(mem.Options{})
	ctx := tctx(t)
	hubFacet := NewFacet("sparrow.hub", "1.0.0")
	hubFacet.Service("Hub").Method("time", Unit, Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		return uint64(42), nil
	})
	hf := hubFacet.MustBuild()
	hf.Def.ID = 16
	mux := session.NewMux()
	for id, h := range hf.handlers {
		mux.Handle(16, id, h)
	}
	hubCh := make(chan *session.Session, 1)
	go func() {
		s, err := session.NewServer(ctx, sc, session.Config{Schema: &schema.Schema{Format: 2, Name: "hub", Version: "1",
			Facets: []schema.Facet{hf.Def}, Annotations: schema.Annotations{}}, Handler: mux})
		if err != nil {
			t.Error(err)
		}
		hubCh <- s
	}()
	n := New(Options{ID: "greeter"})
	if _, err := n.Add(ctx, greeter(t, "greeter", "1.0.0", false)); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Add(ctx, greeter(t, "other", "1.0.0", false)); err == nil {
		t.Fatal("a facet not named after the node was accepted")
	}
	if err := n.Connect(ctx, cc, true); err != nil {
		t.Fatal(err)
	}
	hub := <-hubCh
	// The node calls the hub by name.
	if v, err := n.Call(ctx, "sparrow.hub", "time", nil); err != nil || v != uint64(42) {
		t.Fatalf("%v %v", v, err)
	}
	f, m := methodID(t, hub, "greeter", "greet")
	if v, err := hub.Unary(ctx, f, m, value.Struct{0: "ann"}, nil); err != nil || v != "hello ann" {
		t.Fatalf("%v %v", v, err)
	}
	// Publish a compatible replacement and a second facet at runtime.
	if _, err := n.Add(ctx, greeter(t, "greeter", "1.1.0", true)); err != nil {
		t.Fatal(err)
	}
	id2, err := n.Add(ctx, greeter(t, "greeter.extra", "1.0.0", false))
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := n.FacetID("greeter"); id != f {
		t.Fatal("replacing a facet changed its ID")
	}
	_, m = methodID(t, hub, "greeter", "bye")
	if v, err := hub.Unary(ctx, f, m, "bob", nil); err != nil || v != "bye bob" {
		t.Fatalf("%v %v", v, err)
	}
	if facetID(t, hub, "greeter.extra") != id2 {
		t.Fatal("facet ID")
	}
	// An incompatible replacement is refused and nothing changes.
	bad := greeter(t, "greeter", "2.0.0", true)
	if _, err := n.Add(ctx, bad); err == nil {
		t.Fatal("incompatible replacement accepted")
	}
	if err := n.Remove(ctx, "greeter.extra"); err != nil {
		t.Fatal(err)
	}
	if hub.PeerFacet("greeter.extra") != nil {
		t.Fatal("removed facet still listed")
	}
	if st := hub.Stats(); st.PeerEpoch != 3 {
		t.Fatalf("peer epoch %d", st.PeerEpoch)
	}
}

// TestNodeServe: a hub dials a node (the node is the Sparrow server and
// publishes its facets in Welcome) over WebSocket.
func TestNodeServe(t *testing.T) {
	n := New(Options{ID: "greeter"})
	ctx := tctx(t)
	if _, err := n.Add(ctx, greeter(t, "greeter", "1.0.0", false)); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		served <- n.Serve(context.Background(), c, func(a *wire.Auth) error {
			if a == nil || a.Scheme != "link" {
				return &session.Error{Code: status.Unauthenticated, Message: "link credential required"}
			}
			return nil
		})
	}))
	defer srv.Close()
	conn, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := session.NewClient(ctx, conn, session.Config{Auth: &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, "secret")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	f, m := methodID(t, hub, "greeter", "greet")
	if v, err := hub.Unary(ctx, f, m, value.Struct{0: "zed"}, nil); err != nil || v != "hello zed" {
		t.Fatalf("%v %v", v, err)
	}
	// Principal metadata is honoured on the authenticated hub link.
	hub.Close(status.OK, "done")
	if err := n.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBuilderFlags(t *testing.T) {
	b := NewFacet("x", "1.0.0")
	blob := b.Struct("Blob", Field("data", ByteStream()))
	svc := b.Service("S")
	up := svc.Method("up", blob, Unit, nil)
	down := svc.Method("down", Unit, Stream(Uint), nil)
	plain := svc.Method("plain", String, String, nil, MethodID(40), Idempotent())
	note := svc.Notification("note", String, nil)
	f := b.MustBuild()
	flags := map[uint64]uint64{}
	for _, m := range f.Def.Services[0].Methods {
		flags[m.ID] = m.Flags
	}
	if flags[up] != schema.MethodInputEnd || flags[down] != schema.MethodOutputEnd ||
		flags[plain] != schema.MethodIdempotent || flags[note] != schema.MethodNotification || plain != 40 {
		t.Fatalf("flags %v", flags)
	}
	if _, err := NewFacet("Bad Name", "1.0.0").Build(); err == nil {
		t.Fatal("bad facet name accepted")
	}
}

// TestRunDialReconnects: after the hub drains a session, the node dials
// again (after retry_after_ms) and republishes its facets.
func TestRunDialReconnects(t *testing.T) {
	sessions := make(chan *session.Session, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		s, err := session.NewServer(context.Background(), c, session.Config{MaxClientSchemaSize: -1})
		if err == nil {
			sessions <- s
		}
	}))
	defer srv.Close()
	n := New(Options{ID: "greeter"})
	ctx, cancel := context.WithCancel(tctx(t))
	defer cancel()
	if _, err := n.Add(ctx, greeter(t, "greeter", "1.0.0", false)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- n.RunDial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), DialOptions{}) }()
	first := <-sessions
	if first.PeerFacet("greeter") == nil {
		t.Fatal("no facet")
	}
	retry := uint64(10)
	first.GoAway(status.GoingAway, "redeploy", &retry)
	select {
	case second := <-sessions:
		f, m := methodID(t, second, "greeter", "greet")
		if v, err := second.Unary(ctx, f, m, value.Struct{0: "again"}, nil); err != nil || v != "hello again" {
			t.Fatalf("%v %v", v, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no reconnect")
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatal(err)
	}
}
