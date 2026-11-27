package hub

import (
	"bytes"
	"context"
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
	"github.com/aiviarium/sparrow/go/wire"
)

// recorder is a raw facet that records what reaches the node.
type recorder struct {
	mu       sync.Mutex
	inputs   [][]byte
	md       []wire.Metadata
	reply    []byte
	contexts [][]byte
}

func (r *recorder) facet(name string) *nd.Facet {
	b := nd.NewFacet(name, "1.0.0")
	pt := b.Struct("Point", nd.Field("x", nd.Int), nd.Field("label", nd.String), nd.OptionalField("tags", nd.List(nd.String)))
	svc := b.Service("Raw")
	svc.RawMethod("put", pt, nd.Bytes, session.HandlerFunc(func(ctx context.Context, c *session.ServerCall) (any, error) {
		r.mu.Lock()
		r.inputs = append(r.inputs, append([]byte{}, c.Request().Input...))
		r.md = append(r.md, c.Metadata().Clone())
		reply := r.reply
		r.mu.Unlock()
		return nil, c.RespondRaw(ctx, reply)
	}))
	svc.Method("ping", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) { return "pong", nil })
	return b.MustBuild()
}

func dialInNode(t *testing.T, f *fixture, binding, id, cred string, facets ...*nd.Facet) (*nd.Node, error) {
	t.Helper()
	n := nd.New(nd.Options{Auth: linkAuth(cred), Logger: testLogger(t)}) // the hub checks facet names
	ctx := tctx(t)
	for _, fc := range facets {
		if _, err := n.Add(ctx, fc); err != nil {
			t.Fatal(err)
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := n.Dial(dctx, f.url(binding), nd.DialOptions{CertHashes: [][]byte{f.certHash}})
	if err == nil {
		f.onCleanup(n.Close)
	}
	return n, err
}

func dialInConfig(cred string) *admin.NodeConfig { return &admin.NodeConfig{Link: admin.DialIn(cred)} }

func TestDialInPayloadUnchanged(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")},
		Extensions: policy(grant("group:eng", "acme.*", "use"), grant("group:eng", "acme", "use"))})
	for _, b := range transports {
		t.Run(b, func(t *testing.T) {
			rec := &recorder{reply: []byte{0x44, 0xde, 0xad, 0xbe, 0xef}}
			n, err := dialInNode(t, f, b, "acme", "cred-one", rec.facet("acme"))
			if err != nil {
				t.Fatal(err)
			}
			waitNode(t, f.h, "acme", true)
			cli := f.client(b, aliceToken)
			fid := waitFacet(t, cli, "acme")
			m, err := nd.MethodByName(cli.Session().PeerFacet("acme"), "put")
			if err != nil {
				t.Fatal(err)
			}
			// A non-preferred but valid encoding (a two-byte length for the
			// text): the hub must not re-encode it.
			input := []byte{0x83, 0x18, 0x2a, 0x78, 0x02, 'h', 'i', 0x81, 0x61, 'z'}
			md := wire.Metadata{}
			md.SetPrincipal("user:mallory")
			md.SetContext([]byte{1, 2, 3})
			md.SetText(200, "x-app")
			cc, err := cli.Session().OpenRaw(tctx(t), session.RawRequest{FacetID: fid, MethodID: m.ID, Metadata: md, Input: input}, nil)
			if err != nil {
				t.Fatal(err)
			}
			out, err := cc.ResponseRaw(tctx(t))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, rec.reply) {
				t.Fatalf("response %x, want %x", out, rec.reply)
			}
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if len(rec.inputs) != 1 || !bytes.Equal(rec.inputs[0], input) {
				t.Fatalf("node got %x, client sent %x", rec.inputs, input)
			}
			got := rec.md[0]
			if p, _, _ := got.Principal(); p != "user:alice" {
				t.Fatalf("principal %q: the hub must replace what the caller sent", p)
			}
			if c, _, _ := got.Context(); len(c) < 16 || bytes.Equal(c, []byte{1, 2, 3}) {
				t.Fatalf("context %x", c)
			}
			if v, ok := got[wire.SigilKey(200)]; !ok || !bytes.Equal(v, cbor.AppendText(nil, "x-app")) {
				t.Fatalf("application metadata lost: %v", got)
			}
			if _, ok, _ := got.Credit(); !ok {
				t.Fatal("no credit key")
			}
			n.Close()
			waitNode(t, f.h, "acme", false)
		})
	}
}

func TestDialInCredentials(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	rev := f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")},
		Extensions: policy(grant("user:alice", "acme", "use"))})
	rec := &recorder{reply: cbor.AppendBytes(nil, nil)}
	// A wrong credential is refused.
	_, err := dialInNode(t, f, "websocket", "acme", "wrong", rec.facet("acme"))
	mustCode(t, err, status.Unauthenticated)
	// The right one connects.
	n1, err := dialInNode(t, f, "webtransport", "acme", "cred-one", rec.facet("acme"))
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	cli := f.client("websocket", aliceToken)
	waitFacet(t, cli, "acme")
	if v, err := cli.Call(tctx(t), "acme", "ping", nil); err != nil || v != "pong" {
		t.Fatalf("%v %v", v, err)
	}
	// Rotation: a new secret and a commit that refers to it. The old
	// session is closed with unauthenticated at once.
	f.secret("acme-2", "cred-two")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-2")},
		Extensions: policy(grant("user:alice", "acme", "use"))})
	s1 := n1.Session()
	if s1 != nil {
		select {
		case <-s1.Done():
		case <-time.After(10 * time.Second):
			t.Fatal("old session not closed")
		}
		if g := s1.GoAwayReceived(); g == nil || status.Code(g.Status) != status.Unauthenticated {
			t.Fatalf("old session got %v", g)
		}
	}
	// The old credential no longer works; the new one does.
	_, err = dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acme"))
	mustCode(t, err, status.Unauthenticated)
	if _, err := dialInNode(t, f, "websocket", "acme", "cred-two", rec.facet("acme")); err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	if v, err := cli.Call(tctx(t), "acme", "ping", nil); err != nil || v != "pong" {
		t.Fatalf("after rotation: %v %v", v, err)
	}
	_ = rev
}

func TestOneLinkDirection(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}})
	rec := &recorder{}
	n, err := dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acme"))
	if err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	// Now the hub dials node acme itself; only a node configured to dial
	// in has a dial-in credential, so the old one is unknown (10.2).
	f.secret("acme-dial", "hub-to-acme")
	dialed := dialConfig("https://127.0.0.1:9/sparrow/node", make([]byte, 32), "acme-dial")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialed}})
	if s := n.Session(); s != nil {
		<-s.Done()
	}
	_, err = dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acme"))
	mustCode(t, err, status.Unauthenticated)
	// A link of a kind this hub does not know is a validation problem.
	c, _ := f.adminClient("websocket")
	snap, _ := c.Get(tctx(t))
	ps, err := c.Validate(tctx(t), snap.Revision, &admin.Config{Nodes: map[string]*admin.NodeConfig{"x": {Link: admin.Link{UnknownTag: 7, Unknown: cbor.Null}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || strings.Join(ps[0].Path, "/") != "nodes/x/link" {
		t.Fatalf("problems %v", ps)
	}
}

func TestNamingRules(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	f.secret("acme-1", "cred-one")
	c, _ := f.adminClient("websocket")
	ctx := tctx(t)
	snap, _ := c.Get(ctx)
	// Reserved node IDs and bad grammar.
	_, err := c.Commit(ctx, snap.Revision, &admin.Config{Nodes: map[string]*admin.NodeConfig{
		"sparrow":     dialInConfig("acme-1"),
		"sparrow.x":   dialConfig("https://h.example/n", make([]byte, 32), "missing"),
		"Bad_Name":    dialConfig("https://h.example/n", make([]byte, 32), "missing"),
		"acme":        dialInConfig("acme-1"),
		"acme.charts": dialInConfig("missing"),
	}}, 0)
	mustCode(t, err, status.FailedPrecondition)
	ps := admin.ProblemsOf(err)
	want := map[string]bool{"Bad_Name": true, "sparrow": true, "sparrow.x": true, "acme.charts": true}
	for _, p := range ps {
		delete(want, p.Path[1])
	}
	if len(want) != 0 {
		t.Fatalf("missing problems for %v in %v", want, ps)
	}
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}})
	// A node whose facet is not named after it is closed with
	// invalid_argument.
	rec := &recorder{}
	_, err = dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("acmex"))
	mustCode(t, err, status.InvalidArgument)
	_, err = dialInNode(t, f, "websocket", "acme", "cred-one", rec.facet("other.acme"))
	mustCode(t, err, status.InvalidArgument)
	// acme.sub is fine.
	if _, err := dialInNode(t, f, "webtransport", "acme", "cred-one", rec.facet("acme.sub")); err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	// A node cannot publish a facet named after another node later either.
	testutil.Eventually(t, 5*time.Second, func() bool { return len(f.h.Stats().Nodes["acme"].Listed) == 1 }, "listed")
}
