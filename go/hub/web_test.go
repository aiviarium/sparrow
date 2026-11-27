package hub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/web"
)

func webMap(kv ...any) []byte {
	b := cbor.AppendMapHead(nil, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		b = cbor.AppendRaw(cbor.AppendText(b, kv[i].(string)), kv[i+1].([]byte))
	}
	return b
}

// TestWebFacet: facet 1 sparrow.web for everyone, the ref.web annotations
// at the top level of every schema, moduleRejected reported (9.4), and a
// node's facet that ships modules outside its scope refused.
func TestWebFacet(t *testing.T) {
	var mu sync.Mutex
	var got [][4]string
	f := newFixture(t, func(o *Options) {
		o.Web = true
		o.OnModuleRejected = func(p, id, v, r string) {
			mu.Lock()
			got = append(got, [4]string{p, id, v, r})
			mu.Unlock()
		}
	})
	f.secret("acme-1", "cred-one")
	ext := policy(grant("user:bob", "acme", "use"))
	ext[WebExtension] = webMap(web.AnnApply, cbor.AppendText(nil, "reload"), "web.layout", cbor.AppendText(nil, "wide"))
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"acme": dialInConfig("acme-1")}, Extensions: ext})
	cli := f.client("websocket", bobToken)
	fc := cli.Session().PeerFacet(schema.WebFacetName)
	if fc == nil || fc.ID != schema.WebFacetID {
		t.Fatal("no facet 1 sparrow.web")
	}
	anns := cli.Session().PeerSchema().Schema().Annotations
	if s, _ := cbor.NewDecoder(anns[web.AnnApply]).Text(); s != "reload" {
		t.Fatalf("top-level annotations %v", anns)
	}
	if err := cli.Notify(tctx(t), schema.WebFacetName, "moduleRejected", []any{"acme.charts.ui", "1.0.0", "key_revoked"}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 1
	}, "moduleRejected not reported")
	if got[0] != [4]string{"user:bob", "acme.charts.ui", "1.0.0", "key_revoked"} {
		t.Fatalf("got %v", got)
	}
	if f.h.Stats().ModulesRejected != 1 || cli.Session().Err() != nil {
		t.Fatal("stats or session")
	}
	// A facet that ships a module of another facet is refused (9.4).
	entry := cbor.AppendMapHead(nil, 0) // malformed is refused too
	b := nd.NewFacet("acme", "1.0.0").Annotation(web.AnnModules, cbor.AppendRaw(cbor.AppendArrayHead(nil, 1), entry))
	b.Service("A").Method("ping", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) { return "pong", nil })
	_, err := dialInNode(t, f, "websocket", "acme", "cred-one", b.MustBuild())
	mustCode(t, err, status.InvalidArgument)
	// ref.web with invalid contents is a validation problem.
	c, _ := f.adminClient("websocket")
	snap, _ := c.Get(tctx(t))
	bad := &admin.Config{Nodes: map[string]*admin.NodeConfig{}, Extensions: map[string][]byte{WebExtension: webMap(web.AnnApply, cbor.AppendText(nil, "now"))}}
	if ps, err := c.Validate(tctx(t), snap.Revision, bad); err != nil || len(ps) != 1 || ps[0].Path[1] != WebExtension {
		t.Fatalf("problems %v %v", ps, err)
	}
}

// TestWebExtensionNeedsWeb: without the Web Profile, ref.web is not
// supported.
func TestWebExtensionNeedsWeb(t *testing.T) {
	f := newFixture(t, nil)
	c, _ := f.adminClient("websocket")
	snap, _ := c.Get(tctx(t))
	cfg := &admin.Config{Nodes: map[string]*admin.NodeConfig{}, Extensions: map[string][]byte{WebExtension: webMap(web.AnnApply, cbor.AppendText(nil, "hot"))}}
	if ps, err := c.Validate(tctx(t), snap.Revision, cfg); err != nil || len(ps) != 1 {
		t.Fatalf("problems %v %v", ps, err)
	}
}
