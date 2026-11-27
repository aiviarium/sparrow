package hub

import (
	"bytes"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/schema"
)

func TestGrantPolicy(t *testing.T) {
	gs, err := ParseGrants(EncodeGrants([]Grant{
		grant("user:alice", "acme", "view"),
		grant("group:eng", "acme", "use"),
		grant("user:root", "*", "manage"),
		grant("*", "public.*", "use"),
		grant("peer:hub-b/user:bob", "hub-b/echo", "use"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	p := &hubPolicy{inner: &GrantPolicy{Grants: gs}, bootstrap: map[string]bool{"user:admin": true}}
	alice := Actor{Principal: "user:alice"}
	eng := Actor{Principal: "user:carol", Groups: []string{"group:eng"}}
	acme := FacetRef{ID: 20, Name: "acme", Node: "acme"}
	use := &schema.Method{Annotations: schema.Annotations{}}
	manage := &schema.Method{Annotations: schema.Annotations{adminiface.LevelAnnotation: cbor.AppendText(nil, "manage")}}
	cases := []struct {
		a              Actor
		f              FacetRef
		m              *schema.Method
		visible, allow bool
	}{
		{alice, acme, use, true, false},
		{eng, acme, use, true, true},
		{eng, acme, manage, true, false},
		{Actor{Principal: "user:root"}, acme, manage, true, true},
		{Actor{Principal: "user:x"}, FacetRef{Name: "public.a", Node: "public"}, use, true, true},
		{Actor{Principal: "user:x"}, FacetRef{Name: "public", Node: "public"}, use, false, false},
		{Actor{Principal: "user:x"}, acme, use, false, false},
		{Actor{Principal: "peer:hub-b/user:bob"}, FacetRef{Name: "hub-b/echo", Node: "hub-b", Imported: true}, use, true, true},
		// Fixed rules: the bootstrap administrator and sparrow.web.
		{Actor{Principal: "user:admin"}, FacetRef{Name: adminiface.Name}, manage, true, true},
		{Actor{Principal: "user:admin"}, acme, use, false, false},
		{alice, FacetRef{ID: 1, Name: schema.WebFacetName}, use, true, true},
		{alice, FacetRef{Name: adminiface.Name}, manage, false, false},
	}
	for i, c := range cases {
		if v := p.Visible(c.a, c.f); v != c.visible {
			t.Errorf("case %d: visible %v", i, v)
		}
		if v := p.Allowed(c.a, c.f, c.m); v != c.allow {
			t.Errorf("case %d: allowed %v", i, v)
		}
	}
	for _, bad := range [][]byte{{0x01}, EncodeGrants([]Grant{{Principal: "alice", Facet: "x", Level: LevelUse}}),
		EncodeGrants([]Grant{{Principal: "user:a", Facet: "X Y", Level: LevelUse}}), cbor.AppendArrayHead(nil, 1)} {
		if _, err := ParseGrants(bad); err == nil {
			t.Errorf("%x parsed", bad)
		}
	}
}

func TestFacetTablePersistence(t *testing.T) {
	store, _ := admin.OpenStore(t.TempDir())
	tab, err := newTable(store)
	if err != nil {
		t.Fatal(err)
	}
	k1 := facetKey{"acme", "acme", "1"}
	k2 := facetKey{"acme", "acme", "2"}
	k3 := facetKey{"other", "other", "1"}
	a, b, c := tab.allocate(k1), tab.allocate(k2), tab.allocate(k3)
	if a != 16 || b != 17 || c != 18 || tab.allocate(k1) != 16 {
		t.Fatal(a, b, c)
	}
	f := testFacet(16, "acme", "1.0.0")
	tab.history[a] = f
	tab.known["acme"] = []uint64{a}
	tab.retire("other")
	if err := tab.save(); err != nil {
		t.Fatal(err)
	}
	t2, err := newTable(store)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := t2.lookup(k1); !ok || id != 16 {
		t.Fatal("ID lost")
	}
	if _, ok := t2.lookup(k3); ok {
		t.Fatal("retired ID kept")
	}
	if !facetEqual(t2.history[16], f) || len(t2.known["acme"]) != 1 {
		t.Fatal("history or known facets lost")
	}
	// A retired ID is never handed out again.
	if id := t2.allocate(k3); id != 19 {
		t.Fatalf("re-added node got %d", id)
	}
}

func testFacet(id uint64, name, version string) *schema.Facet {
	return &schema.Facet{ID: id, Name: name, Version: version, Types: []schema.TypeDef{}, Sigils: []schema.Sigil{},
		Retired: []schema.Retired{}, Annotations: schema.Annotations{},
		Services: []schema.Service{{ID: 0, Name: "S", Annotations: schema.Annotations{}, Methods: []schema.Method{
			{ID: 0, Name: "m", Input: schema.Named(schema.TypeUnit), Output: schema.Named(schema.TypeString), Errors: []uint64{}, Annotations: schema.Annotations{}},
		}}}}
}

// renderer is an interface and facets implementing it.
func renderer() *schema.Interface {
	return &schema.Interface{Name: "acme.renderer", Version: "1.0.0", Types: []schema.TypeDef{}, Sigils: []schema.Sigil{},
		Services: []schema.Service{{ID: 0, Name: "Renderer", Annotations: schema.Annotations{}, Methods: []schema.Method{
			{ID: 0, Name: "render", Input: schema.Named(schema.TypeString), Output: schema.Named(schema.TypeBytes), Errors: []uint64{}, Annotations: schema.Annotations{}},
		}}}}
}

func implFacet(id uint64, name string, iface *schema.Interface) *schema.Facet {
	f := &schema.Facet{ID: id, Name: name, Version: "1.0.0", Types: []schema.TypeDef{}, Sigils: []schema.Sigil{},
		Retired: []schema.Retired{}, Annotations: schema.Annotations{}, Services: iface.Clone().Services}
	f.Implements, _ = iface.Hash()
	return f
}

func schemaOf(fs ...*schema.Facet) *schema.Schema {
	s := &schema.Schema{Format: schema.Format, Name: "n", Version: "1", Facets: []schema.Facet{}, Annotations: schema.Annotations{}}
	for _, f := range fs {
		s.Facets = append(s.Facets, *f)
	}
	return s
}

// unitHub is a hub with no listeners and nodes that "connect" by having
// their schemas checked and committed directly.
func unitHub(t *testing.T, cfg *admin.Config) *Hub {
	t.Helper()
	store, _ := admin.OpenStore(t.TempDir())
	h, err := New(Options{Store: store, Bootstrap: []Credential{{Token: "t", Principal: "user:admin"}}, Logger: testLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close(time.Second) })
	h.Apply(cfg, 1)
	return h
}

func (h *Hub) publish(t *testing.T, node string, sc *schema.Schema) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.nodes[node]
	fs, err := h.checkNodeFacetsLocked(n, sc)
	if err != nil {
		return err
	}
	h.commitNodeFacetsLocked(n, fs)
	return nil
}

func facetNames(s *schema.Schema) []string {
	var out []string
	for _, f := range s.Facets {
		out = append(out, f.Name)
	}
	return out
}

func TestComposition(t *testing.T) {
	r := renderer()
	rb, _ := r.Encode()
	ifaces := cbor.AppendArrayHead(nil, 1)
	ifaces = cbor.AppendBytes(ifaces, rb)
	rh, _ := r.Hash()
	cfg := &admin.Config{Nodes: map[string]*admin.NodeConfig{
		"acme":   {Credential: strp("x")},
		"charts": {Credential: strp("y")},
		"hub-b":  {Credential: strp("z"), Peer: boolp(true)},
		"off":    {Credential: strp("w"), Enabled: boolp(false)},
	}, Defaults: map[string]string{string(rh): "charts.svg"}, Extensions: map[string][]byte{
		InterfacesExtension: ifaces,
		PolicyExtension: EncodeGrants([]Grant{
			grant("user:alice", "acme", "use"), grant("user:alice", "acme.*", "use"), grant("user:alice", "charts.*", "use"), grant("user:alice", "hub-b/remote", "use"),
			grant("node:acme", "acme", "view"), grant("node:acme", "charts.*", "view"), grant("node:acme", "hub-b/remote", "view"),
			grant("node:hub-b", "acme", "view"), grant("node:hub-b", "acme.*", "view"), grant("node:hub-b", "charts.*", "view"), grant("node:hub-b", "hub-b/remote", "view"),
			grant("user:bob", "acme", "view")}),
	}}
	h := unitHub(t, cfg)
	if err := h.publish(t, "acme", schemaOf(testFacet(16, "acme", "1.0.0"), implFacet(17, "acme.png", r))); err != nil {
		t.Fatal(err)
	}
	if err := h.publish(t, "charts", schemaOf(implFacet(16, "charts.svg", r))); err != nil {
		t.Fatal(err)
	}
	if err := h.publish(t, "hub-b", schemaOf(testFacet(20, "remote", "1.0.0"))); err != nil {
		t.Fatal(err)
	}
	if err := h.publish(t, "off", schemaOf(testFacet(16, "off", "1.0.0"))); err != nil {
		t.Fatal(err)
	}
	// Naming rules.
	if err := h.publish(t, "acme", schemaOf(testFacet(16, "charts.x", "1.0.0"))); err == nil {
		t.Fatal("foreign name accepted")
	}
	if err := h.publish(t, "hub-b", schemaOf(testFacet(16, "x/y", "1.0.0"))); err == nil {
		t.Fatal("re-exported import accepted")
	}
	// An implements claim that does not hold is refused.
	broken := implFacet(18, "acme.bad", r)
	broken.Services[0].Methods[0].Input = schema.Named(schema.TypeUint)
	if err := h.publish(t, "acme", schemaOf(testFacet(16, "acme", "1.0.0"), broken)); err == nil {
		t.Fatal("broken implements claim accepted")
	}
	alice := h.viewFor(&viewer{h: h, kind: viewClient, actor: Actor{Principal: "user:alice"}})
	want := []string{"acme", "acme.png", "charts.svg", "hub-b/remote"}
	if got := facetNames(alice); len(got) != 4 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
		t.Fatalf("alice sees %v", got)
	}
	// Facet IDs: stable per (node, name, major), sorted.
	for i := 1; i < len(alice.Facets); i++ {
		if alice.Facets[i-1].ID >= alice.Facets[i].ID {
			t.Fatal("not sorted")
		}
	}
	// Imported facets keep their hash under the new name.
	h1, _ := testFacet(0, "remote", "1.0.0").Hash()
	h2, _ := alice.Facets[3].Hash()
	if !bytes.Equal(h1, h2) {
		t.Fatal("import changed the facet hash")
	}
	// sparrow.defaults honours the preference.
	d := alice.Annotations[DefaultsAnnotation]
	m, err := cbor.Decode(d, cbor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := m.(cbor.Map).Get(rh); v != alice.Facets[2].ID {
		t.Fatalf("defaults %v, want facet %d (charts.svg)", m, alice.Facets[2].ID)
	}
	// A node's own facets are left out; it sees the rest that is visible
	// to node:acme.
	acme := h.viewFor(&viewer{h: h, kind: viewNode, node: h.nodes["acme"]})
	if got := facetNames(acme); len(got) != 2 || got[0] != "charts.svg" || got[1] != "hub-b/remote" {
		t.Fatalf("acme sees %v", got)
	}
	// A peer never gets imported facets (no re-export).
	peer := h.viewFor(&viewer{h: h, kind: viewPeer, node: h.nodes["hub-b"]})
	if got := facetNames(peer); len(got) != 3 || got[2] != "charts.svg" {
		t.Fatalf("hub-b sees %v", got)
	}
	// bob sees acme only; the interface has no visible implementation, so
	// no defaults.
	bob := h.viewFor(&viewer{h: h, kind: viewClient, actor: Actor{Principal: "user:bob"}})
	if got := facetNames(bob); len(got) != 1 || got[0] != "acme" {
		t.Fatalf("bob sees %v", got)
	}
	if _, ok := bob.Annotations[DefaultsAnnotation]; ok {
		t.Fatal("defaults without a visible implementation")
	}
	// Without the preferred facet, the lowest ID wins.
	cfg2 := cfg.Clone()
	cfg2.Defaults = map[string]string{string(rh): "nope"}
	h.Apply(cfg2, 2)
	alice = h.viewFor(&viewer{h: h, kind: viewClient, actor: Actor{Principal: "user:alice"}})
	m, _ = cbor.Decode(alice.Annotations[DefaultsAnnotation], cbor.Options{})
	if v, _ := m.(cbor.Map).Get(rh); v != alice.Facets[1].ID {
		t.Fatalf("defaults %v, want the lowest ID %d", m, alice.Facets[1].ID)
	}
	// Compatibility within a major version is checked against the last
	// listed version, across sessions.
	inc := testFacet(16, "acme", "1.1.0")
	inc.Services[0].Methods[0].Output = schema.Named(schema.TypeUint)
	if err := h.publish(t, "acme", schemaOf(inc)); err == nil {
		t.Fatal("incompatible successor accepted")
	}
	if err := h.publish(t, "acme", schemaOf(testFacet(16, "acme", "2.0.0"))); err != nil {
		t.Fatal(err)
	}
	alice = h.viewFor(&viewer{h: h, kind: viewClient, actor: Actor{Principal: "user:alice"}})
	if alice.Facets[len(alice.Facets)-1].Name != "acme" {
		t.Fatalf("a new major version gets a new ID: %v", facetNames(alice))
	}
	// The views survive a restart of the table: same IDs.
	t2, _ := newTable(h.o.Store)
	if id, _ := t2.lookup(facetKey{"acme", "acme", "1"}); id != 16+1 && id != h.tab.ids[facetKey{"acme", "acme", "1"}] {
		t.Fatal("ID not persisted")
	}
}

func TestContextValidity(t *testing.T) {
	clk := testutil.NewFakeClock()
	h := &Hub{clock: clk}
	cc := &callContext{open: true, deadline: clk.Now().Add(10 * time.Second)}
	if !h.contextValidLocked(cc) {
		t.Fatal("open context invalid")
	}
	cc.open, cc.endedAt = false, clk.Now()
	clk.Advance(1900 * time.Millisecond)
	if !h.contextValidLocked(cc) {
		t.Fatal("invalid within the grace period")
	}
	clk.Advance(200 * time.Millisecond)
	if h.contextValidLocked(cc) {
		t.Fatal("valid after the grace period")
	}
	cc2 := &callContext{open: true, deadline: clk.Now().Add(time.Second)}
	clk.Advance(time.Second)
	if h.contextValidLocked(cc2) {
		t.Fatal("valid after the call's deadline")
	}
	cc3 := &callContext{open: true}
	clk.Advance(time.Hour)
	if !h.contextValidLocked(cc3) {
		t.Fatal("an open call without deadline")
	}
}
