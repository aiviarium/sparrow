package hub

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/web"
)

type viewKind int

const (
	viewClient viewKind = iota
	viewNode
	viewPeer
)

// viewer is one session the hub publishes a schema to: a client, a node or
// a peer hub (10.3).
type viewer struct {
	h     *Hub
	kind  viewKind
	actor Actor // a client's principal
	node  *node // a node or peer session
	link  *link

	mu     sync.Mutex // serializes schema updates of this session
	smu    sync.Mutex
	sess   *session.Session
	expiry []session.Timer // the AuthStatus warning and the end (5.5)
}

func (v *viewer) stopExpiry() {
	v.smu.Lock()
	defer v.smu.Unlock()
	for _, t := range v.expiry {
		t.Stop()
	}
	v.expiry = nil
}

func kindFor(n *node) viewKind {
	if n.cfg.IsPeer() {
		return viewPeer
	}
	return viewNode
}

func (v *viewer) session() *session.Session {
	v.smu.Lock()
	defer v.smu.Unlock()
	return v.sess
}

func (v *viewer) setSession(s *session.Session) {
	v.smu.Lock()
	v.sess = s
	v.smu.Unlock()
}

// visibility is the actor whose visible() decides the session's schema: a
// client's principal, or node:<id> for nodes and peers (10.3, 10.8).
func (v *viewer) visibility() Actor {
	if v.node != nil {
		return Actor{Principal: names.NodePrincipal(v.node.id)}
	}
	return v.clientActor()
}

// clientActor returns a client session's actor (AuthRefresh may update
// its groups and expiry).
func (v *viewer) clientActor() Actor {
	v.smu.Lock()
	defer v.smu.Unlock()
	return v.actor
}

func (h *Hub) addViewer(v *viewer) {
	h.mu.Lock()
	h.viewers[v] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) removeViewer(v *viewer) {
	h.mu.Lock()
	delete(h.viewers, v)
	h.mu.Unlock()
}

func (h *Hub) viewerListLocked() []*viewer {
	vs := make([]*viewer, 0, len(h.viewers))
	for v := range h.viewers {
		vs = append(vs, v)
	}
	return vs
}

// listedFacet is a facet as the hub lists it: hub facet ID and listed name.
type listedFacet struct {
	ref FacetRef
	def *schema.Facet // with the hub ID and listed name
	// verified is set when the facet's implements claim was checked.
	verified bool
}

// hubFacetsLocked returns the hub's own facets.
func (h *Hub) hubFacetsLocked() []listedFacet {
	var out []listedFacet
	if h.o.Web {
		f := schema.WebFacet()
		out = append(out, listedFacet{ref: FacetRef{ID: f.ID, Name: f.Name, Def: f}, def: f})
	}
	af := adminiface.Facet(h.adminID)
	out = append(out, listedFacet{ref: FacetRef{ID: h.adminID, Name: af.Name, Def: af}, def: af, verified: true})
	return out
}

// nodeFacetsLocked returns the facets a node lists: its last known facets
// (10.7) as hub facets.
func (h *Hub) nodeFacetsLocked(n *node) []listedFacet {
	out := make([]listedFacet, 0, len(n.listed))
	for _, id := range n.listed {
		f := h.tab.history[id]
		if f == nil {
			continue
		}
		name := f.Name
		def := f.Clone()
		if n.cfg.IsPeer() {
			name = names.Imported(n.id, f.Name)
			def.Name = name
		}
		out = append(out, listedFacet{ref: FacetRef{ID: id, Name: name, Node: n.id, Imported: n.cfg.IsPeer(), Def: def}, def: def,
			verified: def.Implements != nil && h.ifaces[string(def.Implements)] != nil})
	}
	return out
}

// facetLocked finds a listed facet by hub facet ID (any node, enabled or
// not) and its node.
func (h *Hub) facetLocked(id uint64) (*listedFacet, *node) {
	for _, f := range h.hubFacetsLocked() {
		if f.ref.ID == id {
			f := f
			return &f, nil
		}
	}
	for _, n := range h.nodes {
		for _, x := range n.listed {
			if x == id {
				for _, f := range h.nodeFacetsLocked(n) {
					if f.ref.ID == id {
						f := f
						return &f, n
					}
				}
			}
		}
	}
	return nil, nil
}

// viewFor composes the schema of one session (10.3): the hub's own facets
// and every node facet visible to the session's principal, without the
// session's own facets (a node's) and without imported facets for a peer
// (10.8: no re-export), plus the sparrow.defaults annotation.
func (h *Hub) viewFor(v *viewer) *schema.Schema {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.viewForLocked(v)
}

func (h *Hub) viewForLocked(v *viewer) *schema.Schema {
	who := v.visibility()
	var fs []listedFacet
	for _, f := range h.hubFacetsLocked() {
		if h.policy.Visible(who, f.ref) {
			fs = append(fs, f)
		}
	}
	for _, id := range sortedNodeIDs(h.nodes) {
		n := h.nodes[id]
		if !n.cfg.IsEnabled() || (v.node != nil && v.node.id == n.id) {
			continue
		}
		if v.kind == viewPeer && n.cfg.IsPeer() {
			continue // never re-export an imported facet (10.8)
		}
		for _, f := range h.nodeFacetsLocked(n) {
			if h.policy.Visible(who, f.ref) {
				fs = append(fs, f)
			}
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].ref.ID < fs[j].ref.ID })
	sc := &schema.Schema{Format: schema.Format, Name: h.o.SchemaName, Version: h.o.SchemaVersion,
		Facets: make([]schema.Facet, 0, len(fs)), Annotations: schema.Annotations{}}
	for _, f := range fs {
		sc.Facets = append(sc.Facets, *f.def.Clone())
	}
	if d := h.defaultsLocked(fs); d != nil {
		sc.Annotations[DefaultsAnnotation] = d
	}
	if h.o.Web && h.cfg != nil {
		if v, ok := h.cfg.Extensions[WebExtension]; ok {
			if anns, err := web.ParseTopLevel(v, h.o.WebRoots); err == nil {
				for k, a := range anns {
					sc.Annotations[k] = a
				}
			}
		}
	}
	return sc.Canonical()
}

// DefaultsAnnotation is the top-level schema annotation naming the default
// implementation of each interface (10.3).
const DefaultsAnnotation = "sparrow.defaults"

// defaultsLocked builds sparrow.defaults: for every interface with at
// least one visible, verified implementation, the preferred facet of the
// document's defaults when it is among them, else the lowest facet ID.
func (h *Hub) defaultsLocked(fs []listedFacet) cbor.Raw {
	impls := map[string][]listedFacet{}
	for _, f := range fs {
		if f.def.Implements != nil && f.verified {
			impls[string(f.def.Implements)] = append(impls[string(f.def.Implements)], f)
		}
	}
	if len(impls) == 0 {
		return nil
	}
	keys := make([][]byte, 0, len(impls))
	for k := range impls {
		keys = append(keys, []byte(k))
	}
	// Canonical order: byte strings of one length sort bytewise.
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return bytes.Compare(keys[i], keys[j]) < 0
	})
	b := cbor.AppendMapHead(nil, len(keys))
	for _, k := range keys {
		cands := impls[string(k)]
		choice := cands[0].ref.ID
		if h.cfg != nil && h.cfg.Defaults != nil {
			if pref, ok := h.cfg.Defaults[string(k)]; ok {
				for _, c := range cands {
					if c.ref.Name == pref {
						choice = c.ref.ID
					}
				}
			}
		}
		b = cbor.AppendBytes(b, k)
		b = cbor.AppendUint(b, choice)
	}
	return b
}

// refresh sends the session its current view if it changed, and returns
// the pending update (nil if nothing changed or the session is gone).
// ackTimeout 0 uses the session default.
func (v *viewer) refresh(ackTimeout time.Duration) *session.PendingUpdate {
	v.mu.Lock()
	defer v.mu.Unlock()
	s := v.session()
	if s == nil {
		return nil
	}
	select {
	case <-s.Done():
		return nil
	default:
	}
	cur := s.LocalSchema()
	if cur == nil {
		return nil
	}
	want := v.h.viewFor(v)
	wh, err := want.Hash()
	if err != nil {
		v.h.log.Error("composed schema has no hash", "err", err)
		return nil
	}
	ch, _ := cur.Hash()
	if bytes.Equal(wh, ch) {
		return nil
	}
	u, err := s.UpdateSchema(want, session.SchemaUpdateOptions{AckTimeout: ackTimeout})
	if err != nil {
		v.h.log.Warn("schema update failed", "err", err)
		// A view the session cannot take (it would break a rule of 6.6
		// for this session): close it, so the next one starts fresh.
		s.Close(statusSchemaMismatch, "cannot update the schema: "+err.Error())
		return nil
	}
	return u
}

// refreshAll sends every session whose view changed a SchemaUpdate and
// waits until each has acknowledged it or been closed (10.3). Each
// downstream session gets ackTimeout (0: the default).
func (h *Hub) refreshAll(ackTimeout time.Duration) {
	h.mu.Lock()
	vs := h.viewerListLocked()
	h.mu.Unlock()
	var wg sync.WaitGroup
	for _, v := range vs {
		wg.Add(1)
		go func(v *viewer) {
			defer wg.Done()
			if u := v.refresh(ackTimeout); u != nil {
				ctx := context.Background()
				if ackTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, ackTimeout+time.Second)
					defer cancel()
				}
				_ = u.Wait(ctx)
			}
		}(v)
	}
	wg.Wait()
}
