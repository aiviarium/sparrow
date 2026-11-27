package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/websocket"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
	"github.com/aiviarium/sparrow-rpc/go/web"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

const statusSchemaMismatch = status.SchemaMismatch

type linkKind int

const (
	linkDialIn linkKind = iota // the node dialed in
	linkDial                   // the hub dialed the node
)

// link is one session with a node (10.2).
type link struct {
	n    *node
	sess *session.Session
	v    *viewer
	kind linkKind
	// dial-in: the credential it presented and the secret it matched.
	cred     []byte
	credName string

	mu         sync.Mutex
	hubToLocal map[uint64]uint64
	routed     bool
}

func (l *link) localID(hubID uint64) (uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id, ok := l.hubToLocal[hubID]
	return id, ok
}

// node is one configured node.
type node struct {
	h   *Hub
	id  string
	cfg *admin.NodeConfig
	rev uint64 // revision of the configuration it runs under

	// Guarded by h.mu.
	listed  []uint64 // hub facet IDs of its last known facets (10.7)
	link    *link    // the session calls are routed to
	ready   chan struct{}
	state   admin.NodeState
	message string
	dl      *dialer       // the dial loop of a dialed node
	gone    chan struct{} // closed when the node is removed or disabled (10.7)

	switching sync.Mutex   // serializes supersedes and schema updates (10.2)
	waiting   atomic.Int32 // calls waiting for the node to connect (10.7)
}

func (n *node) credentialName() string {
	if n.cfg == nil {
		return ""
	}
	return n.cfg.CredentialName()
}

// setState records a node state and reports it to watchers (hub-admin 4).
// h.mu must not be held.
func (n *node) setState(st admin.NodeState, msg string) {
	h := n.h
	h.mu.Lock()
	if h.nodes[n.id] != n && st != admin.Removed {
		h.mu.Unlock()
		return
	}
	n.state, n.message = st, msg
	rev := h.rev // the revision applied when the event is sent (hub-admin 4)
	h.mu.Unlock()
	ev := admin.NodeEvent{Node: n.id, Revision: rev, State: st}
	if msg != "" {
		ev.Message = &msg
	}
	h.adm.NodeEvent(ev)
}

// nodeFacet is a facet a node publishes, mapped to the hub.
type nodeFacet struct {
	local uint64
	key   facetKey
	def   *schema.Facet // with the hub facet ID
	hubID uint64        // 0 until allocated
}

// checkNodeFacets checks a node's schema (10.2, 10.3): every facet named
// after the node (a peer's facets may have any local name, but none may
// be imported, 10.8), compatible with the last version of its hub facet
// ID, and with a verified implements claim. Errors carry the GoAway code.
func (h *Hub) checkNodeFacets(n *node, sc *schema.Schema) ([]nodeFacet, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.checkNodeFacetsLocked(n, sc)
}

func (h *Hub) checkNodeFacetsLocked(n *node, sc *schema.Schema) ([]nodeFacet, error) {
	if sc == nil {
		return nil, nil
	}
	peer := n.cfg.IsPeer()
	out := make([]nodeFacet, 0, len(sc.Facets))
	for i := range sc.Facets {
		f := &sc.Facets[i]
		if peer {
			if strings.Contains(f.Name, "/") || !names.IsNodeID(f.Name) {
				return nil, &session.Error{Code: status.InvalidArgument, Message: fmt.Sprintf("peer %s exports %q: imported facets are never re-exported (10.8)", n.id, f.Name)}
			}
		} else if !names.OwnedBy(n.id, f.Name) {
			return nil, &session.Error{Code: status.InvalidArgument, Message: fmt.Sprintf("facet %q is not named after node %q (10.2)", f.Name, n.id)}
		}
		if err := web.CheckFacet(f); err != nil {
			// Client modules in the facet's own scope only (9.4).
			return nil, &session.Error{Code: status.InvalidArgument, Message: err.Error()}
		}
		k := facetKey{node: n.id, name: f.Name, major: schema.Major(f.Version)}
		nf := nodeFacet{local: f.ID, key: k, def: f.Clone()}
		if id, ok := h.tab.lookup(k); ok {
			nf.hubID = id
			nf.def.ID = id
			if old := h.tab.history[id]; old != nil {
				if err := schema.Compatible(old, nf.def); err != nil {
					return nil, &session.Error{Code: status.SchemaMismatch, Message: fmt.Sprintf("facet %q is not a compatible successor: %v", f.Name, err)}
				}
			}
		}
		if f.Implements != nil {
			if iface := h.ifaces[string(f.Implements)]; iface != nil {
				if err := schema.VerifyImplements(f, iface); err != nil {
					return nil, &session.Error{Code: status.SchemaMismatch, Message: fmt.Sprintf("facet %q: %v", f.Name, err)}
				}
			} else {
				// A claim to an interface the hub holds no document for is
				// refused like an incompatible update (10.3).
				return nil, &session.Error{Code: status.SchemaMismatch, Message: fmt.Sprintf("facet %q claims interface %x, for which this hub holds no interface document", f.Name, f.Implements)}
			}
		}
		out = append(out, nf)
	}
	return out, nil
}

// commitNodeFacetsLocked allocates IDs, records the definitions and makes
// them the node's listed facets. It reports whether anything changed.
func (h *Hub) commitNodeFacetsLocked(n *node, fs []nodeFacet) (map[uint64]uint64, bool) {
	m := map[uint64]uint64{}
	ids := make([]uint64, 0, len(fs))
	changed := false
	for i := range fs {
		f := &fs[i]
		if f.hubID == 0 {
			f.hubID = h.tab.allocate(f.key)
			f.def.ID = f.hubID
		}
		if old := h.tab.history[f.hubID]; old == nil || !facetEqual(old, f.def) {
			h.tab.history[f.hubID] = f.def
			changed = true
		}
		m[f.hubID] = f.local
		ids = append(ids, f.hubID)
	}
	if !sameIDs(n.listed, ids) {
		changed = true
	}
	n.listed = ids
	h.tab.known[n.id] = ids
	if changed {
		if err := h.tab.save(); err != nil {
			h.log.Error("cannot persist the facet table", "err", err)
		}
	}
	return m, changed
}

func facetEqual(a, b *schema.Facet) bool {
	x, err1 := a.CanonicalBytes()
	y, err2 := b.CanonicalBytes()
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

func sameIDs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// attach makes a new node session the one calls go to (10.2): if its
// facets differ from those listed, the change is relayed to every session
// first, and calls keep going to the old session (or wait) until all have
// acknowledged it; then new calls go to the new session and the old one
// gets GoAway(going_away).
func (h *Hub) attach(n *node, l *link) {
	n.switching.Lock()
	h.mu.Lock()
	l.v.link = l
	if h.nodes[n.id] != n || h.closed {
		h.mu.Unlock()
		n.switching.Unlock()
		l.sess.Close(status.GoingAway, "node no longer configured")
		return
	}
	var peerSchema *schema.Schema
	if st := l.sess.PeerSchema(); st != nil {
		peerSchema = st.Schema()
	}
	fs, err := h.checkNodeFacetsLocked(n, peerSchema)
	if err != nil {
		// Refused facets: the new session goes, an old one is kept (10.2).
		connected := n.link != nil
		h.mu.Unlock()
		n.switching.Unlock()
		l.sess.Close(session.Code(err), err.Error())
		if !connected {
			n.setState(admin.Offline, "refused: "+err.Error())
		}
		return
	}
	mapping, changed := h.commitNodeFacetsLocked(n, fs)
	l.mu.Lock()
	l.hubToLocal = mapping
	l.mu.Unlock()
	h.mu.Unlock()
	if changed {
		h.refreshAll(h.relayTimeout(n)) // the same limits as for an update (10.3)
	}
	h.mu.Lock()
	if ending(l.sess) || h.nodes[n.id] != n {
		// The session ended, or the node went, while its facets were
		// relayed: never route calls to it (they would fail, and calls
		// waiting for the node would wake for nothing).
		h.mu.Unlock()
		n.switching.Unlock()
		l.sess.Close(status.GoingAway, "node session ended before it was routed")
		return
	}
	old := n.link
	n.link = l
	l.mu.Lock()
	l.routed = true
	l.mu.Unlock()
	select {
	case <-n.ready:
	default:
		close(n.ready)
	}
	h.mu.Unlock()
	n.switching.Unlock()
	if old != nil && old != l {
		old.sess.GoAway(status.GoingAway, "superseded by a new session of the node", nil)
	}
	go l.v.refresh(0) // the node's own view may have changed meanwhile
	n.setState(admin.Connected, "")
	go func() {
		<-l.sess.Done()
		h.detach(n, l)
	}()
}

// detach handles the end of a node session.
func (h *Hub) detach(n *node, l *link) {
	h.removeViewer(l.v)
	h.mu.Lock()
	if n.link != l {
		h.mu.Unlock()
		return
	}
	n.link = nil
	n.ready = make(chan struct{})
	enabled := h.nodes[n.id] == n && n.cfg.IsEnabled()
	h.mu.Unlock()
	if enabled && l.kind == linkDialIn {
		// The message is the last connection failure, if any (hub-admin 4).
		n.setState(admin.Offline, sessionReason(l.sess))
	}
}

// ending reports whether a session has ended or is draining.
func ending(s *session.Session) bool {
	select {
	case <-s.Done():
		return true
	default:
	}
	return s.Stats().Draining
}

func sessionReason(s *session.Session) string {
	if err := s.Err(); err != nil {
		return err.Error()
	}
	return ""
}

// nodeSchemaUpdate handles a SchemaUpdate from a node (10.3): checked as
// at connection, relayed to every affected session, acknowledged only
// once each has acked or been closed.
func (h *Hub) nodeSchemaUpdate(v *viewer, u *session.PeerSchemaUpdate) error {
	n := v.node
	n.switching.Lock()
	defer n.switching.Unlock()
	h.mu.Lock()
	l := v.link
	if h.nodes[n.id] != n || l == nil || n.link != l {
		h.mu.Unlock()
		return nil // a superseded or not yet routed session: nothing is listed from it
	}
	fs, err := h.checkNodeFacetsLocked(n, u.New.Schema())
	if err != nil {
		h.mu.Unlock()
		return err
	}
	mapping, changed := h.commitNodeFacetsLocked(n, fs)
	l.mu.Lock()
	// Calls already forwarded keep their node-local IDs; new calls use the
	// new mapping.
	l.hubToLocal = mapping
	l.mu.Unlock()
	h.mu.Unlock()
	if changed {
		h.refreshAll(h.relayTimeout(n))
	}
	return nil
}

// relayTimeout is the time each downstream session gets to ack a change
// from node n (10.3): 5 s for a node's, 2 s for one a peer hub relays.
func (h *Hub) relayTimeout(n *node) time.Duration {
	if n.cfg.IsPeer() {
		return h.o.PeerRelayAckTimeout
	}
	return h.o.RelayAckTimeout
}

// waitLink returns the node's routed session, waiting up to timeout for
// an offline node to connect (10.7). A dialed node is redialed at once, and
// then at least every waitingRedial while calls wait, rather than after its
// backoff.
func (h *Hub) waitLink(ctx context.Context, n *node, timeout time.Duration) (*link, error) {
	h.mu.Lock()
	l, ready, gone := n.link, n.ready, n.gone
	h.mu.Unlock()
	if l != nil {
		return l, nil
	}
	n.waiting.Add(1)
	defer n.waiting.Add(-1)
	n.kickDial()
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		select {
		case <-ready:
		case <-t.C:
			return nil, &session.Error{Code: status.Unavailable, Message: fmt.Sprintf("node %s is not connected", n.id)}
		case <-gone:
			return nil, &session.Error{Code: status.Unimplemented, Message: fmt.Sprintf("node %s was removed or disabled", n.id)}
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		h.mu.Lock()
		l, ready, gone = n.link, n.ready, n.gone
		h.mu.Unlock()
		if l != nil {
			return l, nil
		}
		// The session that became ready has ended again: keep waiting.
	}
}

// ---------------------------------------------------------------------------
// Reconciliation (hub-admin 2.2)
// ---------------------------------------------------------------------------

// Apply implements admin.Applier: it switches to the document at once and
// reconciles nodes in the background.
func (h *Hub) Apply(cfg *admin.Config, rev uint64) {
	h.reconcile.Lock()
	defer h.reconcile.Unlock()
	h.mu.Lock()
	h.cfg, h.rev = cfg, rev
	if h.o.Policy == nil {
		gs, _ := ParseGrants(cfg.Extensions[PolicyExtension])
		h.policy = &hubPolicy{inner: &GrantPolicy{Grants: gs}, bootstrap: h.policy.bootstrap}
	}
	h.loadInterfacesLocked(cfg)
	var removed, changed, added []*node
	olds := map[*node]*admin.NodeConfig{}
	for id, n := range h.nodes {
		nc, ok := cfg.Nodes[id]
		if !ok {
			n.rev = rev // its removal reflects this revision
			delete(h.nodes, id)
			h.tab.retire(id) // a removed node's facet IDs are retired for good
			removed = append(removed, n)
			continue
		}
		if !bytes.Equal(nc.AppendTo(nil), n.cfg.AppendTo(nil)) {
			changed = append(changed, n)
			olds[n] = n.cfg
			n.cfg = nc
		}
		n.rev = rev
	}
	for _, id := range cfg.NodeIDs() {
		if _, ok := h.nodes[id]; ok {
			continue
		}
		n := &node{h: h, id: id, cfg: cfg.Nodes[id], rev: rev, ready: make(chan struct{}), gone: make(chan struct{}), state: admin.Offline}
		if ids, ok := h.tab.known[id]; ok {
			n.listed = ids // last known facets survive restarts (10.7)
		}
		h.nodes[id] = n
		added = append(added, n)
	}
	_ = h.tab.save()
	h.mu.Unlock()

	for _, n := range removed {
		n.markGone()
		n.stopLink("node removed from the configuration")
		n.setState(admin.Removed, "")
	}
	for _, n := range changed {
		h.reconfigure(n, olds[n])
	}
	for _, n := range added {
		n.begin()
	}
	h.mu.Lock()
	unchanged := make([]*node, 0, len(h.nodes))
	for _, n := range h.nodes {
		unchanged = append(unchanged, n)
	}
	h.mu.Unlock()
	for _, n := range unchanged {
		h.mu.Lock()
		st, msg := n.state, n.message
		h.mu.Unlock()
		n.setState(st, msg) // the node now reflects this revision
	}
	go func() {
		h.refreshAll(0)
		h.recheckCalls()
	}()
}

// reconfigure applies a changed NodeConfig (core 10.2, hub-admin 2.2):
// a node that is disabled, or whose link or peer setting changed, has its
// session ended at once, and is dialed anew or waited for only while it
// is still enabled.
func (h *Hub) reconfigure(n *node, old *admin.NodeConfig) {
	nc := n.cfg
	linkChanged := !bytes.Equal(old.Link.AppendTo(nil), nc.Link.AppendTo(nil)) || old.IsPeer() != nc.IsPeer()
	switch {
	case !nc.IsEnabled():
		if old.IsEnabled() {
			n.markGone()
			n.stopLink("node disabled")
		}
		n.setState(admin.Disabled, "")
	case !old.IsEnabled():
		n.unmarkGone()
		n.begin()
	case linkChanged:
		n.stopLink("node reconfigured")
		n.begin()
	}
}

// WebExtension is the document extension holding the top-level web.*
// schema annotations (web.keys, web.revoked, web.apply and client
// configuration) a hub with the Web Profile publishes: a CBOR map from
// annotation key to value (9.4, 9.5).
const WebExtension = "ref.web"

// InterfacesExtension is the document extension listing interface
// documents (a CBOR list of encoded interfaces) the hub verifies implements
// claims against, besides those it knows (10.3).
const InterfacesExtension = "ref.interfaces"

func (h *Hub) validateExtension(nodeID, key string, v []byte) error {
	switch {
	case nodeID == "" && key == PolicyExtension:
		if h.o.Policy != nil {
			return errors.New("this hub uses its own policy; ref.policy is not used")
		}
		_, err := ParseGrants(v)
		return err
	case nodeID == "" && key == InterfacesExtension:
		_, err := parseInterfaces(v)
		return err
	case nodeID == "" && key == WebExtension && h.o.Web:
		_, err := web.ParseTopLevel(v, h.o.WebRoots)
		return err
	}
	return admin.ErrUnsupported
}

func parseInterfaces(v []byte) ([]*schema.Interface, error) {
	d := cbor.NewDecoder(v)
	n, err := d.ArrayHead()
	if err != nil {
		return nil, errors.New("ref.interfaces is a list of encoded interface documents")
	}
	out := make([]*schema.Interface, 0, n)
	for i := 0; i < n; i++ {
		b, err := d.Bytes()
		if err != nil {
			return nil, fmt.Errorf("interface %d: want bytes", i)
		}
		iface, err := schema.DecodeInterface(b)
		if err == nil {
			err = iface.Validate()
		}
		if err != nil {
			return nil, fmt.Errorf("interface %d: %v", i, err)
		}
		out = append(out, iface)
	}
	return out, nil
}

func (h *Hub) loadInterfacesLocked(cfg *admin.Config) {
	for k := range h.ifaces {
		delete(h.ifaces, k)
	}
	ai := adminiface.Interface()
	ah, _ := ai.Hash()
	h.ifaces[string(ah)] = ai
	if v, ok := cfg.Extensions[InterfacesExtension]; ok {
		list, _ := parseInterfaces(v)
		for _, i := range list {
			if hh, err := i.Hash(); err == nil {
				h.ifaces[string(hh)] = i
			}
		}
	}
}

// begin starts a new or newly enabled node as its configuration says: a
// dialed node is dialed at once, a dial-in node is waited for (10.7).
func (n *node) begin() {
	switch {
	case !n.cfg.IsEnabled():
		n.markGone()
		n.setState(admin.Disabled, "")
	case n.cfg.Link.Dial == nil:
		n.setState(admin.Offline, "")
	default:
		n.setState(admin.Offline, "")
		n.redial()
	}
}

// markGone fails the calls waiting for the node (removed or disabled) with
// unimplemented (10.7); unmarkGone re-arms it when the node is enabled.
func (n *node) markGone() {
	n.h.mu.Lock()
	defer n.h.mu.Unlock()
	select {
	case <-n.gone:
	default:
		close(n.gone)
	}
}

func (n *node) unmarkGone() {
	n.h.mu.Lock()
	defer n.h.mu.Unlock()
	select {
	case <-n.gone:
		n.gone = make(chan struct{})
	default:
	}
}

// kickDial makes the dial loop of an offline dialed node try again now.
func (n *node) kickDial() {
	n.h.mu.Lock()
	d := n.dl
	n.h.mu.Unlock()
	if d != nil {
		select {
		case d.kick <- struct{}{}:
		default:
		}
	}
}

// stopDial stops the node's dial loop, if any, leaving its session alone.
func (n *node) stopDial() *dialer {
	h := n.h
	h.mu.Lock()
	dl := n.dl
	n.dl = nil
	h.mu.Unlock()
	if dl != nil {
		dl.stop()
	}
	return dl
}

// stopLink stops the dial loop and ends the node's session at once,
// without the grace period of 5.6 (10.2): the calls running on it end
// with Error(unavailable) toward their callers, then GoAway
// (unauthenticated) and the transport closes. Until a new session is
// ready the node is offline.
func (n *node) stopLink(why string) {
	h := n.h
	dl := n.stopDial()
	h.mu.Lock()
	l := n.link
	if l != nil {
		n.link = nil
		n.ready = make(chan struct{})
	}
	h.mu.Unlock()
	if l != nil {
		h.endLinkNow(l, why)
	}
	if dl != nil {
		dl.wait(10 * time.Second)
	}
}

// endLinkNow ends a node session at once (10.2).
func (h *Hub) endLinkNow(l *link, why string) {
	h.mu.Lock()
	var calls []*activeCall
	for a := range h.calls {
		if a.link == l {
			calls = append(calls, a)
		}
	}
	h.mu.Unlock()
	for _, a := range calls {
		a.end(status.Unavailable, why)
	}
	l.sess.Close(status.Unauthenticated, why)
}

// redial starts a dial loop for the current configuration of a dialed
// node.
func (n *node) redial() {
	h := n.h
	h.mu.Lock()
	cfg := n.cfg
	if h.nodes[n.id] != n || h.closed || cfg.Link.Dial == nil || !cfg.IsEnabled() || n.dl != nil {
		h.mu.Unlock()
		return
	}
	d := &dialer{n: n, done: make(chan struct{}), kick: make(chan struct{}, 1)}
	d.ctx, d.cancel = context.WithCancel(h.ctx)
	n.dl = d
	h.mu.Unlock()
	go d.run(cfg.Link.Dial)
}

// dialer keeps one dialed node connected (10.2), redialing with backoff.
type dialer struct {
	n      *node
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	kick   chan struct{} // a waiting call asks for an attempt now (10.7)
	mu     sync.Mutex
	sess   *session.Session
}

// stop ends the dial loop; whoever stops it ends its session.
func (s *dialer) stop() { s.cancel() }

func (s *dialer) wait(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
	}
}

func (s *dialer) setSession(sess *session.Session) {
	s.mu.Lock()
	s.sess = sess
	s.mu.Unlock()
}

// waitingRedial is the longest wait between redial attempts while calls
// wait for the node.
const waitingRedial = 250 * time.Millisecond

// backoff is the wait before redial attempt n, exponential with jitter as
// a client reconnects (5.6, 10.7): about 500 ms doubling up to about 30 s.
// A call waiting for the node cuts it short.
func backoff(attempt int) time.Duration {
	d := 500 * time.Millisecond << min(attempt, 6)
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// run keeps a dialed node connected (10.2): WebTransport for https,
// WebSocket for wss, the SPKI pin verified on every connection, and
// ["link", credential] presented in Hello.
func (s *dialer) run(d *admin.Dial) {
	defer close(s.done)
	n := s.n
	h := n.h
	for attempt := 0; ; attempt++ {
		if s.ctx.Err() != nil {
			return
		}
		err := s.dialOnce(d)
		if s.ctx.Err() != nil {
			return
		}
		msg := "link ended"
		if err != nil {
			msg = err.Error()
			h.log.Warn("dialing a node failed", "node", n.id, "url", d.URL, "err", err)
		} else {
			attempt = 0
		}
		n.setState(admin.Offline, msg)
		wait := backoff(attempt)
		if n.waiting.Load() > 0 && wait > waitingRedial {
			wait = waitingRedial
		}
		t := time.NewTimer(wait)
		select {
		case <-s.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-s.kick:
			t.Stop()
		}
	}
}

func (s *dialer) dialOnce(d *admin.Dial) error {
	n := s.n
	h := n.h
	cred, ok := h.adm.SecretValue(d.Credential)
	if !ok {
		return fmt.Errorf("secret %q is missing", d.Credential)
	}
	dctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	conn, err := dialPinned(dctx, d.URL, d.Pin)
	cancel()
	if err != nil {
		return err
	}
	v := &viewer{h: h, node: n, kind: kindFor(n)}
	h.addViewer(v)
	credRaw := cbor.AppendBytes(nil, cred)
	if utf8.Valid(cred) {
		credRaw = cbor.AppendText(nil, string(cred))
	}
	cfg := session.Config{
		Schema:  h.viewFor(v),
		Handler: &sessHandler{h: h, v: v},
		Auth:    &wire.Auth{Scheme: "link", Credentials: credRaw},
		OnPeerSchemaUpdate: func(ctx context.Context, ss *session.Session, u *session.PeerSchemaUpdate) error {
			return h.nodeSchemaUpdate(v, u)
		},
	}
	h.sessionConfig(&cfg)
	sess, err := session.NewClient(s.ctx, conn, cfg)
	if err != nil {
		h.removeViewer(v)
		return err
	}
	v.setSession(sess)
	s.setSession(sess)
	l := &link{n: n, sess: sess, v: v, kind: linkDial}
	h.attach(n, l)
	select {
	case <-sess.Done():
	case <-s.ctx.Done():
		if !h.closing() {
			// Reconfigured or removed: ended at once (10.2); stopLink has
			// normally done so already.
			sess.Close(status.Unauthenticated, "node link stopped by the hub")
		}
		// At shutdown Close has sent GoAway and waits for the session.
		select {
		case <-sess.Done():
		case <-time.After(6 * time.Second):
			sess.Close(status.GoingAway, "node link stopped by the hub")
		}
	}
	return sess.Err()
}

// PinFor returns the SHA-256 of a certificate's SubjectPublicKeyInfo, the
// pin of a dialed node (hub-admin 3).
func PinFor(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

func pinVerifier(pin []byte) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("hub: the node presented no certificate")
		}
		if subtle.ConstantTimeCompare(PinFor(cs.PeerCertificates[0]), pin) != 1 {
			return errors.New("hub: the node's public key does not match the configured pin")
		}
		return nil
	}
}

// dialPinned connects to a node and verifies its SPKI pin.
func dialPinned(ctx context.Context, url string, pin []byte) (transport.Conn, error) {
	tc := &tls.Config{InsecureSkipVerify: true, VerifyConnection: pinVerifier(pin), NextProtos: nil}
	switch {
	case strings.HasPrefix(url, "https://"):
		return webtransport.Dial(ctx, url, &webtransport.DialOptions{TLSConfig: tc})
	case strings.HasPrefix(url, "wss://"):
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: false}}
		return websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: hc})
	}
	return nil, fmt.Errorf("hub: cannot dial %q", url)
}
