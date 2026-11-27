package hub

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
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
	"github.com/aiviarium/sparrow-rpc/go/transport/pipe"
	"github.com/aiviarium/sparrow-rpc/go/transport/websocket"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

const statusSchemaMismatch = status.SchemaMismatch

type linkKind int

const (
	linkSpawn linkKind = iota
	linkDialIn
	linkDial
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
	sup     *supervisor // the spawn or dial loop

	switching sync.Mutex // serializes supersedes and schema updates (10.2)
}

func (n *node) credentialName() string {
	if n.cfg == nil || n.cfg.Credential == nil {
		return ""
	}
	return *n.cfg.Credential
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
	rev := n.rev
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
			} else if !h.o.AcceptUnknownInterfaces {
				return nil, &session.Error{Code: status.SchemaMismatch, Message: fmt.Sprintf("facet %q claims interface %x, which this hub does not know and cannot verify", f.Name, f.Implements)}
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
		h.mu.Unlock()
		n.switching.Unlock()
		l.sess.Close(session.Code(err), err.Error())
		return
	}
	mapping, changed := h.commitNodeFacetsLocked(n, fs)
	l.mu.Lock()
	l.hubToLocal = mapping
	l.mu.Unlock()
	h.mu.Unlock()
	if changed {
		h.refreshAll(h.o.RelayAckTimeout)
	}
	h.mu.Lock()
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
		n.setState(admin.Offline, sessionReason(l.sess))
	}
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
		t := h.o.RelayAckTimeout
		if n.cfg.IsPeer() {
			t /= 2 // a peer hub relays further with half of its time (10.3)
		}
		h.refreshAll(t)
	}
	return nil
}

// waitLink returns the node's routed session, waiting up to timeout and
// starting the node if the hub can (10.7).
func (h *Hub) waitLink(ctx context.Context, n *node, timeout time.Duration) (*link, error) {
	h.mu.Lock()
	l, ready := n.link, n.ready
	h.mu.Unlock()
	if l != nil {
		return l, nil
	}
	n.ensureStarted()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ready:
	case <-t.C:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	h.mu.Lock()
	l = n.link
	h.mu.Unlock()
	if l == nil {
		return nil, &session.Error{Code: status.Unavailable, Message: fmt.Sprintf("node %s is not connected", n.id)}
	}
	return l, nil
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
		n := &node{h: h, id: id, cfg: cfg.Nodes[id], rev: rev, ready: make(chan struct{}), state: admin.Offline}
		if ids, ok := h.tab.known[id]; ok {
			n.listed = ids // last known facets survive restarts (10.7)
		} else {
			h.listConfiguredFacetsLocked(n)
		}
		h.nodes[id] = n
		added = append(added, n)
	}
	_ = h.tab.save()
	h.mu.Unlock()

	// Revocation first, ahead of any takeover (10.2).
	h.revalidateCredentials()
	for _, n := range removed {
		n.stopLink()
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

// listConfiguredFacetsLocked lists the facets the document gives for a node
// never seen (10.7).
func (h *Hub) listConfiguredFacetsLocked(n *node) {
	if n.cfg.IsPeer() || len(n.cfg.Facets) == 0 {
		n.listed = nil
		return
	}
	sc := &schema.Schema{Format: schema.Format, Facets: []schema.Facet{}, Annotations: schema.Annotations{}}
	for i, key := range n.cfg.Facets {
		f := h.adm.StoredFacet(key)
		if f == nil {
			continue
		}
		f.ID = schema.FirstFreeFacetID + uint64(i)
		sc.Facets = append(sc.Facets, *f)
	}
	fs, err := h.checkNodeFacetsLocked(n, sc)
	if err != nil {
		h.log.Warn("configured facets of a node are not usable", "node", n.id, "err", err)
		return
	}
	h.commitNodeFacetsLocked(n, fs)
	delete(h.tab.known, n.id) // still never seen
}

// reconfigure applies a changed NodeConfig (hub-admin 2.2).
func (h *Hub) reconfigure(n *node, old *admin.NodeConfig) {
	h.mu.Lock()
	nc := n.cfg
	if _, seen := h.tab.known[n.id]; !seen {
		h.listConfiguredFacetsLocked(n)
	}
	h.mu.Unlock()
	startChanged := !bytes.Equal(encStart(old.Start), encStart(nc.Start)) || old.IsPeer() != nc.IsPeer()
	switch {
	case !nc.IsEnabled():
		n.stopLink()
		n.setState(admin.Disabled, "")
	case !old.IsEnabled() || startChanged:
		// A spawned node is stopped before its new process starts; a
		// dialed node is dialed again and the new session supersedes the
		// old one (the old one closes when it is stopped).
		n.restart()
	}
}

func encStart(s *admin.Start) []byte {
	if s == nil {
		return nil
	}
	return s.AppendTo(nil)
}

// LazyExtension is the node extension that makes a spawned node start on
// its first call instead of at once (CBOR true).
const LazyExtension = "ref.lazy"

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
	case nodeID != "" && key == LazyExtension:
		if b, err := cbor.NewDecoder(v).Bool(); err != nil || len(v) != 1 {
			return errors.New("ref.lazy is a CBOR bool")
		} else {
			_ = b
		}
		return nil
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

func (n *node) lazy() bool {
	v, ok := n.cfg.Extensions[LazyExtension]
	return ok && len(v) == 1 && v[0] == 0xf5
}

// begin starts a new node as its configuration says.
func (n *node) begin() {
	switch {
	case !n.cfg.IsEnabled():
		n.setState(admin.Disabled, "")
	case n.cfg.Start == nil:
		n.setState(admin.Offline, "waiting for the node to dial in")
	case n.cfg.Start.Spawn != nil && n.lazy():
		n.setState(admin.Offline, "starts on its first call")
	default:
		n.restart()
	}
}

// ensureStarted starts a spawned node that is not running (10.7).
func (n *node) ensureStarted() {
	h := n.h
	h.mu.Lock()
	sup := n.sup
	ok := h.nodes[n.id] == n && n.cfg.IsEnabled() && n.cfg.Start != nil && n.cfg.Start.Spawn != nil
	h.mu.Unlock()
	if !ok {
		return
	}
	if sup != nil && !sup.finished() {
		return
	}
	if sup != nil && sup.failed {
		return // marked failed: only a new configuration starts it again
	}
	n.restart()
}

// stopLink stops the node's supervisor and ends its sessions.
func (n *node) stopLink() {
	h := n.h
	h.mu.Lock()
	sup := n.sup
	n.sup = nil
	l := n.link
	if l != nil {
		// New calls wait for the next session (10.7).
		n.link = nil
		n.ready = make(chan struct{})
	}
	h.mu.Unlock()
	if sup != nil {
		sup.stop()
	}
	if l != nil {
		l.sess.GoAway(status.GoingAway, "node removed, disabled or reconfigured", nil)
	}
}

func (n *node) waitStopped(d time.Duration) {
	n.h.mu.Lock()
	sup := n.sup
	n.h.mu.Unlock()
	if sup != nil {
		sup.wait(d)
	}
}

// restart stops the current supervisor (waiting for a spawned process to
// exit) and starts a new one for the current configuration.
func (n *node) restart() {
	h := n.h
	h.mu.Lock()
	old := n.sup
	cfg := n.cfg
	if h.nodes[n.id] != n || h.closed || cfg.Start == nil || !cfg.IsEnabled() {
		h.mu.Unlock()
		return
	}
	s := &supervisor{n: n, done: make(chan struct{})}
	s.ctx, s.cancel = context.WithCancel(h.ctx)
	n.sup = s
	if old != nil && n.link != nil && n.link.kind == linkSpawn {
		// The old process is being stopped: new calls wait for the new
		// one (10.7).
		n.link = nil
		n.ready = make(chan struct{})
	}
	h.mu.Unlock()
	go func() {
		if old != nil {
			old.stop()
			old.wait(30 * time.Second) // never run a node twice (10.7)
		}
		switch {
		case cfg.Start.Spawn != nil:
			s.runSpawn(cfg.Start.Spawn)
		case cfg.Start.Dial != nil:
			s.runDial(cfg.Start.Dial)
		default:
			close(s.done)
		}
	}()
}

// supervisor runs one spawned process or one dial loop.
type supervisor struct {
	n      *node
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	failed bool
	mu     sync.Mutex
	sess   *session.Session
}

func (s *supervisor) stop() {
	s.cancel()
	s.mu.Lock()
	sess := s.sess
	s.mu.Unlock()
	if sess != nil {
		sess.GoAway(status.GoingAway, "node stopped by the hub", nil)
	}
}

func (s *supervisor) wait(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
	}
}

func (s *supervisor) finished() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *supervisor) setSession(sess *session.Session) {
	s.mu.Lock()
	s.sess = sess
	s.mu.Unlock()
}

// Crash policy (reference-server note, section 3): restart with backoff,
// failed after 5 crashes within a minute.
const (
	crashLimit  = 5
	crashWindow = time.Minute
)

func backoff(attempt int) time.Duration {
	d := 250 * time.Millisecond << min(attempt, 7)
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (s *supervisor) runSpawn(sp *admin.Spawn) {
	defer close(s.done)
	n := s.n
	h := n.h
	var crashes []time.Time
	for attempt := 0; ; attempt++ {
		if s.ctx.Err() != nil {
			return
		}
		n.setState(admin.Starting, "")
		clean, err := s.spawnOnce(sp)
		if s.ctx.Err() != nil {
			return
		}
		if clean {
			n.setState(admin.Offline, "exited; starts again on the next call")
			return
		}
		now := time.Now()
		crashes = append(crashes, now)
		for len(crashes) > 0 && now.Sub(crashes[0]) > crashWindow {
			crashes = crashes[1:]
		}
		msg := "crashed"
		if err != nil {
			msg = err.Error()
		}
		h.log.Warn("spawned node ended", "node", n.id, "err", msg)
		if len(crashes) >= crashLimit {
			s.failed = true
			n.setState(admin.Failed, fmt.Sprintf("%d crashes within a minute: %s", len(crashes), msg))
			return
		}
		n.setState(admin.Offline, msg)
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff(len(crashes))):
		}
	}
}

// spawnOnce runs the process once; clean reports a deliberate exit (status
// 0 after the session ended with GoAway from the node).
func (s *supervisor) spawnOnce(sp *admin.Spawn) (clean bool, err error) {
	n := s.n
	h := n.h
	cmd := exec.Command(sp.Command[0], sp.Command[1:]...)
	if sp.Dir != nil {
		cmd.Dir = *sp.Dir
	}
	env := os.Environ()
	for _, k := range sortedEnv(sp.Env) {
		v := sp.Env[k]
		val := v.Value
		if v.Secret {
			b, ok := h.adm.SecretValue(v.Value)
			if !ok {
				return false, fmt.Errorf("secret %q is missing", v.Value)
			}
			val = string(b)
		}
		env = append(env, k+"="+val)
	}
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr io.WriteCloser
	if h.o.SpawnStderr != nil {
		cmd.Stderr = h.o.SpawnStderr
	} else {
		pr, pw := io.Pipe()
		stderr = pw
		cmd.Stderr = pw
		go func() {
			sc := bufio.NewScanner(pr)
			for sc.Scan() {
				h.log.Info("node stderr", "node", n.id, "line", sc.Text())
			}
		}()
	}
	conn, err := pipe.Spawn(cmd)
	if err != nil {
		if stderr != nil {
			stderr.Close()
		}
		return false, err
	}
	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
		if stderr != nil {
			stderr.Close()
		}
	}()
	v := &viewer{h: h, node: n, kind: kindFor(n)}
	cfg := h.nodeServerConfig(v, func(ctx context.Context, hello *wire.Hello) (string, error) {
		// The process is the node it was configured as (10.2).
		return names.NodePrincipal(n.id), nil
	})
	sess, err := session.NewServer(s.ctx, conn, cfg)
	if err != nil {
		h.removeViewer(v)
		_ = conn.Close(status.Unavailable, "handshake failed")
		killAfter(cmd, exited, 2*time.Second)
		return false, err
	}
	v.setSession(sess)
	s.setSession(sess)
	l := &link{n: n, sess: sess, v: v, kind: linkSpawn}
	v.link = l
	h.attach(n, l)
	select {
	case <-sess.Done():
	case <-s.ctx.Done():
		sess.GoAway(status.GoingAway, "node stopped by the hub", nil)
		select {
		case <-sess.Done():
		case <-time.After(5 * time.Second):
			sess.Close(status.GoingAway, "node stopped by the hub")
		}
	}
	err = killAfter(cmd, exited, 5*time.Second)
	g := sess.GoAwayReceived()
	clean = err == nil && g != nil && (status.Code(g.Status) == status.OK || status.Code(g.Status) == status.GoingAway)
	return clean, err
}

// killAfter waits for the process to exit, killing it (and its process
// group) after d.
func killAfter(cmd *exec.Cmd, exited chan error, d time.Duration) error {
	select {
	case err := <-exited:
		return err
	case <-time.After(d):
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
		}
		return <-exited
	}
}

func sortedEnv(m map[string]admin.EnvValue) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sortStrings(ks)
	return ks
}

// nodeServerConfig is the session configuration for a node the hub serves
// (spawned).
func (h *Hub) nodeServerConfig(v *viewer, auth func(context.Context, *wire.Hello) (string, error)) session.Config {
	cfg := session.Config{
		Handler:             &sessHandler{h: h, v: v},
		Authenticate:        auth,
		MaxClientSchemaSize: -1,
		SchemaFor: func(ctx context.Context, principal string, hello *wire.Hello) (*schema.Schema, error) {
			h.addViewer(v)
			return h.viewFor(v), nil
		},
		AcceptClientSchema: func(ctx context.Context, principal string, s *schema.Schema) error {
			_, err := h.checkNodeFacets(v.node, s)
			return err
		},
		OnPeerSchemaUpdate: func(ctx context.Context, s *session.Session, u *session.PeerSchemaUpdate) error {
			return h.nodeSchemaUpdate(v, u)
		},
	}
	h.sessionConfig(&cfg)
	return cfg
}

// runDial keeps a dialed node connected (10.2): WebTransport for https,
// WebSocket for wss, the SPKI pin verified on every connection, and
// ["link", credential] presented in Hello.
func (s *supervisor) runDial(d *admin.Dial) {
	defer close(s.done)
	n := s.n
	h := n.h
	for attempt := 0; ; attempt++ {
		if s.ctx.Err() != nil {
			return
		}
		n.setState(admin.Starting, "dialing "+d.URL)
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
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff(attempt)):
		}
	}
}

func (s *supervisor) dialOnce(d *admin.Dial) error {
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
	v.link = l
	h.attach(n, l)
	select {
	case <-sess.Done():
	case <-s.ctx.Done():
		sess.GoAway(status.GoingAway, "node link stopped by the hub", nil)
		select {
		case <-sess.Done():
		case <-time.After(5 * time.Second):
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
