package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// ContextGrace is how long a call context stays valid after its call ends
// (10.6).
const ContextGrace = 2 * time.Second

// callContext is a context the hub issued for a call it forwarded to a
// node (10.6).
type callContext struct {
	key      string
	link     *link // valid only on the link it was issued on
	actor    Actor // the principal the call acts for
	deadline time.Time
	open     bool
	endedAt  time.Time
	nested   map[*activeCall]struct{} // calls the node made with it
}

// activeCall is a call the hub is handling: authorized for its acting
// principals, forwarded or served by the hub.
type activeCall struct {
	v      *viewer
	actors []Actor
	facet  uint64
	method *schema.Method
	in     *session.ServerCall
	out    *session.ClientCall // nil for a call the hub serves itself
	ctx    *callContext        // the context it carries, if any
	once   sync.Once
}

// end finishes both calls with code: Error toward the caller and Cancel
// toward the node (10.4, 10.6).
func (a *activeCall) end(code status.Code, msg string) {
	a.once.Do(func() {
		_ = a.in.Fail(&session.Error{Code: code, Message: msg})
		if a.out != nil {
			_ = a.out.Cancel(code)
		}
	})
}

// sessHandler serves every call a session makes to the hub (10.4, 10.5).
type sessHandler struct {
	h *Hub
	v *viewer
}

func (sh *sessHandler) ServeCall(ctx context.Context, c *session.ServerCall) {
	h, v := sh.h, sh.v
	start := time.Now()
	deny := func(code status.Code, msg string) {
		if !c.Notification() {
			_ = c.Fail(&session.Error{Code: code, Message: msg})
		}
	}
	actors, cc, err := h.actingPrincipals(v, c)
	if err != nil {
		deny(status.PermissionDenied, err.Error())
		return
	}
	h.mu.Lock()
	lf, n := h.facetLocked(c.FacetID())
	pol := h.policy
	h.mu.Unlock()
	if lf == nil || c.Method() == nil {
		deny(status.Unimplemented, fmt.Sprintf("facet %d is not listed", c.FacetID()))
		return
	}
	for _, a := range actors {
		if !pol.Visible(a, lf.ref) || !pol.Allowed(a, lf.ref, c.Method()) {
			deny(status.PermissionDenied, fmt.Sprintf("%s may not call %s method %d", a.Principal, lf.ref.Name, c.MethodID()))
			return
		}
	}
	if n == nil {
		h.serveOwn(ctx, v, c, actors, cc, lf)
		return
	}
	if n.cfg.IsPeer() && hasPrefix(forwardActor(actors).Principal, "peer:") {
		// A call acting for a peer's principal never goes on to another
		// peer (10.8).
		deny(status.PermissionDenied, "a call acting for "+forwardActor(actors).Principal+" is not forwarded to another peer hub (10.8)")
		return
	}
	if c.Notification() {
		h.forwardNotification(v, c, actors, n, lf)
		return
	}
	h.forward(ctx, start, v, c, actors, cc, n, lf)
}

// actingPrincipals returns the principals a call acts for (10.4), and the
// context it carries if it came from a node with a valid one. The hub
// derives them only from the link and from contexts it issued.
func (h *Hub) actingPrincipals(v *viewer, c *session.ServerCall) ([]Actor, *callContext, error) {
	switch v.kind {
	case viewClient:
		return []Actor{v.clientActor()}, nil, nil
	case viewNode:
		self := Actor{Principal: names.NodePrincipal(v.node.id)}
		raw, ok := c.CallContext()
		if !ok {
			if _, has := c.Metadata()[wire.SigilKey(wire.KeyContext)]; has {
				return nil, nil, errors.New("malformed context")
			}
			return []Actor{self}, nil, nil
		}
		h.mu.Lock()
		cc := h.contexts[string(raw)]
		valid := cc != nil && cc.link == v.link && h.contextValidLocked(cc)
		h.mu.Unlock()
		if !valid {
			// Never a fallback to the node's own principal (10.6).
			return nil, nil, errors.New("unknown or expired call context")
		}
		return []Actor{self, cc.actor}, cc, nil
	case viewPeer:
		self := Actor{Principal: names.NodePrincipal(v.node.id)}
		if _, has := c.Metadata()[wire.SigilKey(wire.KeyContext)]; has {
			// Contexts are issued per node link; a peer never carries one
			// (10.8).
			return nil, nil, errors.New("a call from a peer hub may not carry a context (10.8)")
		}
		p, ok, err := c.Metadata().Principal()
		if err != nil {
			return nil, nil, errors.New("malformed principal")
		}
		if !ok {
			return []Actor{self}, nil, nil
		}
		pp, ok := names.PeerPrincipal(v.node.id, p)
		if !ok {
			return nil, nil, fmt.Errorf("a peer may not act for %q (10.8)", p)
		}
		return []Actor{self, {Principal: pp}}, nil, nil
	}
	return nil, nil, errors.New("unknown session")
}

func (h *Hub) contextValidLocked(cc *callContext) bool {
	now := h.clock.Now()
	if !cc.deadline.IsZero() && !now.Before(cc.deadline) {
		return false
	}
	return cc.open || now.Before(cc.endedAt.Add(ContextGrace))
}

// forwardActor is the principal a forwarded call acts for (the principal
// key the hub sets, 10.6): the context's principal for a node with a
// context, the named peer principal for a peer hub, otherwise the caller
// itself. actingPrincipals puts it last.
func forwardActor(actors []Actor) Actor { return actors[len(actors)-1] }

func (h *Hub) track(a *activeCall) {
	h.mu.Lock()
	h.calls[a] = struct{}{}
	if a.ctx != nil {
		a.ctx.nested[a] = struct{}{}
	}
	h.mu.Unlock()
}

func (h *Hub) untrack(a *activeCall) {
	h.mu.Lock()
	delete(h.calls, a)
	if a.ctx != nil {
		delete(a.ctx.nested, a)
	}
	h.mu.Unlock()
}

// serveOwn serves a call to one of the hub's own facets.
func (h *Hub) serveOwn(ctx context.Context, v *viewer, c *session.ServerCall, actors []Actor, cc *callContext, lf *listedFacet) {
	switch lf.ref.Name {
	case schema.WebFacetName:
		if c.MethodID() == 0 {
			h.moduleRejected(actors[0].Principal, c)
		}
		return
	}
	a := &activeCall{v: v, actors: actors, facet: lf.ref.ID, method: c.Method(), in: c, ctx: cc}
	h.track(a)
	defer h.untrack(a)
	h.admH.ServeCall(ctx, c)
}

// moduleRejected handles the moduleRejected notification of facet 1
// (9.4): [id, version, reason], logged and passed to
// Options.OnModuleRejected. Anything else is dropped like a malformed
// notification.
func (h *Hub) moduleRejected(principal string, c *session.ServerCall) {
	in, err := c.Input()
	list, ok := in.([]any)
	if err != nil || !ok || len(list) != 3 {
		h.log.Debug("malformed moduleRejected dropped", "principal", principal)
		return
	}
	var s [3]string
	for i, v := range list {
		if s[i], ok = v.(string); !ok {
			h.log.Debug("malformed moduleRejected dropped", "principal", principal)
			return
		}
	}
	h.mu.Lock()
	h.rejections++
	h.mu.Unlock()
	h.log.Warn("a client rejected a module", "principal", principal, "module", s[0], "version", s[1], "reason", s[2])
	if f := h.o.OnModuleRejected; f != nil {
		f(principal, s[0], s[1], s[2])
	}
}

// forward forwards a call to the node that owns the facet (10.5).
func (h *Hub) forward(ctx context.Context, start time.Time, v *viewer, c *session.ServerCall, actors []Actor, cc *callContext, n *node, lf *listedFacet) {
	fail := func(code status.Code, msg string) { _ = c.Fail(&session.Error{Code: code, Message: msg}) }
	deadline, hasDeadline := c.Deadline()
	wait := h.o.ConnectTimeout
	if hasDeadline {
		if left := time.Until(deadline); left < wait {
			wait = left
		}
	}
	l, err := h.waitLink(ctx, n, wait)
	if err != nil {
		if hasDeadline && !time.Now().Before(deadline) {
			fail(status.DeadlineExceeded, "the deadline passed while waiting for the node to connect")
			return
		}
		fail(status.Unavailable, err.Error())
		return
	}
	local, ok := l.localID(lf.ref.ID)
	if !ok {
		fail(status.Unimplemented, fmt.Sprintf("node %s no longer publishes %s", n.id, lf.ref.Name))
		return
	}
	md := c.Metadata().Clone()
	for _, k := range []uint64{wire.KeyDeadline, wire.KeyCredit, wire.KeyContext, wire.KeyPrincipal} {
		md.Delete(wire.SigilKey(k))
	}
	act := forwardActor(actors)
	nc := &callContext{link: l, actor: act, open: true, nested: map[*activeCall]struct{}{}}
	if hasDeadline {
		// Lowered by the time already spent, start-up included (10.5).
		left := time.Until(deadline)
		if left <= 0 {
			fail(status.DeadlineExceeded, "deadline exceeded")
			return
		}
		ms := uint64(left.Milliseconds())
		if ms == 0 {
			ms = 1
		}
		md.SetDeadline(ms)
		nc.deadline = h.clock.Now().Add(left)
	}
	md.SetCredit(c.CallerCredit())
	toPeer := n.cfg.IsPeer()
	if !toPeer {
		// A peer hub gets no context: it could not use one, and refuses
		// a call that carries one (10.8).
		key := make([]byte, 16)
		_, _ = rand.Read(key)
		nc.key = string(key)
		md.SetContext(key)
		h.mu.Lock()
		h.contexts[nc.key] = nc
		h.mu.Unlock()
	}
	md.SetPrincipal(act.Principal)
	_ = start
	octx := context.WithoutCancel(ctx)
	out, err := l.sess.OpenRaw(octx, session.ForwardRequest(c, local, md), &session.CallOptions{ManualCredit: true})
	if err != nil {
		if !toPeer {
			h.endContext(nc)
		}
		code := session.Code(err)
		if code != status.MessageTooLarge {
			code = status.Unavailable
		}
		fail(code, "cannot forward the call: "+err.Error())
		return
	}
	a := &activeCall{v: v, actors: actors, facet: lf.ref.ID, method: c.Method(), in: c, out: out, ctx: cc}
	h.track(a)
	_ = session.Relay(ctx, c, out)
	h.untrack(a)
	if !toPeer {
		h.endContext(nc)
	}
}

// endContext starts the grace period of a context (10.6): it stays valid
// for 2 s, then every call still open that carries it is ended.
func (h *Hub) endContext(cc *callContext) {
	h.mu.Lock()
	cc.open = false
	cc.endedAt = h.clock.Now()
	h.mu.Unlock()
	h.clock.AfterFunc(ContextGrace, func() {
		h.mu.Lock()
		delete(h.contexts, cc.key)
		nested := make([]*activeCall, 0, len(cc.nested))
		for a := range cc.nested {
			nested = append(nested, a)
		}
		h.mu.Unlock()
		for _, a := range nested {
			a.end(status.PermissionDenied, "the call context expired")
		}
	})
}

// forwardNotification relays a notification best-effort (10.5): call ID 0
// on both hops, no context, the principal set.
func (h *Hub) forwardNotification(v *viewer, c *session.ServerCall, actors []Actor, n *node, lf *listedFacet) {
	h.mu.Lock()
	l := n.link
	h.mu.Unlock()
	if l == nil {
		return // best-effort: dropped while the node is not connected
	}
	local, ok := l.localID(lf.ref.ID)
	if !ok {
		return
	}
	md := c.Metadata().Clone()
	for _, k := range []uint64{wire.KeyDeadline, wire.KeyCredit, wire.KeyContext, wire.KeyPrincipal} {
		md.Delete(wire.SigilKey(k))
	}
	md.SetPrincipal(forwardActor(actors).Principal)
	_ = l.sess.NotifyRaw(session.ForwardRequest(c, local, md))
}

// recheckCalls ends every running call that one of its acting principals
// is no longer allowed to make (10.4).
func (h *Hub) recheckCalls() {
	h.mu.Lock()
	pol := h.policy
	var bad []*activeCall
	for a := range h.calls {
		if a.out == nil && a.method != nil && !a.method.InputEnds() && !a.method.OutputEnds() {
			// A unary call to the hub's own facet was authorized when it
			// arrived and has no stream to stop: it may be the very call
			// whose effect changed the decision (a commit revoking its own
			// grant), already applied, and ending it would report a change
			// that took effect as permission_denied.
			continue
		}
		lf, _ := h.facetLocked(a.facet)
		ok := lf != nil
		for _, act := range a.actors {
			if !ok {
				break
			}
			ok = pol.Visible(act, lf.ref) && pol.Allowed(act, lf.ref, a.method)
		}
		if !ok {
			bad = append(bad, a)
		}
	}
	h.mu.Unlock()
	for _, a := range bad {
		a.end(status.PermissionDenied, "permission withdrawn")
	}
}

// PolicyChanged re-evaluates a custom Policy (Options.Policy): schema
// updates for sessions whose view changed, and running calls that are no
// longer allowed are ended (10.4). It waits for the updates.
func (h *Hub) PolicyChanged() {
	h.refreshAll(0)
	h.recheckCalls()
}

// Stats is a snapshot for tests and metrics.
type Stats struct {
	Sessions    int
	ActiveCalls int
	// ModulesRejected counts moduleRejected notifications (9.4).
	ModulesRejected int
	Contexts        int
	Nodes           map[string]NodeStat
}

// NodeStat describes one node.
type NodeStat struct {
	State     string
	Connected bool
	Listed    []uint64
}

// Stats returns a snapshot.
func (h *Hub) Stats() Stats {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := Stats{Sessions: len(h.viewers), ActiveCalls: len(h.calls), Contexts: len(h.contexts), ModulesRejected: h.rejections, Nodes: map[string]NodeStat{}}
	for id, n := range h.nodes {
		st.Nodes[id] = NodeStat{State: n.state.String(), Connected: n.link != nil, Listed: append([]uint64{}, n.listed...)}
	}
	return st
}

// Sessions returns the hub-side session of every connected peer, sorted by
// principal, for tests.
func (h *Hub) Sessions() map[string][]*session.Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string][]*session.Session{}
	for v := range h.viewers {
		if s := v.session(); s != nil {
			p := v.visibility().Principal
			out[p] = append(out[p], s)
		}
	}
	for _, ss := range out {
		sort.Slice(ss, func(i, j int) bool { return string(ss[i].SessionID()) < string(ss[j].SessionID()) })
	}
	return out
}

func sortStrings(s []string) { sort.Strings(s) }
