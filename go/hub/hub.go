// Package hub implements the Sparrow Hub Profile (core spec, section 10):
// node links (spawned processes over pipes, nodes that dial in, nodes the
// hub dials), composition of per-session schemas with stable facet IDs,
// authorization with a pluggable Policy, forwarding by rewriting envelopes,
// call contexts, offline and starting nodes, federation with peer hubs, and
// the sparrow.hub.admin facet (package admin) that configures all of it.
//
// A Hub serves any transport connection (ServeConn); package
// cmd/sparrow-hub puts it behind WebTransport and WebSocket listeners.
package hub

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

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
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Relay acknowledgement limits (10.3).
const (
	DefaultRelayAckTimeout     = 5 * time.Second
	DefaultPeerRelayAckTimeout = 2 * time.Second
)

// Credential maps a bearer token to a principal and its groups.
type Credential struct {
	Token     string
	Principal string
	Groups    []string
}

// Options configure a Hub. Everything not here arrives through
// sparrow.hub.admin.
type Options struct {
	// SchemaName and SchemaVersion name the schema documents the hub sends
	// (default "sparrow-hub", "1").
	SchemaName, SchemaVersion string
	// Store is the data directory (hub-admin 2.4). Required.
	Store *admin.Store
	// Bootstrap administrators are always allowed every method of
	// sparrow.hub.admin (hub-admin section 1). At least one is required;
	// each authenticates with ["bearer", Token].
	Bootstrap []Credential
	// Tokens are further bearer credentials for clients.
	Tokens []Credential
	// Authenticate, if set, handles every Hello (and AuthRefresh) whose
	// scheme is not "link" and not a static token, for example a Web
	// Profile ticket. An Actor with Expires set ends the session at that
	// time unless AuthRefresh extends it (5.5).
	Authenticate func(ctx context.Context, h *wire.Hello) (Actor, error)
	// ExpiryWarning is how long before a session's authentication expires
	// the hub sends AuthStatus (5.5: at least 60 s); default 60 s.
	ExpiryWarning time.Duration
	// Policy replaces the built-in grant policy (ref.policy). Call
	// Hub.PolicyChanged when its decisions change.
	Policy Policy
	// Web publishes facet 1 sparrow.web (Web Profile 9.4) and the
	// top-level web.* annotations of the document extension ref.web.
	Web bool
	// WebRoots are the root keys of the client build, if the operator
	// gives them: ref.web certificates and revocation lists must then be
	// signed by one of them.
	WebRoots [][]byte
	// OnModuleRejected is called for every moduleRejected notification a
	// client sends (9.4), after it is logged.
	OnModuleRejected func(principal, id, version, reason string)
	// StartTimeout bounds how long a call waits for a node that is not
	// connected (10.7); default 10 s.
	StartTimeout time.Duration
	// AdminFacetID fixes the facet ID of sparrow.hub.admin (0 allocates
	// one from the facet-ID table, normally 16).
	AdminFacetID uint64
	// Clock drives confirmation deadlines and call-context expiry; nil is
	// the wall clock.
	Clock session.Clock
	// Session adjusts the configuration of every session the hub runs.
	Session func(*session.Config)
	// SpawnStderr receives the standard error of spawned nodes (default:
	// the logger, line by line).
	SpawnStderr io.Writer
	Logger      *slog.Logger
	// CredentialCheckInterval is how often dial-in credentials are
	// re-validated (10.2: at least every 60 s); default 30 s.
	CredentialCheckInterval time.Duration
	// RelayAckTimeout is the time each downstream session gets to ack a
	// node's relayed SchemaUpdate, or the change a superseding session of
	// a node brings (10.3); default 5 s.
	RelayAckTimeout time.Duration
	// PeerRelayAckTimeout is the same for an update relayed from a peer
	// hub (10.3); default 2 s.
	PeerRelayAckTimeout time.Duration
}

// Hub is a running hub.
type Hub struct {
	o     Options
	log   *slog.Logger
	clock session.Clock
	adm   *admin.Manager
	admH  session.Handler
	ctx   context.Context
	stop  context.CancelFunc

	mu         sync.Mutex
	tab        *table
	cfg        *admin.Config
	rev        uint64
	nodes      map[string]*node
	viewers    map[*viewer]struct{}
	policy     *hubPolicy
	ifaces     map[string]*schema.Interface // interface hash -> interface
	calls      map[*activeCall]struct{}
	contexts   map[string]*callContext
	adminID    uint64
	rejections int
	closed     bool
	conns      map[transport.Conn]struct{} // connections ServeConn runs
	wg         sync.WaitGroup
	reconcile  sync.Mutex // serializes Apply
}

// New opens the hub's state from the store and applies the persisted
// document. Close stops it.
func New(o Options) (*Hub, error) {
	if o.Store == nil {
		return nil, errors.New("hub: Options.Store is required")
	}
	if len(o.Bootstrap) == 0 {
		return nil, errors.New("hub: at least one bootstrap administrator is required")
	}
	for _, b := range o.Bootstrap {
		if !names.IsPrincipal(b.Principal) || b.Token == "" {
			return nil, fmt.Errorf("hub: bad bootstrap administrator %q", b.Principal)
		}
	}
	if o.SchemaName == "" {
		o.SchemaName = "sparrow-hub"
	}
	if o.SchemaVersion == "" {
		o.SchemaVersion = "1"
	}
	if o.StartTimeout <= 0 {
		o.StartTimeout = 10 * time.Second
	}
	if o.CredentialCheckInterval <= 0 {
		o.CredentialCheckInterval = 30 * time.Second
	}
	if o.RelayAckTimeout <= 0 {
		o.RelayAckTimeout = DefaultRelayAckTimeout
	}
	if o.ExpiryWarning <= 0 {
		o.ExpiryWarning = 60 * time.Second
	}
	if o.PeerRelayAckTimeout <= 0 {
		o.PeerRelayAckTimeout = DefaultPeerRelayAckTimeout
	}
	h := &Hub{o: o, log: o.Logger, clock: o.Clock, nodes: map[string]*node{}, viewers: map[*viewer]struct{}{}, conns: map[transport.Conn]struct{}{},
		ifaces: map[string]*schema.Interface{}, calls: map[*activeCall]struct{}{},
		contexts: map[string]*callContext{}}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	if h.clock == nil {
		h.clock = session.RealClock{}
	}
	h.ctx, h.stop = context.WithCancel(context.Background())
	boot := map[string]bool{}
	for _, b := range o.Bootstrap {
		boot[b.Principal] = true
	}
	h.policy = &hubPolicy{inner: o.Policy, bootstrap: boot}
	if o.Policy == nil {
		h.policy.inner = &GrantPolicy{}
	}
	tab, err := newTable(o.Store)
	if err != nil {
		return nil, err
	}
	h.tab = tab
	ak := facetKey{node: "", name: adminiface.Name, major: schema.Major(adminiface.Version)}
	if o.AdminFacetID != 0 {
		if o.AdminFacetID < schema.FirstFreeFacetID {
			return nil, errors.New("hub: AdminFacetID must be 16 or more")
		}
		for k, id := range tab.ids {
			if id == o.AdminFacetID && k != ak {
				return nil, fmt.Errorf("hub: facet ID %d is taken by %s/%s", id, k.node, k.name)
			}
		}
		tab.fix(ak, o.AdminFacetID)
	}
	h.adminID = tab.allocate(ak)
	ai := adminiface.Interface()
	ah, _ := ai.Hash()
	h.ifaces[string(ah)] = ai
	if err := tab.save(); err != nil {
		return nil, err
	}
	h.adm, err = admin.NewManager(admin.Options{Store: o.Store, Clock: o.Clock, Logger: h.log,
		Extension: h.validateExtension, OtherKind: func(string, []byte) error { return admin.ErrUnsupported }})
	if err != nil {
		return nil, err
	}
	h.admH = h.adm.Handler()
	h.adm.Start(h)
	h.wg.Add(1)
	go h.credentialLoop()
	return h, nil
}

// SchemaFor returns the schema a client session of this principal gets
// (for the Web Profile's /connect and schema resources, package web). An
// empty principal is the anonymous viewer: only what everyone may see.
func (h *Hub) SchemaFor(principal string, groups []string) (*schema.Schema, error) {
	return h.viewFor(&viewer{h: h, kind: viewClient, actor: Actor{Principal: principal, Groups: groups}}), nil
}

// Admin returns the administration manager.
func (h *Hub) Admin() *admin.Manager { return h.adm }

// AdminFacetID returns the facet ID of sparrow.hub.admin.
func (h *Hub) AdminFacetID() uint64 { return h.adminID }

// Close shuts the hub down: GoAway(going_away) to every session, nodes
// stopped (spawned processes get GoAway and are waited for), and every
// session closed within timeout.
func (h *Hub) Close(timeout time.Duration) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	vs := h.viewerListLocked()
	conns := make([]transport.Conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	nodes := make([]*node, 0, len(h.nodes))
	for _, n := range h.nodes {
		nodes = append(nodes, n)
	}
	h.mu.Unlock()
	for _, v := range vs {
		if s := v.session(); s != nil {
			s.GoAway(status.GoingAway, "hub shutting down", nil)
		}
	}
	var sups []*supervisor
	for _, n := range nodes {
		if s := n.stopLink(); s != nil {
			sups = append(sups, s)
		}
	}
	deadline := time.Now().Add(timeout)
	for _, v := range vs {
		s := v.session()
		if s == nil && v.hsDone != nil {
			// A client whose handshake is still running (its Ready not yet
			// processed) may already consider the session open: wait for
			// the handshake, then send it GoAway too (5.6).
			select {
			case <-v.hsDone:
			case <-time.After(time.Until(deadline)):
			}
			if s = v.session(); s != nil {
				s.GoAway(status.GoingAway, "hub shutting down", nil)
			}
		}
		if s != nil {
			select {
			case <-s.Done():
			case <-time.After(time.Until(deadline)):
				s.Close(status.GoingAway, "hub shut down")
			}
		}
	}
	// A session is done before its transport has finished closing: the
	// WebTransport binding still finishes the shared lane and waits for the
	// peer's finish (up to its linger time) so that GoAway, written just
	// before, reaches the peer. Returning earlier lets the program exit
	// with GoAway unsent and the peer left waiting for its idle timeout.
	connWait := time.Until(deadline)
	if connWait < 0 {
		connWait = 0
	}
	connWait += webtransport.DefaultLinger + time.Second
	connDeadline := time.After(connWait)
	for _, c := range conns {
		select {
		case <-c.Done():
		case <-connDeadline:
		}
	}
	for _, s := range sups {
		s.wait(time.Until(deadline) + 6*time.Second) // spawned processes exit (killed after 5 s)
	}
	h.stop()
	h.wg.Wait()
}

func (h *Hub) closing() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func (h *Hub) sessionConfig(cfg *session.Config) {
	cfg.Logger = h.log
	if h.o.Session != nil {
		h.o.Session(cfg)
	}
}

// ---------------------------------------------------------------------------
// Accepting connections: clients and dial-in nodes (10.2)
// ---------------------------------------------------------------------------

// ServeConn runs one accepted connection (WebTransport, WebSocket or any
// binding) until its session ends: a client, or a node or peer hub that
// dials in with ["link", credential].
func (h *Hub) ServeConn(ctx context.Context, conn transport.Conn) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = conn.Close(status.GoingAway, "hub shutting down")
		return
	}
	h.conns[conn] = struct{}{}
	h.mu.Unlock()
	defer func() {
		// Until the transport has closed (Close waits for it).
		t := time.NewTimer(webtransport.DefaultLinger + time.Second)
		select {
		case <-conn.Done():
		case <-t.C:
		}
		t.Stop()
		h.mu.Lock()
		delete(h.conns, conn)
		h.mu.Unlock()
	}()
	v := &viewer{h: h, hsDone: make(chan struct{})}
	var dialIn *node
	var dialCred []byte
	cfg := session.Config{
		Handler: &sessHandler{h: h, v: v},
		Authenticate: func(ctx context.Context, hello *wire.Hello) (string, error) {
			a, n, cred, err := h.authenticate(ctx, hello)
			if err != nil {
				return "", err
			}
			if n != nil {
				v.node = n
				v.kind = kindFor(n)
				dialIn, dialCred = n, cred
				return names.NodePrincipal(n.id), nil
			}
			v.kind = viewClient
			v.smu.Lock()
			v.actor = a
			v.smu.Unlock()
			return a.Principal, nil
		},
		ClientSchemaLimit: func(principal string) int {
			if v.node != nil {
				return -1 // no 64 KiB limit between a hub and its nodes (10.2)
			}
			return 0
		},
		SchemaFor: func(ctx context.Context, principal string, hello *wire.Hello) (*schema.Schema, error) {
			if !h.addOpenViewer(v) {
				return nil, &session.Error{Code: status.GoingAway, Message: "hub shutting down"}
			}
			return h.viewFor(v), nil
		},
		AcceptClientSchema: func(ctx context.Context, principal string, s *schema.Schema) error {
			if v.node == nil {
				return nil // client facets are scoped to the session (10.3)
			}
			_, err := h.checkNodeFacets(v.node, s)
			return err
		},
		OnPeerSchemaUpdate: func(ctx context.Context, s *session.Session, u *session.PeerSchemaUpdate) error {
			if v.node == nil {
				return nil
			}
			return h.nodeSchemaUpdate(v, u)
		},
		OnAuthRefresh: func(ctx context.Context, s *session.Session, a *wire.Auth) (*wire.AuthStatus, error) {
			return h.authRefresh(ctx, v, s, a)
		},
	}
	h.sessionConfig(&cfg)
	s, err := session.NewServer(ctx, conn, cfg)
	if err != nil {
		close(v.hsDone)
		h.removeViewer(v)
		h.log.Debug("handshake failed", "err", err)
		return
	}
	v.setSession(s)
	close(v.hsDone)
	if h.closing() {
		// Close began while the handshake ran (it waits for this session).
		s.GoAway(status.GoingAway, "hub shutting down", nil)
	}
	if dialIn != nil {
		l := &link{n: dialIn, sess: s, v: v, kind: linkDialIn, cred: dialCred, credName: dialIn.credentialName()}
		h.attach(dialIn, l)
	} else {
		h.armExpiry(v, s)
		go v.refresh(0)
	}
	<-s.Done()
	v.stopExpiry()
	h.removeViewer(v)
}

// authRefresh handles AuthRefresh (5.5): the new credential must be for the
// same principal and login session as the original one, and then extends
// the session's expiry; anything else closes the session with
// GoAway(unauthenticated).
func (h *Hub) authRefresh(ctx context.Context, v *viewer, s *session.Session, a *wire.Auth) (*wire.AuthStatus, error) {
	if v.kind != viewClient {
		return nil, &session.Error{Code: status.Unauthenticated, Message: "a node link does not refresh its credential"}
	}
	hello := wire.Hello{}
	if old := s.Hello(); old != nil {
		hello = *old
	}
	hello.Auth = a
	na, n, _, err := h.authenticate(ctx, &hello)
	if err != nil {
		return nil, err
	}
	v.smu.Lock()
	old := v.actor
	v.smu.Unlock()
	if n != nil || na.Principal != old.Principal || na.LoginSession != old.LoginSession {
		return nil, &session.Error{Code: status.Unauthenticated, Message: "AuthRefresh must present a credential for the same principal and login session"}
	}
	v.smu.Lock()
	groupsChanged := strings.Join(v.actor.Groups, "\x00") != strings.Join(na.Groups, "\x00")
	v.actor.Expires = na.Expires
	v.actor.Groups = na.Groups
	v.smu.Unlock()
	h.armExpiry(v, s)
	if groupsChanged {
		go func() { // permissions changed (5.5)
			v.refresh(0)
			h.recheckCalls()
		}()
	}
	st := &wire.AuthStatus{Status: uint64(status.OK)}
	if !na.Expires.IsZero() {
		t := cbor.Unix(na.Expires.Unix())
		st.ExpiresAt = &t
	}
	return st, nil
}

// armExpiry schedules the AuthStatus warning and the end of a client
// session whose authentication expires (5.5).
func (h *Hub) armExpiry(v *viewer, s *session.Session) {
	v.smu.Lock()
	defer v.smu.Unlock()
	for _, t := range v.expiry {
		t.Stop()
	}
	v.expiry = nil
	exp := v.actor.Expires
	if exp.IsZero() {
		return
	}
	left := exp.Sub(h.clock.Now())
	if left <= 0 {
		go s.GoAway(status.Unauthenticated, "the login session has ended", nil)
		return
	}
	at := cbor.Unix(exp.Unix())
	warn := left - h.o.ExpiryWarning
	if warn < 0 {
		warn = 0
	}
	v.expiry = append(v.expiry,
		h.clock.AfterFunc(warn, func() {
			_ = s.SendAuthStatus(&wire.AuthStatus{Status: uint64(status.OK), ExpiresAt: &at})
		}),
		h.clock.AfterFunc(left, func() {
			s.GoAway(status.Unauthenticated, "the login session has ended", nil)
		}))
}

// EndLoginSession closes every client session of a login session with
// GoAway(unauthenticated), for a host that revokes a sid at logout (9.2).
func (h *Hub) EndLoginSession(sid string) int {
	if sid == "" {
		return 0
	}
	h.mu.Lock()
	var ss []*session.Session
	for v := range h.viewers {
		v.smu.Lock()
		match := v.kind == viewClient && v.actor.LoginSession == sid
		v.smu.Unlock()
		if s := v.session(); match && s != nil {
			ss = append(ss, s)
		}
	}
	h.mu.Unlock()
	for _, s := range ss {
		s.GoAway(status.Unauthenticated, "logged out", nil)
	}
	return len(ss)
}

// authenticate maps Hello.auth to a client actor or a dial-in node.
func (h *Hub) authenticate(ctx context.Context, hello *wire.Hello) (Actor, *node, []byte, error) {
	if hello.Auth == nil {
		if h.o.Authenticate != nil {
			return h.customAuth(ctx, hello)
		}
		return Actor{}, nil, nil, &session.Error{Code: status.Unauthenticated, Message: "a credential is required"}
	}
	switch hello.Auth.Scheme {
	case "link":
		cred, ok := credentialBytes(hello.Auth.Credentials)
		if !ok {
			return Actor{}, nil, nil, &session.Error{Code: status.Unauthenticated, Message: "a link credential is a string or bytes"}
		}
		n, err := h.nodeForCredential(cred)
		return Actor{}, n, cred, err
	case "bearer":
		tok, ok := credentialBytes(hello.Auth.Credentials)
		if ok {
			for _, list := range [][]Credential{h.o.Bootstrap, h.o.Tokens} {
				for _, c := range list {
					if subtle.ConstantTimeCompare([]byte(c.Token), tok) == 1 {
						return Actor{Principal: c.Principal, Groups: c.Groups}, nil, nil, nil
					}
				}
			}
		}
	}
	if h.o.Authenticate != nil {
		return h.customAuth(ctx, hello)
	}
	return Actor{}, nil, nil, &session.Error{Code: status.Unauthenticated, Message: "credential rejected"}
}

func (h *Hub) customAuth(ctx context.Context, hello *wire.Hello) (Actor, *node, []byte, error) {
	a, err := h.o.Authenticate(ctx, hello)
	if err != nil {
		return Actor{}, nil, nil, err
	}
	if !names.IsPrincipal(a.Principal) || hasPrefix(a.Principal, "peer:") || hasPrefix(a.Principal, "node:") {
		return Actor{}, nil, nil, &session.Error{Code: status.Unauthenticated, Message: "the authenticator returned a principal a client cannot have"}
	}
	return a, nil, nil, nil
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func credentialBytes(raw cbor.Raw) ([]byte, bool) {
	d := cbor.NewDecoder(raw)
	if m, err := d.PeekMajor(); err == nil {
		switch m {
		case cbor.MajorText:
			s, err := d.Text()
			return []byte(s), err == nil
		case cbor.MajorBytes:
			b, err := d.Bytes()
			return b, err == nil
		}
	}
	return nil, false
}

// nodeForCredential finds the dial-in node a link credential belongs to.
func (h *Hub) nodeForCredential(cred []byte) (*node, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, id := range sortedNodeIDs(h.nodes) {
		n := h.nodes[id]
		name := n.credentialName()
		if name == "" {
			continue
		}
		v, ok := h.adm.SecretValue(name)
		if ok && subtle.ConstantTimeCompare(v, cred) == 1 {
			if !n.cfg.IsEnabled() {
				return nil, &session.Error{Code: status.FailedPrecondition, Message: "node " + id + " is disabled"}
			}
			return n, nil
		}
	}
	// Only a node configured to dial in has a dial-in credential (10.2).
	return nil, &session.Error{Code: status.Unauthenticated, Message: "unknown link credential"}
}

func sortedNodeIDs(m map[string]*node) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// credentialLoop re-validates dial-in credentials (10.2: at least every
// 60 s); Apply also does it at once on every change.
func (h *Hub) credentialLoop() {
	defer h.wg.Done()
	t := time.NewTicker(h.o.CredentialCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-t.C:
			h.revalidateCredentials()
		}
	}
}

// revalidateCredentials closes every dial-in session whose credential is
// no longer the configured one, with GoAway(unauthenticated).
func (h *Hub) revalidateCredentials() {
	h.mu.Lock()
	var bad []*link
	for v := range h.viewers {
		l := v.link
		if l == nil || l.kind != linkDialIn {
			continue
		}
		n := h.nodes[l.n.id]
		ok := n == l.n && n.credentialName() != "" && n.credentialName() == l.credName
		if ok {
			val, found := h.adm.SecretValue(l.credName)
			ok = found && bytes.Equal(val, l.cred)
		}
		if !ok {
			bad = append(bad, l)
		}
	}
	h.mu.Unlock()
	for _, l := range bad {
		h.log.Info("dial-in credential revoked or changed", "node", l.n.id)
		l.sess.Close(status.Unauthenticated, "the link credential was revoked or changed")
	}
}

// ---------------------------------------------------------------------------
// HTTP endpoints
// ---------------------------------------------------------------------------

// WebSocketHandler returns an http.Handler that accepts Sparrow WebSocket
// connections (4.6). checkOrigin may be nil for the default same-origin
// check.
func (h *Hub) WebSocketHandler(checkOrigin func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CheckOrigin: checkOrigin})
		if err != nil {
			return
		}
		h.ServeConn(h.ctx, c)
	})
}

// WebTransportHandler returns the handler to mount on a WebTransport
// server's HTTP/3 handler at the session path.
func (h *Hub) WebTransportHandler(s *webtransport.Server) http.Handler {
	return s.Handler(func(c *webtransport.Conn, r *http.Request) { h.ServeConn(h.ctx, c) })
}
