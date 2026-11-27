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
	// Authenticate, if set, handles every Hello whose scheme is not "link"
	// and not a static token (for example a Web Profile ticket).
	Authenticate func(ctx context.Context, h *wire.Hello) (Actor, error)
	// Policy replaces the built-in grant policy (ref.policy). Call
	// Hub.PolicyChanged when its decisions change.
	Policy Policy
	// Web publishes facet 1 sparrow.web (Web Profile 9.4).
	Web bool
	// StartTimeout bounds how long a call waits for a node that is not
	// connected (10.7); default 10 s.
	StartTimeout time.Duration
	// AcceptUnknownInterfaces lists facets whose implements claim names an
	// interface the hub does not know (built in, or given in the
	// ref.interfaces extension) instead of refusing them. Such claims are
	// unverified and never chosen as defaults.
	AcceptUnknownInterfaces bool
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
	Logger          *slog.Logger
	// CredentialCheckInterval is how often dial-in credentials are
	// re-validated (10.2: at least every 60 s); default 30 s.
	CredentialCheckInterval time.Duration
	// RelayAckTimeout is the time each downstream session gets to ack a
	// node's relayed SchemaUpdate (10.3: half of the hub's own 10 s);
	// default 5 s, and half of it again for updates from a peer hub.
	RelayAckTimeout time.Duration
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

	mu        sync.Mutex
	tab       *table
	cfg       *admin.Config
	rev       uint64
	nodes     map[string]*node
	viewers   map[*viewer]struct{}
	policy    *hubPolicy
	ifaces    map[string]*schema.Interface // interface hash -> interface
	credSeen  map[string]string            // dial-in credential value -> node ID ever accepted
	calls     map[*activeCall]struct{}
	contexts  map[string]*callContext
	adminID   uint64
	closed    bool
	wg        sync.WaitGroup
	reconcile sync.Mutex // serializes Apply
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
		o.RelayAckTimeout = 5 * time.Second
	}
	h := &Hub{o: o, log: o.Logger, clock: o.Clock, nodes: map[string]*node{}, viewers: map[*viewer]struct{}{},
		ifaces: map[string]*schema.Interface{}, credSeen: map[string]string{}, calls: map[*activeCall]struct{}{},
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
	for _, n := range nodes {
		n.stopLink()
	}
	deadline := time.Now().Add(timeout)
	for _, v := range vs {
		if s := v.session(); s != nil {
			select {
			case <-s.Done():
			case <-time.After(time.Until(deadline)):
				s.Close(status.GoingAway, "hub shut down")
			}
		}
	}
	for _, n := range nodes {
		n.waitStopped(time.Until(deadline) + time.Second)
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
	if h.closing() {
		_ = conn.Close(status.GoingAway, "hub shutting down")
		return
	}
	v := &viewer{h: h}
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
			v.actor = a
			return a.Principal, nil
		},
		ClientSchemaLimit: func(principal string) int {
			if v.node != nil {
				return -1 // no 64 KiB limit between a hub and its nodes (10.2)
			}
			return 0
		},
		SchemaFor: func(ctx context.Context, principal string, hello *wire.Hello) (*schema.Schema, error) {
			h.addViewer(v)
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
	}
	h.sessionConfig(&cfg)
	s, err := session.NewServer(ctx, conn, cfg)
	if err != nil {
		h.removeViewer(v)
		h.log.Debug("handshake failed", "err", err)
		return
	}
	v.setSession(s)
	if dialIn != nil {
		l := &link{n: dialIn, sess: s, v: v, kind: linkDialIn, cred: dialCred, credName: dialIn.credentialName()}
		v.link = l
		h.attach(dialIn, l)
	} else {
		go v.refresh(0)
	}
	<-s.Done()
	h.removeViewer(v)
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
			h.credSeen[string(cred)] = id
			return n, nil
		}
	}
	// A credential that belonged to a node the hub now starts or dials:
	// exactly one link direction per node (10.2).
	if id, ok := h.credSeen[string(cred)]; ok {
		if n := h.nodes[id]; n != nil && n.cfg.Start != nil {
			return nil, &session.Error{Code: status.FailedPrecondition, Message: "node " + id + " is started or dialed by the hub; it may not dial in"}
		}
	}
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
