package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

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

// Options configure a Node.
type Options struct {
	// ID is the node ID. When set, every facet name must equal it or start
	// with it and a dot (10.2).
	ID string
	// SchemaName and Version name the node's schema document.
	SchemaName, Version string
	// Auth is sent in Hello when the node dials (["link", credential] for a
	// hub, 10.2); on stdio it is usually nil.
	Auth *wire.Auth
	// Params are the limits the node imposes on its peer.
	Params wire.Params
	// TrustPeer marks the link as an authenticated link to the node's hub,
	// so Principal and CallContext metadata are honoured (10.2). Stdio
	// links (RunStdio) are always trusted.
	TrustPeer bool
	// Session lets callers adjust the session configuration (timeouts,
	// clock, hooks) before it is used.
	Session func(*session.Config)
	Logger  *slog.Logger
}

// Node is a Sparrow peer that publishes facets and calls others.
type Node struct {
	opts Options
	mux  *session.Mux

	mu      sync.Mutex
	facets  map[uint64]*Facet
	nextID  uint64
	sess    *session.Session
	trusted bool
	connErr error
	lastGA  *wire.GoAway
	ready   chan struct{}
}

// New returns a node with no facets.
func New(o Options) *Node {
	if o.SchemaName == "" {
		o.SchemaName = o.ID
	}
	if o.Version == "" {
		o.Version = "1"
	}
	return &Node{opts: o, mux: session.NewMux(), facets: map[uint64]*Facet{}, nextID: schema.FirstFreeFacetID, ready: make(chan struct{})}
}

// Schema returns the node's current schema document.
func (n *Node) Schema() *schema.Schema {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.schemaLocked()
}

func (n *Node) schemaLocked() *schema.Schema {
	ids := make([]uint64, 0, len(n.facets))
	for id := range n.facets {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	s := &schema.Schema{Format: schema.Format, Name: n.opts.SchemaName, Version: n.opts.Version,
		Facets: []schema.Facet{}, Annotations: schema.Annotations{}}
	for _, id := range ids {
		s.Facets = append(s.Facets, *n.facets[id].Def.Clone())
	}
	return s
}

func (n *Node) checkName(name string) error {
	if n.opts.ID == "" {
		return nil
	}
	if !names.OwnedBy(n.opts.ID, name) {
		return fmt.Errorf("node: facet %q must be named after node %q (10.2)", name, n.opts.ID)
	}
	return nil
}

// Add publishes a facet and returns its facet ID. A facet with the same
// name replaces the existing one in place (a compatible change, 6.7) and
// keeps its ID. While connected, the change is sent as a SchemaUpdate;
// Add returns once the peer acknowledged it.
func (n *Node) Add(ctx context.Context, f *Facet) (uint64, error) {
	if err := n.checkName(f.Def.Name); err != nil {
		return 0, err
	}
	n.mu.Lock()
	id := f.Def.ID
	for fid, cur := range n.facets {
		if cur.Def.Name == f.Def.Name {
			id = fid
		}
	}
	if id == 0 {
		id = n.nextID
	}
	if id >= n.nextID {
		n.nextID = id + 1
	}
	if _, taken := n.facets[id]; taken && n.facets[id].Def.Name != f.Def.Name {
		n.mu.Unlock()
		return 0, fmt.Errorf("node: facet ID %d is taken", id)
	}
	old := n.facets[id]
	nf := &Facet{Def: *f.Def.Clone(), handlers: f.handlers}
	nf.Def.ID = id
	n.facets[id] = nf
	sc := n.schemaLocked()
	sess := n.sess
	n.mu.Unlock()
	n.installHandlers(id, nf)
	if sess != nil {
		if err := n.publish(ctx, sess, sc); err != nil {
			n.mu.Lock()
			if old != nil {
				n.facets[id] = old
			} else {
				delete(n.facets, id)
			}
			n.mu.Unlock()
			n.mux.RemoveFacet(id)
			if old != nil {
				n.installHandlers(id, old)
			}
			return 0, err
		}
	}
	return id, nil
}

// Remove unpublishes a facet by name.
func (n *Node) Remove(ctx context.Context, name string) error {
	n.mu.Lock()
	var id uint64
	for fid, f := range n.facets {
		if f.Def.Name == name {
			id = fid
		}
	}
	if id == 0 {
		n.mu.Unlock()
		return fmt.Errorf("node: no facet %q", name)
	}
	delete(n.facets, id)
	sc := n.schemaLocked()
	sess := n.sess
	n.mu.Unlock()
	if sess != nil {
		if err := n.publish(ctx, sess, sc); err != nil {
			return err
		}
	}
	// Calls already running keep their handlers; new ones are refused by
	// the session as unimplemented.
	n.mux.RemoveFacet(id)
	return nil
}

func (n *Node) publish(ctx context.Context, sess *session.Session, sc *schema.Schema) error {
	u, err := sess.UpdateSchema(sc, session.SchemaUpdateOptions{})
	if err != nil {
		return err
	}
	return u.Wait(ctx)
}

func (n *Node) installHandlers(id uint64, f *Facet) {
	n.mux.RemoveFacet(id)
	for mid, h := range f.handlers {
		n.mux.Handle(id, mid, h)
	}
}

// FacetID returns the ID of one of the node's own facets.
func (n *Node) FacetID(name string) (uint64, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, f := range n.facets {
		if f.Def.Name == name {
			return id, true
		}
	}
	return 0, false
}

// Mux returns the node's call router, for raw handlers.
func (n *Node) Mux() *session.Mux { return n.mux }

func (n *Node) config() session.Config {
	cfg := session.Config{
		Schema:  n.Schema(),
		Params:  n.opts.Params,
		Handler: n.mux,
		Auth:    n.opts.Auth,
		Logger:  n.opts.Logger,
		// A hub's schema can be large (10.2); the 64 KiB limit on client
		// schemas applies to clients, not to nodes.
		MaxClientSchemaSize: -1,
	}
	if n.opts.Session != nil {
		n.opts.Session(&cfg)
	}
	return cfg
}

// Connect runs the client side of a session on conn (the node is the
// Sparrow client) and returns once it is ready. trusted marks the link as
// an authenticated hub link.
func (n *Node) Connect(ctx context.Context, conn transport.Conn, trusted bool) error {
	s, err := session.NewClient(ctx, conn, n.config())
	if err != nil {
		return err
	}
	n.attach(s, trusted)
	return nil
}

// Serve runs the server side of a session on conn, for a node that a hub
// dials (10.2); the node's facets travel in Welcome. authenticate, if set,
// checks the hub's Hello.auth.
func (n *Node) Serve(ctx context.Context, conn transport.Conn, authenticate func(*wire.Auth) error) error {
	cfg := n.config()
	if authenticate != nil {
		cfg.Authenticate = func(ctx context.Context, h *wire.Hello) (string, error) {
			if err := authenticate(h.Auth); err != nil {
				return "", err
			}
			return "hub", nil
		}
	}
	s, err := session.NewServer(ctx, conn, cfg)
	if err != nil {
		return err
	}
	n.attach(s, authenticate != nil || n.opts.TrustPeer)
	return nil
}

func (n *Node) attach(s *session.Session, trusted bool) {
	n.mu.Lock()
	n.sess = s
	n.trusted = trusted || n.opts.TrustPeer
	select {
	case <-n.ready:
	default:
		close(n.ready)
	}
	n.mu.Unlock()
	go func() {
		<-s.Done()
		n.mu.Lock()
		if n.sess == s {
			n.sess = nil
			n.connErr = s.Err()
			n.lastGA = s.GoAwayReceived()
		}
		n.mu.Unlock()
	}()
}

// RunStdio connects on standard input and output, as a process a hub
// started (4.7, 10.2), and blocks until the session ends. Logs must go to
// standard error.
func (n *Node) RunStdio(ctx context.Context) error {
	if err := n.Connect(ctx, pipe.Stdio(), true); err != nil {
		return err
	}
	return n.Wait(ctx)
}

// DialOptions configure Dial.
type DialOptions struct {
	// WebSocketURL is tried when WebTransport does not connect within
	// FallbackAfter (4.8).
	WebSocketURL string
	// FallbackAfter defaults to 3 s.
	FallbackAfter time.Duration
	// TLSConfig and CertHashes configure WebTransport TLS (CertHashes pins
	// the certificate, for development).
	TLSConfig  *tls.Config
	CertHashes [][]byte
	Header     http.Header
	HTTPClient *http.Client
}

// Dial connects to a hub at url: https:// for WebTransport (falling back
// to WebSocketURL), ws:// or wss:// for WebSocket. The link is trusted when
// Options.Auth is set (the node authenticated with a link credential).
func (n *Node) Dial(ctx context.Context, url string, o DialOptions) error {
	conn, err := dialAny(ctx, url, o)
	if err != nil {
		return err
	}
	return n.Connect(ctx, conn, n.opts.Auth != nil)
}

func dialAny(ctx context.Context, url string, o DialOptions) (transport.Conn, error) {
	switch {
	case strings.HasPrefix(url, "ws://"), strings.HasPrefix(url, "wss://"):
		return websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: o.HTTPClient, Header: o.Header})
	case strings.HasPrefix(url, "https://"):
		wait := o.FallbackAfter
		if wait <= 0 {
			wait = 3 * time.Second
		}
		wctx := ctx
		var cancel context.CancelFunc
		if o.WebSocketURL != "" {
			wctx, cancel = context.WithTimeout(ctx, wait)
			defer cancel()
		}
		c, err := webtransport.Dial(wctx, url, &webtransport.DialOptions{TLSConfig: o.TLSConfig, CertHashes: o.CertHashes, Header: o.Header})
		if err == nil {
			return c, nil
		}
		if o.WebSocketURL == "" {
			return nil, err
		}
		return websocket.Dial(ctx, o.WebSocketURL, &websocket.DialOptions{HTTPClient: o.HTTPClient, Header: o.Header})
	}
	return nil, fmt.Errorf("node: unsupported URL scheme in %q", url)
}

// RunDial keeps the node connected to url until ctx ends: after the session
// ends it reconnects with exponential backoff and jitter, from about
// 500 ms up to about 30 s (5.6). It returns ctx's error.
func (n *Node) RunDial(ctx context.Context, url string, o DialOptions) error {
	backoff := 500 * time.Millisecond
	for {
		err := n.Dial(ctx, url, o)
		if err == nil {
			backoff = 500 * time.Millisecond
			_ = n.Wait(ctx)
			if s := n.Session(); s != nil {
				s.Close(status.OK, "reconnecting")
			}
			if g := n.lastGoAway(); g != nil && g.RetryAfterMs != nil {
				backoff = time.Duration(*g.RetryAfterMs) * time.Millisecond
			}
		} else if n.opts.Logger != nil {
			n.opts.Logger.Warn("dial failed", "url", url, "err", err)
		}
		jitter := time.Duration(rand.Int64N(int64(backoff/2) + 1))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff/2 + jitter):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (n *Node) lastGoAway() *wire.GoAway {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastGA
}

// Session returns the current session, or nil.
func (n *Node) Session() *session.Session {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sess
}

// Wait blocks until the current session ends and returns why (nil for a
// clean GoAway(ok) or going_away).
func (n *Node) Wait(ctx context.Context) error {
	s := n.Session()
	if s == nil {
		n.mu.Lock()
		defer n.mu.Unlock()
		return n.connErr
	}
	select {
	case <-s.Done():
	case <-ctx.Done():
		return ctx.Err()
	}
	err := s.Err()
	switch session.Code(err) {
	case status.OK, status.GoingAway:
		return nil
	}
	return err
}

// Close ends the session with GoAway(ok).
func (n *Node) Close() {
	if s := n.Session(); s != nil {
		s.Close(status.OK, "node closing")
	}
}

func (n *Node) session() (*session.Session, error) {
	s := n.Session()
	if s == nil {
		return nil, errNotConnected
	}
	return s, nil
}

// Resolve finds a facet of the peer's schema by name and a method in it.
// Names on a hub may carry a "<peer-id>/" prefix (10.8).
func (n *Node) Resolve(facet, method string) (uint64, *schema.Method, error) {
	s, err := n.session()
	if err != nil {
		return 0, nil, err
	}
	f := s.PeerFacet(facet)
	if f == nil {
		return 0, nil, &session.Error{Code: status.Unimplemented, Message: fmt.Sprintf("the peer has no facet %q", facet)}
	}
	m, err := MethodByName(f, method)
	if err != nil {
		return 0, nil, err
	}
	return f.ID, m, nil
}

// Call makes a unary call by facet and method name.
func (n *Node) Call(ctx context.Context, facet, method string, input any) (any, error) {
	cc, err := n.Open(ctx, facet, method, input, nil)
	if err != nil {
		return nil, err
	}
	return cc.Response(ctx)
}

// Open starts any call by name; use the returned call's Send, Recv,
// Reader and Writer for streams.
func (n *Node) Open(ctx context.Context, facet, method string, input any, o *session.CallOptions) (*session.ClientCall, error) {
	s, err := n.session()
	if err != nil {
		return nil, err
	}
	fid, m, err := n.Resolve(facet, method)
	if err != nil {
		return nil, err
	}
	return s.Call(ctx, fid, m.ID, input, o)
}

// Notify sends a notification by name.
func (n *Node) Notify(ctx context.Context, facet, method string, input any) error {
	s, err := n.session()
	if err != nil {
		return err
	}
	fid, m, err := n.Resolve(facet, method)
	if err != nil {
		return err
	}
	return s.Notify(ctx, fid, m.ID, input)
}

// Principal returns the principal a call acts for, as named by the hub
// (10.6). It is honoured only on a trusted link.
func (n *Node) Principal(call *session.ServerCall) (string, bool) {
	n.mu.Lock()
	trusted := n.trusted
	n.mu.Unlock()
	if !trusted {
		return "", false
	}
	p, ok := call.Principal()
	if ok && !names.IsPrincipal(p) {
		return "", false
	}
	return p, ok
}

// CallFor makes a call on behalf of the principal of an incoming call: it
// carries the call's context (10.6), so the hub checks both that principal
// and the node.
func (n *Node) CallFor(ctx context.Context, in *session.ServerCall, facet, method string, input any) (any, error) {
	o := &session.CallOptions{Metadata: wire.Metadata{}}
	if c, ok := in.CallContext(); ok {
		o.Metadata.SetContext(c)
	}
	cc, err := n.Open(ctx, facet, method, input, o)
	if err != nil {
		return nil, err
	}
	return cc.Response(ctx)
}

var _ = errors.New
