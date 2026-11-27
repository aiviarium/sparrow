// Package session implements one Sparrow RPC session (sections 4-8) over a
// transport binding, in either role: the handshake, control messages,
// schema publication and live updates, and calls with per-call credit,
// cancellation, deadlines, byte streams and the leased stream pool.
//
// It offers two levels of API. The typed level (Session.Call, ServerCall
// Input/Recv/Send/..., Mux) encodes and decodes payloads with the facet's
// schema. The raw level (Session.OpenRaw, ServerCall.RecvRaw/SendRaw,
// Relay) moves whole encoded messages and never decodes payloads, so a hub
// can forward calls by rewriting envelopes (section 10.5). See README.md.
package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport"
	"github.com/aiviarium/sparrow/go/value"
	"github.com/aiviarium/sparrow/go/wire"
)

type hsState int

const (
	hsAwaitHello   hsState = iota // server: before Hello
	hsHandshaking                 // server: Hello received, Welcome not yet sent
	hsAwaitReady                  // server: Welcome sent
	hsAwaitWelcome                // client: Hello sent
	hsOpen                        // handshake complete
)

// Session is one Sparrow session.
type Session struct {
	cfg    Config
	role   wire.Role
	conn   transport.Conn
	clock  Clock
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	shared *lane
	procMu sync.Mutex // serializes shared-lane processing (incl. handshake replay)

	localLimits wire.Limits // limits this side imposes (its own params)

	lastRecv atomic.Int64
	lastSend atomic.Int64

	mu          sync.Mutex
	hs          hsState
	peerLimits  wire.Limits // limits the peer imposes on this side
	hello       *wire.Hello
	welcome     *wire.Welcome
	principal   string
	sessionID   []byte
	welcomeDone bool // client: Welcome processed; server: Welcome sent
	readyDone   bool // server: Ready received; client: Ready sent
	// welcomeSending is set on the server just before Welcome is written:
	// from then on the client may have Welcome and open leased streams,
	// possibly before the write returns.
	welcomeSending bool
	welcomeCh      chan struct{}
	readyCh        chan struct{}
	helloCh        chan struct{}
	hsErr          error
	preAuth        [][]byte
	preAuthLen     int
	sentPreWel     int // client: bytes sent on the shared lane before Welcome
	optimistic     bool
	optReject      bool // client: optimistic start rejected

	calls    map[uint64]*call
	nextID   uint64
	outOpen  int
	outSig   chan struct{}
	inOpen   int
	inLeased int

	sharedReading atomic.Bool // the shared-lane reader is running
	pool          pool

	local         *schema.State
	localAcked    uint64
	pendingFacets map[uint64]uint64 // facet ID -> epoch that added or changed it
	ackSig        chan struct{}
	methodFlags   map[[2]uint64]uint64 // every method this side ever published
	peer          *schema.State
	peerSc        *schema.Schema
	localSc       *schema.Schema
	codecMu       sync.Mutex
	localCodecs   map[*schema.Facet]*value.Codec
	peerCodecs    map[*schema.Facet]*value.Codec
	updMu         sync.Mutex

	goAwaySent *wire.GoAway
	goAwayDone chan struct{} // closed once a GoAway being written is out
	goAwayRecv *wire.GoAway
	draining   bool
	closed     bool
	closeErr   *Error
	closing    bool

	shrinkArmed bool
	pingNonce   uint64
	pingSent    bool
	notifySem   chan struct{}
	ackQ        chan func()
	noCalls     chan struct{} // closed once no call is open after the shared lane ended
}

// NewClient runs the client side of the handshake on conn (5.2). It sends
// Hello and, unless the start is optimistic, waits for Welcome and sends
// Ready. An optimistic client (Config.Optimistic) returns right after
// sending Hello and Ready; Welcome is then handled in the background.
func NewClient(ctx context.Context, conn transport.Conn, cfg Config) (*Session, error) {
	s := newSession(conn, cfg, wire.Client)
	if cfg.Schema != nil {
		st, err := schema.NewState(cfg.Schema.Canonical())
		if err != nil {
			s.terminate(status.InvalidArgument, "invalid local schema", false)
			return nil, err
		}
		s.setLocal(st)
	}
	st, err := conn.SharedLane(ctx)
	if err != nil {
		s.terminate(status.Unavailable, "no shared lane", false)
		return nil, err
	}
	s.mu.Lock()
	s.shared = &lane{s: s, st: st, shared: true}
	s.mu.Unlock()

	hello := &wire.Hello{Versions: cfg.Versions, Caps: cfg.Caps, Auth: cfg.Auth, Params: cfg.Params}
	if len(hello.Versions) == 0 {
		hello.Versions = []uint64{ProtocolVersion}
	}
	var knownHash []byte
	if cfg.KnownSchema != nil {
		knownHash, err = cfg.KnownSchema.Canonical().Hash()
		if err != nil {
			s.terminate(status.InvalidArgument, "invalid cached schema", false)
			return nil, err
		}
		hello.KnownSchema = knownHash
	}
	if s.local != nil {
		h, _ := s.local.Hash()
		raw, err := s.local.Schema().Encode()
		if err != nil {
			s.terminate(status.InvalidArgument, "invalid local schema", false)
			return nil, err
		}
		hello.ClientSchema = &wire.InlineSchema{Hash: h, Schema: raw}
	}
	if cfg.Optimistic {
		if cfg.KnownSchema == nil {
			return nil, errors.New("session: an optimistic start needs Config.KnownSchema")
		}
		if cfg.KnownParams != nil && cfg.KnownParams.Limits(wire.Server).BelowDefaults(wire.Server) {
			return nil, errors.New("session: the cached server limits are below the defaults; start normally")
		}
		hello.Optimistic = true
		hello.Versions = hello.Versions[:1]
		ps, err := schema.NewState(cfg.KnownSchema.Canonical())
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.setPeerLocked(ps)
		s.optimistic = true
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.hello = hello
	s.mu.Unlock()
	if err := s.shared.write(hello.AppendTo(nil)); err != nil {
		s.terminate(status.Unavailable, "cannot send Hello", false)
		return nil, err
	}
	go s.shared.readLoop()
	if cfg.Optimistic {
		if err := s.shared.write((&wire.Ready{SchemaHash: knownHash}).AppendTo(nil)); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.readyDone = true
		close(s.readyCh)
		s.mu.Unlock()
		s.startBackground()
		return s, nil
	}
	// Wait until Ready is written, not just until Welcome is processed: a
	// call the application sends on the shared lane right after NewClient
	// returns must not overtake Ready (it would get not_ready, 5.2).
	select {
	case <-s.readyCh:
	case <-s.done:
	case <-ctx.Done():
		s.terminate(status.Cancelled, "handshake cancelled", false)
		return nil, ctx.Err()
	}
	s.mu.Lock()
	err = s.hsErr
	if err == nil && s.closed {
		err = s.closeErr
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	s.startBackground()
	return s, nil
}

// NewServer runs the server side of the handshake on conn (5.2): it waits
// for Hello (HelloTimeout), checks the version, credential and client
// schema, sends Welcome and returns once Ready has arrived.
func NewServer(ctx context.Context, conn transport.Conn, cfg Config) (*Session, error) {
	s := newSession(conn, cfg, wire.Server)
	sc := cfg.Schema
	if sc == nil {
		sc = &schema.Schema{Format: schema.Format, Name: "", Version: "", Facets: []schema.Facet{}, Annotations: schema.Annotations{}}
	}
	st, err := schema.NewState(sc.Canonical())
	if err != nil {
		s.terminate(status.Internal, "invalid local schema", false)
		return nil, err
	}
	s.setLocal(st)

	helloTimeout := dur(cfg.HelloTimeout, DefaultHelloTimeout)
	timer := s.clock.AfterFunc(helloTimeout, func() {
		s.mu.Lock()
		waiting := s.hs == hsAwaitHello
		s.mu.Unlock()
		if waiting {
			s.terminate(status.DeadlineExceeded, "no Hello within the timeout", false)
		}
	})
	lctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-s.done:
		case <-lctx.Done():
		}
		cancel()
	}()
	sl, err := conn.SharedLane(lctx)
	if err != nil {
		timer.Stop()
		s.terminate(status.Unavailable, "no shared lane", false)
		if s.isClosed() {
			return nil, s.handshakeError()
		}
		return nil, err
	}
	s.mu.Lock()
	s.shared = &lane{s: s, st: sl, shared: true}
	s.mu.Unlock()
	go s.shared.readLoop()
	// Leased streams are taken only once the shared lane is there: one
	// opened before Welcome fails the session with GoAway(protocol_error),
	// which needs the lane (a stream accepted earlier would close the
	// session without it).
	go s.acceptLoop()
	select {
	case <-s.helloCh:
	case <-s.done:
		timer.Stop()
		return nil, s.handshakeError()
	case <-ctx.Done():
		timer.Stop()
		s.terminate(status.Cancelled, "handshake cancelled", false)
		return nil, ctx.Err()
	}
	timer.Stop()
	if err := s.serverHandshake(ctx); err != nil {
		return nil, err
	}
	select {
	case <-s.readyCh:
	case <-s.done:
		return nil, s.handshakeError()
	case <-ctx.Done():
		s.terminate(status.Cancelled, "handshake cancelled", false)
		return nil, ctx.Err()
	}
	s.startBackground()
	return s, nil
}

func newSession(conn transport.Conn, cfg Config, role wire.Role) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		cfg: cfg, role: role, conn: conn, clock: cfg.clock(), log: cfg.Logger,
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		localLimits: cfg.Params.Limits(role),
		welcomeCh:   make(chan struct{}), readyCh: make(chan struct{}), helloCh: make(chan struct{}),
		calls:         map[uint64]*call{},
		pendingFacets: map[uint64]uint64{},
		methodFlags:   map[[2]uint64]uint64{},
		localCodecs:   map[*schema.Facet]*value.Codec{},
		peerCodecs:    map[*schema.Facet]*value.Codec{},
		notifySem:     make(chan struct{}, MaxNotificationHandlers),
		ackQ:          make(chan func(), 64),
	}
	// The role's starting state is set before the goroutines below start:
	// a connection that is already gone ends the session at once, and
	// terminate reads it.
	if role == wire.Client {
		s.hs, s.nextID, s.peerLimits = hsAwaitWelcome, 2, wire.DefaultLimits(wire.Server)
	} else {
		s.hs, s.nextID, s.peerLimits = hsAwaitHello, 1, wire.DefaultLimits(wire.Client)
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	conn.SetReadLimit(s.localLimits.MaxMessageSize)
	now := s.clock.Now().UnixNano()
	s.lastRecv.Store(now)
	s.lastSend.Store(now)
	go s.ackWorker()
	go func() {
		select {
		case <-conn.Done():
		case <-s.done:
			return
		}
		// The shared-lane reader normally sees the end first, after the
		// messages that preceded it (such as GoAway); this is a fallback.
		s.mu.Lock()
		reading := s.shared != nil
		s.mu.Unlock()
		if reading {
			t := time.NewTimer(dur(s.cfg.Linger, DefaultLinger))
			defer t.Stop()
			select {
			case <-s.done:
				return
			case <-t.C:
			}
		}
		s.transportGone()
	}()
	return s
}

func (s *Session) logf(format string, args ...any) {
	s.log.Debug(fmt.Sprintf(format, args...), "role", s.role.String())
}

// startBackground arms the idle timer once the handshake is done.
func (s *Session) startBackground() {
	if s.role == wire.Client {
		go s.acceptLoop()
	}
	s.armIdle()
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

// Role returns this side's role.
func (s *Session) Role() wire.Role { return s.role }

// Conn returns the transport connection.
func (s *Session) Conn() transport.Conn { return s.conn }

// Context is cancelled when the session ends.
func (s *Session) Context() context.Context { return s.ctx }

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns why the session ended, or nil while it is open.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr == nil {
		return nil
	}
	return s.closeErr
}

// Principal returns the principal Config.Authenticate returned (server).
func (s *Session) Principal() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.principal
}

// Hello returns the Hello of the session (sent or received).
func (s *Session) Hello() *wire.Hello {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hello
}

// Welcome returns the Welcome of the session, once sent or received.
func (s *Session) Welcome() *wire.Welcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.welcome
}

// SessionID returns Welcome.session_id.
func (s *Session) SessionID() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

// Welcomed is closed once the client has processed Welcome, or the server
// has sent it.
func (s *Session) Welcomed() <-chan struct{} { return s.welcomeCh }

// LocalLimits are the limits this side imposes on the peer.
func (s *Session) LocalLimits() wire.Limits { return s.localLimits }

// PeerLimits are the limits the peer imposes on this side (defaults until
// its params are known).
func (s *Session) PeerLimits() wire.Limits { return s.peerLimitsSnapshot() }

func (s *Session) peerLimitsSnapshot() wire.Limits {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerLimits
}

// GoAwayReceived returns the peer's GoAway, if any.
func (s *Session) GoAwayReceived() *wire.GoAway {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goAwayRecv
}

// Stats is a snapshot of the session's bookkeeping, for tests and metrics.
type Stats struct {
	OpenCalls      int // calls this side has open, both roles
	OutgoingCalls  int // counted toward the peer's maxConcurrentCalls
	IncomingCalls  int // counted toward this side's maxConcurrentCalls
	PoolOpen       int // leased streams this side opened, still counted
	PoolIdle       int
	PeerLeased     int // leased streams the peer opened, still counted
	LocalEpoch     uint64
	LocalAcked     uint64
	PeerEpoch      uint64
	Draining       bool
	Closed         bool
	MaxCallBuffers uint64 // largest buffered counted bytes seen in any open call
}

// Stats returns a snapshot.
func (s *Session) Stats() Stats {
	s.mu.Lock()
	st := Stats{OpenCalls: len(s.calls), OutgoingCalls: s.outOpen, IncomingCalls: s.inOpen,
		PoolOpen: s.pool.open, PoolIdle: len(s.pool.idle), PeerLeased: s.inLeased,
		LocalAcked: s.localAcked, Draining: s.draining, Closed: s.closed}
	if s.local != nil {
		st.LocalEpoch = s.local.Epoch()
	}
	if s.peer != nil {
		st.PeerEpoch = s.peer.Epoch()
	}
	s.mu.Unlock()
	return st
}

// CallInfo describes one open call, for tests and diagnostics.
type CallInfo struct {
	ID                     uint64
	Caller                 bool // this side is the caller
	Shared                 bool // on the shared lane
	CallerDone, CalleeDone bool // which halves are finished (7.1)
}

// Calls returns the calls this side has open, in both roles.
func (s *Session) Calls() []CallInfo {
	s.mu.Lock()
	cs := make([]*call, 0, len(s.calls))
	for _, c := range s.calls {
		cs = append(cs, c)
	}
	s.mu.Unlock()
	out := make([]CallInfo, 0, len(cs))
	for _, c := range cs {
		c.mu.Lock()
		out = append(out, CallInfo{ID: c.id, Caller: c.caller, Shared: c.ln.shared, CallerDone: c.h.callerDone, CalleeDone: c.h.calleeDone})
		c.mu.Unlock()
	}
	return out
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

func (s *Session) preWelcomeBudget(n int) error {
	s.mu.Lock()
	if s.welcomeDone || !s.optimistic {
		s.mu.Unlock()
		return nil
	}
	if s.sentPreWel+n <= PreAuthLimit || s.sentPreWel == 0 {
		s.sentPreWel += n
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	select {
	case <-s.welcomeCh:
		return nil
	case <-s.done:
		return s.closedError()
	}
}

// checkMinimums checks received params against the minimums of 5.4.
func checkMinimums(p wire.Params) error {
	if err := p.Validate(); err != nil {
		return &Error{Code: status.InvalidArgument, Message: err.Error()}
	}
	return nil
}

func (s *Session) serverHandshake(ctx context.Context) error {
	s.mu.Lock()
	h := s.hello
	s.mu.Unlock()
	reject := func(code status.Code, reason string, versions []uint64) error {
		s.sendGoAwayAndClose(code, reason, nil, versions)
		return &Error{Code: code, Message: reason}
	}
	versionOK := false
	for _, v := range h.Versions {
		if v == ProtocolVersion {
			versionOK = true
		}
	}
	if !versionOK {
		return reject(status.UnsupportedVersion, "no common protocol version", []uint64{ProtocolVersion})
	}
	if err := h.CheckOptimistic(); err != nil {
		return reject(status.ProtocolError, err.Error(), nil)
	}
	if err := checkMinimums(h.Params); err != nil {
		return reject(status.InvalidArgument, err.(*Error).Message, nil)
	}
	principal := ""
	if s.cfg.Authenticate != nil {
		p, err := s.cfg.Authenticate(ctx, h)
		if err != nil {
			code := status.Unauthenticated
			var e *Error
			if errors.As(err, &e) {
				code = e.Code
			}
			return reject(code, err.Error(), nil)
		}
		principal = p
	}
	if s.cfg.SchemaFor != nil {
		sc, err := s.cfg.SchemaFor(ctx, principal, h)
		if err == nil {
			var st *schema.State
			if st, err = schema.NewState(sc.Canonical()); err == nil {
				s.setLocal(st)
			}
		}
		if err != nil {
			code := status.Internal
			var e *Error
			if errors.As(err, &e) {
				code = e.Code
			}
			return reject(code, err.Error(), nil)
		}
	}
	var clientState *schema.State
	if h.ClientSchema != nil {
		max := s.cfg.MaxClientSchemaSize
		if s.cfg.ClientSchemaLimit != nil {
			max = s.cfg.ClientSchemaLimit(principal)
		}
		if max == 0 {
			max = MaxClientSchemaSize
		}
		if max > 0 && len(h.ClientSchema.Schema) > max {
			return reject(status.InvalidArgument, "client schema larger than the limit", nil)
		}
		cs, err := schema.DecodeSchema(h.ClientSchema.Schema)
		if err == nil && max > 0 && schemaDepth(cs) > MaxClientSchemaDepth {
			err = errors.New("type references nested deeper than 32 levels")
		}
		if err == nil {
			clientState, err = schema.NewState(cs)
		}
		if err == nil {
			var hash []byte
			if hash, err = clientState.Hash(); err == nil && !bytes.Equal(hash, h.ClientSchema.Hash) {
				err = errors.New("client schema hash does not match")
			}
		}
		if err == nil && s.cfg.AcceptClientSchema != nil {
			if err = s.cfg.AcceptClientSchema(ctx, principal, clientState.Schema()); err != nil {
				code := status.InvalidArgument
				var e *Error
				if errors.As(err, &e) {
					code = e.Code
				}
				return reject(code, err.Error(), nil)
			}
		}
		if err != nil {
			return reject(status.InvalidArgument, "invalid client schema: "+err.Error(), nil)
		}
	}

	s.mu.Lock()
	local := s.local
	s.mu.Unlock()
	hash, _ := local.Hash()
	offer := s.makeOffer(local, hash, h.KnownSchema)
	sid := make([]byte, 16)
	_, _ = rand.Read(sid)
	w := &wire.Welcome{Version: ProtocolVersion, Caps: s.cfg.Caps, SessionID: sid, Props: s.cfg.Props,
		ServerSchema: offer, Params: s.cfg.Params}

	s.procMu.Lock()
	defer s.procMu.Unlock()
	s.mu.Lock()
	s.welcomeSending = true
	s.mu.Unlock()
	if err := s.shared.write(w.AppendTo(nil)); err != nil {
		return err
	}
	s.mu.Lock()
	s.principal = principal
	s.sessionID = sid
	s.welcome = w
	s.setPeerLocked(clientState)
	s.peerLimits = h.Params.Limits(wire.Client)
	s.welcomeDone = true
	s.hs = hsAwaitReady
	close(s.welcomeCh)
	queued := s.preAuth
	s.preAuth = nil
	s.mu.Unlock()

	if h.Optimistic {
		if !bytes.Equal(h.KnownSchema, hash) {
			z := uint64(0)
			s.sendGoAwayAndCloseLocked(status.SchemaMismatch, "the cached schema is out of date", &z, nil)
			return &Error{Code: status.SchemaMismatch, Message: "optimistic start with an out-of-date schema"}
		}
		if s.localLimits.BelowDefaults(wire.Server) {
			z := uint64(0)
			s.sendGoAwayAndCloseLocked(status.FailedPrecondition, "this server's limits are below the defaults", &z, nil)
			return &Error{Code: status.FailedPrecondition, Message: "optimistic start against limits below the defaults"}
		}
	}
	for _, b := range queued {
		s.handleShared(s.shared, b)
	}
	return nil
}

func (s *Session) makeOffer(local *schema.State, hash, known []byte) wire.SchemaOffer {
	if known != nil && bytes.Equal(known, hash) {
		return wire.SchemaOffer{Kind: wire.OfferUnchanged, Hash: hash}
	}
	if known != nil && s.cfg.SchemaByHash != nil {
		if old := s.cfg.SchemaByHash(known); old != nil {
			if d, err := schema.Diff(old, local.Schema()); err == nil {
				if raw, err := d.Encode(); err == nil {
					return wire.SchemaOffer{Kind: wire.OfferDelta, Hash: hash, From: known, Delta: raw}
				}
			}
		}
	}
	if s.cfg.OfferLocation != nil {
		if loc, ok := s.cfg.OfferLocation(hash); ok {
			return wire.SchemaOffer{Kind: wire.OfferOutOfBand, Hash: hash, Location: loc}
		}
	}
	raw, _ := local.Schema().Encode()
	return wire.SchemaOffer{Kind: wire.OfferFull, Hash: hash, Schema: raw}
}

// schemaDepth returns the deepest type-reference nesting in a schema.
func schemaDepth(sc *schema.Schema) int {
	max := 0
	var ref func(r schema.TypeRef, d int)
	ref = func(r schema.TypeRef, d int) {
		if d > max {
			max = d
		}
		if r.Elem != nil {
			ref(*r.Elem, d+1)
		}
		if r.Key != nil {
			ref(*r.Key, d+1)
		}
	}
	for i := range sc.Facets {
		f := &sc.Facets[i]
		for j := range f.Types {
			t := &f.Types[j]
			for k := range t.Fields {
				ref(t.Fields[k].Type, 1)
			}
			ref(t.Target, 1)
		}
		for j := range f.Services {
			for k := range f.Services[j].Methods {
				m := &f.Services[j].Methods[k]
				ref(m.Input, 1)
				ref(m.Output, 1)
			}
		}
	}
	return max
}

// clientWelcome handles Welcome on the client (reader goroutine).
func (s *Session) clientWelcome(w *wire.Welcome) {
	fail := func(code status.Code, reason string) {
		s.mu.Lock()
		if s.hsErr == nil {
			s.hsErr = &Error{Code: code, Message: reason}
		}
		s.mu.Unlock()
		s.sendGoAwayAndClose(code, reason, nil, nil)
	}
	s.mu.Lock()
	hello := s.hello
	s.mu.Unlock()
	versionOK := false
	for _, v := range hello.Versions {
		if v == w.Version {
			versionOK = true
		}
	}
	if !versionOK {
		fail(status.UnsupportedVersion, "server chose a version this client did not offer")
		return
	}
	if err := checkMinimums(w.Params); err != nil {
		fail(status.InvalidArgument, err.(*Error).Message)
		return
	}
	sc, err := s.loadOffer(&w.ServerSchema)
	if err != nil {
		fail(status.SchemaMismatch, "cannot load the server schema: "+err.Error())
		return
	}
	st, err := schema.NewState(sc)
	if err != nil {
		fail(status.SchemaMismatch, "invalid server schema: "+err.Error())
		return
	}
	hash, _ := st.Hash()
	if !bytes.Equal(hash, w.ServerSchema.Hash) {
		fail(status.SchemaMismatch, "server schema hash does not match the offer")
		return
	}
	if s.cfg.OnServerSchema != nil {
		s.cfg.OnServerSchema(hash, st.Schema(), w.Params)
	}
	s.mu.Lock()
	s.welcome = w
	s.sessionID = w.SessionID
	s.peerLimits = w.Params.Limits(wire.Server)
	optimistic := s.optimistic
	if optimistic && (!bytes.Equal(hello.KnownSchema, hash) || s.peerLimits.BelowDefaults(wire.Server)) {
		// The server will follow with GoAway(schema_mismatch) or
		// GoAway(failed_precondition); none of the calls ran (5.3).
		s.optReject = true
	} else {
		s.setPeerLocked(st)
	}
	s.welcomeDone = true
	s.hs = hsOpen
	close(s.welcomeCh)
	s.signalPoolLocked()
	s.signalOutLocked()
	s.mu.Unlock()
	if optimistic {
		return
	}
	if err := s.shared.write((&wire.Ready{SchemaHash: hash}).AppendTo(nil)); err != nil {
		return
	}
	s.mu.Lock()
	s.readyDone = true
	close(s.readyCh)
	s.mu.Unlock()
}

func (s *Session) loadOffer(o *wire.SchemaOffer) (*schema.Schema, error) {
	switch o.Kind {
	case wire.OfferUnchanged:
		if s.cfg.KnownSchema == nil {
			return nil, errors.New("server offered Unchanged but no schema is cached")
		}
		return s.cfg.KnownSchema.Canonical(), nil
	case wire.OfferDelta:
		if s.cfg.KnownSchema == nil {
			return nil, errors.New("server offered a delta but no schema is cached")
		}
		known, err := s.cfg.KnownSchema.Canonical().Hash()
		if err != nil || !bytes.Equal(known, o.From) {
			return nil, errors.New("delta is from a schema this client does not have")
		}
		d, err := schema.DecodeDelta(o.Delta)
		if err != nil {
			return nil, err
		}
		base, err := schema.NewState(s.cfg.KnownSchema.Canonical())
		if err != nil {
			return nil, err
		}
		n, err := base.Apply(d)
		if err != nil {
			return nil, err
		}
		return n.Schema(), nil
	case wire.OfferFull:
		return schema.DecodeSchema(o.Schema)
	case wire.OfferOutOfBand:
		if s.cfg.FetchSchema == nil {
			return nil, errors.New("server offered the schema out of band and no FetchSchema is configured")
		}
		sc, err := s.cfg.FetchSchema(s.ctx, o.Location, o.Hash)
		if err != nil {
			return nil, err
		}
		return sc.Canonical(), nil
	}
	return nil, fmt.Errorf("unknown offer %d", o.Kind)
}

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------

func (s *Session) decode(b []byte) (wire.Message, bool) {
	m, err := wire.Decode(b)
	if err != nil {
		if wire.IsIgnorable(err) {
			return nil, false
		}
		s.fail(status.ProtocolError, err.Error())
		return nil, false
	}
	return m, true
}

// handleShared handles one shared-lane message; procMu is held.
func (s *Session) handleShared(l *lane, b []byte) {
	s.mu.Lock()
	hs := s.hs
	closed := s.closed
	if !closed && s.role == wire.Server && hs == hsHandshaking {
		s.preAuthLen += len(b)
		if s.preAuthLen > PreAuthLimit {
			s.mu.Unlock()
			s.fail(status.ResourceExhausted, "more than 64 KiB before the credential was verified")
			return
		}
		s.preAuth = append(s.preAuth, b)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if closed {
		return
	}
	m, ok := s.decode(b)
	if !ok {
		return
	}
	switch hs {
	case hsAwaitHello:
		h, ok := m.(*wire.Hello)
		if !ok {
			s.fail(status.ProtocolError, "the first message must be Hello")
			return
		}
		s.mu.Lock()
		s.hello = h
		s.hs = hsHandshaking
		close(s.helloCh)
		s.mu.Unlock()
		return
	case hsAwaitWelcome:
		switch x := m.(type) {
		case *wire.Welcome:
			s.clientWelcome(x)
			return
		case *wire.GoAway:
			s.onGoAway(x)
			return
		}
		if s.optimistic && m.Kind().IsCall() {
			break // an optimistic client may see nothing else before Welcome
		}
		s.fail(status.ProtocolError, "expected Welcome, got "+m.Kind().String())
		return
	}
	switch x := m.(type) {
	case *wire.Hello, *wire.Welcome:
		s.fail(status.ProtocolError, "unexpected "+m.Kind().String())
	case *wire.Ready:
		s.onReady(x)
	case *wire.SchemaUpdate:
		s.onSchemaUpdate(x)
	case *wire.SchemaAck:
		s.onSchemaAck(x)
	case *wire.AuthRefresh:
		s.onAuthRefresh(x)
	case *wire.AuthStatus:
		if s.role != wire.Client {
			s.fail(status.ProtocolError, "AuthStatus sent by the client")
			return
		}
		if s.cfg.OnAuthStatus != nil {
			go s.cfg.OnAuthStatus(s, x)
		}
	case *wire.Ping:
		_ = l.write((&wire.Pong{Nonce: x.Nonce}).AppendTo(nil))
	case *wire.Pong:
		s.mu.Lock()
		s.pingSent = false
		s.mu.Unlock()
	case *wire.GoAway:
		s.onGoAway(x)
	default:
		s.handleCallMessage(l, m, b)
	}
}

// handleLeased handles one message on a leased stream.
func (s *Session) handleLeased(l *lane, b []byte) {
	if s.isClosed() {
		return
	}
	m, ok := s.decode(b)
	if !ok {
		return
	}
	if !m.Kind().IsCall() {
		s.fail(status.ProtocolError, m.Kind().String()+" on a leased stream")
		return
	}
	s.handleCallMessage(l, m, b)
}

func (s *Session) onReady(r *wire.Ready) {
	if s.role != wire.Server {
		s.fail(status.ProtocolError, "Ready sent by the server")
		return
	}
	s.mu.Lock()
	if s.readyDone {
		s.mu.Unlock()
		s.fail(status.ProtocolError, "a second Ready")
		return
	}
	hash, _ := s.local.Hash()
	s.mu.Unlock()
	if !bytes.Equal(r.SchemaHash, hash) {
		s.sendGoAwayAndCloseLocked(status.SchemaMismatch, "Ready names a different schema", nil, nil)
		return
	}
	s.mu.Lock()
	s.readyDone = true
	s.hs = hsOpen
	close(s.readyCh)
	s.signalPoolLocked()
	s.mu.Unlock()
}

func (s *Session) handleCallMessage(l *lane, m wire.Message, b []byte) {
	if r, ok := m.(*wire.Request); ok {
		s.onRequest(l, r, b)
		return
	}
	cm := m.(wire.CallMessage)
	id := cm.Call()
	s.mu.Lock()
	c := s.calls[id]
	s.mu.Unlock()
	if c == nil || c.ln != l {
		if c == nil && !l.shared {
			// A call the callee forgot first: its stream becomes idle with
			// the caller's End or Cancel (7.1).
			if k := m.Kind(); k == wire.KindEnd || k == wire.KindCancel {
				s.mu.Lock()
				if l.awaitCallerEnd == id {
					l.awaitCallerEnd = 0
				}
				s.mu.Unlock()
			}
		}
		return // unknown or ended call, or the wrong stream: ignored (7.1)
	}
	c.deliver(&Msg{Kind: m.Kind(), Raw: b, Message: m, counted: wire.CountedBytes(m, len(b))})
}

// ---------------------------------------------------------------------------
// Control messages
// ---------------------------------------------------------------------------

func (s *Session) onAuthRefresh(a *wire.AuthRefresh) {
	if s.role != wire.Server {
		s.fail(status.ProtocolError, "AuthRefresh sent by the server")
		return
	}
	if s.cfg.OnAuthRefresh == nil {
		_ = s.shared.write((&wire.AuthStatus{Status: uint64(status.Unimplemented)}).AppendTo(nil))
		return
	}
	go func() {
		st, err := s.cfg.OnAuthRefresh(s.ctx, s, &a.Auth)
		if err != nil {
			s.GoAway(status.Unauthenticated, err.Error(), nil)
			return
		}
		if st != nil {
			_ = s.SendAuthStatus(st)
		}
	}()
}

// RefreshAuth sends AuthRefresh with a fresh credential (client, 5.5). The
// server answers with AuthStatus, delivered to Config.OnAuthStatus.
func (s *Session) RefreshAuth(a wire.Auth) error {
	if s.role != wire.Client {
		return errors.New("session: only the client refreshes its credential")
	}
	return s.shared.write((&wire.AuthRefresh{Auth: a}).AppendTo(nil))
}

// SendAuthStatus sends AuthStatus (server): the result of a refresh, or a
// warning that the credential expires soon.
func (s *Session) SendAuthStatus(m *wire.AuthStatus) error {
	if s.role != wire.Server {
		return errors.New("session: only the server sends AuthStatus")
	}
	return s.shared.write(m.AppendTo(nil))
}

// Ping sends a Ping; the reply only refreshes liveness.
func (s *Session) Ping() error {
	s.mu.Lock()
	s.pingNonce++
	n := s.pingNonce
	s.mu.Unlock()
	return s.shared.write((&wire.Ping{Nonce: n}).AppendTo(nil))
}

func (s *Session) idleTimeout() time.Duration {
	s.mu.Lock()
	ms := wire.IdleTimeout(s.localLimits, s.peerLimits)
	s.mu.Unlock()
	return time.Duration(ms) * time.Millisecond
}

// armIdle runs the liveness check (5.5): Ping once nothing has arrived for
// half of idleTimeoutMs, close once nothing has arrived for all of it.
func (s *Session) armIdle() {
	idle := s.idleTimeout()
	if idle <= 0 {
		return
	}
	s.clock.AfterFunc(idle/4, func() {
		if s.isClosed() {
			return
		}
		now := s.clock.Now()
		since := now.Sub(time.Unix(0, s.lastRecv.Load()))
		idle := s.idleTimeout()
		switch {
		case since >= idle:
			s.fail(status.Unavailable, "idle timeout")
			return
		case since >= idle/2:
			s.mu.Lock()
			send := !s.pingSent
			s.pingSent = true
			s.mu.Unlock()
			if send {
				_ = s.Ping()
			}
		}
		s.armIdle()
	})
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

// GoAway starts a graceful shutdown (5.6): no new calls, running calls
// continue until they finish or the grace period ends, then the transport
// is closed. retryAfter may be nil.
func (s *Session) GoAway(code status.Code, reason string, retryAfter *uint64) {
	s.mu.Lock()
	if s.goAwaySent != nil || s.closed {
		s.mu.Unlock()
		return
	}
	g := &wire.GoAway{Status: uint64(code), Reason: reason, RetryAfterMs: retryAfter}
	s.goAwaySent = g
	s.draining = true
	empty := len(s.calls) == 0
	s.mu.Unlock()
	_ = s.shared.write(g.AppendTo(nil))
	s.mu.Lock()
	if s.goAwayDone == nil {
		s.goAwayDone = make(chan struct{})
		close(s.goAwayDone)
	}
	s.mu.Unlock()
	grace := dur(s.cfg.GracePeriod, DefaultGracePeriod)
	s.clock.AfterFunc(grace, func() { s.terminate(code, reason, false) })
	if empty {
		s.drained()
	}
}

// Close ends the session at once with GoAway(status) and closes the
// transport; running calls fail with unavailable.
func (s *Session) Close(code status.Code, reason string) {
	s.sendGoAwayAndClose(code, reason, nil, nil)
}

func (s *Session) onGoAway(g *wire.GoAway) {
	s.mu.Lock()
	if s.goAwayRecv != nil {
		s.mu.Unlock()
		return
	}
	s.goAwayRecv = g
	s.draining = true
	notDispatched := s.role == wire.Client && (s.optReject || !s.welcomeDone)
	handshaking := s.role == wire.Server && !s.readyDone
	empty := len(s.calls) == 0
	s.mu.Unlock()
	if s.cfg.OnGoAway != nil {
		go s.cfg.OnGoAway(s, g)
	}
	if notDispatched {
		s.terminateNotDispatched(g)
		return
	}
	if handshaking {
		s.terminate(status.Code(g.Status), g.Reason, true)
		return
	}
	grace := dur(s.cfg.GracePeriod, DefaultGracePeriod)
	s.clock.AfterFunc(grace, func() { s.terminate(status.Code(g.Status), g.Reason, true) })
	if empty {
		s.drained()
	}
}

// terminateNotDispatched ends a session whose calls certainly did not run.
func (s *Session) terminateNotDispatched(g *wire.GoAway) {
	s.mu.Lock()
	calls := make([]*call, 0, len(s.calls))
	for _, c := range s.calls {
		calls = append(calls, c)
	}
	if s.hsErr == nil {
		s.hsErr = &Error{Code: status.Code(g.Status), Message: g.Reason, Remote: true, NotDispatched: true}
	}
	s.mu.Unlock()
	for _, c := range calls {
		c.failLocal(&Error{Code: status.Code(g.Status), Message: g.Reason, Remote: true, NotDispatched: true})
	}
	s.terminate(status.Code(g.Status), g.Reason, true)
}

// drained is called when no call is open while draining.
func (s *Session) drained() {
	s.mu.Lock()
	g := s.goAwaySent
	r := s.goAwayRecv
	s.mu.Unlock()
	switch {
	case g != nil:
		s.terminate(status.Code(g.Status), g.Reason, false)
	case r != nil:
		s.terminate(status.Code(r.Status), r.Reason, true)
	}
}

// fail ends the session after a session-level error: GoAway(code) and close
// (8: outside any call, a protocol_error closes the session).
func (s *Session) fail(code status.Code, reason string) {
	s.logf("session failed: %v: %s", code, reason)
	s.sendGoAwayAndClose(code, reason, nil, nil)
}

func (s *Session) sendGoAwayAndClose(code status.Code, reason string, retry *uint64, versions []uint64) {
	s.mu.Lock()
	send := s.goAwaySent == nil && !s.closed && s.shared != nil
	var written chan struct{}
	if send {
		s.goAwaySent = &wire.GoAway{Status: uint64(code), Reason: reason, RetryAfterMs: retry, Versions: versions}
		s.draining = true
		written = make(chan struct{})
		s.goAwayDone = written
	}
	g := s.goAwaySent
	pending := s.goAwayDone
	s.mu.Unlock()
	if !send && pending != nil {
		// A GoAway is being written; close once it is out.
		go func() {
			t := time.NewTimer(dur(s.cfg.GoAwayWait, DefaultGoAwayWait))
			defer t.Stop()
			select {
			case <-pending:
			case <-t.C:
			}
			s.terminate(code, reason, false)
		}()
		return
	}
	if send {
		// Written directly: the session may be failing because writes on
		// the lane block or fail.
		l := s.shared
		go func() {
			l.wmu.Lock()
			_ = l.st.WriteMessage(g.AppendTo(nil))
			l.wmu.Unlock()
			close(written)
			s.terminate(code, reason, false)
		}()
		go func() {
			t := time.NewTimer(dur(s.cfg.GoAwayWait, DefaultGoAwayWait))
			defer t.Stop()
			select {
			case <-written:
			case <-t.C:
				s.terminate(code, reason, false)
			}
		}()
		return
	}
	s.terminate(code, reason, false)
}

// sendGoAwayAndCloseLocked is sendGoAwayAndClose while procMu is held.
func (s *Session) sendGoAwayAndCloseLocked(code status.Code, reason string, retry *uint64, versions []uint64) {
	s.sendGoAwayAndClose(code, reason, retry, versions)
}

// sharedEnded handles the end of the shared lane, which ends the session
// (4.1). Calls still open get a moment to finish (messages on leased
// streams may still be arriving), then fail.
func (s *Session) sharedEnded(err error) {
	s.mu.Lock()
	code := status.Unavailable
	reason := "connection closed"
	remote := true
	if s.goAwayRecv != nil {
		code, reason = status.Code(s.goAwayRecv.Status), s.goAwayRecv.Reason
	} else if s.goAwaySent != nil {
		code, reason, remote = status.Code(s.goAwaySent.Status), s.goAwaySent.Reason, false
	} else if ce := (*transport.CloseError)(nil); errors.As(err, &ce) && ce.Code != status.OK {
		code, reason = ce.Code, ce.Reason
	}
	open := len(s.calls)
	s.mu.Unlock()
	if open == 0 {
		s.terminate(code, reason, remote)
		return
	}
	s.mu.Lock()
	if s.noCalls == nil {
		s.noCalls = make(chan struct{})
		if len(s.calls) == 0 {
			close(s.noCalls)
		}
	}
	noCalls := s.noCalls
	s.mu.Unlock()
	go func() {
		t := time.NewTimer(dur(s.cfg.Linger, DefaultLinger))
		defer t.Stop()
		select {
		case <-noCalls:
		case <-t.C:
		}
		s.terminate(code, reason, remote)
	}()
}

// callGoneLocked signals sharedEnded once the last open call is gone
// (s.mu held).
func (s *Session) callGoneLocked() {
	if s.noCalls != nil && len(s.calls) == 0 {
		select {
		case <-s.noCalls:
		default:
			close(s.noCalls)
		}
	}
}

func (s *Session) transportGone() {
	err := s.conn.Err()
	code, reason := status.Unavailable, "transport closed"
	var ce *transport.CloseError
	if errors.As(err, &ce) {
		code, reason = ce.Code, ce.Reason
	}
	s.mu.Lock()
	if s.goAwayRecv != nil {
		code, reason = status.Code(s.goAwayRecv.Status), s.goAwayRecv.Reason
	}
	s.mu.Unlock()
	s.terminate(code, reason, true)
}

// lost handles a failed write on the shared lane.
// peerGoAway waits, up to Linger, for a session whose write just failed to
// end, and returns the GoAway the peer sent before closing, if any, and
// whether it means this side's calls were not dispatched (5.3).
func (s *Session) peerGoAway() (*wire.GoAway, bool) {
	t := time.NewTimer(dur(s.cfg.Linger, DefaultLinger))
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goAwayRecv, s.role == wire.Client && (s.optReject || !s.welcomeDone)
}

func (s *Session) lost(err error) {
	why := "shared lane write failed: " + err.Error()
	if s.sharedReading.Load() {
		// The peer may have closed after a GoAway this side has not read
		// yet: the shared-lane reader delivers it and then ends the
		// session; this is a fallback.
		s.clock.AfterFunc(dur(s.cfg.Linger, DefaultLinger), func() { s.terminate(status.Unavailable, why, false) })
		return
	}
	s.terminate(status.Unavailable, why, false)
}

// terminate closes the session: every open call fails, the transport is
// closed with the status, and Done is closed.
func (s *Session) terminate(code status.Code, reason string, remote bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.closeErr = &Error{Code: code, Message: reason, Remote: remote}
	if s.hsErr == nil && s.hs != hsOpen {
		s.hsErr = s.closeErr
	}
	notDispatched := s.role == wire.Client && ((!s.welcomeDone && !s.optimistic) || s.optReject)
	calls := make([]*call, 0, len(s.calls))
	for _, c := range s.calls {
		calls = append(calls, c)
	}
	s.signalPoolLocked()
	s.signalOutLocked()
	if s.ackSig != nil {
		close(s.ackSig)
		s.ackSig = nil
	}
	s.mu.Unlock()
	for _, c := range calls {
		c.failLocal(&Error{Code: status.Unavailable, Message: "session closed: " + reason, NotDispatched: notDispatched})
	}
	s.cancel()
	close(s.done)
	go func() { _ = s.conn.Close(code, reason) }()
}

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) closedError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr != nil {
		return &Error{Code: status.Unavailable, Message: "session closed: " + s.closeErr.Message}
	}
	return &Error{Code: status.Unavailable, Message: "session closed"}
}

// handshakeError returns why the handshake failed.
func (s *Session) handshakeError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hsErr != nil {
		return s.hsErr
	}
	if s.closeErr != nil {
		return s.closeErr
	}
	return &Error{Code: status.Unavailable, Message: "session closed"}
}

func (s *Session) closedErrorOr(err error) error {
	if s.isClosed() {
		return s.closedError()
	}
	return err
}

func (s *Session) wrapTransportErr(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var re *transport.ResetError
	if errors.As(err, &re) {
		return &Error{Code: re.Code, Message: "stream reset", Remote: re.Remote}
	}
	return &Error{Code: status.Unavailable, Message: err.Error()}
}

func (s *Session) signalOutLocked() {
	if s.outSig != nil {
		close(s.outSig)
		s.outSig = nil
	}
}

func (s *Session) ackWorker() {
	for {
		select {
		case f := <-s.ackQ:
			f()
		case <-s.done:
			return
		}
	}
}

// unused guard for imports kept for future use
var _ = cbor.Null
