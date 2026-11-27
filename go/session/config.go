package session

import (
	"context"
	"log/slog"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/wire"
)

// ProtocolVersion is the protocol version this implementation speaks.
const ProtocolVersion = 1

// Timing defaults (sections 5.2, 5.5, 5.6, 6.6, 7.5, 4.2).
const (
	DefaultHelloTimeout     = 10 * time.Second
	DefaultSchemaAckTimeout = 10 * time.Second
	DefaultCancelGiveUp     = 5 * time.Second
	DefaultCancelBroken     = 30 * time.Second
	DefaultGracePeriod      = 30 * time.Second
	DefaultLeaseIdle        = 30 * time.Second
	DefaultKeepIdle         = 2
	DefaultLinger           = time.Second
	DefaultResetWait        = 5 * time.Second
	DefaultGoAwayWait       = 2 * time.Second

	// PreAuthLimit bounds the shared-lane data the server buffers after
	// Hello until the credential is verified, and the data an optimistic
	// client sends before Welcome (5.2, 5.3).
	PreAuthLimit = 64 << 10
	// MaxClientSchemaSize is the default limit on Hello.client_schema.
	MaxClientSchemaSize = 64 << 10
	// MaxClientSchemaDepth bounds type-reference nesting in a client schema.
	MaxClientSchemaDepth = 32
	// MaxTokens is the number of byte tokens one sender may open in a call.
	MaxTokens = 64
	// SharedChunk is the largest Bytes chunk sent on the shared lane.
	SharedChunk = 16 << 10
	// LeaseChunk is the largest Bytes chunk sent on a leased stream (also
	// bounded by the peer's maxMessageSize).
	LeaseChunk = 256 << 10
	// MaxNotificationHandlers bounds notifications handled at once; more
	// are dropped (7.3: best-effort).
	MaxNotificationHandlers = 64
)

// Config configures a session. The zero value of every field is a usable
// default unless noted.
type Config struct {
	// Schema is this peer's own schema: the server's goes in Welcome, the
	// client's (optional) inline in Hello. A server with a nil Schema
	// publishes an empty one. A client with a nil Schema publishes none and
	// cannot publish one later.
	Schema *schema.Schema
	// Params are the limits this peer imposes on the other (5.4).
	Params wire.Params
	// Handler serves calls to this peer's facets. Nil answers every call
	// with Error(unimplemented).
	Handler Handler
	// Caps are this peer's capabilities.
	Caps wire.TextMap

	// Clock drives every timer; nil is the wall clock.
	Clock Clock
	// Logger receives diagnostics; nil discards them.
	Logger *slog.Logger

	// --- client side ---

	// Versions are the protocol versions offered, preferred first;
	// default [1].
	Versions []uint64
	// Auth is the credential sent in Hello.
	Auth *wire.Auth
	// KnownSchema is the cached server schema, offered as known_schema.
	KnownSchema *schema.Schema
	// KnownParams are the cached Welcome.params of that server; an
	// optimistic start is refused locally if they are below the defaults.
	KnownParams *wire.Params
	// Optimistic sends Hello, Ready and the first calls in one flight
	// (5.3). It needs KnownSchema.
	Optimistic bool
	// FetchSchema loads a schema offered out of band ([3, hash, location]).
	// It must return a schema whose hash is hash.
	FetchSchema func(ctx context.Context, location string, hash []byte) (*schema.Schema, error)
	// OnServerSchema is called with the server's schema and params after
	// Welcome, so the client can update its cache.
	OnServerSchema func(hash []byte, s *schema.Schema, params wire.Params)
	// OnAuthStatus is called for every AuthStatus the server sends.
	OnAuthStatus func(s *Session, m *wire.AuthStatus)

	// --- server side ---

	// Authenticate verifies Hello.auth and returns the principal. An error
	// closes the session with GoAway(unauthenticated), or with the code of
	// an *Error.
	Authenticate func(ctx context.Context, hello *wire.Hello) (principal string, err error)
	// AcceptClientSchema may reject the client schema (for example a hub
	// checks that facet names belong to the node); an error closes the
	// session with GoAway(invalid_argument) or the code of an *Error.
	AcceptClientSchema func(ctx context.Context, principal string, s *schema.Schema) error
	// SchemaByHash returns an older schema of this server by hash, so a
	// Delta offer can be sent to a client that names it in known_schema.
	SchemaByHash func(hash []byte) *schema.Schema
	// OfferLocation, if it returns ok, makes the offer out of band
	// ([3, hash, location]) instead of Full.
	OfferLocation func(hash []byte) (location string, ok bool)
	// Props are Welcome.props.
	Props wire.TextMap
	// MaxClientSchemaSize limits Hello.client_schema; 0 means 64 KiB and a
	// negative value means no limit (between a hub and its nodes, 10.2).
	MaxClientSchemaSize int
	// ClientSchemaLimit, if set, replaces MaxClientSchemaSize per session,
	// once the principal is known: a hub lifts the limit for its nodes
	// (10.2) and keeps it for clients on the same listener.
	ClientSchemaLimit func(principal string) int
	// SchemaFor, if set, chooses the server's schema once the credential is
	// verified, before Welcome: a hub sends each principal the facets
	// visible to it (10.3). It replaces Schema.
	SchemaFor func(ctx context.Context, principal string, hello *wire.Hello) (*schema.Schema, error)
	// HelloTimeout defaults to 10 s.
	HelloTimeout time.Duration
	// OnAuthRefresh handles AuthRefresh: it returns the AuthStatus to send
	// (status ok and the new expiry), or an error, which closes the session
	// with GoAway(unauthenticated). Nil answers unimplemented.
	OnAuthRefresh func(ctx context.Context, s *Session, auth *wire.Auth) (*wire.AuthStatus, error)

	// --- both ---

	// OnPeerSchemaUpdate runs after a peer SchemaUpdate has been applied
	// and before SchemaAck is sent; updates are handled one at a time, in
	// order. A hub uses it to relay the change and ack only once every
	// downstream session has (10.3). An error closes the session with
	// GoAway(schema_mismatch) or the code of an *Error.
	OnPeerSchemaUpdate func(ctx context.Context, s *Session, u *PeerSchemaUpdate) error
	// OnGoAway is called when the peer sends GoAway.
	OnGoAway func(s *Session, m *wire.GoAway)

	SchemaAckTimeout time.Duration // default 10 s
	CancelGiveUp     time.Duration // default 5 s
	CancelBroken     time.Duration // default 30 s
	GracePeriod      time.Duration // default 30 s
	// LeaseIdle is how long a leased stream may stay idle before it is
	// closed; default 30 s. KeepIdle streams are kept regardless (default
	// 2; negative keeps none).
	LeaseIdle time.Duration
	KeepIdle  int
	// WaitForLease makes calls wait for a leased stream when the pool is
	// exhausted, instead of falling back to the shared lane (4.2 rule 6).
	WaitForLease bool
	// Linger bounds how long the session waits for open calls to finish
	// after the peer finished the shared lane; default 1 s.
	Linger time.Duration
	// ResetWait bounds how long a leased stream this side reset stays
	// counted toward maxStreams while it waits for the peer to end its own
	// direction (4.2 rule 5); default 5 s. On a binding that cannot reset
	// one direction alone, the stream stays counted for this long.
	ResetWait time.Duration
	// GoAwayWait bounds how long the session waits for a GoAway it is
	// writing before it closes the transport anyway (the lane may be
	// blocked); default 2 s.
	GoAwayWait time.Duration
}

// PeerSchemaUpdate describes an applied SchemaUpdate from the peer.
type PeerSchemaUpdate struct {
	Epoch uint64
	Hash  []byte
	Delta schema.Delta
	// RawDelta is the delta as received.
	RawDelta cbor.Raw
	Old, New *schema.State
}

func (c *Config) clock() Clock {
	if c.Clock == nil {
		return RealClock{}
	}
	return c.Clock
}

func dur(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func (c *Config) keepIdle() int {
	switch {
	case c.KeepIdle < 0:
		return 0
	case c.KeepIdle == 0:
		return DefaultKeepIdle
	}
	return c.KeepIdle
}
