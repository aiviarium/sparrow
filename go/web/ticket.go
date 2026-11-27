package web

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/names"
)

// MaxTicketLifetime is the longest a ticket may be presented after issue
// (9.2: exp within 60 s of issue).
const MaxTicketLifetime = 60 * time.Second

// Claims are the claims of a ticket (9.2). Groups is not one of the claims
// the spec lists; the reference hub adds it, when the login has groups, so
// the edge can authorize without calling the host.
type Claims struct {
	Subject        string   `json:"sub"`
	LoginSession   string   `json:"sid"`
	Audience       string   `json:"aud"`
	Expires        int64    `json:"exp"`
	IssuedAt       int64    `json:"iat"`
	ID             string   `json:"jti"`
	SessionExpires int64    `json:"sexp"`
	Groups         []string `json:"groups,omitempty"`
}

// ExpiresAt returns exp as a time.
func (c *Claims) ExpiresAt() time.Time { return time.Unix(c.Expires, 0) }

// SessionExpiresAt returns sexp as a time.
func (c *Claims) SessionExpiresAt() time.Time { return time.Unix(c.SessionExpires, 0) }

// JTIStore records ticket IDs until they expire, so each ticket is used
// once (9.2). Edges that share one hostname share one store.
type JTIStore interface {
	// Use records jti until the given time and reports whether it was
	// new.
	Use(jti string, until time.Time, now time.Time) bool
}

// MemoryJTIStore is an in-process JTIStore.
type MemoryJTIStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// Use implements JTIStore.
func (s *MemoryJTIStore) Use(jti string, until, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	if len(s.seen) > 1024 {
		for k, t := range s.seen {
			if !now.Before(t) {
				delete(s.seen, k)
			}
		}
	}
	if t, ok := s.seen[jti]; ok && now.Before(t) {
		return false
	}
	s.seen[jti] = until
	return true
}

// Tickets issues and verifies tickets: JWTs signed with EdDSA (Ed25519),
// bound to one edge instance (aud), single-use (9.2).
type Tickets struct {
	// Key signs tickets; Public verifies them (an edge that only verifies
	// needs Public alone).
	Key ed25519.PrivateKey
	// Public is the verification key; derived from Key when nil.
	Public ed25519.PublicKey
	// Audience names this edge instance: tickets are issued for it and
	// only tickets for it are accepted.
	Audience string
	// Lifetime is how long a ticket may be presented (default 45 s, at
	// most MaxTicketLifetime).
	Lifetime time.Duration
	// Store records used ticket IDs (default: in memory).
	Store JTIStore
	// Now is the clock (default time.Now).
	Now func() time.Time

	once sync.Once
}

func (t *Tickets) init() {
	t.once.Do(func() {
		if t.Public == nil && t.Key != nil {
			t.Public = t.Key.Public().(ed25519.PublicKey)
		}
		if t.Store == nil {
			t.Store = &MemoryJTIStore{}
		}
		if t.Now == nil {
			t.Now = time.Now
		}
		if t.Lifetime <= 0 {
			t.Lifetime = 45 * time.Second
		}
		if t.Lifetime > MaxTicketLifetime {
			t.Lifetime = MaxTicketLifetime
		}
	})
}

var b64 = base64.RawURLEncoding

// KeyID is the "kid" of the ticket header: base64url of the first 16 bytes
// of SHA-256 of the public key.
func ticketKeyID(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return b64.EncodeToString(s[:16])
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// Issue signs a ticket for a login.
func (t *Tickets) Issue(l *Login) (string, *Claims, error) {
	t.init()
	if t.Key == nil {
		return "", nil, errors.New("web: no ticket signing key")
	}
	now := t.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", nil, err
	}
	exp := now.Add(t.Lifetime)
	c := &Claims{Subject: l.Principal, LoginSession: l.Session, Audience: t.Audience, IssuedAt: now.Unix(),
		Expires: exp.Unix(), ID: b64.EncodeToString(jti), SessionExpires: l.Expires.Unix(), Groups: l.Groups}
	h, _ := json.Marshal(jwtHeader{Alg: "EdDSA", Typ: "JWT", Kid: ticketKeyID(t.Public)})
	p, err := json.Marshal(c)
	if err != nil {
		return "", nil, err
	}
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(t.Key, []byte(in))
	return in + "." + b64.EncodeToString(sig), c, nil
}

// TicketError says why a ticket was refused.
type TicketError struct{ Reason string }

func (e *TicketError) Error() string { return "web: ticket refused: " + e.Reason }

func refuse(format string, a ...any) error { return &TicketError{Reason: fmt.Sprintf(format, a...)} }

// Parse checks a ticket's signature and claims without using it up: the
// EdDSA signature, this edge as aud, exp in the future and within 60 s of
// iat, sexp in the future, a principal as sub, a sid and a jti.
func (t *Tickets) Parse(ticket string) (*Claims, error) {
	t.init()
	parts := strings.Split(ticket, ".")
	if len(parts) != 3 {
		return nil, refuse("not a JWT")
	}
	hb, err1 := b64.DecodeString(parts[0])
	pb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, refuse("bad base64url")
	}
	var h jwtHeader
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "EdDSA" {
		return nil, refuse("the algorithm must be EdDSA")
	}
	if t.Public == nil || !ed25519.Verify(t.Public, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, refuse("bad signature")
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, refuse("bad claims")
	}
	now := t.Now().Unix()
	safe := func(n int64) bool { return n >= -cbor.MaxSafeInt && n <= cbor.MaxSafeInt }
	switch {
	case !safe(c.IssuedAt) || !safe(c.Expires) || !safe(c.SessionExpires):
		return nil, refuse("a time claim is beyond ±(2^53 - 1)")
	case c.Audience != t.Audience:
		return nil, refuse("issued for another edge (aud %q)", c.Audience)
	case c.Expires <= now:
		return nil, refuse("expired")
	case c.IssuedAt == 0 || c.IssuedAt > c.Expires ||
		uint64(c.Expires)-uint64(c.IssuedAt) > uint64(MaxTicketLifetime/time.Second): // no overflow
		return nil, refuse("exp is more than 60 s after iat")
	case c.SessionExpires <= now:
		return nil, refuse("the login session has ended")
	case !names.IsPrincipal(c.Subject):
		return nil, refuse("sub is not a principal")
	case c.LoginSession == "" || c.ID == "":
		return nil, refuse("sid and jti are required")
	}
	return &c, nil
}

// Verify checks a ticket (Parse) and uses it up: a ticket is accepted
// once.
func (t *Tickets) Verify(ticket string) (*Claims, error) {
	c, err := t.Parse(ticket)
	if err != nil {
		return nil, err
	}
	if !t.Store.Use(c.ID, c.ExpiresAt().Add(time.Second), t.Now()) {
		return nil, refuse("already used")
	}
	return c, nil
}
