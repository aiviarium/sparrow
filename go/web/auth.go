package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Login is what HTTP authentication established for a request: the
// principal, its groups, the login session and when it ends (9.1, 9.2).
type Login struct {
	Principal string
	Groups    []string
	// Session is the login session's ID (the ticket's sid).
	Session string
	// Expires is when the login session ends (the ticket's sexp).
	Expires time.Time
	// Cookie is set when the login came from a cookie, so /connect also
	// checks the request's Origin (9.1).
	Cookie bool
}

// ErrNoLogin means the request carries no valid login: /connect answers
// 401 (log in again).
var ErrNoLogin = errors.New("web: not logged in")

// Authenticator is the host's HTTP authentication (9.1: "whatever
// authentication the host already has"). It returns ErrNoLogin (or any
// error) for a request without a valid login.
type Authenticator interface {
	Authenticate(r *http.Request) (*Login, error)
}

// AuthenticatorFunc adapts a function, for tests and simple hosts.
type AuthenticatorFunc func(r *http.Request) (*Login, error)

// Authenticate implements Authenticator.
func (f AuthenticatorFunc) Authenticate(r *http.Request) (*Login, error) { return f(r) }

// StaticToken is one bearer token of StaticTokens.
type StaticToken struct {
	Token     string
	Principal string
	Groups    []string
}

// StaticTokens authenticates "Authorization: Bearer <token>" against a
// fixed list, for development and tests (reference-server note, section
// 5). The login session of a token is derived from the token, and lasts
// SessionLifetime (default 8 h) from each request.
type StaticTokens struct {
	Tokens          []StaticToken
	SessionLifetime time.Duration
	Now             func() time.Time
}

// Authenticate implements Authenticator.
func (s *StaticTokens) Authenticate(r *http.Request) (*Login, error) {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return nil, ErrNoLogin
	}
	for _, t := range s.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Token), []byte(tok)) == 1 {
			now := time.Now
			if s.Now != nil {
				now = s.Now
			}
			life := s.SessionLifetime
			if life <= 0 {
				life = 8 * time.Hour
			}
			sum := sha256.Sum256([]byte(t.Token))
			return &Login{Principal: t.Principal, Groups: t.Groups, Session: "static-" + hex.EncodeToString(sum[:8]),
				Expires: now().Add(life).Truncate(time.Second)}, nil
		}
	}
	return nil, ErrNoLogin
}
