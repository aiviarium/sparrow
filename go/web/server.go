// Package web implements the hub side of the Sparrow Web Profile (core spec
// section 9): POST /sparrow/connect with pluggable HTTP authentication and
// single-use EdDSA JWT tickets (9.1, 9.2), the schema and module resources
// (9.3) with their caching rules and hash checks, the web.* annotations a
// hub publishes (9.4, 9.5), and a client (Client, Loader, Snapshot) that
// follows the browser rules: module signatures, rollback protection,
// revocation and offline snapshots (9.5, 9.6).
package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/websign"
)

// Paths of the Web Profile resources.
const (
	ConnectPath = "/sparrow/connect"
	SchemaPath  = "/sparrow/schema/"
	ModsPath    = "/sparrow/mods/"
)

// Host is what the Web Profile server needs from the hub.
type Host interface {
	// SchemaFor returns the schema a session of this principal would get.
	// An empty principal is the anonymous viewer: what every user may see.
	SchemaFor(principal string, groups []string) (*schema.Schema, error)
}

// ModuleSource returns module and asset files by their hash.
type ModuleSource interface {
	Open(hash []byte) ([]byte, bool)
}

// Endpoints are the session endpoints /connect returns, WebTransport
// first, WebSocket as the fallback (9.1).
type Endpoints struct {
	WebTransport string `json:"webtransport,omitempty"`
	WebSocket    string `json:"websocket,omitempty"`
}

// ServerOptions configure a Server.
type ServerOptions struct {
	Tickets   *Tickets
	Auth      Authenticator
	Host      Host
	Endpoints Endpoints
	// CertHashes are the SHA-256 hashes of the certificate, returned as
	// serverCertificateHashes for a self-signed WebTransport endpoint.
	CertHashes [][]byte
	// AllowedOrigins are origins allowed besides the endpoint's own; "*"
	// allows every origin. Requests from them get CORS headers.
	AllowedOrigins []string
	// MinHostAPI is the lowest client hostApi this host serves; an older
	// client gets 426 (9.1).
	MinHostAPI string
	// Modules is where module and asset files come from.
	Modules ModuleSource
	Logger  *slog.Logger
}

// Server serves /sparrow/connect, /sparrow/schema/{hash} and
// /sparrow/mods/{hash}.{ext}.
type Server struct {
	o   ServerOptions
	log *slog.Logger

	mu      sync.Mutex
	schemas map[string]*cachedSchema // schema hash -> bytes and who saw it
	order   []string
}

type cachedSchema struct {
	bytes      []byte
	principals map[string]bool
}

// NewServer returns a Server.
func NewServer(o ServerOptions) (*Server, error) {
	if o.Tickets == nil || o.Auth == nil || o.Host == nil {
		return nil, errors.New("web: Tickets, Auth and Host are required")
	}
	if o.Tickets.Audience == "" {
		return nil, errors.New("web: the ticket audience (this edge instance) is required")
	}
	if o.MinHostAPI != "" {
		if _, err := websign.ParseVersion(o.MinHostAPI); err != nil {
			return nil, fmt.Errorf("web: MinHostAPI: %v", err)
		}
	}
	s := &Server{o: o, log: o.Logger, schemas: map[string]*cachedSchema{}}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// Tickets returns the ticket issuer and verifier.
func (s *Server) Tickets() *Tickets { return s.o.Tickets }

// ServeHTTP routes the three resources.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.cors(w, r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch {
	case r.URL.Path == ConnectPath:
		s.connect(w, r)
	case strings.HasPrefix(r.URL.Path, SchemaPath):
		s.schema(w, r)
	case strings.HasPrefix(r.URL.Path, ModsPath):
		s.mods(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Mount registers the server's paths on a mux.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.Handle(ConnectPath, s)
	mux.Handle(SchemaPath, s)
	mux.Handle(ModsPath, s)
}

func (s *Server) originAllowed(r *http.Request, origin string) bool {
	for _, a := range s.o.AllowedOrigins {
		if a == "*" || a == origin {
			return true
		}
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

// cors answers for a cross-origin request from an allowed origin and
// reports false for a disallowed one.
func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	if !s.originAllowed(r, o) {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", o)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Add("Vary", "Origin")
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET, POST")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		h.Set("Access-Control-Max-Age", "600")
	}
	return true
}

// ---------------------------------------------------------------------------
// /sparrow/connect (9.1, 9.2)
// ---------------------------------------------------------------------------

// ClientInfo describes the client in a connect request.
type ClientInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	HostAPI string `json:"hostApi,omitempty"`
}

// ConnectRequest is the JSON body of POST /sparrow/connect: a connect, or
// the refresh form.
type ConnectRequest struct {
	Client          *ClientInfo `json:"client,omitempty"`
	KnownSchemaHash string      `json:"knownSchemaHash,omitempty"`
	Refresh         *struct {
		Endpoint string `json:"endpoint"`
	} `json:"refresh,omitempty"`
}

// ConnectResponse is the 200 answer to a connect request (9.1).
type ConnectResponse struct {
	Ticket                  string    `json:"ticket"`
	TicketExpiresAt         string    `json:"ticketExpiresAt"`
	SessionExpiresAt        string    `json:"sessionExpiresAt"`
	Endpoints               Endpoints `json:"endpoints"`
	ProtocolVersions        []uint64  `json:"protocolVersions"`
	SchemaHash              string    `json:"schemaHash"`
	SchemaURL               string    `json:"schemaUrl"`
	ServerCertificateHashes []string  `json:"serverCertificateHashes"`
}

// RefreshResponse is the answer to the refresh form: only a new ticket
// (9.2).
type RefreshResponse struct {
	Ticket string `json:"ticket"`
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// CSRF-safe requests only: a JSON body with Content-Type
	// application/json (9.1).
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	login, err := s.o.Auth.Authenticate(r)
	if err != nil || login == nil {
		http.Error(w, "log in again", http.StatusUnauthorized)
		return
	}
	if login.Cookie {
		// A cookie login also needs an allowed Origin (9.1).
		if o := r.Header.Get("Origin"); o == "" || !s.originAllowed(r, o) {
			http.Error(w, "a cookie-authenticated request needs an allowed Origin", http.StatusForbidden)
			return
		}
	}
	if !login.Expires.After(s.o.Tickets.now()) {
		http.Error(w, "the login session has ended", http.StatusUnauthorized)
		return
	}
	var req ConnectRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad JSON body", http.StatusBadRequest)
		return
	}
	if req.Refresh != nil {
		s.refresh(w, login, req.Refresh.Endpoint)
		return
	}
	if s.o.MinHostAPI != "" {
		api := ""
		if req.Client != nil {
			api = req.Client.HostAPI
		}
		v, err := websign.ParseVersion(api)
		if err != nil {
			http.Error(w, "client.hostApi must be a semver version", http.StatusBadRequest)
			return
		}
		min, _ := websign.ParseVersion(s.o.MinHostAPI)
		if v.Compare(min) < 0 {
			http.Error(w, "hostApi "+api+" is too old for this host (needs "+s.o.MinHostAPI+")", http.StatusUpgradeRequired)
			return
		}
	}
	sc, hash, err := s.schemaFor(login)
	if err != nil {
		s.log.Error("web: cannot compose the schema", "principal", login.Principal, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = sc
	ticket, c, err := s.o.Tickets.Issue(login)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := ConnectResponse{Ticket: ticket, TicketExpiresAt: c.ExpiresAt().UTC().Format(time.RFC3339),
		SessionExpiresAt: login.Expires.UTC().Format(time.RFC3339), Endpoints: s.o.Endpoints,
		ProtocolVersions: []uint64{1}, SchemaHash: b64.EncodeToString(hash), SchemaURL: SchemaPath + b64.EncodeToString(hash)}
	for _, h := range s.o.CertHashes {
		resp.ServerCertificateHashes = append(resp.ServerCertificateHashes, b64.EncodeToString(h))
	}
	writeJSON(w, resp)
}

func (s *Server) refresh(w http.ResponseWriter, login *Login, endpoint string) {
	if endpoint == "" || (endpoint != s.o.Endpoints.WebTransport && endpoint != s.o.Endpoints.WebSocket) {
		http.Error(w, "refresh.endpoint is not an endpoint of this edge", http.StatusBadRequest)
		return
	}
	ticket, _, err := s.o.Tickets.Issue(login)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, RefreshResponse{Ticket: ticket})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (t *Tickets) now() time.Time {
	t.init()
	return t.Now()
}

// schemaFor composes the principal's schema and remembers its bytes for
// GET /sparrow/schema/{hash}.
func (s *Server) schemaFor(l *Login) (*schema.Schema, []byte, error) {
	sc, err := s.o.Host.SchemaFor(l.Principal, l.Groups)
	if err != nil {
		return nil, nil, err
	}
	h, err := sc.Hash()
	if err != nil {
		return nil, nil, err
	}
	b, err := sc.CanonicalBytes()
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.schemas[string(h)]
	if c == nil {
		c = &cachedSchema{bytes: b, principals: map[string]bool{}}
		s.schemas[string(h)] = c
		s.order = append(s.order, string(h))
		if len(s.order) > 256 {
			delete(s.schemas, s.order[0])
			s.order = s.order[1:]
		}
	}
	c.principals[l.Principal] = true
	return sc, h, nil
}

// ---------------------------------------------------------------------------
// /sparrow/schema/{hash} and /sparrow/mods/{hash}.{ext} (9.3)
// ---------------------------------------------------------------------------

const immutable = "max-age=31536000, immutable"

func (s *Server) schema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	hash, err := b64.DecodeString(strings.TrimPrefix(r.URL.Path, SchemaPath))
	if err != nil || len(hash) != 33 {
		http.NotFound(w, r)
		return
	}
	login, err := s.o.Auth.Authenticate(r)
	if err != nil || login == nil {
		http.Error(w, "log in again", http.StatusUnauthorized)
		return
	}
	if _, _, err := s.schemaFor(login); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	c := s.schemas[string(hash)]
	ok := c != nil && c.principals[login.Principal]
	var b []byte
	if ok {
		b = c.bytes
	}
	s.mu.Unlock()
	if !ok {
		// Unknown, or a schema of another principal: never revealed.
		http.NotFound(w, r)
		return
	}
	// Schemas differ by permission here, so they are always private (9.3).
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Cache-Control", "private, "+immutable)
	w.Header().Set("ETag", `"`+b64.EncodeToString(hash)+`"`)
	_, _ = w.Write(b)
}

// ContentType returns the media type for a module or asset extension.
func ContentType(ext string) string {
	switch strings.ToLower(ext) {
	case "js", "mjs":
		return "text/javascript"
	case "css":
		return "text/css"
	case "wasm":
		return "application/wasm"
	case "json":
		return "application/json"
	case "svg":
		return "image/svg+xml"
	}
	if t := mime.TypeByExtension("." + ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

func (s *Server) mods(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, ModsPath)
	hs, ext, ok := strings.Cut(name, ".")
	hash, err := b64.DecodeString(hs)
	if !ok || err != nil || len(hash) != 33 || ext == "" || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	// Public: a file every user may load, which the anonymous view lists.
	public := false
	if sc, err := s.o.Host.SchemaFor("", nil); err == nil {
		es, _ := SchemaEntries(sc)
		if f, found := FindFile(es, hash); found && f.Ext == ext {
			public = true
		}
	}
	if !public {
		login, err := s.o.Auth.Authenticate(r)
		if err != nil || login == nil {
			http.Error(w, "log in again", http.StatusUnauthorized)
			return
		}
		sc, err := s.o.Host.SchemaFor(login.Principal, login.Groups)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		es, _ := SchemaEntries(sc)
		f, found := FindFile(es, hash)
		if !found || f.Ext != ext {
			// Not a file of a facet this user sees.
			http.NotFound(w, r)
			return
		}
	}
	if s.o.Modules == nil {
		http.NotFound(w, r)
		return
	}
	data, ok := s.o.Modules.Open(hash)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !bytes.Equal(websign.FileHash(data), hash) {
		// Never serve bytes that do not match their name.
		s.log.Error("web: module file does not match its hash", "hash", hs)
		http.Error(w, "module store corrupted", http.StatusInternalServerError)
		return
	}
	cc := "private, " + immutable
	if public {
		cc = "public, " + immutable
	}
	w.Header().Set("Content-Type", ContentType(ext))
	w.Header().Set("Cache-Control", cc)
	w.Header().Set("ETag", `"`+hs+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// ---------------------------------------------------------------------------
// Module directory
// ---------------------------------------------------------------------------

// ModuleDir is a ModuleSource over a directory of module and asset files
// (any names; files are found by the hash of their contents). The
// directory is indexed at the first lookup and again when a hash is
// missing, at most once a second.
type ModuleDir struct {
	Dir string

	mu      sync.Mutex
	index   map[string]string // hash -> path
	scanned time.Time
}

// Open implements ModuleSource. The caller checks the hash of what it
// gets.
func (m *ModuleDir) Open(hash []byte) ([]byte, bool) {
	m.mu.Lock()
	p, ok := m.index[string(hash)]
	if !ok && time.Since(m.scanned) > time.Second {
		m.scanLocked()
		p, ok = m.index[string(hash)]
	}
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return b, true
}

func (m *ModuleDir) scanLocked() {
	m.scanned = time.Now()
	idx := map[string]string{}
	_ = filepath.WalkDir(m.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err == nil {
			idx[string(websign.FileHash(b))] = p
		}
		return nil
	})
	m.index = idx
}

// FileName is the URL path of a module file: /sparrow/mods/{hash}.{ext}.
func FileName(hash []byte, ext string) string { return ModsPath + b64.EncodeToString(hash) + "." + ext }

// EncodeHash is the base64url (no padding) form of a hash used in JSON and
// URLs (9.1).
func EncodeHash(h []byte) string { return b64.EncodeToString(h) }

// DecodeHash parses EncodeHash's form.
func DecodeHash(s string) ([]byte, error) { return b64.DecodeString(s) }
