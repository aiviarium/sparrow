// Command sparrow-hub is the Sparrow reference server: a hub (Hub Profile,
// core spec section 10) configured at run time through sparrow.hub.admin
// (spec/hub-admin.md), listening on WebTransport (HTTP/3) and WebSocket.
//
//	sparrow-hub -config hub.json [-addr-file addrs.json]
//
// The static configuration file (JSON) holds only what cannot come through
// sparrow.hub.admin: listen addresses, TLS, the data directory and the
// bootstrap administrator. See Config. The hub never starts nodes: they
// dial in, or the hub dials the ones the document lists with a URL and pin.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/hub"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
	"github.com/aiviarium/sparrow-rpc/go/web"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Config is the static configuration file.
type Config struct {
	// SchemaName names the schema documents the hub sends.
	SchemaName string `json:"schemaName"`
	// WebTransport is the UDP address for HTTP/3 ("" disables it), served
	// at /sparrow/wt.
	WebTransport string `json:"webtransport"`
	// WebSocket is the TCP address for WebSocket ("" disables it), served
	// at /sparrow/ws; over TLS unless WebSocketPlain is set.
	WebSocket      string `json:"websocket"`
	WebSocketPlain bool   `json:"websocketPlain"`
	// TLS certificate and key files; or SelfSigned for development (a
	// 10-day certificate for Hosts, whose hash is logged and written to
	// the address file for serverCertificateHashes pinning).
	TLS struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"tls"`
	SelfSigned bool     `json:"selfSigned"`
	Hosts      []string `json:"hosts"`
	// DataDir holds the persisted state (hub-admin 2.4).
	DataDir string `json:"dataDir"`
	// Bootstrap administrators, always allowed on sparrow.hub.admin; each
	// authenticates with ["bearer", credential]. CredentialFile reads the
	// credential from a file instead.
	Bootstrap []struct {
		Principal      string `json:"principal"`
		Credential     string `json:"credential"`
		CredentialFile string `json:"credentialFile"`
	} `json:"bootstrap"`
	// Tokens are static bearer credentials for clients (development and
	// tests; reference-server note, section 5).
	Tokens []struct {
		Token     string   `json:"token"`
		Principal string   `json:"principal"`
		Groups    []string `json:"groups"`
	} `json:"tokens"`
	// Web turns on the Web Profile: facet 1 sparrow.web, POST
	// /sparrow/connect, /sparrow/schema/{hash} and /sparrow/mods/{hash}.{ext}
	// on both listeners. `true` or an object (WebConfig).
	Web WebConfig `json:"web"`
	// ConnectTimeoutMs bounds how long a call waits for a node that is not
	// connected (core 10.7; default 10000).
	ConnectTimeoutMs uint64 `json:"connectTimeoutMs"`
	// AllowedOrigins are the Origins accepted besides the hub's own (and
	// requests without one); ["*"] allows every origin.
	AllowedOrigins []string `json:"allowedOrigins"`
	// ShutdownGraceMs bounds the drain at shutdown (default 10000).
	ShutdownGraceMs uint64 `json:"shutdownGraceMs"`
	// Log is the level: debug, info, warn or error.
	Log string `json:"log"`
}

// WebConfig configures the Web Profile (core spec section 9).
type WebConfig struct {
	Enabled bool `json:"-"`
	// Audience names this edge instance in tickets (default: the
	// WebTransport endpoint, else the WebSocket one).
	Audience string `json:"audience"`
	// TicketKeyFile holds the hex Ed25519 seed that signs tickets; without
	// it a new key is made at every start (tickets then do not survive a
	// restart, which their 60 s lifetime makes harmless).
	TicketKeyFile string `json:"ticketKeyFile"`
	// TicketLifetimeMs is how long a ticket may be presented (default
	// 45000, at most 60000).
	TicketLifetimeMs uint64 `json:"ticketLifetimeMs"`
	// SessionLifetimeMs is the login session of a static token (default
	// 8 h).
	SessionLifetimeMs uint64 `json:"sessionLifetimeMs"`
	// ModulesDir is a directory of module and asset files, found by the
	// hash of their contents; the facets' web.modules entries sign them.
	ModulesDir string `json:"modulesDir"`
	// RootKeys (hex Ed25519 public keys) of the client build: ref.web
	// certificates and revocation lists must be signed by one of them.
	RootKeys []string `json:"rootKeys"`
	// MinHostAPI is the lowest client hostApi served (426 below it).
	MinHostAPI string `json:"minHostApi"`
}

// UnmarshalJSON accepts true, false or an object.
func (w *WebConfig) UnmarshalJSON(b []byte) error {
	var on bool
	if err := json.Unmarshal(b, &on); err == nil {
		*w = WebConfig{Enabled: on}
		return nil
	}
	type plain WebConfig
	var p plain
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("web: %v", err)
	}
	*w = WebConfig(p)
	w.Enabled = true
	return nil
}

// Addrs are the endpoints the hub listens on, written to -addr-file.
type Addrs struct {
	WebTransport string `json:"webtransport,omitempty"`
	WebSocket    string `json:"websocket,omitempty"`
	// CertHash is the SHA-256 of the certificate (serverCertificateHashes)
	// and Pin the SHA-256 of its SubjectPublicKeyInfo (Dial.pin of a hub
	// that dials this one), both hex.
	CertHash string `json:"certHash"`
	Pin      string `json:"pin"`
	// Web is the base URL of the Web Profile endpoints on the TCP
	// listener (POST <web>/sparrow/connect), when web is on.
	Web string `json:"web,omitempty"`
}

func main() {
	cfgPath := flag.String("config", "", "static configuration file (JSON)")
	addrFile := flag.String("addr-file", "", "write the listening endpoints (JSON) to this file once ready")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: sparrow-hub -config hub.json [-addr-file addrs.json]")
		os.Exit(2)
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sparrow-hub:", err)
		os.Exit(2)
	}
	log := newLogger(cfg.Log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = Run(ctx, cfg, log, func(a Addrs) {
		log.Info("ready", "webtransport", a.WebTransport, "websocket", a.WebSocket, "certHash", a.CertHash, "pin", a.Pin)
		if *addrFile != "" {
			b, _ := json.MarshalIndent(a, "", "  ")
			tmp := *addrFile + ".tmp"
			if err := os.WriteFile(tmp, b, 0o600); err == nil {
				_ = os.Rename(tmp, *addrFile)
			}
		}
	})
	if err != nil {
		log.Error("sparrow-hub", "err", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// LoadConfig reads and checks a static configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if c.DataDir == "" {
		return nil, errors.New("dataDir is required")
	}
	if len(c.Bootstrap) == 0 {
		return nil, errors.New("at least one bootstrap administrator is required")
	}
	for i := range c.Bootstrap {
		b := &c.Bootstrap[i]
		if b.CredentialFile != "" {
			v, err := os.ReadFile(b.CredentialFile)
			if err != nil {
				return nil, err
			}
			b.Credential = strings.TrimSpace(string(v))
		}
		if b.Credential == "" {
			return nil, fmt.Errorf("bootstrap administrator %q has no credential", b.Principal)
		}
	}
	if c.WebTransport == "" && c.WebSocket == "" {
		return nil, errors.New("listen on webtransport, websocket or both")
	}
	if !c.SelfSigned && (c.TLS.Cert == "" || c.TLS.Key == "") && (c.WebTransport != "" || !c.WebSocketPlain) {
		return nil, errors.New("tls.cert and tls.key are required (or selfSigned for development)")
	}
	return &c, nil
}

// selfSignedKeyFile keeps the key of the self-signed certificate in the
// data directory: the certificate is made anew at every start, but its SPKI
// pin, which nodes dialing in may check, stays the same.
const selfSignedKeyFile = "selfsigned.key"

func selfSignedKey(store *admin.Store) (*ecdsa.PrivateKey, error) {
	b, err := store.Read(selfSignedKeyFile)
	if err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			return x509.ParseECPrivateKey(blk.Bytes)
		}
		return nil, fmt.Errorf("%s: no PEM block", selfSignedKeyFile)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return key, store.Write(selfSignedKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// Run serves until ctx ends, then shuts down gracefully: GoAway to every
// session and node, then the listeners close.
func Run(ctx context.Context, c *Config, log *slog.Logger, ready func(Addrs)) error {
	var cert tls.Certificate
	store, err := admin.OpenStore(c.DataDir)
	if err != nil {
		return err
	}
	if c.SelfSigned {
		hosts := c.Hosts
		if len(hosts) == 0 {
			hosts = []string{"127.0.0.1", "localhost"}
		}
		var key *ecdsa.PrivateKey
		if key, err = selfSignedKey(store); err == nil {
			cert, _, err = webtransport.SelfSignedWithKey(key, hosts...)
		}
	} else if c.TLS.Cert != "" {
		cert, err = tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	}
	if err != nil {
		return err
	}
	var addrs Addrs
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(cert.Certificate[0])
		addrs.CertHash = hex.EncodeToString(sum[:])
		addrs.Pin = hex.EncodeToString(hub.PinFor(leaf))
	}
	// Listen first: the Web Profile needs the endpoints before serving.
	var pc net.PacketConn
	var ln net.Listener
	if c.WebTransport != "" {
		if pc, err = net.ListenPacket("udp", c.WebTransport); err != nil {
			return err
		}
		addrs.WebTransport = "https://" + hostPort(pc.LocalAddr(), c.Hosts) + "/sparrow/wt"
	}
	if c.WebSocket != "" {
		if ln, err = net.Listen("tcp", c.WebSocket); err != nil {
			if pc != nil {
				pc.Close()
			}
			return err
		}
		scheme, httpScheme := "wss://", "https://"
		if c.WebSocketPlain {
			scheme, httpScheme = "ws://", "http://"
		}
		addrs.WebSocket = scheme + hostPort(ln.Addr(), c.Hosts) + "/sparrow/ws"
		if c.Web.Enabled {
			addrs.Web = httpScheme + hostPort(ln.Addr(), c.Hosts)
		}
	}
	closeListeners := func() {
		if pc != nil {
			pc.Close()
		}
		if ln != nil {
			ln.Close()
		}
	}
	o := hub.Options{Store: store, SchemaName: c.SchemaName, Web: c.Web.Enabled, Logger: log, ConnectTimeout: time.Duration(c.ConnectTimeoutMs) * time.Millisecond}
	for _, b := range c.Bootstrap {
		o.Bootstrap = append(o.Bootstrap, hub.Credential{Principal: b.Principal, Token: b.Credential})
	}
	for _, t := range c.Tokens {
		o.Tokens = append(o.Tokens, hub.Credential{Token: t.Token, Principal: t.Principal, Groups: t.Groups})
	}
	var tickets *web.Tickets
	if c.Web.Enabled {
		if tickets, err = newTickets(&c.Web, addrs); err != nil {
			closeListeners()
			return err
		}
		for _, k := range c.Web.RootKeys {
			b, err := hex.DecodeString(k)
			if err != nil || len(b) != 32 {
				closeListeners()
				return fmt.Errorf("web.rootKeys: %q is not a hex Ed25519 public key", k)
			}
			o.WebRoots = append(o.WebRoots, b)
		}
		o.Authenticate = ticketAuthenticator(tickets)
	}
	h, err := hub.New(o)
	if err != nil {
		closeListeners()
		return err
	}
	var webSrv *web.Server
	if c.Web.Enabled {
		so := web.ServerOptions{Tickets: tickets, Host: h, Logger: log, AllowedOrigins: c.AllowedOrigins, MinHostAPI: c.Web.MinHostAPI,
			Endpoints: web.Endpoints{WebTransport: addrs.WebTransport, WebSocket: addrs.WebSocket}}
		st := &web.StaticTokens{SessionLifetime: time.Duration(c.Web.SessionLifetimeMs) * time.Millisecond}
		for _, t := range c.Tokens {
			st.Tokens = append(st.Tokens, web.StaticToken{Token: t.Token, Principal: t.Principal, Groups: t.Groups})
		}
		so.Auth = st
		if c.SelfSigned && len(cert.Certificate) > 0 {
			sum := sha256.Sum256(cert.Certificate[0])
			so.CertHashes = [][]byte{sum[:]}
		}
		if c.Web.ModulesDir != "" {
			so.Modules = &web.ModuleDir{Dir: c.Web.ModulesDir}
		}
		if webSrv, err = web.NewServer(so); err != nil {
			h.Close(time.Second)
			closeListeners()
			return err
		}
	}
	checkOrigin := originChecker(c.AllowedOrigins)
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}
	errc := make(chan error, 2)
	var closers []func()
	if pc != nil {
		srv := webtransport.NewServer(webtransport.ServerOptions{TLSConfig: tlsConf, CheckOrigin: checkOrigin})
		mux := http.NewServeMux()
		mux.Handle("/sparrow/wt", h.WebTransportHandler(srv))
		if webSrv != nil {
			webSrv.Mount(mux)
		}
		srv.WT.H3.Handler = mux
		go func() { errc <- srv.Serve(pc) }()
		closers = append(closers, func() { _ = srv.Close() })
	}
	if ln != nil {
		mux := http.NewServeMux()
		mux.Handle("/sparrow/ws", h.WebSocketHandler(checkOrigin))
		if webSrv != nil {
			webSrv.Mount(mux)
		}
		hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		if c.WebSocketPlain {
			go func() { errc <- hs.Serve(ln) }()
		} else {
			hs.TLSConfig = tlsConf.Clone()
			go func() { errc <- hs.ServeTLS(ln, "", "") }()
		}
		closers = append(closers, func() {
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = hs.Shutdown(sctx)
		})
	}
	if ready != nil {
		ready(addrs)
	}
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	grace := time.Duration(c.ShutdownGraceMs) * time.Millisecond
	if grace <= 0 {
		grace = 10 * time.Second
	}
	log.Info("shutting down", "grace", grace)
	h.Close(grace)
	for _, f := range closers {
		f()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
		return serveErr
	}
	return nil
}

func hostPort(a net.Addr, hosts []string) string {
	host, port, _ := net.SplitHostPort(a.String())
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
		if len(hosts) > 0 {
			host = hosts[0]
		}
	}
	return net.JoinHostPort(host, port)
}

// newTickets makes the ticket issuer: the key from TicketKeyFile or a new
// one, this edge instance as the audience.
func newTickets(w *WebConfig, a Addrs) (*web.Tickets, error) {
	var key ed25519.PrivateKey
	if w.TicketKeyFile != "" {
		b, err := os.ReadFile(w.TicketKeyFile)
		if err != nil {
			return nil, err
		}
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("web.ticketKeyFile must hold a hex Ed25519 seed (32 bytes)")
		}
		key = ed25519.NewKeyFromSeed(seed)
	} else {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		key = k
	}
	aud := w.Audience
	if aud == "" {
		aud = a.WebTransport
		if aud == "" {
			aud = a.WebSocket
		}
	}
	if w.TicketLifetimeMs > 60000 {
		return nil, errors.New("web.ticketLifetimeMs is at most 60000 (9.2)")
	}
	return &web.Tickets{Key: key, Audience: aud, Lifetime: time.Duration(w.TicketLifetimeMs) * time.Millisecond}, nil
}

// ticketAuthenticator accepts a Web Profile ticket in Hello and AuthRefresh
// as ["bearer", ticket] (9.2), once.
func ticketAuthenticator(t *web.Tickets) func(context.Context, *wire.Hello) (hub.Actor, error) {
	return func(ctx context.Context, h *wire.Hello) (hub.Actor, error) {
		if h.Auth == nil || h.Auth.Scheme != "bearer" {
			return hub.Actor{}, &session.Error{Code: status.Unauthenticated, Message: "a ticket is presented as [\"bearer\", ticket]"}
		}
		tok, err := cbor.NewDecoder(h.Auth.Credentials).Text()
		if err != nil {
			return hub.Actor{}, &session.Error{Code: status.Unauthenticated, Message: "a ticket is a text string"}
		}
		c, err := t.Verify(tok)
		if err != nil {
			return hub.Actor{}, &session.Error{Code: status.Unauthenticated, Message: err.Error()}
		}
		return hub.Actor{Principal: c.Subject, Groups: c.Groups, LoginSession: c.LoginSession, Expires: c.SessionExpiresAt()}, nil
	}
}

// originChecker allows requests without Origin, the hub's own origin, and
// the configured ones (4.6: servers MUST check Origin).
func originChecker(allowed []string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		o := r.Header.Get("Origin")
		if o == "" {
			return true
		}
		for _, a := range allowed {
			if a == "*" || a == o {
				return true
			}
		}
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
}
