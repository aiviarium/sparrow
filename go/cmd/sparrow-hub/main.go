// Command sparrow-hub is the Sparrow reference server: a hub (Hub Profile,
// core spec section 10) configured at run time through sparrow.hub.admin
// (spec/hub-admin.md), listening on WebTransport (HTTP/3) and WebSocket.
//
//	sparrow-hub -config hub.json [-addr-file addrs.json]
//
// The static configuration file (JSON) holds only what cannot come through
// sparrow.hub.admin: listen addresses, TLS, the data directory and the
// bootstrap administrator. See Config.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
	"github.com/aiviarium/sparrow-rpc/go/hub"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
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
	// Web publishes facet 1 sparrow.web.
	Web bool `json:"web"`
	// StartTimeoutMs bounds how long calls wait for a node (default 10000).
	StartTimeoutMs uint64 `json:"startTimeoutMs"`
	// AllowedOrigins are the Origins accepted besides the hub's own (and
	// requests without one); ["*"] allows every origin.
	AllowedOrigins []string `json:"allowedOrigins"`
	// ShutdownGraceMs bounds the drain at shutdown (default 10000).
	ShutdownGraceMs uint64 `json:"shutdownGraceMs"`
	// Log is the level: debug, info, warn or error.
	Log string `json:"log"`
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

// Run serves until ctx ends, then shuts down gracefully: GoAway to every
// session and node, then the listeners close.
func Run(ctx context.Context, c *Config, log *slog.Logger, ready func(Addrs)) error {
	var cert tls.Certificate
	var err error
	if c.SelfSigned {
		hosts := c.Hosts
		if len(hosts) == 0 {
			hosts = []string{"127.0.0.1", "localhost"}
		}
		cert, _, err = webtransport.SelfSigned(hosts...)
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
	store, err := admin.OpenStore(c.DataDir)
	if err != nil {
		return err
	}
	o := hub.Options{Store: store, SchemaName: c.SchemaName, Web: c.Web, Logger: log, StartTimeout: time.Duration(c.StartTimeoutMs) * time.Millisecond}
	for _, b := range c.Bootstrap {
		o.Bootstrap = append(o.Bootstrap, hub.Credential{Principal: b.Principal, Token: b.Credential})
	}
	for _, t := range c.Tokens {
		o.Tokens = append(o.Tokens, hub.Credential{Token: t.Token, Principal: t.Principal, Groups: t.Groups})
	}
	h, err := hub.New(o)
	if err != nil {
		return err
	}
	checkOrigin := originChecker(c.AllowedOrigins)
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}
	errc := make(chan error, 2)
	var closers []func()
	if c.WebTransport != "" {
		srv := webtransport.NewServer(webtransport.ServerOptions{TLSConfig: tlsConf, CheckOrigin: checkOrigin})
		mux := http.NewServeMux()
		mux.Handle("/sparrow/wt", h.WebTransportHandler(srv))
		srv.WT.H3.Handler = mux
		pc, err := net.ListenPacket("udp", c.WebTransport)
		if err != nil {
			h.Close(time.Second)
			return err
		}
		addrs.WebTransport = "https://" + hostPort(pc.LocalAddr(), c.Hosts) + "/sparrow/wt"
		go func() { errc <- srv.Serve(pc) }()
		closers = append(closers, func() { _ = srv.Close() })
	}
	if c.WebSocket != "" {
		ln, err := net.Listen("tcp", c.WebSocket)
		if err != nil {
			h.Close(time.Second)
			return err
		}
		mux := http.NewServeMux()
		mux.Handle("/sparrow/ws", h.WebSocketHandler(checkOrigin))
		hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		scheme := "wss://"
		if c.WebSocketPlain {
			scheme = "ws://"
			go func() { errc <- hs.Serve(ln) }()
		} else {
			hs.TLSConfig = tlsConf.Clone()
			go func() { errc <- hs.ServeTLS(ln, "", "") }()
		}
		addrs.WebSocket = scheme + hostPort(ln.Addr(), c.Hosts) + "/sparrow/ws"
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
