// Package localhub embeds a Sparrow hub in-process for desktop (Wails) clients.
//
// It listens on 127.0.0.1 with both WebTransport (HTTP/3, self-signed ECDSA
// certificate + serverCertificateHashes) and WebSocket (plain loopback),
// mints a per-launch random bearer token for the embedded WebView, supports
// local Go nodes and 1-hop federation to remote Sparrow hubs over WebTransport,
// and proxies/caches federated web.modules from peer hubs so the WebView can
// load signed UI modules from both local and remote services through one origin.
package localhub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/adminiface"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/hub"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport/webtransport"
	"github.com/aiviarium/sparrow/go/web"
	"github.com/aiviarium/sparrow/go/websign"
	"github.com/aiviarium/sparrow/go/wire"
)

// PeerConfig describes a remote Sparrow hub to federate with (1-hop, core 10.8).
type PeerConfig struct {
	// ID is the peer hub's local name; its facets are imported as "<ID>/<facet>".
	ID string `json:"id"`
	// URL is the peer hub's WebTransport (https://...) or WebSocket (ws://.../wss://...) endpoint.
	URL string `json:"url"`
	// Pin is the hex SHA-256 of the peer hub's SubjectPublicKeyInfo (optional for CA-signed TLS).
	Pin string `json:"pin,omitempty"`
	// Credential is the link credential registered on the peer hub for this desktop hub.
	Credential string `json:"credential"`
	// WebBaseURL is the peer hub's HTTP origin (e.g. "https://hub.example.com") used to
	// proxy and cache federated web.modules and assets. Optional.
	WebBaseURL string `json:"webBaseUrl,omitempty"`
	// WebAuthHeader is an optional Authorization header value (e.g. "Bearer ...")
	// sent when fetching non-public modules from WebBaseURL.
	WebAuthHeader string `json:"webAuthHeader,omitempty"`
}

// Config configures the embedded local hub.
type Config struct {
	// DataDir stores the hub's admin state and cached federated modules.
	// If empty, a temporary directory is created and removed on Close.
	DataDir string
	// ModulesDir serves locally installed signed web modules (optional).
	ModulesDir string
	// Principal is the local desktop user principal (default "user:local").
	Principal string
	// Groups are optional policy groups for the local desktop user.
	Groups []string
	// RootKeys are hex-encoded 32-byte Ed25519 root public keys for web.modules.
	RootKeys []string
	// MinHostAPI is the minimum hostApi advertised by the web profile (default "3.0.0").
	MinHostAPI string
	// Peers lists remote hubs to federate with on startup.
	Peers []PeerConfig
	// Logger receives hub logs (defaults to slog.Default()).
	Logger *slog.Logger
}

// ClientInfo is passed to the Wails frontend so @aiviarium/sparrow-client can
// connect to the embedded local hub.
type ClientInfo struct {
	BaseURL      string   `json:"baseUrl"`
	WebTransport string   `json:"webtransport"`
	WebSocket    string   `json:"websocket"`
	CertHash     string   `json:"certHash"`
	Token        string   `json:"token"`
	RootKeys     []string `json:"rootKeys"`
	Principal    string   `json:"principal"`
}

// Instance is a running embedded local Sparrow hub.
type Instance struct {
	Hub       *hub.Hub
	Info      ClientInfo
	Pin       []byte // SPKI SHA-256 of the local WebTransport listener
	adminTok  string
	adminNode *nd.Node
	adminCli  *admin.Client
	dataDir   string
	tempDir   bool
	modStore  *peerModuleStore
	wtSrv     *webtransport.Server
	httpSrv   *http.Server
	mu        sync.Mutex
	doc       admin.Config
	gen       uint64
	closers   []func()
	closed    bool
}

type peerWebTarget struct {
	id         string
	baseURL    string
	authHeader string
	client     *http.Client
}

// peerModuleStore implements web.ModuleSource: serves from local ModulesDir
// first, then local disk cache, then fetches and hash-verifies from configured
// peer hubs' HTTP module endpoints (caching on disk for offline reloads).
type peerModuleStore struct {
	local    *web.ModuleDir
	cacheDir string
	mu       sync.RWMutex
	peers    []peerWebTarget
}

func (s *peerModuleStore) addPeer(t peerWebTarget) {
	s.mu.Lock()
	s.peers = append(s.peers, t)
	s.mu.Unlock()
}

func (s *peerModuleStore) Open(hash []byte) ([]byte, bool) {
	if s.local != nil {
		if b, ok := s.local.Open(hash); ok {
			return b, true
		}
	}
	cachePath := filepath.Join(s.cacheDir, hex.EncodeToString(hash))
	if b, err := os.ReadFile(cachePath); err == nil {
		if bytes.Equal(websign.FileHash(b), hash) {
			return b, true
		}
	}
	s.mu.RLock()
	peers := append([]peerWebTarget(nil), s.peers...)
	s.mu.RUnlock()

	// Try fetching from peer hubs via web.FileName(hash, ext) (which includes web.ModsPath).
	for _, peer := range peers {
		for _, ext := range []string{"js", "css", "json", "wasm", "svg", "bin"} {
			u := peer.baseURL + web.FileName(hash, ext)
			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err != nil {
				continue
			}
			if peer.authHeader != "" {
				req.Header.Set("Authorization", peer.authHeader)
			}
			resp, err := peer.client.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				continue
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			_ = resp.Body.Close()
			if err != nil {
				continue
			}
			if !bytes.Equal(websign.FileHash(body), hash) {
				continue
			}
			_ = os.MkdirAll(s.cacheDir, 0o700)
			_ = os.WriteFile(cachePath, body, 0o600)
			return body, true
		}
	}
	return nil, false
}

// Start launches an in-process Sparrow hub listening on 127.0.0.1 with both
// WebTransport (HTTP/3) and WebSocket + Web Profile HTTP endpoints.
func Start(ctx context.Context, cfg Config) (*Instance, error) {
	if cfg.Principal == "" {
		cfg.Principal = "user:local"
	}
	if cfg.MinHostAPI == "" {
		cfg.MinHostAPI = "3.0.0"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	tempDir := false
	dataDir := cfg.DataDir
	if dataDir == "" {
		d, err := os.MkdirTemp("", "sparrow-desktop-hub-*")
		if err != nil {
			return nil, fmt.Errorf("localhub: temp dir: %w", err)
		}
		dataDir = d
		tempDir = true
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("localhub: data dir: %w", err)
	}
	cacheDir := filepath.Join(dataDir, "module-cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("localhub: cache dir: %w", err)
	}
	modsDir := cfg.ModulesDir
	if modsDir == "" {
		modsDir = filepath.Join(dataDir, "modules")
		_ = os.MkdirAll(modsDir, 0o700)
	}

	userTok := randomHex(32)
	adminTok := randomHex(32)

	store, err := admin.OpenStore(filepath.Join(dataDir, "store"))
	if err != nil {
		return nil, fmt.Errorf("localhub: open store: %w", err)
	}

	var rootKeys [][]byte
	for _, rk := range cfg.RootKeys {
		b, err := hex.DecodeString(rk)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("localhub: invalid root key %q", rk)
		}
		rootKeys = append(rootKeys, b)
	}

	// Self-signed ECDSA cert (10-day validity, WebTransport serverCertificateHashes compatible).
	cert, certHash, err := webtransport.SelfSigned("127.0.0.1")
	if err != nil {
		return nil, fmt.Errorf("localhub: self-signed cert: %w", err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pin := hub.PinFor(leaf)

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("localhub: listen udp: %w", err)
	}
	wtURL := fmt.Sprintf("https://127.0.0.1:%d/sparrow/wt", udpConn.LocalAddr().(*net.UDPAddr).Port)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("localhub: listen tcp: %w", err)
	}
	httpAddr := httpLn.Addr().String()
	baseURL := "http://" + httpAddr
	wsURL := "ws://" + httpAddr + "/sparrow/ws"

	_, ticketKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_ = udpConn.Close()
		_ = httpLn.Close()
		return nil, fmt.Errorf("localhub: ticket key: %w", err)
	}
	tickets := &web.Tickets{
		Key:      ticketKey,
		Audience: wtURL,
		Lifetime: 60 * time.Second,
	}

	h, err := hub.New(hub.Options{
		Store: store,
		Bootstrap: []hub.Credential{
			{Token: adminTok, Principal: "user:admin"},
		},
		Tokens: []hub.Credential{
			{Token: userTok, Principal: cfg.Principal, Groups: cfg.Groups},
		},
		Web:            true,
		WebRoots:       rootKeys,
		Authenticate:   ticketAuthenticator(tickets),
		Logger:         cfg.Logger,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		_ = udpConn.Close()
		_ = httpLn.Close()
		return nil, fmt.Errorf("localhub: hub.New: %w", err)
	}

	modStore := &peerModuleStore{
		local:    &web.ModuleDir{Dir: modsDir},
		cacheDir: cacheDir,
	}

	webSrv, err := web.NewServer(web.ServerOptions{
		Tickets:        tickets,
		Host:           h,
		Logger:         cfg.Logger,
		AllowedOrigins: []string{"*"},
		MinHostAPI:     cfg.MinHostAPI,
		Endpoints: web.Endpoints{
			WebTransport: wtURL,
			WebSocket:    wsURL,
		},
		CertHashes: [][]byte{certHash},
		Modules:    modStore,
		Auth: &web.StaticTokens{
			SessionLifetime: 24 * time.Hour,
			Tokens: []web.StaticToken{
				{Token: userTok, Principal: cfg.Principal, Groups: cfg.Groups},
			},
		},
	})
	if err != nil {
		h.Close(time.Second)
		_ = udpConn.Close()
		_ = httpLn.Close()
		return nil, fmt.Errorf("localhub: web.NewServer: %w", err)
	}

	wtSrv := webtransport.NewServer(webtransport.ServerOptions{
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		CheckOrigin: func(*http.Request) bool { return true },
	})
	wtMux := http.NewServeMux()
	wtMux.Handle("/sparrow/wt", h.WebTransportHandler(wtSrv))
	webSrv.Mount(wtMux)
	wtSrv.WT.H3.Handler = wtMux
	go func() { _ = wtSrv.Serve(udpConn) }()

	httpMux := http.NewServeMux()
	httpMux.Handle("/sparrow/ws", h.WebSocketHandler(func(*http.Request) bool { return true }))
	webSrv.Mount(httpMux)
	httpSrv := &http.Server{Handler: httpMux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = httpSrv.Serve(httpLn) }()

	// Connect an in-process admin client to manage local nodes, peers, and policy.
	adminNode := nd.New(nd.Options{
		Auth:   &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, adminTok)},
		Logger: cfg.Logger,
	})
	if err := adminNode.Dial(ctx, wsURL, nd.DialOptions{}); err != nil {
		_ = httpSrv.Close()
		_ = wtSrv.Close()
		h.Close(time.Second)
		return nil, fmt.Errorf("localhub: dial admin: %w", err)
	}
	adminCli, err := admin.NewClient(adminNode.Session(), adminiface.Name)
	if err != nil {
		adminNode.Close()
		_ = httpSrv.Close()
		_ = wtSrv.Close()
		h.Close(time.Second)
		return nil, fmt.Errorf("localhub: admin client: %w", err)
	}

	inst := &Instance{
		Hub:       h,
		Pin:       pin,
		adminTok:  adminTok,
		adminNode: adminNode,
		adminCli:  adminCli,
		dataDir:   dataDir,
		tempDir:   tempDir,
		modStore:  modStore,
		wtSrv:     wtSrv,
		httpSrv:   httpSrv,
		doc: admin.Config{
			Nodes: map[string]*admin.NodeConfig{},
		},
		Info: ClientInfo{
			BaseURL:      baseURL,
			WebTransport: wtURL,
			WebSocket:    wsURL,
			CertHash:     hex.EncodeToString(certHash),
			Token:        userTok,
			RootKeys:     append([]string(nil), cfg.RootKeys...),
			Principal:    cfg.Principal,
		},
	}

	if err := inst.commitLocked(ctx); err != nil {
		inst.Close()
		return nil, fmt.Errorf("localhub: initial commit: %w", err)
	}

	for _, p := range cfg.Peers {
		if err := inst.AddPeer(ctx, p); err != nil {
			inst.Close()
			return nil, fmt.Errorf("localhub: add peer %q: %w", p.ID, err)
		}
	}

	return inst, nil
}

// AttachLocalNode registers a dial-in local node ID on the hub, creates a
// *node.Node with the given facets, and dials it into the embedded local hub
// over WebTransport.
func (i *Instance) AttachLocalNode(ctx context.Context, id string, facets ...*nd.Facet) (*nd.Node, error) {
	cred := randomHex(24)
	secName := "local-" + id

	i.mu.Lock()
	if err := i.adminCli.SetSecret(ctx, secName, []byte(cred)); err != nil {
		i.mu.Unlock()
		return nil, err
	}
	i.doc.Nodes[id] = &admin.NodeConfig{Link: admin.DialIn(secName)}
	if err := i.commitLocked(ctx); err != nil {
		i.mu.Unlock()
		return nil, err
	}
	i.mu.Unlock()

	n := nd.New(nd.Options{
		ID:   id,
		Auth: &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, cred)},
	})
	for _, f := range facets {
		if _, err := n.Add(ctx, f); err != nil {
			return nil, fmt.Errorf("localhub: add facet on %q: %w", id, err)
		}
	}
	if err := n.Dial(ctx, i.Info.WebTransport, nd.DialOptions{
		CertHashes: [][]byte{mustHex(i.Info.CertHash)},
	}); err != nil {
		return nil, fmt.Errorf("localhub: dial local node %q: %w", id, err)
	}
	i.mu.Lock()
	i.closers = append(i.closers, n.Close)
	i.mu.Unlock()
	return n, nil
}

// AddPeer configures 1-hop federation to a remote Sparrow hub (core 10.8).
// Facets exported by the peer appear as "<peer.ID>/<facet>".
func (i *Instance) AddPeer(ctx context.Context, p PeerConfig) error {
	if p.ID == "" || p.URL == "" || p.Credential == "" {
		return errors.New("localhub: peer id, url, and credential are required")
	}
	var pinBytes []byte
	if p.Pin != "" {
		b, err := hex.DecodeString(p.Pin)
		if err != nil || len(b) != sha256.Size {
			return fmt.Errorf("localhub: peer %q: invalid pin", p.ID)
		}
		pinBytes = b
	}
	secName := "peer-" + p.ID
	peerFlag := true

	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.adminCli.SetSecret(ctx, secName, []byte(p.Credential)); err != nil {
		return err
	}
	i.doc.Nodes[p.ID] = &admin.NodeConfig{
		Link: admin.Dialed(admin.Dial{
			URL:        p.URL,
			Pin:        pinBytes,
			Credential: secName,
		}),
		Peer: &peerFlag,
	}
	if p.WebBaseURL != "" {
		base := strings.TrimRight(p.WebBaseURL, "/")
		hc := &http.Client{Timeout: 15 * time.Second}
		if len(pinBytes) == sha256.Size {
			hc.Transport = &http.Transport{TLSClientConfig: pinnedTLS(pinBytes)}
		}
		i.modStore.addPeer(peerWebTarget{id: p.ID, baseURL: base, authHeader: p.WebAuthHeader, client: hc})
	}
	return i.commitLocked(ctx)
}

// Close shuts down all attached local nodes, HTTP/WebTransport listeners, and the hub.
func (i *Instance) Close() {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return
	}
	i.closed = true
	closers := append([]func(){}, i.closers...)
	i.mu.Unlock()

	for k := len(closers) - 1; k >= 0; k-- {
		closers[k]()
	}
	if i.adminNode != nil {
		i.adminNode.Close()
	}
	i.Hub.Close(3 * time.Second)
	if i.httpSrv != nil {
		_ = i.httpSrv.Close()
	}
	if i.wtSrv != nil {
		_ = i.wtSrv.Close()
	}
	if i.tempDir && i.dataDir != "" {
		_ = os.RemoveAll(i.dataDir)
	}
}

func (i *Instance) commitLocked(ctx context.Context) error {
	doc := i.doc
	doc.Extensions = map[string][]byte{
		hub.PolicyExtension: hub.EncodeGrants([]hub.Grant{
			{Principal: i.Info.Principal, Facet: "*", Level: hub.LevelUse},
		}),
	}
	gen, err := i.adminCli.Commit(ctx, i.gen, &doc, 0)
	if err != nil {
		return err
	}
	i.gen = gen
	return nil
}

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

func pinnedTLS(pin []byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			got := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if string(got[:]) != string(pin) {
				return errors.New("peer SPKI pin mismatch")
			}
			return nil
		},
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// MarshalInfoJSON returns ClientInfo serialized as JSON (convenience helper).
func (i *Instance) MarshalInfoJSON() ([]byte, error) {
	return json.Marshal(i.Info)
}
