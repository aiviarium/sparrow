// Command echo-node is an example Sparrow node. It runs in one of three
// ways; whatever starts it (a person, a service manager, an orchestrator, a
// test) hands it its configuration, since a hub never starts nodes (core
// section 10.2):
//
//   - -hub URL dials in to a hub (https:// WebTransport, ws:// or wss://
//     WebSocket), presenting ["link", credential], and reconnects with
//     backoff whenever the session ends. -hub-pin checks the hub's
//     SubjectPublicKeyInfo hash instead of the system roots (self-signed
//     hubs).
//   - -listen ADDR (WebTransport over UDP) and/or -listen-wss ADDR
//     (WebSocket over TLS) wait to be dialed by a hub, which must present
//     ["link", credential]. The node prints one JSON line on standard
//     output, {"webtransport": URL, "websocket": URL, "pin": HEX}, with the
//     SHA-256 of its SubjectPublicKeyInfo: the URL and pin to register with
//     sparrow.hub.admin. -key-file keeps the key (made if missing), so the
//     pin survives restarts.
//   - With neither, it speaks the pipe binding on its standard input and
//     output (4.7), for a supervisor that starts it as a child process.
//
// Logs go to standard error. With -web-modules it ships client modules
// (Web Profile 9.4) in its facet.
//
// It publishes one facet named after the node ID (default "echo") with a
// service Echo:
//
//	echo(string) -> string                 unary, idempotent
//	reverse(string) -> string              unary
//	count(uint) -> stream uint             1..n, then End
//	sum(stream uint) -> uint
//	chat(stream string) -> stream string   echoes each message
//	upload(bytes stream) -> uint           number of bytes received
//	download(uint) -> bytes stream         n bytes
//	whoami(unit) -> string                 the principal the hub named
//	log(string)                            notification, written to stderr
//	fail(string) -> unit                   fails with the error "echo_failed"
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/websocket"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Path is where a listening node serves sessions.
const Path = "/sparrow/node"

func main() {
	id := flag.String("id", "echo", "node ID; the facet is named after it")
	hubURL := flag.String("hub", "", "dial in to the hub at this URL (https:// WebTransport, ws:// or wss:// WebSocket)")
	hubPin := flag.String("hub-pin", "", "with -hub: hex SHA-256 of the hub's SubjectPublicKeyInfo, checked instead of the system roots")
	credential := flag.String("credential", "", "with -hub: the link credential presented as [\"link\", credential]; with -listen: the one the hub must present")
	listen := flag.String("listen", "", "serve WebTransport on this UDP address, for a hub that dials the node")
	listenWSS := flag.String("listen-wss", "", "serve WebSocket over TLS on this TCP address, for a hub that dials the node")
	keyFile := flag.String("key-file", "", "with -listen: PEM file holding the node's ECDSA key, made if missing")
	webModules := flag.String("web-modules", "", "file holding a CBOR list of signed web-module entries, published as the facet's web.modules annotation (Web Profile 9.4)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	listening := *listen != "" || *listenWSS != ""
	if *hubURL != "" && listening {
		fail("flags", errors.New("-hub and -listen exclude each other: a node has one link direction"))
	}
	if listening && *credential == "" {
		fail("flags", errors.New("-listen needs -credential, the credential the hub presents"))
	}

	opts := node.Options{ID: *id, Logger: log}
	if *hubURL != "" && *credential != "" {
		opts.Auth = &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, *credential)}
	}
	n := node.New(opts)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	f := Facet(*id, n, log)
	if *webModules != "" {
		b, err := os.ReadFile(*webModules)
		if err == nil {
			err = cbor.Validate(b, cbor.Options{})
		}
		if err != nil {
			fail("web modules", err)
		}
		f.Def.Annotations["web.modules"] = b
	}
	if _, err := n.Add(ctx, f); err != nil {
		fail("add facet", err)
	}
	var err error
	switch {
	case *hubURL != "":
		var do node.DialOptions
		if *hubPin != "" {
			pin, perr := hex.DecodeString(*hubPin)
			if perr != nil || len(pin) != sha256.Size {
				fail("flags", errors.New("-hub-pin is the hex SHA-256 of a SubjectPublicKeyInfo"))
			}
			tc := pinnedTLS(pin)
			do.TLSConfig = tc
			do.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		}
		err = n.RunDial(ctx, *hubURL, do)
	case listening:
		err = serveListening(ctx, n, log, *listen, *listenWSS, *keyFile, *credential)
	default:
		err = n.RunStdio(ctx)
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	n.Shutdown(sctx)
	cancel()
	if err != nil && !errors.Is(err, context.Canceled) {
		fail("session ended", err)
	}
}

// pinnedTLS accepts exactly the server key whose SPKI hash is pin.
func pinnedTLS(pin []byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // the pin replaces chain verification
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("the hub's public key does not match -hub-pin")
			}
			return nil
		},
	}
}

// loadKey reads the node's key from path, or makes one (and writes it when
// path is set).
func loadKey(path string) (*ecdsa.PrivateKey, error) {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			blk, _ := pem.Decode(b)
			if blk == nil {
				return nil, fmt.Errorf("%s: no PEM block", path)
			}
			return x509.ParseECPrivateKey(blk.Bytes)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil || path == "" {
		return key, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return key, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// serveListening serves sessions from a hub that dials the node (10.2):
// the node is the Sparrow server and its facets travel in Welcome.
func serveListening(ctx context.Context, n *node.Node, log *slog.Logger, wtAddr, wssAddr, keyFile, cred string) error {
	key, err := loadKey(keyFile)
	if err != nil {
		return err
	}
	hosts := []string{"127.0.0.1", "localhost"}
	for _, a := range []string{wtAddr, wssAddr} {
		if h, _, err := net.SplitHostPort(a); err == nil && h != "" && h != "127.0.0.1" && h != "localhost" {
			hosts = append(hosts, h)
		}
	}
	cert, _, err := webtransport.SelfSignedWithKey(key, hosts...)
	if err != nil {
		return err
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	auth := func(a *wire.Auth) error {
		if a == nil || a.Scheme != "link" || !credentialIs(a.Credentials, cred) {
			return &session.Error{Code: status.Unauthenticated, Message: "the hub presented a wrong link credential"}
		}
		return nil
	}
	serve := func(c transport.Conn) {
		if err := n.Serve(ctx, c, auth); err != nil {
			log.Warn("a dialing hub was refused", "err", err)
			return
		}
		log.Info("a hub connected")
	}
	addrs := map[string]string{"pin": hex.EncodeToString(pin[:])}
	errc := make(chan error, 2)
	if wtAddr != "" {
		pc, err := net.ListenPacket("udp", wtAddr)
		if err != nil {
			return err
		}
		srv := webtransport.NewServer(webtransport.ServerOptions{
			TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
			CheckOrigin: func(*http.Request) bool { return true },
		})
		mux := http.NewServeMux()
		mux.Handle(Path, srv.Handler(func(c *webtransport.Conn, _ *http.Request) { serve(c) }))
		srv.WT.H3.Handler = mux
		go func() { errc <- srv.Serve(pc) }()
		defer srv.Close()
		addrs["webtransport"] = "https://" + pc.LocalAddr().String() + Path
	}
	if wssAddr != "" {
		ln, err := tls.Listen("tcp", wssAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			return err
		}
		hs := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != Path {
					http.NotFound(w, r)
					return
				}
				c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CheckOrigin: func(*http.Request) bool { return true }})
				if err != nil {
					return
				}
				serve(c)
			}),
			ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		}
		go func() { errc <- hs.Serve(ln) }()
		defer hs.Close()
		addrs["websocket"] = "wss://" + ln.Addr().String() + Path
	}
	line, _ := json.Marshal(addrs)
	fmt.Println(string(line))
	log.Info("waiting for a hub to dial", "addrs", string(line))
	select {
	case <-ctx.Done():
		// GoAway to the hub before the listeners close (main waits for
		// the transport too).
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.Shutdown(sctx)
		cancel()
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

// credentialIs compares a Hello credential (text or bytes) with want.
func credentialIs(raw cbor.Raw, want string) bool {
	d := cbor.NewDecoder(raw)
	var got []byte
	switch m, _ := d.PeekMajor(); m {
	case cbor.MajorText:
		s, err := d.Text()
		if err != nil {
			return false
		}
		got = []byte(s)
	case cbor.MajorBytes:
		b, err := d.Bytes()
		if err != nil {
			return false
		}
		got = b
	default:
		return false
	}
	return subtle.ConstantTimeCompare(got, []byte(want)) == 1
}

// Facet builds the echo facet for node n.
func Facet(name string, n *node.Node, log *slog.Logger) *node.Facet {
	b := node.NewFacet(name, "1.0.0")
	failed := b.ErrorCode("echo_failed")
	svc := b.Service("Echo")
	svc.Method("echo", node.String, node.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		return c.Input()
	}, node.Idempotent())
	svc.Method("reverse", node.String, node.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		r := []rune(in.(string))
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r), nil
	})
	svc.Method("count", node.Uint, node.Stream(node.Uint), func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		for i := uint64(1); i <= in.(uint64); i++ {
			if err := c.Send(ctx, i); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	svc.Method("sum", node.Stream(node.Uint), node.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		var sum uint64
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return sum, nil
			}
			if err != nil {
				return nil, err
			}
			sum += v.(uint64)
		}
	})
	svc.Method("chat", node.Stream(node.String), node.Stream(node.String), func(ctx context.Context, c *session.ServerCall) (any, error) {
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			if err := c.Send(ctx, v); err != nil {
				return nil, err
			}
		}
	})
	svc.Method("upload", node.ByteStream(), node.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		k, err := io.Copy(io.Discard, c.Reader(0))
		return uint64(k), err
	})
	svc.Method("download", node.Uint, node.ByteStream(), func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		w := c.Writer(ctx, 0)
		chunk := []byte(strings.Repeat("sparrow!", 512))
		left := int(in.(uint64))
		for left > 0 {
			k := min(left, len(chunk))
			if _, err := w.Write(chunk[:k]); err != nil {
				return nil, err
			}
			left -= k
		}
		return nil, w.Close()
	})
	svc.Method("whoami", node.Unit, node.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		p, ok := n.Principal(c)
		if !ok {
			return "", nil
		}
		return p, nil
	})
	svc.Notification("log", node.String, func(ctx context.Context, c *session.ServerCall) error {
		v, err := c.Input()
		if err == nil {
			log.Info("log", "text", v)
		}
		return nil
	})
	svc.Method("fail", node.String, node.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return nil, &session.Error{Code: failed, Message: fmt.Sprint(in)}
	}, node.Errors(uint64(failed)))
	return b.MustBuild()
}
