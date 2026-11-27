// Package webtransport is the Sparrow WebTransport binding (section 4.5),
// on quic-go and webtransport-go (HTTP/3).
//
// The shared lane is the first bidirectional stream the client opens, with
// header byte 0x00; every leased stream starts with 0x01, sent by the peer
// that opened it. After the header each message is preceded by its length
// as a QUIC varint. A stream reset carries a core status code as its
// WebTransport error code, and the session close carries the core status
// code and a reason of at most 1024 bytes.
//
// maxStreams is enforced by the session (section 4.2), not here; the QUIC
// stream limit is only a backstop and defaults to well above maxStreams+2.
package webtransport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	wt "github.com/quic-go/webtransport-go"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// DefaultLinger is how long Close waits, after finishing the shared lane,
// for the peer to finish its own direction or close the session, so that
// messages written just before the close are delivered.
const DefaultLinger = 2 * time.Second

// headerTimeout bounds how long an accepted stream may take to send its
// header byte.
const headerTimeout = 10 * time.Second

// DefaultMaxIncomingStreams is the QUIC backstop for incoming bidirectional
// streams per connection.
const DefaultMaxIncomingStreams = 256

func quicConfig(c *quic.Config, maxIncoming int64) *quic.Config {
	if c == nil {
		c = &quic.Config{}
	} else {
		c = c.Clone()
	}
	c.EnableDatagrams = true
	c.EnableStreamResetPartialDelivery = true
	if c.MaxIncomingStreams == 0 {
		if maxIncoming == 0 {
			maxIncoming = DefaultMaxIncomingStreams
		}
		c.MaxIncomingStreams = maxIncoming
	}
	return c
}

// ServerOptions configure a Server.
type ServerOptions struct {
	// TLSConfig holds the server certificate. Required.
	TLSConfig *tls.Config
	// Addr is the UDP address for ListenAndServe.
	Addr string
	// CheckOrigin validates the Origin of a session request; nil uses
	// webtransport-go's same-origin default.
	CheckOrigin func(r *http.Request) bool
	// MaxIncomingStreams is the QUIC backstop (SHOULD be at least the
	// Welcome maxStreams + 2); 0 means DefaultMaxIncomingStreams.
	MaxIncomingStreams int64
	// QUICConfig is cloned and adjusted (datagrams and partial-delivery
	// resets are required by WebTransport).
	QUICConfig *quic.Config
	// Linger overrides DefaultLinger for accepted connections.
	Linger time.Duration
}

// Server accepts Sparrow WebTransport sessions on an HTTP/3 server. Mount
// Handler (or call Upgrade from your own handler) on WT.H3.Handler.
type Server struct {
	WT     *wt.Server
	linger time.Duration
}

// NewServer returns a server; set WT.H3.Handler before serving.
func NewServer(o ServerOptions) *Server {
	h3 := &http3.Server{
		Addr:       o.Addr,
		TLSConfig:  http3.ConfigureTLSConfig(o.TLSConfig),
		QUICConfig: quicConfig(o.QUICConfig, o.MaxIncomingStreams),
	}
	wt.ConfigureHTTP3Server(h3)
	return &Server{WT: &wt.Server{H3: h3, CheckOrigin: o.CheckOrigin}, linger: o.Linger}
}

// Upgrade accepts a WebTransport session request and returns the server
// end of the connection. On failure the caller should answer the request
// with an error status.
func (s *Server) Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	sess, err := s.WT.Upgrade(w, r)
	if err != nil {
		return nil, err
	}
	return newConn(sess, wire.Server, s.linger, nil), nil
}

// Handler returns an http.Handler that upgrades every request and passes
// the connection to accept, in a new goroutine.
func (s *Server) Handler(accept func(*Conn, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := s.Upgrade(w, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		go accept(c, r)
	})
}

// Serve serves HTTP/3 on a UDP socket.
func (s *Server) Serve(pc net.PacketConn) error { return s.WT.Serve(pc) }

// ListenAndServe listens on Addr.
func (s *Server) ListenAndServe() error { return s.WT.ListenAndServe() }

// Close stops the server and closes its connections.
func (s *Server) Close() error { return s.WT.Close() }

// DialOptions configure Dial.
type DialOptions struct {
	// TLSConfig for the QUIC handshake; nil uses system roots.
	TLSConfig *tls.Config
	// CertHashes pins the server certificate like the browser option
	// serverCertificateHashes: each is the SHA-256 of a DER certificate.
	// When set, the certificate chain is not verified against roots; the
	// leaf must match one hash. Intended for development (4.5).
	CertHashes [][]byte
	// Header is sent with the session request.
	Header http.Header
	// QUICConfig is cloned and adjusted.
	QUICConfig *quic.Config
	// Linger overrides DefaultLinger.
	Linger time.Duration
}

// Dial opens a WebTransport session to an https:// URL and returns the
// client end of the connection.
func Dial(ctx context.Context, url string, o *DialOptions) (*Conn, error) {
	if o == nil {
		o = &DialOptions{}
	}
	tc := o.TLSConfig
	if tc == nil {
		tc = &tls.Config{}
	} else {
		tc = tc.Clone()
	}
	if len(o.CertHashes) > 0 {
		hashes := o.CertHashes
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("webtransport: no server certificate")
			}
			sum := sha256.Sum256(raw[0])
			for _, h := range hashes {
				if len(h) == len(sum) && subtle.ConstantTimeCompare(h, sum[:]) == 1 {
					return nil
				}
			}
			return errors.New("webtransport: server certificate does not match a pinned hash")
		}
	}
	d := &wt.Dialer{TLSClientConfig: tc, QUICConfig: quicConfig(o.QUICConfig, 0)}
	_, sess, err := d.Dial(ctx, url, o.Header)
	if err != nil {
		d.Close()
		return nil, err
	}
	return newConn(sess, wire.Client, o.Linger, func() { d.Close() }), nil
}

// Conn is a Sparrow WebTransport connection.
type Conn struct {
	sess    *wt.Session
	role    wire.Role
	linger  time.Duration
	onClose func()
	limit   atomic.Uint64

	sharedMu    sync.Mutex
	shared      *stream
	sharedReady chan struct{}

	acceptMu   sync.Mutex
	acceptCond *sync.Cond
	acceptQ    []*stream

	mu        sync.Mutex
	err       error
	done      chan struct{}
	closeOnce sync.Once
}

func newConn(sess *wt.Session, role wire.Role, linger time.Duration, onClose func()) *Conn {
	if linger == 0 {
		linger = DefaultLinger
	}
	c := &Conn{sess: sess, role: role, linger: linger, onClose: onClose,
		sharedReady: make(chan struct{}), done: make(chan struct{})}
	c.acceptCond = sync.NewCond(&c.acceptMu)
	c.limit.Store(wire.DefaultMaxMessageSize)
	// acceptLoop ends with the session's close error (code and reason).
	go c.acceptLoop()
	return c
}

// Session returns the WebTransport session.
func (c *Conn) Session() *wt.Session { return c.sess }

func (c *Conn) peerRole() wire.Role {
	if c.role == wire.Client {
		return wire.Server
	}
	return wire.Client
}

func (c *Conn) acceptLoop() {
	for {
		s, err := c.sess.AcceptStream(context.Background())
		if err != nil {
			c.remoteClosed(err)
			return
		}
		go c.classify(s)
	}
}

func (c *Conn) classify(s *wt.Stream) {
	_ = s.SetReadDeadline(time.Now().Add(headerTimeout))
	st := newStream(c, s, false, 0)
	h, err := st.br.ReadByte()
	_ = s.SetReadDeadline(time.Time{})
	if err != nil {
		s.CancelRead(wt.StreamErrorCode(status.ProtocolError))
		s.CancelWrite(wt.StreamErrorCode(status.ProtocolError))
		return
	}
	c.sharedMu.Lock()
	kind, err := wire.ClassifyStreamHeader(h, c.peerRole(), c.shared != nil)
	if err == nil && kind == wire.ProfileStream {
		err = fmt.Errorf("stream header 0x%02x is reserved for a profile this peer does not implement", h)
	}
	if err != nil {
		c.sharedMu.Unlock()
		_ = c.Close(status.ProtocolError, err.Error())
		return
	}
	if kind == wire.SharedLane {
		c.shared = st
		close(c.sharedReady)
		c.sharedMu.Unlock()
		return
	}
	c.sharedMu.Unlock()
	c.acceptMu.Lock()
	c.acceptQ = append(c.acceptQ, st)
	c.acceptCond.Broadcast()
	c.acceptMu.Unlock()
}

// Leases is true.
func (c *Conn) Leases() bool { return true }

// SharedLane opens (client) or waits for (server) the shared lane.
func (c *Conn) SharedLane(ctx context.Context) (transport.Stream, error) {
	if c.role == wire.Server {
		select {
		case <-c.sharedReady:
			return c.shared, nil
		case <-c.done:
			return nil, c.closedErr()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c.sharedMu.Lock()
	defer c.sharedMu.Unlock()
	if c.shared != nil {
		return c.shared, nil
	}
	s, err := c.sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	c.shared = newStream(c, s, true, wire.HeaderSharedLane)
	close(c.sharedReady)
	return c.shared, nil
}

// OpenStream opens a leased stream; the header goes out with its first
// message.
func (c *Conn) OpenStream(ctx context.Context) (transport.Stream, error) {
	select {
	case <-c.sharedReady:
	default:
		return nil, errors.New("webtransport: the shared lane must be opened first")
	}
	s, err := c.sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	return newStream(c, s, true, wire.HeaderLeased), nil
}

// AcceptStream returns the next leased stream the peer opened.
func (c *Conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	stop := context.AfterFunc(ctx, func() {
		c.acceptMu.Lock()
		c.acceptCond.Broadcast()
		c.acceptMu.Unlock()
	})
	defer stop()
	c.acceptMu.Lock()
	defer c.acceptMu.Unlock()
	for len(c.acceptQ) == 0 {
		select {
		case <-c.done:
			return nil, c.closedErr()
		default:
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c.acceptCond.Wait()
	}
	s := c.acceptQ[0]
	c.acceptQ = c.acceptQ[1:]
	return s, nil
}

// SetReadLimit sets maxMessageSize for every stream.
func (c *Conn) SetReadLimit(n uint64) { c.limit.Store(n) }

// Close finishes the shared lane, waits up to the linger time for the peer
// to finish its direction or close, then closes the session with the core
// status code and the reason (at most 1024 bytes).
func (c *Conn) Close(code status.Code, reason string) error {
	reason = status.TruncateReason(reason, status.MaxWebTransportReason)
	wcode, err := status.WebTransportCode(code)
	if err != nil {
		wcode = uint32(status.Internal)
	}
	var cerr error
	c.closeOnce.Do(func() {
		c.setErr(&transport.CloseError{Code: code, Reason: reason})
		c.sharedMu.Lock()
		sh := c.shared
		c.sharedMu.Unlock()
		if sh != nil && code != status.ProtocolError {
			_ = sh.CloseWrite()
			t := time.NewTimer(c.linger)
			select {
			case <-sh.readDone:
			case <-c.sess.Context().Done():
			case <-t.C:
			}
			t.Stop()
		}
		cerr = c.sess.CloseWithError(wt.SessionErrorCode(wcode), reason)
		c.finishLocked()
	})
	return cerr
}

func (c *Conn) remoteClosed(err error) {
	ce := &transport.CloseError{Code: status.Unavailable, Remote: true}
	var se *wt.SessionError
	if errors.As(err, &se) {
		ce.Reason = se.Message
		ce.Remote = se.Remote
		if code, ok := status.FromWebTransportCode(uint32(se.ErrorCode)); ok {
			ce.Code = code
		}
	} else if err != nil {
		ce.Reason = err.Error()
	}
	c.closeOnce.Do(func() {
		c.setErr(ce)
		_ = c.sess.CloseWithError(0, "")
		c.finishLocked()
	})
}

func (c *Conn) finishLocked() {
	close(c.done)
	c.acceptMu.Lock()
	c.acceptCond.Broadcast()
	c.acceptMu.Unlock()
	if c.onClose != nil {
		c.onClose()
	}
}

func (c *Conn) setErr(e error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = e
	}
	c.mu.Unlock()
}

func (c *Conn) closedErr() error {
	if e := c.Err(); e != nil {
		return e
	}
	return transport.ErrClosed
}

// Done is closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns how the connection ended.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

type stream struct {
	c  *Conn
	s  *wt.Stream
	br *bufio.Reader
	fr *wire.FrameReader

	hdr        byte
	hdrPending bool
	wbuf       []byte

	readDone  chan struct{}
	readOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

func newStream(c *Conn, s *wt.Stream, opener bool, hdr byte) *stream {
	br := bufio.NewReaderSize(s, 32<<10)
	st := &stream{c: c, s: s, br: br, fr: wire.NewFrameReader(br, wire.DefaultMaxMessageSize),
		hdr: hdr, hdrPending: opener, readDone: make(chan struct{})}
	return st
}

func mapErr(err error) error {
	var se *wt.StreamError
	if errors.As(err, &se) {
		code, ok := status.FromWebTransportCode(uint32(se.ErrorCode))
		if !ok {
			code = status.Unknown
		}
		return &transport.ResetError{Code: code, Remote: se.Remote}
	}
	var sess *wt.SessionError
	if errors.As(err, &sess) {
		code, ok := status.FromWebTransportCode(uint32(sess.ErrorCode))
		if !ok {
			code = status.Unavailable
		}
		return &transport.CloseError{Code: code, Reason: sess.Message, Remote: sess.Remote}
	}
	return err
}

func (s *stream) ReadMessage() ([]byte, error) {
	s.fr.Max = s.c.limit.Load()
	b, err := s.fr.ReadFrame()
	if err == nil {
		return b, nil
	}
	var tl *wire.TooLargeError
	if errors.As(err, &tl) || errors.Is(err, wire.ErrEmptyFrame) {
		return nil, err
	}
	s.readOnce.Do(func() { close(s.readDone) })
	if err == io.EOF {
		return nil, io.EOF
	}
	select {
	case <-s.c.done:
		return nil, s.c.closedErr()
	default:
	}
	return nil, mapErr(err)
}

func (s *stream) WriteMessage(msg []byte) error {
	s.wbuf = s.wbuf[:0]
	if s.hdrPending {
		s.wbuf = append(s.wbuf, s.hdr)
		s.hdrPending = false
	}
	s.wbuf = wire.AppendFrame(s.wbuf, msg)
	if _, err := s.s.Write(s.wbuf); err != nil {
		select {
		case <-s.c.done:
			return s.c.closedErr()
		default:
		}
		return mapErr(err)
	}
	return nil
}

func (s *stream) CloseWrite() error {
	s.closeOnce.Do(func() {
		if s.hdrPending {
			s.hdrPending = false
			if _, err := s.s.Write([]byte{s.hdr}); err != nil {
				s.closeErr = mapErr(err)
				return
			}
		}
		s.closeErr = s.s.Close()
	})
	return s.closeErr
}

func (s *stream) Reset(code status.Code) {
	wc, err := status.WebTransportCode(code)
	if err != nil {
		wc = uint32(status.Internal)
	}
	s.s.CancelWrite(wt.StreamErrorCode(wc))
	s.s.CancelRead(wt.StreamErrorCode(wc))
	s.readOnce.Do(func() { close(s.readDone) })
}

// SelfSigned returns a self-signed ECDSA P-256 certificate for the given
// hosts (DNS names or IP addresses), valid for 10 days as browsers require
// for serverCertificateHashes, and the SHA-256 of its DER encoding for
// pinning with DialOptions.CertHashes.
func SelfSigned(hosts ...string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sparrow-dev"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, sum[:], nil
}
