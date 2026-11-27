package webtransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	wt "github.com/quic-go/webtransport-go"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

type fixture struct {
	url   string
	hash  []byte
	conns chan *Conn
}

func newFixture(t *testing.T) *fixture {
	cert, hash, err := SelfSigned("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{hash: hash, conns: make(chan *Conn, 4)}
	srv := NewServer(ServerOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, CheckOrigin: func(*http.Request) bool { return true }})
	mux := http.NewServeMux()
	mux.Handle("/s", srv.Handler(func(c *Conn, _ *http.Request) { f.conns <- c }))
	srv.WT.H3.Handler = mux
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })
	f.url = fmt.Sprintf("https://127.0.0.1:%d/s", pc.LocalAddr().(*net.UDPAddr).Port)
	return f
}

func (f *fixture) dial(t *testing.T) (*Conn, *Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, f.url, &DialOptions{CertHashes: [][]byte{f.hash}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-f.conns:
		return c, s
	case <-ctx.Done():
		t.Fatal("no server conn")
	}
	return nil, nil
}

func TestStreams(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c, s := f.dial(t)
	ctx := context.Background()
	cl, err := c.SharedLane(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.WriteMessage([]byte{0x81, 0x07}); err != nil {
		t.Fatal(err)
	}
	sl, err := s.SharedLane(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := sl.ReadMessage(); err != nil || !bytes.Equal(b, []byte{0x81, 0x07}) {
		t.Fatalf("%x %v", b, err)
	}
	// Leased streams in both directions, with resets carrying codes.
	for _, dir := range []struct {
		name     string
		open, ac *Conn
	}{{"client-opened", c, s}, {"server-opened", s, c}} {
		t.Run(dir.name, func(t *testing.T) {
			ls, err := dir.open.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			big := bytes.Repeat([]byte{0xaa}, 200000)
			if err := ls.WriteMessage(big); err != nil {
				t.Fatal(err)
			}
			as, err := dir.ac.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if b, err := as.ReadMessage(); err != nil || !bytes.Equal(b, big) {
				t.Fatalf("%d %v", len(b), err)
			}
			// Finishing a direction is EOF for the reader.
			if err := ls.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if _, err := as.ReadMessage(); err != io.EOF {
				t.Fatalf("want EOF, got %v", err)
			}
			_ = as.WriteMessage([]byte{0xf6})
			if b, err := ls.ReadMessage(); err != nil || b[0] != 0xf6 {
				t.Fatalf("%x %v", b, err)
			}
			_ = as.CloseWrite()
			if _, err := ls.ReadMessage(); err != io.EOF {
				t.Fatalf("want EOF, got %v", err)
			}
			// A reset carries the core status code.
			ls2, _ := dir.open.OpenStream(ctx)
			_ = ls2.WriteMessage([]byte{0xf6})
			as2, _ := dir.ac.AcceptStream(ctx)
			if _, err := as2.ReadMessage(); err != nil {
				t.Fatal(err)
			}
			ls2.Reset(status.Cancelled)
			_, err = as2.ReadMessage()
			var re *transport.ResetError
			if !errors.As(err, &re) || re.Code != status.Cancelled || !re.Remote {
				t.Fatalf("got %v", err)
			}
		})
	}
	// The read limit is enforced before buffering.
	s.SetReadLimit(1000)
	_ = cl.WriteMessage(make([]byte, 5000))
	_, err = sl.ReadMessage()
	var tl *wire.TooLargeError
	if !errors.As(err, &tl) {
		t.Fatalf("got %v", err)
	}
}

func TestClose(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c, s := f.dial(t)
	cl, _ := c.SharedLane(context.Background())
	_ = cl.WriteMessage([]byte{0xf6})
	sl, _ := s.SharedLane(context.Background())
	if _, err := sl.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	// Each side reads its shared lane to the end, as a session does, so
	// a closing side sees the peer's finish instead of waiting out its
	// linger.
	drain := func(st transport.Stream, finish bool) {
		go func() {
			for {
				if _, err := st.ReadMessage(); err != nil {
					if finish {
						_ = st.CloseWrite()
					}
					return
				}
			}
		}()
	}
	drain(sl, false)
	long := strings.Repeat("é", 1000) // 2000 bytes
	go func() { _ = s.Close(status.GoingAway, long) }()
	// The peer sees the shared lane finish first, then the session close.
	if _, err := cl.ReadMessage(); err != io.EOF {
		t.Fatalf("want EOF on the shared lane, got %v", err)
	}
	_ = c.Close(status.OK, "")
	<-s.Done()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client not closed")
	}
	if ce, ok := c.Err().(*transport.CloseError); !ok || ce.Code != status.OK {
		t.Fatalf("client err %v", c.Err())
	}

	// A remote close carries code and (truncated) reason.
	c2, s2 := f.dial(t)
	l2, _ := c2.SharedLane(context.Background())
	_ = l2.WriteMessage([]byte{0xf6})
	sl2, _ := s2.SharedLane(context.Background())
	_, _ = sl2.ReadMessage()
	drain(sl2, true)
	drain(l2, false)
	_ = c2.Close(status.SchemaMismatch, long)
	select {
	case <-s2.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server not closed")
	}
	// webtransport-go's dialer closes the QUIC connection as soon as the
	// session closes, which can overtake the close capsule; the server then
	// sees a plain connection close (unavailable). GoAway carries the
	// status at the session level either way.
	ce, ok := s2.Err().(*transport.CloseError)
	if !ok || !ce.Remote || len(ce.Reason) > 1024 || (ce.Code != status.SchemaMismatch && ce.Code != status.Unavailable) {
		t.Fatalf("server err %#v", s2.Err())
	}
	if ce.Code == status.SchemaMismatch && !strings.HasPrefix(long, ce.Reason) {
		t.Fatal("reason not truncated at a character boundary")
	}

	// A server-side close always carries code and reason.
	c3, s3 := f.dial(t)
	l3, _ := c3.SharedLane(context.Background())
	_ = l3.WriteMessage([]byte{0xf6})
	sl3, _ := s3.SharedLane(context.Background())
	_, _ = sl3.ReadMessage()
	go func() {
		for {
			if _, err := l3.ReadMessage(); err != nil {
				_ = l3.CloseWrite()
				return
			}
		}
	}()
	drain(sl3, false)
	_ = s3.Close(status.Unauthenticated, long)
	select {
	case <-c3.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client not closed")
	}
	ce, ok = c3.Err().(*transport.CloseError)
	if !ok || ce.Code != status.Unauthenticated || !ce.Remote || len(ce.Reason) > 1024 || !strings.HasPrefix(long, ce.Reason) {
		t.Fatalf("client err %#v", c3.Err())
	}
}

// rawSession dials with webtransport-go directly, to break stream rules.
func rawSession(t *testing.T, f *fixture) *wt.Session {
	d := &wt.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, QUICConfig: quicConfig(nil, 0)}
	t.Cleanup(func() { d.Close() })
	_, sess, err := d.Dial(context.Background(), f.url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestHeaderRules(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, tc := range []struct {
		name    string
		headers []byte
	}{
		{"unknown-header", []byte{0x05}},
		{"profile-header", []byte{0x40}},
		{"second-shared-lane", []byte{0x00, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := rawSession(t, f)
			s := <-f.conns
			for _, h := range tc.headers {
				st, err := sess.OpenStreamSync(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				// Two shared lanes are refused in either arrival order.
				_, _ = st.Write([]byte{h})
			}
			select {
			case <-s.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("not closed")
			}
			if ce, ok := s.Err().(*transport.CloseError); !ok || ce.Code != status.ProtocolError {
				t.Fatalf("got %v", s.Err())
			}
		})
	}
	t.Run("shared-lane-opened-by-server", func(t *testing.T) {
		c, s := f.dial(t)
		st, err := s.Session().OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = st.Write([]byte{0x00})
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("not closed")
		}
		if ce, ok := c.Err().(*transport.CloseError); !ok || ce.Code != status.ProtocolError {
			t.Fatalf("got %v", c.Err())
		}
	})
}

func TestPinning(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, f.url, &DialOptions{CertHashes: [][]byte{make([]byte, 32)}}); err == nil {
		t.Fatal("dialed with a wrong pinned hash")
	}
	if _, err := Dial(ctx, f.url, nil); err == nil {
		t.Fatal("dialed a self-signed server without pinning")
	}
}
