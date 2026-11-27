package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/aiviarium/sparrow/go/transport/pipe"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport"
	"github.com/aiviarium/sparrow/go/transport/mem"
	wsb "github.com/aiviarium/sparrow/go/transport/websocket"
	wtb "github.com/aiviarium/sparrow/go/transport/webtransport"
	"github.com/aiviarium/sparrow/go/value"
)

// Test facet "test" (ID 16), service 0 "T".
const (
	tFacet = 16

	mEcho     = 1  // string -> string
	mCount    = 2  // uint -> [3, uint]
	mSum      = 3  // [3, uint] -> uint
	mChat     = 4  // [3, string] -> [3, string]
	mUpload   = 5  // [4] -> uint
	mDownload = 6  // uint -> [4]
	mNotify   = 7  // string -> unit, notification
	mSlow     = 8  // uint (ms) -> unit, honours cancellation
	mHang     = 9  // unit -> unit, never answers (raw handler)
	mAttach   = 10 // Attach{name, data [4]} -> uint
	mFetch    = 11 // string -> Blob{name, data [4]}
	mWatch    = 12 // uint -> [3, uint], shared
	mBig      = 13 // [uint n, uint size] list -> [3, bytes]
	mBlock    = 14 // unit -> unit: waits on a test channel
	mFail     = 15 // string -> unit: fails with an application error

	tAttach = 64
	tBlob   = 65
	errApp  = 64 // sigil: error code
)

func u(id uint64) schema.TypeRef { return schema.Named(id) }

func method(id uint64, name string, in, out schema.TypeRef, flags uint64) schema.Method {
	return schema.Method{ID: id, Name: name, Input: in, Output: out, Errors: []uint64{}, Flags: flags, Annotations: schema.Annotations{}}
}

func testFacet(id uint64, name string, extra ...schema.Method) schema.Facet {
	str, ui, unit := u(schema.TypeString), u(schema.TypeUint), u(schema.TypeUnit)
	bs := schema.ByteStream()
	fields := []schema.Field{
		{Tag: 0, Name: "name", Type: str, Flags: 0, Annotations: schema.Annotations{}},
		{Tag: 1, Name: "data", Type: bs, Flags: 0, Annotations: schema.Annotations{}},
	}
	methods := []schema.Method{
		method(mEcho, "echo", str, str, schema.MethodIdempotent),
		method(mCount, "count", ui, schema.Stream(ui), schema.MethodOutputEnd),
		method(mSum, "sum", schema.Stream(ui), ui, schema.MethodInputEnd),
		method(mChat, "chat", schema.Stream(str), schema.Stream(str), schema.MethodInputEnd|schema.MethodOutputEnd),
		method(mUpload, "upload", bs, ui, schema.MethodInputEnd),
		method(mDownload, "download", ui, bs, schema.MethodOutputEnd),
		method(mNotify, "notify", str, unit, schema.MethodNotification),
		method(mSlow, "slow", ui, unit, 0),
		method(mHang, "hang", unit, unit, 0),
		method(mAttach, "attach", u(tAttach), ui, schema.MethodInputEnd),
		method(mFetch, "fetch", str, u(tBlob), schema.MethodOutputEnd),
		method(mWatch, "watch", ui, schema.Stream(ui), schema.MethodOutputEnd|schema.MethodShared),
		method(mBig, "big", schema.List(ui), schema.Stream(u(schema.TypeBytes)), schema.MethodOutputEnd),
		method(mBlock, "block", unit, unit, 0),
		method(mFail, "fail", str, unit, 0),
	}
	methods = append(methods, extra...)
	return schema.Facet{
		ID: id, Name: name, Version: "1.0.0",
		Types: []schema.TypeDef{
			{Kind: schema.KindStruct, ID: tAttach, Name: "Attach", Fields: fields, Annotations: schema.Annotations{}},
			{Kind: schema.KindStruct, ID: tBlob, Name: "Blob", Fields: append([]schema.Field(nil), fields...), Annotations: schema.Annotations{}},
		},
		Services: []schema.Service{{ID: 0, Name: "T", Methods: methods, Annotations: schema.Annotations{}}},
		Sigils:   []schema.Sigil{{ID: errApp, Name: "app_error", Kind: schema.SigilError, Annotations: schema.Annotations{}}},
		Retired:  []schema.Retired{}, Annotations: schema.Annotations{},
	}
}

func testSchema(name string, facets ...schema.Facet) *schema.Schema {
	if len(facets) == 0 {
		facets = []schema.Facet{testFacet(tFacet, "test")}
	}
	return &schema.Schema{Format: schema.Format, Name: name, Version: "1", Facets: facets, Annotations: schema.Annotations{}}
}

// testHandlers serves the test facet.
type testHandlers struct {
	notified chan string
	block    chan struct{}
	started  chan uint64
	hangSeen chan struct{}
	mu       sync.Mutex
	cancels  int
}

func newTestHandlers() *testHandlers {
	return &testHandlers{notified: make(chan string, 1000), block: make(chan struct{}), started: make(chan uint64, 1000), hangSeen: make(chan struct{}, 100)}
}

func (h *testHandlers) mux(facet uint64) *Mux {
	m := NewMux()
	h.register(m, facet)
	return m
}

func (h *testHandlers) register(m *Mux, facet uint64) {
	m.HandleFunc(facet, mEcho, func(ctx context.Context, c *ServerCall) (any, error) { return c.Input() })
	m.HandleFunc(facet, mCount, func(ctx context.Context, c *ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		n := in.(uint64)
		_ = c.SendHeaders(nil)
		for i := uint64(0); i < n; i++ {
			if err := c.Send(ctx, i); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	m.HandleFunc(facet, mSum, func(ctx context.Context, c *ServerCall) (any, error) {
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
	m.HandleFunc(facet, mChat, func(ctx context.Context, c *ServerCall) (any, error) {
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			if err := c.Send(ctx, "re: "+v.(string)); err != nil {
				return nil, err
			}
		}
	})
	m.HandleFunc(facet, mUpload, func(ctx context.Context, c *ServerCall) (any, error) {
		n, err := io.Copy(io.Discard, c.Reader(0))
		if err != nil {
			return nil, err
		}
		return uint64(n), nil
	})
	m.HandleFunc(facet, mDownload, func(ctx context.Context, c *ServerCall) (any, error) {
		in, _ := c.Input()
		n := int(in.(uint64))
		w := c.Writer(ctx, 0)
		buf := make([]byte, 4096)
		for n > 0 {
			k := min(n, len(buf))
			for i := range buf[:k] {
				buf[i] = byte(n + i)
			}
			if _, err := w.Write(buf[:k]); err != nil {
				return nil, err
			}
			n -= k
		}
		return nil, w.Close()
	})
	m.HandleFunc(facet, mNotify, func(ctx context.Context, c *ServerCall) (any, error) {
		v, err := c.Input()
		if err == nil {
			h.notified <- v.(string)
		}
		return nil, nil
	})
	m.HandleFunc(facet, mSlow, func(ctx context.Context, c *ServerCall) (any, error) {
		in, _ := c.Input()
		h.started <- c.ID()
		select {
		case <-time.After(time.Duration(in.(uint64)) * time.Millisecond):
			return nil, nil
		case <-ctx.Done():
			h.mu.Lock()
			h.cancels++
			h.mu.Unlock()
			return nil, context.Cause(ctx)
		}
	})
	m.Handle(facet, mHang, rawHandler(func(ctx context.Context, c *ServerCall) {
		h.hangSeen <- struct{}{}
		<-c.Session().Done() // never answers, even to Cancel
	}))
	m.HandleFunc(facet, mAttach, func(ctx context.Context, c *ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		st := in.(value.Struct)
		tok := uint64(st[1].(value.Token))
		n, err := io.Copy(io.Discard, c.Reader(tok))
		if err != nil {
			return nil, err
		}
		return uint64(n) + uint64(len(st[0].(string))), nil
	})
	m.HandleFunc(facet, mFetch, func(ctx context.Context, c *ServerCall) (any, error) {
		in, _ := c.Input()
		// Bytes first, then the Response that mentions the token (7.8).
		w := c.Writer(ctx, 7)
		if err := w.WriteAll([]byte(strings.Repeat(in.(string), 1000))); err != nil {
			return nil, err
		}
		return value.Struct{0: in.(string), 1: value.Token(7)}, nil
	})
	m.HandleFunc(facet, mWatch, func(ctx context.Context, c *ServerCall) (any, error) {
		in, _ := c.Input()
		for i := uint64(0); i < in.(uint64); i++ {
			if err := c.Send(ctx, i); err != nil {
				return nil, err
			}
		}
		<-ctx.Done() // a subscription: open until cancelled
		return nil, context.Cause(ctx)
	})
	m.HandleFunc(facet, mBig, func(ctx context.Context, c *ServerCall) (any, error) {
		in, _ := c.Input()
		l := in.([]any)
		n, size := l[0].(uint64), l[1].(uint64)
		item := make([]byte, size)
		for i := uint64(0); i < n; i++ {
			if err := c.Send(ctx, item); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	m.HandleFunc(facet, mBlock, func(ctx context.Context, c *ServerCall) (any, error) {
		h.started <- c.ID()
		select {
		case <-h.block:
			return nil, nil
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	})
	m.HandleFunc(facet, mFail, func(ctx context.Context, c *ServerCall) (any, error) {
		in, _ := c.Input()
		return nil, &Error{Code: errApp, Message: in.(string), Details: cbor.AppendText(nil, "detail")}
	})
}

type rawHandler func(ctx context.Context, c *ServerCall)

func (f rawHandler) ServeCall(ctx context.Context, c *ServerCall) { f(ctx, c) }

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

type binding struct {
	name string
	// connect returns the client and server ends of a fresh connection.
	connect func(t testing.TB) (transport.Conn, transport.Conn)
	leases  bool
}

func memBinding() binding {
	return binding{"mem", func(t testing.TB) (transport.Conn, transport.Conn) {
		c, s := mem.Pipe(mem.Options{})
		return c, s
	}, true}
}

func wsBinding() binding {
	return binding{"websocket", func(t testing.TB) (transport.Conn, transport.Conn) {
		ch := make(chan transport.Conn, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := wsb.Accept(w, r, nil)
			if err != nil {
				return
			}
			ch <- c
		}))
		t.Cleanup(srv.Close)
		c, err := wsb.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		return c, <-ch
	}, false}
}

// One WebTransport server serves every test; each connection gets its own
// path, so tests running in parallel each receive their own server end.
var (
	wtOnce  sync.Once
	wtURL   string
	wtHash  []byte
	wtConns sync.Map // path -> chan transport.Conn
	wtSeq   atomic.Int64
	wtErr   error
)

func wtBinding() binding {
	return binding{"webtransport", func(t testing.TB) (transport.Conn, transport.Conn) {
		wtOnce.Do(func() {
			cert, hash, err := wtb.SelfSigned("localhost", "127.0.0.1")
			if err != nil {
				wtErr = err
				return
			}
			wtHash = hash
			srv := wtb.NewServer(wtb.ServerOptions{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
				CheckOrigin: func(*http.Request) bool { return true }})
			mux := http.NewServeMux()
			mux.Handle("/sparrow/", srv.Handler(func(c *wtb.Conn, r *http.Request) {
				if ch, ok := wtConns.Load(r.URL.Path); ok {
					ch.(chan transport.Conn) <- c
					return
				}
				_ = c.Close(status.NotFound, "no test waits for this connection")
			}))
			srv.WT.H3.Handler = mux
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				wtErr = err
				return
			}
			go func() { _ = srv.Serve(pc) }()
			wtURL = fmt.Sprintf("https://127.0.0.1:%d", pc.LocalAddr().(*net.UDPAddr).Port)
		})
		if wtErr != nil {
			t.Fatal(wtErr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path := fmt.Sprintf("/sparrow/%d", wtSeq.Add(1))
		ch := make(chan transport.Conn, 1)
		wtConns.Store(path, ch)
		defer wtConns.Delete(path)
		c, err := wtb.Dial(ctx, wtURL+path, &wtb.DialOptions{CertHashes: [][]byte{wtHash}})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case s := <-ch:
			return c, s
		case <-ctx.Done():
			t.Fatal("no server connection")
		}
		return nil, nil
	}, true}
}

func pipeBinding() binding {
	return binding{"pipe", func(t testing.TB) (transport.Conn, transport.Conn) {
		a, b := net.Pipe()
		return pipe.New(a), pipe.New(b)
	}, false}
}

func allBindings() []binding {
	return []binding{memBinding(), wsBinding(), wtBinding(), pipeBinding()}
}

// pair connects a client and a server session.
func pair(t testing.TB, b binding, ccfg, scfg Config) (*Session, *Session) {
	t.Helper()
	cc, sc := b.connect(t)
	return pairOn(t, cc, sc, ccfg, scfg)
}

// testLinger replaces DefaultLinger in tests: messages that precede the
// end of a connection arrive within it on every binding here.
const testLinger = 200 * time.Millisecond

// fastTimers shortens the wall-clock waits that tests do not assert on
// (the linger after a connection ends and the wait for a GoAway being
// written); a test that sets them keeps its values.
func fastTimers(c *Config) {
	if c.Linger == 0 {
		c.Linger = testLinger
	}
	if c.GoAwayWait == 0 {
		c.GoAwayWait = testLinger
	}
}

func pairOn(t testing.TB, cc, sc transport.Conn, ccfg, scfg Config) (*Session, *Session) {
	t.Helper()
	fastTimers(&ccfg)
	fastTimers(&scfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var srv *Session
	var serr error
	done := make(chan struct{})
	go func() {
		srv, serr = NewServer(ctx, sc, scfg)
		close(done)
	}()
	cli, err := NewClient(ctx, cc, ccfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	<-done
	if serr != nil {
		t.Fatalf("server: %v", serr)
	}
	t.Cleanup(func() {
		cli.Close(status.OK, "test done")
		srv.Close(status.OK, "test done")
	})
	return cli, srv
}

// stdPair is a client and server where the server publishes the test facet.
func stdPair(t testing.TB, b binding, h *testHandlers, mod func(c, s *Config)) (*Session, *Session) {
	ccfg := Config{}
	scfg := Config{Schema: testSchema("server"), Handler: h.mux(tFacet)}
	if mod != nil {
		mod(&ccfg, &scfg)
	}
	return pair(t, b, ccfg, scfg)
}

func code(err error) status.Code { return Code(err) }

func mustCode(t testing.TB, err error, want status.Code) {
	t.Helper()
	if got := Code(err); got != want {
		t.Fatalf("status %v (%v), want %v", got, err, want)
	}
}

var errAny = errors.New("any")

func testutilEventually(t testing.TB, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func asResetErr(err error) error {
	var re *transport.ResetError
	if errors.As(err, &re) {
		return &Error{Code: re.Code}
	}
	return err
}
