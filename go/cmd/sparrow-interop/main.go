// Command sparrow-interop is the Go side of the interoperability tests of
// the TypeScript implementation (../ts, test/interop.test.ts). It speaks
// the pipe binding (core section 4.7) in either role:
//
//	sparrow-interop client
//	    The started process: the Sparrow client on its standard input and
//	    output. It publishes the facet interop.client, runs the check suite
//	    against the parent's interop.test, notifies "suite passed" through
//	    interop.test/log and then waits for the parent to end the session.
//
//	sparrow-interop server CMD [ARGS...]
//	    Starts CMD as the Sparrow client on a pipe and serves interop.test
//	    with session.NewServer. It calls the child's interop.client facet,
//	    waits for the child's "suite passed" notification, sends
//	    GoAway(going_away) and exits 0 if the child exited 0 and every
//	    check of its own passed.
//
//	sparrow-interop decode
//	    Differential checks: reads lines "<what> <hex>" from standard input
//	    and answers each with one line, "ok <hex>", "ok <n>" or "err". what
//	    is cbor (validate, then the Core Deterministic Encoding), message
//	    (wire.Decode, then the message encoded again), schema (decode and
//	    validate a schema document, then its canonical encoding) or
//	    timestamp (a tag-1 value as the value codec reads it, in whole
//	    milliseconds, cbor.Time.UnixMilli).
//
// Diagnostics go to standard error. Both facets are defined exactly as in
// ts/test/fixture/interop.mjs.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport/pipe"
	"github.com/aiviarium/sparrow/go/value"
	"github.com/aiviarium/sparrow/go/wire"
)

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[go %s] %s\n", role, fmt.Sprintf(format, args...))
}

var role = "interop"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sparrow-interop client | server CMD [ARGS...]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "client":
		role = "client"
		err = runClient()
	case "decode":
		role = "decode"
		err = runDecode(os.Stdin, os.Stdout)
	case "server":
		role = "server"
		if len(os.Args) < 3 {
			err = errors.New("server needs a command to start")
			break
		}
		err = runServer(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		logf("FAILED: %v", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Facets
// ---------------------------------------------------------------------------

type serverIDs struct {
	methods  map[string]uint64
	failed   uint64
	failInfo uint64
}

func serverFacet() (*schema.Facet, serverIDs) {
	b := node.NewFacet("interop.test", "1.0.0").ID(16)
	failed := b.ErrorCode("interop_failed")
	failInfo := b.Struct("FailInfo", node.Field("reason", node.String), node.Field("code", node.Uint))
	color, _ := b.Enum("Color", "red", "green", "blue")
	point := b.Struct("Point", node.Field("x", node.Int), node.Field("y", node.Int), node.OptionalField("label", node.String))
	shape := b.Union("Shape", node.Field("circle", node.Float64), node.Field("square", point), node.Field("none", node.Unit))
	filter := b.SparseStruct("Filter", node.OptionalField("limit", node.Uint), node.OptionalField("query", node.String))
	b.Symbol("sym.hello")
	every := b.Struct("Everything",
		node.Field("s", node.String), node.Field("i", node.Int), node.Field("u", node.Uint), node.Field("f", node.Float64),
		node.Field("b", node.Bool), node.Field("data", node.Bytes), node.Field("ts", node.Timestamp), node.Field("id", node.UUID),
		node.Field("tags", node.List(node.String)), node.Field("scores", node.Map(node.String, node.Int)),
		node.Field("color", color), node.Field("shape", shape), node.Field("point", point), node.Field("filter", filter),
		node.OptionalField("opt", node.String), node.Field("dyn", node.Dynamic), node.Field("sym", node.Symbol),
		node.Field("big", node.Int), node.Field("f32", node.Float32))
	svc := b.Service("Test")
	ids := serverIDs{methods: map[string]uint64{}, failed: uint64(failed), failInfo: failInfo.ID}
	add := func(name string, in, out schema.TypeRef, opts ...node.MethodOption) {
		ids.methods[name] = svc.Method(name, in, out, nil, opts...)
	}
	add("echo", node.String, node.String, node.Idempotent())
	add("count", node.Uint, node.Stream(node.Uint))
	add("sum", node.Stream(node.Int), node.Int)
	add("upper", node.Stream(node.String), node.Stream(node.String))
	ids.methods["log"] = svc.Notification("log", node.String, nil)
	add("lastLog", node.Unit, node.String)
	add("fail", node.String, node.Unit, node.Errors(uint64(failed)))
	add("slow", node.Uint, node.Unit)
	add("wasCancelled", node.Unit, node.Bool)
	add("progress", node.Uint, node.String)
	add("roundtrip", every, every)
	add("callback", node.String, node.String)
	add("upload", node.ByteStream(), node.Uint)
	add("download", node.Uint, node.ByteStream())
	add("headers", node.Unit, node.Stream(node.String))
	add("optional", node.Opt(node.String), node.Opt(node.String))
	f := b.MustBuild().Def
	return &f, ids
}

func clientFacet() (*schema.Facet, map[string]uint64) {
	b := node.NewFacet("interop.client", "1.0.0").ID(16)
	svc := b.Service("Client")
	ids := map[string]uint64{
		"greet": svc.Method("greet", node.String, node.String, nil),
		"count": svc.Method("count", node.Uint, node.Stream(node.Uint), nil),
	}
	f := b.MustBuild().Def
	return &f, ids
}

func schemaOf(name string, f *schema.Facet) *schema.Schema {
	return &schema.Schema{Format: schema.Format, Name: name, Version: "1.0.0", Facets: []schema.Facet{*f}, Annotations: schema.Annotations{}}
}

func textMD(kv ...any) wire.Metadata {
	md := wire.Metadata{}
	for i := 0; i < len(kv); i += 2 {
		v, err := cbor.Encode(kv[i+1])
		if err != nil {
			panic(err)
		}
		md[wire.TextKey(kv[i].(string))] = v
	}
	return md
}

// serverState is what the interop.test handlers record.
type serverState struct {
	mu        sync.Mutex
	lastLog   string
	cancelled bool
	logs      chan string
}

func serverMux(ids serverIDs, st *serverState) *session.Mux {
	m := session.NewMux()
	h := func(name string, f session.HandlerFunc) { m.HandleFunc(16, ids.methods[name], f) }
	h("echo", func(ctx context.Context, c *session.ServerCall) (any, error) { return c.Input() })
	h("count", func(ctx context.Context, c *session.ServerCall) (any, error) {
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
	h("sum", func(ctx context.Context, c *session.ServerCall) (any, error) {
		var sum int64
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return sum, nil
			}
			if err != nil {
				return nil, err
			}
			sum += v.(int64)
		}
	})
	h("upper", func(ctx context.Context, c *session.ServerCall) (any, error) {
		if err := c.SendHeaders(textMD("x-mode", "upper")); err != nil {
			return nil, err
		}
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			if err := c.Send(ctx, strings.ToUpper(v.(string))); err != nil {
				return nil, err
			}
		}
	})
	h("log", func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, _ := c.Input()
		s, _ := v.(string)
		st.mu.Lock()
		st.lastLog = s
		st.mu.Unlock()
		select {
		case st.logs <- s:
		default:
		}
		return nil, nil
	})
	h("lastLog", func(ctx context.Context, c *session.ServerCall) (any, error) {
		st.mu.Lock()
		defer st.mu.Unlock()
		return st.lastLog, nil
	})
	h("fail", func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, _ := c.Input()
		msg := v.(string)
		d, err := c.Codec().Encode(schema.Named(schema.TypeDynamic), value.Dynamic{Type: ids.failInfo, Value: value.Struct{0: msg, 1: uint64(7)}})
		if err != nil {
			return nil, err
		}
		return nil, &session.Error{Code: status.Code(ids.failed), Message: msg, Details: d}
	})
	h("slow", func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, _ := c.Input()
		st.mu.Lock()
		st.cancelled = false
		st.mu.Unlock()
		select {
		case <-time.After(time.Duration(v.(uint64)) * time.Millisecond):
			return nil, nil
		case <-ctx.Done():
			st.mu.Lock()
			st.cancelled = true
			st.mu.Unlock()
			return nil, context.Cause(ctx)
		}
	})
	h("wasCancelled", func(ctx context.Context, c *session.ServerCall) (any, error) {
		for i := 0; i < 50; i++ {
			st.mu.Lock()
			done := st.cancelled
			st.mu.Unlock()
			if done {
				return true, nil
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false, nil
	})
	h("progress", func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, _ := c.Input()
		n := v.(uint64)
		for i := uint64(1); i <= n; i++ {
			note := fmt.Sprintf("step %d", i)
			if err := c.Progress(ctx, i, &n, &note); err != nil {
				return nil, err
			}
		}
		return "done", nil
	})
	h("roundtrip", func(ctx context.Context, c *session.ServerCall) (any, error) { return c.Input() })
	h("callback", func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, _ := c.Input()
		s := c.Session()
		f := s.PeerFacet("interop.client")
		if f == nil {
			return nil, session.Errorf(status.FailedPrecondition, "the client published no interop.client facet")
		}
		m, err := node.MethodByName(f, "greet")
		if err != nil {
			return nil, err
		}
		return s.Unary(ctx, f.ID, m.ID, v, nil)
	})
	h("upload", func(ctx context.Context, c *session.ServerCall) (any, error) {
		n, err := io.Copy(io.Discard, c.Reader(0))
		if err != nil {
			return nil, err
		}
		return uint64(n), nil
	})
	h("download", func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, _ := c.Input()
		data := make([]byte, v.(uint64))
		for i := range data {
			data[i] = byte(i)
		}
		return nil, c.Writer(ctx, 0).WriteAll(data)
	})
	h("headers", func(ctx context.Context, c *session.ServerCall) (any, error) {
		if err := c.SendHeaders(textMD("x-test", "yes")); err != nil {
			return nil, err
		}
		for _, s := range []string{"a", "b"} {
			if err := c.Send(ctx, s); err != nil {
				return nil, err
			}
		}
		return nil, c.End(textMD("x-done", true))
	})
	h("optional", func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, err := c.Input()
		if err != nil || v == nil {
			return nil, err
		}
		return v.(string) + "!", nil
	})
	return m
}

func clientMux(ids map[string]uint64) *session.Mux {
	m := session.NewMux()
	m.HandleFunc(16, ids["greet"], func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, err := c.Input()
		if err != nil {
			return nil, err
		}
		return "hello, " + v.(string), nil
	})
	m.HandleFunc(16, ids["count"], func(ctx context.Context, c *session.ServerCall) (any, error) {
		v, err := c.Input()
		if err != nil {
			return nil, err
		}
		for i := uint64(1); i <= v.(uint64); i++ {
			if err := c.Send(ctx, i); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return m
}

// ---------------------------------------------------------------------------
// The client suite: every shape of interop.test, against the peer's schema
// ---------------------------------------------------------------------------

type peer struct {
	s *session.Session
	f *schema.Facet
}

func (p *peer) method(name string) uint64 {
	m, err := node.MethodByName(p.f, name)
	if err != nil {
		panic(err)
	}
	return m.ID
}

func (p *peer) unary(ctx context.Context, name string, in any, o *session.CallOptions) (any, error) {
	return p.s.Unary(ctx, p.f.ID, p.method(name), in, o)
}

func (p *peer) typeID(name string) uint64 {
	for _, t := range p.f.Types {
		if t.Name == name {
			return t.ID
		}
	}
	panic("no type " + name)
}

func (p *peer) sigil(name string) uint64 {
	for _, s := range p.f.Sigils {
		if s.Name == name {
			return s.ID
		}
	}
	panic("no sigil " + name)
}

func expect(cond bool, format string, args ...any) error {
	if !cond {
		return fmt.Errorf(format, args...)
	}
	return nil
}

func runSuite(ctx context.Context, s *session.Session) ([]string, error) {
	f := s.PeerFacet("interop.test")
	if f == nil {
		return nil, errors.New("the server has no facet interop.test")
	}
	p := &peer{s: s, f: f}
	var done []string
	check := func(name string, fn func() error) error {
		if err := fn(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		done = append(done, name)
		return nil
	}
	collect := func(cc *session.ClientCall) ([]any, error) {
		var out []any
		for {
			v, err := cc.Recv(ctx)
			if err == io.EOF {
				return out, nil
			}
			if err != nil {
				return out, err
			}
			out = append(out, v)
		}
	}
	steps := []struct {
		name string
		fn   func() error
	}{
		{"unary", func() error {
			v, err := p.unary(ctx, "echo", "hi", nil)
			if err != nil {
				return err
			}
			return expect(v == "hi", "echo returned %v", v)
		}},
		{"unary-optional", func() error {
			v, err := p.unary(ctx, "optional", nil, nil)
			if err != nil || v != nil {
				return fmt.Errorf("optional(null) = %v, %v", v, err)
			}
			v, err = p.unary(ctx, "optional", "x", nil)
			if err != nil {
				return err
			}
			return expect(v == "x!", "optional(x) = %v", v)
		}},
		{"server-stream", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("count"), uint64(300), nil)
			if err != nil {
				return err
			}
			items, err := collect(cc)
			if err != nil {
				return err
			}
			return expect(len(items) == 300 && items[299] == uint64(300), "got %d items", len(items))
		}},
		{"server-stream-credit", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("count"), uint64(50), &session.CallOptions{Credit: 8})
			if err != nil {
				return err
			}
			items, err := collect(cc)
			if err != nil {
				return err
			}
			return expect(len(items) == 50, "got %d items", len(items))
		}},
		{"client-stream", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("sum"), nil, nil)
			if err != nil {
				return err
			}
			for i := 1; i <= 5000; i++ {
				if err := cc.Send(ctx, int64(i)); err != nil {
					return err
				}
			}
			if err := cc.CloseSend(nil); err != nil {
				return err
			}
			v, err := cc.Response(ctx)
			if err != nil {
				return err
			}
			return expect(v == int64(12502500), "sum = %v", v)
		}},
		{"bidi-stream", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("upper"), nil, nil)
			if err != nil {
				return err
			}
			for _, x := range []string{"x", "y", "z"} {
				if err := cc.Send(ctx, x); err != nil {
					return err
				}
				v, err := cc.Recv(ctx)
				if err != nil {
					return err
				}
				if v != strings.ToUpper(x) {
					return fmt.Errorf("got %v for %s", v, x)
				}
			}
			if err := cc.CloseSend(nil); err != nil {
				return err
			}
			if _, err := cc.Recv(ctx); err != io.EOF {
				return fmt.Errorf("want EOF, got %v", err)
			}
			md, _ := cc.Headers(ctx)
			return expect(bytes.Equal(md[wire.TextKey("x-mode")], cbor.AppendText(nil, "upper")), "headers %v", md)
		}},
		{"notification", func() error {
			if err := s.Notify(ctx, f.ID, p.method("log"), "note from go"); err != nil {
				return err
			}
			for i := 0; i < 100; i++ {
				v, err := p.unary(ctx, "lastLog", nil, nil)
				if err != nil {
					return err
				}
				if v == "note from go" {
					return nil
				}
				time.Sleep(10 * time.Millisecond)
			}
			return errors.New("the notification did not arrive")
		}},
		{"error-details", func() error {
			_, err := p.unary(ctx, "fail", "boom", nil)
			var e *session.Error
			if !errors.As(err, &e) {
				return fmt.Errorf("want *session.Error, got %v", err)
			}
			if uint64(e.Code) != p.sigil("interop_failed") || e.Message != "boom" || !e.Remote {
				return fmt.Errorf("error %+v", e)
			}
			codec, err := value.New(f)
			if err != nil {
				return err
			}
			d, err := codec.Decode(schema.Named(schema.TypeDynamic), e.Details)
			if err != nil {
				return err
			}
			dv := d.(value.Dynamic)
			st := dv.Value.(value.Struct)
			return expect(dv.Type == p.typeID("FailInfo") && st[0] == "boom" && st[1] == uint64(7), "details %+v", dv)
		}},
		{"cancel", func() error {
			cctx, cancel := context.WithCancel(ctx)
			time.AfterFunc(50*time.Millisecond, cancel)
			_, err := p.unary(cctx, "slow", uint64(10000), nil)
			if session.Code(err) != status.Cancelled {
				return fmt.Errorf("want cancelled, got %v", err)
			}
			v, err := p.unary(ctx, "wasCancelled", nil, nil)
			if err != nil {
				return err
			}
			return expect(v == true, "the callee did not see the cancel")
		}},
		{"deadline", func() error {
			cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancel()
			_, err := p.unary(cctx, "slow", uint64(10000), nil)
			if c := session.Code(err); c != status.DeadlineExceeded {
				return fmt.Errorf("want deadline_exceeded, got %v", err)
			}
			v, err := p.unary(ctx, "wasCancelled", nil, nil)
			if err != nil {
				return err
			}
			return expect(v == true, "the callee did not see the deadline")
		}},
		{"progress", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("progress"), uint64(5), nil)
			if err != nil {
				return err
			}
			v, err := cc.Response(ctx)
			if err != nil {
				return err
			}
			pr := cc.LastProgress()
			return expect(v == "done" && pr != nil && pr.Done == 5 && *pr.Total == 5 && *pr.Note == "step 5", "progress %v %+v", v, pr)
		}},
		{"values", func() error {
			uuid := value.UUID{0x6f, 0x1c, 0x2e, 0x4a, 0x8b, 0x3d, 0x4f, 0x5e, 0x9a, 0x7b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b}
			ev := value.Struct{
				0: "héllo ✓", 1: int64(-42), 2: uint64(4294967296), 3: 1.5, 4: true, 5: []byte{0, 1, 2, 255},
				6: cbor.Time{IsFloat: true, Float: 1795780800.5}, 7: uuid, 8: []any{"a", "b"},
				9:  cbor.Map{{Key: "alice", Value: int64(3)}, {Key: "bob", Value: int64(-1)}},
				10: p.sigil("Color.green"),
				11: value.Union{Tag: 1, Value: value.Struct{0: int64(1), 1: int64(2), 2: "p"}},
				12: value.Struct{0: int64(-7), 1: int64(9007199254740991)},
				13: value.Struct{1: "q"},
				15: value.Dynamic{Type: p.typeID("Point"), Value: value.Struct{0: int64(3), 1: int64(4)}},
				16: "sym.hello",
				17: int64(math.MinInt64),
				18: float32(0.5),
			}
			codec, err := value.New(f)
			if err != nil {
				return err
			}
			every := p.typeID("Everything")
			want, err := codec.Encode(schema.Named(every), ev)
			if err != nil {
				return err
			}
			cc, err := s.Call(ctx, f.ID, p.method("roundtrip"), ev, nil)
			if err != nil {
				return err
			}
			got, err := cc.ResponseRaw(ctx)
			if err != nil {
				return err
			}
			return expect(bytes.Equal(got, want), "roundtrip bytes differ:\n got %x\nwant %x", got, want)
		}},
		{"callback", func() error {
			v, err := p.unary(ctx, "callback", "server", nil)
			if err != nil {
				return err
			}
			return expect(v == "hello, server", "callback = %v", v)
		}},
		{"upload", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("upload"), nil, nil)
			if err != nil {
				return err
			}
			if err := cc.Writer(ctx, 0).WriteAll(bytes.Repeat([]byte{7}, 40000)); err != nil {
				return err
			}
			if err := cc.CloseSend(nil); err != nil {
				return err
			}
			v, err := cc.Response(ctx)
			if err != nil {
				return err
			}
			return expect(v == uint64(40000), "upload = %v", v)
		}},
		{"download", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("download"), uint64(50000), nil)
			if err != nil {
				return err
			}
			data, err := io.ReadAll(cc.Reader(0))
			if err != nil {
				return err
			}
			if err := cc.Wait(ctx); err != nil {
				return err
			}
			return expect(len(data) == 50000 && data[257] == 1, "download of %d bytes", len(data))
		}},
		{"headers-trailers", func() error {
			cc, err := s.Call(ctx, f.ID, p.method("headers"), nil, nil)
			if err != nil {
				return err
			}
			items, err := collect(cc)
			if err != nil {
				return err
			}
			md, _ := cc.Headers(ctx)
			tr := cc.Trailers()
			return expect(len(items) == 2 && items[1] == "b" && bytes.Equal(md[wire.TextKey("x-test")], cbor.AppendText(nil, "yes")) &&
				bytes.Equal(tr[wire.TextKey("x-done")], cbor.AppendBool(nil, true)), "items %v headers %v trailers %v", items, md, tr)
		}},
		{"concurrent", func() error {
			var wg sync.WaitGroup
			errs := make(chan error, 50)
			for i := 0; i < 50; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					v, err := p.unary(ctx, "echo", fmt.Sprintf("n%d", i), nil)
					if err == nil && v != fmt.Sprintf("n%d", i) {
						err = fmt.Errorf("echo %d = %v", i, v)
					}
					errs <- err
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					return err
				}
			}
			return nil
		}},
	}
	for _, st := range steps {
		if err := check(st.name, st.fn); err != nil {
			return done, err
		}
	}
	return done, nil
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

func runClient() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cf, cids := clientFacet()
	s, err := session.NewClient(ctx, pipe.Stdio(nil), session.Config{
		Schema:  schemaOf("interop.client", cf),
		Handler: clientMux(cids),
		Auth:    &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "interop")},
	})
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	done, err := runSuite(ctx, s)
	if err != nil {
		s.Close(status.Internal, "client failed")
		return err
	}
	logf("passed %d checks: %s", len(done), strings.Join(done, " "))
	f := s.PeerFacet("interop.test")
	m, _ := node.MethodByName(f, "log")
	if err := s.Notify(ctx, f.ID, m.ID, "suite passed"); err != nil {
		return err
	}
	// The parent calls this side's facet, then ends the session with GoAway.
	select {
	case <-s.Done():
	case <-ctx.Done():
		return errors.New("the server did not end the session")
	}
	if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != status.GoingAway {
		return fmt.Errorf("want GoAway(going_away) from the server, got %+v (%v)", g, s.Err())
	}
	return nil
}

func runServer(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sf, ids := serverFacet()
	st := &serverState{logs: make(chan string, 16)}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "SPARROW_WAIT_FOR_SERVER=1")
	conn, err := pipe.Spawn(cmd, nil)
	if err != nil {
		return err
	}
	s, err := session.NewServer(ctx, conn, session.Config{
		Schema:  schemaOf("interop.server", sf),
		Handler: serverMux(ids, st),
		Authenticate: func(ctx context.Context, h *wire.Hello) (string, error) {
			if h.Auth == nil || !bytes.Equal(h.Auth.Credentials, cbor.AppendText(nil, "interop")) {
				return "", errors.New("bad credential")
			}
			return "ext:ts", nil
		},
	})
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	// Calls from the server to the client's facet.
	cf := s.PeerFacet("interop.client")
	if cf == nil {
		return errors.New("the client published no interop.client facet")
	}
	greet, err := node.MethodByName(cf, "greet")
	if err != nil {
		return err
	}
	v, err := s.Unary(ctx, cf.ID, greet.ID, "go server", nil)
	if err != nil || v != "hello, go server" {
		return fmt.Errorf("greet = %v, %v", v, err)
	}
	count, err := node.MethodByName(cf, "count")
	if err != nil {
		return err
	}
	cc, err := s.Call(ctx, cf.ID, count.ID, uint64(3), nil)
	if err != nil {
		return err
	}
	var items []any
	for {
		x, err := cc.Recv(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		items = append(items, x)
	}
	if len(items) != 3 || items[2] != uint64(3) {
		return fmt.Errorf("client count = %v", items)
	}
	logf("called the client's facet: greet, count")
	// Wait for the client's suite.
	for {
		select {
		case l := <-st.logs:
			if l != "suite passed" {
				continue
			}
		case <-conn.Exited():
			return fmt.Errorf("the client exited before its suite passed: %v", conn.Wait())
		case <-ctx.Done():
			return errors.New("timed out waiting for the client's suite")
		}
		break
	}
	s.GoAway(status.GoingAway, "interop done", nil)
	select {
	case <-conn.Exited():
		if err := conn.Wait(); err != nil {
			return fmt.Errorf("the client failed: %w", err)
		}
	case <-ctx.Done():
		return errors.New("the client did not exit")
	}
	<-s.Done()
	logf("the client passed; session closed: %v", s.Err())
	return nil
}

// ---------------------------------------------------------------------------
// Differential decoding
// ---------------------------------------------------------------------------

func runDecode(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	w := bufio.NewWriter(out)
	defer w.Flush()
	tsCodec, err := value.New(&schema.Facet{ID: 16, Name: "x", Version: "1.0.0", Types: []schema.TypeDef{}, Services: []schema.Service{},
		Sigils: []schema.Sigil{}, Retired: []schema.Retired{}, Annotations: schema.Annotations{}})
	if err != nil {
		return err
	}
	for sc.Scan() {
		what, h, _ := strings.Cut(sc.Text(), " ")
		b, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("bad input line %q", sc.Text())
		}
		res := "err"
		switch what {
		case "cbor":
			if c, err := cbor.Canonical(b, cbor.Options{}); err == nil {
				res = "ok " + hex.EncodeToString(c)
			}
		case "message":
			if m, err := wire.Decode(b); err == nil {
				res = "ok " + hex.EncodeToString(wire.Encode(m))
			}
		case "schema":
			if s, err := schema.DecodeSchema(b); err == nil && s.Validate() == nil {
				if c, err := s.CanonicalBytes(); err == nil {
					res = "ok " + hex.EncodeToString(c)
				}
			}
		case "timestamp":
			if v, err := tsCodec.Decode(schema.Named(schema.TypeTimestamp), b); err == nil {
				if ms, ok := v.(cbor.Time).UnixMilli(); ok {
					res = fmt.Sprintf("ok %d", ms)
				}
			}
		default:
			return fmt.Errorf("unknown input kind %q", what)
		}
		if _, err := fmt.Fprintln(w, res); err != nil {
			return err
		}
	}
	return sc.Err()
}
