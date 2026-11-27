package session

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func forBindings(t *testing.T, f func(t *testing.T, b binding)) {
	for _, b := range allBindings() {
		t.Run(b.name, func(t *testing.T) { f(t, b) })
	}
}

func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestShapes(t *testing.T) {
	forBindings(t, func(t *testing.T, b binding) {
		h := newTestHandlers()
		cli, srv := stdPair(t, b, h, nil)
		ctx := tctx(t)

		t.Run("server-stream", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mCount, uint64(2000), nil)
			if err != nil {
				t.Fatal(err)
			}
			for i := uint64(0); i < 2000; i++ {
				v, err := cc.Recv(ctx)
				if err != nil {
					t.Fatalf("item %d: %v", i, err)
				}
				if v != i {
					t.Fatalf("item %d = %v", i, v)
				}
			}
			if _, err := cc.Recv(ctx); err != io.EOF {
				t.Fatalf("want EOF, got %v", err)
			}
			if err := cc.Wait(ctx); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("client-stream", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mSum, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var want uint64
			for i := uint64(0); i < 3000; i++ {
				want += i
				if err := cc.Send(ctx, i); err != nil {
					t.Fatal(err)
				}
			}
			if err := cc.CloseSend(nil); err != nil {
				t.Fatal(err)
			}
			out, err := cc.Response(ctx)
			if err != nil || out != want {
				t.Fatalf("got %v %v, want %d", out, err, want)
			}
		})
		t.Run("bidi", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mChat, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 50; i++ {
				msg := string(rune('a' + i%26))
				if err := cc.Send(ctx, msg); err != nil {
					t.Fatal(err)
				}
				v, err := cc.Recv(ctx)
				if err != nil || v != "re: "+msg {
					t.Fatalf("got %v %v", v, err)
				}
			}
			_ = cc.CloseSend(nil)
			if _, err := cc.Recv(ctx); err != io.EOF {
				t.Fatalf("want EOF, got %v", err)
			}
		})
		t.Run("upload", func(t *testing.T) {
			cc, err := cli.Call(ctx, tFacet, mUpload, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			data := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
			if err := cc.Writer(ctx, 0).WriteAll(data); err != nil {
				t.Fatal(err)
			}
			if err := cc.CloseSend(nil); err != nil {
				t.Fatal(err)
			}
			out, err := cc.Response(ctx)
			if err != nil || out != uint64(len(data)) {
				t.Fatalf("got %v %v", out, err)
			}
		})
		t.Run("download", func(t *testing.T) {
			const n = 3 << 20
			cc, err := cli.Call(ctx, tFacet, mDownload, uint64(n), nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(cc.Reader(0))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != n {
				t.Fatalf("got %d bytes", len(got))
			}
			if err := cc.Wait(ctx); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("referenced-tokens", func(t *testing.T) {
			// Input with a token: Request(value with token 3), Bytes, End.
			in := value.Struct{0: "file", 1: value.Token(3)}
			cc, err := cli.Call(ctx, tFacet, mAttach, in, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := cc.Writer(ctx, 3).WriteAll(make([]byte, 100000)); err != nil {
				t.Fatal(err)
			}
			_ = cc.CloseSend(nil)
			out, err := cc.Response(ctx)
			if err != nil || out != uint64(100004) {
				t.Fatalf("got %v %v", out, err)
			}
			// Output with a token, Bytes sent before the Response.
			cc, err = cli.Call(ctx, tFacet, mFetch, "xy", nil)
			if err != nil {
				t.Fatal(err)
			}
			v, err := cc.Response(ctx)
			if err != nil {
				t.Fatal(err)
			}
			st := v.(value.Struct)
			data, err := io.ReadAll(cc.Reader(uint64(st[1].(value.Token))))
			if err != nil || len(data) != 2000 {
				t.Fatalf("got %d bytes, %v", len(data), err)
			}
			if err := cc.Wait(ctx); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("application-error", func(t *testing.T) {
			_, err := cli.Unary(ctx, tFacet, mFail, "boom", nil)
			e, ok := err.(*Error)
			if !ok || e.Code != errApp || e.Message != "boom" || !e.Remote || len(e.Details) == 0 {
				t.Fatalf("got %#v", err)
			}
		})
		t.Run("unknown-method", func(t *testing.T) {
			flags := uint64(0)
			cc, err := cli.OpenRaw(ctx, RawRequest{FacetID: tFacet, MethodID: 999}, &CallOptions{Flags: &flags})
			if err != nil {
				t.Fatal(err)
			}
			m, err := cc.RecvRaw(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if e, ok := m.Message.(*wire.Error); !ok || status.Code(e.Status) != status.Unimplemented {
				t.Fatalf("got %v", m.Message)
			}
			cc, err = cli.OpenRaw(ctx, RawRequest{FacetID: 77, MethodID: 1}, &CallOptions{Flags: &flags})
			if err != nil {
				t.Fatal(err)
			}
			m, err = cc.RecvRaw(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if e, ok := m.Message.(*wire.Error); !ok || status.Code(e.Status) != status.Unimplemented {
				t.Fatalf("got %v", m.Message)
			}
			// Typed calls to a method the peer does not list fail locally.
			if _, err := cli.Call(ctx, tFacet, 999, nil, nil); Code(err) != status.Unimplemented {
				t.Fatalf("got %v", err)
			}
		})
		t.Run("notifications", func(t *testing.T) {
			for i := 0; i < 10; i++ {
				if err := cli.Notify(ctx, tFacet, mNotify, "n"); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 10; i++ {
				select {
				case <-h.notified:
				case <-time.After(5 * time.Second):
					t.Fatal("notification not delivered")
				}
			}
		})
		t.Run("server-calls-client", func(t *testing.T) {
			// The server calls a facet the client published inline in Hello.
			_ = srv
		})
		t.Run("concurrent", func(t *testing.T) {
			errs := make(chan error, 50)
			for i := 0; i < 50; i++ {
				go func() {
					out, err := cli.Unary(ctx, tFacet, mEcho, "x", nil)
					if err == nil && out != "x" {
						err = io.ErrUnexpectedEOF
					}
					errs <- err
				}()
			}
			for i := 0; i < 50; i++ {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
		})
	})
}

// TestBidirectional: both sides publish a schema and call each other.
func TestBidirectional(t *testing.T) {
	forBindings(t, func(t *testing.T, b binding) {
		hc, hs := newTestHandlers(), newTestHandlers()
		ccfg := Config{Schema: testSchema("client", testFacet(20, "cli")), Handler: hc.mux(20)}
		scfg := Config{Schema: testSchema("server"), Handler: hs.mux(tFacet)}
		cli, srv := pair(t, b, ccfg, scfg)
		ctx := tctx(t)
		out, err := srv.Unary(ctx, 20, mEcho, "from server", nil)
		if err != nil || out != "from server" {
			t.Fatalf("server->client: %v %v", out, err)
		}
		cc, err := srv.Call(ctx, 20, mCount, uint64(100), nil)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for {
			_, err := cc.Recv(ctx)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			n++
		}
		if n != 100 {
			t.Fatalf("got %d items", n)
		}
		out, err = cli.Unary(ctx, tFacet, mEcho, "from client", nil)
		if err != nil || out != "from client" {
			t.Fatalf("client->server: %v %v", out, err)
		}
		if b.leases {
			// The server leases its own streams to the client.
			testutilEventually(t, func() bool { return srv.Stats().PoolOpen >= 1 })
		}
	})
}
