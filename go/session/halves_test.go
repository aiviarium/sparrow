package session

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/wire"
)

func TestHalves(t *testing.T) {
	t.Parallel()
	type step struct {
		caller bool
		kind   wire.Kind
		final  bool
	}
	for _, tc := range []struct {
		name  string
		flags uint64
		steps []step
		ended bool
	}{
		{"unary", 0, []step{{false, wire.KindResponse, true}}, true},
		{"unary error", 0, []step{{false, wire.KindError, true}}, true},
		{"unary End ignored", 0, []step{{false, wire.KindEnd, false}}, false},
		{"server stream", schema.MethodOutputEnd, []step{
			{false, wire.KindHeaders, false}, {false, wire.KindItem, false}, {false, wire.KindEnd, true}}, true},
		{"response with tokens then End", schema.MethodOutputEnd, []step{
			{false, wire.KindResponse, false}, {false, wire.KindBytes, false}, {false, wire.KindEnd, true}}, true},
		{"client stream", schema.MethodInputEnd, []step{
			{true, wire.KindItem, false}, {true, wire.KindEnd, true}, {false, wire.KindResponse, true}}, true},
		{"client stream callee first", schema.MethodInputEnd, []step{
			{false, wire.KindError, true}, {true, wire.KindItem, false}, {true, wire.KindEnd, true}}, true},
		{"cancel", schema.MethodInputEnd | schema.MethodOutputEnd, []step{
			{true, wire.KindCancel, true}, {false, wire.KindItem, false}, {false, wire.KindError, true}}, true},
		{"bidi open", schema.MethodInputEnd | schema.MethodOutputEnd, []step{
			{true, wire.KindEnd, true}, {false, wire.KindItem, false}}, false},
	} {
		h := newHalves(tc.flags)
		h.request()
		for i, s := range tc.steps {
			var got bool
			if s.caller {
				got = h.callerMsg(s.kind)
			} else {
				got = h.calleeMsg(s.kind)
			}
			if got != s.final {
				t.Errorf("%s: step %d (%v) finished=%v, want %v", tc.name, i, s.kind, got, s.final)
			}
		}
		if h.ended() != tc.ended {
			t.Errorf("%s: ended=%v", tc.name, h.ended())
		}
	}
	// A unary call can be cancelled after its caller half is finished.
	h := newHalves(0)
	h.request()
	if !h.callerDone || !h.callerMaySend(wire.KindCancel) || h.callerMaySend(wire.KindItem) {
		t.Fatal("unary caller rules")
	}
	h.calleeMsg(wire.KindResponse)
	if h.callerMaySend(wire.KindCancel) || h.calleeMaySend(wire.KindItem) {
		t.Fatal("rules after the end")
	}
}

func TestSchemaDepth(t *testing.T) {
	t.Parallel()
	r := schema.Named(schema.TypeUint)
	for i := 0; i < 40; i++ {
		r = schema.List(r)
	}
	f := testFacet(20, "deep")
	f.Services[0].Methods[0].Input = r
	if d := schemaDepth(testSchema("x", f)); d < 40 {
		t.Fatalf("depth %d", d)
	}
}

// TestCloseSendAfterCalleeFinished: an upload whose callee answers as soon
// as the last chunk arrives has its caller half finished by the session
// (End on the caller's behalf, 7.1); the documented CloseSend after the
// writer then succeeds instead of reporting the call as ended.
func TestCloseSendAfterCalleeFinished(t *testing.T) {
	t.Parallel()
	for _, b := range []binding{memBinding(), wsBinding()} {
		t.Run(b.name, func(t *testing.T) {
			cli, _ := stdPair(t, b, newTestHandlers(), nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cc, err := cli.Call(ctx, tFacet, mUpload, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := cc.Writer(ctx, 0).WriteAll([]byte("abc")); err != nil {
				t.Fatal(err)
			}
			if out, err := cc.Response(ctx); err != nil || out != uint64(3) {
				t.Fatalf("got %v %v", out, err)
			}
			// The session's End has gone out and the call has ended.
			testutilEventually(t, func() bool {
				cc.c.mu.Lock()
				defer cc.c.mu.Unlock()
				return cc.c.ended
			})
			if err := cc.CloseSend(nil); err != nil {
				t.Fatalf("CloseSend after the callee finished: %v", err)
			}
		})
	}
}
