package session

import (
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/wire"
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
