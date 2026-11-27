package conformance

import (
	"bytes"
	"testing"

	"github.com/aiviarium/sparrow/go/adminiface"
	"github.com/aiviarium/sparrow/go/internal/vectors"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/value"
	"github.com/aiviarium/sparrow/go/wire"
)

func TestAdmin(t *testing.T) {
	each(t, "admin.json", func(t *testing.T, v vectors.Vector) {
		i := decodeInterfaceField(t, v, "input")
		if err := i.Validate(); err != nil {
			t.Fatal(err)
		}
		cb, _ := i.CanonicalBytes()
		if !bytes.Equal(cb, v.Hex("canonical_cbor")) || !bytes.Equal(cb, v.CBOR("canonical")) {
			t.Fatalf("canonical differs")
		}
		// The library's constructor builds exactly this interface.
		lb, err := adminiface.Interface().CanonicalBytes()
		if err != nil || !bytes.Equal(lb, cb) {
			t.Fatalf("adminiface.Interface() differs from the vector\n got %x\nwant %x", lb, cb)
		}
		if h := adminiface.InterfaceHash(); !bytes.Equal(h, v.Hex("hash")) {
			t.Fatalf("interface hash %x, want %x", h, v.Hex("hash"))
		}
	}, "interface")

	each(t, "admin.json", func(t *testing.T, v vectors.Vector) {
		f := decodeFacetField(t, v, "input")
		if err := f.Validate(); err != nil {
			t.Fatal(err)
		}
		cb, _ := f.CanonicalBytes()
		lb, _ := adminiface.Facet(f.ID).CanonicalBytes()
		if !bytes.Equal(cb, v.Hex("canonical_cbor")) || !bytes.Equal(lb, cb) {
			t.Fatalf("adminiface.Facet differs from the vector")
		}
		if h, _ := f.Hash(); !bytes.Equal(h, v.Hex("facet_hash")) {
			t.Fatalf("facet hash %x", h)
		}
		if hi, _ := f.HashInput(); !bytes.Equal(hi, v.Hex("hash_input_cbor")) {
			t.Fatalf("hash input")
		}
		iface := decodeInterfaceField(t, vector(t, v.String("interface")), "input")
		if err := schema.VerifyImplements(f, iface); err != nil || !v.Bool("expected_conforms") {
			t.Fatalf("implements: %v", err)
		}
	}, "facet")

	codec := codecFor(t, adminiface.Facet(20))
	each(t, "admin.json", func(t *testing.T, v vectors.Vector) {
		cb := v.Hex("cbor")
		if !bytes.Equal(cb, v.CBOR("value")) {
			t.Fatalf("cbor differs from typed JSON value")
		}
		typ := schema.Named(uint64(v.Int("type_id")))
		val, err := codec.Decode(typ, cb)
		if err != nil {
			t.Fatalf("decode with the admin types: %v", err)
		}
		got, err := codec.Encode(typ, val)
		if err != nil || !bytes.Equal(got, cb) {
			t.Fatalf("re-encoded %x, %v\nwant %x", got, err, cb)
		}
		if td := adminiface.Facet(20).Type(typ.ID); td == nil || td.Name != v.String("type_name") {
			t.Fatalf("type name")
		}
	}, "admin_value")

	each(t, "admin.json", func(t *testing.T, v vectors.Vector) {
		m := checkMessageVector(t, v)
		e, ok := m.(*wire.Error)
		if !ok || e.Status != uint64(status.FailedPrecondition) {
			t.Fatalf("want Error(failed_precondition), got %+v", m)
		}
		d, err := codec.Decode(schema.Named(schema.TypeDynamic), e.Details)
		if err != nil {
			t.Fatalf("details: %v", err)
		}
		if dy, ok := d.(value.Dynamic); !ok || dy.Type != adminiface.TypeProblems {
			t.Fatalf("details %+v are not dynamic Problems", d)
		}
	}, "message")
}
