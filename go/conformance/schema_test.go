package conformance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// facetCode converts the vectors' error vocabulary to a schema.Code; the two
// are the same.
func facetCode(code string) schema.Code { return schema.Code(code) }

func codeOf(t *testing.T, err error) schema.Code {
	t.Helper()
	var se *schema.Error
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a *schema.Error", err)
	}
	return se.Code
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func decodeFacetField(t *testing.T, v vectors.Vector, field string) *schema.Facet {
	t.Helper()
	f, err := schema.DecodeFacet(v.CBOR(field))
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return f
}

func decodeSchemaField(t *testing.T, v vectors.Vector, field string) *schema.Schema {
	t.Helper()
	s, err := schema.DecodeSchema(v.CBOR(field))
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return s
}

func decodeInterfaceField(t *testing.T, v vectors.Vector, field string) *schema.Interface {
	t.Helper()
	i, err := schema.DecodeInterface(v.CBOR(field))
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return i
}

type facetHashEntry struct {
	ID   uint64 `json:"facet_id"`
	Name string `json:"facet_name"`
	Hash string `json:"facet_hash"`
}

func checkFacetHashes(t *testing.T, v vectors.Vector, s *schema.Schema) {
	t.Helper()
	var want []facetHashEntry
	v.Into("facet_hashes", &want)
	c := s.Canonical()
	if len(c.Facets) != len(want) {
		t.Fatalf("%d facets, want %d", len(c.Facets), len(want))
	}
	for i, e := range want {
		f := &c.Facets[i]
		h, err := f.Hash()
		if err != nil || f.ID != e.ID || f.Name != e.Name || hx(h) != e.Hash {
			t.Fatalf("facet %d %q hash %x, want %d %q %s", f.ID, f.Name, h, e.ID, e.Name, e.Hash)
		}
	}
}

func TestSchema(t *testing.T) {
	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		f := decodeFacetField(t, v, "input")
		if err := f.Validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		cb, err := f.CanonicalBytes()
		if err != nil || !bytes.Equal(cb, v.Hex("canonical_cbor")) {
			t.Fatalf("canonical %x (%v)\nwant %x", cb, err, v.Hex("canonical_cbor"))
		}
		if !bytes.Equal(v.CBOR("canonical"), cb) {
			t.Fatalf("typed JSON canonical differs from canonical_cbor")
		}
		hi, _ := f.HashInput()
		if !bytes.Equal(hi, v.Hex("hash_input_cbor")) {
			t.Fatalf("hash input %x", hi)
		}
		h, _ := f.Hash()
		if !bytes.Equal(h, v.Hex("facet_hash")) {
			t.Fatalf("hash %x, want %x", h, v.Hex("facet_hash"))
		}
		// canonical bytes decode and re-encode to themselves
		g, err := schema.DecodeFacet(cb)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := g.Encode(); !bytes.Equal(b, cb) {
			t.Fatalf("canonical facet does not round-trip")
		}
		if f.ID == schema.WebFacetID {
			wb, _ := schema.WebFacet().CanonicalBytes()
			if !bytes.Equal(wb, cb) || !bytes.Equal(schema.WebFacetHash(), h) {
				t.Fatalf("built-in sparrow.web differs from the vector")
			}
		}
	}, "facet")

	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		i := decodeInterfaceField(t, v, "input")
		err := i.Validate()
		if !v.Bool("expected_valid") {
			if err == nil {
				t.Fatalf("invalid interface accepted")
			}
			if c := codeOf(t, err); c != facetCode(v.String("expected_error")) {
				t.Fatalf("error %v, want %s", err, v.String("expected_error"))
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		cb, _ := i.CanonicalBytes()
		if !bytes.Equal(cb, v.Hex("canonical_cbor")) || !bytes.Equal(cb, v.CBOR("canonical")) {
			t.Fatalf("canonical %x", cb)
		}
		if h, _ := i.Hash(); !bytes.Equal(h, v.Hex("hash")) {
			t.Fatalf("hash %x", h)
		}
	}, "interface")

	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		iface := decodeInterfaceField(t, vector(t, v.String("interface")), "input")
		f := decodeFacetField(t, v, "facet")
		if err := f.Validate(); err != nil {
			t.Fatal(err)
		}
		mm := schema.Conforms(f, iface)
		if (mm == nil) != v.Bool("expected_conforms") {
			t.Fatalf("Conforms = %v, want conforms=%v", mm, v.Bool("expected_conforms"))
		}
		var first []uint64
		v.Into("first_mismatch", &first)
		if mm != nil && (uint64(mm.Space) != first[0] || mm.ID != first[1]) {
			t.Fatalf("first mismatch %v %d, want %v", mm.Space, mm.ID, first)
		}
		if f.Implements != nil && mm == nil {
			if err := schema.VerifyImplements(f, iface); err != nil {
				t.Fatalf("implements claim: %v", err)
			}
		}
	}, "conformance")

	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		s := decodeSchemaField(t, v, "input")
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		cb, _ := s.CanonicalBytes()
		if !bytes.Equal(cb, v.Hex("canonical_cbor")) || !bytes.Equal(cb, v.CBOR("canonical")) {
			t.Fatalf("canonical differs")
		}
		if int64(len(cb)) != v.Int("canonical_length") {
			t.Fatalf("canonical_length")
		}
		checkFacetHashes(t, v, s)
		hi, _ := s.HashInput()
		if !bytes.Equal(hi, v.Hex("hash_input_cbor")) || !bytes.Equal(hi, v.CBOR("hash_input")) {
			t.Fatalf("hash input differs")
		}
		if h, _ := s.Hash(); !bytes.Equal(h, v.Hex("hash")) {
			t.Fatalf("hash %x", h)
		}
	}, "schema")

	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		s := decodeSchemaField(t, v, "input")
		err := s.Validate()
		if v.Bool("expected_valid") || err == nil {
			t.Fatalf("Validate = %v", err)
		}
		if c := codeOf(t, err); c != facetCode(v.String("expected_error")) {
			t.Fatalf("error %v, want %s", err, v.String("expected_error"))
		}
		if err := s.ValidateWith(schema.ValidateOptions{AllowUnsorted: true}); err != nil {
			t.Fatalf("contents should be otherwise valid: %v", err)
		}
		if h, _ := s.Hash(); !bytes.Equal(h, v.Hex("hash_if_canonicalised")) {
			t.Fatalf("hash %x", h)
		}
	}, "schema_sent")

	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		s := decodeSchemaField(t, v, "input")
		err := s.Validate()
		if v.Bool("expected_valid") || err == nil {
			t.Fatalf("Validate = %v", err)
		}
		if c := codeOf(t, err); c != facetCode(v.String("expected_error")) {
			t.Fatalf("error %v, want %s", err, v.String("expected_error"))
		}
		if h, _ := s.Facets[0].Hash(); !bytes.Equal(h, v.Hex("facet_hash")) || !bytes.Equal(h, schema.WebFacetHash()) {
			t.Fatalf("facet 1 hash %x", h)
		}
	}, "schema_invalid")

	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		a := decodeSchemaField(t, v, "schema_a")
		b := decodeSchemaField(t, v, "schema_b")
		for _, s := range []*schema.Schema{a, b} {
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			if h, _ := s.Facets[0].Hash(); !bytes.Equal(h, v.Hex("facet_hash")) {
				t.Fatalf("facet hash %x", h)
			}
		}
		ha, _ := a.Hash()
		hb, _ := b.Hash()
		if !bytes.Equal(ha, v.Hex("schema_hash_a")) || !bytes.Equal(hb, v.Hex("schema_hash_b")) || bytes.Equal(ha, hb) {
			t.Fatalf("schema hashes %x %x", ha, hb)
		}
	}, "facet_hash_invariance")

	each(t, "schema.json", func(t *testing.T, v vectors.Vector) {
		from := stateOf(t, v.String("from"))
		if h, _ := from.Hash(); !bytes.Equal(h, v.Hex("from_hash")) {
			t.Fatalf("from hash %x", h)
		}
		d, err := schema.DecodeDelta(v.CBOR("delta"))
		if err != nil {
			t.Fatalf("decode delta: %v", err)
		}
		n, err := from.Apply(d)
		if !v.Bool("expected_valid") {
			if err == nil {
				t.Fatalf("invalid delta accepted")
			}
			if c := codeOf(t, err); c != facetCode(v.String("expected_error")) {
				t.Fatalf("error %v, want %s (%s)", err, v.String("expected_error"), v.String("error_detail"))
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		// epoch counts deltas from the base schema
		depth := uint64(0)
		for name := v.Name; vector(t, name).Type == "delta"; name = vector(t, name).String("from") {
			depth++
		}
		if depth != uint64(v.Int("epoch")) || n.Epoch() != depth {
			t.Fatalf("epoch %d (state %d), want %d", depth, n.Epoch(), v.Int("epoch"))
		}
		var removed []uint64
		v.Into("removed_facet_ids_after", &removed)
		if got := n.RemovedFacetIDs(); !equalU64(got, removed) {
			t.Fatalf("removed %v, want %v", got, removed)
		}
		s := n.Schema()
		cb, _ := s.CanonicalBytes()
		if !bytes.Equal(cb, v.Hex("canonical_cbor")) {
			t.Fatalf("canonical differs")
		}
		checkFacetHashes(t, v, s)
		h, _ := n.Hash()
		if !bytes.Equal(h, v.Hex("hash")) {
			t.Fatalf("hash %x", h)
		}
		// the SchemaUpdate carrying this delta
		var su struct {
			Message json.RawMessage `json:"message"`
			CBOR    string          `json:"cbor"`
		}
		v.Into("schema_update", &su)
		m := checkMessageBytes(t, "schema_update", su.Message, vectors.MustHex(su.CBOR)).(*wire.SchemaUpdate)
		d2, err := schema.DecodeDelta(m.Delta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := from.ApplyUpdate(m.Epoch, m.Hash, d2); err != nil {
			t.Fatal(err)
		}
		// Diff reproduces an equivalent delta
		dd, err := schema.Diff(from.Schema(), s)
		if err != nil {
			t.Fatal(err)
		}
		n2, err := from.Apply(dd)
		if err != nil {
			t.Fatalf("applying Diff: %v", err)
		}
		if h2, _ := n2.Hash(); !bytes.Equal(h2, h) {
			t.Fatalf("Diff result hash differs")
		}
	}, "delta")
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
