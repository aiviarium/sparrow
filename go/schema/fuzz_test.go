package schema

import (
	"bytes"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

// fuzzBases are valid schemas a delta is applied to: the test schema and
// every valid schema of the vectors.
func fuzzBases(f *testing.F) []*Schema {
	out := []*Schema{baseSchema()}
	for _, b := range fuzzseed.Hex("schema.json") {
		if s, err := DecodeSchema(b); err == nil && s.Validate() == nil {
			out = append(out, s)
		}
		if len(out) == 16 {
			break
		}
	}
	return out
}

// FuzzDelta applies arbitrary deltas to valid schemas: an accepted delta
// yields a valid schema whose canonical bytes decode to the same hash, Diff
// of the two applied to the base reproduces it, and the delta re-encodes
// to one that applies the same way.
func FuzzDelta(f *testing.F) {
	bases := fuzzBases(f)
	nf := base().Clone()
	nf.Version = "1.1.0"
	for _, d := range []Delta{
		{{Op: OpPut, Facet: nf}},
		{{Op: OpRemove, FacetID: 16}},
		{{Op: OpRemove, FacetID: 16}, {Op: OpPut, Facet: base()}},
		{{Op: OpVersion, Version: "2"}, {Op: OpAnnotations, Annotations: Annotations{}}},
	} {
		b, err := d.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(0), b)
	}
	for _, b := range fuzzseed.Hex("schema.json") {
		if _, err := DecodeDelta(b); err == nil {
			for i := range bases {
				f.Add(uint8(i), b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, b []byte) {
		d, err := DecodeDelta(b)
		if err != nil {
			return
		}
		old := bases[int(which)%len(bases)]
		st, err := NewState(old)
		if err != nil {
			t.Fatal(err)
		}
		n, err := st.Apply(d)
		if err != nil {
			return
		}
		if n.Epoch() != st.Epoch()+1 {
			t.Fatal("epoch")
		}
		s := n.Schema()
		if err := s.Validate(); err != nil {
			t.Fatalf("applied delta gave an invalid schema: %v", err)
		}
		h, err := n.Hash()
		if err != nil {
			t.Fatal(err)
		}
		c, err := s.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		s2, err := DecodeSchema(c)
		if err != nil {
			t.Fatalf("canonical bytes do not decode: %v", err)
		}
		if h2, _ := s2.Hash(); !bytes.Equal(h, h2) {
			t.Fatal("hash changed through the canonical bytes")
		}
		if _, err := n.ApplyUpdate(n.Epoch()+1, h, nil); err != nil {
			t.Fatalf("empty update: %v", err)
		}
		e, err := d.Encode()
		if err != nil {
			t.Fatalf("accepted delta does not encode: %v", err)
		}
		d2, err := DecodeDelta(e)
		if err != nil {
			t.Fatalf("re-encoded delta does not decode: %v", err)
		}
		n2, err := st.ApplyUpdate(1, h, d2)
		if err != nil {
			t.Fatalf("re-encoded delta: %v", err)
		}
		_ = n2
		// Diff and Apply agree (a removal may be followed by a re-add, so
		// Diff of the schemas is applied to a fresh state).
		dd, err := Diff(st.Schema(), s)
		if err != nil {
			t.Fatalf("Diff: %v", err)
		}
		if _, err := st.ApplyUpdate(1, h, dd); err != nil {
			t.Fatalf("Diff result does not apply: %v", err)
		}
	})
}

// FuzzFacetPair decodes two facets and checks the relations between them:
// a valid facet is compatible with itself, a facet with an equal hash is
// compatible, hashing does not depend on order, and Conforms agrees with
// VerifyImplements for a facet that claims the interface.
func FuzzFacetPair(f *testing.F) {
	b1, _ := base().Encode()
	nf := base().Clone()
	nf.Version = "1.1.0"
	b2, _ := nf.Encode()
	f.Add(b1, b2)
	ib, _ := iface().Encode()
	f.Add(b1, ib)
	hex := fuzzseed.Hex("schema.json", "admin.json")
	for i := 0; i+1 < len(hex); i += 2 {
		f.Add(hex[i], hex[i+1])
	}
	f.Fuzz(func(t *testing.T, a, b []byte) {
		fa, err := DecodeFacet(a)
		if err != nil {
			return
		}
		if fa.Validate() != nil {
			return
		}
		h1, err := fa.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if h2, _ := fa.Canonical().Hash(); !bytes.Equal(h1, h2) {
			t.Fatal("hash depends on order")
		}
		if err := Compatible(fa, fa); err != nil {
			t.Fatalf("facet not compatible with itself: %v", err)
		}
		if fb, err := DecodeFacet(b); err == nil {
			ab, ba := Compatible(fa, fb), Compatible(fb, fa)
			_, _ = ab, ba
			if fb.Validate() == nil {
				if hb, _ := fb.Hash(); bytes.Equal(h1, hb) && Compatible(fa, fb) != nil {
					t.Fatal("equal hashes but incompatible")
				}
			}
		}
		if ib, err := DecodeInterface(b); err == nil && ib.Validate() == nil {
			m := Conforms(fa, ib)
			claim := fa.Clone()
			claim.Implements, _ = ib.Hash()
			if err := VerifyImplements(claim, ib); (err == nil) != (m == nil) {
				t.Fatalf("Conforms %v, VerifyImplements %v", m, err)
			}
		}
	})
}
