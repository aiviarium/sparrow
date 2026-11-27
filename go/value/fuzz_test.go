package value

import (
	"bytes"
	"testing"

	"github.com/aiviarium/sparrow/go/internal/fuzzseed"
	"github.com/aiviarium/sparrow/go/schema"
)

// FuzzDecodeWithFacet decodes arbitrary values against the types of an
// arbitrary valid facet: no panic, no runaway recursion, and an accepted
// value that re-encodes does so stably.
func FuzzDecodeWithFacet(f *testing.F) {
	fb, err := facet().Encode()
	if err != nil {
		f.Fatal(err)
	}
	values := fuzzseed.Hex("encoding.json")
	facets := [][]byte{fb}
	for _, b := range fuzzseed.Hex("schema.json", "admin.json") {
		if fc, err := schema.DecodeFacet(b); err == nil && fc.Validate() == nil {
			facets = append(facets, b)
		}
	}
	for i, v := range values {
		f.Add(facets[i%len(facets)], uint16(i), v)
	}
	f.Fuzz(func(t *testing.T, fbytes []byte, which uint16, b []byte) {
		fc, err := schema.DecodeFacet(fbytes)
		if err != nil || fc.Validate() != nil {
			return
		}
		c, err := New(fc)
		if err != nil {
			t.Fatalf("New on a valid facet: %v", err)
		}
		types := []schema.TypeRef{}
		for id := uint64(0); id < 12; id++ {
			types = append(types, schema.Named(id))
		}
		for _, td := range fc.Types {
			types = append(types, schema.Named(td.ID))
		}
		typ := types[int(which>>2)%len(types)]
		switch which & 3 {
		case 1:
			typ = schema.List(typ)
		case 2:
			typ = schema.Optional(typ)
		case 3:
			typ = schema.MapOf(schema.Named(schema.TypeString), typ)
		}
		_, _ = c.DecodeInner(typ, b)
		v, err := c.Decode(typ, b)
		if err != nil {
			return
		}
		e, err := c.Encode(typ, v)
		if err != nil {
			return // unknown enum values or variants cannot be re-sent
		}
		v2, err := c.Decode(typ, e)
		if err != nil {
			t.Fatalf("re-encoded %x does not decode: %v", e, err)
		}
		e2, err := c.Encode(typ, v2)
		if err != nil || !bytes.Equal(e, e2) {
			t.Fatalf("encoding not stable %x %x (%v)", e, e2, err)
		}
	})
}
