package adminiface

import (
	"bytes"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/schema"
)

func TestInterfaceAndFacet(t *testing.T) {
	i := Interface()
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
	f := Facet(20)
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	if m := schema.Conforms(f, i); m != nil {
		t.Fatalf("facet does not conform: %v", m)
	}
	if err := schema.VerifyImplements(f, i); err != nil {
		t.Fatal(err)
	}
	h, _ := i.Hash()
	if !bytes.Equal(h, InterfaceHash()) || len(h) != schema.HashLen {
		t.Fatalf("interface hash %x", h)
	}
	// fresh copies
	Facet(20).Types[0].Name = "x"
	if Types()[0].Name != "Config" {
		t.Fatal("Types shares state")
	}
	k, err := StoredFacetKey(f)
	fh, _ := f.Hash()
	if err != nil || bytes.Equal(k, fh) || len(k) != schema.HashLen {
		t.Fatalf("stored key %x facet hash %x (%v)", k, fh, err)
	}
	g := f.Clone()
	g.ID = 99
	if k2, _ := StoredFacetKey(g); !bytes.Equal(k, k2) {
		t.Fatal("stored key depends on the facet ID")
	}
	g.Name = "sparrow.hub.admin2"
	if k3, _ := StoredFacetKey(g); bytes.Equal(k, k3) {
		t.Fatal("stored key ignores the name")
	}
}
