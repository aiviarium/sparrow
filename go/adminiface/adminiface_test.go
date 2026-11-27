package adminiface

import (
	"bytes"
	"testing"

	"github.com/aiviarium/sparrow/go/schema"
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
}
