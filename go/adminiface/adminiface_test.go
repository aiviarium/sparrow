package adminiface

import (
	"bytes"
	"strings"
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
	// Each enum value sigil is named after its enum (core 6.5).
	names := map[uint64]string{}
	for _, sg := range i.Sigils {
		names[sg.ID] = sg.Name
	}
	for _, td := range i.Types {
		for _, v := range td.Values {
			if !strings.HasPrefix(names[v], td.Name+".") {
				t.Errorf("sigil %d of enum %s is named %q", v, td.Name, names[v])
			}
		}
	}
	// fresh copies
	Facet(20).Types[0].Name = "x"
	if Types()[0].Name != "Config" {
		t.Fatal("Types shares state")
	}
}
