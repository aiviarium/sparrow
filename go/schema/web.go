package schema

import "sync"

// WebFacetName is the name of facet 1.
const WebFacetName = "sparrow.web"

// WebFacet returns a fresh copy of facet 1, sparrow.web (section 9.4):
// version 1.0.0, no types, sigils, interface, retired IDs or annotations,
// and one service 0 "Client" with one method 0 "moduleRejected", a
// notification whose input is a list of strings (module id, version,
// reason) and whose output is unit.
func WebFacet() *Facet {
	return &Facet{
		ID:      WebFacetID,
		Name:    WebFacetName,
		Version: "1.0.0",
		Types:   []TypeDef{},
		Services: []Service{{
			ID:   0,
			Name: "Client",
			Methods: []Method{{
				ID:          0,
				Name:        "moduleRejected",
				Input:       List(Named(TypeString)),
				Output:      Named(TypeUnit),
				Errors:      []uint64{},
				Flags:       MethodNotification,
				Annotations: Annotations{},
			}},
			Annotations: Annotations{},
		}},
		Sigils:      []Sigil{},
		Implements:  nil,
		Retired:     []Retired{},
		Annotations: Annotations{},
	}
}

// IDs within sparrow.web.
const (
	WebServiceClient        uint64 = 0
	WebMethodModuleRejected uint64 = 0
)

var webHash = sync.OnceValue(func() []byte {
	h, err := WebFacet().Hash()
	if err != nil {
		panic(err)
	}
	return h
})

// WebFacetHash returns the facet hash of sparrow.web.
func WebFacetHash() []byte { return append([]byte{}, webHash()...) }
