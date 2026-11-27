package hub

import (
	"bytes"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
	"github.com/aiviarium/sparrow-rpc/go/schema"
)

// FuzzExtensions parses the document extensions the hub checks (ref.policy
// grants and ref.interfaces): accepted grants re-encode to the same
// grants, and accepted interfaces are valid.
func FuzzExtensions(f *testing.F) {
	f.Add(EncodeGrants([]Grant{{Principal: "user:alice", Facet: "echo", Level: LevelUse}, {Principal: "*", Facet: "acme.*", Level: LevelView}}))
	f.Add(EncodeGrants([]Grant{{Principal: "peer:hub-b/group:eng", Facet: "hub-b/notes", Level: LevelManage}}))
	for _, b := range fuzzseed.Hex("admin.json", "hub.json") {
		f.Add(b)
		f.Add(cbor.AppendBytes(cbor.AppendArrayHead(nil, 1), b))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if gs, err := ParseGrants(b); err == nil {
			e := EncodeGrants(gs)
			gs2, err := ParseGrants(e)
			if err != nil || len(gs2) != len(gs) || !bytes.Equal(EncodeGrants(gs2), e) {
				t.Fatalf("grants round trip: %v", err)
			}
			p := &GrantPolicy{Grants: gs}
			a := Actor{Principal: "user:alice", Groups: []string{"group:eng"}}
			for _, name := range []string{"echo", "acme.x", "hub-b/notes"} {
				ref := FacetRef{Name: name}
				if p.Allowed(a, ref, &schema.Method{}) && !p.Visible(a, ref) {
					t.Fatal("allowed but not visible")
				}
			}
		}
		if is, err := parseInterfaces(b); err == nil {
			for _, i := range is {
				if i.Validate() != nil {
					t.Fatal("invalid interface accepted")
				}
			}
		}
	})
}
