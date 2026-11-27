package names

import (
	"regexp"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

// The grammars as regular expressions: the model the checks must match.
var (
	reNodeID    = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*$`)
	reFacet     = regexp.MustCompile(`^([a-z0-9-]+(\.[a-z0-9-]+)*/)?[a-z0-9-]+(\.[a-z0-9-]+)*$`)
	rePrincipal = regexp.MustCompile(`^(peer:[a-z0-9-]+(\.[a-z0-9-]+)*/)?(user|group|node):[A-Za-z0-9._@-]+$`)
)

// FuzzNames checks every name grammar against its regular expression and
// the helpers that build names against the grammars.
func FuzzNames(f *testing.F) {
	for _, s := range []string{"acme", "acme.notes", "peer-1/acme.notes", "user:alice@example.com", "peer:hub-b/user:x",
		"peer:hub-b/peer:hub-c/user:x", "a..b", "A", "node:", "group:eng", ".", "a/b/c", "\xff"} {
		f.Add(s, "acme")
	}
	for _, s := range fuzzseed.Text("hub.json", "admin.json") {
		f.Add(s, "hub-b")
	}
	f.Fuzz(func(t *testing.T, s, other string) {
		if IsNodeID(s) != reNodeID.MatchString(s) {
			t.Fatalf("IsNodeID(%q) = %v", s, IsNodeID(s))
		}
		if IsModuleID(s) != IsNodeID(s) {
			t.Fatal("IsModuleID")
		}
		if IsFacetName(s) != reFacet.MatchString(s) {
			t.Fatalf("IsFacetName(%q) = %v", s, IsFacetName(s))
		}
		if IsPrincipal(s) != rePrincipal.MatchString(s) {
			t.Fatalf("IsPrincipal(%q) = %v", s, IsPrincipal(s))
		}
		if p, ok := PeerPrincipal(other, s); ok {
			if !IsPrincipal(p) || p != "peer:"+other+"/"+s {
				t.Fatalf("PeerPrincipal(%q, %q) = %q", other, s, p)
			}
		} else if IsNodeID(other) && IsPrincipal(s) && s[:min(len(s), 5)] != "peer:" {
			t.Fatalf("PeerPrincipal refused %q, %q", other, s)
		}
		if IsNodeID(other) && IsNodeID(s) {
			im := Imported(other, s)
			if !IsFacetName(im) {
				t.Fatalf("Imported %q not a facet name", im)
			}
			if peer, local := SplitPeer(im); peer != other || local != s {
				t.Fatal("SplitPeer(Imported)")
			}
			if ModuleInFacet(im, s) != ModuleInFacet(s, s) || !ModuleInFacet(s, s) {
				t.Fatal("ModuleInFacet ignores the peer prefix")
			}
			if !IsPrincipal(NodePrincipal(s)) {
				t.Fatal("NodePrincipal")
			}
		}
		if OwnedBy(other, s) && IsNodeID(s) && !IsNodeID(other) {
			t.Fatalf("a valid facet name %q owned by an invalid node ID %q", s, other)
		}
		_ = IsASCII(s)
	})
}
