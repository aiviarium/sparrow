package hub

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
)

// Actor is one acting principal (Hub Profile 10.4) with the groups its
// credential carries.
type Actor struct {
	Principal string
	Groups    []string
}

// FacetRef describes a facet the hub lists, for policy decisions.
type FacetRef struct {
	ID   uint64 // hub facet ID
	Name string // the name the hub lists it under ("<peer>/<name>" when imported)
	Node string // the owning node, "" for the hub's own facets
	// Imported is set for a facet of a peer hub (10.8).
	Imported bool
	Def      *schema.Facet
}

// Policy makes the two decisions of section 10.4. The hub calls it for
// every acting principal of every call and for every facet of every
// session's schema; it must be safe for concurrent use. A Policy is
// immutable: the hub replaces it to change decisions.
type Policy interface {
	Visible(a Actor, f FacetRef) bool
	// Allowed is only asked for visible facets.
	Allowed(a Actor, f FacetRef, m *schema.Method) bool
}

// Level is a grant level.
type Level int

// Grant levels: view lists the facet, use calls its methods, manage also
// calls methods annotated "sparrow.level": "manage".
const (
	LevelNone Level = iota
	LevelView
	LevelUse
	LevelManage
)

func (l Level) String() string {
	switch l {
	case LevelView:
		return "view"
	case LevelUse:
		return "use"
	case LevelManage:
		return "manage"
	}
	return "none"
}

// ParseLevel parses view, use or manage.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "view":
		return LevelView, nil
	case "use":
		return LevelUse, nil
	case "manage":
		return LevelManage, nil
	}
	return LevelNone, fmt.Errorf("unknown level %q (want view, use or manage)", s)
}

// Grant is one entry of the built-in policy: a principal (or a group, or
// "*" for everyone) gets a level on a facet (by listed name, "*" for all,
// or "prefix.*" for every facet whose name starts with "prefix.").
type Grant struct {
	Principal string
	Facet     string
	Level     Level
}

// PolicyExtension is the document extension key of the built-in policy
// (reference-server note, section 4).
const PolicyExtension = "ref.policy"

// ParseGrants decodes the value of the ref.policy extension: a CBOR list
// of [principal, facet name, level].
func ParseGrants(b []byte) ([]Grant, error) {
	v, err := cbor.Decode(b, cbor.Options{})
	if err != nil {
		return nil, err
	}
	list, ok := v.([]any)
	if !ok {
		return nil, errors.New("ref.policy must be a list of [principal, facet, level]")
	}
	out := make([]Grant, 0, len(list))
	for i, e := range list {
		g, ok := e.([]any)
		if !ok || len(g) != 3 {
			return nil, fmt.Errorf("grant %d must be [principal, facet, level]", i)
		}
		p, ok1 := g[0].(string)
		f, ok2 := g[1].(string)
		l, ok3 := g[2].(string)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("grant %d must hold three strings", i)
		}
		if p != "*" && !names.IsPrincipal(p) {
			return nil, fmt.Errorf("grant %d: %q is not a principal", i, p)
		}
		if f != "*" && !names.IsFacetName(strings.TrimSuffix(f, ".*")) {
			return nil, fmt.Errorf("grant %d: %q is not a facet name or pattern", i, f)
		}
		lv, err := ParseLevel(l)
		if err != nil {
			return nil, fmt.Errorf("grant %d: %v", i, err)
		}
		out = append(out, Grant{Principal: p, Facet: f, Level: lv})
	}
	return out, nil
}

// EncodeGrants encodes grants as the ref.policy extension value.
func EncodeGrants(gs []Grant) []byte {
	b := cbor.AppendArrayHead(nil, len(gs))
	for _, g := range gs {
		b = cbor.AppendArrayHead(b, 3)
		b = cbor.AppendText(b, g.Principal)
		b = cbor.AppendText(b, g.Facet)
		b = cbor.AppendText(b, g.Level.String())
	}
	return b
}

// GrantPolicy is the built-in policy (reference-server note, section 4).
type GrantPolicy struct{ Grants []Grant }

func (p *GrantPolicy) level(a Actor, f FacetRef) Level {
	best := LevelNone
	for _, g := range p.Grants {
		if g.Level <= best || !facetMatches(g.Facet, f.Name) || !principalMatches(g.Principal, a) {
			continue
		}
		best = g.Level
	}
	return best
}

func facetMatches(pattern, name string) bool {
	if pattern == "*" || pattern == name {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, ".*"); ok {
		return strings.HasPrefix(name, prefix+".")
	}
	return false
}

func principalMatches(p string, a Actor) bool {
	if p == "*" || p == a.Principal {
		return true
	}
	for _, g := range a.Groups {
		if g == p {
			return true
		}
	}
	return false
}

// Visible needs view.
func (p *GrantPolicy) Visible(a Actor, f FacetRef) bool { return p.level(a, f) >= LevelView }

// Allowed needs use, or manage for a method annotated "sparrow.level":
// "manage".
func (p *GrantPolicy) Allowed(a Actor, f FacetRef, m *schema.Method) bool {
	need := LevelUse
	if MethodLevel(m) == "manage" {
		need = LevelManage
	}
	return p.level(a, f) >= need
}

// MethodLevel returns a method's sparrow.level hint, or "".
func MethodLevel(m *schema.Method) string {
	if m == nil {
		return ""
	}
	raw, ok := m.Annotations[adminiface.LevelAnnotation]
	if !ok {
		return ""
	}
	s, err := cbor.NewDecoder(raw).Text()
	if err != nil {
		return ""
	}
	return s
}

// hubPolicy wraps the configured policy with the hub's fixed rules: the
// bootstrap administrators are always allowed every method of
// sparrow.hub.admin (hub-admin section 1), and facet 1 sparrow.web is part
// of every session's schema and callable by everyone (9.4).
type hubPolicy struct {
	inner     Policy
	bootstrap map[string]bool
}

func (p *hubPolicy) fixed(a Actor, f FacetRef) (bool, bool) {
	if f.Node == "" && !f.Imported {
		switch f.Name {
		case schema.WebFacetName:
			return true, true
		case adminiface.Name:
			if p.bootstrap[a.Principal] {
				return true, true
			}
		}
	}
	return false, false
}

func (p *hubPolicy) Visible(a Actor, f FacetRef) bool {
	if v, ok := p.fixed(a, f); ok {
		return v
	}
	return p.inner != nil && p.inner.Visible(a, f)
}

func (p *hubPolicy) Allowed(a Actor, f FacetRef, m *schema.Method) bool {
	if v, ok := p.fixed(a, f); ok {
		return v
	}
	return p.inner != nil && p.inner.Visible(a, f) && p.inner.Allowed(a, f, m)
}
