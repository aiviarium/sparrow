package schema

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

// Error is a schema error. Code is a stable identifier (the vocabulary of
// the test vectors, with "part" spelled "facet"); Detail is for humans.
type Error struct {
	Code   Code
	Detail string
}

func (e *Error) Error() string { return "schema: " + string(e.Code) + ": " + e.Detail }

// Code identifies the kind of a schema error.
type Code string

// Error codes.
const (
	CodeMalformed             Code = "malformed"
	CodeTooLarge              Code = "too_large"
	CodeUnsupportedFormat     Code = "unsupported_format"
	CodeBadTypeRef            Code = "bad_type_ref"
	CodeUnknownDeltaOp        Code = "unknown_delta_op"
	CodeInvalidName           Code = "invalid_name"
	CodeReservedID            Code = "reserved_id"
	CodeDuplicateID           Code = "duplicate_id"
	CodeRetiredIDReused       Code = "retired_id_reused"
	CodeBadRetiredEntry       Code = "bad_retired_entry"
	CodeDanglingReference     Code = "dangling_reference"
	CodeStreamMisplaced       Code = "stream_type_misplaced"
	CodeMissingEndFlag        Code = "missing_end_flag"
	CodeFloat                 Code = "float_in_canonical_data"
	CodeBadSigilKind          Code = "bad_sigil_kind"
	CodeInterfaceNotClosed    Code = "interface_not_closed"
	CodeFacetsNotSorted       Code = "facets_not_sorted"
	CodeDuplicateFacetID      Code = "duplicate_facet_id"
	CodeDuplicateFacetName    Code = "duplicate_facet_name"
	CodeReservedFacetID       Code = "reserved_facet_id"
	CodeFacet1Mismatch        Code = "facet1_mismatch"
	CodeFacetRenamed          Code = "facet_renamed"
	CodeMajorVersionChanged   Code = "major_version_changed"
	CodeRetiredNotCarriedOver Code = "retired_not_carried_over"
	CodeDroppedIDNotRetired   Code = "dropped_id_not_retired"
	CodeIncompatibleChange    Code = "incompatible_change"
	CodeRemovedFacetMismatch  Code = "removed_facet_mismatch"
	CodeUnknownFacet          Code = "unknown_facet"
	CodeHashMismatch          Code = "hash_mismatch"
	CodeEpochMismatch         Code = "epoch_mismatch"
	CodeImplementsMismatch    Code = "implements_mismatch"
)

func errorf(code Code, f string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(f, args...)}
}

// HashLen is the length of every Sparrow hash: 0x01 || SHA-256.
const HashLen = 33

// HashAlgSHA256 is the leading byte naming SHA-256.
const HashAlgSHA256 = 0x01

// Hash returns 0x01 || SHA-256(b).
func Hash(b []byte) []byte {
	s := sha256.Sum256(b)
	return append([]byte{HashAlgSHA256}, s[:]...)
}

// ---------------------------------------------------------------------------
// Deep copies
// ---------------------------------------------------------------------------

func (a Annotations) clone() Annotations {
	if a == nil {
		return nil
	}
	c := make(Annotations, len(a))
	for k, v := range a {
		c[k] = v
	}
	return c
}

func (t TypeRef) clone() TypeRef {
	c := t
	if t.Elem != nil {
		e := t.Elem.clone()
		c.Elem = &e
	}
	if t.Key != nil {
		k := t.Key.clone()
		c.Key = &k
	}
	return c
}

func (t *TypeDef) clone() TypeDef {
	c := *t
	c.Fields = make([]Field, len(t.Fields))
	for i, f := range t.Fields {
		f.Type = f.Type.clone()
		f.Annotations = f.Annotations.clone()
		c.Fields[i] = f
	}
	if t.Kind != KindStruct && t.Kind != KindUnion {
		c.Fields = nil
	}
	c.Values = append([]uint64(nil), t.Values...)
	c.Target = t.Target.clone()
	c.Annotations = t.Annotations.clone()
	return c
}

func (m *Method) clone() Method {
	c := *m
	c.Input = m.Input.clone()
	c.Output = m.Output.clone()
	c.Errors = append([]uint64{}, m.Errors...)
	c.Annotations = m.Annotations.clone()
	return c
}

func (s *Service) clone() Service {
	c := *s
	c.Methods = make([]Method, len(s.Methods))
	for i := range s.Methods {
		c.Methods[i] = s.Methods[i].clone()
	}
	c.Annotations = s.Annotations.clone()
	return c
}

func cloneDefs(types []TypeDef, services []Service, sigils []Sigil) ([]TypeDef, []Service, []Sigil) {
	t := make([]TypeDef, len(types))
	for i := range types {
		t[i] = types[i].clone()
	}
	s := make([]Service, len(services))
	for i := range services {
		s[i] = services[i].clone()
	}
	g := make([]Sigil, len(sigils))
	for i, x := range sigils {
		x.Annotations = x.Annotations.clone()
		g[i] = x
	}
	return t, s, g
}

// Clone returns a deep copy of the facet.
func (f *Facet) Clone() *Facet {
	c := *f
	c.Types, c.Services, c.Sigils = cloneDefs(f.Types, f.Services, f.Sigils)
	if f.Implements != nil {
		c.Implements = append([]byte{}, f.Implements...)
	}
	c.Retired = append([]Retired{}, f.Retired...)
	c.Annotations = f.Annotations.clone()
	return &c
}

// Clone returns a deep copy of the interface.
func (i *Interface) Clone() *Interface {
	c := *i
	c.Types, c.Services, c.Sigils = cloneDefs(i.Types, i.Services, i.Sigils)
	return &c
}

// Clone returns a deep copy of the schema.
func (s *Schema) Clone() *Schema {
	c := *s
	c.Facets = make([]Facet, len(s.Facets))
	for i := range s.Facets {
		c.Facets[i] = *s.Facets[i].Clone()
	}
	c.Annotations = s.Annotations.clone()
	return &c
}

// ---------------------------------------------------------------------------
// Canonical form (section 6.6)
// ---------------------------------------------------------------------------

func sortUints(xs []uint64) { sort.SliceStable(xs, func(i, j int) bool { return xs[i] < xs[j] }) }

// sortDefs sorts types, services and sigils by ID, methods by ID within
// their service, fields and variants by tag, enum values and errors by
// sigil ID. Every other array keeps its order.
func sortDefs(types []TypeDef, services []Service, sigils []Sigil) {
	sort.SliceStable(types, func(i, j int) bool { return types[i].ID < types[j].ID })
	for i := range types {
		t := &types[i]
		sort.SliceStable(t.Fields, func(a, b int) bool { return t.Fields[a].Tag < t.Fields[b].Tag })
		sortUints(t.Values)
	}
	sort.SliceStable(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	for i := range services {
		ms := services[i].Methods
		sort.SliceStable(ms, func(a, b int) bool { return ms[a].ID < ms[b].ID })
		for j := range ms {
			sortUints(ms[j].Errors)
		}
	}
	sort.SliceStable(sigils, func(i, j int) bool { return sigils[i].ID < sigils[j].ID })
}

// Canonical returns a sorted deep copy of the facet.
func (f *Facet) Canonical() *Facet {
	c := f.Clone()
	sortDefs(c.Types, c.Services, c.Sigils)
	sort.SliceStable(c.Retired, func(i, j int) bool {
		if c.Retired[i].Space != c.Retired[j].Space {
			return c.Retired[i].Space < c.Retired[j].Space
		}
		return c.Retired[i].ID < c.Retired[j].ID
	})
	return c
}

// Canonical returns a sorted deep copy of the interface.
func (i *Interface) Canonical() *Interface {
	c := i.Clone()
	sortDefs(c.Types, c.Services, c.Sigils)
	return c
}

// Canonical returns a sorted deep copy of the schema, facets sorted by ID.
func (s *Schema) Canonical() *Schema {
	c := s.Clone()
	for i := range c.Facets {
		c.Facets[i] = *c.Facets[i].Canonical()
	}
	sort.SliceStable(c.Facets, func(i, j int) bool { return c.Facets[i].ID < c.Facets[j].ID })
	return c
}

// CanonicalBytes returns the Core Deterministic Encoding of the canonical
// facet.
func (f *Facet) CanonicalBytes() ([]byte, error) {
	w := &writer{canonical: true}
	w.facet(f.Canonical())
	return w.b, w.err
}

// HashInput returns the bytes a facet hash covers: the canonical facet with
// its name set to "" and its id set to 0.
func (f *Facet) HashInput() ([]byte, error) {
	c := f.Canonical()
	c.ID, c.Name = 0, ""
	w := &writer{canonical: true}
	w.facet(c)
	return w.b, w.err
}

// Hash returns the facet hash, which does not depend on the facet's ID or
// name.
func (f *Facet) Hash() ([]byte, error) {
	b, err := f.HashInput()
	if err != nil {
		return nil, err
	}
	return Hash(b), nil
}

// CanonicalBytes returns the canonical encoding of the interface.
func (i *Interface) CanonicalBytes() ([]byte, error) {
	w := &writer{canonical: true}
	w.iface(i.Canonical())
	return w.b, w.err
}

// Hash returns the interface hash.
func (i *Interface) Hash() ([]byte, error) {
	b, err := i.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	return Hash(b), nil
}

// CanonicalBytes returns the canonical encoding of the schema.
func (s *Schema) CanonicalBytes() ([]byte, error) {
	w := &writer{canonical: true}
	w.schema(s.Canonical())
	return w.b, w.err
}

// HashInput returns the bytes the schema hash covers:
// [format, name, version, [* [facet_id, facet_name, facet_hash]], annotations]
// with the entries sorted by facet ID, in Core Deterministic Encoding.
func (s *Schema) HashInput() ([]byte, error) {
	c := s.Canonical()
	w := &writer{canonical: true}
	w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, 5), c.Format)
	w.b = cbor.AppendText(cbor.AppendText(w.b, c.Name), c.Version)
	w.b = cbor.AppendArrayHead(w.b, len(c.Facets))
	for i := range c.Facets {
		f := &c.Facets[i]
		h, err := f.Hash()
		if err != nil {
			return nil, err
		}
		w.b = cbor.AppendText(cbor.AppendUint(cbor.AppendArrayHead(w.b, 3), f.ID), f.Name)
		w.b = cbor.AppendBytes(w.b, h)
	}
	w.annotations(c.Annotations)
	return w.b, w.err
}

// Hash returns the schema hash.
func (s *Schema) Hash() ([]byte, error) {
	b, err := s.HashInput()
	if err != nil {
		return nil, err
	}
	return Hash(b), nil
}
