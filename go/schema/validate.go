package schema

import (
	"bytes"
	"fmt"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/names"
)

// index holds a facet's or interface's definitions by ID.
type index struct {
	types   map[uint64]*TypeDef
	sigils  map[uint64]*Sigil
	methods map[uint64]*Method
	svcs    map[uint64]*Service
}

func buildIndex(types []TypeDef, services []Service, sigils []Sigil) *index {
	ix := &index{map[uint64]*TypeDef{}, map[uint64]*Sigil{}, map[uint64]*Method{}, map[uint64]*Service{}}
	for i := range types {
		ix.types[types[i].ID] = &types[i]
	}
	for i := range sigils {
		ix.sigils[sigils[i].ID] = &sigils[i]
	}
	for i := range services {
		s := &services[i]
		ix.svcs[s.ID] = s
		for j := range s.Methods {
			ix.methods[s.Methods[j].ID] = &s.Methods[j]
		}
	}
	return ix
}

// annotationsHaveFloat reports a float in any annotation value.
func annotationsHaveFloat(a Annotations) bool {
	for _, v := range a {
		if cbor.ContainsFloat(v) {
			return true
		}
	}
	return false
}

func defsHaveFloat(types []TypeDef, services []Service, sigils []Sigil) bool {
	for i := range types {
		t := &types[i]
		if annotationsHaveFloat(t.Annotations) {
			return true
		}
		for j := range t.Fields {
			if annotationsHaveFloat(t.Fields[j].Annotations) {
				return true
			}
		}
	}
	for i := range services {
		if annotationsHaveFloat(services[i].Annotations) {
			return true
		}
		for j := range services[i].Methods {
			if annotationsHaveFloat(services[i].Methods[j].Annotations) {
				return true
			}
		}
	}
	for i := range sigils {
		if annotationsHaveFloat(sigils[i].Annotations) {
			return true
		}
	}
	return false
}

func checkASCIINames(where string, types []TypeDef, services []Service, sigils []Sigil) error {
	bad := func(kind, n string) error {
		return errorf(CodeInvalidName, "%s: %s name %q is not ASCII", where, kind, n)
	}
	for i := range types {
		t := &types[i]
		if !names.IsASCII(t.Name) {
			return bad("type", t.Name)
		}
		for j := range t.Fields {
			if !names.IsASCII(t.Fields[j].Name) {
				return bad("field or variant", t.Fields[j].Name)
			}
		}
	}
	for i := range services {
		if !names.IsASCII(services[i].Name) {
			return bad("service", services[i].Name)
		}
		for j := range services[i].Methods {
			if !names.IsASCII(services[i].Methods[j].Name) {
				return bad("method", services[i].Methods[j].Name)
			}
		}
	}
	for i := range sigils {
		if !names.IsASCII(sigils[i].Name) {
			return bad("sigil", sigils[i].Name)
		}
	}
	return nil
}

// validateDefs checks the definitions of one facet or interface: ASCII
// names, IDs (reserved, duplicate, retired), that every reference resolves
// within it (references inside tombstones excepted), sigil kinds, stream
// placement and End flags (sections 6.1-6.6).
func validateDefs(where string, types []TypeDef, services []Service, sigils []Sigil, retired []Retired) (*index, error) {
	if err := checkASCIINames(where, types, services, sigils); err != nil {
		return nil, err
	}
	ret := map[Retired]bool{}
	for _, r := range retired {
		if r.Space > SpaceSigil {
			return nil, errorf(CodeBadRetiredEntry, "%s: retired space %d", where, r.Space)
		}
		ret[r] = true
	}
	ix := &index{map[uint64]*TypeDef{}, map[uint64]*Sigil{}, map[uint64]*Method{}, map[uint64]*Service{}}
	for i := range types {
		t := &types[i]
		switch {
		case t.ID < FirstFreeTypeID:
			return nil, errorf(CodeReservedID, "%s: type %d is reserved", where, t.ID)
		case ix.types[t.ID] != nil:
			return nil, errorf(CodeDuplicateID, "%s: type %d", where, t.ID)
		case ret[Retired{SpaceType, t.ID}]:
			return nil, errorf(CodeRetiredIDReused, "%s: type %d is retired", where, t.ID)
		case t.Kind > KindAlias:
			return nil, errorf(CodeMalformed, "%s: type %d has unknown kind %d", where, t.ID, t.Kind)
		}
		ix.types[t.ID] = t
	}
	for i := range sigils {
		s := &sigils[i]
		switch {
		case s.ID < FirstFreeSigil:
			return nil, errorf(CodeReservedID, "%s: sigil %d is reserved", where, s.ID)
		case ix.sigils[s.ID] != nil:
			return nil, errorf(CodeDuplicateID, "%s: sigil %d", where, s.ID)
		case ret[Retired{SpaceSigil, s.ID}]:
			return nil, errorf(CodeRetiredIDReused, "%s: sigil %d is retired", where, s.ID)
		case s.Kind > SigilSymbol:
			return nil, errorf(CodeBadSigilKind, "%s: sigil %d has kind %d", where, s.ID, s.Kind)
		}
		ix.sigils[s.ID] = s
	}
	// Sigil names are unique within a facet or interface (6.5).
	sigilNames := make(map[string]bool, len(sigils))
	for i := range sigils {
		s := &sigils[i]
		if sigilNames[s.Name] {
			return nil, errorf(CodeDuplicateSigilName, "%s: sigil %d is named %q like another", where, s.ID, s.Name)
		}
		sigilNames[s.Name] = true
	}
	for i := range services {
		s := &services[i]
		if ix.svcs[s.ID] != nil {
			return nil, errorf(CodeDuplicateID, "%s: service %d", where, s.ID)
		}
		if ret[Retired{SpaceService, s.ID}] {
			return nil, errorf(CodeRetiredIDReused, "%s: service %d is retired", where, s.ID)
		}
		ix.svcs[s.ID] = s
		for j := range s.Methods {
			m := &s.Methods[j]
			if ix.methods[m.ID] != nil {
				return nil, errorf(CodeDuplicateID, "%s: method %d appears twice", where, m.ID)
			}
			if ret[Retired{SpaceMethod, m.ID}] {
				return nil, errorf(CodeRetiredIDReused, "%s: method %d is retired", where, m.ID)
			}
			ix.methods[m.ID] = m
		}
	}

	var checkRef func(r TypeRef, at string, top bool) error
	checkRef = func(r TypeRef, at string, top bool) error {
		switch r.Kind {
		case RefNamed:
			if r.ID >= FirstReservedBuiltinType && r.ID <= LastReservedBuiltinType {
				return errorf(CodeReservedTypeID, "%s references type %d; TypeIds 12-31 are reserved for later built-ins", at, r.ID)
			}
			if r.ID <= MaxBuiltinType || ix.types[r.ID] != nil {
				return nil
			}
			return errorf(CodeDanglingReference, "%s references type %d, not defined in this facet", at, r.ID)
		case RefList, RefOptional:
			return checkRef(*r.Elem, at, false)
		case RefMap:
			if err := checkRef(*r.Key, at, false); err != nil {
				return err
			}
			return checkRef(*r.Elem, at, false)
		case RefStream:
			if !top {
				return errorf(CodeStreamMisplaced, "%s: [3, T] is only allowed as a method's whole input or output", at)
			}
			return checkRef(*r.Elem, at, false)
		case RefByteStream:
			return nil
		}
		return errorf(CodeBadTypeRef, "%s", at)
	}
	enumOf := map[uint64]uint64{} // kind-0 sigil -> the enum listing it
	for i := range types {
		t := &types[i]
		at := fmt.Sprintf("%s: type %d", where, t.ID)
		switch t.Kind {
		case KindStruct, KindUnion:
			tags := map[uint64]bool{}
			for j := range t.Fields {
				f := &t.Fields[j]
				if tags[f.Tag] {
					return nil, errorf(CodeDuplicateID, "%s: tag %d appears twice", at, f.Tag)
				}
				tags[f.Tag] = true
				if f.Removed() {
					continue // tombstones are never encoded; their references are not checked
				}
				if err := checkRef(f.Type, at, false); err != nil {
					return nil, err
				}
			}
		case KindEnum:
			seen := map[uint64]bool{}
			for _, v := range t.Values {
				if seen[v] {
					return nil, errorf(CodeDuplicateID, "%s lists sigil %d twice", at, v)
				}
				seen[v] = true
				if s := ix.sigils[v]; s == nil || s.Kind != SigilEnumValue {
					return nil, errorf(CodeDanglingReference, "%s lists sigil %d, not a kind-0 sigil of this facet", at, v)
				}
				// A kind-0 sigil is a value of exactly one enum (6.5).
				if other, ok := enumOf[v]; ok {
					return nil, errorf(CodeSigilInTwoEnums, "%s lists sigil %d, a value of type %d too", at, v, other)
				}
				enumOf[v] = t.ID
			}
		case KindAlias:
			if err := checkRef(t.Target, at, false); err != nil {
				return nil, err
			}
		}
	}
	for i := range services {
		for j := range services[i].Methods {
			m := &services[i].Methods[j]
			at := fmt.Sprintf("%s: method %d", where, m.ID)
			if err := checkRef(m.Input, at, true); err != nil {
				return nil, err
			}
			if err := checkRef(m.Output, at, true); err != nil {
				return nil, err
			}
			for _, e := range m.Errors {
				if e < 32 {
					continue // core status codes need no schema entry
				}
				if s := ix.sigils[e]; s == nil || s.Kind != SigilError {
					return nil, errorf(CodeDanglingReference, "%s lists error %d, not a kind-1 sigil of this facet", at, e)
				}
			}
			if m.IsNotification() {
				if m.Output.Kind != RefNamed || m.Output.ID != TypeUnit {
					return nil, errorf(CodeInvalidNotification, "%s: a notification (flag 0x2) must have output unit", at)
				}
				if ReachesByteStream(m.Input, ix.types) {
					return nil, errorf(CodeInvalidNotification, "%s: a notification (flag 0x2) must not have [4] in its input", at)
				}
			}
			if NeedsEnd(m.Input, ix.types) && !m.InputEnds() {
				return nil, errorf(CodeMissingEndFlag, "%s: input is a stream or reaches [4], so flag 0x8 is required", at)
			}
			if NeedsEnd(m.Output, ix.types) && !m.OutputEnds() {
				return nil, errorf(CodeMissingEndFlag, "%s: output is a stream or reaches [4], so flag 0x10 is required", at)
			}
		}
	}
	return ix, nil
}

// NeedsEnd reports whether a method half with this type must be finished
// by End: it is a stream, or reaches [4] anywhere, following referenced
// types of the facet (tombstones excepted).
func NeedsEnd(r TypeRef, types map[uint64]*TypeDef) bool {
	return r.IsStream() || ReachesByteStream(r, types)
}

// ReachesByteStream reports whether [4] is reachable from r.
func ReachesByteStream(r TypeRef, types map[uint64]*TypeDef) bool {
	return reaches(r, types, map[uint64]bool{})
}

func reaches(r TypeRef, types map[uint64]*TypeDef, seen map[uint64]bool) bool {
	switch r.Kind {
	case RefByteStream:
		return true
	case RefMap:
		return reaches(*r.Key, types, seen) || reaches(*r.Elem, types, seen)
	case RefList, RefOptional, RefStream:
		return reaches(*r.Elem, types, seen)
	}
	t := types[r.ID]
	if t == nil || seen[r.ID] {
		return false
	}
	seen[r.ID] = true
	switch t.Kind {
	case KindStruct, KindUnion:
		for i := range t.Fields {
			if !t.Fields[i].Removed() && reaches(t.Fields[i].Type, types, seen) {
				return true
			}
		}
	case KindAlias:
		return reaches(t.Target, types, seen)
	}
	return false
}

// TypeIndex returns the facet's types by ID.
func (f *Facet) TypeIndex() map[uint64]*TypeDef { return buildIndex(f.Types, nil, nil).types }

// Validate checks one facet on its own: no floats, the facet-name grammar,
// and the definition rules of validateDefs. It does not check the facet ID
// rules, which depend on the schema (see Schema.Validate).
func (f *Facet) Validate() error {
	_, err := f.validate()
	return err
}

func (f *Facet) validate() (*index, error) {
	where := fmt.Sprintf("facet %d", f.ID)
	if annotationsHaveFloat(f.Annotations) || defsHaveFloat(f.Types, f.Services, f.Sigils) {
		return nil, errorf(CodeFloat, "%s contains a float", where)
	}
	if !names.IsFacetName(f.Name) {
		return nil, errorf(CodeInvalidName, "%s: facet name %q does not match the facet-name grammar", where, f.Name)
	}
	return validateDefs(where, f.Types, f.Services, f.Sigils, f.Retired)
}

// Validate checks an interface: its definitions, and that it contains
// exactly the types and sigils its services reach, not counting references
// inside tombstones (section 6.5).
func (i *Interface) Validate() error {
	if defsHaveFloat(i.Types, i.Services, i.Sigils) {
		return errorf(CodeFloat, "interface contains a float")
	}
	ix, err := validateDefs("interface", i.Types, i.Services, i.Sigils, nil)
	if err != nil {
		return err
	}
	seenT := map[uint64]bool{}
	seenS := map[uint64]bool{}
	var walk func(r TypeRef)
	walk = func(r TypeRef) {
		switch r.Kind {
		case RefMap:
			walk(*r.Key)
			walk(*r.Elem)
			return
		case RefList, RefOptional, RefStream:
			walk(*r.Elem)
			return
		case RefByteStream:
			return
		}
		t := ix.types[r.ID]
		if t == nil || seenT[r.ID] {
			return
		}
		seenT[r.ID] = true
		switch t.Kind {
		case KindStruct, KindUnion:
			for j := range t.Fields {
				if t.Fields[j].Removed() {
					continue // a tombstone reaches nothing
				}
				walk(t.Fields[j].Type)
			}
		case KindEnum:
			for _, v := range t.Values {
				seenS[v] = true
			}
		case KindAlias:
			walk(t.Target)
		}
	}
	for _, m := range ix.methods {
		walk(m.Input)
		walk(m.Output)
		for _, e := range m.Errors {
			seenS[e] = true
		}
	}
	for j := range i.Types {
		if !seenT[i.Types[j].ID] {
			return errorf(CodeInterfaceNotClosed, "type %d is not reached from the interface's services", i.Types[j].ID)
		}
	}
	for j := range i.Sigils {
		if !seenS[i.Sigils[j].ID] {
			return errorf(CodeInterfaceNotClosed, "sigil %d is not reached from the interface's services", i.Sigils[j].ID)
		}
	}
	return nil
}

// ValidateOptions select the schema-level checks.
type ValidateOptions struct {
	// AllowUnsorted skips the check that facets are listed sorted by ID,
	// for a schema that was canonicalised locally rather than received.
	AllowUnsorted bool
}

// Validate checks a received schema document (section 6.6, rule 3, and
// section 6.1): the format, no floats anywhere, facets listed sorted by ID,
// unique facet IDs and names, no reserved facet ID other than 1, facet 1
// matching sparrow.web by name and facet hash, and every facet valid.
func (s *Schema) Validate() error { return s.ValidateWith(ValidateOptions{}) }

// ValidateWith is Validate with options.
func (s *Schema) ValidateWith(o ValidateOptions) error {
	if s.Format != Format {
		return errorf(CodeUnsupportedFormat, "schema format %d, want %d", s.Format, Format)
	}
	if annotationsHaveFloat(s.Annotations) {
		return errorf(CodeFloat, "schema contains a float")
	}
	for i := range s.Facets {
		f := &s.Facets[i]
		if annotationsHaveFloat(f.Annotations) || defsHaveFloat(f.Types, f.Services, f.Sigils) {
			return errorf(CodeFloat, "schema contains a float")
		}
	}
	if !o.AllowUnsorted {
		for i := 1; i < len(s.Facets); i++ {
			if s.Facets[i-1].ID >= s.Facets[i].ID {
				if s.Facets[i-1].ID == s.Facets[i].ID {
					return errorf(CodeDuplicateFacetID, "facet %d", s.Facets[i].ID)
				}
				return errorf(CodeFacetsNotSorted, "facet %d listed after facet %d", s.Facets[i].ID, s.Facets[i-1].ID)
			}
		}
	}
	ids := map[uint64]bool{}
	nameSeen := map[string]bool{}
	for i := range s.Facets {
		f := &s.Facets[i]
		if ids[f.ID] {
			return errorf(CodeDuplicateFacetID, "facet %d", f.ID)
		}
		if nameSeen[f.Name] {
			return errorf(CodeDuplicateFacetName, "%q", f.Name)
		}
		ids[f.ID], nameSeen[f.Name] = true, true
		if f.ID < FirstFreeFacetID && f.ID != WebFacetID {
			return errorf(CodeReservedFacetID, "facet %d (%q): IDs 0 and 2-15 MUST NOT appear", f.ID, f.Name)
		}
		if f.ID == WebFacetID {
			if ok, err := IsWebFacet(f); err != nil {
				return err
			} else if !ok {
				return errorf(CodeFacet1Mismatch, "facet 1 does not match the definition of sparrow.web by name and facet hash")
			}
		}
		if err := f.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// IsWebFacet reports whether f matches the built-in sparrow.web facet by
// facet hash and is named sparrow.web.
func IsWebFacet(f *Facet) (bool, error) {
	h, err := f.Hash()
	if err != nil {
		return false, err
	}
	return bytes.Equal(h, WebFacetHash()) && f.Name == WebFacetName, nil
}
