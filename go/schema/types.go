// Package schema implements the Sparrow facet model (section 6): Go types
// for schemas, facets, type definitions, services, methods, sigils and
// interfaces; their CBOR encoding; canonical form and hashes; validation;
// the compatibility check between versions of a facet (6.7); interface
// conformance on wire shapes (6.5); deltas (6.6); and the built-in facet 1,
// sparrow.web (9.4).
package schema

import (
	"github.com/aiviarium/sparrow/go/cbor"
)

// Format is the schema document format this package implements.
const Format = 2

// Built-in TypeIds (section 6.3).
const (
	TypeUnit      uint64 = 0
	TypeBool      uint64 = 1
	TypeInt       uint64 = 2
	TypeUint      uint64 = 3
	TypeFloat32   uint64 = 4
	TypeFloat64   uint64 = 5
	TypeString    uint64 = 6
	TypeBytes     uint64 = 7
	TypeTimestamp uint64 = 8
	TypeUUID      uint64 = 9
	TypeDynamic   uint64 = 10
	TypeSymbol    uint64 = 11

	// MaxBuiltinType is the highest built-in TypeId this revision defines.
	MaxBuiltinType = TypeSymbol
	// FirstReservedBuiltinType and LastReservedBuiltinType bound the TypeIds
	// reserved for built-ins of later core versions (section 6.4): a schema
	// that uses them is invalid under this version.
	FirstReservedBuiltinType uint64 = 12
	LastReservedBuiltinType  uint64 = 31
	// FirstFreeTypeID is the first TypeId a facet may define.
	FirstFreeTypeID uint64 = 64
	// FirstFreeSigil is the first sigil a facet may define.
	FirstFreeSigil uint64 = 64
	// FirstFreeFacetID is the first facet ID outside the reserved range.
	FirstFreeFacetID uint64 = 16
	// WebFacetID is the ID of the built-in facet sparrow.web.
	WebFacetID uint64 = 1
)

// TypeKind is the kind of a user-defined type.
type TypeKind uint64

const (
	KindStruct TypeKind = 0
	KindEnum   TypeKind = 1
	KindUnion  TypeKind = 2
	KindAlias  TypeKind = 3
)

func (k TypeKind) String() string {
	switch k {
	case KindStruct:
		return "struct"
	case KindEnum:
		return "enum"
	case KindUnion:
		return "union"
	case KindAlias:
		return "alias"
	}
	return "unknown"
}

// Struct flags.
const StructSparse uint64 = 0x1

// Field and variant flags.
const (
	FieldOptional   uint64 = 0x1
	FieldDeprecated uint64 = 0x2 // hint only
	FieldRemoved    uint64 = 0x4 // tombstone
)

// Method flags (section 6.4).
const (
	MethodIdempotent   uint64 = 0x1 // hint
	MethodNotification uint64 = 0x2
	MethodShared       uint64 = 0x4 // hint
	MethodInputEnd     uint64 = 0x8
	MethodOutputEnd    uint64 = 0x10

	// methodHintFlags are cleared in wire shapes and may change freely.
	methodHintFlags = MethodIdempotent | MethodShared
	// methodFixedFlags never change once a method is defined.
	methodFixedFlags = MethodNotification | MethodInputEnd | MethodOutputEnd
)

// Sigil kinds.
const (
	SigilEnumValue uint64 = 0
	SigilError     uint64 = 1
	SigilSymbol    uint64 = 2
)

// Space names an ID space in `retired` and in conformance mismatches.
type Space uint64

const (
	SpaceType    Space = 0
	SpaceService Space = 1
	SpaceMethod  Space = 2
	SpaceSigil   Space = 3
)

func (s Space) String() string {
	switch s {
	case SpaceType:
		return "type"
	case SpaceService:
		return "service"
	case SpaceMethod:
		return "method"
	case SpaceSigil:
		return "sigil"
	}
	return "space?"
}

// Annotations is profile-defined metadata, {* tstr => any}. Values are raw
// CBOR; unknown keys must be ignored. A nil Annotations encodes as {}.
type Annotations map[string]cbor.Raw

// RefKind is the form of a type reference.
type RefKind uint8

const (
	RefNamed      RefKind = iota // uint: a TypeId
	RefList                      // [0, T]
	RefMap                       // [1, K, V]
	RefOptional                  // [2, T]
	RefStream                    // [3, T], only as a method's whole input or output
	RefByteStream                // [4]
)

// TypeRef is a type reference (section 6.3).
type TypeRef struct {
	Kind RefKind
	ID   uint64   // RefNamed
	Elem *TypeRef // element for list/optional/stream, value for map
	Key  *TypeRef // RefMap
}

// Named returns a reference to a TypeId.
func Named(id uint64) TypeRef { return TypeRef{Kind: RefNamed, ID: id} }

// List returns [0, t].
func List(t TypeRef) TypeRef { return TypeRef{Kind: RefList, Elem: &t} }

// MapOf returns [1, k, v].
func MapOf(k, v TypeRef) TypeRef { return TypeRef{Kind: RefMap, Key: &k, Elem: &v} }

// Optional returns [2, t].
func Optional(t TypeRef) TypeRef { return TypeRef{Kind: RefOptional, Elem: &t} }

// Stream returns [3, t].
func Stream(t TypeRef) TypeRef { return TypeRef{Kind: RefStream, Elem: &t} }

// ByteStream returns [4].
func ByteStream() TypeRef { return TypeRef{Kind: RefByteStream} }

// IsStream reports whether r is [3, T].
func (r TypeRef) IsStream() bool { return r.Kind == RefStream }

// Equal reports whether two references are identical.
func (r TypeRef) Equal(o TypeRef) bool {
	if r.Kind != o.Kind || r.ID != o.ID {
		return false
	}
	if (r.Elem == nil) != (o.Elem == nil) || (r.Key == nil) != (o.Key == nil) {
		return false
	}
	if r.Elem != nil && !r.Elem.Equal(*o.Elem) {
		return false
	}
	return r.Key == nil || r.Key.Equal(*o.Key)
}

// Field is a struct field or a union variant:
// [tag, name, type, flags, annotations].
type Field struct {
	Tag         uint64
	Name        string
	Type        TypeRef
	Flags       uint64
	Annotations Annotations
}

// Removed reports whether the field is a tombstone.
func (f *Field) Removed() bool { return f.Flags&FieldRemoved != 0 }

// Optional reports whether the field is optional.
func (f *Field) Optional() bool { return f.Flags&FieldOptional != 0 }

// TypeDef is a user-defined type:
//
//	[0, id, name, fields, flags, annotations]  struct
//	[1, id, name, values, annotations]         enum
//	[2, id, name, variants, annotations]       union
//	[3, id, name, target, annotations]         alias
type TypeDef struct {
	Kind        TypeKind
	ID          uint64
	Name        string
	Fields      []Field  // struct fields or union variants
	Flags       uint64   // struct only
	Values      []uint64 // enum: sigil IDs
	Target      TypeRef  // alias
	Annotations Annotations
}

// Sparse reports whether a struct is sparse.
func (t *TypeDef) Sparse() bool { return t.Kind == KindStruct && t.Flags&StructSparse != 0 }

// Field returns the field or variant with a tag.
func (t *TypeDef) Field(tag uint64) *Field {
	for i := range t.Fields {
		if t.Fields[i].Tag == tag {
			return &t.Fields[i]
		}
	}
	return nil
}

// Method is [id, name, input, output, errors, flags, annotations].
type Method struct {
	ID          uint64
	Name        string
	Input       TypeRef
	Output      TypeRef
	Errors      []uint64
	Flags       uint64
	Annotations Annotations
}

// InputEnds reports flag 0x8: the caller's half is finished by End.
func (m *Method) InputEnds() bool { return m.Flags&MethodInputEnd != 0 }

// OutputEnds reports flag 0x10: the callee's half is finished by End.
func (m *Method) OutputEnds() bool { return m.Flags&MethodOutputEnd != 0 }

// IsNotification reports flag 0x2.
func (m *Method) IsNotification() bool { return m.Flags&MethodNotification != 0 }

// Service is [id, name, methods, annotations].
type Service struct {
	ID          uint64
	Name        string
	Methods     []Method
	Annotations Annotations
}

// Sigil is [id, name, kind, annotations].
type Sigil struct {
	ID          uint64
	Name        string
	Kind        uint64
	Annotations Annotations
}

// Retired is one entry of a facet's retired list: [space, id].
type Retired struct {
	Space Space
	ID    uint64
}

// Facet is a self-contained unit of a schema:
// [id, name, version, types, services, sigils, implements, retired, annotations].
type Facet struct {
	ID          uint64
	Name        string
	Version     string
	Types       []TypeDef
	Services    []Service
	Sigils      []Sigil
	Implements  []byte // interface hash, nil = null
	Retired     []Retired
	Annotations Annotations
}

// Type returns the type with an ID, or nil.
func (f *Facet) Type(id uint64) *TypeDef {
	for i := range f.Types {
		if f.Types[i].ID == id {
			return &f.Types[i]
		}
	}
	return nil
}

// Sigil returns the sigil with an ID, or nil.
func (f *Facet) Sigil(id uint64) *Sigil {
	for i := range f.Sigils {
		if f.Sigils[i].ID == id {
			return &f.Sigils[i]
		}
	}
	return nil
}

// Service returns the service with an ID, or nil.
func (f *Facet) Service(id uint64) *Service {
	for i := range f.Services {
		if f.Services[i].ID == id {
			return &f.Services[i]
		}
	}
	return nil
}

// Method returns the method with an ID, searching every service, and the
// service holding it; nil if absent. MethodIds are unique within a facet.
func (f *Facet) Method(id uint64) (*Method, *Service) {
	for i := range f.Services {
		s := &f.Services[i]
		for j := range s.Methods {
			if s.Methods[j].ID == id {
				return &s.Methods[j], s
			}
		}
	}
	return nil, nil
}

// IsRetired reports whether an ID is in the facet's retired list.
func (f *Facet) IsRetired(space Space, id uint64) bool {
	for _, r := range f.Retired {
		if r.Space == space && r.ID == id {
			return true
		}
	}
	return false
}

// Interface is a contract several facets can implement:
// [name, version, types, services, sigils].
type Interface struct {
	Name     string
	Version  string
	Types    []TypeDef
	Services []Service
	Sigils   []Sigil
}

// Schema is a peer's schema document:
// [format, name, version, facets, annotations].
type Schema struct {
	Format      uint64
	Name        string
	Version     string
	Facets      []Facet
	Annotations Annotations
}

// Facet returns the facet with an ID, or nil.
func (s *Schema) Facet(id uint64) *Facet {
	for i := range s.Facets {
		if s.Facets[i].ID == id {
			return &s.Facets[i]
		}
	}
	return nil
}

// DeltaOpKind selects a delta operation.
type DeltaOpKind uint64

const (
	OpPut         DeltaOpKind = 0 // [0, facet]: add, or replace the facet with the same ID
	OpRemove      DeltaOpKind = 1 // [1, facet_id]
	OpAnnotations DeltaOpKind = 2 // [2, annotations]
	OpVersion     DeltaOpKind = 3 // [3, version]
)

// DeltaOp is one delta operation.
type DeltaOp struct {
	Op          DeltaOpKind
	Facet       *Facet      // OpPut
	FacetID     uint64      // OpRemove
	Annotations Annotations // OpAnnotations
	Version     string      // OpVersion
}

// Delta is a list of operations applied in order.
type Delta []DeltaOp
