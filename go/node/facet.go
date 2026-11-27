// Package node is a library for writing Sparrow nodes and clients: define
// facets with a builder, register handlers, connect to a hub (WebTransport,
// WebSocket, or the standard input and output of a process the hub
// started), call other facets by name, and publish or update facets while
// connected. It sits on top of package session.
package node

import (
	"context"
	"errors"
	"fmt"

	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
)

// Type references for the built-in types (6.3) and constructors.
var (
	Unit      = schema.Named(schema.TypeUnit)
	Bool      = schema.Named(schema.TypeBool)
	Int       = schema.Named(schema.TypeInt)
	Uint      = schema.Named(schema.TypeUint)
	Float32   = schema.Named(schema.TypeFloat32)
	Float64   = schema.Named(schema.TypeFloat64)
	String    = schema.Named(schema.TypeString)
	Bytes     = schema.Named(schema.TypeBytes)
	Timestamp = schema.Named(schema.TypeTimestamp)
	UUID      = schema.Named(schema.TypeUUID)
	Dynamic   = schema.Named(schema.TypeDynamic)
	Symbol    = schema.Named(schema.TypeSymbol)
)

// List returns [0, t].
func List(t schema.TypeRef) schema.TypeRef { return schema.List(t) }

// Map returns [1, k, v].
func Map(k, v schema.TypeRef) schema.TypeRef { return schema.MapOf(k, v) }

// Opt returns [2, t].
func Opt(t schema.TypeRef) schema.TypeRef { return schema.Optional(t) }

// Stream returns [3, t], for a method's whole input or output.
func Stream(t schema.TypeRef) schema.TypeRef { return schema.Stream(t) }

// ByteStream returns [4].
func ByteStream() schema.TypeRef { return schema.ByteStream() }

// FieldDef is a struct field or union variant for the builder.
type FieldDef struct {
	Name  string
	Type  schema.TypeRef
	Flags uint64
	Tag   *uint64
}

// Field returns a required field (tags are assigned in order unless set).
func Field(name string, t schema.TypeRef) FieldDef { return FieldDef{Name: name, Type: t} }

// OptionalField returns an optional field.
func OptionalField(name string, t schema.TypeRef) FieldDef {
	return FieldDef{Name: name, Type: t, Flags: schema.FieldOptional}
}

// WithTag fixes the field's tag.
func (f FieldDef) WithTag(tag uint64) FieldDef { f.Tag = &tag; return f }

// MethodOption tunes a method.
type MethodOption func(*schema.Method)

// Idempotent sets flag 0x1.
func Idempotent() MethodOption { return func(m *schema.Method) { m.Flags |= schema.MethodIdempotent } }

// Shared sets flag 0x4: the method's calls run on the shared lane.
func Shared() MethodOption { return func(m *schema.Method) { m.Flags |= schema.MethodShared } }

// MethodID fixes the method's ID.
func MethodID(id uint64) MethodOption { return func(m *schema.Method) { m.ID = id } }

// Errors lists extra error sigils the method may return.
func Errors(sigils ...uint64) MethodOption {
	return func(m *schema.Method) { m.Errors = append(m.Errors, sigils...) }
}

// Annotate sets a method annotation (raw CBOR value).
func Annotate(key string, v []byte) MethodOption {
	return func(m *schema.Method) { m.Annotations[key] = v }
}

// FacetBuilder builds a facet and its handlers. IDs are assigned in order
// (types and sigils from 64, services and methods from 0) unless fixed;
// keep the order stable, or fix the IDs, so they stay stable across
// restarts (6.6).
type FacetBuilder struct {
	f         schema.Facet
	id        uint64
	nextType  uint64
	nextSigil uint64
	nextSvc   uint64
	nextMeth  uint64
	handlers  map[uint64]session.Handler
	err       error
}

// NewFacet starts a facet. Its name must follow the facet-name grammar and,
// on a hub, start with the node ID (10.2).
func NewFacet(name, version string) *FacetBuilder {
	return &FacetBuilder{
		f: schema.Facet{Name: name, Version: version, Types: []schema.TypeDef{}, Services: []schema.Service{},
			Sigils: []schema.Sigil{}, Retired: []schema.Retired{}, Annotations: schema.Annotations{}},
		nextType: schema.FirstFreeTypeID, nextSigil: schema.FirstFreeSigil, handlers: map[uint64]session.Handler{},
	}
}

// ID fixes the facet ID (16 and up); otherwise the node assigns one.
func (b *FacetBuilder) ID(id uint64) *FacetBuilder { b.id = id; return b }

// Annotation sets a facet annotation (raw CBOR value).
func (b *FacetBuilder) Annotation(key string, v []byte) *FacetBuilder {
	b.f.Annotations[key] = v
	return b
}

// Retire records retired IDs (for a facet that removed definitions).
func (b *FacetBuilder) Retire(space schema.Space, ids ...uint64) *FacetBuilder {
	for _, id := range ids {
		b.f.Retired = append(b.f.Retired, schema.Retired{Space: space, ID: id})
	}
	return b
}

func (b *FacetBuilder) typeID() uint64 { id := b.nextType; b.nextType++; return id }

func fields(defs []FieldDef) []schema.Field {
	out := make([]schema.Field, 0, len(defs))
	next := uint64(0)
	for _, d := range defs {
		tag := next
		if d.Tag != nil {
			tag = *d.Tag
		}
		next = tag + 1
		out = append(out, schema.Field{Tag: tag, Name: d.Name, Type: d.Type, Flags: d.Flags, Annotations: schema.Annotations{}})
	}
	return out
}

// Struct defines a struct type and returns a reference to it.
func (b *FacetBuilder) Struct(name string, f ...FieldDef) schema.TypeRef {
	id := b.typeID()
	b.f.Types = append(b.f.Types, schema.TypeDef{Kind: schema.KindStruct, ID: id, Name: name, Fields: fields(f), Annotations: schema.Annotations{}})
	return schema.Named(id)
}

// SparseStruct defines a sparse struct (encoded as a map).
func (b *FacetBuilder) SparseStruct(name string, f ...FieldDef) schema.TypeRef {
	id := b.typeID()
	b.f.Types = append(b.f.Types, schema.TypeDef{Kind: schema.KindStruct, ID: id, Name: name, Fields: fields(f),
		Flags: schema.StructSparse, Annotations: schema.Annotations{}})
	return schema.Named(id)
}

// Union defines a union type.
func (b *FacetBuilder) Union(name string, variants ...FieldDef) schema.TypeRef {
	id := b.typeID()
	b.f.Types = append(b.f.Types, schema.TypeDef{Kind: schema.KindUnion, ID: id, Name: name, Fields: fields(variants), Annotations: schema.Annotations{}})
	return schema.Named(id)
}

// Alias defines a named alias, needed to send a composite as dynamic.
func (b *FacetBuilder) Alias(name string, target schema.TypeRef) schema.TypeRef {
	id := b.typeID()
	b.f.Types = append(b.f.Types, schema.TypeDef{Kind: schema.KindAlias, ID: id, Name: name, Target: target, Annotations: schema.Annotations{}})
	return schema.Named(id)
}

func (b *FacetBuilder) sigil(name string, kind uint64) uint64 {
	id := b.nextSigil
	b.nextSigil++
	b.f.Sigils = append(b.f.Sigils, schema.Sigil{ID: id, Name: name, Kind: kind, Annotations: schema.Annotations{}})
	return id
}

// Enum defines an enum; it returns the type and the sigil of each value.
func (b *FacetBuilder) Enum(name string, values ...string) (schema.TypeRef, map[string]uint64) {
	m := map[string]uint64{}
	ids := make([]uint64, 0, len(values))
	for _, v := range values {
		s := b.sigil(v, schema.SigilEnumValue)
		m[v] = s
		ids = append(ids, s)
	}
	id := b.typeID()
	b.f.Types = append(b.f.Types, schema.TypeDef{Kind: schema.KindEnum, ID: id, Name: name, Values: ids, Annotations: schema.Annotations{}})
	return schema.Named(id), m
}

// ErrorCode defines an application error code (a kind-1 sigil); return it
// from a handler with &session.Error{Code: code}.
func (b *FacetBuilder) ErrorCode(name string) status.Code {
	return status.Code(b.sigil(name, schema.SigilError))
}

// Symbol defines an interned symbol (kind-2 sigil).
func (b *FacetBuilder) Symbol(name string) uint64 { return b.sigil(name, schema.SigilSymbol) }

// Service starts a service of the facet.
func (b *FacetBuilder) Service(name string) *ServiceBuilder {
	id := b.nextSvc
	b.nextSvc++
	b.f.Services = append(b.f.Services, schema.Service{ID: id, Name: name, Methods: []schema.Method{}, Annotations: schema.Annotations{}})
	return &ServiceBuilder{b: b, idx: len(b.f.Services) - 1}
}

// ServiceBuilder adds methods to a service.
type ServiceBuilder struct {
	b   *FacetBuilder
	idx int
}

// Method adds a method with a typed handler (see session.HandlerFunc for
// how its result finishes the call). Flags 0x8 and 0x10 are set from the
// types (a stream, or [4] anywhere); a nil handler leaves the method
// unimplemented. It returns the method ID.
func (s *ServiceBuilder) Method(name string, in, out schema.TypeRef, h session.HandlerFunc, opts ...MethodOption) uint64 {
	var hh session.Handler
	if h != nil {
		hh = h
	}
	return s.add(name, in, out, 0, hh, opts)
}

// RawMethod adds a method served by a raw handler.
func (s *ServiceBuilder) RawMethod(name string, in, out schema.TypeRef, h session.Handler, opts ...MethodOption) uint64 {
	return s.add(name, in, out, 0, h, opts)
}

// Notification adds a notification method (flag 0x2, output unit).
func (s *ServiceBuilder) Notification(name string, in schema.TypeRef, h func(ctx context.Context, call *session.ServerCall) error, opts ...MethodOption) uint64 {
	var hh session.Handler
	if h != nil {
		hh = session.HandlerFunc(func(ctx context.Context, c *session.ServerCall) (any, error) { return nil, h(ctx, c) })
	}
	return s.add(name, in, Unit, schema.MethodNotification, hh, opts)
}

func (s *ServiceBuilder) add(name string, in, out schema.TypeRef, flags uint64, h session.Handler, opts []MethodOption) uint64 {
	b := s.b
	m := schema.Method{ID: b.nextMeth, Name: name, Input: in, Output: out, Errors: []uint64{}, Flags: flags, Annotations: schema.Annotations{}}
	for _, o := range opts {
		o(&m)
	}
	if m.ID >= b.nextMeth {
		b.nextMeth = m.ID + 1
	}
	types := map[uint64]*schema.TypeDef{}
	for i := range b.f.Types {
		types[b.f.Types[i].ID] = &b.f.Types[i]
	}
	if schema.NeedsEnd(in, types) {
		m.Flags |= schema.MethodInputEnd
	}
	if schema.NeedsEnd(out, types) {
		m.Flags |= schema.MethodOutputEnd
	}
	svc := &b.f.Services[s.idx]
	svc.Methods = append(svc.Methods, m)
	if h != nil {
		b.handlers[m.ID] = h
	}
	return m.ID
}

// Facet is a built facet with its handlers.
type Facet struct {
	Def      schema.Facet
	handlers map[uint64]session.Handler
	fixedID  bool
}

// Build validates the facet.
func (b *FacetBuilder) Build() (*Facet, error) {
	if b.err != nil {
		return nil, b.err
	}
	f := b.f.Clone()
	f.ID = b.id
	probe := f.Clone()
	if probe.ID == 0 {
		probe.ID = schema.FirstFreeFacetID
	}
	if err := probe.Validate(); err != nil {
		return nil, fmt.Errorf("node: facet %q: %w", f.Name, err)
	}
	h := map[uint64]session.Handler{}
	for k, v := range b.handlers {
		h[k] = v
	}
	return &Facet{Def: *f, handlers: h, fixedID: b.id != 0}, nil
}

// MustBuild is Build that panics on error, for static definitions.
func (b *FacetBuilder) MustBuild() *Facet {
	f, err := b.Build()
	if err != nil {
		panic(err)
	}
	return f
}

// MethodByName finds a method of a facet by name ("method" or
// "Service.method").
func MethodByName(f *schema.Facet, name string) (*schema.Method, error) {
	var found *schema.Method
	for i := range f.Services {
		svc := &f.Services[i]
		for j := range svc.Methods {
			m := &svc.Methods[j]
			if m.Name == name || svc.Name+"."+m.Name == name {
				if found != nil && m.Name == name {
					return nil, fmt.Errorf("node: method name %q is ambiguous in facet %q", name, f.Name)
				}
				found = m
			}
		}
	}
	if found == nil {
		return nil, &session.Error{Code: status.Unimplemented, Message: fmt.Sprintf("facet %q has no method %q", f.Name, name)}
	}
	return found, nil
}

var errNotConnected = errors.New("node: not connected")
