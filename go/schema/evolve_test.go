package schema

import (
	"bytes"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

// TestCompatible walks the table of section 6.7 row by row.
func TestCompatible(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *Facet)
		want   Code
	}{
		// allowed
		{"no change", func(f *Facet) {}, ""},
		{"add an optional field", func(f *Facet) {
			f.Types[0].Fields = append(f.Types[0].Fields, Field{Tag: 5, Name: "x", Type: Named(TypeBool), Flags: FieldOptional})
		}, ""},
		{"add a field born as a tombstone", func(f *Facet) {
			f.Types[0].Fields = append(f.Types[0].Fields, Field{Tag: 5, Name: "x", Type: Named(TypeBool), Flags: FieldRemoved})
		}, ""},
		{"add an enum value", func(f *Facet) {
			f.Sigils = append(f.Sigils, Sigil{ID: 72, Name: "Color.blue"})
			f.Types[2].Values = append(f.Types[2].Values, 72)
		}, ""},
		{"add a union variant", func(f *Facet) {
			f.Types[3].Fields = append(f.Types[3].Fields, Field{Tag: 2, Name: "cleared", Type: Named(TypeUnit)})
		}, ""},
		{"add a type, service, method and sigil", func(f *Facet) {
			f.Types = append(f.Types, TypeDef{Kind: KindAlias, ID: 75, Name: "N", Target: Named(TypeUint)})
			f.Services = append(f.Services, Service{ID: 2, Name: "New", Methods: []Method{{ID: 130, Name: "m", Input: Named(75), Output: Named(0)}}})
			f.Sigils = append(f.Sigils, Sigil{ID: 90, Name: "s", Kind: SigilSymbol})
		}, ""},
		{"move a method to another service", func(f *Facet) {
			m := f.Services[0].Methods[0]
			f.Services[0].Methods = f.Services[0].Methods[1:]
			f.Services[1].Methods = append(f.Services[1].Methods, m)
		}, ""},
		{"change annotations everywhere", func(f *Facet) {
			a := Annotations{"doc": cbor.AppendText(nil, "new")}
			f.Annotations, f.Types[0].Annotations, f.Types[0].Fields[0].Annotations = a, a, a
			f.Services[0].Annotations, f.Services[0].Methods[0].Annotations, f.Sigils[0].Annotations = a, a, a
		}, ""},
		{"rename everything inside", func(f *Facet) {
			f.Types[0].Name, f.Types[0].Fields[0].Name, f.Services[0].Name = "N2", "id2", "S2"
			f.Services[0].Methods[0].Name, f.Sigils[0].Name = "m2", "s2"
		}, ""},
		{"deprecate a field, change hint flags", func(f *Facet) {
			f.Types[0].Fields[1].Flags |= FieldDeprecated
			f.Services[0].Methods[0].Flags = MethodShared
			f.Services[0].Methods[1].Flags = MethodIdempotent
		}, ""},
		{"remove a type, service, method and sigil into retired", func(f *Facet) {
			f.Types = f.Types[:6]       // drop alias 72
			f.Services = f.Services[:1] // drop Admin and its method 110
			f.Sigils = f.Sigils[:3]     // drop symbol 80
			f.Retired = append(f.Retired, Retired{SpaceType, 72}, Retired{SpaceService, 1}, Retired{SpaceMethod, 110}, Retired{SpaceSigil, 80})
		}, ""},
		{"remove an optional field", func(f *Facet) { f.Types[0].Fields[2].Flags |= FieldRemoved }, ""},
		{"remove a variant", func(f *Facet) { f.Types[3].Fields[1].Flags |= FieldRemoved }, ""},
		{"change a method's errors", func(f *Facet) { f.Services[0].Methods[1].Errors = nil }, ""},
		{"minor version bump", func(f *Facet) { f.Version = "1.7.0" }, ""},
		{"change implements", func(f *Facet) { f.Implements = []byte{1} }, ""},
		{"set End flags on a plain method", func(f *Facet) {}, ""},
		// forbidden
		{"add a required field", func(f *Facet) {
			f.Types[0].Fields = append(f.Types[0].Fields, Field{Tag: 5, Name: "x", Type: Named(TypeBool)})
		}, CodeIncompatibleChange},
		{"remove an enum value", func(f *Facet) { f.Types[2].Values = []uint64{70} }, CodeIncompatibleChange},
		{"remove a required field", func(f *Facet) { f.Types[0].Fields[1].Flags |= FieldRemoved }, CodeIncompatibleChange},
		{"drop a field without a tombstone", func(f *Facet) { f.Types[0].Fields = f.Types[0].Fields[:4] }, CodeIncompatibleChange},
		{"drop a tombstone", func(f *Facet) {
			f.Types[0].Fields = append(f.Types[0].Fields[:3:3], f.Types[0].Fields[4])
		}, CodeIncompatibleChange},
		{"revive a tombstone", func(f *Facet) { f.Types[0].Fields[3].Flags = FieldOptional; f.Types[0].Fields[3].Type = Named(6) }, CodeIncompatibleChange},
		{"change a definition's kind", func(f *Facet) {
			f.Types[6] = TypeDef{Kind: KindStruct, ID: 72, Name: "Tags", Fields: []Field{}}
		}, CodeIncompatibleChange},
		{"change the sparse flag", func(f *Facet) { f.Types[1].Flags = 0 }, CodeIncompatibleChange},
		{"change an alias target", func(f *Facet) { f.Types[6].Target = List(Named(TypeBytes)) }, CodeIncompatibleChange},
		{"change a field's type", func(f *Facet) { f.Types[0].Fields[1].Type = Named(TypeBytes) }, CodeIncompatibleChange},
		{"change a variant's type", func(f *Facet) { f.Types[3].Fields[1].Type = Named(TypeString) }, CodeIncompatibleChange},
		{"change a sigil's kind", func(f *Facet) { f.Sigils[3].Kind = SigilError }, CodeIncompatibleChange},
		{"make an optional field required", func(f *Facet) { f.Types[0].Fields[2].Flags = 0 }, CodeIncompatibleChange},
		{"make a required field optional", func(f *Facet) { f.Types[0].Fields[1].Flags |= FieldOptional }, CodeIncompatibleChange},
		{"change a field's type as it becomes a tombstone", func(f *Facet) {
			f.Types[0].Fields[2].Flags |= FieldRemoved
			f.Types[0].Fields[2].Type = Named(TypeBytes)
		}, CodeIncompatibleChange},
		{"change a tombstone's type", func(f *Facet) { f.Types[0].Fields[3].Type = Named(TypeString) }, CodeIncompatibleChange},
		{"change a tombstone's flags", func(f *Facet) { f.Types[0].Fields[3].Flags |= FieldDeprecated }, CodeIncompatibleChange},
		{"rename a tombstone", func(f *Facet) { f.Types[0].Fields[3].Name = "oldLegacy" }, ""},
		{"change a variant's type as it becomes a tombstone", func(f *Facet) {
			f.Types[3].Fields[1].Flags |= FieldRemoved
			f.Types[3].Fields[1].Type = Named(TypeString)
		}, CodeIncompatibleChange},
		{"change a method's input", func(f *Facet) { f.Services[0].Methods[0].Input = Named(TypeString) }, CodeIncompatibleChange},
		{"change a method's output", func(f *Facet) { f.Services[0].Methods[0].Output = Optional(Named(64)) }, CodeIncompatibleChange},
		{"change flag 0x2", func(f *Facet) { f.Services[0].Methods[5].Flags = 0 }, CodeIncompatibleChange},
		{"change flag 0x8", func(f *Facet) { f.Services[0].Methods[0].Flags |= MethodInputEnd }, CodeIncompatibleChange},
		{"change flag 0x10", func(f *Facet) { f.Services[0].Methods[0].Flags |= MethodOutputEnd }, CodeIncompatibleChange},
		{"make [4] reachable from a half without End", func(f *Facet) {
			f.Types[0].Fields = append(f.Types[0].Fields, Field{Tag: 5, Name: "blob", Type: ByteStream(), Flags: FieldOptional})
		}, CodeMissingEndFlag},
		{"change the major version", func(f *Facet) { f.Version = "2.0.0" }, CodeMajorVersionChanged},
		{"rename the facet", func(f *Facet) { f.Name = "acme.memos" }, CodeFacetRenamed},
		{"remove a type without retiring it", func(f *Facet) { f.Types = f.Types[:6] }, CodeDroppedIDNotRetired},
		{"remove a service without retiring it", func(f *Facet) {
			f.Services = f.Services[:1]
			f.Retired = append(f.Retired, Retired{SpaceMethod, 110})
		}, CodeDroppedIDNotRetired},
		{"remove a method without retiring it", func(f *Facet) { f.Services[1].Methods = nil }, CodeDroppedIDNotRetired},
		{"remove a sigil without retiring it", func(f *Facet) { f.Sigils = f.Sigils[:3] }, CodeDroppedIDNotRetired},
		{"shrink retired", func(f *Facet) { f.Retired = f.Retired[:1] }, CodeRetiredNotCarriedOver},
		{"invalid new version", func(f *Facet) { f.Types[0].ID = 1 }, CodeReservedID},
	}
	old := base()
	for _, tc := range tests {
		nw := base()
		tc.mutate(nw)
		if got := code(Compatible(old, nw)); got != tc.want {
			t.Errorf("%s: %v, want %q", tc.name, Compatible(old, nw), tc.want)
		}
	}
	// major version 0 counts too
	a, b := base(), base()
	a.Version, b.Version = "0.1.0", "0.9.0"
	if err := Compatible(a, b); err != nil {
		t.Errorf("0.1.0 -> 0.9.0: %v", err)
	}
	b.Version = "1.0.0"
	if code(Compatible(a, b)) != CodeMajorVersionChanged {
		t.Error("0.x -> 1.0.0 allowed")
	}
}

func iface() *Interface {
	return &Interface{Name: "acme.Renderer", Version: "1.0.0",
		Types: []TypeDef{
			{Kind: KindStruct, ID: 64, Name: "Spec", Fields: []Field{
				{Tag: 0, Name: "kind", Type: Named(65)},
				{Tag: 1, Name: "title", Type: Optional(Named(TypeString)), Flags: FieldOptional},
			}},
			{Kind: KindEnum, ID: 65, Name: "Kind", Values: []uint64{64, 65}},
		},
		Services: []Service{{ID: 0, Name: "Renderer", Methods: []Method{
			{ID: 0, Name: "render", Input: Named(64), Output: Named(TypeBytes), Errors: []uint64{66, 3}, Flags: MethodIdempotent},
		}}},
		Sigils: []Sigil{{ID: 64, Name: "line"}, {ID: 65, Name: "bar"}, {ID: 66, Name: "unsupported", Kind: SigilError}},
	}
}

func implementing() *Facet {
	i := iface()
	return &Facet{ID: 20, Name: "acme.charts", Version: "3.0.0", Types: i.Types, Services: i.Services, Sigils: i.Sigils}
}

func TestConforms(t *testing.T) {
	if err := iface().Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(f *Facet)
		want   *Mismatch
	}{
		{"identical", func(f *Facet) {}, nil},
		{"names, annotations and hints differ", func(f *Facet) {
			f.Types[0].Name, f.Types[0].Fields[0].Name = "X", "y"
			f.Types[0].Annotations = Annotations{"doc": cbor.Null}
			f.Types[0].Fields[1].Flags |= FieldDeprecated
			f.Services[0].Name, f.Services[0].Annotations = "Z", Annotations{"auth.hint": cbor.Null}
			f.Services[0].Methods[0].Flags = MethodShared
			f.Services[0].Methods[0].Errors = []uint64{3, 66}
			f.Sigils[0].Name = "q"
		}, nil},
		{"extra definitions", func(f *Facet) {
			f.Types = append(f.Types, TypeDef{Kind: KindAlias, ID: 80, Name: "x", Target: Named(TypeUint)})
			f.Services[0].Methods = append(f.Services[0].Methods, Method{ID: 9, Name: "extra", Input: Named(0), Output: Named(0)})
			f.Services = append(f.Services, Service{ID: 5, Name: "Other"})
		}, nil},
		{"field type differs", func(f *Facet) { f.Types[0].Fields[1].Type = Named(TypeString) }, &Mismatch{SpaceType, 64}},
		{"field optional flag differs", func(f *Facet) { f.Types[0].Fields[1].Flags = 0 }, &Mismatch{SpaceType, 64}},
		{"enum value missing", func(f *Facet) { f.Types[1].Values = []uint64{64} }, &Mismatch{SpaceType, 65}},
		{"type missing", func(f *Facet) { f.Types = f.Types[:1] }, &Mismatch{SpaceType, 65}},
		{"service missing", func(f *Facet) { f.Services[0].ID = 3 }, &Mismatch{SpaceService, 0}},
		{"method in another service", func(f *Facet) {
			f.Services = append(f.Services, Service{ID: 1, Name: "B", Methods: f.Services[0].Methods})
			f.Services[0].Methods = nil
		}, &Mismatch{SpaceMethod, 0}},
		{"method flags 0x2 differ", func(f *Facet) { f.Services[0].Methods[0].Flags = MethodNotification }, &Mismatch{SpaceMethod, 0}},
		{"method errors differ", func(f *Facet) { f.Services[0].Methods[0].Errors = []uint64{66} }, &Mismatch{SpaceMethod, 0}},
		{"sigil kind differs", func(f *Facet) { f.Sigils[2].Kind = SigilSymbol }, &Mismatch{SpaceSigil, 66}},
		{"sigil missing", func(f *Facet) { f.Sigils = f.Sigils[:2] }, &Mismatch{SpaceSigil, 66}},
	}
	for _, tc := range tests {
		f := implementing()
		f.Types, f.Services, f.Sigils = cloneDefs(f.Types, f.Services, f.Sigils)
		tc.mutate(f)
		got := Conforms(f, iface())
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	f := implementing()
	h, _ := iface().Hash()
	f.Implements = h
	if err := VerifyImplements(f, iface()); err != nil {
		t.Errorf("VerifyImplements: %v", err)
	}
	f.Implements = []byte{1, 2}
	if code(VerifyImplements(f, iface())) != CodeImplementsMismatch {
		t.Error("wrong hash accepted")
	}
	f.Implements = h
	f.Sigils = f.Sigils[:2]
	if code(VerifyImplements(f, iface())) != CodeImplementsMismatch {
		t.Error("non-conforming facet accepted")
	}
	if err := VerifyImplements(&Facet{}, iface()); err != nil {
		t.Error("no claim must pass")
	}
	// an interface must be closed
	i := iface()
	i.Sigils = append(i.Sigils, Sigil{ID: 90, Name: "stray"})
	if code(i.Validate()) != CodeInterfaceNotClosed {
		t.Error("stray sigil accepted")
	}
	i = iface()
	i.Types = append(i.Types, TypeDef{Kind: KindAlias, ID: 90, Name: "stray", Target: Named(1)})
	if code(i.Validate()) != CodeInterfaceNotClosed {
		t.Error("stray type accepted")
	}
	i = iface()
	i.Types[0].Annotations = Annotations{"x": cbor.AppendFloat(nil, 0.5)}
	if code(i.Validate()) != CodeFloat {
		t.Error("float in interface")
	}
}

func TestDelta(t *testing.T) {
	st, err := NewState(baseSchema())
	if err != nil {
		t.Fatal(err)
	}
	h0, _ := st.Hash()
	v2 := base()
	v2.Version = "1.1.0"
	v2.Types[0].Fields = append(v2.Types[0].Fields, Field{Tag: 5, Name: "pinned", Type: Named(TypeBool), Flags: FieldOptional})
	n, err := st.Apply(Delta{{Op: OpPut, Facet: v2}, {Op: OpVersion, Version: "2"}, {Op: OpAnnotations, Annotations: Annotations{}}})
	if err != nil {
		t.Fatal(err)
	}
	if n.Epoch() != 1 || st.Epoch() != 0 {
		t.Fatal("epochs")
	}
	if s := n.Schema(); s.Version != "2" || len(s.Annotations) != 0 || s.Facet(16).Version != "1.1.0" {
		t.Fatal("delta not applied")
	}
	if h, _ := st.Hash(); !bytes.Equal(h, h0) {
		t.Fatal("Apply changed the original state")
	}
	h1, _ := n.Hash()
	d, _ := Diff(st.Schema(), n.Schema())
	if _, err := st.ApplyUpdate(1, h1, d); err != nil {
		t.Fatalf("ApplyUpdate(Diff): %v", err)
	}
	if _, err := st.ApplyUpdate(2, h1, d); code(err) != CodeEpochMismatch {
		t.Errorf("wrong epoch: %v", err)
	}
	if _, err := st.ApplyUpdate(1, h0, d); code(err) != CodeHashMismatch {
		t.Errorf("wrong hash: %v", err)
	}
	if dd, _ := Diff(n.Schema(), n.Schema()); len(dd) != 0 {
		t.Errorf("Diff of equal schemas: %v", dd)
	}
	// encode and decode the delta
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if d2, err := DecodeDelta(b); err != nil || len(d2) != len(d) {
		t.Fatalf("delta round trip: %v", err)
	}

	removed, err := n.Apply(Delta{{Op: OpRemove, FacetID: 16}})
	if err != nil {
		t.Fatal(err)
	}
	if ids := removed.RemovedFacetIDs(); len(ids) != 1 || ids[0] != 16 {
		t.Fatalf("removed %v", ids)
	}
	back := base()
	back.Version = "1.2.0"
	back.Types[0].Fields = append(back.Types[0].Fields, Field{Tag: 5, Name: "pinned", Type: Named(TypeBool), Flags: FieldOptional})
	cases := []struct {
		name  string
		delta Delta
		want  Code
	}{
		{"re-add compatible successor", Delta{{Op: OpPut, Facet: back}}, ""},
		{"re-add older, incompatible version", Delta{{Op: OpPut, Facet: base()}}, CodeIncompatibleChange},
		{"re-add renamed", Delta{{Op: OpPut, Facet: func() *Facet { f := back.Clone(); f.Name = "acme.memos"; return f }()}}, CodeRemovedFacetMismatch},
		{"re-add new major", Delta{{Op: OpPut, Facet: func() *Facet { f := back.Clone(); f.Version = "2.0.0"; return f }()}}, CodeRemovedFacetMismatch},
		{"re-add without retired", Delta{{Op: OpPut, Facet: func() *Facet { f := back.Clone(); f.Retired = nil; return f }()}}, CodeRetiredNotCarriedOver},
		{"new major under a new ID", Delta{{Op: OpPut, Facet: func() *Facet {
			f := base()
			f.ID, f.Version = 18, "2.0.0"
			return f
		}()}}, ""},
		{"remove unknown facet", Delta{{Op: OpRemove, FacetID: 99}}, CodeUnknownFacet},
		{"reserved facet id", Delta{{Op: OpPut, Facet: &Facet{ID: 3, Name: "x", Version: "1"}}}, CodeReservedFacetID},
		{"duplicate facet name", Delta{{Op: OpPut, Facet: func() *Facet { f := base(); f.ID = 30; return f }()},
			{Op: OpPut, Facet: func() *Facet { f := base(); f.ID = 31; return f }()}}, CodeDuplicateFacetName},
		{"float annotations", Delta{{Op: OpAnnotations, Annotations: Annotations{"x": cbor.AppendFloat(nil, 1.5)}}}, CodeFloat},
		{"put without facet", Delta{{Op: OpPut}}, CodeMalformed},
		{"unknown op", Delta{{Op: 7}}, CodeUnknownDeltaOp},
	}
	for _, tc := range cases {
		_, err := removed.Apply(tc.delta)
		if code(err) != tc.want {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	readded, err := removed.Apply(Delta{{Op: OpPut, Facet: back}})
	if err != nil || len(readded.RemovedFacetIDs()) != 0 {
		t.Fatalf("re-add: %v", err)
	}
	// a replacement in place must be compatible
	if _, err := n.Apply(Delta{{Op: OpPut, Facet: base()}}); code(err) != CodeIncompatibleChange {
		t.Errorf("incompatible in-place replace: %v", err)
	}
	if _, err := NewState(&Schema{Format: 1}); code(err) != CodeUnsupportedFormat {
		t.Error("NewState validates")
	}
}

func TestView(t *testing.T) {
	s := baseSchema()
	v := s.View(16)
	if len(v.Facets) != 1 || len(s.Facets) != 2 || v.Facet(16) != nil {
		t.Fatal("View")
	}
	v2 := s.View()
	h1, _ := s.Hash()
	h2, _ := v2.Hash()
	if !bytes.Equal(h1, h2) {
		t.Fatal("View() changed the schema")
	}
}

func FuzzSchema(f *testing.F) {
	b, _ := baseSchema().Encode()
	f.Add(b)
	fb, _ := base().Encode()
	f.Add(fb)
	ib, _ := iface().Encode()
	f.Add(ib)
	db, _ := Delta{{Op: OpPut, Facet: base()}, {Op: OpRemove, FacetID: 16}, {Op: OpVersion, Version: "x"}}.Encode()
	f.Add(db)
	for _, b := range fuzzseed.Hex("schema.json", "admin.json") {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := DecodeSchema(b); err == nil {
			verr := s.Validate()
			c, err := s.CanonicalBytes()
			if err != nil {
				return // invalid annotation values
			}
			s2, err := DecodeSchema(c)
			if err != nil {
				t.Fatalf("canonical bytes do not decode: %v", err)
			}
			c2, _ := s2.CanonicalBytes()
			if !bytes.Equal(c, c2) {
				t.Fatal("canonical form not stable")
			}
			if _, err := s.Hash(); err != nil {
				t.Fatal(err)
			}
			if verr == nil {
				st, err := NewState(s)
				if err != nil {
					t.Fatal(err)
				}
				d, err := Diff(s, s)
				if err != nil || len(d) != 0 {
					t.Fatal("Diff")
				}
				if _, err := st.Apply(d); err != nil {
					t.Fatal(err)
				}
				for i := range s.Facets {
					_ = Compatible(&s.Facets[i], &s.Facets[i])
				}
			}
		}
		if fc, err := DecodeFacet(b); err == nil {
			_ = fc.Validate()
			_, _ = fc.Hash()
			_ = Compatible(fc, base())
			_ = Conforms(fc, iface())
		}
		if i, err := DecodeInterface(b); err == nil {
			_ = i.Validate()
			_, _ = i.Hash()
			_ = Conforms(base(), i)
		}
		if d, err := DecodeDelta(b); err == nil {
			st, _ := NewState(baseSchema())
			_, _ = st.Apply(d)
			_, _ = d.Encode()
		}
		_, _ = DecodeTypeRef(b)
	})
}
