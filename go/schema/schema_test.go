package schema

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aiviarium/sparrow/go/cbor"
)

// base returns a valid facet exercising every kind of definition.
func base() *Facet {
	return &Facet{
		ID: 16, Name: "acme.notes", Version: "1.0.0",
		Types: []TypeDef{
			{Kind: KindStruct, ID: 64, Name: "Note", Fields: []Field{
				{Tag: 0, Name: "id", Type: Named(68)},
				{Tag: 1, Name: "title", Type: Named(TypeString)},
				{Tag: 2, Name: "body", Type: Optional(Named(TypeString)), Flags: FieldOptional},
				{Tag: 3, Name: "legacy", Type: Named(999), Flags: FieldOptional | FieldRemoved}, // tombstone: not checked
				{Tag: 4, Name: "color", Type: Named(66), Flags: FieldOptional | FieldDeprecated},
			}},
			{Kind: KindStruct, ID: 65, Name: "Filter", Flags: StructSparse, Fields: []Field{
				{Tag: 0, Name: "query", Type: Named(TypeString), Flags: FieldOptional},
			}},
			{Kind: KindEnum, ID: 66, Name: "Color", Values: []uint64{70, 71}},
			{Kind: KindUnion, ID: 67, Name: "Change", Fields: []Field{
				{Tag: 0, Name: "upserted", Type: Named(64)},
				{Tag: 1, Name: "deleted", Type: Named(68)},
			}},
			{Kind: KindAlias, ID: 68, Name: "NoteId", Target: Named(TypeUUID)},
			{Kind: KindStruct, ID: 69, Name: "Attachment", Fields: []Field{
				{Tag: 0, Name: "name", Type: Named(TypeString)},
				{Tag: 1, Name: "data", Type: ByteStream()},
			}},
			{Kind: KindAlias, ID: 72, Name: "Tags", Target: List(Named(TypeString))},
		},
		Services: []Service{
			{ID: 0, Name: "Notes", Methods: []Method{
				{ID: 100, Name: "get", Input: Named(68), Output: Named(64), Flags: MethodIdempotent},
				{ID: 101, Name: "put", Input: Named(64), Output: Named(68), Errors: []uint64{65, 3}},
				{ID: 102, Name: "watch", Input: Named(65), Output: Stream(Named(67)), Flags: MethodOutputEnd | MethodShared},
				{ID: 103, Name: "attach", Input: Named(69), Output: Named(TypeUnit), Flags: MethodInputEnd},
				{ID: 104, Name: "export", Input: Named(65), Output: ByteStream(), Flags: MethodOutputEnd},
				{ID: 105, Name: "touch", Input: Named(TypeUnit), Output: Named(TypeUnit), Flags: MethodNotification},
			}},
			{ID: 1, Name: "Admin", Methods: []Method{
				{ID: 110, Name: "import", Input: Stream(Named(64)), Output: MapOf(Named(TypeString), Named(TypeUint)), Flags: MethodInputEnd},
			}},
		},
		Sigils: []Sigil{
			{ID: 65, Name: "conflict", Kind: SigilError},
			{ID: 70, Name: "Color.red", Kind: SigilEnumValue},
			{ID: 71, Name: "Color.green", Kind: SigilEnumValue},
			{ID: 80, Name: "note.updated", Kind: SigilSymbol},
		},
		Retired:     []Retired{{SpaceType, 90}, {SpaceMethod, 120}},
		Annotations: Annotations{"doc": cbor.AppendText(nil, "Notes")},
	}
}

func code(err error) Code {
	var se *Error
	if errors.As(err, &se) {
		return se.Code
	}
	if err != nil {
		return "other"
	}
	return ""
}

func TestValidateFacet(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("base facet: %v", err)
	}
	float := cbor.AppendFloat(nil, 1.5)
	tests := []struct {
		name   string
		mutate func(f *Facet)
		want   Code
	}{
		{"reserved type id", func(f *Facet) { f.Types[0].ID = 63 }, CodeReservedID},
		{"reserved sigil id", func(f *Facet) { f.Sigils[0].ID = 40 }, CodeReservedID},
		{"duplicate type", func(f *Facet) { f.Types[1].ID = 64 }, CodeDuplicateID},
		{"duplicate sigil", func(f *Facet) { f.Sigils[1].ID = 65 }, CodeDuplicateID},
		{"duplicate service", func(f *Facet) { f.Services[1].ID = 0 }, CodeDuplicateID},
		{"duplicate method across services", func(f *Facet) { f.Services[1].Methods[0].ID = 100 }, CodeDuplicateID},
		{"duplicate field tag", func(f *Facet) { f.Types[0].Fields[1].Tag = 0 }, CodeDuplicateID},
		{"duplicate enum value", func(f *Facet) { f.Types[2].Values = []uint64{70, 70} }, CodeDuplicateID},
		{"retired type reused", func(f *Facet) { f.Types[6].ID = 90 }, CodeRetiredIDReused},
		{"retired method reused", func(f *Facet) { f.Services[0].Methods[0].ID = 120 }, CodeRetiredIDReused},
		{"retired service reused", func(f *Facet) { f.Retired = append(f.Retired, Retired{SpaceService, 1}) }, CodeRetiredIDReused},
		{"retired sigil reused", func(f *Facet) { f.Retired = append(f.Retired, Retired{SpaceSigil, 80}) }, CodeRetiredIDReused},
		{"bad retired space", func(f *Facet) { f.Retired = append(f.Retired, Retired{4, 1}) }, CodeBadRetiredEntry},
		{"dangling field type", func(f *Facet) { f.Types[0].Fields[1].Type = Named(200) }, CodeDanglingReference},
		{"reserved builtin range", func(f *Facet) { f.Types[0].Fields[1].Type = Named(12) }, CodeReservedTypeID},
		{"reserved builtin range, upper end", func(f *Facet) { f.Services[0].Methods[0].Output = List(Named(31)) }, CodeReservedTypeID},
		{"reserved range 32-63", func(f *Facet) { f.Types[0].Fields[1].Type = Named(32) }, CodeDanglingReference},
		{"notification with output", func(f *Facet) { f.Services[0].Methods[5].Output = Named(TypeBool) }, CodeInvalidNotification},
		{"notification with stream output", func(f *Facet) {
			f.Services[0].Methods[5].Output = Stream(Named(TypeUnit))
			f.Services[0].Methods[5].Flags |= MethodOutputEnd
		}, CodeInvalidNotification},
		{"notification with [4] input", func(f *Facet) {
			f.Services[0].Methods[5].Input = Named(69)
			f.Services[0].Methods[5].Flags |= MethodInputEnd
		}, CodeInvalidNotification},
		{"dangling nested ref", func(f *Facet) { f.Types[6].Target = List(Optional(Named(77))) }, CodeDanglingReference},
		{"dangling map key", func(f *Facet) { f.Services[1].Methods[0].Output = MapOf(Named(78), Named(3)) }, CodeDanglingReference},
		{"dangling method input", func(f *Facet) { f.Services[0].Methods[0].Input = Named(300) }, CodeDanglingReference},
		{"enum value not a sigil", func(f *Facet) { f.Types[2].Values = []uint64{70, 72} }, CodeDanglingReference},
		{"enum value of the wrong kind", func(f *Facet) { f.Types[2].Values = []uint64{70, 80} }, CodeDanglingReference},
		{"error not kind 1", func(f *Facet) { f.Services[0].Methods[1].Errors = []uint64{70} }, CodeDanglingReference},
		{"error in reserved range", func(f *Facet) { f.Services[0].Methods[1].Errors = []uint64{40} }, CodeDanglingReference},
		{"bad sigil kind", func(f *Facet) { f.Sigils[3].Kind = 3 }, CodeBadSigilKind},
		{"duplicate sigil name", func(f *Facet) { f.Sigils[3].Name = "Color.red" }, CodeDuplicateSigilName},
		{"duplicate sigil name across kinds", func(f *Facet) { f.Sigils[0].Name = "note.updated" }, CodeDuplicateSigilName},
		{"stream in a field", func(f *Facet) { f.Types[0].Fields[1].Type = Stream(Named(6)) }, CodeStreamMisplaced},
		{"stream in an alias", func(f *Facet) { f.Types[6].Target = Stream(Named(6)) }, CodeStreamMisplaced},
		{"stream of stream", func(f *Facet) {
			f.Services[0].Methods[2].Output = Stream(Stream(Named(6)))
		}, CodeStreamMisplaced},
		{"stream in a list in a method", func(f *Facet) {
			f.Services[0].Methods[0].Output = List(Stream(Named(6)))
		}, CodeStreamMisplaced},
		{"stream output without 0x10", func(f *Facet) { f.Services[0].Methods[2].Flags = 0 }, CodeMissingEndFlag},
		{"stream input without 0x8", func(f *Facet) { f.Services[1].Methods[0].Flags = 0 }, CodeMissingEndFlag},
		{"byte stream output without 0x10", func(f *Facet) { f.Services[0].Methods[4].Flags = 0 }, CodeMissingEndFlag},
		{"[4] reached through a struct without 0x8", func(f *Facet) { f.Services[0].Methods[3].Flags = 0 }, CodeMissingEndFlag},
		{"[4] reached through union and alias", func(f *Facet) {
			f.Types[4].Target = Optional(Named(69)) // NoteId now reaches [4]
		}, CodeMissingEndFlag},
		{"non-ASCII type", func(f *Facet) { f.Types[0].Name = "Notizé" }, CodeInvalidName},
		{"non-ASCII field", func(f *Facet) { f.Types[0].Fields[0].Name = "é" }, CodeInvalidName},
		{"non-ASCII variant", func(f *Facet) { f.Types[3].Fields[0].Name = "é" }, CodeInvalidName},
		{"non-ASCII service", func(f *Facet) { f.Services[0].Name = "é" }, CodeInvalidName},
		{"non-ASCII method", func(f *Facet) { f.Services[0].Methods[0].Name = "é" }, CodeInvalidName},
		{"non-ASCII sigil", func(f *Facet) { f.Sigils[0].Name = "é" }, CodeInvalidName},
		{"facet name upper case", func(f *Facet) { f.Name = "Acme.notes" }, CodeInvalidName},
		{"facet name empty label", func(f *Facet) { f.Name = "acme..notes" }, CodeInvalidName},
		{"float in facet annotations", func(f *Facet) { f.Annotations["x"] = float }, CodeFloat},
		{"float nested in field annotations", func(f *Facet) {
			f.Types[0].Fields[0].Annotations = Annotations{"x": append(cbor.AppendArrayHead(nil, 1), float...)}
		}, CodeFloat},
		{"float in method annotations", func(f *Facet) { f.Services[0].Methods[0].Annotations = Annotations{"x": float} }, CodeFloat},
		{"float in sigil annotations", func(f *Facet) { f.Sigils[0].Annotations = Annotations{"x": float} }, CodeFloat},
		{"unknown type kind", func(f *Facet) { f.Types[0].Kind = 7 }, CodeMalformed},
		// accepted
		{"peer-prefixed facet name", func(f *Facet) { f.Name = "hub-b/acme.notes" }, ""},
		{"tombstone may reference anything", func(f *Facet) { f.Types[0].Fields[3].Type = Stream(Named(500)) }, ""},
		{"End flags set without need", func(f *Facet) { f.Services[0].Methods[0].Flags |= MethodInputEnd | MethodOutputEnd }, ""},
		{"two enums with a value none", func(f *Facet) {
			f.Types = append(f.Types,
				TypeDef{Kind: KindEnum, ID: 73, Name: "Mode", Values: []uint64{90}},
				TypeDef{Kind: KindEnum, ID: 74, Name: "Level", Values: []uint64{91}})
			f.Sigils = append(f.Sigils, Sigil{ID: 90, Name: "Mode.none"}, Sigil{ID: 91, Name: "Level.none"})
		}, ""},
		{"core error code listed", func(f *Facet) { f.Services[0].Methods[0].Errors = []uint64{5, 31} }, ""},
		{"recursive types", func(f *Facet) {
			f.Types = append(f.Types, TypeDef{Kind: KindStruct, ID: 73, Name: "Tree", Fields: []Field{
				{Tag: 0, Name: "kids", Type: List(Named(73))}}})
		}, ""},
	}
	for _, tc := range tests {
		f := base()
		tc.mutate(f)
		if got := code(f.Validate()); got != tc.want {
			t.Errorf("%s: %v, want %q", tc.name, f.Validate(), tc.want)
		}
	}
}

func baseSchema() *Schema {
	return &Schema{Format: 2, Name: "acme.host", Version: "1", Facets: []Facet{*WebFacet(), *base()},
		Annotations: Annotations{"web.apply": cbor.AppendText(nil, "hot")}}
}

func TestValidateSchema(t *testing.T) {
	if err := baseSchema().Validate(); err != nil {
		t.Fatal(err)
	}
	other := base()
	other.ID, other.Name = 17, "acme.other"
	tests := []struct {
		name   string
		mutate func(s *Schema)
		want   Code
	}{
		{"format 1", func(s *Schema) { s.Format = 1 }, CodeUnsupportedFormat},
		{"unsorted", func(s *Schema) { s.Facets = []Facet{s.Facets[1], s.Facets[0]} }, CodeFacetsNotSorted},
		{"duplicate id", func(s *Schema) { s.Facets = append(s.Facets, s.Facets[1]) }, CodeDuplicateFacetID},
		{"duplicate name", func(s *Schema) {
			f := *other
			f.Name = "acme.notes"
			s.Facets = append(s.Facets, f)
		}, CodeDuplicateFacetName},
		{"facet 0", func(s *Schema) { s.Facets[1].ID = 0; s.Facets = []Facet{s.Facets[1], s.Facets[0]} }, CodeReservedFacetID},
		{"facet 15", func(s *Schema) { s.Facets[1].ID = 15 }, CodeReservedFacetID},
		{"facet 2", func(s *Schema) { s.Facets[1].ID = 2 }, CodeReservedFacetID},
		{"facet 1 altered", func(s *Schema) { s.Facets[0].Services[0].Methods[0].Flags = 0 }, CodeFacet1Mismatch},
		{"facet 1 renamed", func(s *Schema) { s.Facets[0].Name = "other.web" }, CodeFacet1Mismatch},
		{"facet 1 annotated", func(s *Schema) { s.Facets[0].Annotations = Annotations{"doc": cbor.Null} }, CodeFacet1Mismatch},
		{"float in schema annotations", func(s *Schema) { s.Annotations["x"] = cbor.AppendFloat(nil, 2.5) }, CodeFloat},
		{"invalid facet", func(s *Schema) { s.Facets[1].Types[0].ID = 1 }, CodeReservedID},
		// accepted
		{"no facet 1", func(s *Schema) { s.Facets = s.Facets[1:] }, ""},
		{"facet 1 with unsorted content", func(s *Schema) {
			s.Facets[0].Services[0].Annotations = Annotations{}
		}, ""},
		{"two facets", func(s *Schema) { s.Facets = append(s.Facets, *other) }, ""},
	}
	for _, tc := range tests {
		s := baseSchema()
		tc.mutate(s)
		if got := code(s.Validate()); got != tc.want {
			t.Errorf("%s: %v, want %q", tc.name, s.Validate(), tc.want)
		}
	}
	s := baseSchema()
	s.Facets = []Facet{s.Facets[1], s.Facets[0]}
	if err := s.ValidateWith(ValidateOptions{AllowUnsorted: true}); err != nil {
		t.Errorf("AllowUnsorted: %v", err)
	}
}

func TestCodecRoundTrip(t *testing.T) {
	s := baseSchema()
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeSchema(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := d.Encode()
	if !bytes.Equal(b, b2) {
		t.Fatal("schema does not round-trip")
	}
	// a stored schema file may start with tag 55799
	if _, err := DecodeSchema(append([]byte{0xd9, 0xd9, 0xf7}, b...)); err != nil {
		t.Errorf("self-described prefix: %v", err)
	}
	h1, _ := s.Hash()
	h2, _ := d.Hash()
	if !bytes.Equal(h1, h2) || len(h1) != HashLen || h1[0] != HashAlgSHA256 {
		t.Fatal("hash")
	}
	// canonical form ignores list order and annotation key order
	shuffled := baseSchema()
	f := &shuffled.Facets[1]
	f.Types[0], f.Types[3] = f.Types[3], f.Types[0]
	f.Types[0].Fields[0], f.Types[0].Fields[1] = f.Types[0].Fields[1], f.Types[0].Fields[0]
	f.Services[0].Methods[0], f.Services[0].Methods[5] = f.Services[0].Methods[5], f.Services[0].Methods[0]
	f.Services[0], f.Services[1] = f.Services[1], f.Services[0]
	f.Sigils[0], f.Sigils[3] = f.Sigils[3], f.Sigils[0]
	f.Retired[0], f.Retired[1] = f.Retired[1], f.Retired[0]
	for i := range f.Services {
		for j := range f.Services[i].Methods {
			if m := &f.Services[i].Methods[j]; m.ID == 101 {
				m.Errors = []uint64{3, 65}
			}
		}
	}
	f.Annotations["doc"] = cbor.Raw{0x78, 0x05, 'N', 'o', 't', 'e', 's'} // non-preferred length
	h3, err := shuffled.Hash()
	if err != nil || !bytes.Equal(h1, h3) {
		t.Fatalf("canonical hash differs for reordered input: %v", err)
	}
	// but the arrays inside annotations keep their order
	f.Annotations["doc"] = cbor.Raw{0x82, 0x01, 0x02}
	g := baseSchema()
	g.Facets[1].Annotations["doc"] = cbor.Raw{0x82, 0x02, 0x01}
	ha, _ := shuffled.Hash()
	hb, _ := g.Hash()
	if bytes.Equal(ha, hb) {
		t.Fatal("annotation array order ignored")
	}
	// the facet hash ignores the facet's ID and name
	w := WebFacet()
	w.ID, w.Name = 42, "renamed"
	if h, _ := w.Hash(); !bytes.Equal(h, WebFacetHash()) {
		t.Fatal("facet hash depends on id or name")
	}
	if ok, _ := IsWebFacet(w); ok {
		t.Fatal("renamed web facet accepted as sparrow.web")
	}
}

func TestDecodeErrors(t *testing.T) {
	good, _ := baseSchema().Encode()
	tests := []struct {
		name string
		in   []byte
		want Code
	}{
		{"not cbor", []byte{0xff}, CodeMalformed},
		{"format 3", []byte{0x85, 0x03, 0x60, 0x60, 0x80, 0xa0}, CodeUnsupportedFormat},
		{"short schema", []byte{0x84, 0x02, 0x60, 0x60, 0x80}, CodeMalformed},
		{"facet with 8 elements", []byte{0x85, 0x02, 0x60, 0x60, 0x81, 0x88, 0x10, 0x60, 0x60, 0x80, 0x80, 0x80, 0xf6, 0x80}, CodeMalformed},
		{"trailing", append(append([]byte{}, good...), 0x00), CodeMalformed},
		{"annotations key not text", []byte{0x85, 0x02, 0x60, 0x60, 0x80, 0xa1, 0x01, 0x01}, CodeMalformed},
		{"name not text", []byte{0x85, 0x02, 0x01, 0x60, 0x80, 0xa0}, CodeMalformed},
		{"facet ID beyond 2^53 - 1", []byte{0x85, 0x02, 0x60, 0x60, 0x81, 0x89, 0x1b, 0, 0x20, 0, 0, 0, 0, 0, 0, 0x60, 0x60, 0x80, 0x80, 0x80, 0xf6, 0x80, 0xa0, 0xa0}, CodeMalformed},
	}
	for _, tc := range tests {
		_, err := DecodeSchema(tc.in)
		if code(err) != tc.want {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.want)
		}
	}
	if _, err := (DecodeOptions{MaxBytes: 10}).DecodeSchema(good); code(err) != CodeTooLarge {
		t.Errorf("MaxBytes: %v", err)
	}
	refs := []struct {
		in   []byte
		want Code
	}{
		{[]byte{0x80}, CodeBadTypeRef},
		{[]byte{0x81, 0x05}, CodeBadTypeRef},
		{[]byte{0x82, 0x04, 0x00}, CodeBadTypeRef},
		{[]byte{0x82, 0x01, 0x00}, CodeBadTypeRef},
		{[]byte{0x61, 0x61}, CodeMalformed},
		{[]byte{0x20}, CodeMalformed},
		{[]byte{0x1b, 0, 0x20, 0, 0, 0, 0, 0, 0}, CodeMalformed}, // a TypeId beyond 2^53 - 1 (3.1)
	}
	for _, tc := range refs {
		if _, err := DecodeTypeRef(tc.in); code(err) != tc.want {
			t.Errorf("type-ref %x: %v, want %s", tc.in, err, tc.want)
		}
	}
	for _, r := range []TypeRef{Named(5), List(Named(64)), MapOf(Named(6), Optional(Named(3))), Stream(ByteStream()), ByteStream()} {
		got, err := DecodeTypeRef(r.Encode())
		if err != nil || !got.Equal(r) {
			t.Errorf("type-ref round trip %x: %v", r.Encode(), err)
		}
	}
	// type-def kinds and lengths
	tds := []struct {
		in   []byte
		want Code
	}{
		{[]byte{0x85, 0x04, 0x18, 0x40, 0x60, 0x00, 0xa0}, CodeMalformed},                         // kind 4
		{[]byte{0x85, 0x00, 0x18, 0x40, 0x60, 0x80, 0xa0}, CodeMalformed},                         // struct without flags
		{[]byte{0x86, 0x01, 0x18, 0x40, 0x60, 0x80, 0x00, 0xa0}, CodeMalformed},                   // enum with 6 elements
		{[]byte{0x85, 0x03, 0x18, 0x40, 0x60, 0x83, 0x01, 0x06, 0x06, 0xa0}, ""},                  // alias to map
		{[]byte{0x86, 0x00, 0x18, 0x40, 0x60, 0x81, 0x84, 0, 0x60, 0, 0, 0, 0xa0}, CodeMalformed}, // field of 4
	}
	for _, tc := range tds {
		in := append([]byte{0x89, 0x10, 0x61, 'a', 0x60, 0x81}, tc.in...)
		in = append(in, 0x80, 0x80, 0xf6, 0x80, 0xa0)
		if _, err := DecodeFacet(in); code(err) != tc.want {
			t.Errorf("type-def %x: %v, want %q", tc.in, err, tc.want)
		}
	}
	if _, err := DecodeDelta([]byte{0x81, 0x82, 0x04, 0x00}); code(err) != CodeUnknownDeltaOp {
		t.Errorf("delta op 4: %v", err)
	}
	if _, err := DecodeDelta([]byte{0x81, 0x83, 0x01, 0x10, 0x00}); code(err) != CodeMalformed {
		t.Errorf("delta op with 3 elements: %v", err)
	}
	if _, err := DecodeInterface([]byte{0x84, 0x60, 0x60, 0x80, 0x80}); code(err) != CodeMalformed {
		t.Errorf("interface of 4: %v", err)
	}
	if _, err := (Delta{{Op: 9}}).Encode(); code(err) != CodeUnknownDeltaOp {
		t.Error("encoding an unknown delta op")
	}
	if _, err := (&Facet{Annotations: Annotations{"x": cbor.Raw{0xff}}}).CanonicalBytes(); code(err) != CodeMalformed {
		t.Error("canonical encoding of an invalid annotation")
	}
}

func TestWebFacet(t *testing.T) {
	w := WebFacet()
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	m, s := w.Method(WebMethodModuleRejected)
	if m == nil || s.ID != WebServiceClient || !m.IsNotification() || m.Name != "moduleRejected" ||
		!m.Input.Equal(List(Named(TypeString))) || !m.Output.Equal(Named(TypeUnit)) {
		t.Fatalf("moduleRejected = %+v", m)
	}
	if ok, err := IsWebFacet(w); !ok || err != nil {
		t.Fatal("IsWebFacet")
	}
	h := WebFacetHash()
	h[0] = 0
	if WebFacetHash()[0] != HashAlgSHA256 {
		t.Fatal("WebFacetHash returns shared memory")
	}
}

func TestAccessors(t *testing.T) {
	f := base()
	if f.Type(64).Name != "Note" || f.Type(1) != nil || f.Sigil(80).Kind != SigilSymbol || f.Sigil(1) != nil {
		t.Error("Type/Sigil")
	}
	if f.Service(1).Name != "Admin" || f.Service(9) != nil {
		t.Error("Service")
	}
	if m, s := f.Method(110); m == nil || s.ID != 1 || !m.InputEnds() || m.OutputEnds() {
		t.Error("Method")
	}
	if m, _ := f.Method(999); m != nil {
		t.Error("Method(999)")
	}
	if !f.IsRetired(SpaceType, 90) || f.IsRetired(SpaceType, 64) {
		t.Error("IsRetired")
	}
	if f.Type(64).Field(4).Name != "color" || f.Type(64).Field(9) != nil || !f.Type(65).Sparse() || f.Type(64).Sparse() {
		t.Error("Field/Sparse")
	}
	if !f.Type(64).Field(3).Removed() || !f.Type(64).Field(2).Optional() {
		t.Error("field flags")
	}
	if Major("0.3.1") != "0" || Major("12") != "12" || Major("") != "" {
		t.Error("Major")
	}
	for _, k := range []TypeKind{KindStruct, KindEnum, KindUnion, KindAlias, 9} {
		if k.String() == "" {
			t.Error("TypeKind.String")
		}
	}
	for _, s := range []Space{SpaceType, SpaceService, SpaceMethod, SpaceSigil, 9} {
		if s.String() == "" {
			t.Error("Space.String")
		}
	}
	types := f.TypeIndex()
	if !NeedsEnd(Named(69), types) || NeedsEnd(Named(64), types) || !NeedsEnd(Stream(Named(6)), types) ||
		!ReachesByteStream(List(Named(69)), types) || ReachesByteStream(Named(67), types) {
		t.Error("NeedsEnd / ReachesByteStream")
	}
	if (&Error{Code: CodeMalformed, Detail: "x"}).Error() == "" || (&Mismatch{SpaceType, 1}).Error() == "" {
		t.Error("errors")
	}
	if (DeltaOp{Op: OpPut, Facet: f}).String() == "" || (DeltaOp{Op: 9}).String() == "" {
		t.Error("DeltaOp.String")
	}
}
