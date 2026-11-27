package main

import "fmt"

// The example server schema: a small notes service. It is written here
// deliberately UNSORTED (types, services, methods, fields, variants, enum
// values, method errors and sigils are all out of order) so that the
// canonical form has real work to do.

const (
	tyNote       = 64
	tyFilter     = 65
	tyColor      = 66
	tyChange     = 67
	tyNoteID     = 68
	tyAttachment = 69
	tyTagCount   = 75

	sgQuota   = 64
	sgConflct = 65
	sgRed     = 70
	sgGreen   = 71
	sgBlue    = 72
	sgYellow  = 73
	sgUpdated = 80
	sgDeleted = 81
)

func notesMethods() []any {
	return []any{
		method(103, "attach", tyAttachment, tUnit, list(sgQuota), fInputEnd,
			ann{"doc": "Attach a file to a note; the file data travels as a byte token."}),
		method(101, "put", tyNote, tyNoteID, list(sgConflct, sgQuota), 0, nil),
		method(104, "export", tyFilter, tByteStream(), nil, fIdempotent|fOutputEnd,
			ann{"http.contentType": "application/zip"}),
		method(100, "get", tyNoteID, tyNote, nil, fIdempotent, ann{"doc": "Fetch one note by id."}),
		method(102, "watch", tyFilter, tStream(tyChange), nil, fShared|fOutputEnd, nil),
	}
}

func baseSchemaInput() []any {
	types := []any{
		enumDef(tyColor, "acme.notes.Color", list(sgBlue, sgRed, sgGreen), nil),
		structDef(tyNote, "acme.notes.Note", list(
			field(3, "tags", tList(tString), 0, nil),
			field(0, "id", tyNoteID, 0, nil),
			field(7, "pinned", tBool, 0x1|0x2, ann{"deprecated.use": "acme.notes.Note.color"}),
			field(2, "body", tOpt(tString), 0x1, ann{"ui.multiline": true, "ui.maxLength": 20000}),
			field(1, "title", tString, 0, nil),
			field(6, "color", tOpt(tyColor), 0x1, nil),
			field(4, "updated", tTimestamp, 0, nil),
			// tag 5 was removed in an earlier version; it stays unused.
		), 0, ann{"ui.label": "Note", "ui.icon": "sticky-note"}),
		structDef(tyAttachment, "acme.notes.Attachment", list(
			field(2, "data", tByteStream(), 0, nil),
			field(0, "name", tString, 0, nil),
			field(1, "mime", tOpt(tString), 0x1, nil),
		), 0, nil),
		unionDef(tyChange, "acme.notes.Change", list(
			variant(1, "deleted", tyNoteID, nil),
			variant(2, "cleared", tUnit, nil),
			variant(0, "upserted", tyNote, nil),
		), nil),
		structDef(tyFilter, "acme.notes.NoteFilter", list(
			field(2, "limit", tOpt(tUint), 0x1, nil),
			field(0, "query", tOpt(tString), 0x1, nil),
			field(4, "tags", tOpt(tList(tString)), 0x1, nil),
			field(1, "color", tOpt(tyColor), 0x1, nil),
			field(3, "since", tOpt(tTimestamp), 0x1, nil),
		), 0x1 /* sparse */, nil),
		aliasDef(tyNoteID, "acme.notes.NoteId", tUUID, nil),
	}
	services := []any{
		service(65, "acme.notes.Admin", list(
			method(113, "touch", tUnit, tUnit, nil, fNotification, nil),
			method(111, "sync", tStream(tyChange), tStream(tyChange), list(sgConflct), fInputEnd|fOutputEnd, nil),
			method(110, "import", tStream(tyNote), tUint, list(sgQuota), fInputEnd, nil),
			method(112, "restore", tByteStream(), tUint, nil, fInputEnd, ann{"auth.role": "admin"}),
		), ann{"auth.role": "admin"}),
		service(64, "acme.notes.Notes", notesMethods(), ann{"doc": "Personal notes."}),
	}
	sigils := []any{
		sigil(sgUpdated, "note.updated", 2, nil),
		sigil(sgGreen, "acme.notes.Color.green", 0, nil),
		sigil(sgConflct, "acme.notes.conflict", 1, ann{"http.status": 409}),
		sigil(sgRed, "acme.notes.Color.red", 0, nil),
		sigil(sgDeleted, "note.deleted", 2, nil),
		sigil(sgQuota, "acme.notes.quota_exceeded", 1, ann{"http.status": 429}),
		sigil(sgBlue, "acme.notes.Color.blue", 0, nil),
	}
	return schemaDoc("acme.notes", "2026.11.3", types, services, sigils,
		ann{"web.apply": "reload", "acme.owner": "notes-team"})
}

func clientSchemaInput() []any {
	return schemaDoc("acme.notes.web", "1.4.0", nil, list(
		service(64, "acme.notes.ClientUi", list(
			method(65, "navigate", tString, tBool, nil, 0, nil),
			method(64, "toast", tString, tUnit, nil, fNotification, nil),
		), nil),
	), nil, nil)
}

func deltaA() []any {
	ms := append(notesMethods(),
		method(105, "tagCounts", tUnit, tList(tyTagCount), nil, fIdempotent, nil))
	return []any{
		[]any{2, sigil(sgYellow, "acme.notes.Color.yellow", 0, nil)},
		[]any{0, enumDef(tyColor, "acme.notes.Color", list(sgYellow, sgRed, sgBlue, sgGreen), nil)},
		[]any{0, structDef(tyTagCount, "acme.notes.TagCount", list(
			field(1, "count", tUint, 0, nil),
			field(0, "tag", tString, 0, nil),
		), 0, nil)},
		[]any{1, service(64, "acme.notes.Notes", ms, ann{"doc": "Personal notes."})},
		[]any{5, "2026.11.4"},
	}
}

func deltaB() []any {
	return []any{
		[]any{3, 1, 113},       // retire method acme.notes.Admin.touch
		[]any{3, 2, sgDeleted}, // retire sigil note.deleted
		[]any{4, ann{"web.apply": "hot", "acme.owner": "notes-team", "acme.region": "eu"}},
		[]any{5, "2026.11.5"},
	}
}

type schemaResults struct {
	base, a, b       *schemaState
	baseHash, hA, hB []byte
	client           []any
	clientHash       []byte
}

var schemaRes *schemaResults

func schemas() *schemaResults {
	if schemaRes != nil {
		return schemaRes
	}
	r := &schemaResults{}
	r.base = newState(baseSchemaInput())
	if e := validateSchema(r.base.doc); e != nil {
		panic(e)
	}
	r.baseHash = schemaHash(r.base.doc)
	var e *deltaError
	r.a, e = r.base.apply(deltaA())
	if e != nil {
		panic(e)
	}
	r.hA = schemaHash(r.a.doc)
	r.b, e = r.a.apply(deltaB())
	if e != nil {
		panic(e)
	}
	r.hB = schemaHash(r.b.doc)
	r.client = canonical(clientSchemaInput())
	if e := validateSchema(r.client); e != nil {
		panic(e)
	}
	r.clientHash = schemaHash(r.client)
	schemaRes = r
	return r
}

func schemaVectors() O {
	r := schemas()
	full := func(name, desc string, input []any, canon []any) O {
		cb := enc(canon)
		h := schemaHash(canon)
		return o(
			"name", name,
			"description", desc,
			"spec", "6.2-6.6",
			"type", "schema",
			"input", tj(input),
			"canonical", tj(canon),
			"canonical_diag", diag(cb),
			"canonical_cbor", hx(cb),
			"canonical_length", len(cb),
			"sha256", hx(h[1:]),
			"hash", hx(h),
		)
	}
	var vs []any
	vs = append(vs, full("schema/server-base",
		"Example server schema 'acme.notes' with two services, a struct with a removed tag and a deprecated field, a sparse struct, an enum, a union, an alias, method flags including 0x8 and 0x10, sigils of all three kinds and annotations. The input is deliberately unsorted.",
		baseSchemaInput(), r.base.doc))
	vs = append(vs, full("schema/client",
		"Small client schema as sent inline in Hello.client_schema (client-callable services). Its methods are unsorted in the input.",
		clientSchemaInput(), r.client))

	type dv struct {
		name, desc, from string
		fromState        *schemaState
		fromHash         []byte
		epoch            int
		delta            []any
	}
	valid := []dv{
		{"schema/delta-1-add", "Epoch 1: add sigil Color.yellow, replace enum Color to include it (values unsorted), add struct TagCount, replace service Notes with a new method tagCounts (105), set version.",
			"schema/server-base", r.base, r.baseHash, 1, deltaA()},
		{"schema/delta-2-retire", "Epoch 2: retire method Admin.touch (113) and sigil note.deleted (81), replace top-level annotations, set version.",
			"schema/delta-1-add", r.a, r.hA, 2, deltaB()},
	}
	for _, d := range valid {
		res, e := d.fromState.apply(d.delta)
		if e != nil {
			panic(e)
		}
		cb := enc(res.doc)
		h := schemaHash(res.doc)
		upd := []any{3, d.epoch, h, d.delta}
		ub := enc(upd)
		vs = append(vs, o(
			"name", d.name,
			"description", d.desc,
			"spec", "6.6",
			"type", "delta",
			"from", d.from,
			"from_hash", hx(d.fromHash),
			"epoch", d.epoch,
			"delta", tj(d.delta),
			"expected_valid", true,
			"retired_after", retiredTJ(res),
			"canonical_cbor", hx(cb),
			"canonical_length", len(cb),
			"hash", hx(h),
			"schema_update", o("message", tj(upd), "diag", diag(ub), "cbor", hx(ub)),
		))
	}

	invalid := []struct {
		name, desc, code string
		delta            []any
	}{
		{"schema/delta-invalid-retire-referenced", "Retire type acme.notes.NoteId (68) while methods get/put, struct Note and union Change still reference it. Leaves a dangling reference, so the delta is invalid and handled like a hash mismatch (section 6.6 rule 2).",
			"dangling_reference", []any{[]any{3, 0, tyNoteID}}},
		{"schema/delta-invalid-unknown-type", "Add a struct whose field references TypeId 99, which no schema defines.",
			"dangling_reference", []any{[]any{0, structDef(76, "acme.notes.Broken", list(field(0, "x", 99, 0, nil)), 0, nil)}}},
		{"schema/delta-invalid-reuse-retired", "Add a sigil with ID 81, retired in epoch 2. IDs MUST NOT be reused within a session (section 6.1).",
			"retired_id_reused", []any{[]any{2, sigil(sgDeleted, "note.purged", 2, nil)}}},
		{"schema/delta-invalid-method-shape-change", "Replace service Notes with method get (100) changed from unary to a server stream. A method's input, output and flags 0x2/0x8/0x10 never change (section 6.4).",
			"incompatible_method_change", []any{[]any{1, service(64, "acme.notes.Notes", changedGet(), ann{"doc": "Personal notes."})}}},
	}
	for _, d := range invalid {
		_, e := r.b.apply(d.delta)
		if e == nil || e.Code != d.code {
			panic(fmt.Sprintf("%s: expected %s, got %v", d.name, d.code, e))
		}
		vs = append(vs, o(
			"name", d.name,
			"description", d.desc,
			"spec", "6.6",
			"type", "delta",
			"from", "schema/delta-2-retire",
			"from_hash", hx(r.hB),
			"epoch", 3,
			"delta", tj(d.delta),
			"expected_valid", false,
			"expected_error", d.code,
			"error_detail", e.Detail,
		))
	}
	return o("area", "schema", "vectors", vs)
}

func changedGet() []any {
	ms := append(notesMethods(),
		method(105, "tagCounts", tUnit, tList(tyTagCount), nil, fIdempotent, nil))
	for i, m := range ms {
		if num(m.([]any)[0]) == 100 {
			ms[i] = method(100, "get", tyNoteID, tStream(tyNote), nil, fIdempotent|fOutputEnd, nil)
		}
	}
	return ms
}

func retiredTJ(st *schemaState) O {
	names := []string{"types", "methods", "sigils", "services"}
	out := O{}
	for i, n := range names {
		ids := []int64{}
		for id := range st.retired[i] {
			ids = append(ids, id)
		}
		sortInts(ids)
		out = append(out, kv{n, ids})
	}
	return out
}

func sortInts(xs []int64) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j] < xs[j-1]; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}
