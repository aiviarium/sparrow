package main

import "fmt"

// Example data. Inputs are deliberately UNSORTED (types, services, methods,
// fields, variants, enum values, errors, sigils, retired, facets) so the
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

	facetWeb    = 1
	facetNotes  = 16
	facetCharts = 17
)

// ---- facet 1, sparrow.web (section 9.4) ----

func webFacet() []any {
	return facetDoc(facetWeb, "sparrow.web", "1.0.0", nil,
		list(service(0, "Client", list(
			method(0, "moduleRejected", tList(tString), tUnit, nil, fNotification, nil),
		), nil)), nil, nil, nil, nil)
}

// ---- facet 16, acme.notes ----

type notesOpts struct {
	version string
	v11     bool // apply the epoch-1 changes
}

func notesFacet(o notesOpts) []any {
	colorValues := list(sgBlue, sgRed, sgGreen)
	if o.v11 {
		colorValues = list(sgYellow, sgBlue, sgRed, sgGreen)
	}
	noteFields := list(
		field(3, "tags", tList(tString), 0, nil),
		field(0, "id", tyNoteID, 0, nil),
		field(7, "pinned", tBool, ffOptional|ffDeprecated, ann{"deprecated.use": "color"}),
		field(5, "legacyLabel", tString, ffOptional|ffRemoved, nil),
		field(2, "body", tOpt(tString), ffOptional, ann{"ui.multiline": true, "ui.maxLength": 20000}),
		field(1, "title", tString, 0, nil),
		field(6, "color", tOpt(tyColor), ffOptional, nil),
		field(4, "updated", tTimestamp, 0, nil),
	)
	if o.v11 {
		noteFields = append(noteFields, field(8, "archived", tOpt(tBool), ffOptional, nil))
	}
	clearedFlags := 0
	if o.v11 {
		clearedFlags = ffRemoved
	}
	types := list(
		enumDef(tyColor, "Color", colorValues, nil),
		structDef(tyNote, "Note", noteFields, 0, ann{"ui.label": "Note", "ui.icon": "sticky-note"}),
		structDef(tyAttachment, "Attachment", list(
			field(2, "data", tByteStream(), 0, nil),
			field(0, "name", tString, 0, nil),
			field(1, "mime", tOpt(tString), ffOptional, nil),
		), 0, nil),
		unionDef(tyChange, "Change", list(
			variant(1, "deleted", tyNoteID, 0, nil),
			variant(2, "cleared", tUnit, clearedFlags, nil),
			variant(0, "upserted", tyNote, 0, nil),
		), nil),
		structDef(tyFilter, "NoteFilter", list(
			field(2, "limit", tOpt(tUint), ffOptional, nil),
			field(0, "query", tOpt(tString), ffOptional, nil),
			field(4, "tags", tOpt(tList(tString)), ffOptional, nil),
			field(1, "color", tOpt(tyColor), ffOptional, nil),
			field(3, "since", tOpt(tTimestamp), ffOptional, nil),
		), 0x1 /* sparse */, nil),
		aliasDef(tyNoteID, "NoteId", tUUID, nil),
	)
	if o.v11 {
		types = append(types, structDef(tyTagCount, "TagCount", list(
			field(1, "count", tUint, 0, nil),
			field(0, "tag", tString, 0, nil),
		), 0, nil))
	}
	adminMethods := list(
		method(111, "sync", tStream(tyChange), tStream(tyChange), list(sgConflct), fInputEnd|fOutputEnd, nil),
		method(110, "import", tStream(tyNote), tUint, list(sgQuota), fInputEnd, nil),
		method(112, "restore", tByteStream(), tUint, nil, fInputEnd, ann{"auth.role": "admin"}),
	)
	if !o.v11 {
		adminMethods = append(list(method(113, "touch", tUnit, tUnit, nil, fNotification, nil)), adminMethods...)
	}
	notesMethods := list(
		method(103, "attach", tyAttachment, tUnit, list(sgQuota), fInputEnd,
			ann{"doc": "Attach a file to a note; the data travels as a byte token."}),
		method(101, "put", tyNote, tyNoteID, list(sgConflct, sgQuota), 0, nil),
		method(104, "export", tyFilter, tByteStream(), nil, fIdempotent|fOutputEnd, ann{"http.contentType": "application/zip"}),
		method(100, "get", tyNoteID, tyNote, nil, fIdempotent, ann{"doc": "Fetch one note by id."}),
		method(102, "watch", tyFilter, tStream(tyChange), nil, fShared|fOutputEnd, nil),
	)
	if o.v11 {
		notesMethods = append(notesMethods, method(105, "tagCounts", tUnit, tList(tyTagCount), nil, fIdempotent, nil))
	}
	sigils := list(
		sigil(sgUpdated, "note.updated", 2, nil),
		sigil(sgGreen, "Color.green", 0, nil),
		sigil(sgConflct, "conflict", 1, ann{"http.status": 409}),
		sigil(sgRed, "Color.red", 0, nil),
		sigil(sgQuota, "quota_exceeded", 1, ann{"http.status": 429}),
		sigil(sgBlue, "Color.blue", 0, nil),
	)
	ret := retired([2]int{spSigil, 82}, [2]int{spType, 70})
	if o.v11 {
		sigils = append(sigils, sigil(sgYellow, "Color.yellow", 0, nil))
		ret = retired([2]int{spSigil, 82}, [2]int{spMethod, 113}, [2]int{spType, 70}, [2]int{spSigil, sgDeleted})
	} else {
		sigils = append(sigils, sigil(sgDeleted, "note.deleted", 2, nil))
	}
	return facetDoc(facetNotes, "acme.notes", o.version, types,
		list(
			service(1, "Admin", adminMethods, ann{"auth.role": "admin"}),
			service(0, "Notes", notesMethods, ann{"doc": "Personal notes."}),
		), sigils, nil, ret, ann{"acme.owner": "notes-team"})
}

func notesV1() []any  { return notesFacet(notesOpts{version: "1.0.0"}) }
func notesV11() []any { return notesFacet(notesOpts{version: "1.1.0", v11: true}) }

// ---- interface acme.charts.Renderer and facet 17, acme.charts ----

func rendererIface() []any {
	return ifaceDoc("acme.charts.Renderer", "1.0.0",
		list(
			structDef(66, "Series", list(field(1, "points", tList(tInt), 0, nil), field(0, "label", tString, 0, nil)), 0, nil),
			structDef(64, "ChartSpec", list(
				field(2, "series", tList(66), 0, nil),
				field(0, "kind", 65, 0, nil),
				field(1, "title", tOpt(tString), ffOptional, nil),
			), 0, nil),
			enumDef(65, "ChartKind", list(65, 64), nil),
		),
		list(service(0, "Renderer", list(method(0, "render", 64, tBytes, list(66), fIdempotent, nil)), nil)),
		list(sigil(66, "unsupported_kind", 1, nil), sigil(64, "ChartKind.line", 0, nil), sigil(65, "ChartKind.bar", 0, nil)),
	)
}

type chartsOpts struct {
	id          int
	name        string
	version     string
	pointsType  any
	extraMethod bool
	notIdem     bool
	deprecate   bool // mark Chart.heading deprecated (hint flag 0x2)
	drawOutput  any  // replace draw's output type
	moveDraw    bool // move draw to service 1
	noExtras    bool
	themeNote   bool
	implements  bool
}

func chartsFacet(o chartsOpts) []any {
	if o.pointsType == nil {
		o.pointsType = tList(tInt)
	}
	renderFlags := fIdempotent
	if o.notIdem {
		renderFlags = 0
	}
	if o.name == "" {
		o.name = "acme.charts"
	}
	headingFlags := ffOptional
	if o.deprecate {
		headingFlags |= ffDeprecated
	}
	drawOut := any(tBytes)
	if o.drawOutput != nil {
		drawOut = o.drawOutput
	}
	types := list(
		structDef(64, "Chart", list(
			field(1, "heading", tOpt(tString), headingFlags, ann{"ui.placeholder": "Untitled"}),
			field(0, "type", 65, 0, nil),
			field(2, "data", tList(66), 0, nil),
		), 0, ann{"doc": "What to draw."}),
		enumDef(65, "Kind", list(64, 65), nil),
		structDef(66, "DataSeries", list(field(0, "name", tString, 0, nil), field(1, "values", o.pointsType, 0, nil)), 0, nil),
	)
	draw := method(0, "draw", 64, drawOut, list(66), renderFlags, ann{"doc": "Returns SVG bytes."})
	renderMethods := list(draw)
	if o.moveDraw {
		renderMethods = list()
	}
	if o.extraMethod {
		renderMethods = append(renderMethods, method(2, "drawPng", 64, tBytes, list(66), fIdempotent, nil))
	}
	services := list(service(0, "ChartRenderer", renderMethods, ann{"auth.hint": "public"}))
	sigils := list(sigil(66, "chart.unsupported", 1, ann{"http.status": 422}), sigil(64, "Kind.line", 0, nil), sigil(65, "Kind.bar", 0, nil))
	var an ann
	if !o.noExtras {
		themeAnn := ann(nil)
		if o.themeNote {
			themeAnn = ann{"doc": "A colour theme."}
		}
		types = append(types, structDef(80, "Theme", list(field(1, "dark", tOpt(tBool), ffOptional, nil), field(0, "name", tString, 0, nil)), 0, themeAnn))
		themeMethods := list(
			method(1, "listThemes", tUnit, tList(80), nil, fIdempotent, nil),
			method(3, "setTheme", tString, tUnit, nil, fNotification, nil),
		)
		if o.moveDraw {
			themeMethods = append(themeMethods, draw)
		}
		services = append(services, service(1, "Themes", themeMethods, nil))
		an = ann{"doc": "Chart rendering.", "web.modules": []any{moduleByName("module/acme-charts").full}}
	}
	var impl []byte
	if o.implements {
		impl = ifaceHash(rendererIface())
	}
	return facetDoc(o.id, o.name, o.version, types, services, sigils, impl, nil, an)
}

func chartsV1() []any {
	return chartsFacet(chartsOpts{id: facetCharts, version: "1.0.0", implements: true})
}

// ---- schemas ----

func serverSchemaInput() []any {
	return schemaDoc("acme.host", "2026.12.1", list(webFacet(), notesV1(), chartsV1()),
		ann{"web.apply": "reload", "web.keys": []any{certByName("cert/acme").full}, "web.revoked": revList.full})
}

func clientSchemaInput() []any {
	return schemaDoc("acme.notes.web", "1.4.0", list(
		facetDoc(16, "acme.notes.web", "1.4.0", nil, list(
			service(0, "ClientUi", list(
				method(65, "navigate", tString, tBool, nil, 0, nil),
				method(64, "toast", tString, tUnit, nil, fNotification, nil),
			), nil),
		), nil, nil, nil, nil),
	), nil)
}

// The schema a node 'acme.charts' publishes on its own link: the same facet
// under node-local facet ID 16 (section 10.3).
func nodeSchemaInput() []any {
	p := chartsV1()
	p[pID] = 16
	return schemaDoc("acme.charts", "1.0.0", list(p), nil)
}

func deltaA() []any {
	return []any{[]any{0, notesV11()}, []any{3, "2026.12.2"}}
}

func chartsV2() []any {
	p := chartsFacet(chartsOpts{id: 18, version: "2.0.0", pointsType: tList(tUint)})
	return p
}

func deltaB() []any {
	return []any{
		[]any{1, facetCharts},
		[]any{0, chartsV2()},
		[]any{2, ann{"web.apply": "hot", "web.keys": []any{certByName("cert/acme").full}, "web.revoked": revList.full}},
	}
}

func deltaC() []any {
	return []any{
		[]any{1, 18},
		[]any{0, chartsFacet(chartsOpts{id: facetCharts, version: "1.0.1", implements: true, themeNote: true})},
		[]any{3, "2026.12.3"},
	}
}

type schemaResults struct {
	base, a, b, c *schemaState
	baseHash      []byte
	hA, hB, hC    []byte
	client, node  []any
	clientHash    []byte
	nodeHash      []byte
}

var schemaRes *schemaResults

func schemas() *schemaResults {
	if schemaRes != nil {
		return schemaRes
	}
	r := &schemaResults{}
	r.base = newState(serverSchemaInput())
	if e := validateSchema(r.base.doc); e != nil {
		panic(e)
	}
	if e := validateIface(rendererIface()); e != nil {
		panic(e)
	}
	r.baseHash = schemaHash(r.base.doc)
	var e *deltaError
	if r.a, e = r.base.apply(deltaA()); e != nil {
		panic(e)
	}
	if r.b, e = r.a.apply(deltaB()); e != nil {
		panic(e)
	}
	if r.c, e = r.b.apply(deltaC()); e != nil {
		panic(e)
	}
	r.hA, r.hB, r.hC = schemaHash(r.a.doc), schemaHash(r.b.doc), schemaHash(r.c.doc)
	r.client = canonicalSchema(clientSchemaInput())
	r.node = canonicalSchema(nodeSchemaInput())
	for _, s := range [][]any{r.client, r.node} {
		if e := validateSchema(s); e != nil {
			panic(e)
		}
	}
	r.clientHash, r.nodeHash = schemaHash(r.client), schemaHash(r.node)
	schemaRes = r
	return r
}

func facetHashes(doc []any) []any {
	out := []any{}
	for _, p := range canonicalSchema(doc)[3].([]any) {
		pd := p.([]any)
		out = append(out, o("facet_id", pd[pID], "facet_name", pd[pName], "facet_hash", hx(facetHash(pd))))
	}
	return out
}

func schemaVectors() O {
	r := schemas()
	var vs []any
	add := func(v O) { vs = append(vs, v) }

	facetVec := func(name, desc string, p []any) {
		if _, e := validateFacet(p); e != nil {
			panic(e)
		}
		c := canonicalFacet(p)
		hb := enc(facetHashInput(p))
		add(o("name", name, "description", desc, "spec", "6.2, 6.6", "type", "facet",
			"input", tj(p), "canonical", tj(c), "canonical_cbor", hx(enc(c)),
			"hash_input_diag", diag(hb), "hash_input_cbor", hx(hb), "facet_hash", hx(facetHash(p))))
	}
	facetVec("facet/sparrow-web", "Facet 1, sparrow.web (section 9.4): service 0 Client, notification method 0 moduleRejected with input [0, 6] and output unit. Every web-profile server includes it.", webFacet())
	facetVec("facet/acme-notes", "Facet 16 'acme.notes': a struct with a tombstoned field (tag 5, flag 0x4) and a deprecated field, a sparse struct, an enum, a union, an alias, two services, method flags incl. 0x8 and 0x10, sigils of all three kinds, retired IDs. Input unsorted.", notesV1())
	facetVec("facet/acme-charts", "Facet 17 'acme.charts': implements interface acme.charts.Renderer under its own names and annotations, adds a type and a service of its own, and ships a signed web module in its web.modules annotation.", chartsV1())

	iface := rendererIface()
	ic := canonicalIface(iface)
	add(o("name", "interface/acme-charts-renderer", "description", "Interface acme.charts.Renderer 1.0.0: one service and exactly the types and sigils it reaches. Its hash covers the canonical interface (names included).",
		"spec", "6.5, 6.6", "type", "interface", "input", tj(iface), "canonical", tj(ic), "canonical_cbor", hx(enc(ic)),
		"hash", hx(ifaceHash(iface)), "expected_valid", true))
	badIface := rendererIface()
	badIface[2] = append(badIface[2].([]any), structDef(90, "Unused", list(field(0, "x", tString, 0, nil)), 0, nil))
	if e := validateIface(badIface); e == nil || e.Code != "interface_not_closed" {
		panic(fmt.Sprint("bad interface: ", e))
	}
	add(o("name", "interface/invalid-not-closed", "description", "An interface with a type its services never reach. An interface contains exactly the types and sigils its services reach (section 6.5).",
		"spec", "6.5", "type", "interface", "input", tj(badIface), "expected_valid", false, "expected_error", "interface_not_closed"))

	dupIface := rendererIface()
	dupIface[4].([]any)[0].([]any)[1] = "ChartKind.line"
	if e := validateIface(dupIface); e == nil || e.Code != "duplicate_sigil_name" {
		panic(fmt.Sprint("duplicate sigil name interface: ", e))
	}
	add(o("name", "interface/invalid-duplicate-sigil-name", "description", "acme.charts.Renderer with its error sigil 66 renamed 'ChartKind.line', the name of enum value sigil 64. Sigil names MUST be unique within a facet or interface (6.5).",
		"spec", "6.5", "type", "interface", "input", tj(dupIface), "expected_valid", false, "expected_error", "duplicate_sigil_name"))

	// References inside tombstones do not count towards reachability (6.5).
	withTombstone := func(defineLegacy bool) []any {
		i := rendererIface()
		for _, t := range i[2].([]any) {
			if num(t.([]any)[1]) == 64 {
				t.([]any)[3] = append(t.([]any)[3].([]any), field(3, "legacy", 90, ffOptional|ffRemoved, nil))
			}
		}
		if defineLegacy {
			i[2] = append(i[2].([]any), structDef(90, "LegacyStyle", list(field(0, "css", tString, 0, nil)), 0, nil))
		}
		return i
	}
	tsIface := withTombstone(false)
	if e := validateIface(tsIface); e != nil {
		panic(e)
	}
	tsc := canonicalIface(tsIface)
	add(o("name", "interface/tombstone-reference-not-counted", "description", "acme.charts.Renderer with a tombstoned field ChartSpec.legacy (tag 3, flags 0x5) whose type 90 the interface does not contain. References inside tombstones are not checked (6.6 rule 3) and do not count when deciding what the services reach (6.5), so the interface is valid and closed without type 90.",
		"spec", "6.5, 6.6", "type", "interface", "input", tj(tsIface), "canonical", tj(tsc), "canonical_cbor", hx(enc(tsc)),
		"hash", hx(ifaceHash(tsIface)), "expected_valid", true))
	tsBad := withTombstone(true)
	if e := validateIface(tsBad); e == nil || e.Code != "interface_not_closed" {
		panic(fmt.Sprint("tombstone interface: ", e))
	}
	add(o("name", "interface/invalid-reached-only-through-tombstone", "description", "The same interface also defining type 90, which only the tombstone ChartSpec.legacy refers to. A reference inside a tombstone does not reach anything, so type 90 is not reached and the interface is not closed (6.5).",
		"spec", "6.5", "type", "interface", "input", tj(tsBad), "expected_valid", false, "expected_error", "interface_not_closed"))

	// Conformance.
	namesOnly := func() []any {
		i := canonicalIface(rendererIface())
		types := deepCopy(i[2]).([]any)
		for _, t := range types {
			td := t.([]any)
			td[2] = "Renamed" + td[2].(string)
			td[len(td)-1] = ann{"doc": "renamed"}
			if num(td[0]) == 0 {
				for _, f := range td[3].([]any) {
					f.([]any)[1] = "f_" + f.([]any)[1].(string)
				}
			}
		}
		svcs := deepCopy(i[3]).([]any)
		for _, s := range svcs {
			sd := s.([]any)
			sd[1] = "Other" + sd[1].(string)
			for _, m := range sd[2].([]any) {
				m.([]any)[1] = "renamedMethod"
				m.([]any)[6] = ann{"auth.hint": "anything"}
			}
		}
		sigs := deepCopy(i[4]).([]any)
		for _, s := range sigs {
			s.([]any)[1] = "sig." + s.([]any)[1].(string)
		}
		return facetDoc(20, "acme.altcharts", "3.2.0", types, svcs, sigs, ifaceHash(rendererIface()), nil, ann{"doc": "differs only in names and annotations"})
	}
	conf := []struct {
		name, desc string
		facet      []any
		want       []any
	}{
		{"conformance/acme-charts", "Facet acme.charts conforms: same IDs and wire shapes, different names and annotations, extra type 80 and service 1.", chartsV1(), nil},
		{"conformance/names-and-annotations-only", "A facet that differs from the interface only in names and annotations conforms (byte comparison of wire shapes).", namesOnly(), nil},
		{"conformance/field-type-differs", "DataSeries.values is [0, uint] instead of [0, int]: type 66 does not conform.",
			chartsFacet(chartsOpts{id: 21, name: "acme.badcharts", version: "1.0.0", pointsType: tList(tUint), implements: true}), []any{spType, 66}},
		{"conformance/extra-method-in-service", "The facet adds a method (2, drawPng) to the interface's service 0. A service's wire shape leaves out its method list and each interface method is compared on its own, so the facet conforms.",
			chartsFacet(chartsOpts{id: 21, name: "acme.badcharts", version: "1.0.0", extraMethod: true, implements: true}), nil},
		{"conformance/hint-flags-differ", "Method draw is not flagged idempotent (0x1) and field heading is flagged deprecated (0x2). Hint flags are cleared in wire shapes, so the facet conforms.",
			chartsFacet(chartsOpts{id: 21, name: "acme.badcharts", version: "1.0.0", notIdem: true, deprecate: true, implements: true}), nil},
		{"conformance/method-output-differs", "Method draw returns string instead of bytes: method 0 does not conform.",
			chartsFacet(chartsOpts{id: 21, name: "acme.badcharts", version: "1.0.0", drawOutput: tString, implements: true}), []any{spMethod, 0}},
		{"conformance/method-in-other-service", "Method draw sits in service 1 instead of the interface's service 0. Service 0 itself matches, but its method 0 is missing.",
			chartsFacet(chartsOpts{id: 21, name: "acme.badcharts", version: "1.0.0", moveDraw: true, implements: true}), []any{spMethod, 0}},
	}
	for _, c := range conf {
		if _, e := validateFacet(c.facet); e != nil {
			panic(e)
		}
		got := conforms(c.facet, iface)
		if (got == nil) != (c.want == nil) || (got != nil && fmt.Sprint(got) != fmt.Sprint(c.want)) {
			panic(fmt.Sprintf("%s: conforms gave %v, want %v", c.name, got, c.want))
		}
		var mismatch any
		if got != nil {
			mismatch = got
		}
		add(o("name", c.name, "description", c.desc, "spec", "6.5", "type", "conformance",
			"interface", "interface/acme-charts-renderer", "facet", tj(c.facet),
			"expected_conforms", got == nil, "first_mismatch", mismatch))
	}

	schemaVec := func(name, desc string, input []any) {
		if e := validateSentSchema(input); e != nil {
			panic(fmt.Sprint(name, ": ", e))
		}
		c := canonicalSchema(input)
		hi := schemaHashInput(input)
		hb := enc(hi)
		add(o("name", name, "description", desc, "spec", "6.2, 6.6", "type", "schema",
			"input", tj(input), "canonical", tj(c), "canonical_cbor", hx(enc(c)), "canonical_length", len(enc(c)),
			"facet_hashes", facetHashes(input),
			"hash_input", tj(hi), "hash_input_diag", diag(hb), "hash_input_cbor", hx(hb), "hash", hx(schemaHash(input))))
	}
	schemaVec("schema/server-base", "Server schema 'acme.host' with facets 1 (sparrow.web), 16 (acme.notes) and 17 (acme.charts), listed by ID as 6.1 requires (their contents unsorted), and top-level web.* annotations (web.apply, web.keys with the acme certificate, web.revoked). The schema hash covers [format, name, version, [* [facet_id, facet_name, facet_hash]], annotations].", serverSchemaInput())
	schemaVec("schema/client", "Client schema as sent in Hello.client_schema.", clientSchemaInput())
	schemaVec("schema/node-acme-charts", "The schema node 'acme.charts' publishes on its own link: the acme.charts facet under node-local facet ID 16. Its facet hash equals that of facet 17 in schema/server-base.", nodeSchemaInput())

	scenarioSchemaVectors(add, schemaVec)

	unsorted := serverSchemaInput()
	ps := unsorted[3].([]any)
	unsorted[3] = list(ps[2], ps[1], ps[0])
	e := validateSentSchema(unsorted)
	if e == nil || e.Code != "facets_not_sorted" || validateSchema(unsorted) != nil {
		panic(fmt.Sprint("facets order: ", e))
	}
	add(o("name", "schema/sent-facets-out-of-order", "description", "schema/server-base with its facets listed as 17, 16, 1. A schema lists its facets sorted by ID (6.1), and a receiver checks the rules of 6.1 (6.6 rule 3), so as a received document it is invalid. Its contents are otherwise valid, and canonicalisation for hashing would sort it (the hash equals schema/server-base's).",
		"spec", "6.1, 6.6", "type", "schema_sent", "input", tj(unsorted), "expected_valid", false, "expected_error", "facets_not_sorted",
		"hash_if_canonicalised", hx(schemaHash(unsorted))))

	renamedWeb := serverSchemaInput()
	renamedWeb[3].([]any)[0].([]any)[pName] = "acme.web"
	if e := validateSentSchema(renamedWeb); e == nil || e.Code != "facet1_mismatch" || hx(facetHash(renamedWeb[3].([]any)[0].([]any))) != hx(facetHash(webFacet())) {
		panic(fmt.Sprint("facet 1 renamed: ", e))
	}
	add(o("name", "schema/invalid-facet1-renamed", "description", "schema/server-base with facet 1 named 'acme.web' instead of 'sparrow.web'. Its facet hash still equals that of sparrow.web (names are not hashed), but facet 1 MUST match its definition by name and facet hash (6.1), so the schema is invalid.",
		"spec", "6.1, 9.4", "type", "schema_invalid", "input", tj(renamedWeb), "facet_hash", hx(facetHash(webFacet())), "expected_valid", false, "expected_error", "facet1_mismatch"))

	// Facet hash invariance under rename and re-id.
	pa := notesV1()
	pb := notesV1()
	pb[pID], pb[pName] = 42, "hub-b/acme.notes"
	sa := schemaDoc("hub-a", "1.0.0", list(pa), nil)
	sb := schemaDoc("hub-a", "1.0.0", list(pb), nil)
	if hx(facetHash(pa)) != hx(facetHash(pb)) || hx(schemaHash(sa)) == hx(schemaHash(sb)) {
		panic("facet hash invariance")
	}
	add(o("name", "schema/facet-hash-invariance", "description", "The same facet listed as 16 'acme.notes' and as 42 'hub-b/acme.notes' (an imported name, section 10.8): identical facet hash, different schema hashes.",
		"spec", "6.6, 10.8", "type", "facet_hash_invariance",
		"schema_a", tj(sa), "schema_b", tj(sb),
		"facet_hash", hx(facetHash(pa)), "schema_hash_a", hx(schemaHash(sa)), "schema_hash_b", hx(schemaHash(sb))))

	// Deltas.
	type dv struct {
		name, desc, from string
		st               *schemaState
		epoch            int
		delta            []any
	}
	for _, d := range []dv{
		{"schema/delta-1-replace-facet", "Epoch 1: replace facet 16 with compatible version 1.1.0: adds a sigil, an enum value, a struct, a method and an optional field; removes method 113 and sigil 81 (both now in retired); tombstones union variant 2 (flag 0x4). Also sets the schema version.",
			"schema/server-base", r.base, 1, deltaA()},
		{"schema/delta-2-new-major", "Epoch 2: acme.charts moves to major version 2, which is a new facet: remove facet 17 and add facet 18 (no longer implements the interface). Replace top-level annotations.",
			"schema/delta-1-replace-facet", r.a, 2, deltaB()},
		{"schema/delta-3-readd-facet", "Epoch 3: remove facet 18 and bring facet 17 back as acme.charts 1.0.1, a compatible successor of the 1.0.0 the session last saw (allowed, section 6.1).",
			"schema/delta-2-new-major", r.b, 3, deltaC()},
	} {
		res, e := d.st.apply(d.delta)
		if e != nil {
			panic(e)
		}
		h := schemaHash(res.doc)
		upd := []any{3, d.epoch, h, d.delta}
		ub := enc(upd)
		add(o("name", d.name, "description", d.desc, "spec", "6.6", "type", "delta",
			"from", d.from, "from_hash", hx(schemaHash(d.st.doc)), "epoch", d.epoch, "delta", tj(d.delta),
			"expected_valid", true, "removed_facet_ids_after", res.removedIDs(),
			"canonical_cbor", hx(enc(res.doc)), "facet_hashes", facetHashes(res.doc), "hash", hx(h),
			"schema_update", o("message", tj(upd), "diag", diag(ub), "cbor", hx(ub))))
	}

	mod := func(f func(p []any)) []any { p := notesV11(); p[pVersion] = "1.2.0"; f(p); return p }
	adminSvc := func(p []any) []any {
		for _, s := range p[pServices].([]any) {
			if num(s.([]any)[0]) == 1 {
				return s.([]any)
			}
		}
		panic("no admin")
	}
	noteField := func(p []any, typeID int64, tag int64) []any {
		for _, t := range p[pTypes].([]any) {
			if num(t.([]any)[1]) == typeID {
				for _, f := range t.([]any)[3].([]any) {
					if num(f.([]any)[0]) == tag {
						return f.([]any)
					}
				}
			}
		}
		panic("no such field")
	}
	notesSvc := func(p []any) []any {
		for _, s := range p[pServices].([]any) {
			if num(s.([]any)[0]) == 0 {
				return s.([]any)
			}
		}
		panic("no notes")
	}
	invalid := []struct {
		name, desc, from, code string
		st                     *schemaState
		delta                  []any
	}{
		{"schema/delta-invalid-incompatible-replace", "Replace facet 16 with 1.2.0 (same major) where Note.updated (tag 4) changes type from timestamp to uint. Not a compatible change (section 6.7).",
			"schema/delta-1-replace-facet", "incompatible_change", r.a, []any{[]any{0, mod(func(p []any) {
				for _, t := range p[pTypes].([]any) {
					if num(t.([]any)[1]) == tyNote {
						for _, f := range t.([]any)[3].([]any) {
							if num(f.([]any)[0]) == 4 {
								f.([]any)[2] = tUint
							}
						}
					}
				}
			})}}},
		{"schema/delta-invalid-reuse-retired", "Replace facet 16 with a version that defines method 113 again, although [2, 113] is in its retired list.",
			"schema/delta-1-replace-facet", "retired_id_reused", r.a, []any{[]any{0, mod(func(p []any) {
				s := adminSvc(p)
				s[2] = append(s[2].([]any), method(113, "touch", tUnit, tUnit, nil, fNotification, nil))
			})}}},
		{"schema/delta-invalid-cross-facet-reference", "Replace facet 16 with a version whose new struct references TypeId 80, which exists only in facet 17. No reference crosses a facet (section 6.1): dangling.",
			"schema/delta-1-replace-facet", "dangling_reference", r.a, []any{[]any{0, mod(func(p []any) {
				p[pTypes] = append(p[pTypes].([]any), structDef(76, "Styled", list(field(0, "theme", 80, 0, nil)), 0, nil))
			})}}},
		{"schema/delta-invalid-dropped-not-retired", "Replace facet 16 with a version that drops method 105 without listing [2, 105] in retired (section 6.6 rule 2).",
			"schema/delta-1-replace-facet", "dropped_id_not_retired", r.a, []any{[]any{0, mod(func(p []any) {
				s := notesSvc(p)
				ms := []any{}
				for _, m := range s[2].([]any) {
					if num(m.([]any)[0]) != 105 {
						ms = append(ms, m)
					}
				}
				s[2] = ms
			})}}},
		{"schema/delta-invalid-facet-renamed", "Replace facet 16 with a facet named 'acme.memos'. Renaming a facet is not allowed (section 6.7).",
			"schema/delta-1-replace-facet", "facet_renamed", r.a, []any{[]any{0, mod(func(p []any) { p[pName] = "acme.memos" })}}},
		{"schema/delta-invalid-major-in-place", "Replace facet 16 in place with version 2.0.0. A new major version is a new facet (section 10.3), so an in-place replace across majors is rejected.",
			"schema/delta-1-replace-facet", "major_version_changed", r.a, []any{[]any{0, mod(func(p []any) { p[pVersion] = "2.0.0" })}}},
		{"schema/delta-invalid-float", "Top-level annotations containing a float. Canonical data MUST NOT contain floats (section 3.2).",
			"schema/delta-1-replace-facet", "float_in_canonical_data", r.a, []any{[]any{2, ann{"web.apply": "hot", "ui.scale": 1.5}}}},
		{"schema/delta-invalid-reserved-facet-id", "Add a facet with ID 5. Facet IDs 0 and 2-15 MUST NOT appear (6.1).",
			"schema/delta-1-replace-facet", "reserved_facet_id", r.a, []any{[]any{0, facetDoc(5, "acme.extra", "1.0.0", nil, nil, nil, nil, nil, nil)}}},
		{"schema/delta-invalid-facet-name-non-ascii", "Add a facet named 'acme.caf\u00e9'. Facet names match [a-z0-9-]+(\\.[a-z0-9-]+)*, ASCII only (6.1).",
			"schema/delta-1-replace-facet", "invalid_name", r.a, []any{[]any{0, facetDoc(19, "acme.caf\u00e9", "1.0.0", nil, nil, nil, nil, nil, nil)}}},
		{"schema/delta-invalid-facet-name-uppercase", "Add a facet named 'Acme.Tools': upper case is outside the facet-name grammar.",
			"schema/delta-1-replace-facet", "invalid_name", r.a, []any{[]any{0, facetDoc(19, "Acme.Tools", "1.0.0", nil, nil, nil, nil, nil, nil)}}},
		{"schema/delta-invalid-type-name-non-ascii", "Add a facet whose struct is named 'Gr\u00fc\u00dfe'. Type names are ASCII (6.1).",
			"schema/delta-1-replace-facet", "invalid_name", r.a, []any{[]any{0, facetDoc(19, "acme.greetings", "1.0.0", list(structDef(64, "Gr\u00fc\u00dfe", list(field(0, "text", tString, 0, nil)), 0, nil)), nil, nil, nil, nil, nil)}}},
		{"schema/delta-invalid-variant-name-non-ascii", "Add a facet whose union has a variant named 'gel\u00f6scht'. Variant names are ASCII (6.1).",
			"schema/delta-1-replace-facet", "invalid_name", r.a, []any{[]any{0, facetDoc(19, "acme.events", "1.0.0", list(unionDef(64, "Event", list(variant(0, "gel\u00f6scht", tUnit, 0, nil)), nil)), nil, nil, nil, nil, nil)}}},
		{"schema/delta-invalid-facet1-mismatch", "Replace facet 1 with sparrow.web version 1.0.1. Facet 1 MUST match its definition exactly, by facet hash (6.1).",
			"schema/delta-1-replace-facet", "facet1_mismatch", r.a, []any{[]any{0, func() []any { p := webFacet(); p[pVersion] = "1.0.1"; return p }()}}},
		{"schema/delta-invalid-required-made-optional", "Replace facet 16 with 1.2.0 where the required field Note.title (tag 1) becomes optional (flag 0x1). Making a required field optional is not allowed: older readers still require it (6.7).",
			"schema/delta-1-replace-facet", "incompatible_change", r.a, []any{[]any{0, mod(func(p []any) {
				noteField(p, tyNote, 1)[3] = ffOptional
			})}}},
		{"schema/delta-invalid-tombstone-changes-type", "Replace facet 16 with 1.2.0 where the optional field Note.color (tag 6) becomes a tombstone (flags 0x5) and at the same time changes its type from [2, 66] to [2, 6]. A tombstone keeps its last definition (6.7).",
			"schema/delta-1-replace-facet", "incompatible_change", r.a, []any{[]any{0, mod(func(p []any) {
				f := noteField(p, tyNote, 6)
				f[2], f[3] = tOpt(tString), ffOptional|ffRemoved
			})}}},
		{"schema/delta-invalid-existing-tombstone-changes-type", "Replace facet 16 with 1.2.0 where the variant Change.cleared (tag 2), already a tombstone in 1.1.0, changes its type from unit to string. A tombstone keeps its last definition and never changes again, apart from its name and annotations (6.7).",
			"schema/delta-1-replace-facet", "incompatible_change", r.a, []any{[]any{0, mod(func(p []any) {
				noteField(p, tyChange, 2)[2] = tString
			})}}},
		{"schema/delta-invalid-tombstone-flags-changed", "Replace facet 16 with 1.2.0 where the tombstone Note.legacyLabel (tag 5, flags 0x5) also gets the deprecated flag (flags 0x7). A tombstone never changes again, apart from its name and annotations (6.7).",
			"schema/delta-1-replace-facet", "incompatible_change", r.a, []any{[]any{0, mod(func(p []any) {
				noteField(p, tyNote, 5)[3] = ffOptional | ffRemoved | ffDeprecated
			})}}},
		{"schema/delta-invalid-notification-output", "Replace facet 16 with 1.2.0 that adds method 106 'ping' flagged notification (0x2) with output bool. A notification MUST have output unit (6.4).",
			"schema/delta-1-replace-facet", "invalid_notification", r.a, []any{[]any{0, mod(func(p []any) {
				s := notesSvc(p)
				s[2] = append(s[2].([]any), method(106, "ping", tUnit, tBool, nil, fNotification, nil))
			})}}},
		{"schema/delta-invalid-notification-byte-stream", "Replace facet 16 with 1.2.0 that adds method 106 'drop' flagged notification (0x2, and 0x8 as its input reaches [4]) whose input is an Attachment, which has a [4] field. A notification MUST NOT have [4] in its input (6.4, 7.3).",
			"schema/delta-1-replace-facet", "invalid_notification", r.a, []any{[]any{0, mod(func(p []any) {
				s := notesSvc(p)
				s[2] = append(s[2].([]any), method(106, "drop", tyAttachment, tUnit, nil, fNotification|fInputEnd, nil))
			})}}},
		{"schema/delta-invalid-reserved-type-id", "Replace facet 16 with 1.2.0 that adds a struct whose field has type 12. TypeIds 12-31 are reserved for built-ins of later core versions, so a schema that uses them is invalid (6.4).",
			"schema/delta-1-replace-facet", "reserved_type_id", r.a, []any{[]any{0, mod(func(p []any) {
				p[pTypes] = append(p[pTypes].([]any), structDef(76, "Future", list(field(0, "x", 12, 0, nil)), 0, nil))
			})}}},
		{"schema/delta-invalid-duplicate-sigil-name", "Replace facet 16 with 1.2.0 that adds an enum Shade (type 76) whose one value, sigil 84, is named 'Color.red' like sigil 70. Sigil names MUST be unique within a facet; an enum value's sigil is named after its enum, so Shade's red would be 'Shade.red' (6.5).",
			"schema/delta-1-replace-facet", "duplicate_sigil_name", r.a, []any{[]any{0, mod(func(p []any) {
				p[pTypes] = append(p[pTypes].([]any), enumDef(76, "Shade", list(84), nil))
				p[pSigils] = append(p[pSigils].([]any), sigil(84, "Color.red", 0, nil))
			})}}},
		{"schema/delta-invalid-sigil-in-two-enums", "Replace facet 16 with 1.2.0 that adds an enum Shade (type 76) whose one value is sigil 70, already the value Color.red of enum Color. A kind-0 sigil is a value of exactly one enum (6.5).",
			"schema/delta-1-replace-facet", "sigil_in_two_enums", r.a, []any{[]any{0, mod(func(p []any) {
				p[pTypes] = append(p[pTypes].([]any), enumDef(76, "Shade", list(70), nil))
			})}}},
		{"schema/delta-invalid-readd-renamed", "Facet 17 was removed in epoch 2. Bringing ID 17 back with a different name ('acme.maps') is not allowed (section 6.1).",
			"schema/delta-2-new-major", "removed_facet_mismatch", r.b, []any{[]any{0, chartsFacet(chartsOpts{id: facetCharts, name: "acme.maps", version: "1.0.0", noExtras: true})}}},
	}
	for _, d := range invalid {
		_, e := d.st.apply(d.delta)
		if e == nil || e.Code != d.code {
			panic(fmt.Sprintf("%s: expected %s, got %v", d.name, d.code, e))
		}
		add(o("name", d.name, "description", d.desc, "spec", "6.1, 6.6, 6.7", "type", "delta",
			"from", d.from, "from_hash", hx(schemaHash(d.st.doc)), "delta", tj(d.delta),
			"expected_valid", false, "expected_error", d.code, "error_detail", e.Detail))
	}
	return o("area", "schema", "vectors", vs)
}
