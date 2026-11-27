package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// The sparrow.hub.admin v1 interface (spec/hub-admin.md, section 5).

const (
	adConfig = 64 + iota
	adNodeConfig
	adLink
	adDial
	adSnapshot
	adCommitRequest
	adValidateRequest
	adProblem
	adProblems
	adSecret
	adNames
	adEvent
	adRevisionEvent
	adRevisionState
	adNodeEvent
	adNodeState
)

const (
	sgPending = 64 + iota
	sgConfirmed
	sgRolledBack
	sgConnected
	sgOffline
	sgDisabled
	sgRemoved
)

// adminTypes are types 64-79 of section 5.1. An optional field has flag 0x1
// and its plain type (hub-admin 5).
func adminTypes() []any {
	of := func(tag int, name string, t any) []any { return field(tag, name, t, ffOptional, nil) }
	rf := func(tag int, name string, t any) []any { return field(tag, name, t, 0, nil) }
	return list(
		structDef(adConfig, "Config", list(
			rf(0, "nodes", tMap(tString, adNodeConfig)),
			of(1, "defaults", tMap(tBytes, tString)),
			of(2, "extensions", tMap(tString, tBytes)),
		), 0, nil),
		structDef(adNodeConfig, "NodeConfig", list(
			rf(0, "link", adLink),
			of(1, "peer", tBool),
			of(2, "enabled", tBool),
			of(3, "extensions", tMap(tString, tBytes)),
		), 0, nil),
		unionDef(adLink, "Link", list(
			variant(0, "dial", adDial, 0, nil),
			variant(1, "credential", tString, 0, nil),
		), nil),
		structDef(adDial, "Dial", list(rf(0, "url", tString), rf(1, "pin", tBytes), rf(2, "credential", tString)), 0, nil),
		structDef(adSnapshot, "Snapshot", list(
			rf(0, "revision", tUint), rf(1, "config", adConfig), rf(2, "state", adRevisionState), of(3, "confirmInMs", tUint),
		), 0, nil),
		structDef(adCommitRequest, "CommitRequest", list(rf(0, "base", tUint), rf(1, "config", adConfig), rf(2, "confirmWithinMs", tUint)), 0, nil),
		structDef(adValidateRequest, "ValidateRequest", list(rf(0, "base", tUint), rf(1, "config", adConfig)), 0, nil),
		structDef(adProblem, "Problem", list(rf(0, "path", tList(tString)), rf(1, "message", tString)), 0, nil),
		aliasDef(adProblems, "Problems", tList(adProblem), nil),
		structDef(adSecret, "Secret", list(rf(0, "name", tString), rf(1, "value", tBytes)), 0, nil),
		aliasDef(adNames, "Names", tList(tString), nil),
		unionDef(adEvent, "Event", list(
			variant(0, "snapshot", adSnapshot, 0, nil),
			variant(1, "revision", adRevisionEvent, 0, nil),
			variant(2, "node", adNodeEvent, 0, nil),
		), nil),
		structDef(adRevisionEvent, "RevisionEvent", list(rf(0, "revision", tUint), rf(1, "state", adRevisionState), of(2, "confirmInMs", tUint)), 0, nil),
		enumDef(adRevisionState, "RevisionState", list(sgPending, sgConfirmed, sgRolledBack), nil),
		structDef(adNodeEvent, "NodeEvent", list(rf(0, "node", tString), rf(1, "revision", tUint), rf(2, "state", adNodeState), of(3, "message", tString)), 0, nil),
		enumDef(adNodeState, "NodeState", list(sgConnected, sgOffline, sgDisabled, sgRemoved), nil),
	)
}

func adminSigils() []any {
	return list(
		sigil(sgPending, "RevisionState.pending", 0, nil), sigil(sgConfirmed, "RevisionState.confirmed", 0, nil),
		sigil(sgRolledBack, "RevisionState.rolledBack", 0, nil),
		sigil(sgConnected, "NodeState.connected", 0, nil), sigil(sgOffline, "NodeState.offline", 0, nil),
		sigil(sgDisabled, "NodeState.disabled", 0, nil), sigil(sgRemoved, "NodeState.removed", 0, nil),
	)
}

// adminMethods are the methods of service 0 Admin (section 5.2). Every error
// the table names is a core status code, which `errors` never lists
// (6.4), so every errors list is empty.
func adminMethods(an ann) []any {
	m := func(id int, name string, in, out any, flags int) []any {
		return method(id, name, in, out, nil, flags, an)
	}
	return list(
		m(0, "get", tUnit, adSnapshot, fIdempotent),
		m(1, "validate", adValidateRequest, adProblems, fIdempotent),
		m(2, "commit", adCommitRequest, tUint, 0),
		m(3, "confirm", tUint, tUnit, fIdempotent),
		m(4, "rollback", tUint, tUint, 0),
		m(5, "setSecret", adSecret, tUnit, 0),
		m(6, "deleteSecret", tString, tUnit, fIdempotent),
		m(7, "listSecrets", tUnit, adNames, fIdempotent),
		m(8, "watch", tUnit, tStream(adEvent), fOutputEnd),
	)
}

// adminIface: the interface carries no annotations; the facet adds the
// sparrow.level hint (section 1), which conformance ignores.
func adminIface() []any {
	return ifaceDoc("sparrow.hub.admin", "1.0.0", adminTypes(),
		list(service(0, "Admin", adminMethods(nil), nil)), adminSigils())
}

func adminFacet(id int) []any {
	return facetDoc(id, "sparrow.hub.admin", "1.0.0", adminTypes(),
		list(service(0, "Admin", adminMethods(ann{"sparrow.level": "manage"}), nil)), adminSigils(),
		ifaceHash(adminIface()), nil, nil)
}

// Example values.
var adminPin = func() []byte {
	s := sha256.Sum256([]byte("TEST-ONLY SubjectPublicKeyInfo of notes.example.com"))
	return s[:]
}()

func adminExampleConfig() []any {
	policy := enc([]any{[]any{"user:alice", "acme.charts", "use"}, []any{"group:ops", "sparrow.hub.admin", "manage"}})
	return []any{
		map[string]any{
			"acme.charts": []any{[]any{1, "charts-link"}},
			"acme.notes":  []any{[]any{0, []any{"https://notes.example.com/sparrow/wt", adminPin, "hub-to-notes"}}},
			"acme.sensor": []any{[]any{1, "sensor-link"}},
			"hub-b":       []any{[]any{1, "hub-b-link"}, true},
			"acme.old":    []any{[]any{1, "old-link"}, nil, false},
		},
		map[any]any{cbor.ByteString(ifaceHash(rendererIface())): "acme.charts"},
		map[string]any{"ref.policy": policy},
	}
}

func adminVectors() O {
	var vs []any
	add := func(v O) { vs = append(vs, v) }

	iface := adminIface()
	if e := validateIface(iface); e != nil {
		panic(e)
	}
	ic := canonicalIface(iface)
	add(o("name", "admin/interface", "description", "The canonical interface document of sparrow.hub.admin v1 (hub-admin section 5): types 64-79, enum sigils 64-70 (kind 0), service 0 Admin with methods 0-8. Method flags: 0x1 (idempotent) on get, validate, confirm, deleteSecret and listSecrets; 0x10 on watch, whose output is [3, Event]; no other flags. An optional field has flag 0x1 and its plain type. The interface document is named sparrow.hub.admin, version \"1.0.0\", carries no annotations, and its methods list no errors, since every error they use is a core code (hub-admin 5).",
		"spec", "hub-admin 5, core 6.5, 6.6", "type", "interface", "input", tj(iface), "canonical", tj(ic), "canonical_cbor", hx(enc(ic)),
		"hash", hx(ifaceHash(iface)), "expected_valid", true))

	f := adminFacet(20)
	if _, e := validateFacet(f); e != nil {
		panic(e)
	}
	if m := conforms(f, iface); m != nil {
		panic(fmt.Sprint("admin facet does not conform: ", m))
	}
	fc := canonicalFacet(f)
	fhb := enc(facetHashInput(f))
	add(o("name", "admin/facet", "description", "A hub's sparrow.hub.admin facet, version 1.0.0, under facet ID 20 (the hub's choice). It implements admin/interface and adds the hint annotation \"sparrow.level\": \"manage\" to every method (hub-admin section 1); annotations are not part of wire shapes, so it conforms.",
		"spec", "hub-admin 1, core 6.5", "type", "facet",
		"input", tj(f), "canonical", tj(fc), "canonical_cbor", hx(enc(fc)),
		"hash_input_diag", diag(fhb), "hash_input_cbor", hx(fhb), "facet_hash", hx(facetHash(f)),
		"interface", "admin/interface", "expected_conforms", true))

	// Values encoded with the interface's types.
	cfg := adminExampleConfig()
	valueVec := func(name, desc string, typeID int, logical string, v any) {
		b := enc(v)
		add(o("name", name, "description", desc, "spec", "hub-admin 3, 5.1, core 3.4", "type", "admin_value",
			"interface", "admin/interface", "type_id", typeID, "type_name", typeName(iface, typeID), "logical", logical,
			"value", tj(v), "diag", diag(b), "cbor", hx(b)))
	}
	valueVec("admin/value/config", "A Config (type 64) with five nodes, each with its Link (field 0, a union): acme.charts dialing in (variant 1, the secret it presents); acme.notes dialed (variant 0, a Dial) at an https URL with a 32-byte pin and the credential secret the hub presents; acme.sensor dialing in; hub-b, a peer hub dialing in; acme.old, disabled. defaults maps the Renderer interface hash to acme.charts, and extensions carries the reference server's ref.policy as an embedded CBOR document. Absent optional fields are null and trailing nulls are omitted.",
		adConfig, "see description", cfg)
	valueVec("admin/value/config-empty", "The document of a hub that was never configured, revision 0: {nodes: {}}, i.e. [{}] (hub-admin 2).", adConfig, "{nodes: {}}", []any{map[string]any{}})
	commit := []any{6, cfg, 30000}
	valueVec("admin/value/commit-request", "CommitRequest (type 69): base revision 6, the Config of admin/value/config, confirmWithinMs 30000.", adCommitRequest, "base 6, config, confirmWithinMs 30000", commit)
	snap := []any{7, cfg, sgPending, 24500}
	valueVec("admin/value/snapshot", "Snapshot (type 68) right after that commit: revision 7, pending (sigil 64), confirmInMs 24500.", adSnapshot, "revision 7, pending, confirmInMs 24500", snap)
	valueVec("admin/value/event-snapshot", "Event (type 75) variant 0: the Snapshot every watch starts with.", adEvent, "snapshot", []any{0, snap})
	valueVec("admin/value/event-rolled-back", "Event variant 1: RevisionEvent revision 7 rolledBack (66), confirmInMs absent.", adEvent, "revision 7 rolledBack", []any{1, []any{7, sgRolledBack}})
	valueVec("admin/value/event-confirmed", "Event variant 1: RevisionEvent revision 8 confirmed (65): the rollback target applied as revision N+1 (hub-admin 2.3).", adEvent, "revision 8 confirmed", []any{1, []any{8, sgConfirmed}})
	valueVec("admin/value/event-node", "Event variant 2: NodeEvent for acme.charts under revision 8, connected (67), no message.", adEvent, "acme.charts connected", []any{2, []any{"acme.charts", 8, sgConnected}})
	valueVec("admin/value/event-node-offline", "Event variant 2: NodeEvent for acme.notes under revision 8, offline (68), with a message.", adEvent, "acme.notes offline", []any{2, []any{"acme.notes", 8, sgOffline, "dial failed: pinned key hash does not match"}})
	problems := []any{
		[]any{[]any{"nodes", "acme.charts", "link", "credential"}, "secret \"charts-link\" is not stored"},
		[]any{[]any{"nodes", "acme.notes", "link", "dial", "pin"}, "Dial.pin must be 32 bytes"},
	}
	valueVec("admin/value/problems", "Problems (type 72, alias of list<Problem>): each Problem.path lists the keys from the document root using the field names of hub-admin section 3, with a union's variant name as one more key (\"link\", then the Link variant \"credential\" or \"dial\", then \"pin\" inside Dial); byte-string map keys would be lowercase hex (hub-admin 5.1).", adProblems, "two problems", problems)

	errMsg := []any{20, 10, 9, "invalid configuration", []any{adProblems, problems}}
	eb := enc(errMsg)
	add(o("name", "admin/commit-invalid", "description", "commit answered with Error(failed_precondition) (status 9) whose details are the dynamic value [72, problems] (hub-admin 5.2, core 8).",
		"spec", "hub-admin 5.2, core 7.2, 8", "type", "message", "kind", 20, "kind_name", "Error", "message", tj(errMsg),
		"diag", diag(eb), "cbor", hx(eb), "length", len(eb), "framed", hx(cat(varint(uint64(len(eb))), eb))))
	return o("area", "admin", "vectors", vs)
}

func typeName(iface []any, id int) string {
	for _, t := range iface[2].([]any) {
		if num(t.([]any)[1]) == int64(id) {
			return t.([]any)[2].(string)
		}
	}
	panic("no type")
}
