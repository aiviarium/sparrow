// Package adminiface defines sparrow.hub.admin v1, the standard hub
// administration interface (spec/hub-admin.md, section 5), as schema
// values: the interface document, the facet a hub publishes for it, its
// type, method and sigil IDs, and the stored-facet key of section 2.1.
//
// The definitions match the vectors in test-vectors/admin.json: every
// constructor returns a fresh copy that callers may modify.
package adminiface

import (
	"sync"

	"github.com/aiviarium/sparrow-rpc/go/schema"
)

// Name is the interface's and the facet's name; Version their version.
const (
	Name    = "sparrow.hub.admin"
	Version = "1.0.0"
)

// TypeIds (section 5.1).
const (
	TypeConfig          uint64 = 64
	TypeNodeConfig      uint64 = 65
	TypeDial            uint64 = 66
	TypeSnapshot        uint64 = 67
	TypeCommitRequest   uint64 = 68
	TypeValidateRequest uint64 = 69
	TypeProblem         uint64 = 70
	TypeProblems        uint64 = 71
	TypeSecret          uint64 = 72
	TypeNames           uint64 = 73
	TypeHashes          uint64 = 74
	TypeEvent           uint64 = 75
	TypeRevisionEvent   uint64 = 76
	TypeRevisionState   uint64 = 77
	TypeNodeEvent       uint64 = 78
	TypeNodeState       uint64 = 79
)

// Field tags of the structs and variant tags of the unions.
const (
	ConfigNodes, ConfigDefaults, ConfigExtensions uint64 = 0, 1, 2

	NodeConfigDial, NodeConfigCredential, NodeConfigFacets  uint64 = 0, 1, 2
	NodeConfigPeer, NodeConfigEnabled, NodeConfigExtensions uint64 = 3, 4, 5

	DialURL, DialPin, DialCredential uint64 = 0, 1, 2

	SnapshotRevision, SnapshotConfig, SnapshotState, SnapshotConfirmInMs uint64 = 0, 1, 2, 3
	CommitBase, CommitConfig, CommitConfirmWithinMs                      uint64 = 0, 1, 2
	ValidateBase, ValidateConfig                                         uint64 = 0, 1
	ProblemPath, ProblemMessage                                          uint64 = 0, 1
	SecretName, SecretValue                                              uint64 = 0, 1

	EventSnapshot, EventRevision, EventNode                             uint64 = 0, 1, 2
	RevisionEventRevision, RevisionEventState, RevisionEventConfirmInMs uint64 = 0, 1, 2
	NodeEventNode, NodeEventRevision, NodeEventState, NodeEventMessage  uint64 = 0, 1, 2, 3
)

// Sigils: the enum values of RevisionState and NodeState, all kind 0.
const (
	SigilPending    uint64 = 64
	SigilConfirmed  uint64 = 65
	SigilRolledBack uint64 = 66
	SigilConnected  uint64 = 67
	SigilOffline    uint64 = 68
	SigilDisabled   uint64 = 69
	SigilRemoved    uint64 = 70
)

// ServiceAdmin is the interface's only service.
const ServiceAdmin uint64 = 0

// MethodIds of service 0 Admin (section 5.2).
const (
	MethodGet          uint64 = 0
	MethodValidate     uint64 = 1
	MethodCommit       uint64 = 2
	MethodConfirm      uint64 = 3
	MethodRollback     uint64 = 4
	MethodSetSecret    uint64 = 5
	MethodDeleteSecret uint64 = 6
	MethodListSecrets  uint64 = 7
	MethodPutFacet     uint64 = 8
	MethodDeleteFacet  uint64 = 9
	MethodListFacets   uint64 = 10
	MethodWatch        uint64 = 11
)

// LevelAnnotation is the hint every method of the facet carries (section 1).
const LevelAnnotation = "sparrow.level"

var (
	named = schema.Named
	list  = schema.List
	mapOf = schema.MapOf
)

// opt is an optional field: flag 0x1 and its plain type (section 5).
func opt(tag uint64, name string, t schema.TypeRef) schema.Field {
	return schema.Field{Tag: tag, Name: name, Type: t, Flags: schema.FieldOptional, Annotations: schema.Annotations{}}
}

func req(tag uint64, name string, t schema.TypeRef) schema.Field {
	return schema.Field{Tag: tag, Name: name, Type: t, Annotations: schema.Annotations{}}
}

func strct(id uint64, name string, fields ...schema.Field) schema.TypeDef {
	return schema.TypeDef{Kind: schema.KindStruct, ID: id, Name: name, Fields: fields, Annotations: schema.Annotations{}}
}

func union(id uint64, name string, variants ...schema.Field) schema.TypeDef {
	return schema.TypeDef{Kind: schema.KindUnion, ID: id, Name: name, Fields: variants, Annotations: schema.Annotations{}}
}

func alias(id uint64, name string, target schema.TypeRef) schema.TypeDef {
	return schema.TypeDef{Kind: schema.KindAlias, ID: id, Name: name, Target: target, Annotations: schema.Annotations{}}
}

func enum(id uint64, name string, values ...uint64) schema.TypeDef {
	return schema.TypeDef{Kind: schema.KindEnum, ID: id, Name: name, Values: values, Annotations: schema.Annotations{}}
}

var (
	tString = named(schema.TypeString)
	tBytes  = named(schema.TypeBytes)
	tUint   = named(schema.TypeUint)
	tBool   = named(schema.TypeBool)
	tUnit   = named(schema.TypeUnit)
)

// Types returns types 64-79. An optional field has flag 0x1 and its plain
// type.
func Types() []schema.TypeDef {
	return []schema.TypeDef{
		strct(TypeConfig, "Config",
			req(0, "nodes", mapOf(tString, named(TypeNodeConfig))),
			opt(1, "defaults", mapOf(tBytes, tString)),
			opt(2, "extensions", mapOf(tString, tBytes))),
		strct(TypeNodeConfig, "NodeConfig",
			opt(0, "dial", named(TypeDial)),
			opt(1, "credential", tString),
			opt(2, "facets", list(tBytes)),
			opt(3, "peer", tBool),
			opt(4, "enabled", tBool),
			opt(5, "extensions", mapOf(tString, tBytes))),
		strct(TypeDial, "Dial", req(0, "url", tString), req(1, "pin", tBytes), req(2, "credential", tString)),
		strct(TypeSnapshot, "Snapshot", req(0, "revision", tUint), req(1, "config", named(TypeConfig)), req(2, "state", named(TypeRevisionState)), opt(3, "confirmInMs", tUint)),
		strct(TypeCommitRequest, "CommitRequest", req(0, "base", tUint), req(1, "config", named(TypeConfig)), req(2, "confirmWithinMs", tUint)),
		strct(TypeValidateRequest, "ValidateRequest", req(0, "base", tUint), req(1, "config", named(TypeConfig))),
		strct(TypeProblem, "Problem", req(0, "path", list(tString)), req(1, "message", tString)),
		alias(TypeProblems, "Problems", list(named(TypeProblem))),
		strct(TypeSecret, "Secret", req(0, "name", tString), req(1, "value", tBytes)),
		alias(TypeNames, "Names", list(tString)),
		alias(TypeHashes, "Hashes", list(tBytes)),
		union(TypeEvent, "Event", req(0, "snapshot", named(TypeSnapshot)), req(1, "revision", named(TypeRevisionEvent)), req(2, "node", named(TypeNodeEvent))),
		strct(TypeRevisionEvent, "RevisionEvent", req(0, "revision", tUint), req(1, "state", named(TypeRevisionState)), opt(2, "confirmInMs", tUint)),
		enum(TypeRevisionState, "RevisionState", SigilPending, SigilConfirmed, SigilRolledBack),
		strct(TypeNodeEvent, "NodeEvent", req(0, "node", tString), req(1, "revision", tUint), req(2, "state", named(TypeNodeState)), opt(3, "message", tString)),
		enum(TypeNodeState, "NodeState", SigilConnected, SigilOffline, SigilDisabled, SigilRemoved),
	}
}

// Sigils returns sigils 64-70, all kind 0 (enum values).
func Sigils() []schema.Sigil {
	names := []string{"pending", "confirmed", "rolledBack", "connected", "offline", "disabled", "removed"}
	out := make([]schema.Sigil, len(names))
	for i, n := range names {
		out[i] = schema.Sigil{ID: SigilPending + uint64(i), Name: n, Kind: schema.SigilEnumValue, Annotations: schema.Annotations{}}
	}
	return out
}

// Methods returns methods 0-11 of service 0, each with the given
// annotations (nil for none). Every error the methods name is a core status
// code, so every errors list is empty.
func Methods(ann schema.Annotations) []schema.Method {
	idem := schema.MethodIdempotent
	m := func(id uint64, name string, in, out schema.TypeRef, flags uint64) schema.Method {
		a := schema.Annotations{}
		for k, v := range ann {
			a[k] = v
		}
		return schema.Method{ID: id, Name: name, Input: in, Output: out, Errors: []uint64{}, Flags: flags, Annotations: a}
	}
	return []schema.Method{
		m(MethodGet, "get", tUnit, named(TypeSnapshot), idem),
		m(MethodValidate, "validate", named(TypeValidateRequest), named(TypeProblems), idem),
		m(MethodCommit, "commit", named(TypeCommitRequest), tUint, 0),
		m(MethodConfirm, "confirm", tUint, tUnit, idem),
		m(MethodRollback, "rollback", tUint, tUint, 0),
		m(MethodSetSecret, "setSecret", named(TypeSecret), tUnit, 0),
		m(MethodDeleteSecret, "deleteSecret", tString, tUnit, idem),
		m(MethodListSecrets, "listSecrets", tUnit, named(TypeNames), idem),
		m(MethodPutFacet, "putFacet", tBytes, tBytes, idem),
		m(MethodDeleteFacet, "deleteFacet", tBytes, tUnit, idem),
		m(MethodListFacets, "listFacets", tUnit, named(TypeHashes), idem),
		m(MethodWatch, "watch", tUnit, schema.Stream(named(TypeEvent)), schema.MethodOutputEnd),
	}
}

// Interface returns the interface document sparrow.hub.admin 1.0.0. It
// carries no annotations; Facet adds the sparrow.level hint.
func Interface() *schema.Interface {
	return &schema.Interface{
		Name:    Name,
		Version: Version,
		Types:   Types(),
		Services: []schema.Service{{
			ID: ServiceAdmin, Name: "Admin", Methods: Methods(nil), Annotations: schema.Annotations{},
		}},
		Sigils: Sigils(),
	}
}

var ifaceHash = sync.OnceValue(func() []byte {
	h, err := Interface().Hash()
	if err != nil {
		panic(err)
	}
	return h
})

// InterfaceHash returns the interface hash, the value of `implements` in
// the facet.
func InterfaceHash() []byte { return append([]byte{}, ifaceHash()...) }

// manage is the CBOR text "manage".
var manage = []byte{0x66, 'm', 'a', 'n', 'a', 'g', 'e'}

// Facet returns the facet a hub publishes under the given facet ID: name
// sparrow.hub.admin, version 1.0.0, implementing Interface, with the hint
// annotation "sparrow.level": "manage" on every method (section 1).
func Facet(id uint64) *schema.Facet {
	return &schema.Facet{
		ID:      id,
		Name:    Name,
		Version: Version,
		Types:   Types(),
		Services: []schema.Service{{
			ID: ServiceAdmin, Name: "Admin",
			Methods:     Methods(schema.Annotations{LevelAnnotation: manage}),
			Annotations: schema.Annotations{},
		}},
		Sigils:      Sigils(),
		Implements:  InterfaceHash(),
		Retired:     []schema.Retired{},
		Annotations: schema.Annotations{},
	}
}

// StoredFacetKey returns the key putFacet returns for a facet: 0x01 ||
// SHA-256 of the canonical facet with its ID set to 0 and its name kept
// (section 2.1). It differs from the facet hash, which blanks the name.
func StoredFacetKey(f *schema.Facet) ([]byte, error) { return f.StoredKey() }
