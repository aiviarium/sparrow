package main

import (
	"crypto/sha256"
	"fmt"
	"sort"
)

// Schema documents are handled as generic CBOR trees ([]any / map[string]any)
// that mirror the CDDL in section 6 one to one.

type ann = map[string]any

func a(m ann) ann {
	if m == nil {
		return ann{}
	}
	return m
}

func list(xs ...any) []any {
	if xs == nil {
		return []any{}
	}
	return xs
}

// type-ref helpers (section 6.3)
func tList(t any) []any   { return []any{0, t} }
func tMap(k, v any) []any { return []any{1, k, v} }
func tOpt(t any) []any    { return []any{2, t} }
func tStream(t any) []any { return []any{3, t} }
func tByteStream() []any  { return []any{4} }

// Built-in TypeIds (section 6.3)
const (
	tUnit = iota
	tBool
	tInt
	tUint
	tFloat32
	tFloat64
	tString
	tBytes
	tTimestamp
	tUUID
	tAny
	tSymbol
)

func structDef(id int, name string, fields []any, flags int, an ann) []any {
	return []any{0, id, name, list(fields...), flags, a(an)}
}
func enumDef(id int, name string, values []any, an ann) []any {
	return []any{1, id, name, list(values...), a(an)}
}
func unionDef(id int, name string, variants []any, an ann) []any {
	return []any{2, id, name, list(variants...), a(an)}
}
func aliasDef(id int, name string, target any, an ann) []any {
	return []any{3, id, name, target, a(an)}
}
func field(tag int, name string, typ any, flags int, an ann) []any {
	return []any{tag, name, typ, flags, a(an)}
}
func variant(tag int, name string, typ any, an ann) []any {
	return []any{tag, name, typ, a(an)}
}
func method(id int, name string, in, out any, errors []any, flags int, an ann) []any {
	return []any{id, name, in, out, list(errors...), flags, a(an)}
}
func service(id int, name string, methods []any, an ann) []any {
	return []any{id, name, list(methods...), a(an)}
}
func sigil(id int, name string, kind int, an ann) []any {
	return []any{id, name, kind, a(an)}
}
func schemaDoc(name, version string, types, services, sigils []any, an ann) []any {
	return []any{1, name, version, list(types...), list(services...), list(sigils...), a(an)}
}

// Method flags (section 6.4)
const (
	fIdempotent   = 0x1
	fNotification = 0x2
	fShared       = 0x4
	fInputEnd     = 0x8
	fOutputEnd    = 0x10
)

func sortByInt(xs []any, key func(any) int64) {
	sort.SliceStable(xs, func(i, j int) bool { return key(xs[i]) < key(xs[j]) })
}
func first(x any) int64  { return num(x.([]any)[0]) }
func second(x any) int64 { return num(x.([]any)[1]) }
func self(x any) int64   { return num(x) }

// canonical returns the canonical form of a schema (section 6.6) as a new
// tree. Retired definitions are never present in the trees this program
// keeps (retiring removes them), so only sorting is needed here.
func canonical(s []any) []any {
	c := deepCopy(s).([]any)
	types := c[3].([]any)
	sortByInt(types, second)
	for _, t := range types {
		td := t.([]any)
		switch num(td[0]) {
		case 0:
			sortByInt(td[3].([]any), first)
		case 1:
			sortByInt(td[3].([]any), self)
		case 2:
			sortByInt(td[3].([]any), first)
		}
	}
	services := c[4].([]any)
	sortByInt(services, first)
	for _, sv := range services {
		ms := sv.([]any)[2].([]any)
		sortByInt(ms, first)
		for _, m := range ms {
			sortByInt(m.([]any)[4].([]any), self)
		}
	}
	sortByInt(c[5].([]any), first)
	return c
}

func schemaHash(canon []any) []byte {
	sum := sha256.Sum256(enc(canon))
	return append([]byte{0x01}, sum[:]...)
}

// ---------------------------------------------------------------------------
// Delta application (section 6.6). See test-vectors/README.md, "Assumptions".
// ---------------------------------------------------------------------------

type schemaState struct {
	doc     []any
	retired [4]map[int64]bool // 0 type, 1 method, 2 sigil, 3 service
}

func newState(doc []any) *schemaState {
	st := &schemaState{doc: canonical(doc)}
	for i := range st.retired {
		st.retired[i] = map[int64]bool{}
	}
	return st
}

func (st *schemaState) clone() *schemaState {
	n := &schemaState{doc: deepCopy(st.doc).([]any)}
	for i := range st.retired {
		n.retired[i] = map[int64]bool{}
		for k := range st.retired[i] {
			n.retired[i][k] = true
		}
	}
	return n
}

type deltaError struct {
	Code   string
	Detail string
}

func (e *deltaError) Error() string { return e.Code + ": " + e.Detail }

func derr(code, f string, args ...any) *deltaError {
	return &deltaError{code, fmt.Sprintf(f, args...)}
}

func indexByID(xs []any, idPos int, id int64) int {
	for i, x := range xs {
		if num(x.([]any)[idPos]) == id {
			return i
		}
	}
	return -1
}

func (st *schemaState) apply(delta []any) (*schemaState, *deltaError) {
	n := st.clone()
	doc := n.doc
	for _, opv := range delta {
		op := opv.([]any)
		switch num(op[0]) {
		case 0: // add or replace type
			td := deepCopy(op[1]).([]any)
			id := num(td[1])
			if n.retired[0][id] {
				return nil, derr("retired_id_reused", "type %d was retired", id)
			}
			types := doc[3].([]any)
			if i := indexByID(types, 1, id); i >= 0 {
				types[i] = td
			} else {
				doc[3] = append(types, td)
			}
		case 1: // add or replace service
			sd := deepCopy(op[1]).([]any)
			id := num(sd[0])
			if n.retired[3][id] {
				return nil, derr("retired_id_reused", "service %d was retired", id)
			}
			for _, m := range sd[2].([]any) {
				mid := num(m.([]any)[0])
				if n.retired[1][mid] {
					return nil, derr("retired_id_reused", "method %d was retired", mid)
				}
			}
			services := doc[4].([]any)
			if i := indexByID(services, 0, id); i >= 0 {
				old := services[i].([]any)
				if e := checkServiceReplace(old, sd); e != nil {
					return nil, e
				}
				services[i] = sd
			} else {
				doc[4] = append(services, sd)
			}
		case 2: // add sigil
			sg := deepCopy(op[1]).([]any)
			id := num(sg[0])
			if n.retired[2][id] {
				return nil, derr("retired_id_reused", "sigil %d was retired", id)
			}
			if indexByID(doc[5].([]any), 0, id) >= 0 {
				return nil, derr("duplicate_id", "sigil %d already exists", id)
			}
			doc[5] = append(doc[5].([]any), sg)
		case 3: // retire
			space, id := num(op[1]), num(op[2])
			if e := n.retire(space, id); e != nil {
				return nil, e
			}
		case 4:
			doc[6] = deepCopy(op[1])
		case 5:
			doc[2] = op[1]
		default:
			return nil, derr("unknown_delta_op", "op %d", num(op[0]))
		}
	}
	n.doc = canonical(doc)
	if e := validateSchema(n.doc); e != nil {
		return nil, e
	}
	return n, nil
}

func checkServiceReplace(old, nw []any) *deltaError {
	newMethods := map[int64][]any{}
	for _, m := range nw[2].([]any) {
		newMethods[num(m.([]any)[0])] = m.([]any)
	}
	for _, m := range old[2].([]any) {
		om := m.([]any)
		id := num(om[0])
		nm, ok := newMethods[id]
		if !ok {
			return derr("method_dropped_without_retire", "service %d replacement omits method %d", num(old[0]), id)
		}
		const fixed = fNotification | fInputEnd | fOutputEnd
		if hx(enc(om[2])) != hx(enc(nm[2])) || hx(enc(om[3])) != hx(enc(nm[3])) ||
			num(om[5])&fixed != num(nm[5])&fixed {
			return derr("incompatible_method_change", "method %d changed input, output or flags 0x2/0x8/0x10", id)
		}
	}
	return nil
}

func (n *schemaState) retire(space, id int64) *deltaError {
	doc := n.doc
	switch space {
	case 0:
		types := doc[3].([]any)
		i := indexByID(types, 1, id)
		if i < 0 {
			return derr("unknown_id_retired", "type %d", id)
		}
		doc[3] = append(types[:i:i], types[i+1:]...)
	case 1:
		for _, sv := range doc[4].([]any) {
			s := sv.([]any)
			ms := s[2].([]any)
			if i := indexByID(ms, 0, id); i >= 0 {
				s[2] = append(ms[:i:i], ms[i+1:]...)
				n.retired[1][id] = true
				return nil
			}
		}
		return derr("unknown_id_retired", "method %d", id)
	case 2:
		sg := doc[5].([]any)
		i := indexByID(sg, 0, id)
		if i < 0 {
			return derr("unknown_id_retired", "sigil %d", id)
		}
		doc[5] = append(sg[:i:i], sg[i+1:]...)
	case 3:
		services := doc[4].([]any)
		i := indexByID(services, 0, id)
		if i < 0 {
			return derr("unknown_id_retired", "service %d", id)
		}
		for _, m := range services[i].([]any)[2].([]any) {
			n.retired[1][num(m.([]any)[0])] = true
		}
		doc[4] = append(services[:i:i], services[i+1:]...)
	default:
		return derr("unknown_id_space", "space %d", space)
	}
	n.retired[space][id] = true
	return nil
}

// validateSchema checks the rules this program enforces on a full schema.
func validateSchema(doc []any) *deltaError {
	types := map[int64][]any{}
	for _, t := range doc[3].([]any) {
		td := t.([]any)
		id := num(td[1])
		if id < 64 {
			return derr("reserved_id", "type %d is in the reserved range 0-63", id)
		}
		if types[id] != nil {
			return derr("duplicate_id", "type %d", id)
		}
		types[id] = td
	}
	sigils := map[int64]int64{}
	for _, s := range doc[5].([]any) {
		sd := s.([]any)
		id := num(sd[0])
		if id < 64 {
			return derr("reserved_id", "sigil %d is in the reserved range 0-63", id)
		}
		if _, dup := sigils[id]; dup {
			return derr("duplicate_id", "sigil %d", id)
		}
		sigils[id] = num(sd[2])
	}
	var checkRef func(ref any, where string, top bool) *deltaError
	checkRef = func(ref any, where string, top bool) *deltaError {
		switch r := ref.(type) {
		case []any:
			switch num(r[0]) {
			case 0, 2:
				return checkRef(r[1], where, false)
			case 1:
				if e := checkRef(r[1], where, false); e != nil {
					return e
				}
				return checkRef(r[2], where, false)
			case 3:
				if !top {
					return derr("stream_type_misplaced", "%s: [3, T] outside a method input/output", where)
				}
				return checkRef(r[1], where, false)
			case 4:
				return nil
			}
			return derr("bad_type_ref", "%s", where)
		default:
			id := num(r)
			if id <= tSymbol {
				return nil
			}
			if types[id] == nil {
				return derr("dangling_reference", "%s references type %d, which is not defined", where, id)
			}
			return nil
		}
	}
	for _, t := range doc[3].([]any) {
		td := t.([]any)
		where := fmt.Sprintf("type %d", num(td[1]))
		switch num(td[0]) {
		case 0:
			for _, f := range td[3].([]any) {
				if e := checkRef(f.([]any)[2], where, false); e != nil {
					return e
				}
			}
		case 1:
			for _, v := range td[3].([]any) {
				sid := num(v)
				if k, ok := sigils[sid]; !ok || k != 0 {
					return derr("dangling_reference", "%s lists sigil %d, which is not a defined enum-value sigil", where, sid)
				}
			}
		case 2:
			for _, v := range td[3].([]any) {
				if e := checkRef(v.([]any)[2], where, false); e != nil {
					return e
				}
			}
		case 3:
			if e := checkRef(td[3], where, false); e != nil {
				return e
			}
		}
	}
	services := map[int64]bool{}
	methods := map[int64]bool{}
	for _, sv := range doc[4].([]any) {
		s := sv.([]any)
		sid := num(s[0])
		if sid < 64 {
			return derr("reserved_id", "service %d is in the reserved range 0-63", sid)
		}
		if services[sid] {
			return derr("duplicate_id", "service %d", sid)
		}
		services[sid] = true
		for _, mv := range s[2].([]any) {
			m := mv.([]any)
			mid := num(m[0])
			if mid < 32 {
				return derr("reserved_id", "method %d is in the reserved core range 0-31", mid)
			}
			if methods[mid] {
				return derr("duplicate_id", "method %d appears twice", mid)
			}
			methods[mid] = true
			where := fmt.Sprintf("method %d", mid)
			if e := checkRef(m[2], where, true); e != nil {
				return e
			}
			if e := checkRef(m[3], where, true); e != nil {
				return e
			}
			for _, ev := range m[4].([]any) {
				e := num(ev)
				if e < 32 {
					continue
				}
				if k, ok := sigils[e]; !ok || k != 1 {
					return derr("dangling_reference", "%s lists error %d, which is not a defined error sigil", where, e)
				}
			}
			flags := num(m[5])
			if needsEnd(m[2], types) && flags&fInputEnd == 0 {
				return derr("missing_end_flag", "%s: input is a stream or contains [4] but flag 0x8 is not set", where)
			}
			if needsEnd(m[3], types) && flags&fOutputEnd == 0 {
				return derr("missing_end_flag", "%s: output is a stream or contains [4] but flag 0x10 is not set", where)
			}
		}
	}
	return nil
}

// needsEnd reports whether a method half is a stream or contains [4]
// anywhere (following user type references).
func needsEnd(ref any, types map[int64][]any) bool {
	if r, ok := ref.([]any); ok && num(r[0]) == 3 {
		return true
	}
	return containsByteStream(ref, types, map[int64]bool{})
}

func containsByteStream(ref any, types map[int64][]any, seen map[int64]bool) bool {
	switch r := ref.(type) {
	case []any:
		switch num(r[0]) {
		case 4:
			return true
		case 1:
			return containsByteStream(r[1], types, seen) || containsByteStream(r[2], types, seen)
		default:
			return containsByteStream(r[1], types, seen)
		}
	default:
		id := num(r)
		if seen[id] || types[id] == nil {
			return false
		}
		seen[id] = true
		td := types[id]
		switch num(td[0]) {
		case 0:
			for _, f := range td[3].([]any) {
				if containsByteStream(f.([]any)[2], types, seen) {
					return true
				}
			}
		case 2:
			for _, v := range td[3].([]any) {
				if containsByteStream(v.([]any)[2], types, seen) {
					return true
				}
			}
		case 3:
			return containsByteStream(td[3], types, seen)
		}
	}
	return false
}
