package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Schema documents (format 2, section 6) are handled as generic CBOR trees
// ([]any / map[string]any) that mirror the CDDL one to one.

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
	tDynamic
	tSymbol
)

// Field and variant flags (section 6.3)
const (
	ffOptional   = 0x1
	ffDeprecated = 0x2
	ffRemoved    = 0x4
)

// Method flags (section 6.4)
const (
	fIdempotent   = 0x1
	fNotification = 0x2
	fShared       = 0x4
	fInputEnd     = 0x8
	fOutputEnd    = 0x10
)

// TypeIds 12-31 are reserved for built-ins of later core versions (6.4).
const (
	firstReservedBuiltin = 12
	lastReservedBuiltin  = 31
)

// Retired spaces (section 6.2)
const (
	spType    = 0
	spService = 1
	spMethod  = 2
	spSigil   = 3
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
func variant(tag int, name string, typ any, flags int, an ann) []any {
	return []any{tag, name, typ, flags, a(an)}
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
func retired(pairs ...[2]int) []any {
	out := []any{}
	for _, p := range pairs {
		out = append(out, []any{p[0], p[1]})
	}
	return out
}

// facet = [id, name, version, types, services, sigils, implements, retired, annotations]
const (
	pID = iota
	pName
	pVersion
	pTypes
	pServices
	pSigils
	pImplements
	pRetired
	pAnn
)

func facetDoc(id int, name, version string, types, services, sigils []any, implements []byte, ret []any, an ann) []any {
	var impl any
	if implements != nil {
		impl = implements
	}
	if ret == nil {
		ret = []any{}
	}
	return []any{id, name, version, list(types...), list(services...), list(sigils...), impl, ret, a(an)}
}

// interface = [name, version, types, services, sigils]
func ifaceDoc(name, version string, types, services, sigils []any) []any {
	return []any{name, version, list(types...), list(services...), list(sigils...)}
}

// schema = [format, name, version, facets, annotations]
func schemaDoc(name, version string, facets []any, an ann) []any {
	return []any{2, name, version, list(facets...), a(an)}
}

func sortByInt(xs []any, key func(any) int64) {
	sort.SliceStable(xs, func(i, j int) bool { return key(xs[i]) < key(xs[j]) })
}
func first(x any) int64  { return num(x.([]any)[0]) }
func second(x any) int64 { return num(x.([]any)[1]) }
func self(x any) int64   { return num(x) }

// canonDefs sorts types, services and sigils in place (section 6.6).
func canonDefs(types, services, sigils []any) {
	sortByInt(types, second)
	for _, t := range types {
		td := t.([]any)
		switch num(td[0]) {
		case 0, 2:
			sortByInt(td[3].([]any), first)
		case 1:
			sortByInt(td[3].([]any), self)
		}
	}
	sortByInt(services, first)
	for _, sv := range services {
		ms := sv.([]any)[2].([]any)
		sortByInt(ms, first)
		for _, m := range ms {
			sortByInt(m.([]any)[4].([]any), self)
		}
	}
	sortByInt(sigils, first)
}

func canonicalFacet(p []any) []any {
	c := deepCopy(p).([]any)
	canonDefs(c[pTypes].([]any), c[pServices].([]any), c[pSigils].([]any))
	r := c[pRetired].([]any)
	sort.SliceStable(r, func(i, j int) bool {
		a, b := r[i].([]any), r[j].([]any)
		if num(a[0]) != num(b[0]) {
			return num(a[0]) < num(b[0])
		}
		return num(a[1]) < num(b[1])
	})
	return c
}

func canonicalIface(i []any) []any {
	c := deepCopy(i).([]any)
	canonDefs(c[2].([]any), c[3].([]any), c[4].([]any))
	return c
}

func canonicalSchema(s []any) []any {
	c := deepCopy(s).([]any)
	facets := c[3].([]any)
	for i, p := range facets {
		facets[i] = canonicalFacet(p.([]any))
	}
	sortByInt(facets, first)
	return c
}

func h33(b []byte) []byte {
	s := sha256.Sum256(b)
	return append([]byte{0x01}, s[:]...)
}

// facetHashInput is the canonical facet with name "" and id 0.
func facetHashInput(p []any) []any {
	c := canonicalFacet(p)
	c[pID] = 0
	c[pName] = ""
	return c
}

func facetHash(p []any) []byte { return h33(enc(facetHashInput(p))) }
func ifaceHash(i []any) []byte { return h33(enc(canonicalIface(i))) }

// schemaHashInput is [format, name, version, [* [facet_id, facet_name, facet_hash]], annotations].
func schemaHashInput(s []any) []any {
	c := canonicalSchema(s)
	entries := []any{}
	for _, p := range c[3].([]any) {
		pd := p.([]any)
		entries = append(entries, []any{pd[pID], pd[pName], facetHash(pd)})
	}
	return []any{c[0], c[1], c[2], entries, c[4]}
}

func schemaHash(s []any) []byte { return h33(enc(schemaHashInput(s))) }

// ---------------------------------------------------------------------------
// Wire shapes and interface conformance (section 6.5)
// ---------------------------------------------------------------------------

func blankType(td []any) []any {
	c := deepCopy(td).([]any)
	c[2] = ""
	c[len(c)-1] = map[string]any{}
	switch num(c[0]) {
	case 0, 2:
		for _, f := range c[3].([]any) {
			fd := f.([]any)
			fd[1] = ""
			fd[4] = map[string]any{}
			if num(c[0]) == 0 {
				fd[3] = num(fd[3]) &^ ffDeprecated // hint flag
			}
		}
	}
	return c
}

// blankService: a service's wire shape leaves out its method list (6.5).
func blankService(sd []any) []any {
	return []any{sd[0], "", map[string]any{}}
}

// blankMethod clears the name, the annotations and the hint flags 0x1, 0x4.
func blankMethod(md []any) []any {
	c := deepCopy(md).([]any)
	c[1] = ""
	c[5] = num(c[5]) &^ (fIdempotent | fShared)
	c[6] = map[string]any{}
	return c
}

func blankSigil(sg []any) []any {
	c := deepCopy(sg).([]any)
	c[1] = ""
	c[3] = map[string]any{}
	return c
}

// conforms checks a facet against an interface. It returns the first
// mismatch as [space, id] (space as in `retired`), or nil.
func conforms(facet, iface []any) []any {
	p := canonicalFacet(facet)
	i := canonicalIface(iface)
	type group struct {
		space       int
		iDefs, pDef []any
		idPos       int
		blank       func([]any) []any
	}
	groups := []group{
		{spType, i[2].([]any), p[pTypes].([]any), 1, blankType},
		{spService, i[3].([]any), p[pServices].([]any), 0, blankService},
		{spSigil, i[4].([]any), p[pSigils].([]any), 0, blankSigil},
	}
	for _, g := range groups {
		for _, d := range g.iDefs {
			dd := d.([]any)
			id := num(dd[g.idPos])
			j := indexByID(g.pDef, g.idPos, id)
			if j < 0 || !bytes.Equal(enc(g.blank(dd)), enc(g.blank(g.pDef[j].([]any)))) {
				return []any{g.space, id}
			}
			if g.space != spService {
				continue
			}
			pMethods := g.pDef[j].([]any)[2].([]any)
			for _, m := range dd[2].([]any) {
				md := m.([]any)
				mid := num(md[0])
				k := indexByID(pMethods, 0, mid)
				if k < 0 || !bytes.Equal(enc(blankMethod(md)), enc(blankMethod(pMethods[k].([]any)))) {
					return []any{spMethod, mid}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

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

func containsFloat(v any) bool {
	switch x := v.(type) {
	case float32, float64:
		return true
	case []any:
		for _, e := range x {
			if containsFloat(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if containsFloat(e) {
				return true
			}
		}
	case map[any]any:
		for k, e := range x {
			if containsFloat(k) || containsFloat(e) {
				return true
			}
		}
	case cbor.Tag:
		return containsFloat(x.Content)
	}
	return false
}

type defs struct {
	types   map[int64][]any
	sigils  map[int64]int64 // id -> kind
	methods map[int64][]any
	svcs    map[int64][]any
}

// validateDefs checks one facet or interface: IDs, references within it,
// End flags and stream placement (sections 6.1-6.6).
func validateDefs(where string, types, services, sigils, ret []any) (*defs, *deltaError) {
	d := &defs{map[int64][]any{}, map[int64]int64{}, map[int64][]any{}, map[int64][]any{}}
	if e := checkASCIINames(where, types, services, sigils); e != nil {
		return nil, e
	}
	retiredSet := map[[2]int64]bool{}
	for _, r := range ret {
		rp := r.([]any)
		sp := num(rp[0])
		if sp < 0 || sp > 3 {
			return nil, derr("bad_retired_entry", "%s: space %d", where, sp)
		}
		retiredSet[[2]int64{sp, num(rp[1])}] = true
	}
	for _, t := range types {
		td := t.([]any)
		id := num(td[1])
		if id < 64 {
			return nil, derr("reserved_id", "%s: type %d is reserved", where, id)
		}
		if d.types[id] != nil {
			return nil, derr("duplicate_id", "%s: type %d", where, id)
		}
		if retiredSet[[2]int64{spType, id}] {
			return nil, derr("retired_id_reused", "%s: type %d is retired", where, id)
		}
		d.types[id] = td
	}
	for _, s := range sigils {
		sd := s.([]any)
		id := num(sd[0])
		if id < 64 {
			return nil, derr("reserved_id", "%s: sigil %d is reserved", where, id)
		}
		if _, dup := d.sigils[id]; dup {
			return nil, derr("duplicate_id", "%s: sigil %d", where, id)
		}
		if retiredSet[[2]int64{spSigil, id}] {
			return nil, derr("retired_id_reused", "%s: sigil %d is retired", where, id)
		}
		d.sigils[id] = num(sd[2])
	}
	// Sigil names are unique within a facet or interface (6.5).
	sigilNames := map[string]bool{}
	for _, s := range sigils {
		sd := s.([]any)
		n := sd[1].(string)
		if sigilNames[n] {
			return nil, derr("duplicate_sigil_name", "%s: sigil %d is named %q like another", where, num(sd[0]), n)
		}
		sigilNames[n] = true
	}
	for _, sv := range services {
		s := sv.([]any)
		sid := num(s[0])
		if d.svcs[sid] != nil {
			return nil, derr("duplicate_id", "%s: service %d", where, sid)
		}
		if retiredSet[[2]int64{spService, sid}] {
			return nil, derr("retired_id_reused", "%s: service %d is retired", where, sid)
		}
		d.svcs[sid] = s
		for _, mv := range s[2].([]any) {
			m := mv.([]any)
			mid := num(m[0])
			if d.methods[mid] != nil {
				return nil, derr("duplicate_id", "%s: method %d appears twice", where, mid)
			}
			if retiredSet[[2]int64{spMethod, mid}] {
				return nil, derr("retired_id_reused", "%s: method %d is retired", where, mid)
			}
			d.methods[mid] = m
		}
	}
	var checkRef func(ref any, at string, top bool) *deltaError
	checkRef = func(ref any, at string, top bool) *deltaError {
		switch r := ref.(type) {
		case []any:
			switch num(r[0]) {
			case 0, 2:
				return checkRef(r[1], at, false)
			case 1:
				if e := checkRef(r[1], at, false); e != nil {
					return e
				}
				return checkRef(r[2], at, false)
			case 3:
				if !top {
					return derr("stream_type_misplaced", "%s: [3, T] not a method's whole input/output", at)
				}
				return checkRef(r[1], at, false)
			case 4:
				return nil
			}
			return derr("bad_type_ref", "%s", at)
		default:
			id := num(r)
			if id >= firstReservedBuiltin && id <= lastReservedBuiltin {
				return derr("reserved_type_id", "%s references type %d; TypeIds 12-31 are reserved for later built-ins (6.4)", at, id)
			}
			if id <= tSymbol || d.types[id] != nil {
				return nil
			}
			return derr("dangling_reference", "%s references type %d, not defined in this facet", at, id)
		}
	}
	enumOf := map[int64]int64{} // kind-0 sigil -> the enum listing it
	for _, t := range types {
		td := t.([]any)
		at := fmt.Sprintf("%s: type %d", where, num(td[1]))
		switch num(td[0]) {
		case 0, 2:
			for _, f := range td[3].([]any) {
				fd := f.([]any)
				if num(fd[3])&ffRemoved != 0 {
					continue // tombstones are never encoded; see Assumptions
				}
				if e := checkRef(fd[2], at, false); e != nil {
					return nil, e
				}
			}
		case 1:
			for _, v := range td[3].([]any) {
				sid := num(v)
				if k, ok := d.sigils[sid]; !ok || k != 0 {
					return nil, derr("dangling_reference", "%s lists sigil %d, not a kind-0 sigil of this facet", at, sid)
				}
				// A kind-0 sigil is a value of exactly one enum (6.5).
				if other, ok := enumOf[sid]; ok {
					return nil, derr("sigil_in_two_enums", "%s lists sigil %d, a value of type %d too", at, sid, other)
				}
				enumOf[sid] = num(td[1])
			}
		case 3:
			if e := checkRef(td[3], at, false); e != nil {
				return nil, e
			}
		}
	}
	for _, sv := range services {
		for _, mv := range sv.([]any)[2].([]any) {
			m := mv.([]any)
			at := fmt.Sprintf("%s: method %d", where, num(m[0]))
			if e := checkRef(m[2], at, true); e != nil {
				return nil, e
			}
			if e := checkRef(m[3], at, true); e != nil {
				return nil, e
			}
			for _, ev := range m[4].([]any) {
				e := num(ev)
				if e < 32 {
					continue
				}
				if k, ok := d.sigils[e]; !ok || k != 1 {
					return nil, derr("dangling_reference", "%s lists error %d, not a kind-1 sigil of this facet", at, e)
				}
			}
			flags := num(m[5])
			if flags&fNotification != 0 {
				if _, isRef := m[3].([]any); isRef || num(m[3]) != tUnit {
					return nil, derr("invalid_notification", "%s: a notification (flag 0x2) must have output unit", at)
				}
				if containsByteStream(m[2], d.types, map[int64]bool{}) {
					return nil, derr("invalid_notification", "%s: a notification (flag 0x2) must not have [4] in its input", at)
				}
			}
			if needsEnd(m[2], d.types) && flags&fInputEnd == 0 {
				return nil, derr("missing_end_flag", "%s: input needs flag 0x8", at)
			}
			if needsEnd(m[3], d.types) && flags&fOutputEnd == 0 {
				return nil, derr("missing_end_flag", "%s: output needs flag 0x10", at)
			}
		}
	}
	return d, nil
}

var nameRe = regexp.MustCompile(`^([a-z0-9-]+(\.[a-z0-9-]+)*/)?[a-z0-9-]+(\.[a-z0-9-]+)*$`)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// checkASCIINames: names of types, services, methods, fields and sigils are
// ASCII, and so are variant names (6.1).
func checkASCIINames(where string, types, services, sigils []any) *deltaError {
	bad := func(kind, n string) *deltaError {
		return derr("invalid_name", "%s: %s name %q is not ASCII", where, kind, n)
	}
	for _, t := range types {
		td := t.([]any)
		if !isASCII(td[2].(string)) {
			return bad("type", td[2].(string))
		}
		if num(td[0]) == 0 || num(td[0]) == 2 {
			for _, f := range td[3].([]any) {
				if n := f.([]any)[1].(string); !isASCII(n) {
					return bad("field or variant", n)
				}
			}
		}
	}
	for _, sv := range services {
		sd := sv.([]any)
		if !isASCII(sd[1].(string)) {
			return bad("service", sd[1].(string))
		}
		for _, m := range sd[2].([]any) {
			if n := m.([]any)[1].(string); !isASCII(n) {
				return bad("method", n)
			}
		}
	}
	for _, sg := range sigils {
		if n := sg.([]any)[1].(string); !isASCII(n) {
			return bad("sigil", n)
		}
	}
	return nil
}

func validateFacet(p []any) (*defs, *deltaError) {
	where := fmt.Sprintf("facet %d", num(p[pID]))
	if containsFloat(p) {
		return nil, derr("float_in_canonical_data", "%s contains a float", where)
	}
	if n := p[pName].(string); !nameRe.MatchString(n) {
		return nil, derr("invalid_name", "%s: facet name %q does not match the facet-name grammar", where, n)
	}
	return validateDefs(where, p[pTypes].([]any), p[pServices].([]any), p[pSigils].([]any), p[pRetired].([]any))
}

// validateIface also checks that the interface contains exactly what its
// services reach (section 6.5).
func validateIface(i []any) *deltaError {
	if containsFloat(i) {
		return derr("float_in_canonical_data", "interface contains a float")
	}
	d, e := validateDefs("interface", i[2].([]any), i[3].([]any), i[4].([]any), nil)
	if e != nil {
		return e
	}
	seenT := map[int64]bool{}
	seenS := map[int64]bool{}
	var walk func(ref any)
	walk = func(ref any) {
		switch r := ref.(type) {
		case []any:
			for _, x := range r[1:] {
				walk(x)
			}
		default:
			id := num(r)
			if seenT[id] || d.types[id] == nil {
				return
			}
			seenT[id] = true
			td := d.types[id]
			switch num(td[0]) {
			case 0, 2:
				for _, f := range td[3].([]any) {
					if num(f.([]any)[3])&ffRemoved != 0 {
						continue // references inside tombstones do not count (6.5)
					}
					walk(f.([]any)[2])
				}
			case 1:
				for _, v := range td[3].([]any) {
					seenS[num(v)] = true
				}
			case 3:
				walk(td[3])
			}
		}
	}
	for _, m := range d.methods {
		walk(m[2])
		walk(m[3])
		for _, ev := range m[4].([]any) {
			seenS[num(ev)] = true
		}
	}
	for _, t := range i[2].([]any) {
		if id := num(t.([]any)[1]); !seenT[id] {
			return derr("interface_not_closed", "type %d is not reached from the interface's services", id)
		}
	}
	for _, s := range i[4].([]any) {
		if id := num(s.([]any)[0]); !seenS[id] {
			return derr("interface_not_closed", "sigil %d is not reached from the interface's services", id)
		}
	}
	return nil
}

// validateSchema checks a whole schema document.
func validateSchema(doc []any) *deltaError {
	if containsFloat(doc) {
		return derr("float_in_canonical_data", "schema contains a float")
	}
	ids := map[int64]bool{}
	names := map[string]bool{}
	for _, pv := range doc[3].([]any) {
		p := pv.([]any)
		id := num(p[pID])
		name := p[pName].(string)
		if ids[id] {
			return derr("duplicate_facet_id", "facet %d", id)
		}
		if names[name] {
			return derr("duplicate_facet_name", "%q", name)
		}
		ids[id], names[name] = true, true
		if id < 16 && id != 1 {
			return derr("reserved_facet_id", "facet %d (%q): IDs 0 and 2-15 MUST NOT appear", id, name)
		}
		if id == 1 && (name != "sparrow.web" || !bytes.Equal(facetHash(p), facetHash(webFacet()))) {
			return derr("facet1_mismatch", "facet 1 does not match the spec's definition of sparrow.web by name and facet hash")
		}
		if _, e := validateFacet(p); e != nil {
			return e
		}
	}
	return nil
}

// validateSentSchema additionally checks that a schema document as sent
// lists its facets sorted by ID (6.1).
func validateSentSchema(doc []any) *deltaError {
	facets := doc[3].([]any)
	for i := 1; i < len(facets); i++ {
		if num(facets[i-1].([]any)[pID]) >= num(facets[i].([]any)[pID]) {
			return derr("facets_not_sorted", "facet %d listed after facet %d", num(facets[i].([]any)[pID]), num(facets[i-1].([]any)[pID]))
		}
	}
	return validateSchema(doc)
}

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
		case 0, 2:
			for _, f := range td[3].([]any) {
				fd := f.([]any)
				if num(fd[3])&ffRemoved == 0 && containsByteStream(fd[2], types, seen) {
					return true
				}
			}
		case 3:
			return containsByteStream(td[3], types, seen)
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Compatibility of a replacing facet (sections 6.6 rule 2, 6.7)
// ---------------------------------------------------------------------------

func major(v string) string { return strings.SplitN(v, ".", 2)[0] }

func refEq(a, b any) bool { return bytes.Equal(enc(a), enc(b)) }

func compatible(old, nw []any) *deltaError {
	pid := num(old[pID])
	if old[pName] != nw[pName] {
		return derr("facet_renamed", "facet %d: %q -> %q", pid, old[pName], nw[pName])
	}
	if major(old[pVersion].(string)) != major(nw[pVersion].(string)) {
		return derr("major_version_changed", "facet %d: %s -> %s; a new major version is a new facet", pid, old[pVersion], nw[pVersion])
	}
	newRet := map[[2]int64]bool{}
	for _, r := range nw[pRetired].([]any) {
		rp := r.([]any)
		newRet[[2]int64{num(rp[0]), num(rp[1])}] = true
	}
	for _, r := range old[pRetired].([]any) {
		rp := r.([]any)
		if !newRet[[2]int64{num(rp[0]), num(rp[1])}] {
			return derr("retired_not_carried_over", "facet %d: retired [%d, %d] missing", pid, num(rp[0]), num(rp[1]))
		}
	}
	od, e := validateFacet(old)
	if e != nil {
		return e
	}
	nd, e := validateFacet(nw)
	if e != nil {
		return e
	}
	dropped := func(space int, id int64) *deltaError {
		if !newRet[[2]int64{int64(space), id}] {
			return derr("dropped_id_not_retired", "facet %d: [%d, %d] was removed but is not in retired", pid, space, id)
		}
		return nil
	}
	for _, id := range sortedKeys(od.types) {
		ot := od.types[id]
		ntd, ok := nd.types[id]
		if !ok {
			if e := dropped(spType, id); e != nil {
				return e
			}
			continue
		}
		if e := typeCompatible(pid, ot, ntd); e != nil {
			return e
		}
	}
	for _, id := range sortedKeys(od.svcs) {
		if _, ok := nd.svcs[id]; !ok {
			if e := dropped(spService, id); e != nil {
				return e
			}
		}
	}
	for _, id := range sortedKeys(od.methods) {
		om := od.methods[id]
		nm, ok := nd.methods[id]
		if !ok {
			if e := dropped(spMethod, id); e != nil {
				return e
			}
			continue
		}
		const fixed = fNotification | fInputEnd | fOutputEnd
		if !refEq(om[2], nm[2]) || !refEq(om[3], nm[3]) || num(om[5])&fixed != num(nm[5])&fixed {
			return derr("incompatible_change", "facet %d: method %d changed input, output or flags 0x2/0x8/0x10", pid, id)
		}
	}
	for _, id := range sortedKeys(od.sigils) {
		k, ok := nd.sigils[id]
		if !ok {
			if e := dropped(spSigil, id); e != nil {
				return e
			}
			continue
		}
		if k != od.sigils[id] {
			return derr("incompatible_change", "facet %d: sigil %d changed kind", pid, id)
		}
	}
	return nil
}

func sortedKeys[V any](m map[int64]V) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func typeCompatible(pid int64, ot, nt []any) *deltaError {
	id := num(ot[1])
	bad := func(f string, args ...any) *deltaError {
		return derr("incompatible_change", "facet %d: type %d: %s", pid, id, fmt.Sprintf(f, args...))
	}
	if num(ot[0]) != num(nt[0]) {
		return bad("kind changed")
	}
	switch num(ot[0]) {
	case 0, 2: // struct, union: members by tag
		isStruct := num(ot[0]) == 0
		if isStruct && num(ot[4])&1 != num(nt[4])&1 {
			return bad("sparse flag changed")
		}
		newM := map[int64][]any{}
		for _, f := range nt[3].([]any) {
			newM[first(f)] = f.([]any)
		}
		oldM := map[int64]bool{}
		for _, f := range ot[3].([]any) {
			of := f.([]any)
			tag := num(of[0])
			oldM[tag] = true
			nf, ok := newM[tag]
			if !ok {
				return bad("tag %d disappeared (removed members stay as tombstones)", tag)
			}
			oRem, nRem := num(of[3])&ffRemoved != 0, num(nf[3])&ffRemoved != 0
			switch {
			case oRem && !nRem:
				return bad("tag %d reused after removal", tag)
			case oRem && nRem:
				if !refEq(of[2], nf[2]) || num(of[3]) != num(nf[3]) {
					return bad("tombstone %d changed its type or flags (a tombstone never changes, apart from its name and annotations)", tag)
				}
			case nRem:
				if isStruct && num(of[3])&ffOptional == 0 {
					return bad("required field %d removed", tag)
				}
				if !refEq(of[2], nf[2]) {
					return bad("tag %d changed type as it became a tombstone", tag)
				}
			default:
				if !refEq(of[2], nf[2]) {
					return bad("tag %d changed type", tag)
				}
				if isStruct && num(of[3])&ffOptional != 0 && num(nf[3])&ffOptional == 0 {
					return bad("field %d made required", tag)
				}
				if isStruct && num(of[3])&ffOptional == 0 && num(nf[3])&ffOptional != 0 {
					return bad("required field %d made optional", tag)
				}
			}
		}
		if isStruct {
			for tag, nf := range newM {
				if !oldM[tag] && num(nf[3])&(ffOptional|ffRemoved) == 0 {
					return bad("new field %d is required", tag)
				}
			}
		}
	case 1:
		nv := map[int64]bool{}
		for _, v := range nt[3].([]any) {
			nv[num(v)] = true
		}
		for _, v := range ot[3].([]any) {
			if !nv[num(v)] {
				return bad("enum value %d removed", num(v))
			}
		}
	case 3:
		if !refEq(ot[3], nt[3]) {
			return bad("alias target changed")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Delta application (section 6.6)
// ---------------------------------------------------------------------------

type schemaState struct {
	doc     []any           // canonical schema
	removed map[int64][]any // facet ID -> last version seen, for re-adds
}

func newState(doc []any) *schemaState {
	return &schemaState{doc: canonicalSchema(doc), removed: map[int64][]any{}}
}

func (st *schemaState) clone() *schemaState {
	n := &schemaState{doc: deepCopy(st.doc).([]any), removed: map[int64][]any{}}
	for k, v := range st.removed {
		n.removed[k] = v
	}
	return n
}

func (st *schemaState) removedIDs() []int64 { return sortedKeys(st.removed) }

func (st *schemaState) apply(delta []any) (*schemaState, *deltaError) {
	n := st.clone()
	doc := n.doc
	for _, opv := range delta {
		op := opv.([]any)
		switch num(op[0]) {
		case 0:
			p := canonicalFacet(op[1].([]any))
			id := num(p[pID])
			facets := doc[3].([]any)
			if i := indexByID(facets, pID, id); i >= 0 {
				if e := compatible(facets[i].([]any), p); e != nil {
					return nil, e
				}
				facets[i] = p
			} else {
				if last, ok := n.removed[id]; ok {
					if last[pName] != p[pName] || major(last[pVersion].(string)) != major(p[pVersion].(string)) {
						return nil, derr("removed_facet_mismatch", "facet %d was %q %s; it may only come back with the same name and major version (got %q %s)",
							id, last[pName], last[pVersion], p[pName], p[pVersion])
					}
					if e := compatible(last, p); e != nil {
						return nil, e
					}
					delete(n.removed, id)
				}
				doc[3] = append(facets, p)
			}
		case 1:
			id := num(op[1])
			facets := doc[3].([]any)
			i := indexByID(facets, pID, id)
			if i < 0 {
				return nil, derr("unknown_facet", "facet %d", id)
			}
			n.removed[id] = facets[i].([]any)
			doc[3] = append(facets[:i:i], facets[i+1:]...)
		case 2:
			doc[4] = deepCopy(op[1])
		case 3:
			doc[2] = op[1]
		default:
			return nil, derr("unknown_delta_op", "op %d", num(op[0]))
		}
	}
	n.doc = canonicalSchema(doc)
	if e := validateSchema(n.doc); e != nil {
		return nil, e
	}
	return n, nil
}
