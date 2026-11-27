package schema

import (
	"fmt"
	"sort"
	"strings"
)

// Major returns the major version of a facet: the first number of its
// version string, 0 included (section 6.7).
func Major(version string) string {
	m, _, _ := strings.Cut(version, ".")
	return m
}

// Compatible checks that nw may replace old in place, implementing the
// table of section 6.7 together with rule 2 of 6.6:
//
//   - the name and the major version stay the same;
//   - retired only grows, and every type, service, method and sigil ID the
//     new version drops appears in its retired list;
//   - a type keeps its kind; a struct keeps its sparse flag; an alias keeps
//     its target;
//   - struct fields and union variants keep their tags forever: a tag never
//     disappears, a tombstone stays a tombstone, a member keeps its type
//     (also when it becomes a tombstone, and as a tombstone), a field never
//     changes between optional and required, only optional fields and
//     variants may become tombstones, and a new field must be optional;
//   - an enum keeps every value;
//   - a method keeps its input, its output and flags 0x2, 0x8 and 0x10
//     (it may move to another service of the facet);
//   - a sigil keeps its kind.
//
// Both versions must also be valid facets, which rules out making [4]
// reachable from a half whose End flag is not set.
func Compatible(old, nw *Facet) error {
	id := old.ID
	if old.Name != nw.Name {
		return errorf(CodeFacetRenamed, "facet %d: %q -> %q", id, old.Name, nw.Name)
	}
	if Major(old.Version) != Major(nw.Version) {
		return errorf(CodeMajorVersionChanged, "facet %d: %s -> %s; a new major version is a new facet", id, old.Version, nw.Version)
	}
	newRet := map[Retired]bool{}
	for _, r := range nw.Retired {
		newRet[r] = true
	}
	for _, r := range old.Retired {
		if !newRet[r] {
			return errorf(CodeRetiredNotCarriedOver, "facet %d: retired [%d, %d] missing", id, r.Space, r.ID)
		}
	}
	oi, err := old.validate()
	if err != nil {
		return err
	}
	ni, err := nw.validate()
	if err != nil {
		return err
	}
	dropped := func(space Space, x uint64) error {
		if !newRet[Retired{space, x}] {
			return errorf(CodeDroppedIDNotRetired, "facet %d: [%d, %d] was removed but is not in retired", id, space, x)
		}
		return nil
	}
	for _, tid := range sortedKeys(oi.types) {
		nt, ok := ni.types[tid]
		if !ok {
			if err := dropped(SpaceType, tid); err != nil {
				return err
			}
			continue
		}
		if err := typeCompatible(id, oi.types[tid], nt); err != nil {
			return err
		}
	}
	for _, sid := range sortedKeys(oi.svcs) {
		if _, ok := ni.svcs[sid]; !ok {
			if err := dropped(SpaceService, sid); err != nil {
				return err
			}
		}
	}
	for _, mid := range sortedKeys(oi.methods) {
		om := oi.methods[mid]
		nm, ok := ni.methods[mid]
		if !ok {
			if err := dropped(SpaceMethod, mid); err != nil {
				return err
			}
			continue
		}
		if !om.Input.Equal(nm.Input) || !om.Output.Equal(nm.Output) || om.Flags&methodFixedFlags != nm.Flags&methodFixedFlags {
			return errorf(CodeIncompatibleChange, "facet %d: method %d changed input, output or flags 0x2/0x8/0x10", id, mid)
		}
	}
	for _, sid := range sortedKeys(oi.sigils) {
		ns, ok := ni.sigils[sid]
		if !ok {
			if err := dropped(SpaceSigil, sid); err != nil {
				return err
			}
			continue
		}
		if ns.Kind != oi.sigils[sid].Kind {
			return errorf(CodeIncompatibleChange, "facet %d: sigil %d changed kind", id, sid)
		}
	}
	return nil
}

func sortedKeys[V any](m map[uint64]V) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func typeCompatible(fid uint64, ot, nt *TypeDef) error {
	bad := func(f string, args ...any) error {
		return errorf(CodeIncompatibleChange, "facet %d: type %d: %s", fid, ot.ID, fmt.Sprintf(f, args...))
	}
	if ot.Kind != nt.Kind {
		return bad("kind changed")
	}
	switch ot.Kind {
	case KindStruct, KindUnion:
		isStruct := ot.Kind == KindStruct
		if isStruct && ot.Flags&StructSparse != nt.Flags&StructSparse {
			return bad("sparse flag changed")
		}
		newM := map[uint64]*Field{}
		for i := range nt.Fields {
			newM[nt.Fields[i].Tag] = &nt.Fields[i]
		}
		oldM := map[uint64]bool{}
		for i := range ot.Fields {
			of := &ot.Fields[i]
			oldM[of.Tag] = true
			nf, ok := newM[of.Tag]
			if !ok {
				return bad("tag %d disappeared (removed members stay as tombstones)", of.Tag)
			}
			switch oRem, nRem := of.Removed(), nf.Removed(); {
			case oRem && !nRem:
				return bad("tag %d reused after removal", of.Tag)
			case oRem && nRem:
				if !of.Type.Equal(nf.Type) {
					return bad("tombstone %d changed type (a tombstone keeps its last definition)", of.Tag)
				}
			case nRem:
				if isStruct && !of.Optional() {
					return bad("required field %d removed", of.Tag)
				}
				if !of.Type.Equal(nf.Type) {
					return bad("tag %d changed type as it became a tombstone", of.Tag)
				}
			default:
				if !of.Type.Equal(nf.Type) {
					return bad("tag %d changed type", of.Tag)
				}
				if isStruct && of.Optional() && !nf.Optional() {
					return bad("field %d made required", of.Tag)
				}
				if isStruct && !of.Optional() && nf.Optional() {
					return bad("required field %d made optional", of.Tag)
				}
			}
		}
		if isStruct {
			for i := range nt.Fields {
				nf := &nt.Fields[i]
				if !oldM[nf.Tag] && !nf.Optional() && !nf.Removed() {
					return bad("new field %d is required", nf.Tag)
				}
			}
		}
	case KindEnum:
		nv := map[uint64]bool{}
		for _, v := range nt.Values {
			nv[v] = true
		}
		for _, v := range ot.Values {
			if !nv[v] {
				return bad("enum value %d removed", v)
			}
		}
	case KindAlias:
		if !ot.Target.Equal(nt.Target) {
			return bad("alias target changed")
		}
	}
	return nil
}
