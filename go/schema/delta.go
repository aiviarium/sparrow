package schema

import (
	"bytes"
	"fmt"
)

// State is a peer's schema as tracked within one session: the current
// canonical schema, its epoch, and the last version of every facet removed
// during the session, so that a removed facet ID only comes back as a
// compatible successor with the same name and major version (6.1).
//
// A State is immutable; Apply returns a new one.
type State struct {
	schema  *Schema
	epoch   uint64
	removed map[uint64]*Facet
}

// NewState starts tracking a schema at epoch 0. The schema is validated
// as a received document.
func NewState(s *Schema) (*State, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &State{schema: s.Canonical(), removed: map[uint64]*Facet{}}, nil
}

// Schema returns a copy of the current canonical schema.
func (st *State) Schema() *Schema { return st.schema.Clone() }

// Epoch returns the current epoch.
func (st *State) Epoch() uint64 { return st.epoch }

// Hash returns the current schema hash.
func (st *State) Hash() ([]byte, error) { return st.schema.Hash() }

// RemovedFacetIDs returns, sorted, the IDs of facets removed during the
// session and not added back.
func (st *State) RemovedFacetIDs() []uint64 { return sortedKeys(st.removed) }

// Apply applies a delta and returns the new state at the next epoch. It
// checks every replacement for compatibility (6.6 rule 2), the re-add rule
// for removed facet IDs (6.1), and then validates the whole resulting
// schema (6.6 rule 3). A receiver that gets an error closes the session
// with schema_mismatch.
func (st *State) Apply(d Delta) (*State, error) {
	n := &State{schema: st.schema.Clone(), epoch: st.epoch + 1, removed: map[uint64]*Facet{}}
	for k, v := range st.removed {
		n.removed[k] = v
	}
	s := n.schema
	for _, op := range d {
		switch op.Op {
		case OpPut:
			if op.Facet == nil {
				return nil, errorf(CodeMalformed, "put without a facet")
			}
			f := op.Facet.Canonical()
			if cur := s.Facet(f.ID); cur != nil {
				if err := Compatible(cur, f); err != nil {
					return nil, err
				}
				*cur = *f
				continue
			}
			if last, ok := n.removed[f.ID]; ok {
				if last.Name != f.Name || Major(last.Version) != Major(f.Version) {
					return nil, errorf(CodeRemovedFacetMismatch,
						"facet %d was %q %s; it may only come back with the same name and major version (got %q %s)",
						f.ID, last.Name, last.Version, f.Name, f.Version)
				}
				if err := Compatible(last, f); err != nil {
					return nil, err
				}
				delete(n.removed, f.ID)
			}
			s.Facets = append(s.Facets, *f)
		case OpRemove:
			i := facetIndex(s, op.FacetID)
			if i < 0 {
				return nil, errorf(CodeUnknownFacet, "facet %d", op.FacetID)
			}
			removed := s.Facets[i]
			n.removed[op.FacetID] = &removed
			s.Facets = append(s.Facets[:i:i], s.Facets[i+1:]...)
		case OpAnnotations:
			s.Annotations = op.Annotations.clone()
		case OpVersion:
			s.Version = op.Version
		default:
			return nil, errorf(CodeUnknownDeltaOp, "delta op %d", op.Op)
		}
	}
	n.schema = s.Canonical()
	if err := n.schema.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// ApplyUpdate applies a SchemaUpdate: the epoch must be the next one and
// the resulting schema hash must equal hash.
func (st *State) ApplyUpdate(epoch uint64, hash []byte, d Delta) (*State, error) {
	if epoch != st.epoch+1 {
		return nil, errorf(CodeEpochMismatch, "epoch %d after %d", epoch, st.epoch)
	}
	n, err := st.Apply(d)
	if err != nil {
		return nil, err
	}
	h, err := n.Hash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(h, hash) {
		return nil, errorf(CodeHashMismatch, "schema hash %x, update names %x", h, hash)
	}
	return n, nil
}

func facetIndex(s *Schema, id uint64) int {
	for i := range s.Facets {
		if s.Facets[i].ID == id {
			return i
		}
	}
	return -1
}

// Diff returns a delta that turns old into nw: removals first, then added
// or changed facets by ID, then top-level annotations and version if they
// changed. Facets are compared by canonical encoding.
func Diff(old, nw *Schema) (Delta, error) {
	oc, nc := old.Canonical(), nw.Canonical()
	var d Delta
	for i := range oc.Facets {
		if nc.Facet(oc.Facets[i].ID) == nil {
			d = append(d, DeltaOp{Op: OpRemove, FacetID: oc.Facets[i].ID})
		}
	}
	for i := range nc.Facets {
		f := &nc.Facets[i]
		of := oc.Facet(f.ID)
		if of != nil {
			a, err := of.CanonicalBytes()
			if err != nil {
				return nil, err
			}
			b, err := f.CanonicalBytes()
			if err != nil {
				return nil, err
			}
			if bytes.Equal(a, b) {
				continue
			}
		}
		d = append(d, DeltaOp{Op: OpPut, Facet: f.Clone()})
	}
	if !annotationsEqual(oc.Annotations, nc.Annotations) {
		d = append(d, DeltaOp{Op: OpAnnotations, Annotations: nc.Annotations.clone()})
	}
	if oc.Version != nc.Version {
		d = append(d, DeltaOp{Op: OpVersion, Version: nc.Version})
	}
	return d, nil
}

func annotationsEqual(a, b Annotations) bool {
	wa, wb := &writer{canonical: true}, &writer{canonical: true}
	wa.annotations(a)
	wb.annotations(b)
	return wa.err == nil && wb.err == nil && bytes.Equal(wa.b, wb.b)
}

// View returns a copy of the schema without the given facets, as a hub
// leaves a node's own facets out of the schema it sends to that node
// (section 10.3).
func (s *Schema) View(omit ...uint64) *Schema {
	c := s.Clone()
	keep := c.Facets[:0]
	for _, f := range c.Facets {
		skip := false
		for _, id := range omit {
			if f.ID == id {
				skip = true
			}
		}
		if !skip {
			keep = append(keep, f)
		}
	}
	c.Facets = keep
	return c
}

// String renders an error-free summary, for logs.
func (op DeltaOp) String() string {
	switch op.Op {
	case OpPut:
		return fmt.Sprintf("put facet %d", op.Facet.ID)
	case OpRemove:
		return fmt.Sprintf("remove facet %d", op.FacetID)
	case OpAnnotations:
		return "replace annotations"
	case OpVersion:
		return fmt.Sprintf("version %q", op.Version)
	}
	return fmt.Sprintf("op %d", op.Op)
}
