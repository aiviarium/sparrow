package schema

import (
	"bytes"
	"fmt"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

// Mismatch names the first definition of an interface that a facet does
// not match: a type, service or sigil, or a method (SpaceMethod).
type Mismatch struct {
	Space Space
	ID    uint64
}

func (m *Mismatch) Error() string {
	return fmt.Sprintf("schema: facet does not implement the interface: %v %d differs", m.Space, m.ID)
}

// Wire shapes (section 6.5): the canonical encoding of a definition with
// every name replaced by "", every annotations map by {}, the hint flags
// cleared (method 0x1 and 0x4, field 0x2), and for a service its method
// list left out.

func typeShape(t *TypeDef) []byte {
	c := t.clone()
	sortDefs([]TypeDef{c}, nil, nil)
	c.Name, c.Annotations = "", nil
	for i := range c.Fields {
		f := &c.Fields[i]
		f.Name, f.Annotations = "", nil
		if c.Kind == KindStruct {
			f.Flags &^= FieldDeprecated
		}
	}
	w := &writer{canonical: true}
	w.typeDef(&c)
	return w.b
}

func serviceShape(s *Service) []byte {
	b := cbor.AppendUint(cbor.AppendArrayHead(nil, 3), s.ID)
	return cbor.AppendMapHead(cbor.AppendText(b, ""), 0)
}

func methodShape(m *Method) []byte {
	c := m.clone()
	sortUints(c.Errors)
	c.Name, c.Annotations = "", nil
	c.Flags &^= methodHintFlags
	w := &writer{canonical: true}
	w.method(&c)
	return w.b
}

func sigilShape(s *Sigil) []byte {
	c := *s
	c.Name, c.Annotations = "", nil
	w := &writer{canonical: true}
	w.sigil(&c)
	return w.b
}

// Conforms checks whether a facet implements an interface (section 6.5):
// every type, sigil and service of the interface appears in the facet with
// the same ID and wire shape, and every method of each interface service
// appears in the facet's service of the same ID with the same ID and wire
// shape. The facet may add definitions, including methods. It returns the
// first mismatch in the order types, services (each followed by its
// methods), sigils, or nil.
func Conforms(f *Facet, iface *Interface) *Mismatch {
	fc := f.Canonical()
	ic := iface.Canonical()
	fx := buildIndex(fc.Types, fc.Services, fc.Sigils)
	for i := range ic.Types {
		t := &ic.Types[i]
		ft := fx.types[t.ID]
		if ft == nil || !bytes.Equal(typeShape(t), typeShape(ft)) {
			return &Mismatch{SpaceType, t.ID}
		}
	}
	for i := range ic.Services {
		s := &ic.Services[i]
		fs := fx.svcs[s.ID]
		if fs == nil || !bytes.Equal(serviceShape(s), serviceShape(fs)) {
			return &Mismatch{SpaceService, s.ID}
		}
		for j := range s.Methods {
			m := &s.Methods[j]
			var fm *Method
			for k := range fs.Methods {
				if fs.Methods[k].ID == m.ID {
					fm = &fs.Methods[k]
				}
			}
			if fm == nil || !bytes.Equal(methodShape(m), methodShape(fm)) {
				return &Mismatch{SpaceMethod, m.ID}
			}
		}
	}
	for i := range ic.Sigils {
		s := &ic.Sigils[i]
		fs := fx.sigils[s.ID]
		if fs == nil || !bytes.Equal(sigilShape(s), sigilShape(fs)) {
			return &Mismatch{SpaceSigil, s.ID}
		}
	}
	return nil
}

// VerifyImplements checks a facet's implements claim against an interface:
// the claimed hash must equal the interface hash and the facet must
// conform. A facet that claims nothing passes.
func VerifyImplements(f *Facet, iface *Interface) error {
	if f.Implements == nil {
		return nil
	}
	h, err := iface.Hash()
	if err != nil {
		return err
	}
	if !bytes.Equal(h, f.Implements) {
		return errorf(CodeImplementsMismatch, "facet %d claims interface %x, not %x", f.ID, f.Implements, h)
	}
	if m := Conforms(f, iface); m != nil {
		return errorf(CodeImplementsMismatch, "facet %d: %v %d does not match the interface", f.ID, m.Space, m.ID)
	}
	return nil
}
