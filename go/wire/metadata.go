package wire

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/aiviarium/sparrow/go/cbor"
)

// Key is a metadata or trailers key: a symbol, that is a sigil (uint) or a
// text string (section 7.2).
type Key struct {
	Sigil  uint64
	Text   string
	IsText bool
}

// SigilKey returns a sigil key.
func SigilKey(s uint64) Key { return Key{Sigil: s} }

// TextKey returns a text key.
func TextKey(s string) Key { return Key{Text: s, IsText: true} }

func (k Key) String() string {
	if k.IsText {
		return fmt.Sprintf("%q", k.Text)
	}
	return fmt.Sprintf("%d", k.Sigil)
}

func (k Key) append(dst []byte) []byte {
	if k.IsText {
		return cbor.AppendText(dst, k.Text)
	}
	return cbor.AppendUint(dst, k.Sigil)
}

// Core metadata keys (section 7.2).
const (
	KeyDeadline  uint64 = 32 // uint, milliseconds the caller will wait
	KeyTrace     uint64 = 33 // bytes, packed traceparent (26 bytes)
	KeyReserved  uint64 = 34 // reserved
	KeyCredit    uint64 = 35 // uint, initial credit for the callee's half
	KeyContext   uint64 = 36 // bytes, hub call context (Hub Profile)
	KeyPrincipal uint64 = 37 // string, principal of a forwarded call (Hub Profile)
)

// TraceLen is the length of a packed traceparent: version (1), trace ID
// (16), parent ID (8), flags (1).
const TraceLen = 26

// Metadata is a metadata or trailers map, {* symbol => any}. Values are
// raw CBOR. A nil Metadata encodes as an empty map. Unknown keys are kept
// (and ignored by the typed accessors).
type Metadata map[Key]cbor.Raw

// ErrMetadataValue is wrapped by accessors when a core key holds a value of
// the wrong type.
var ErrMetadataValue = errors.New("wire: bad metadata value")

func (m Metadata) get(k uint64) (cbor.Raw, bool) {
	v, ok := m[SigilKey(k)]
	return v, ok
}

func (m Metadata) uintKey(k uint64) (uint64, bool, error) {
	v, ok := m.get(k)
	if !ok {
		return 0, false, nil
	}
	d := cbor.NewDecoder(v)
	u, err := d.Uint()
	if err != nil || !d.Done() {
		return 0, true, fmt.Errorf("%w: key %d must be a uint", ErrMetadataValue, k)
	}
	return u, true, nil
}

func (m Metadata) bytesKey(k uint64) ([]byte, bool, error) {
	v, ok := m.get(k)
	if !ok {
		return nil, false, nil
	}
	d := cbor.NewDecoder(v)
	b, err := d.Bytes()
	if err != nil || !d.Done() {
		return nil, true, fmt.Errorf("%w: key %d must be bytes", ErrMetadataValue, k)
	}
	return b, true, nil
}

// Deadline returns the deadline key (milliseconds).
func (m Metadata) Deadline() (uint64, bool, error) { return m.uintKey(KeyDeadline) }

// Credit returns the credit key (bytes).
func (m Metadata) Credit() (uint64, bool, error) { return m.uintKey(KeyCredit) }

// Trace returns the packed traceparent.
func (m Metadata) Trace() ([]byte, bool, error) {
	b, ok, err := m.bytesKey(KeyTrace)
	if err == nil && ok && len(b) != TraceLen {
		err = fmt.Errorf("%w: trace must be %d bytes, got %d", ErrMetadataValue, TraceLen, len(b))
	}
	return b, ok, err
}

// Context returns the hub call context.
func (m Metadata) Context() ([]byte, bool, error) { return m.bytesKey(KeyContext) }

// Principal returns the principal key.
func (m Metadata) Principal() (string, bool, error) {
	v, ok := m.get(KeyPrincipal)
	if !ok {
		return "", false, nil
	}
	d := cbor.NewDecoder(v)
	s, err := d.Text()
	if err != nil || !d.Done() {
		return "", true, fmt.Errorf("%w: principal must be a string", ErrMetadataValue)
	}
	return s, true, nil
}

func (m *Metadata) set(k Key, v cbor.Raw) {
	if *m == nil {
		*m = Metadata{}
	}
	(*m)[k] = v
}

// SetUint sets a sigil key to a uint value.
func (m *Metadata) SetUint(k uint64, v uint64) { m.set(SigilKey(k), cbor.AppendUint(nil, v)) }

// SetBytes sets a sigil key to a byte string value.
func (m *Metadata) SetBytes(k uint64, v []byte) { m.set(SigilKey(k), cbor.AppendBytes(nil, v)) }

// SetText sets a sigil key to a text value.
func (m *Metadata) SetText(k uint64, v string) { m.set(SigilKey(k), cbor.AppendText(nil, v)) }

// SetDeadline sets the deadline key.
func (m *Metadata) SetDeadline(ms uint64) { m.SetUint(KeyDeadline, ms) }

// SetCredit sets the credit key.
func (m *Metadata) SetCredit(n uint64) { m.SetUint(KeyCredit, n) }

// SetTrace sets the packed traceparent.
func (m *Metadata) SetTrace(b []byte) error {
	if len(b) != TraceLen {
		return fmt.Errorf("%w: trace must be %d bytes", ErrMetadataValue, TraceLen)
	}
	m.SetBytes(KeyTrace, b)
	return nil
}

// SetContext sets the hub call context.
func (m *Metadata) SetContext(b []byte) { m.SetBytes(KeyContext, b) }

// SetPrincipal sets the principal key.
func (m *Metadata) SetPrincipal(p string) { m.SetText(KeyPrincipal, p) }

// Delete removes a key.
func (m Metadata) Delete(k Key) { delete(m, k) }

// Clone returns a shallow copy (values are shared).
func (m Metadata) Clone() Metadata {
	if m == nil {
		return nil
	}
	c := make(Metadata, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// AppendTo appends the map with its keys in Core Deterministic order, so
// equal metadata always encodes to equal bytes.
func (m Metadata) AppendTo(dst []byte) []byte {
	type kv struct {
		k []byte
		v cbor.Raw
	}
	entries := make([]kv, 0, len(m))
	for k, v := range m {
		entries = append(entries, kv{k.append(nil), v})
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].k, entries[j].k) < 0 })
	dst = cbor.AppendMapHead(dst, len(entries))
	for _, e := range entries {
		dst = cbor.AppendRaw(append(dst, e.k...), e.v)
	}
	return dst
}

func readMetadata(d *cbor.Decoder) (Metadata, error) {
	n, err := d.MapHead()
	if err != nil {
		return nil, err
	}
	m := make(Metadata, n)
	for i := 0; i < n; i++ {
		var k Key
		maj, err := d.PeekMajor()
		if err != nil {
			return nil, err
		}
		switch maj {
		case cbor.MajorUint:
			s, _ := d.Uint()
			k = SigilKey(s)
		case cbor.MajorText:
			t, err := d.Text()
			if err != nil {
				return nil, err
			}
			k = TextKey(t)
		default:
			return nil, fmt.Errorf("wire: metadata key at offset %d is not a symbol", d.Offset())
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("wire: duplicate metadata key %v", k)
		}
		v, err := d.Raw()
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, nil
}

// TextMap is a map with text keys and raw values: caps, props
// ({* tstr => any}). A nil TextMap encodes as an empty map.
type TextMap map[string]cbor.Raw

// AppendTo appends the map in Core Deterministic key order.
func (m TextMap) AppendTo(dst []byte) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	cbor.SortTextKeys(keys)
	dst = cbor.AppendMapHead(dst, len(keys))
	for _, k := range keys {
		dst = cbor.AppendRaw(cbor.AppendText(dst, k), m[k])
	}
	return dst
}

func readTextMap(d *cbor.Decoder) (TextMap, error) {
	n, err := d.MapHead()
	if err != nil {
		return nil, err
	}
	m := make(TextMap, n)
	for i := 0; i < n; i++ {
		k, err := d.Text()
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("wire: duplicate key %q", k)
		}
		if m[k], err = d.Raw(); err != nil {
			return nil, err
		}
	}
	return m, nil
}
