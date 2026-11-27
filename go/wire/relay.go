package wire

import (
	"errors"
	"fmt"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

// PeekCall reads the kind of an encoded message and, for a call message
// (kinds 16-25), its call ID, without decoding the rest. For other kinds
// the call ID is 0. b should have passed Decode or cbor.Validate.
func PeekCall(b []byte) (Kind, uint64, error) {
	d := cbor.NewDecoder(b)
	n, err := d.ArrayHead()
	if err != nil {
		return 0, 0, err
	}
	if n == 0 {
		return 0, 0, errors.New("wire: empty envelope")
	}
	k, err := d.Uint()
	if err != nil {
		return 0, 0, err
	}
	kind := Kind(k)
	if !kind.IsCall() {
		return kind, 0, nil
	}
	if n < 2 {
		return kind, 0, errors.New("wire: call message without call ID")
	}
	id, err := d.Uint()
	return kind, id, err
}

// RewriteCallID returns a copy of an encoded call message (kinds 17-25)
// with its call ID replaced and every other element copied byte for byte,
// as a hub relays a call's later messages (section 10.5). A Request must be
// rewritten with ForwardRequest instead, since its facet ID and metadata
// change too.
func RewriteCallID(b []byte, newID uint64) ([]byte, error) {
	d := cbor.NewDecoder(b)
	n, err := d.ArrayHead()
	if err != nil {
		return nil, err
	}
	if n < 2 {
		return nil, errors.New("wire: not a call message")
	}
	k, err := d.Uint()
	if err != nil {
		return nil, err
	}
	kind := Kind(k)
	if !kind.IsCall() || kind == KindRequest {
		return nil, fmt.Errorf("wire: cannot rewrite the call ID of %v", kind)
	}
	if _, err := d.Uint(); err != nil {
		return nil, err
	}
	rest := b[d.Offset():]
	out := cbor.AppendUint(cbor.AppendArrayHead(make([]byte, 0, len(b)+8), n), k)
	out = cbor.AppendUint(out, newID)
	return append(out, rest...), nil
}

// ForwardRequest returns the encoding of r as forwarded on another hop:
// new call ID and facet ID, the given metadata, and the input copied byte
// for byte. The method ID never changes.
func ForwardRequest(r *Request, callID, facetID uint64, md Metadata) []byte {
	f := Request{CallID: callID, FacetID: facetID, MethodID: r.MethodID, Metadata: md, Input: r.Input}
	return f.AppendTo(nil)
}
