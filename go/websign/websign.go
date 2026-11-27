// Package websign implements module signing of the Sparrow Web Profile
// (section 9.5): key IDs, signature inputs, publisher certificates,
// revocation lists, web-module entries, the acceptance rules and semver
// version precedence for rollback protection.
package websign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/aiviarium/sparrow/go/cbor"
)

// Signature domains.
const (
	DomainModule  = "sparrow-module-v1"
	DomainCert    = "sparrow-cert-v1"
	DomainRevoked = "sparrow-revoked-v1"
)

// KeyIDLen is the length of a key_id.
const KeyIDLen = 16

// KeyID returns the first 16 bytes of SHA-256 of a raw 32-byte Ed25519
// public key.
func KeyID(pub []byte) []byte {
	s := sha256.Sum256(pub)
	return append([]byte{}, s[:KeyIDLen]...)
}

// SignedBytes returns what a signature covers: the canonical CBOR of the
// two-element array [domain, value], where value is the signed array or map
// without its signature element.
func SignedBytes(domain string, value cbor.Raw) ([]byte, error) {
	b := cbor.AppendText(cbor.AppendArrayHead(nil, 2), domain)
	b = cbor.AppendRaw(b, value)
	return cbor.Canonical(b, cbor.Options{NoFloats: true})
}

// Sign signs value under a domain.
func Sign(priv ed25519.PrivateKey, domain string, value cbor.Raw) ([]byte, error) {
	b, err := SignedBytes(domain, value)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, b), nil
}

// VerifySignature checks a signature over value under a domain.
func VerifySignature(pub []byte, domain string, value cbor.Raw, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	b, err := SignedBytes(domain, value)
	return err == nil && ed25519.Verify(pub, b, sig)
}

// FileHash returns a file hash in schema hash format: 0x01 || SHA-256.
func FileHash(data []byte) []byte {
	s := sha256.Sum256(data)
	return append([]byte{0x01}, s[:]...)
}

// ---------------------------------------------------------------------------
// Certificates and revocation lists
// ---------------------------------------------------------------------------

// Certificate is a web.keys entry:
// [publisher_key, namespace, expires, root_key_id, root_sig].
type Certificate struct {
	PublisherKey []byte
	Namespace    string
	Expires      int64 // tag 1, integer seconds
	RootKeyID    []byte
	RootSig      []byte
}

// Unsigned returns the signed array without root_sig.
func (c *Certificate) Unsigned() cbor.Raw {
	b := cbor.AppendBytes(cbor.AppendArrayHead(nil, 4), c.PublisherKey)
	b = cbor.AppendText(b, c.Namespace)
	b = cbor.AppendTime(b, cbor.Unix(c.Expires))
	return cbor.AppendBytes(b, c.RootKeyID)
}

// Encode returns the certificate as it appears in web.keys.
func (c *Certificate) Encode() cbor.Raw {
	u := c.Unsigned()
	b := append(cbor.AppendArrayHead(nil, 5), u[1:]...)
	return cbor.AppendBytes(b, c.RootSig)
}

// SignCertificate creates a certificate signed by a root key.
func SignCertificate(root ed25519.PrivateKey, publisher []byte, namespace string, expires int64) (*Certificate, error) {
	c := &Certificate{PublisherKey: publisher, Namespace: namespace, Expires: expires,
		RootKeyID: KeyID(root.Public().(ed25519.PublicKey))}
	sig, err := Sign(root, DomainCert, c.Unsigned())
	c.RootSig = sig
	return c, err
}

// DecodeCertificate decodes a web.keys entry.
func DecodeCertificate(raw []byte) (*Certificate, error) {
	if err := cbor.Validate(raw, cbor.Options{}); err != nil {
		return nil, err
	}
	d := cbor.NewDecoder(raw)
	n, err := d.ArrayHead()
	if err != nil {
		return nil, err
	}
	if n != 5 {
		return nil, fmt.Errorf("websign: certificate has %d elements, want 5", n)
	}
	c := &Certificate{}
	if c.PublisherKey, err = d.Bytes(); err != nil {
		return nil, err
	}
	if c.Namespace, err = d.Text(); err != nil {
		return nil, err
	}
	t, err := d.Time()
	if err != nil {
		return nil, err
	}
	if t.IsFloat {
		return nil, errors.New("websign: expires must be integer seconds")
	}
	c.Expires = t.Sec
	if c.RootKeyID, err = d.Bytes(); err != nil {
		return nil, err
	}
	if c.RootSig, err = d.Bytes(); err != nil {
		return nil, err
	}
	return c, nil
}

// Revocation is a web.revoked list: [seq, [* key_id], root_key_id, root_sig].
type Revocation struct {
	Seq       uint64
	KeyIDs    [][]byte
	RootKeyID []byte
	RootSig   []byte
}

// Unsigned returns the signed array without root_sig.
func (r *Revocation) Unsigned() cbor.Raw {
	b := cbor.AppendUint(cbor.AppendArrayHead(nil, 3), r.Seq)
	b = cbor.AppendArrayHead(b, len(r.KeyIDs))
	for _, k := range r.KeyIDs {
		b = cbor.AppendBytes(b, k)
	}
	return cbor.AppendBytes(b, r.RootKeyID)
}

// Encode returns the list as it appears in web.revoked.
func (r *Revocation) Encode() cbor.Raw {
	u := r.Unsigned()
	return cbor.AppendBytes(append(cbor.AppendArrayHead(nil, 4), u[1:]...), r.RootSig)
}

// SignRevocation creates a revocation list signed by a root key.
func SignRevocation(root ed25519.PrivateKey, seq uint64, keyIDs [][]byte) (*Revocation, error) {
	r := &Revocation{Seq: seq, KeyIDs: keyIDs, RootKeyID: KeyID(root.Public().(ed25519.PublicKey))}
	sig, err := Sign(root, DomainRevoked, r.Unsigned())
	r.RootSig = sig
	return r, err
}

// DecodeRevocation decodes a web.revoked list.
func DecodeRevocation(raw []byte) (*Revocation, error) {
	if err := cbor.Validate(raw, cbor.Options{}); err != nil {
		return nil, err
	}
	d := cbor.NewDecoder(raw)
	n, err := d.ArrayHead()
	if err != nil {
		return nil, err
	}
	if n != 4 {
		return nil, fmt.Errorf("websign: revocation list has %d elements, want 4", n)
	}
	r := &Revocation{}
	if r.Seq, err = d.SafeUint(); err != nil {
		return nil, err
	}
	k, err := d.ArrayHead()
	if err != nil {
		return nil, err
	}
	for i := 0; i < k; i++ {
		id, err := d.Bytes()
		if err != nil {
			return nil, err
		}
		r.KeyIDs = append(r.KeyIDs, id)
	}
	if r.RootKeyID, err = d.Bytes(); err != nil {
		return nil, err
	}
	if r.RootSig, err = d.Bytes(); err != nil {
		return nil, err
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// Module entries
// ---------------------------------------------------------------------------

// Module is a web-module entry (section 9.4). Fields holds every entry of
// the map, including unknown keys and sig, as raw CBOR.
type Module struct {
	ID      string
	Version string
	Hash    []byte
	KeyID   []byte
	Sig     []byte
	Fields  map[string]cbor.Raw
}

// DecodeModule decodes a web-module map.
func DecodeModule(raw []byte) (*Module, error) {
	if err := cbor.Validate(raw, cbor.Options{}); err != nil {
		return nil, err
	}
	d := cbor.NewDecoder(raw)
	n, err := d.MapHead()
	if err != nil {
		return nil, err
	}
	m := &Module{Fields: map[string]cbor.Raw{}}
	for i := 0; i < n; i++ {
		k, err := d.Text()
		if err != nil {
			return nil, err
		}
		if m.Fields[k], err = d.Raw(); err != nil {
			return nil, err
		}
	}
	text := func(k string) (string, error) {
		v, ok := m.Fields[k]
		if !ok {
			return "", fmt.Errorf("websign: module has no %q", k)
		}
		return cbor.NewDecoder(v).Text()
	}
	if m.ID, err = text("id"); err != nil {
		return nil, err
	}
	if m.Version, err = text("version"); err != nil {
		return nil, err
	}
	for _, k := range []string{"url", "hostApi"} {
		if _, err := text(k); err != nil {
			return nil, err
		}
	}
	if _, ok := m.Fields["deps"]; !ok {
		return nil, errors.New(`websign: module has no "deps"`)
	}
	hv, ok := m.Fields["hash"]
	if !ok {
		return nil, errors.New(`websign: module has no "hash"`)
	}
	if m.Hash, err = cbor.NewDecoder(hv).Bytes(); err != nil {
		return nil, err
	}
	sv, ok := m.Fields["sig"]
	if !ok {
		return nil, errors.New(`websign: module has no "sig"`)
	}
	sd := cbor.NewDecoder(sv)
	if k, err := sd.ArrayHead(); err != nil || k != 2 {
		return nil, errors.New("websign: sig must be [key_id, signature]")
	}
	if m.KeyID, err = sd.Bytes(); err != nil {
		return nil, err
	}
	if m.Sig, err = sd.Bytes(); err != nil {
		return nil, err
	}
	return m, nil
}

// Unsigned returns the entry without sig, canonically encoded.
func (m *Module) Unsigned() (cbor.Raw, error) {
	keys := make([]string, 0, len(m.Fields))
	for k := range m.Fields {
		if k != "sig" {
			keys = append(keys, k)
		}
	}
	cbor.SortTextKeys(keys)
	b := cbor.AppendMapHead(nil, len(keys))
	for _, k := range keys {
		b = cbor.AppendRaw(cbor.AppendText(b, k), m.Fields[k])
	}
	return cbor.Canonical(b, cbor.Options{NoFloats: true})
}

// Encode returns the entry with sig.
func (m *Module) Encode() (cbor.Raw, error) {
	f := map[string]cbor.Raw{}
	for k, v := range m.Fields {
		f[k] = v
	}
	sig := cbor.AppendBytes(cbor.AppendArrayHead(nil, 2), m.KeyID)
	f["sig"] = cbor.AppendBytes(sig, m.Sig)
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	cbor.SortTextKeys(keys)
	b := cbor.AppendMapHead(nil, len(keys))
	for _, k := range keys {
		b = cbor.AppendRaw(cbor.AppendText(b, k), f[k])
	}
	return cbor.Canonical(b, cbor.Options{NoFloats: true})
}

// SignModule sets the module's sig with the given key, root or publisher.
func SignModule(m *Module, key ed25519.PrivateKey) error {
	u, err := m.Unsigned()
	if err != nil {
		return err
	}
	sig, err := Sign(key, DomainModule, u)
	if err != nil {
		return err
	}
	m.KeyID, m.Sig = KeyID(key.Public().(ed25519.PublicKey)), sig
	return nil
}

// VerifyFile checks module bytes against the signed hash.
func (m *Module) VerifyFile(data []byte) bool { return bytes.Equal(FileHash(data), m.Hash) }

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

// Reason is a verification verdict; ReasonOK accepts.
type Reason string

const (
	ReasonOK                  Reason = "ok"
	ReasonBadModuleSignature  Reason = "bad_module_signature"
	ReasonUnknownKey          Reason = "unknown_key"
	ReasonUnknownRoot         Reason = "unknown_root"
	ReasonBadCertSignature    Reason = "bad_certificate_signature"
	ReasonNamespaceNoDot      Reason = "namespace_missing_trailing_dot"
	ReasonCertificateExpired  Reason = "certificate_expired"
	ReasonNamespaceNotCovered Reason = "namespace_not_covered"
	ReasonKeyRevoked          Reason = "key_revoked"
)

// certRank orders certificate failures by how far the checks got.
var certRank = map[Reason]int{ReasonUnknownKey: 0, ReasonUnknownRoot: 1, ReasonBadCertSignature: 2,
	ReasonNamespaceNoDot: 3, ReasonCertificateExpired: 4, ReasonNamespaceNotCovered: 5}

// Verifier holds what a client checks modules against.
type Verifier struct {
	// Roots are the root public keys embedded in the client build.
	Roots [][]byte
	// Certificates are the web.keys entries of the top-level schema
	// annotations.
	Certificates []*Certificate
	// Revocation is the list in effect (see SelectRevocation), or nil.
	Revocation *Revocation
	// Now is the time, in seconds, at which certificate expiry is checked:
	// when the module is accepted into a snapshot.
	Now int64
}

func (v *Verifier) root(keyID []byte) []byte {
	for _, r := range v.Roots {
		if bytes.Equal(KeyID(r), keyID) {
			return r
		}
	}
	return nil
}

// SelectRevocation returns the list with the highest seq among those signed
// by a root key; lists not signed by a root key do not count. It returns
// nil if none counts.
func SelectRevocation(roots [][]byte, lists ...*Revocation) *Revocation {
	v := &Verifier{Roots: roots}
	var best *Revocation
	for _, l := range lists {
		if l == nil {
			continue
		}
		pub := v.root(l.RootKeyID)
		if pub == nil || !VerifySignature(pub, DomainRevoked, l.Unsigned(), l.RootSig) {
			continue
		}
		if best == nil || l.Seq > best.Seq {
			best = l
		}
	}
	return best
}

func (v *Verifier) revoked(keyID []byte) bool {
	if v.Revocation == nil || v.root(keyID) != nil {
		return false // entries naming a root key are ignored
	}
	for _, k := range v.Revocation.KeyIDs {
		if bytes.Equal(k, keyID) {
			return true
		}
	}
	return false
}

// CertificateValid checks a certificate on its own and for a module id,
// returning ReasonOK if it lets its publisher key sign that module now.
func (v *Verifier) CertificateValid(c *Certificate, moduleID string) Reason {
	root := v.root(c.RootKeyID)
	switch {
	case root == nil:
		return ReasonUnknownRoot
	case !VerifySignature(root, DomainCert, c.Unsigned(), c.RootSig):
		return ReasonBadCertSignature
	case !strings.HasSuffix(c.Namespace, "."):
		return ReasonNamespaceNoDot
	case v.Now >= c.Expires: // valid while now is strictly before expires
		return ReasonCertificateExpired
	case !strings.HasPrefix(moduleID, c.Namespace): // UTF-8 byte prefix
		return ReasonNamespaceNotCovered
	}
	return ReasonOK
}

// Verify decides whether a module is accepted. Every rule must hold: the
// signing key is a root key, or a publisher key that is not revoked and
// has at least one valid certificate whose namespace covers the module id;
// and the signature over ["sparrow-module-v1", entry without sig] checks.
// The verdict does not depend on the order of the checks. When several
// certificates name the key and none is valid, the reason is that of the
// one that passed the most checks.
func (v *Verifier) Verify(m *Module) Reason {
	key := v.root(m.KeyID)
	if key == nil {
		if v.revoked(m.KeyID) {
			return ReasonKeyRevoked
		}
		reason := ReasonUnknownKey
		for _, c := range v.Certificates {
			if !bytes.Equal(KeyID(c.PublisherKey), m.KeyID) {
				continue
			}
			if r := v.CertificateValid(c, m.ID); r != ReasonOK {
				if certRank[r] > certRank[reason] {
					reason = r // report the certificate that came closest
				}
				continue
			}
			key = c.PublisherKey
			break
		}
		if key == nil {
			return reason
		}
	}
	u, err := m.Unsigned()
	if err != nil || !VerifySignature(key, DomainModule, u, m.Sig) {
		return ReasonBadModuleSignature
	}
	return ReasonOK
}
