package conformance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/websign"
)

// checkSigned checks the parts every signed vector shares and returns the
// encoded unsigned value.
func checkSigned(t *testing.T, v vectors.Vector, unsigned []byte) {
	t.Helper()
	if !bytes.Equal(unsigned, v.CBOR("unsigned")) {
		t.Fatalf("unsigned value differs\n got %x\nwant %x", unsigned, v.CBOR("unsigned"))
	}
	sb, err := websign.SignedBytes(v.String("domain"), unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sb, v.Hex("signed_bytes")) || !bytes.Equal(sb, v.CBOR("signed_value")) {
		t.Fatalf("signed bytes %x", sb)
	}
	key := ed25519.NewKeyFromSeed(v.Hex("signer_seed"))
	sig, err := websign.Sign(key, v.String("domain"), unsigned)
	if err != nil || !bytes.Equal(sig, v.Hex("signature")) {
		t.Fatalf("signature %x, want %x", sig, v.Hex("signature"))
	}
	if !websign.VerifySignature(key.Public().(ed25519.PublicKey), v.String("domain"), unsigned, sig) {
		t.Fatal("signature does not verify")
	}
}

func certificates(t *testing.T) []*websign.Certificate {
	var out []*websign.Certificate
	for _, v := range file(t, "signing.json").Vectors {
		if v.Type != "certificate" {
			continue
		}
		c, err := websign.DecodeCertificate(v.Hex("certificate_cbor"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func TestSigning(t *testing.T) {
	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		if !v.Bool("test_only") {
			t.Fatal("key not marked test-only")
		}
		pub := ed25519.NewKeyFromSeed(v.Hex("seed")).Public().(ed25519.PublicKey)
		s := sha256.Sum256(pub)
		if !bytes.Equal(pub, v.Hex("public_key")) || !bytes.Equal(s[:], v.Hex("sha256_public_key")) ||
			!bytes.Equal(websign.KeyID(pub), v.Hex("key_id")) {
			t.Fatalf("key mismatch")
		}
	}, "key")

	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		cb := v.Hex("certificate_cbor")
		if !bytes.Equal(cb, v.CBOR("certificate")) {
			t.Fatal("certificate_cbor differs from certificate")
		}
		c, err := websign.DecodeCertificate(cb)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(c.Encode(), cb) {
			t.Fatal("re-encoding differs")
		}
		checkSigned(t, v, c.Unsigned())
		if !bytes.Equal(c.RootSig, v.Hex("signature")) {
			t.Fatal("root_sig")
		}
	}, "certificate")

	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		rb := v.Hex("revocation_cbor")
		if !bytes.Equal(rb, v.CBOR("revocation")) {
			t.Fatal("revocation_cbor differs")
		}
		r, err := websign.DecodeRevocation(rb)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(r.Encode(), rb) {
			t.Fatal("re-encoding differs")
		}
		checkSigned(t, v, r.Unsigned())
	}, "revocation")

	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		eb := v.Hex("entry_cbor")
		if !bytes.Equal(eb, v.CBOR("entry")) {
			t.Fatal("entry_cbor differs")
		}
		m, err := websign.DecodeModule(eb)
		if err != nil {
			t.Fatal(err)
		}
		if enc, _ := m.Encode(); !bytes.Equal(enc, eb) {
			t.Fatal("re-encoding differs")
		}
		u, err := m.Unsigned()
		if err != nil {
			t.Fatal(err)
		}
		if v.Name == "module/tampered" {
			// signed before the version changed: the vector's unsigned value
			// is the original one, so only the signature input is checked.
			if bytes.Equal(u, v.CBOR("unsigned")) {
				t.Fatal("tampered entry equals what was signed")
			}
			u = v.CBOR("unsigned")
		}
		checkSigned(t, v, u)
		if !bytes.Equal(m.Sig, v.Hex("signature")) {
			t.Fatal("sig")
		}
		file := []byte(v.String("file_utf8"))
		if !bytes.Equal(websign.FileHash(file), v.Hex("file_hash")) || !m.VerifyFile(file) {
			t.Fatal("file hash")
		}
	}, "module")

	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		if !bytes.Equal(websign.FileHash([]byte(v.String("file_utf8"))), v.Hex("hash")) {
			t.Fatal("file hash")
		}
	}, "file_hash")

	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		var ctx struct {
			Roots []string `json:"root_public_keys"`
			Now   int64    `json:"now"`
		}
		if err := json.Unmarshal(file(t, "signing.json").Header["verification_context"], &ctx); err != nil {
			t.Fatal(err)
		}
		var roots [][]byte
		for _, r := range ctx.Roots {
			roots = append(roots, vectors.MustHex(r))
		}
		rev, err := websign.DecodeRevocation(vector(t, v.String("revocation")).Hex("revocation_cbor"))
		if err != nil {
			t.Fatal(err)
		}
		m, err := websign.DecodeModule(vector(t, v.String("module")).Hex("entry_cbor"))
		if err != nil {
			t.Fatal(err)
		}
		ver := &websign.Verifier{Roots: roots, Certificates: certificates(t),
			Revocation: websign.SelectRevocation(roots, rev), Now: ctx.Now}
		got := ver.Verify(m)
		if string(got) != v.String("expected_reason") || (got == websign.ReasonOK) != v.Bool("expected_valid") {
			t.Fatalf("Verify = %s, want %s", got, v.String("expected_reason"))
		}
	}, "verify")

	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		if got := names.ModuleInFacet(v.String("facet_name"), v.String("module_id")); got != v.Bool("expected_valid") {
			t.Fatalf("ModuleInFacet = %v", got)
		}
	}, "module_scope")

	each(t, "signing.json", func(t *testing.T, v vectors.Vector) {
		var ann map[string]json.RawMessage
		v.Into("facet_annotations", &ann)
		var keys []string
		for k := range ann {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		h, ig := websign.FacetWebKeys(keys)
		var wantH, wantI []string
		v.Into("honoured_web_keys", &wantH)
		v.Into("ignored_web_keys", &wantI)
		sort.Strings(wantH)
		sort.Strings(wantI)
		if !equalStrings(h, wantH) || !equalStrings(ig, wantI) {
			t.Fatalf("honoured %v ignored %v", h, ig)
		}
	}, "facet_web_keys")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
