package websign

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

// FuzzDecode decodes certificates, revocation lists and module entries:
// whatever decodes re-encodes to bytes that decode to the same thing.
func FuzzDecode(f *testing.F) {
	for _, b := range fuzzseed.Hex("signing.json") {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := DecodeCertificate(b); err == nil {
			e := c.Encode()
			c2, err := DecodeCertificate(e)
			if err != nil || !bytes.Equal(c2.Encode(), e) {
				t.Fatalf("certificate round trip: %v", err)
			}
			if !bytes.Equal(c2.Unsigned(), c.Unsigned()) {
				t.Fatal("certificate signed bytes changed")
			}
		}
		if r, err := DecodeRevocation(b); err == nil {
			e := r.Encode()
			r2, err := DecodeRevocation(e)
			if err != nil || !bytes.Equal(r2.Encode(), e) {
				t.Fatalf("revocation round trip: %v", err)
			}
		}
		if m, err := DecodeModule(b); err == nil {
			u, uerr := m.Unsigned()
			e, err := m.Encode()
			if (err == nil) != (uerr == nil) {
				t.Fatalf("Encode %v, Unsigned %v", err, uerr)
			}
			if err != nil {
				return // floats in fields: not canonical data
			}
			m2, err := DecodeModule(e)
			if err != nil {
				t.Fatalf("module round trip: %v", err)
			}
			u2, err := m2.Unsigned()
			if err != nil || !bytes.Equal(u, u2) || m2.ID != m.ID || !bytes.Equal(m2.Sig, m.Sig) {
				t.Fatalf("module signed bytes changed: %v", err)
			}
		}
	})
}

// FuzzVerify checks the acceptance verdict of a module against arbitrary
// certificates and a revocation list, with the vectors' root keys: it does
// not depend on the order of the certificates, it is ok only if the
// signature checks with a key the verdict allows, and a module signed
// with a fresh key for the test is accepted exactly when its key is
// covered.
func FuzzVerify(f *testing.F) {
	hex := fuzzseed.Hex("signing.json")
	var roots [][]byte
	for _, b := range hex {
		if len(b) == 32 {
			roots = append(roots, b)
		}
	}
	roots = append(roots, pub(key(1)))
	var mods, certs, revs [][]byte
	for _, b := range hex {
		if _, err := DecodeModule(b); err == nil {
			mods = append(mods, b)
		}
		if _, err := DecodeCertificate(b); err == nil {
			certs = append(certs, b)
		}
		if _, err := DecodeRevocation(b); err == nil {
			revs = append(revs, b)
		}
	}
	certs = append(certs, nil)
	revs = append(revs, nil)
	for i, m := range mods {
		f.Add(m, certs[i%len(certs)], certs[(i+1)%len(certs)], revs[i%len(revs)], int64(1700000000+i))
	}
	f.Fuzz(func(t *testing.T, mb, c1, c2, rb []byte, now int64) {
		m, err := DecodeModule(mb)
		if err != nil {
			return
		}
		var cs []*Certificate
		for _, b := range [][]byte{c1, c2} {
			if c, err := DecodeCertificate(b); err == nil {
				cs = append(cs, c)
			}
		}
		var rev *Revocation
		if r, err := DecodeRevocation(rb); err == nil {
			rev = SelectRevocation(roots, r)
		}
		v := &Verifier{Roots: roots, Certificates: cs, Revocation: rev, Now: now}
		got := v.Verify(m)
		rv := &Verifier{Roots: roots, Revocation: rev, Now: now}
		for i := len(cs) - 1; i >= 0; i-- {
			rv.Certificates = append(rv.Certificates, cs[i])
		}
		if r := rv.Verify(m); r != got {
			t.Fatalf("verdict depends on certificate order: %s vs %s", got, r)
		}
		if got != ReasonOK {
			return
		}
		u, err := m.Unsigned()
		if err != nil {
			t.Fatal(err)
		}
		ok := false
		if k := v.root(m.KeyID); k != nil {
			ok = VerifySignature(k, DomainModule, u, m.Sig)
		}
		for _, c := range cs {
			if bytes.Equal(KeyID(c.PublisherKey), m.KeyID) && v.CertificateValid(c, m.ID) == ReasonOK &&
				!v.revoked(m.KeyID) && VerifySignature(c.PublisherKey, DomainModule, u, m.Sig) {
				ok = true
			}
		}
		if !ok {
			t.Fatal("accepted a module no allowed key signed")
		}
	})
}

// FuzzVersion parses semver strings: precedence is a total order that
// ignores build metadata only, and Rollback follows it.
func FuzzVersion(f *testing.F) {
	for _, s := range []string{"1.0.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7", "1.0.0-x.7.z.92",
		"1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85", "2.0.0-rc.1", "01.0.0", "1.0", "1.0.0-01"} {
		f.Add(s, "1.0.0-alpha.beta")
	}
	for _, s := range fuzzseed.Text("signing.json") {
		f.Add(s, "3.1.0")
	}
	f.Add("1.0.0-18446744073709551616", "1.0.0-18446744073709551617") // beyond uint64
	f.Fuzz(func(t *testing.T, a, b string) {
		va, err := ParseVersion(a)
		if err != nil {
			return
		}
		vb, err := ParseVersion(b)
		if err != nil {
			return
		}
		ab, ba := va.Compare(vb), vb.Compare(va)
		if ab != -ba {
			t.Fatalf("Compare not antisymmetric: %q %q %d %d", a, b, ab, ba)
		}
		strip := func(s string) string {
			if i := strings.IndexByte(s, '+'); i >= 0 {
				return s[:i]
			}
			return s
		}
		if (ab == 0) != (strip(a) == strip(b)) {
			t.Fatalf("Compare(%q, %q) = %d", a, b, ab)
		}
		var r Rollback
		if err := r.Record("m", a); err != nil {
			t.Fatal(err)
		}
		if ok, err := r.Allowed("m", b); err != nil || ok != (ab <= 0) {
			t.Fatalf("Allowed(%q after %q) = %v %v", b, a, ok, err)
		}
	})
}
