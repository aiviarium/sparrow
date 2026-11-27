package websign

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

func key(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}

func pub(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

func module(t *testing.T, id, version string, signer ed25519.PrivateKey) *Module {
	t.Helper()
	file := []byte("export default () => ({})")
	m := &Module{Fields: map[string]cbor.Raw{
		"id":      cbor.AppendText(nil, id),
		"version": cbor.AppendText(nil, version),
		"hash":    cbor.AppendBytes(nil, FileHash(file)),
		"url":     cbor.AppendText(nil, "/m.js"),
		"deps":    cbor.AppendArrayHead(nil, 0),
		"hostApi": cbor.AppendText(nil, "^3.1"),
	}}
	if err := SignModule(m, signer); err != nil {
		t.Fatal(err)
	}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeModule(b)
	if err != nil {
		t.Fatal(err)
	}
	if !d.VerifyFile(file) || d.VerifyFile([]byte("x")) {
		t.Fatal("VerifyFile")
	}
	return d
}

func TestVerify(t *testing.T) {
	root, acme, beta, other := key(1), key(2), key(3), key(4)
	const now = 1000
	certA, _ := SignCertificate(root, pub(acme), "acme.", now+10)
	certAOld, _ := SignCertificate(root, pub(acme), "acme.", now-10) // expired, but another is valid
	certB, _ := SignCertificate(root, pub(beta), "beta.", now+10)
	certNoDot, _ := SignCertificate(root, pub(other), "other", now+10)
	forged, _ := SignCertificate(other, pub(other), "other.", now+10) // not signed by a root
	rev1, _ := SignRevocation(root, 1, [][]byte{KeyID(pub(beta))})
	rev2, _ := SignRevocation(root, 2, [][]byte{KeyID(pub(root))}) // naming the root is ignored
	forgedRev, _ := SignRevocation(other, 9, [][]byte{KeyID(pub(acme))})
	v := &Verifier{Roots: [][]byte{pub(root)}, Certificates: []*Certificate{certAOld, certA, certB, certNoDot, forged}, Now: now}

	if got := SelectRevocation(v.Roots, rev1, forgedRev, nil, rev2); got != rev2 {
		t.Fatalf("SelectRevocation picked seq %d", got.Seq)
	}
	if SelectRevocation(v.Roots, forgedRev) != nil {
		t.Fatal("forged list counted")
	}
	tests := []struct {
		name string
		m    *Module
		rev  *Revocation
		want Reason
	}{
		{"publisher", module(t, "acme.charts", "1.0.0", acme), rev1, ReasonOK},
		{"root", module(t, "anything.at.all", "1.0.0", root), rev2, ReasonOK},
		{"namespace not covered", module(t, "acmecorp.x", "1.0.0", acme), nil, ReasonNamespaceNotCovered},
		{"namespace without dot", module(t, "other.x", "1.0.0", other), nil, ReasonNamespaceNoDot},
		{"revoked", module(t, "beta.x", "1.0.0", beta), rev1, ReasonKeyRevoked},
		{"not revoked by a later list that only names the root", module(t, "beta.x", "1.0.0", beta), rev2, ReasonOK},
		{"unknown key", module(t, "acme.x", "1.0.0", key(9)), nil, ReasonUnknownKey},
	}
	for _, tc := range tests {
		v.Revocation = tc.rev
		if got := v.Verify(tc.m); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
	v.Revocation = nil
	m := module(t, "acme.charts", "1.0.0", acme)
	m.Fields["version"] = cbor.AppendText(nil, "1.0.1") // tampered after signing
	if got := v.Verify(m); got != ReasonBadModuleSignature {
		t.Errorf("tampered: %s", got)
	}
	m = module(t, "acme.charts", "1.0.0", acme)
	m.Fields["extra"] = cbor.AppendUint(nil, 1) // unknown keys are covered too
	if got := v.Verify(m); got != ReasonBadModuleSignature {
		t.Errorf("extra key: %s", got)
	}
	// expiry is strictly-before
	v.Now = now + 10
	if got := v.Verify(module(t, "acme.charts", "1.0.0", acme)); got != ReasonCertificateExpired {
		t.Errorf("at expiry: %s", got)
	}
	// a certificate whose root signature is bad
	bad := *certA
	bad.Namespace = "acme.charts."
	v.Now, v.Certificates = now, []*Certificate{&bad}
	if got := v.Verify(module(t, "acme.charts", "1.0.0", acme)); got != ReasonBadCertSignature {
		t.Errorf("bad cert: %s", got)
	}
	v.Roots = nil
	if got := v.Verify(module(t, "acme.charts", "1.0.0", acme)); got != ReasonUnknownRoot {
		t.Errorf("unknown root: %s", got)
	}
}

func TestEncodings(t *testing.T) {
	root := key(1)
	c, _ := SignCertificate(root, pub(key(2)), "acme.", 1798761600)
	d, err := DecodeCertificate(c.Encode())
	if err != nil || !bytes.Equal(d.Encode(), c.Encode()) {
		t.Fatalf("certificate round trip: %v", err)
	}
	r, _ := SignRevocation(root, 3, [][]byte{{1}, {2}})
	dr, err := DecodeRevocation(r.Encode())
	if err != nil || !bytes.Equal(dr.Encode(), r.Encode()) {
		t.Fatalf("revocation round trip: %v", err)
	}
	if !VerifySignature(pub(root), DomainRevoked, r.Unsigned(), r.RootSig) ||
		VerifySignature(pub(root), DomainCert, r.Unsigned(), r.RootSig) {
		t.Fatal("domain separation")
	}
	if VerifySignature([]byte{1}, DomainCert, c.Unsigned(), c.RootSig) || VerifySignature(pub(root), DomainCert, c.Unsigned(), []byte{1}) {
		t.Fatal("bad key or signature sizes accepted")
	}
	bad := [][]byte{
		{0x84, 0x40, 0x60, 0xc1, 0x00, 0x40},                   // 4 elements
		{0x85, 0x40, 0x60, 0xc1, 0xf9, 0x3c, 0x00, 0x40, 0x40}, // float expires
		{0x85, 0x40, 0x60, 0x00, 0x40, 0x40},                   // untagged expires
		{0x85, 0x60, 0x60, 0xc1, 0x00, 0x40, 0x40},             // key not bytes
	}
	for _, b := range bad {
		if _, err := DecodeCertificate(b); err == nil {
			t.Errorf("certificate %x accepted", b)
		}
	}
	for _, b := range [][]byte{{0x83, 0x00, 0x80, 0x40}, {0x84, 0x20, 0x80, 0x40, 0x40}, {0x84, 0x00, 0x81, 0x00, 0x40, 0x40}} {
		if _, err := DecodeRevocation(b); err == nil {
			t.Errorf("revocation %x accepted", b)
		}
	}
	if _, err := DecodeModule([]byte{0xa1, 0x62, 'i', 'd', 0x61, 'a'}); err == nil {
		t.Error("module without fields accepted")
	}
	if _, err := DecodeModule([]byte{0x80}); err == nil {
		t.Error("module array accepted")
	}
	if len(KeyID(pub(root))) != KeyIDLen {
		t.Error("KeyID length")
	}
}

func TestSemver(t *testing.T) {
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "1.10.0", "2.0.0"}
	for i := range order {
		for j := range order {
			got, err := CompareVersions(order[i], order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if err != nil || got != want {
				t.Errorf("Compare(%s, %s) = %d, %v", order[i], order[j], got, err)
			}
		}
	}
	if c, _ := CompareVersions("1.0.0+build.1", "1.0.0+other"); c != 0 {
		t.Error("build metadata affects precedence")
	}
	for _, bad := range []string{"1", "1.0", "01.0.0", "1.0.0-", "1.0.0-01", "1.0.0-a..b", "1.0.0+", "v1.0.0", "1.0.0-ä", "a.b.c"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
	var r Rollback
	if ok, _ := r.Allowed("m", "0.1.0"); !ok {
		t.Error("nothing recorded")
	}
	_ = r.Record("m", "1.4.2")
	_ = r.Record("m", "1.3.0")
	for v, want := range map[string]bool{"1.4.2": true, "1.4.3": true, "1.4.2-rc.1": false, "1.3.9": false} {
		if ok, err := r.Allowed("m", v); ok != want || err != nil {
			t.Errorf("Allowed(%s) = %v %v", v, ok, err)
		}
	}
	if err := r.Record("m", "x"); err == nil {
		t.Error("Record accepted a bad version")
	}
	if _, err := r.Allowed("m", "x"); err == nil {
		t.Error("Allowed accepted a bad version")
	}
}

func TestFacetWebKeys(t *testing.T) {
	h, ig := FacetWebKeys([]string{"doc", "web.apply", "web.keys", "web.modules", "webx"})
	if len(h) != 1 || h[0] != "web.modules" || len(ig) != 2 {
		t.Errorf("%v %v", h, ig)
	}
}
