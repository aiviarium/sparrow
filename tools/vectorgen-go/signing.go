package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Section 9.5 "Signed formats".
//
// ALL KEYS IN THIS FILE ARE TEST-ONLY. Their seeds are trivial byte
// patterns (32 x 0x01, 32 x 0x02, ...). Never use them for anything real.

const (
	domainModule  = "sparrow-module-v1"
	domainCert    = "sparrow-cert-v1"
	domainRevoked = "sparrow-revoked-v1"

	tExpires = 1798761600 // 2027-01-01T00:00:00Z
	tExpired = 1793491200 // 2026-11-01T00:00:00Z
	tNow     = 1795737600 // 2026-11-27T00:00:00Z, the verification time used by the cases
)

type testKey struct {
	label string
	seed  []byte
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	id    []byte
}

func mkKey(label string, b byte) *testKey {
	seed := bytes.Repeat([]byte{b}, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &testKey{label, seed, priv, pub, keyID(pub)}
}

func keyID(pub []byte) []byte {
	s := sha256.Sum256(pub)
	return s[:16]
}

func fileHash(b []byte) []byte {
	s := sha256.Sum256(b)
	return append([]byte{0x01}, s[:]...)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signedBytes: domain string as raw UTF-8 bytes, immediately followed by the
// canonical CBOR of the value without its signature element. No separator
// and no length prefix (see Assumptions).
func signedBytes(domain string, unsigned any) []byte {
	return cat([]byte(domain), enc(unsigned))
}

var (
	kRoot    = mkKey("TEST-ONLY root key (seed 32 x 0x01)", 0x01)
	kAcme    = mkKey("TEST-ONLY publisher key 'acme' (seed 32 x 0x02)", 0x02)
	kBeta    = mkKey("TEST-ONLY publisher key 'beta', revoked (seed 32 x 0x03)", 0x03)
	kNoCert  = mkKey("TEST-ONLY uncertified key (seed 32 x 0x04)", 0x04)
	kGamma   = mkKey("TEST-ONLY publisher key 'gamma', certificate expired (seed 32 x 0x05)", 0x05)
	kDelta   = mkKey("TEST-ONLY publisher key 'delta', namespace without trailing dot (seed 32 x 0x06)", 0x06)
	kOmega   = mkKey("TEST-ONLY publisher key 'omega', certificate signed with the wrong domain (seed 32 x 0x07)", 0x07)
	allKeys  = []*testKey{kRoot, kAcme, kBeta, kNoCert, kGamma, kDelta, kOmega}
	rootKeys = []*testKey{kRoot}
)

func expiresTag(t uint64) cbor.Tag { return cbor.Tag{Number: 1, Content: t} }

type cert struct {
	name, desc string
	pub        *testKey
	ns         string
	expires    uint64
	domain     string
	unsigned   []any
	signed     []byte
	sig        []byte
	full       []any
}

func mkCert(name, desc string, k *testKey, ns string, expires uint64, domain string) *cert {
	c := &cert{name: name, desc: desc, pub: k, ns: ns, expires: expires, domain: domain}
	c.unsigned = []any{[]byte(k.pub), ns, expiresTag(expires), kRoot.id}
	c.signed = signedBytes(domain, c.unsigned)
	c.sig = ed25519.Sign(kRoot.priv, c.signed)
	c.full = append(append([]any{}, c.unsigned...), c.sig)
	return c
}

var certs = []*cert{
	mkCert("cert/acme", "Publisher certificate: key 'acme' may sign modules whose id starts with 'acme.' until 2027-01-01.", kAcme, "acme.", tExpires, domainCert),
	mkCert("cert/beta", "Publisher certificate for key 'beta' (namespace 'beta.'). The key is later revoked.", kBeta, "beta.", tExpires, domainCert),
	mkCert("cert/gamma-expired", "Publisher certificate for key 'gamma' that expired on 2026-11-01.", kGamma, "gamma.", tExpired, domainCert),
	mkCert("cert/delta-no-dot", "INVALID: namespace 'delta' does not end with a dot (section 9.5). Correctly signed, but must be rejected.", kDelta, "delta", tExpires, domainCert),
	mkCert("cert/omega-wrong-domain", "INVALID: signed over 'sparrow-module-v1' instead of 'sparrow-cert-v1'.", kOmega, "omega.", tExpires, domainModule),
}

type revocation struct {
	unsigned []any
	signed   []byte
	sig      []byte
	full     []any
}

func mkRevocation() *revocation {
	r := &revocation{}
	r.unsigned = []any{3, []any{kBeta.id}, kRoot.id}
	r.signed = signedBytes(domainRevoked, r.unsigned)
	r.sig = ed25519.Sign(kRoot.priv, r.signed)
	r.full = append(append([]any{}, r.unsigned...), r.sig)
	return r
}

var revList = mkRevocation()

type module struct {
	name, desc string
	file       string
	entry      map[string]any // without sig
	signer     *testKey
	domain     string
	signed     []byte
	sig        []byte
	full       map[string]any
	tamper     func(map[string]any)
}

func mkModule(name, desc, id, version string, deps []any, signer *testKey, domain string, extra map[string]any, tamper func(map[string]any)) *module {
	file := "// " + id + "@" + version + " (test fixture)\nexport default function register(host) {\n  return { id: '" + id + "' };\n}\n"
	h := fileHash([]byte(file))
	entry := map[string]any{
		"id":      id,
		"version": version,
		"hash":    h,
		"url":     "/sparrow/mods/" + b64url(h) + ".js",
		"deps":    list(deps...),
		"hostApi": "^3.1",
	}
	for k, v := range extra {
		entry[k] = v
	}
	m := &module{name: name, desc: desc, file: file, entry: entry, signer: signer, domain: domain, tamper: tamper}
	m.signed = signedBytes(domain, entry)
	m.sig = ed25519.Sign(signer.priv, m.signed)
	full := deepCopy(entry).(map[string]any)
	full["sig"] = []any{signer.id, m.sig}
	if tamper != nil {
		tamper(full)
	}
	m.full = full
	return m
}

var cssAsset = []byte(".acme-chart { display: block; }\n")

var modules = []*module{
	mkModule("module/acme-charts", "Module signed by the certified publisher key 'acme'; has assets and load.", "acme.charts", "1.4.2", list("acme.core"), kAcme, domainModule,
		map[string]any{"assets": []any{map[string]any{"path": "charts.css", "hash": fileHash(cssAsset)}}, "load": "lazy"}, nil),
	mkModule("module/acme-core", "Module signed directly by the root key.", "acme.core", "3.1.0", nil, kRoot, domainModule,
		map[string]any{"load": "eager"}, nil),
	mkModule("module/wrong-domain", "Signed by 'acme' over 'sparrow-cert-v1' instead of 'sparrow-module-v1'.", "acme.grid", "0.9.0", nil, kAcme, domainCert, nil, nil),
	mkModule("module/namespace-not-covered", "Signed by 'acme', whose namespace 'acme.' does not cover 'acmecorp.widgets'.", "acmecorp.widgets", "1.0.0", nil, kAcme, domainModule, nil, nil),
	mkModule("module/namespace-no-dot", "Signed by 'delta', whose certificate namespace 'delta' lacks the trailing dot. 'delta.maps' starts with 'delta', but the certificate is invalid.", "delta.maps", "1.0.0", nil, kDelta, domainModule, nil, nil),
	mkModule("module/revoked-key", "Signed by 'beta', which the revocation list revokes.", "beta.tools", "2.0.0", nil, kBeta, domainModule, nil, nil),
	mkModule("module/expired-cert", "Signed by 'gamma', whose certificate expired before the verification time.", "gamma.reports", "1.0.0", nil, kGamma, domainModule, nil, nil),
	mkModule("module/cert-wrong-domain", "Signed by 'omega', whose certificate signature used the wrong domain string.", "omega.maps", "1.0.0", nil, kOmega, domainModule, nil, nil),
	mkModule("module/uncertified-key", "Signed by a key that is neither a root key nor certified.", "acme.extra", "1.0.0", nil, kNoCert, domainModule, nil, nil),
	mkModule("module/tampered", "Signed for version 1.4.2, then 'version' changed to 1.4.3 after signing.", "acme.charts", "1.4.2", list("acme.core"), kAcme, domainModule, nil,
		func(m map[string]any) { m["version"] = "1.4.3" }),
}

var expectedReasons = map[string]string{
	"module/acme-charts":           "ok",
	"module/acme-core":             "ok",
	"module/wrong-domain":          "bad_module_signature",
	"module/namespace-not-covered": "namespace_not_covered",
	"module/namespace-no-dot":      "namespace_missing_trailing_dot",
	"module/revoked-key":           "key_revoked",
	"module/expired-cert":          "certificate_expired",
	"module/cert-wrong-domain":     "bad_certificate_signature",
	"module/uncertified-key":       "unknown_key",
	"module/tampered":              "bad_module_signature",
}

// verifyModule implements the acceptance check of section 9.5 in the order
// documented in test-vectors/README.md.
func verifyModule(entry map[string]any, roots []*testKey, webKeys [][]any, revoked []any, now uint64) string {
	rootByID := map[string][]byte{}
	for _, r := range roots {
		rootByID[hx(r.id)] = r.pub
	}
	revokedIDs := map[string]bool{}
	if rp, ok := rootByID[hx(revoked[2].([]byte))]; ok {
		if ed25519.Verify(rp, signedBytes(domainRevoked, revoked[:3]), revoked[3].([]byte)) {
			for _, id := range revoked[1].([]any) {
				revokedIDs[hx(id.([]byte))] = true
			}
		}
	}
	sig := entry["sig"].([]any)
	kid, signature := sig[0].([]byte), sig[1].([]byte)
	if revokedIDs[hx(kid)] {
		return "key_revoked"
	}
	id := entry["id"].(string)
	var key []byte
	if rp, ok := rootByID[hx(kid)]; ok {
		key = rp
	} else {
		reason := "unknown_key"
		for _, c := range webKeys {
			pub := c[0].([]byte)
			if !bytes.Equal(keyID(pub), kid) {
				continue
			}
			rp, ok := rootByID[hx(c[3].([]byte))]
			switch {
			case !ok:
				reason = "unknown_root"
			case !ed25519.Verify(rp, signedBytes(domainCert, c[:4]), c[4].([]byte)):
				reason = "bad_certificate_signature"
			case !strings.HasSuffix(c[1].(string), "."):
				reason = "namespace_missing_trailing_dot"
			case now >= c[2].(cbor.Tag).Content.(uint64):
				reason = "certificate_expired"
			case !strings.HasPrefix(id, c[1].(string)):
				reason = "namespace_not_covered"
			default:
				key = pub
			}
			if key != nil {
				break
			}
		}
		if key == nil {
			return reason
		}
	}
	unsigned := map[string]any{}
	for k, v := range entry {
		if k != "sig" {
			unsigned[k] = v
		}
	}
	if !ed25519.Verify(key, signedBytes(domainModule, unsigned), signature) {
		return "bad_module_signature"
	}
	return "ok"
}

func signingVectors() O {
	var vs []any
	for _, k := range allKeys {
		vs = append(vs, o(
			"name", "key/"+strings.Fields(strings.TrimPrefix(k.label, "TEST-ONLY "))[0]+"-"+hx(k.seed[:1]),
			"description", k.label+". key_id = first 16 bytes of SHA-256 of the raw 32-byte public key.",
			"spec", "9.5",
			"type", "key",
			"test_only", true,
			"seed", hx(k.seed),
			"public_key", hx(k.pub),
			"sha256_public_key", hx(func() []byte { s := sha256.Sum256(k.pub); return s[:] }()),
			"key_id", hx(k.id),
		))
	}
	var webKeys [][]any
	var webKeysAny []any
	for _, c := range certs {
		ub := enc(c.unsigned)
		fb := enc(c.full)
		vs = append(vs, o(
			"name", c.name,
			"description", c.desc,
			"spec", "9.5",
			"type", "certificate",
			"signer_seed", hx(kRoot.seed),
			"domain", c.domain,
			"domain_hex", hx([]byte(c.domain)),
			"unsigned", tj(c.unsigned),
			"unsigned_diag", diag(ub),
			"unsigned_cbor", hx(ub),
			"signed_bytes", hx(c.signed),
			"signature", hx(c.sig),
			"certificate", tj(c.full),
			"certificate_cbor", hx(fb),
		))
		webKeys = append(webKeys, c.full)
		webKeysAny = append(webKeysAny, c.full)
	}
	rb := enc(revList.unsigned)
	vs = append(vs, o(
		"name", "revocation/list-3",
		"description", "Revocation list with seq 3 revoking key 'beta', signed by the root key.",
		"spec", "9.5",
		"type", "revocation",
		"signer_seed", hx(kRoot.seed),
		"domain", domainRevoked,
		"domain_hex", hx([]byte(domainRevoked)),
		"unsigned", tj(revList.unsigned),
		"unsigned_diag", diag(rb),
		"unsigned_cbor", hx(rb),
		"signed_bytes", hx(revList.signed),
		"signature", hx(revList.sig),
		"revocation", tj(revList.full),
		"revocation_cbor", hx(enc(revList.full)),
	))
	for _, m := range modules {
		ub := enc(m.entry)
		vs = append(vs, o(
			"name", m.name,
			"description", m.desc,
			"spec", "9.4, 9.5",
			"type", "module",
			"file_utf8", m.file,
			"file_hash", hx(fileHash([]byte(m.file))),
			"signer_seed", hx(m.signer.seed),
			"domain", m.domain,
			"unsigned", tj(m.entry),
			"unsigned_diag", diag(ub),
			"unsigned_cbor", hx(ub),
			"signed_bytes", hx(m.signed),
			"signature", hx(m.sig),
			"entry", tj(m.full),
			"entry_cbor", hx(enc(m.full)),
		))
	}
	if len(cssAsset) > 0 {
		vs = append(vs, o(
			"name", "file-hash/charts-css",
			"description", "Asset file hash in schema-hash format: 0x01 || SHA-256(file bytes).",
			"spec", "9.4",
			"type", "file_hash",
			"file_utf8", string(cssAsset),
			"hash", hx(fileHash(cssAsset)),
		))
	}
	// Verification cases: one per module, all against the same context.
	var validMods []any
	for _, m := range modules {
		got := verifyModule(m.full, rootKeys, webKeys, revList.full, tNow)
		want := expectedReasons[m.name]
		if got != want {
			panic(m.name + ": verify gave " + got + ", expected " + want)
		}
		if got == "ok" {
			validMods = append(validMods, m.full)
		}
		vs = append(vs, o(
			"name", "verify/"+strings.TrimPrefix(m.name, "module/"),
			"description", "Accept or reject "+m.name+" against the shared verification context. "+m.desc,
			"spec", "9.5",
			"type", "verify",
			"context", "verification_context",
			"module", m.name,
			"expected_valid", got == "ok",
			"expected_reason", got,
		))
	}
	webAnn := map[string]any{
		"web.keys":    webKeysAny,
		"web.revoked": revList.full,
		"web.modules": validMods,
	}
	wb := enc(webAnn)
	return o("area", "signing",
		"test_only_keys", "Every key in this file is derived from a trivial TEST-ONLY seed. Never use these keys outside tests.",
		"verification_context", o(
			"description", "Shared context for all 'verify' vectors: the root keys built into the client, the schema annotations web.keys and web.revoked (all certificates and the revocation list in this file), and the time at which certificate expiry is checked.",
			"root_public_keys", []any{hx(kRoot.pub)},
			"now", tNow,
			"now_iso", "2026-11-27T00:00:00Z",
			"web_keys", "all 'certificate' vectors, in file order",
			"web_revoked", "revocation/list-3",
		),
		"web_annotations_example", o(
			"description", "The web.* top-level schema annotations as a server would publish them: all certificates, the revocation list and the modules that verify. Encoded canonically.",
			"value", tj(webAnn),
			"cbor", hx(wb),
		),
		"vectors", vs)
}
