package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Sections 9.4 and 9.5.
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

func fileHash(b []byte) []byte { return h33(b) }

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signedBytes: the canonical CBOR of the two-element array [domain, value]
// (section 9.5), where value is the signed array or map without its
// signature element.
func signedBytes(domain string, unsigned any) []byte {
	return enc([]any{domain, unsigned})
}

var (
	kRoot    = mkKey("TEST-ONLY root key (seed 32 x 0x01)", 0x01)
	kAcme    = mkKey("TEST-ONLY publisher key 'acme' (seed 32 x 0x02)", 0x02)
	kBeta    = mkKey("TEST-ONLY publisher key 'beta', revoked (seed 32 x 0x03)", 0x03)
	kNoCert  = mkKey("TEST-ONLY uncertified key (seed 32 x 0x04)", 0x04)
	kGamma   = mkKey("TEST-ONLY publisher key 'gamma', certificate expired (seed 32 x 0x05)", 0x05)
	kDelta   = mkKey("TEST-ONLY publisher key 'delta', namespace without trailing dot (seed 32 x 0x06)", 0x06)
	kOmega   = mkKey("TEST-ONLY publisher key 'omega', certificate signed with the wrong domain (seed 32 x 0x07)", 0x07)
	kEpsilon = mkKey("TEST-ONLY publisher key 'epsilon', certificate expires exactly at the verification time (seed 32 x 0x08)", 0x08)
	allKeys  = []*testKey{kRoot, kAcme, kBeta, kNoCert, kGamma, kDelta, kOmega, kEpsilon}
	rootKeys = []*testKey{kRoot}
)

func expiresTag(t uint64) cbor.Tag { return cbor.Tag{Number: 1, Content: t} }

type cert struct {
	name, desc string
	pub        *testKey
	domain     string
	unsigned   []any
	signed     []byte
	sig        []byte
	full       []any
}

func mkCert(name, desc string, k *testKey, ns string, expires uint64, domain string) *cert {
	c := &cert{name: name, desc: desc, pub: k, domain: domain}
	c.unsigned = []any{[]byte(k.pub), ns, expiresTag(expires), kRoot.id}
	c.signed = signedBytes(domain, c.unsigned)
	c.sig = ed25519.Sign(kRoot.priv, c.signed)
	c.full = append(append([]any{}, c.unsigned...), c.sig)
	return c
}

var certs = []*cert{
	mkCert("cert/acme", "Publisher certificate: key 'acme' may sign modules whose id starts with 'acme.' until 2027-01-01.", kAcme, "acme.", tExpires, domainCert),
	mkCert("cert/beta", "Publisher certificate for key 'beta' (namespace 'beta.'). The key is revoked by revocation/list-3.", kBeta, "beta.", tExpires, domainCert),
	mkCert("cert/gamma-expired", "Publisher certificate for key 'gamma' that expired on 2026-11-01.", kGamma, "gamma.", tExpired, domainCert),
	mkCert("cert/delta-no-dot", "INVALID: namespace 'delta' does not end with a dot. Correctly signed, but must be rejected.", kDelta, "delta", tExpires, domainCert),
	mkCert("cert/omega-wrong-domain", "INVALID: signed over ['sparrow-module-v1', ...] instead of ['sparrow-cert-v1', ...].", kOmega, "omega.", tExpires, domainModule),
	mkCert("cert/epsilon-boundary", "Certificate whose expires equals the verification time: not valid (valid only strictly before expires).", kEpsilon, "epsilon.", tNow, domainCert),
}

func certByName(n string) *cert {
	for _, c := range certs {
		if c.name == n {
			return c
		}
	}
	panic(n)
}

type revocation struct {
	name, desc string
	signer     *testKey
	unsigned   []any
	signed     []byte
	sig        []byte
	full       []any
}

func mkRevocation(name, desc string, seq int, ids [][]byte, signer *testKey) *revocation {
	r := &revocation{name: name, desc: desc, signer: signer}
	idl := []any{}
	for _, id := range ids {
		idl = append(idl, id)
	}
	r.unsigned = []any{seq, idl, kRoot.id}
	r.signed = signedBytes(domainRevoked, r.unsigned)
	r.sig = ed25519.Sign(signer.priv, r.signed)
	r.full = append(append([]any{}, r.unsigned...), r.sig)
	return r
}

var revocations = []*revocation{
	mkRevocation("revocation/list-3", "Revocation list seq 3 revoking key 'beta', signed by the root key. Used by the default verification context.", 3, [][]byte{kBeta.id}, kRoot),
	mkRevocation("revocation/lists-root", "Root-signed list (seq 4) naming the root key's own key_id and publisher key 'beta'. The entry naming a root key is ignored and the rest of the list applies (9.5): the root stays trusted, 'beta' is revoked.", 4, [][]byte{kRoot.id, kBeta.id}, kRoot),
	mkRevocation("revocation/forged", "List claiming root_key_id of the root key but signed by publisher key 'acme', revoking 'acme'. Only a list signed by a root key counts, so it is ignored.", 9, [][]byte{kAcme.id}, kAcme),
}

var revList = revocations[0]

func revByName(n string) *revocation {
	for _, r := range revocations {
		if r.name == n {
			return r
		}
	}
	panic(n)
}

type module struct {
	name, desc string
	file       string
	entry      map[string]any // without sig
	signer     *testKey
	domain     string
	signed     []byte
	sig        []byte
	full       map[string]any
	reason     string
}

func mkModule(name, desc, id, version string, deps []any, signer *testKey, domain string, extra map[string]any, tamper func(map[string]any), reason string) *module {
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
	m := &module{name: name, desc: desc, file: file, entry: entry, signer: signer, domain: domain, reason: reason}
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
	mkModule("module/acme-charts", "Module 'acme.charts.ui' of part acme.charts, signed by the certified publisher key 'acme'; has assets and load.", "acme.charts.ui", "1.4.2", list("acme.core.boot"), kAcme, domainModule,
		map[string]any{"assets": []any{map[string]any{"path": "charts.css", "hash": fileHash(cssAsset)}}, "load": "lazy"}, nil, "ok"),
	mkModule("module/acme-core", "Module signed directly by the root key.", "acme.core.boot", "3.1.0", nil, kRoot, domainModule,
		map[string]any{"load": "eager"}, nil, "ok"),
	mkModule("module/wrong-domain", "Signed by 'acme' over ['sparrow-cert-v1', entry] instead of ['sparrow-module-v1', entry].", "acme.grid.ui", "0.9.0", nil, kAcme, domainCert, nil, nil, "bad_module_signature"),
	mkModule("module/namespace-not-covered", "Signed by 'acme', whose namespace 'acme.' does not cover 'acmecorp.widgets'.", "acmecorp.widgets", "1.0.0", nil, kAcme, domainModule, nil, nil, "namespace_not_covered"),
	mkModule("module/namespace-no-dot", "Signed by 'delta', whose certificate namespace 'delta' lacks the trailing dot. 'delta.maps' starts with 'delta', but the certificate is invalid.", "delta.maps", "1.0.0", nil, kDelta, domainModule, nil, nil, "namespace_missing_trailing_dot"),
	mkModule("module/revoked-key", "Signed by 'beta', which revocation/list-3 revokes.", "beta.tools", "2.0.0", nil, kBeta, domainModule, nil, nil, "key_revoked"),
	mkModule("module/expired-cert", "Signed by 'gamma', whose certificate expired before the verification time.", "gamma.reports", "1.0.0", nil, kGamma, domainModule, nil, nil, "certificate_expired"),
	mkModule("module/expiry-boundary", "Signed by 'epsilon', whose certificate expires exactly at the verification time (strictly-before rule).", "epsilon.x", "1.0.0", nil, kEpsilon, domainModule, nil, nil, "certificate_expired"),
	mkModule("module/cert-wrong-domain", "Signed by 'omega', whose certificate signature used the wrong domain string.", "omega.maps", "1.0.0", nil, kOmega, domainModule, nil, nil, "bad_certificate_signature"),
	mkModule("module/uncertified-key", "Signed by a key that is neither a root key nor certified.", "acme.extra", "1.0.0", nil, kNoCert, domainModule, nil, nil, "unknown_key"),
	mkModule("module/tampered", "Signed for version 1.4.2, then 'version' changed to 1.4.3 after signing.", "acme.charts.ui", "1.4.2", list("acme.core.boot"), kAcme, domainModule, nil,
		func(m map[string]any) { m["version"] = "1.4.3" }, "bad_module_signature"),
}

func moduleByName(n string) *module {
	for _, m := range modules {
		if m.name == n {
			return m
		}
	}
	panic(n)
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
	id := entry["id"].(string)
	key, isRoot := rootByID[hx(kid)]
	if !isRoot {
		if revokedIDs[hx(kid)] {
			return "key_revoked"
		}
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
			case !bytes.HasPrefix([]byte(id), []byte(c[1].(string))):
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

// moduleInPart implements the 9.4 rule: a module id in a part's web.modules
// follows the part-name grammar and equals the part's name or starts with
// it and a dot, ignoring a "<peer-id>/" prefix the hub added.
func moduleInPart(partName, moduleID string) bool {
	if i := strings.Index(partName, "/"); i >= 0 {
		partName = partName[i+1:]
	}
	if !nodeIDRe.MatchString(moduleID) {
		return false
	}
	return moduleID == partName || strings.HasPrefix(moduleID, partName+".")
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
	for _, c := range certs {
		vs = append(vs, o(
			"name", c.name, "description", c.desc, "spec", "9.5", "type", "certificate",
			"signer_seed", hx(kRoot.seed), "domain", c.domain,
			"unsigned", tj(c.unsigned),
			"signed_value", tj([]any{c.domain, c.unsigned}),
			"signed_diag", diag(c.signed),
			"signed_bytes", hx(c.signed),
			"signature", hx(c.sig),
			"certificate", tj(c.full),
			"certificate_cbor", hx(enc(c.full)),
		))
		webKeys = append(webKeys, c.full)
	}
	for _, r := range revocations {
		vs = append(vs, o(
			"name", r.name, "description", r.desc, "spec", "9.5", "type", "revocation",
			"signer_seed", hx(r.signer.seed), "domain", domainRevoked,
			"unsigned", tj(r.unsigned),
			"signed_value", tj([]any{domainRevoked, r.unsigned}),
			"signed_diag", diag(r.signed),
			"signed_bytes", hx(r.signed),
			"signature", hx(r.sig),
			"revocation", tj(r.full),
			"revocation_cbor", hx(enc(r.full)),
		))
	}
	for _, m := range modules {
		vs = append(vs, o(
			"name", m.name, "description", m.desc, "spec", "9.4, 9.5", "type", "module",
			"file_utf8", m.file, "file_hash", hx(fileHash([]byte(m.file))),
			"signer_seed", hx(m.signer.seed), "domain", m.domain,
			"unsigned", tj(m.entry),
			"signed_value", tj([]any{m.domain, m.entry}),
			"signed_bytes", hx(m.signed),
			"signature", hx(m.sig),
			"entry", tj(m.full),
			"entry_cbor", hx(enc(m.full)),
		))
	}
	vs = append(vs, o(
		"name", "file-hash/charts-css", "description", "Asset file hash in schema-hash format: 0x01 || SHA-256(file bytes).",
		"spec", "9.4", "type", "file_hash", "file_utf8", string(cssAsset), "hash", hx(fileHash(cssAsset)),
	))
	addVerify := func(name, desc, mod, rev string) {
		m := moduleByName(mod)
		got := verifyModule(m.full, rootKeys, webKeys, revByName(rev).full, tNow)
		want := m.reason
		if rev == "revocation/forged" || (rev == "revocation/lists-root" && m.name == "module/acme-core") {
			want = "ok"
		}
		if got != want {
			panic(name + ": verify gave " + got + ", expected " + want)
		}
		vs = append(vs, o(
			"name", name, "description", desc, "spec", "9.5", "type", "verify",
			"context", "verification_context", "module", mod, "revocation", rev,
			"expected_valid", got == "ok", "expected_reason", got,
		))
	}
	for _, m := range modules {
		addVerify("verify/"+strings.TrimPrefix(m.name, "module/"), "Accept or reject "+m.name+". "+m.desc, m.name, "revocation/list-3")
	}
	addVerify("verify/root-not-revocable", "module/acme-core (root-signed) with revocation/lists-root in effect: root keys cannot be revoked, so the module is accepted.", "module/acme-core", "revocation/lists-root")
	addVerify("verify/publisher-revoked-by-list-naming-root", "module/revoked-key (signed by 'beta') with revocation/lists-root in effect: the list also names the root key, whose entry is ignored, but the rest applies, so 'beta' is revoked.", "module/revoked-key", "revocation/lists-root")
	addVerify("verify/forged-revocation-ignored", "module/acme-charts with revocation/forged in effect: that list is not signed by a root key, so it does not count and 'acme' is not revoked.", "module/acme-charts", "revocation/forged")

	// Module ids against part names (section 9.4).
	scope := []struct {
		part, id, desc string
	}{
		{"acme.charts", "acme.charts.ui", "Starts with the part name and a dot."},
		{"acme.charts", "acme.charts.ui.extra", "Deeper ids are fine."},
		{"acme.charts", "acme.charts", "Equal to the part name: allowed (9.4)."},
		{"acme.charts", "acme.chartsx.ui", "Shares a string prefix but not the part name followed by a dot."},
		{"acme.charts", "acme.notes.ui", "Another part's name: a part cannot ship modules under another part's name."},
		{"acme.charts", "acme.charts.Ui", "Upper case: module ids follow the ASCII part-name grammar."},
		{"acme.charts", "acme.charts.caf\u00e9", "Non-ASCII: module ids follow the ASCII part-name grammar."},
		{"hub-b/acme.charts", "acme.charts.ui", "Imported part: the '<peer-id>/' prefix a hub added is ignored."},
		{"hub-b/acme.charts", "acme.charts", "Imported part, id equal to the unprefixed name."},
		{"hub-b/acme.charts", "hub-b/acme.charts.ui", "Module ids never carry the prefix ('/' is outside the grammar)."},
		{"sparrow.web", "sparrow.web.core", "Part 1 may ship modules named after it."},
	}
	for _, s := range scope {
		vs = append(vs, o(
			"name", "module-scope/"+strings.ReplaceAll(s.part, "/", "_")+"/"+s.id, "description", s.desc,
			"spec", "9.4, 10.8", "type", "module_scope",
			"part_name", s.part, "module_id", s.id, "expected_valid", moduleInPart(s.part, s.id),
		))
	}
	partAnn := map[string]any{"web.modules": []any{}, "web.apply": "hot", "web.keys": []any{}, "web.title": "Hijacked", "doc": "A part's annotations."}
	vs = append(vs, o(
		"name", "module-scope/part-web-keys", "description", "A part's own annotations may carry only web.modules; a client ignores any other web.* key in a part, and reads web.keys, web.revoked and client configuration from top-level schema annotations only (section 9.4). Non-web keys are untouched.",
		"spec", "9.4", "type", "part_web_keys",
		"part_annotations", tj(partAnn), "honoured_web_keys", []any{"web.modules"}, "ignored_web_keys", []any{"web.apply", "web.keys", "web.title"},
	))
	return o("area", "signing",
		"test_only_keys", "Every key in this file is derived from a trivial TEST-ONLY seed. Never use these keys outside tests.",
		"verification_context", o(
			"description", "Shared context for all 'verify' vectors: the root keys built into the client, the certificates offered in web.keys (all 'certificate' vectors in file order), the revocation list named by each vector, and the time at which certificate expiry is checked.",
			"root_public_keys", []any{hx(kRoot.pub)},
			"now", tNow,
			"now_iso", "2026-11-27T00:00:00Z",
			"web_keys", "all 'certificate' vectors, in file order",
		),
		"vectors", vs)
}
