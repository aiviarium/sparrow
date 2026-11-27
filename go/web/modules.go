package web

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/websign"
)

// Annotation keys of the Web Profile (9.4, 9.5, 9.6).
const (
	AnnModules = "web.modules" // a facet's own client modules
	AnnKeys    = "web.keys"    // top level: publisher certificates
	AnnRevoked = "web.revoked" // top level: the revocation list
	AnnApply   = "web.apply"   // top level: "hot", "reload" or "prompt"
)

// Asset is one entry of a web-module's assets.
type Asset struct {
	Path string
	Hash []byte
}

// Entry is a web-module entry (9.4) with its signature (package websign).
type Entry struct {
	// Facet is the name of the facet that ships it, as listed.
	Facet   string
	Module  *websign.Module
	URL     string
	Deps    []string
	HostAPI string
	Assets  []Asset
	Load    string // "eager" (default) or "lazy"
}

// ID and Version of the module.
func (e *Entry) ID() string      { return e.Module.ID }
func (e *Entry) Version() string { return e.Module.Version }

// Hash of the module file.
func (e *Entry) Hash() []byte { return e.Module.Hash }

// DecodeEntry decodes and checks one web-module map: required fields with
// their types, a semver version, a hash in schema-hash format, deps that
// are module ids, a hostApi semver range, assets and load.
func DecodeEntry(raw []byte) (*Entry, error) {
	m, err := websign.DecodeModule(raw)
	if err != nil {
		return nil, err
	}
	e := &Entry{Module: m, Load: "eager"}
	if !names.IsModuleID(m.ID) {
		return nil, fmt.Errorf("web: module id %q does not follow the module-id grammar", m.ID)
	}
	if _, err := websign.ParseVersion(m.Version); err != nil {
		return nil, fmt.Errorf("web: module %s: %v", m.ID, err)
	}
	if len(m.Hash) != 33 || m.Hash[0] != 0x01 {
		return nil, fmt.Errorf("web: module %s: hash must be 0x01 || SHA-256", m.ID)
	}
	e.URL, _ = cbor.NewDecoder(m.Fields["url"]).Text()
	e.HostAPI, _ = cbor.NewDecoder(m.Fields["hostApi"]).Text()
	if _, err := ParseRange(e.HostAPI); err != nil {
		return nil, fmt.Errorf("web: module %s: hostApi: %v", m.ID, err)
	}
	d := cbor.NewDecoder(m.Fields["deps"])
	n, err := d.ArrayHead()
	if err != nil {
		return nil, fmt.Errorf("web: module %s: deps must be a list of module ids", m.ID)
	}
	for i := 0; i < n; i++ {
		s, err := d.Text()
		if err != nil || !names.IsModuleID(s) {
			return nil, fmt.Errorf("web: module %s: deps must be a list of module ids", m.ID)
		}
		e.Deps = append(e.Deps, s)
	}
	if raw, ok := m.Fields["assets"]; ok {
		d := cbor.NewDecoder(raw)
		n, err := d.ArrayHead()
		if err != nil {
			return nil, fmt.Errorf("web: module %s: assets must be a list", m.ID)
		}
		for i := 0; i < n; i++ {
			a, err := decodeAsset(d)
			if err != nil {
				return nil, fmt.Errorf("web: module %s: asset %d: %v", m.ID, i, err)
			}
			e.Assets = append(e.Assets, a)
		}
	}
	if raw, ok := m.Fields["load"]; ok {
		s, err := cbor.NewDecoder(raw).Text()
		if err != nil || (s != "eager" && s != "lazy") {
			return nil, fmt.Errorf("web: module %s: load must be \"eager\" or \"lazy\"", m.ID)
		}
		e.Load = s
	}
	return e, nil
}

func decodeAsset(d *cbor.Decoder) (Asset, error) {
	var a Asset
	n, err := d.MapHead()
	if err != nil {
		return a, errors.New("want {path, hash}")
	}
	for i := 0; i < n; i++ {
		k, err := d.Text()
		if err != nil {
			return a, err
		}
		switch k {
		case "path":
			a.Path, err = d.Text()
		case "hash":
			a.Hash, err = d.Bytes()
		default:
			err = d.Skip()
		}
		if err != nil {
			return a, err
		}
	}
	if a.Path == "" || len(a.Hash) != 33 || a.Hash[0] != 0x01 {
		return a, errors.New("an asset has a path and a hash in schema-hash format")
	}
	return a, nil
}

// FacetEntries decodes a facet's web.modules annotation. Every module id
// must equal the facet's name or start with it and a dot, ignoring a
// <peer-id>/ prefix (9.4).
func FacetEntries(f *schema.Facet) ([]*Entry, error) {
	raw, ok := f.Annotations[AnnModules]
	if !ok {
		return nil, nil
	}
	d := cbor.NewDecoder(raw)
	n, err := d.ArrayHead()
	if err != nil {
		return nil, fmt.Errorf("web: facet %s: web.modules must be a list of web-module entries", f.Name)
	}
	out := make([]*Entry, 0, n)
	for i := 0; i < n; i++ {
		r, err := d.Raw()
		if err != nil {
			return nil, err
		}
		e, err := DecodeEntry(r)
		if err != nil {
			return nil, fmt.Errorf("web: facet %s: module %d: %v", f.Name, i, err)
		}
		if !names.ModuleInFacet(f.Name, e.ID()) {
			return nil, fmt.Errorf("web: facet %s may not ship module %q (9.4)", f.Name, e.ID())
		}
		e.Facet = f.Name
		out = append(out, e)
	}
	return out, nil
}

// CheckFacet is the hub's check of a node's facet (9.4): a web.modules
// annotation, if present, is a list of well-formed web-module entries in
// the facet's scope. Signatures are the client's to verify.
func CheckFacet(f *schema.Facet) error {
	_, err := FacetEntries(f)
	return err
}

// Rejection is a module a client does not load, with the reason it sends
// in moduleRejected (9.4).
type Rejection struct {
	Facet, ID, Version, Reason string
}

// SchemaEntries gathers the modules of every facet of a schema (9.4).
// A facet whose web.modules is malformed or out of scope contributes
// nothing and is reported.
func SchemaEntries(sc *schema.Schema) ([]*Entry, []Rejection) {
	var out []*Entry
	var rej []Rejection
	for i := range sc.Facets {
		es, err := FacetEntries(&sc.Facets[i])
		if err != nil {
			rej = append(rej, Rejection{Facet: sc.Facets[i].Name, Reason: "invalid_modules: " + err.Error()})
			continue
		}
		out = append(out, es...)
	}
	return out, rej
}

// FileRef is a file a schema's modules reference: a module or an asset.
type FileRef struct {
	Hash  []byte
	Ext   string // the extension of its URL or path, without the dot
	Entry *Entry
}

// Files returns every module and asset file of the entries, by hash.
func Files(es []*Entry) []FileRef {
	var out []FileRef
	for _, e := range es {
		ext := strings.TrimPrefix(path.Ext(e.URL), ".")
		if ext == "" {
			ext = "js"
		}
		out = append(out, FileRef{Hash: e.Hash(), Ext: ext, Entry: e})
		for _, a := range e.Assets {
			out = append(out, FileRef{Hash: a.Hash, Ext: strings.TrimPrefix(path.Ext(a.Path), "."), Entry: e})
		}
	}
	return out
}

// FindFile looks a hash up among the files of the entries.
func FindFile(es []*Entry, hash []byte) (FileRef, bool) {
	for _, f := range Files(es) {
		if bytes.Equal(f.Hash, hash) {
			return f, true
		}
	}
	return FileRef{}, false
}

// ---------------------------------------------------------------------------
// The hub's Web Profile configuration
// ---------------------------------------------------------------------------

// ParseTopLevel checks the value of the reference hub's document extension
// ref.web: a CBOR map from top-level schema annotation keys, each starting
// with "web.", to their values (9.4, 9.5, 9.6). web.keys must be a list of
// certificates, web.revoked a revocation list, web.apply one of "hot",
// "reload" and "prompt"; with roots given, certificates and the list must
// be signed by one of them. Other web.* keys are client configuration and
// any valid CBOR.
func ParseTopLevel(b []byte, roots [][]byte) (schema.Annotations, error) {
	if err := cbor.Validate(b, cbor.Options{}); err != nil {
		return nil, err
	}
	d := cbor.NewDecoder(b)
	n, err := d.MapHead()
	if err != nil {
		return nil, errors.New("ref.web is a map of web.* annotations")
	}
	out := schema.Annotations{}
	v := &websign.Verifier{Roots: roots}
	for i := 0; i < n; i++ {
		k, err := d.Text()
		if err != nil {
			return nil, errors.New("ref.web keys are text")
		}
		raw, err := d.Raw()
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(k, "web.") || k == AnnModules {
			return nil, fmt.Errorf("ref.web: %q is not a top-level web.* annotation", k)
		}
		switch k {
		case AnnKeys:
			cd := cbor.NewDecoder(raw)
			m, err := cd.ArrayHead()
			if err != nil {
				return nil, errors.New("web.keys is a list of certificates")
			}
			for j := 0; j < m; j++ {
				cr, _ := cd.Raw()
				c, err := websign.DecodeCertificate(cr)
				if err != nil {
					return nil, fmt.Errorf("web.keys %d: %v", j, err)
				}
				if !strings.HasSuffix(c.Namespace, ".") {
					return nil, fmt.Errorf("web.keys %d: namespace %q must end with a dot", j, c.Namespace)
				}
				if len(roots) > 0 {
					if r := v.CertificateValid(c, c.Namespace); r != websign.ReasonOK && r != websign.ReasonCertificateExpired {
						return nil, fmt.Errorf("web.keys %d: %s", j, r)
					}
				}
			}
		case AnnRevoked:
			l, err := websign.DecodeRevocation(raw)
			if err != nil {
				return nil, fmt.Errorf("web.revoked: %v", err)
			}
			if len(roots) > 0 && websign.SelectRevocation(roots, l) == nil {
				return nil, errors.New("web.revoked is not signed by a root key")
			}
		case AnnApply:
			s, err := cbor.NewDecoder(raw).Text()
			if err != nil || (s != "hot" && s != "reload" && s != "prompt") {
				return nil, errors.New(`web.apply is "hot", "reload" or "prompt"`)
			}
		}
		out[k] = raw
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Semver ranges (the hostApi field)
// ---------------------------------------------------------------------------

// Range is a semver range as used in hostApi: comparators (=, >, >=, <,
// <=, ^, ~ and bare versions, partial ones allowed, x and * wildcards)
// joined by spaces (all must hold) and "||" (any set may hold).
type Range struct{ sets [][]comparator }

type comparator struct {
	op string
	v  websign.Version
}

// ParseRange parses a hostApi range such as "^3.1".
func ParseRange(s string) (*Range, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty range")
	}
	r := &Range{}
	for _, alt := range strings.Split(s, "||") {
		var set []comparator
		for _, f := range strings.Fields(alt) {
			cs, err := parseComparator(f)
			if err != nil {
				return nil, err
			}
			set = append(set, cs...)
		}
		if len(set) == 0 {
			return nil, fmt.Errorf("empty alternative in %q", s)
		}
		r.sets = append(r.sets, set)
	}
	return r, nil
}

// partial parses "3", "3.1", "3.1.4", "3.x", "*" into a version and the
// number of parts given.
func partial(s string) (websign.Version, int, error) {
	var v websign.Version
	if s == "*" || s == "x" || s == "X" {
		return v, 0, nil
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return v, 0, fmt.Errorf("bad version %q", s)
	}
	nums := []*uint64{&v.Major, &v.Minor, &v.Patch}
	given := 0
	for i, p := range parts {
		if p == "x" || p == "X" || p == "*" {
			break
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, 0, fmt.Errorf("bad version %q", s)
		}
		*nums[i] = n
		given++
	}
	if hasPre {
		if given != 3 {
			return v, 0, fmt.Errorf("bad version %q", s)
		}
		full, err := websign.ParseVersion(core + "-" + pre)
		if err != nil {
			return v, 0, err
		}
		return full, 3, nil
	}
	return v, given, nil
}

// bump returns the lowest version above every version that keeps the
// parts before part: 3.1 bumped at part 1 is 3.2.0. ok is false when that
// part is already the largest number, and no version is above them.
func bump(v websign.Version, part int) (_ websign.Version, ok bool) {
	switch part {
	case 0:
		return websign.Version{Major: v.Major + 1}, v.Major != math.MaxUint64
	case 1:
		return websign.Version{Major: v.Major, Minor: v.Minor + 1}, v.Minor != math.MaxUint64
	}
	return websign.Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1}, v.Patch != math.MaxUint64
}

func parseComparator(f string) ([]comparator, error) {
	op := ""
	for _, p := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(f, p) {
			op, f = p, f[len(p):]
			break
		}
	}
	v, given, err := partial(f)
	if err != nil {
		return nil, err
	}
	lower := func(v websign.Version) comparator { return comparator{">=", v} }
	// between is v up to (not including) v bumped at part: no upper bound
	// when the bump overflows.
	between := func(v websign.Version, part int) []comparator {
		if u, ok := bump(v, part); ok {
			return []comparator{lower(v), {"<", u}}
		}
		return []comparator{lower(v)}
	}
	switch op {
	case "", "=":
		if given == 0 {
			return []comparator{{">=", websign.Version{}}}, nil
		}
		if given == 3 {
			return []comparator{{"=", v}}, nil
		}
		return between(v, given-1), nil
	case "^":
		if given == 0 {
			return []comparator{{">=", websign.Version{}}}, nil
		}
		// The first non-zero part given is fixed.
		switch {
		case v.Major > 0 || given == 1:
			return between(v, 0), nil
		case v.Minor > 0 || given == 2:
			return between(v, 1), nil
		}
		return between(v, 2), nil
	case "~":
		if given == 0 {
			return []comparator{{">=", websign.Version{}}}, nil
		}
		if given == 1 {
			return between(v, 0), nil
		}
		return between(v, 1), nil
	case ">=", "<":
		return []comparator{{op, v}}, nil
	case ">":
		if given < 3 && given > 0 {
			if u, ok := bump(v, given-1); ok {
				return []comparator{{">=", u}}, nil
			}
			max := websign.Version{Major: math.MaxUint64, Minor: math.MaxUint64, Patch: math.MaxUint64}
			return []comparator{{">", max}}, nil // nothing is above
		}
		return []comparator{{">", v}}, nil
	case "<=":
		if given < 3 && given > 0 {
			if u, ok := bump(v, given-1); ok {
				return []comparator{{"<", u}}, nil
			}
			return []comparator{{">=", websign.Version{}}}, nil // everything is below
		}
		return []comparator{{"<=", v}}, nil
	}
	return nil, fmt.Errorf("bad comparator %q", f)
}

// Contains reports whether a version satisfies the range. A pre-release
// version only satisfies comparators that name a pre-release of the same
// MAJOR.MINOR.PATCH, as in common semver range semantics.
func (r *Range) Contains(version string) bool {
	v, err := websign.ParseVersion(version)
	if err != nil {
		return false
	}
	for _, set := range r.sets {
		ok := true
		preAllowed := len(v.Pre) == 0
		for _, c := range set {
			k := v.Compare(c.v)
			switch c.op {
			case "=":
				ok = ok && k == 0
			case ">":
				ok = ok && k > 0
			case ">=":
				ok = ok && k >= 0
			case "<":
				ok = ok && k < 0
			case "<=":
				ok = ok && k <= 0
			}
			if len(c.v.Pre) > 0 && c.v.Major == v.Major && c.v.Minor == v.Minor && c.v.Patch == v.Patch {
				preAllowed = true
			}
		}
		if ok && preAllowed {
			return true
		}
	}
	return false
}
