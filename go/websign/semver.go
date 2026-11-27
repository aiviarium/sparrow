package websign

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed semver 2.0 version.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string // pre-release identifiers
	Build               string   // ignored for precedence
}

// ParseVersion parses a semver 2.0 version (no leading "v").
func ParseVersion(s string) (Version, error) {
	var v Version
	rest := s
	if i := strings.IndexByte(rest, '+'); i >= 0 {
		v.Build = rest[i+1:]
		rest = rest[:i]
		if !validIdents(v.Build, false) {
			return v, fmt.Errorf("websign: bad build metadata in %q", s)
		}
	}
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		pre := rest[i+1:]
		rest = rest[:i]
		if !validIdents(pre, true) {
			return v, fmt.Errorf("websign: bad pre-release in %q", s)
		}
		v.Pre = strings.Split(pre, ".")
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("websign: %q is not MAJOR.MINOR.PATCH", s)
	}
	nums := []*uint64{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		if !isNumeric(p) || (len(p) > 1 && p[0] == '0') {
			return v, fmt.Errorf("websign: bad version number %q in %q", p, s)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, fmt.Errorf("websign: %q: %v", s, err)
		}
		*nums[i] = n
	}
	return v, nil
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validIdents(s string, pre bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return false
			}
		}
		if pre && isNumeric(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Compare returns -1, 0 or 1 by semver precedence: numbers compared
// numerically, a pre-release lower than its release, pre-release
// identifiers compared one by one (numeric ones numerically and lower than
// alphanumeric ones, which compare in ASCII order; a shorter list is lower
// when all else is equal). Build metadata is ignored.
func (v Version) Compare(o Version) int {
	if c := cmpU(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmpU(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmpU(v.Patch, o.Patch); c != 0 {
		return c
	}
	switch {
	case len(v.Pre) == 0 && len(o.Pre) == 0:
		return 0
	case len(v.Pre) == 0:
		return 1
	case len(o.Pre) == 0:
		return -1
	}
	for i := 0; i < len(v.Pre) && i < len(o.Pre); i++ {
		a, b := v.Pre[i], o.Pre[i]
		an, bn := isNumeric(a), isNumeric(b)
		switch {
		case an && bn:
			// Numeric identifiers have no leading zeros and no size limit
			// (semver 2.0 item 11): the longer one is larger, and equal
			// lengths compare digit by digit.
			if c := cmpU(uint64(len(a)), uint64(len(b))); c != 0 {
				return c
			}
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		case an:
			return -1
		case bn:
			return 1
		default:
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		}
	}
	return cmpU(uint64(len(v.Pre)), uint64(len(o.Pre)))
}

// CompareVersions parses and compares two version strings.
func CompareVersions(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// Rollback records the highest version of each module seen in a snapshot
// that booted successfully, and rejects lower versions afterwards
// (section 9.5). The one previous snapshot kept for rollback is exempt;
// the caller does not consult Rollback for it.
type Rollback struct {
	highest map[string]Version
}

// Record notes a module version from a snapshot that booted.
func (r *Rollback) Record(id, version string) error {
	v, err := ParseVersion(version)
	if err != nil {
		return err
	}
	if r.highest == nil {
		r.highest = map[string]Version{}
	}
	if h, ok := r.highest[id]; !ok || v.Compare(h) > 0 {
		r.highest[id] = v
	}
	return nil
}

// Allowed reports whether a module version may be accepted: it is not
// lower than the highest recorded version of that module.
func (r *Rollback) Allowed(id, version string) (bool, error) {
	v, err := ParseVersion(version)
	if err != nil {
		return false, err
	}
	h, ok := r.highest[id]
	return !ok || v.Compare(h) >= 0, nil
}

// FacetWebKeys splits the web.* keys of a facet's own annotations into the
// ones a client honours (only web.modules) and the ones it ignores
// (section 9.4); web.keys, web.revoked and client configuration are read
// from top-level schema annotations only. Non-web keys are not returned.
func FacetWebKeys(keys []string) (honoured, ignored []string) {
	for _, k := range keys {
		switch {
		case k == "web.modules":
			honoured = append(honoured, k)
		case strings.HasPrefix(k, "web."):
			ignored = append(ignored, k)
		}
	}
	return honoured, ignored
}
