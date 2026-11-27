package admin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/aiviarium/sparrow/go/names"
)

// ErrUnsupported is returned by the ValidateEnv extension hook for an
// extension key the hub does not support.
var ErrUnsupported = errors.New("not supported by this hub")

// ValidateEnv supplies what document validation needs from the hub and the
// stores. Nil hooks mean "nothing exists" and "nothing is supported".
type ValidateEnv struct {
	SecretExists func(name string) bool
	// SecretValue returns a stored secret's value, to check that the
	// secrets links name have pairwise distinct values; nil skips that.
	SecretValue func(name string) ([]byte, bool)
	// Extension checks one extension: node is "" for the document's own
	// extensions. It returns ErrUnsupported for an unknown key, or another
	// error for invalid contents.
	Extension func(node, key string, value []byte) error
}

// IsReservedNodeID reports whether a node ID is reserved for the hub
// (sparrow and sparrow.*, Hub Profile 10.2).
func IsReservedNodeID(id string) bool { return id == "sparrow" || strings.HasPrefix(id, "sparrow.") }

// ValidSecretName reports whether a secret name follows the node-ID grammar
// (section 2.1).
func ValidSecretName(name string) bool { return names.IsNodeID(name) }

// linkSecret is one secret a link names, and where.
type linkSecret struct {
	node, name string
	path       []string
}

// Validate checks a document against every rule of section 3 and returns
// the problems found, in a stable order; none means valid.
func Validate(c *Config, env ValidateEnv) []Problem {
	var ps []Problem
	add := func(msg string, path ...string) {
		ps = append(ps, Problem{Path: append([]string{}, path...), Message: msg})
	}
	var named []linkSecret
	for _, id := range c.NodeIDs() {
		n := c.Nodes[id]
		np := []string{"nodes", id}
		if !names.IsNodeID(id) {
			add("node ID does not follow the grammar [a-z0-9-]+(.[a-z0-9-]+)*", np...)
		} else if IsReservedNodeID(id) {
			add("node IDs sparrow and sparrow.* are reserved for the hub", np...)
		}
		lp := append(np, "link")
		switch l := n.Link; {
		case l.Dial != nil:
			p := append(lp, "dial")
			u, err := url.Parse(l.Dial.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "wss") || u.Host == "" {
				add("url must be an https (WebTransport) or wss (WebSocket) URL", append(p, "url")...)
			}
			if len(l.Dial.Pin) != 32 {
				add(fmt.Sprintf("pin must be the 32-byte SHA-256 of the node's SubjectPublicKeyInfo, not %d bytes", len(l.Dial.Pin)), append(p, "pin")...)
			}
			named = append(named, linkSecret{id, l.Dial.Credential, append(p, "credential")})
		case l.Credential != nil:
			named = append(named, linkSecret{id, *l.Credential, append(lp, "credential")})
		default:
			add(fmt.Sprintf("unknown link variant %d", l.UnknownTag), lp...)
		}
		for _, k := range sortedKeys(n.Extensions) {
			checkExtension(env, id, k, n.Extensions[k], append(np, "extensions", k), add)
		}
	}
	// Every secret a link names exists, is named once in the document, and
	// has a value no other such secret has: no credential presented to one
	// party can be replayed to another (section 3).
	first := map[string]string{}  // secret name -> first node naming it
	values := map[string]string{} // secret value -> first secret with it
	for _, ls := range named {
		if env.SecretExists == nil || !env.SecretExists(ls.name) {
			add(fmt.Sprintf("secret %q is not stored", ls.name), ls.path...)
			continue
		}
		if other, dup := first[ls.name]; dup {
			add(fmt.Sprintf("secret %q is already named by the link of node %q", ls.name, other), ls.path...)
			continue
		}
		first[ls.name] = ls.node
		if env.SecretValue == nil {
			continue
		}
		if v, ok := env.SecretValue(ls.name); ok {
			if other, dup := values[string(v)]; dup {
				add(fmt.Sprintf("secret %q has the same value as secret %q", ls.name, other), ls.path...)
			} else {
				values[string(v)] = ls.name
			}
		}
	}
	for _, k := range sortedKeys(c.Defaults) {
		p := []string{"defaults", hex.EncodeToString([]byte(k))}
		if len(k) != 33 {
			add(fmt.Sprintf("an interface hash has 33 bytes, not %d", len(k)), p...)
		}
		if !names.IsFacetName(c.Defaults[k]) {
			add(fmt.Sprintf("%q is not a facet name", c.Defaults[k]), p...)
		}
	}
	for _, k := range sortedKeys(c.Extensions) {
		checkExtension(env, "", k, c.Extensions[k], []string{"extensions", k}, add)
	}
	return ps
}

func checkExtension(env ValidateEnv, node, key string, v []byte, path []string, add func(string, ...string)) {
	var err error = ErrUnsupported
	if env.Extension != nil {
		err = env.Extension(node, key, v)
	}
	switch {
	case errors.Is(err, ErrUnsupported):
		add(fmt.Sprintf("extension %q is not supported by this hub", key), path...)
	case err != nil:
		add(err.Error(), path...)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// References lists the secrets a document's links name.
func References(c *Config) map[string]bool {
	secrets := map[string]bool{}
	if c == nil {
		return secrets
	}
	for _, n := range c.Nodes {
		if n.Link.Dial != nil {
			secrets[n.Link.Dial.Credential] = true
		}
		if n.Link.Credential != nil {
			secrets[*n.Link.Credential] = true
		}
	}
	return secrets
}
