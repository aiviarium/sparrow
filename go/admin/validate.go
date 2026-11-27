package admin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
)

// ErrUnsupported is returned by the ValidateEnv extension hook for an
// extension key the hub does not support.
var ErrUnsupported = errors.New("not supported by this hub")

// ValidateEnv supplies what document validation needs from the hub and the
// stores. Nil hooks mean "nothing exists" and "nothing is supported".
type ValidateEnv struct {
	SecretExists func(name string) bool
	// SecretValue returns a stored secret's value, to check that no two
	// dial-in nodes present the same credential and that the hub never
	// presents one of them; nil skips those checks.
	SecretValue func(name string) ([]byte, bool)
	// StoredFacet returns the stored facet with this key, or nil.
	StoredFacet func(key []byte) *schema.Facet
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

// Validate checks a document against every rule of section 3 and returns
// the problems found, in a stable order; none means valid.
func Validate(c *Config, env ValidateEnv) []Problem {
	var ps []Problem
	add := func(msg string, path ...string) {
		ps = append(ps, Problem{Path: append([]string{}, path...), Message: msg})
	}
	secret := func(name string, path ...string) {
		if env.SecretExists == nil || !env.SecretExists(name) {
			add(fmt.Sprintf("secret %q is not stored", name), path...)
		}
	}
	// Secrets the hub presents (Dial.credential) and secrets dial-in nodes
	// present (NodeConfig.credential) must never overlap.
	presented := map[string]string{}
	accepted := map[string]string{}
	acceptedValue := map[string]string{} // secret value -> first dial-in node
	for _, id := range c.NodeIDs() {
		n := c.Nodes[id]
		if n.Credential != nil {
			if _, ok := accepted[*n.Credential]; !ok {
				accepted[*n.Credential] = id
			}
		}
		if n.Dial != nil {
			presented[n.Dial.Credential] = id
		}
	}
	for _, id := range c.NodeIDs() {
		n := c.Nodes[id]
		np := []string{"nodes", id}
		if !names.IsNodeID(id) {
			add("node ID does not follow the grammar [a-z0-9-]+(.[a-z0-9-]+)*", np...)
		} else if IsReservedNodeID(id) {
			add("node IDs sparrow and sparrow.* are reserved for the hub", np...)
		}
		switch {
		case n.Dial != nil && n.Credential != nil:
			add("a node has exactly one link direction: dial or credential, not both", np...)
		case n.Dial == nil && n.Credential == nil:
			add("a node has exactly one link direction: a dial, or a credential for dialing in", np...)
		}
		if n.Credential != nil {
			secret(*n.Credential, append(np, "credential")...)
			// No two dial-in nodes present the same credential (section 3):
			// the credential alone names the node (Hub Profile 10.2).
			if first := accepted[*n.Credential]; first != id {
				add(fmt.Sprintf("dial-in node %q already uses secret %q", first, *n.Credential), append(np, "credential")...)
			} else if env.SecretValue != nil {
				if v, ok := env.SecretValue(*n.Credential); ok {
					if other, dup := acceptedValue[string(v)]; dup {
						add(fmt.Sprintf("secret %q has the same value as the credential of dial-in node %q", *n.Credential, other), append(np, "credential")...)
					} else {
						acceptedValue[string(v)] = id
					}
				}
			}
			if other, ok := presented[*n.Credential]; ok {
				add(fmt.Sprintf("secret %q is also the credential the hub presents to node %q", *n.Credential, other), append(np, "credential")...)
			}
		}
		if d := n.Dial; d != nil {
			p := append(np, "dial")
			u, err := url.Parse(d.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "wss") || u.Host == "" {
				add("url must be an https (WebTransport) or wss (WebSocket) URL", append(p, "url")...)
			}
			if len(d.Pin) != 32 {
				add(fmt.Sprintf("pin must be the 32-byte SHA-256 of the node's SubjectPublicKeyInfo, not %d bytes", len(d.Pin)), append(p, "pin")...)
			}
			secret(d.Credential, append(p, "credential")...)
			if other, ok := accepted[d.Credential]; ok {
				add(fmt.Sprintf("secret %q is also the credential dial-in node %q presents", d.Credential, other), append(p, "credential")...)
			} else if env.SecretValue != nil {
				// Nor may it have the value of one (section 3): the hub's
				// own credential could otherwise be replayed to it.
				if v, ok := env.SecretValue(d.Credential); ok {
					for _, oid := range c.NodeIDs() {
						o := c.Nodes[oid]
						if o.Credential == nil {
							continue
						}
						if ov, ok := env.SecretValue(*o.Credential); ok && string(ov) == string(v) {
							add(fmt.Sprintf("secret %q has the same value as the credential dial-in node %q presents", d.Credential, oid), append(p, "credential")...)
							break
						}
					}
				}
			}
		}
		if n.Facets != nil {
			fp := append(np, "facets")
			if n.IsPeer() && len(n.Facets) > 0 {
				add("a peer hub lists no facets", fp...)
			}
			seen := map[string]bool{}
			for i, key := range n.Facets {
				ip := append(fp, strconv.Itoa(i))
				if seen[string(key)] {
					add("facet listed twice", ip...)
					continue
				}
				seen[string(key)] = true
				var f *schema.Facet
				if env.StoredFacet != nil {
					f = env.StoredFacet(key)
				}
				if f == nil {
					add(fmt.Sprintf("no stored facet %x", key), ip...)
					continue
				}
				if !names.OwnedBy(id, f.Name) {
					add(fmt.Sprintf("facet %q is not named after node %q", f.Name, id), ip...)
				}
			}
		}
		for _, k := range sortedKeys(n.Extensions) {
			checkExtension(env, id, k, n.Extensions[k], append(np, "extensions", k), add)
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

// References lists the secrets and stored facets a document refers to.
func References(c *Config) (secrets map[string]bool, facets map[string]bool) {
	secrets, facets = map[string]bool{}, map[string]bool{}
	if c == nil {
		return
	}
	for _, n := range c.Nodes {
		if n.Credential != nil {
			secrets[*n.Credential] = true
		}
		if n.Dial != nil {
			secrets[n.Dial.Credential] = true
		}
		for _, f := range n.Facets {
			facets[string(f)] = true
		}
	}
	return
}
