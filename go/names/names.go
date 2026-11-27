// Package names checks the ASCII name grammars of Sparrow: facet names,
// node IDs and module ids (sections 6.1, 9.4, 10.2), imported facet names
// (10.8) and principals (10.4).
package names

import "strings"

// IsNodeID reports whether s matches [a-z0-9-]+(\.[a-z0-9-]+)*, the grammar
// of node IDs, facet names and module ids.
func IsNodeID(s string) bool {
	if s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// IsModuleID reports whether s follows the module id grammar (the same as
// node IDs).
func IsModuleID(s string) bool { return IsNodeID(s) }

// SplitPeer splits an imported facet name "<peer-id>/<name>" into its peer
// ID and local name. A name without "/" returns peer "".
func SplitPeer(name string) (peer, local string) {
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

// IsFacetName reports whether s is a valid facet name: the node-ID grammar,
// optionally prefixed with "<peer-id>/" by an importing hub (10.8).
func IsFacetName(s string) bool {
	peer, local := SplitPeer(s)
	if strings.Contains(s, "/") && !IsNodeID(peer) {
		return false
	}
	return IsNodeID(local)
}

// Imported returns the name an importing hub lists a peer's facet under.
func Imported(peerID, name string) string { return peerID + "/" + name }

// OwnedBy reports whether a node may publish a facet with this name: the
// name equals the node ID or starts with the node ID and a dot (10.2).
func OwnedBy(nodeID, facetName string) bool {
	return facetName == nodeID || strings.HasPrefix(facetName, nodeID+".")
}

// ModuleInFacet reports whether a facet may ship a module with this id in
// its web.modules annotation (9.4): the id follows the module grammar and
// equals the facet's name or starts with it and a dot, ignoring any
// "<peer-id>/" prefix a hub added.
func ModuleInFacet(facetName, moduleID string) bool {
	_, local := SplitPeer(facetName)
	if !IsModuleID(moduleID) {
		return false
	}
	return moduleID == local || strings.HasPrefix(moduleID, local+".")
}

// IsASCII reports whether s holds only ASCII characters, as names of types,
// services, methods, fields, variants and sigils must (6.1).
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Principal kinds (10.4).
var principalKinds = map[string]bool{"user": true, "group": true, "node": true}

// IsPrincipal reports whether s is a valid principal: "kind:id" with kind
// user, group or node and id of ASCII letters, digits and . _ - @; or a
// peer principal "peer:<hub-id>/" followed by a non-peer principal.
func IsPrincipal(s string) bool {
	if rest, ok := strings.CutPrefix(s, "peer:"); ok {
		hub, inner, found := strings.Cut(rest, "/")
		return found && IsNodeID(hub) && isLocalPrincipal(inner)
	}
	return isLocalPrincipal(s)
}

func isLocalPrincipal(s string) bool {
	kind, id, ok := strings.Cut(s, ":")
	if !ok || !principalKinds[kind] || id == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' || c == '@') {
			return false
		}
	}
	return true
}

// PeerPrincipal returns the principal a receiving hub checks for a call
// from peer hub peerID naming principal p (10.8). It refuses a principal
// that already starts with "peer:" or is invalid.
func PeerPrincipal(peerID, p string) (string, bool) {
	if strings.HasPrefix(p, "peer:") || !isLocalPrincipal(p) || !IsNodeID(peerID) {
		return "", false
	}
	return "peer:" + peerID + "/" + p, true
}

// NodePrincipal returns "node:<id>".
func NodePrincipal(nodeID string) string { return "node:" + nodeID }
