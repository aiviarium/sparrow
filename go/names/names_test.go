package names

import "testing"

func TestGrammars(t *testing.T) {
	ids := map[string]bool{"acme": true, "acme.charts": true, "my-node.v2": true, "a-.-b": true, "0": true,
		"": false, "Acme": false, "acme..charts": false, ".acme": false, "acme.": false, "acme_charts": false,
		"acme/charts": false, "café": false, "a b": false}
	for s, want := range ids {
		if IsNodeID(s) != want || IsModuleID(s) != want {
			t.Errorf("IsNodeID(%q) != %v", s, want)
		}
	}
	facets := map[string]bool{"acme.notes": true, "hub-b/acme.notes": true, "Hub/acme": false, "/acme": false,
		"hub-b/": false, "a/b/c": false, "acme.café": false}
	for s, want := range facets {
		if IsFacetName(s) != want {
			t.Errorf("IsFacetName(%q) != %v", s, want)
		}
	}
	if !OwnedBy("acme.charts", "acme.charts.admin") || OwnedBy("acme.charts", "acme.chartsx") || OwnedBy("acme.charts", "acme") {
		t.Error("OwnedBy")
	}
	if !ModuleInFacet("hub-b/acme.charts", "acme.charts.ui") || ModuleInFacet("acme.charts", "hub-b/acme.charts.ui") ||
		ModuleInFacet("acme.charts", "acme.chartsx") || !ModuleInFacet("acme.charts", "acme.charts") {
		t.Error("ModuleInFacet")
	}
	if !IsASCII("PanelConfig") || IsASCII("Grüße") {
		t.Error("IsASCII")
	}
	if Imported("hub-b", "acme.notes") != "hub-b/acme.notes" {
		t.Error("Imported")
	}
}

func TestPrincipals(t *testing.T) {
	ps := map[string]bool{"user:alice": true, "group:admins": true, "node:acme.charts": true,
		"user:alice@example.com": true, "user:a_b-c.D": true, "peer:hub-b/user:alice": true,
		"peer:hub-b/peer:hub-c/user:x": false, "admin:root": false, "user:": false, "user:a b": false,
		"peer:hub-b/": false, "peer:Hub/user:a": false, "peer:user:alice": false, "user:jürgen": false, "alice": false}
	for s, want := range ps {
		if IsPrincipal(s) != want {
			t.Errorf("IsPrincipal(%q) != %v", s, want)
		}
	}
	if p, ok := PeerPrincipal("hub-b", "user:bob"); !ok || p != "peer:hub-b/user:bob" {
		t.Error("PeerPrincipal")
	}
	if _, ok := PeerPrincipal("hub-b", "peer:hub-c/user:x"); ok {
		t.Error("nested peer principal accepted")
	}
	if _, ok := PeerPrincipal("Hub", "user:bob"); ok {
		t.Error("bad hub id accepted")
	}
	if NodePrincipal("x") != "node:x" {
		t.Error("NodePrincipal")
	}
}
