package admin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// The JSON form of a document, for tools and people (sparrow-admin):
//
//	{
//	  "nodes": {
//	    "remote": {"dial": {"url": "https://...", "pin": "<hex>", "credential": "secret-name"}},
//	    "acme":   {"credential": "secret-name", "facets": ["<hex key>"], "peer": false, "enabled": true,
//	               "extensions": {"key": "<hex CBOR>"}}
//	  },
//	  "defaults":   {"<hex interface hash>": "facet.name"},
//	  "extensions": {"key": "<hex CBOR>"}
//	}
//
// Struct fields are keys named as in the interface (hub-admin 5.1), and
// byte strings (values and map keys) are lowercase hex; Problem.path uses
// the same keys. A node with a "start" key (the form before hub-admin
// revision 35) is refused.

type jsonConfig struct {
	Nodes      map[string]*jsonNode `json:"nodes"`
	Defaults   map[string]string    `json:"defaults,omitempty"`
	Extensions map[string]string    `json:"extensions,omitempty"`
}

type jsonNode struct {
	Dial       *jsonDial         `json:"dial,omitempty"`
	Start      json.RawMessage   `json:"start,omitempty"`
	Credential *string           `json:"credential,omitempty"`
	Facets     []string          `json:"facets,omitempty"`
	Peer       *bool             `json:"peer,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Extensions map[string]string `json:"extensions,omitempty"`
}

type jsonDial struct {
	URL        string `json:"url"`
	Pin        string `json:"pin"`
	Credential string `json:"credential"`
}

func hexMap(m map[string][]byte) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = hex.EncodeToString(v)
	}
	return out
}

func unhexMap(m map[string]string, what string) (map[string][]byte, error) {
	if m == nil {
		return nil, nil
	}
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %v", what, k, err)
		}
		out[k] = b
	}
	return out, nil
}

// MarshalJSON writes the JSON form.
func (c *Config) MarshalJSON() ([]byte, error) {
	j := jsonConfig{Nodes: map[string]*jsonNode{}, Extensions: hexMap(c.Extensions)}
	if c.Defaults != nil {
		j.Defaults = map[string]string{}
		for k, v := range c.Defaults {
			j.Defaults[hex.EncodeToString([]byte(k))] = v
		}
	}
	for id, n := range c.Nodes {
		jn := &jsonNode{Credential: n.Credential, Peer: n.Peer, Enabled: n.Enabled, Extensions: hexMap(n.Extensions)}
		for _, f := range n.Facets {
			jn.Facets = append(jn.Facets, hex.EncodeToString(f))
		}
		if d := n.Dial; d != nil {
			jn.Dial = &jsonDial{URL: d.URL, Pin: hex.EncodeToString(d.Pin), Credential: d.Credential}
		}
		j.Nodes[id] = jn
	}
	return json.Marshal(j)
}

// UnmarshalJSON reads the JSON form.
func (c *Config) UnmarshalJSON(b []byte) error {
	var j jsonConfig
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	out := Config{Nodes: map[string]*NodeConfig{}}
	var err error
	if out.Extensions, err = unhexMap(j.Extensions, "extension"); err != nil {
		return err
	}
	if j.Defaults != nil {
		out.Defaults = map[string]string{}
		for k, v := range j.Defaults {
			h, err := hex.DecodeString(k)
			if err != nil {
				return fmt.Errorf("defaults key %q: %v", k, err)
			}
			out.Defaults[string(h)] = v
		}
	}
	ids := make([]string, 0, len(j.Nodes))
	for id := range j.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		jn := j.Nodes[id]
		if jn == nil {
			jn = &jsonNode{}
		}
		n := &NodeConfig{Credential: jn.Credential, Peer: jn.Peer, Enabled: jn.Enabled}
		if n.Extensions, err = unhexMap(jn.Extensions, "extension"); err != nil {
			return fmt.Errorf("node %s: %v", id, err)
		}
		for _, f := range jn.Facets {
			k, err := hex.DecodeString(f)
			if err != nil {
				return fmt.Errorf("node %s facet %q: %v", id, f, err)
			}
			n.Facets = append(n.Facets, k)
		}
		if jn.Start != nil {
			return fmt.Errorf("node %s: \"start\" is not part of the document; a dialed node has \"dial\"", id)
		}
		if jn.Dial != nil {
			pin, err := hex.DecodeString(jn.Dial.Pin)
			if err != nil {
				return fmt.Errorf("node %s pin: %v", id, err)
			}
			n.Dial = &Dial{URL: jn.Dial.URL, Pin: pin, Credential: jn.Dial.Credential}
		}
		out.Nodes[id] = n
	}
	*c = out
	return nil
}
