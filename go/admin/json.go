package admin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// The JSON form of a document, for tools and people (sparrow-admin):
//
//	{
//	  "nodes": {
//	    "remote": {"link": {"dial": {"url": "https://...", "pin": "<hex>", "credential": "secret-name"}}},
//	    "acme":   {"link": {"credential": "secret-name"}, "peer": false, "enabled": true,
//	               "extensions": {"key": "<hex CBOR>"}}
//	  },
//	  "defaults":   {"<hex interface hash>": "facet.name"},
//	  "extensions": {"key": "<hex CBOR>"}
//	}
//
// Struct fields are keys named as in the interface (hub-admin 5.1), a
// union is an object with its variant name as the only key, and byte
// strings (values and map keys) are lowercase hex, the same keys
// Problem.path uses. Unknown keys are refused.

type jsonConfig struct {
	Nodes      map[string]*jsonNode `json:"nodes"`
	Defaults   map[string]string    `json:"defaults,omitempty"`
	Extensions map[string]string    `json:"extensions,omitempty"`
}

type jsonNode struct {
	Link       *jsonLink         `json:"link"`
	Peer       *bool             `json:"peer,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Extensions map[string]string `json:"extensions,omitempty"`
}

type jsonLink struct {
	Dial       *jsonDial `json:"dial,omitempty"`
	Credential *string   `json:"credential,omitempty"`
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
		jn := &jsonNode{Link: &jsonLink{Credential: n.Link.Credential}, Peer: n.Peer, Enabled: n.Enabled, Extensions: hexMap(n.Extensions)}
		if d := n.Link.Dial; d != nil {
			jn.Link.Dial = &jsonDial{URL: d.URL, Pin: hex.EncodeToString(d.Pin), Credential: d.Credential}
		}
		if n.Link.Dial == nil && n.Link.Credential == nil {
			return nil, fmt.Errorf("node %s: link variant %d has no JSON form", id, n.Link.UnknownTag)
		}
		j.Nodes[id] = jn
	}
	return json.Marshal(j)
}

// UnmarshalJSON reads the JSON form.
func (c *Config) UnmarshalJSON(b []byte) error {
	var j jsonConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
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
		if jn == nil || jn.Link == nil {
			return fmt.Errorf("node %s: link is required", id)
		}
		n := &NodeConfig{Peer: jn.Peer, Enabled: jn.Enabled}
		if n.Extensions, err = unhexMap(jn.Extensions, "extension"); err != nil {
			return fmt.Errorf("node %s: %v", id, err)
		}
		switch l := jn.Link; {
		case l.Dial != nil && l.Credential != nil, l.Dial == nil && l.Credential == nil:
			return fmt.Errorf("node %s: link is one of {\"dial\": ...} and {\"credential\": ...}", id)
		case l.Dial != nil:
			pin, err := hex.DecodeString(l.Dial.Pin)
			if err != nil {
				return fmt.Errorf("node %s pin: %v", id, err)
			}
			n.Link = Dialed(Dial{URL: l.Dial.URL, Pin: pin, Credential: l.Dial.Credential})
		default:
			n.Link = DialIn(*l.Credential)
		}
		out.Nodes[id] = n
	}
	*c = out
	return nil
}
