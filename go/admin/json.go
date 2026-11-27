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
//	    "echo":   {"start": {"spawn": {"command": ["echo-node"], "env": {"A": {"literal": "x"}, "B": {"secret": "name"}}, "dir": "/x"}}},
//	    "remote": {"start": {"dial": {"url": "https://...", "pin": "<hex>", "credential": "secret-name"}}},
//	    "acme":   {"credential": "secret-name", "facets": ["<hex key>"], "peer": false, "enabled": true,
//	               "extensions": {"key": "<hex CBOR>"}},
//	    "w":      {"start": {"other": {"kind": "wasm", "params": "<hex CBOR>"}}}
//	  },
//	  "defaults":   {"<hex interface hash>": "facet.name"},
//	  "extensions": {"key": "<hex CBOR>"}
//	}
//
// Struct fields are keys named as in the interface (hub-admin 5.1), a
// union is an object with its variant name as the only key, and byte
// strings (values and map keys) are lowercase hex; Problem.path follows
// this form. For convenience the reader also accepts the start variant
// directly in the node ({"spawn": ...}) and an environment literal as a
// plain string.

type jsonConfig struct {
	Nodes      map[string]*jsonNode `json:"nodes"`
	Defaults   map[string]string    `json:"defaults,omitempty"`
	Extensions map[string]string    `json:"extensions,omitempty"`
}

type jsonStart struct {
	Spawn *jsonSpawn `json:"spawn,omitempty"`
	Dial  *jsonDial  `json:"dial,omitempty"`
	Other *jsonOther `json:"other,omitempty"`
}

type jsonNode struct {
	Start      *jsonStart        `json:"start,omitempty"`
	Spawn      *jsonSpawn        `json:"spawn,omitempty"`
	Dial       *jsonDial         `json:"dial,omitempty"`
	Other      *jsonOther        `json:"other,omitempty"`
	Credential *string           `json:"credential,omitempty"`
	Facets     []string          `json:"facets,omitempty"`
	Peer       *bool             `json:"peer,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Extensions map[string]string `json:"extensions,omitempty"`
}

type jsonSpawn struct {
	Command []string                   `json:"command"`
	Env     map[string]json.RawMessage `json:"env,omitempty"`
	Dir     *string                    `json:"dir,omitempty"`
}

type jsonDial struct {
	URL        string `json:"url"`
	Pin        string `json:"pin"`
	Credential string `json:"credential"`
}

type jsonOther struct {
	Kind   string `json:"kind"`
	Params string `json:"params"`
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
		if s := n.Start; s != nil {
			jn.Start = &jsonStart{}
			switch {
			case s.Spawn != nil:
				js := &jsonSpawn{Command: s.Spawn.Command, Dir: s.Spawn.Dir}
				if s.Spawn.Env != nil {
					js.Env = map[string]json.RawMessage{}
					for k, v := range s.Spawn.Env {
						var b []byte
						if v.Secret {
							b, _ = json.Marshal(map[string]string{"secret": v.Value})
						} else {
							b, _ = json.Marshal(map[string]string{"literal": v.Value})
						}
						js.Env[k] = b
					}
				}
				jn.Start.Spawn = js
			case s.Dial != nil:
				jn.Start.Dial = &jsonDial{URL: s.Dial.URL, Pin: hex.EncodeToString(s.Dial.Pin), Credential: s.Dial.Credential}
			case s.Other != nil:
				jn.Start.Other = &jsonOther{Kind: s.Other.Kind, Params: hex.EncodeToString(s.Other.Params)}
			}
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
		starts := 0
		if js := jn.Start; js != nil {
			if jn.Spawn != nil || jn.Dial != nil || jn.Other != nil {
				return fmt.Errorf("node %s: start given twice", id)
			}
			jn.Spawn, jn.Dial, jn.Other = js.Spawn, js.Dial, js.Other
			if js.Spawn == nil && js.Dial == nil && js.Other == nil {
				return fmt.Errorf("node %s: start needs one of spawn, dial and other", id)
			}
		}
		if jn.Spawn != nil {
			starts++
			sp := &Spawn{Command: jn.Spawn.Command, Dir: jn.Spawn.Dir}
			if jn.Spawn.Env != nil {
				sp.Env = map[string]EnvValue{}
				for k, raw := range jn.Spawn.Env {
					var lit string
					if json.Unmarshal(raw, &lit) == nil {
						sp.Env[k] = EnvValue{Value: lit}
						continue
					}
					var u map[string]string
					if err := json.Unmarshal(raw, &u); err != nil || len(u) != 1 {
						return fmt.Errorf("node %s env %s: {\"literal\": value} or {\"secret\": name}", id, k)
					}
					if v, ok := u["literal"]; ok {
						sp.Env[k] = EnvValue{Value: v}
					} else if v, ok := u["secret"]; ok {
						sp.Env[k] = EnvValue{Secret: true, Value: v}
					} else {
						return fmt.Errorf("node %s env %s: {\"literal\": value} or {\"secret\": name}", id, k)
					}
				}
			}
			n.Start = &Start{Spawn: sp}
		}
		if jn.Dial != nil {
			starts++
			pin, err := hex.DecodeString(jn.Dial.Pin)
			if err != nil {
				return fmt.Errorf("node %s pin: %v", id, err)
			}
			n.Start = &Start{Dial: &Dial{URL: jn.Dial.URL, Pin: pin, Credential: jn.Dial.Credential}}
		}
		if jn.Other != nil {
			starts++
			p, err := hex.DecodeString(jn.Other.Params)
			if err != nil {
				return fmt.Errorf("node %s params: %v", id, err)
			}
			n.Start = &Start{Other: &Other{Kind: jn.Other.Kind, Params: p}}
		}
		if starts > 1 {
			return fmt.Errorf("node %s: at most one of spawn, dial and other", id)
		}
		out.Nodes[id] = n
	}
	*c = out
	return nil
}
