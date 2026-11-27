// Package admin implements sparrow.hub.admin v1 (spec/hub-admin.md): the
// desired-state document and its CBOR encoding, validation, revisions with
// confirmation and rollback, stored secrets and facets, watch, and the
// persistence of section 2.4 in a data directory with atomic writes.
//
// A Manager holds the state and serves the facet; a hub implements Applier
// to switch to a committed document and reconcile its nodes (section 2.2),
// and reports node states back with Manager.NodeEvent. Client is a small
// caller of the facet for controllers, tools and tests.
package admin

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/aiviarium/sparrow/go/adminiface"
	"github.com/aiviarium/sparrow/go/cbor"
)

// Config is the desired-state document (section 3). A nil map is an absent
// optional field, an empty one a present empty map; both survive a round
// trip, so two documents are equal exactly when their canonical encodings
// are.
type Config struct {
	Nodes map[string]*NodeConfig
	// Defaults maps an interface hash (as a string of its bytes) to the
	// preferred facet name.
	Defaults   map[string]string
	Extensions map[string][]byte
}

// NodeConfig configures one node.
type NodeConfig struct {
	Link       Link
	Peer       *bool
	Enabled    *bool
	Extensions map[string][]byte
}

// IsEnabled reports the enabled flag (default true).
func (n *NodeConfig) IsEnabled() bool { return n.Enabled == nil || *n.Enabled }

// IsPeer reports the peer flag (default false).
func (n *NodeConfig) IsPeer() bool { return n.Peer != nil && *n.Peer }

// Link is the Link union (type 66): exactly one of Dial (the hub dials
// the node) or Credential (the secret a node that dials in presents), or
// a variant this hub does not know (UnknownTag, kept as Unknown).
type Link struct {
	Dial       *Dial
	Credential *string
	UnknownTag uint64
	Unknown    cbor.Raw
}

// DialIn returns a Link for a node that dials in presenting the secret.
func DialIn(secret string) Link { return Link{Credential: &secret} }

// Dialed returns a Link for a node the hub dials.
func Dialed(d Dial) Link { return Link{Dial: &d} }

// CredentialName returns the dial-in credential's secret name, or "".
func (n *NodeConfig) CredentialName() string {
	if n.Link.Credential == nil {
		return ""
	}
	return *n.Link.Credential
}

// Dial makes the hub dial a node.
type Dial struct {
	URL        string
	Pin        []byte
	Credential string
}

// EmptyConfig returns {nodes: {}}, the document of revision 0.
func EmptyConfig() *Config { return &Config{Nodes: map[string]*NodeConfig{}} }

// Clone returns a deep copy (through the encoding).
func (c *Config) Clone() *Config {
	n, err := DecodeConfig(c.Encode())
	if err != nil {
		panic(err)
	}
	return n
}

// Clone returns a deep copy of a node's configuration.
func (n *NodeConfig) Clone() *NodeConfig {
	return (&Config{Nodes: map[string]*NodeConfig{"n": n}}).Clone().Nodes["n"]
}

// Equal reports whether two documents are the same.
func (c *Config) Equal(o *Config) bool { return bytes.Equal(c.Encode(), o.Encode()) }

// NodeIDs returns the node IDs in sorted order.
func (c *Config) NodeIDs() []string {
	ids := make([]string, 0, len(c.Nodes))
	for id := range c.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ---------------------------------------------------------------------------
// Encoding (Core Deterministic: map keys sorted by their encoded bytes,
// trailing nulls of structs omitted, section 3.4)
// ---------------------------------------------------------------------------

type mapEntry struct{ k, v []byte }

func appendMap(dst []byte, entries []mapEntry) []byte {
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].k, entries[j].k) < 0 })
	dst = cbor.AppendMapHead(dst, len(entries))
	for _, e := range entries {
		dst = append(dst, e.k...)
		dst = append(dst, e.v...)
	}
	return dst
}

// appendStruct writes a positional struct, omitting trailing nulls.
func appendStruct(dst []byte, fields ...[]byte) []byte {
	n := len(fields)
	for n > 0 && fields[n-1] == nil {
		n--
	}
	dst = cbor.AppendArrayHead(dst, n)
	for _, f := range fields[:n] {
		if f == nil {
			dst = cbor.AppendNull(dst)
		} else {
			dst = append(dst, f...)
		}
	}
	return dst
}

func text(s string) []byte  { return cbor.AppendText(nil, s) }
func bstr(b []byte) []byte  { return cbor.AppendBytes(nil, b) }
func uintv(v uint64) []byte { return cbor.AppendUint(nil, v) }
func boolv(v bool) []byte   { return cbor.AppendBool(nil, v) }
func optText(s *string) []byte {
	if s == nil {
		return nil
	}
	return text(*s)
}

func encStringBytesMap(m map[string][]byte) []byte {
	if m == nil {
		return nil
	}
	es := make([]mapEntry, 0, len(m))
	for k, v := range m {
		es = append(es, mapEntry{text(k), bstr(v)})
	}
	return appendMap(nil, es)
}

// Encode returns the canonical encoding of the document (type 64 Config).
func (c *Config) Encode() []byte { return c.AppendTo(nil) }

// AppendTo appends the canonical encoding.
func (c *Config) AppendTo(dst []byte) []byte {
	nodes := make([]mapEntry, 0, len(c.Nodes))
	for id, n := range c.Nodes {
		if n == nil {
			n = &NodeConfig{}
		}
		nodes = append(nodes, mapEntry{text(id), n.AppendTo(nil)})
	}
	var defaults []byte
	if c.Defaults != nil {
		es := make([]mapEntry, 0, len(c.Defaults))
		for k, v := range c.Defaults {
			es = append(es, mapEntry{bstr([]byte(k)), text(v)})
		}
		defaults = appendMap(nil, es)
	}
	return appendStruct(dst, appendMap(nil, nodes), defaults, encStringBytesMap(c.Extensions))
}

// AppendTo appends the canonical encoding of a NodeConfig (type 65).
func (n *NodeConfig) AppendTo(dst []byte) []byte {
	var peer, enabled []byte
	if n.Peer != nil {
		peer = boolv(*n.Peer)
	}
	if n.Enabled != nil {
		enabled = boolv(*n.Enabled)
	}
	return appendStruct(dst, n.Link.AppendTo(nil), peer, enabled, encStringBytesMap(n.Extensions))
}

// AppendTo appends the Link union (type 66).
func (l *Link) AppendTo(dst []byte) []byte {
	dst = cbor.AppendArrayHead(dst, 2)
	switch {
	case l.Dial != nil:
		dst = cbor.AppendUint(dst, adminiface.LinkDial)
		return l.Dial.AppendTo(dst)
	case l.Credential != nil:
		dst = cbor.AppendUint(dst, adminiface.LinkCredential)
		return cbor.AppendText(dst, *l.Credential)
	}
	dst = cbor.AppendUint(dst, l.UnknownTag)
	if l.Unknown == nil {
		return cbor.AppendNull(dst)
	}
	return append(dst, l.Unknown...)
}

// AppendTo appends the canonical encoding of a Dial (type 67).
func (d *Dial) AppendTo(dst []byte) []byte {
	return appendStruct(dst, text(d.URL), bstr(d.Pin), text(d.Credential))
}

// ---------------------------------------------------------------------------
// Decoding: tolerant as section 3.4 requires (extra struct elements and
// unknown union variants are kept or skipped), strict on types.
// ---------------------------------------------------------------------------

// DecodeError is a document that does not match its type.
type DecodeError struct {
	Path []string
	Msg  string
}

func (e *DecodeError) Error() string { return fmt.Sprintf("admin: %v: %s", e.Path, e.Msg) }

type dec struct {
	d    *cbor.Decoder
	err  error
	path []string
}

func (r *dec) fail(msg string, args ...any) {
	if r.err == nil {
		r.err = &DecodeError{Path: append([]string{}, r.path...), Msg: fmt.Sprintf(msg, args...)}
	}
}

func (r *dec) push(p string) { r.path = append(r.path, p) }
func (r *dec) pop()          { r.path = r.path[:len(r.path)-1] }

func (r *dec) null() bool {
	if r.err != nil {
		return true
	}
	if r.d.PeekNull() {
		_ = r.d.Null()
		return true
	}
	return false
}

func (r *dec) text() string {
	if r.err != nil {
		return ""
	}
	s, err := r.d.Text()
	if err != nil {
		r.fail("want a string: %v", err)
	}
	return s
}

func (r *dec) bytes() []byte {
	if r.err != nil {
		return nil
	}
	b, err := r.d.Bytes()
	if err != nil {
		r.fail("want bytes: %v", err)
	}
	return append([]byte{}, b...)
}

func (r *dec) uint() uint64 {
	if r.err != nil {
		return 0
	}
	v, err := r.d.Uint()
	if err != nil {
		r.fail("want an unsigned integer: %v", err)
	}
	return v
}

func (r *dec) boolean() bool {
	if r.err != nil {
		return false
	}
	v, err := r.d.Bool()
	if err != nil {
		r.fail("want a bool: %v", err)
	}
	return v
}

func (r *dec) array() int {
	if r.err != nil {
		return 0
	}
	n, err := r.d.ArrayHead()
	if err != nil {
		r.fail("want an array: %v", err)
	}
	return n
}

func (r *dec) mapHead() int {
	if r.err != nil {
		return 0
	}
	n, err := r.d.MapHead()
	if err != nil {
		r.fail("want a map: %v", err)
	}
	return n
}

func (r *dec) skip(n int) {
	for i := 0; i < n && r.err == nil; i++ {
		if err := r.d.Skip(); err != nil {
			r.fail("%v", err)
		}
	}
}

func (r *dec) raw() cbor.Raw {
	if r.err != nil {
		return nil
	}
	v, err := r.d.Raw()
	if err != nil {
		r.fail("%v", err)
	}
	return append(cbor.Raw{}, v...)
}

// structFields reads a positional struct: f is called for each element
// index below known; later elements are skipped (3.4).
func (r *dec) structFields(known int, f func(i int)) {
	n := r.array()
	for i := 0; i < n && r.err == nil; i++ {
		if i >= known {
			r.skip(1)
			continue
		}
		f(i)
	}
}

func (r *dec) stringBytesMap() map[string][]byte {
	n := r.mapHead()
	m := make(map[string][]byte, n)
	for i := 0; i < n && r.err == nil; i++ {
		k := r.text()
		r.push(k)
		if _, dup := m[k]; dup {
			r.fail("duplicate key")
		}
		m[k] = r.bytes()
		r.pop()
	}
	return m
}

func decodeWith(b []byte, f func(r *dec)) error {
	if err := cbor.Validate(b, cbor.Options{}); err != nil {
		return &DecodeError{Msg: err.Error()}
	}
	r := &dec{d: cbor.NewDecoder(b)}
	f(r)
	if r.err == nil && !r.d.Done() {
		r.fail("trailing bytes")
	}
	return r.err
}

// DecodeConfig decodes a Config.
func DecodeConfig(b []byte) (*Config, error) {
	var c *Config
	err := decodeWith(b, func(r *dec) { c = r.config() })
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (r *dec) config() *Config {
	c := &Config{}
	r.structFields(3, func(i int) {
		switch i {
		case 0:
			r.push("nodes")
			n := r.mapHead()
			c.Nodes = make(map[string]*NodeConfig, n)
			for j := 0; j < n && r.err == nil; j++ {
				id := r.text()
				r.push(id)
				if _, dup := c.Nodes[id]; dup {
					r.fail("duplicate node")
				}
				c.Nodes[id] = r.nodeConfig()
				r.pop()
			}
			r.pop()
		case 1:
			r.push("defaults")
			if !r.null() {
				n := r.mapHead()
				c.Defaults = make(map[string]string, n)
				for j := 0; j < n && r.err == nil; j++ {
					k := string(r.bytes())
					r.push(fmt.Sprintf("%x", k))
					c.Defaults[k] = r.text()
					r.pop()
				}
			}
			r.pop()
		case 2:
			r.push("extensions")
			if !r.null() {
				c.Extensions = r.stringBytesMap()
			}
			r.pop()
		}
	})
	if c.Nodes == nil && r.err == nil {
		r.fail("nodes is required")
	}
	return c
}

func (r *dec) nodeConfig() *NodeConfig {
	n := &NodeConfig{}
	hasLink := false
	r.structFields(4, func(i int) {
		switch i {
		case 0:
			r.push("link")
			hasLink = !r.null()
			if hasLink {
				n.Link = r.link()
			}
			r.pop()
		case 1:
			r.push("peer")
			if !r.null() {
				v := r.boolean()
				n.Peer = &v
			}
			r.pop()
		case 2:
			r.push("enabled")
			if !r.null() {
				v := r.boolean()
				n.Enabled = &v
			}
			r.pop()
		case 3:
			r.push("extensions")
			if !r.null() {
				n.Extensions = r.stringBytesMap()
			}
			r.pop()
		}
	})
	if !hasLink && r.err == nil {
		r.fail("link is required")
	}
	return n
}

func (r *dec) link() Link {
	var l Link
	if n := r.array(); n != 2 && r.err == nil {
		r.fail("a union is [tag, value]")
		return l
	}
	switch tag := r.uint(); tag {
	case adminiface.LinkDial:
		r.push("dial")
		l.Dial = r.dial()
		r.pop()
	case adminiface.LinkCredential:
		r.push("credential")
		c := r.text()
		l.Credential = &c
		r.pop()
	default:
		l.UnknownTag = tag
		l.Unknown = r.raw()
	}
	return l
}

func (r *dec) dial() *Dial {
	d := &Dial{}
	seen := 0
	r.structFields(3, func(i int) {
		seen++
		switch i {
		case 0:
			r.push("url")
			d.URL = r.text()
		case 1:
			r.push("pin")
			d.Pin = r.bytes()
		case 2:
			r.push("credential")
			d.Credential = r.text()
		}
		r.pop()
	})
	if seen < 3 && r.err == nil {
		r.fail("url, pin and credential are required")
	}
	return d
}

// ---------------------------------------------------------------------------
// The other types of section 5.1
// ---------------------------------------------------------------------------

// RevisionState is the state of a revision.
type RevisionState uint64

// Revision states (sigils 64-66).
const (
	Pending    = RevisionState(adminiface.SigilPending)
	Confirmed  = RevisionState(adminiface.SigilConfirmed)
	RolledBack = RevisionState(adminiface.SigilRolledBack)
)

// String returns the value name alone, the sigil name without its
// "RevisionState." prefix (core 6.5 lets bindings show it so): pending,
// confirmed or rolledBack. The JSON output of sparrow-admin uses it.
func (s RevisionState) String() string {
	switch s {
	case Pending:
		return "pending"
	case Confirmed:
		return "confirmed"
	case RolledBack:
		return "rolledBack"
	}
	return fmt.Sprintf("RevisionState(%d)", uint64(s))
}

// NodeState is the state of a node.
type NodeState uint64

// Node states (sigils 67-70).
const (
	Connected = NodeState(adminiface.SigilConnected)
	Offline   = NodeState(adminiface.SigilOffline)
	Disabled  = NodeState(adminiface.SigilDisabled)
	Removed   = NodeState(adminiface.SigilRemoved)
)

// String returns the value name alone, the sigil name without its
// "NodeState." prefix: connected, offline, disabled or removed.
func (s NodeState) String() string {
	switch s {
	case Connected:
		return "connected"
	case Offline:
		return "offline"
	case Disabled:
		return "disabled"
	case Removed:
		return "removed"
	}
	return fmt.Sprintf("NodeState(%d)", uint64(s))
}

// Snapshot is type 68.
type Snapshot struct {
	Revision    uint64
	Config      *Config
	State       RevisionState
	ConfirmInMs *uint64
}

// RevisionEvent is type 76.
type RevisionEvent struct {
	Revision    uint64
	State       RevisionState
	ConfirmInMs *uint64
}

// NodeEvent is type 78.
type NodeEvent struct {
	Node     string
	Revision uint64
	State    NodeState
	Message  *string
}

// Event is type 75: exactly one of its fields is set.
type Event struct {
	Snapshot *Snapshot
	Revision *RevisionEvent
	Node     *NodeEvent
}

// Problem is type 71.
type Problem struct {
	Path    []string
	Message string
}

func (p Problem) String() string { return fmt.Sprintf("%v: %s", p.Path, p.Message) }

func optUint(v *uint64) []byte {
	if v == nil {
		return nil
	}
	return uintv(*v)
}

// AppendTo encodes a Snapshot.
func (s *Snapshot) AppendTo(dst []byte) []byte {
	return appendStruct(dst, uintv(s.Revision), s.Config.Encode(), uintv(uint64(s.State)), optUint(s.ConfirmInMs))
}

// Encode encodes an Event.
func (e *Event) Encode() []byte {
	dst := cbor.AppendArrayHead(nil, 2)
	switch {
	case e.Snapshot != nil:
		dst = cbor.AppendUint(dst, adminiface.EventSnapshot)
		return e.Snapshot.AppendTo(dst)
	case e.Revision != nil:
		dst = cbor.AppendUint(dst, adminiface.EventRevision)
		r := e.Revision
		return appendStruct(dst, uintv(r.Revision), uintv(uint64(r.State)), optUint(r.ConfirmInMs))
	default:
		dst = cbor.AppendUint(dst, adminiface.EventNode)
		n := e.Node
		return appendStruct(dst, text(n.Node), uintv(n.Revision), uintv(uint64(n.State)), optText(n.Message))
	}
}

// EncodeProblems encodes a Problems list (type 72).
func EncodeProblems(ps []Problem) []byte {
	dst := cbor.AppendArrayHead(nil, len(ps))
	for _, p := range ps {
		path := cbor.AppendArrayHead(nil, len(p.Path))
		for _, s := range p.Path {
			path = cbor.AppendText(path, s)
		}
		dst = appendStruct(dst, path, text(p.Message))
	}
	return dst
}

// ProblemsDetails returns Error.details for an invalid document: the
// dynamic value [72, problems] (section 5.2).
func ProblemsDetails(ps []Problem) cbor.Raw {
	dst := cbor.AppendArrayHead(nil, 2)
	dst = cbor.AppendUint(dst, adminiface.TypeProblems)
	return append(dst, EncodeProblems(ps)...)
}

// DecodeSnapshot decodes type 68.
func DecodeSnapshot(b []byte) (*Snapshot, error) {
	var s *Snapshot
	err := decodeWith(b, func(r *dec) { s = r.snapshot() })
	return s, err
}

func (r *dec) snapshot() *Snapshot {
	s := &Snapshot{}
	r.structFields(4, func(i int) {
		switch i {
		case 0:
			s.Revision = r.uint()
		case 1:
			r.push("config")
			s.Config = r.config()
			r.pop()
		case 2:
			s.State = RevisionState(r.uint())
		case 3:
			if !r.null() {
				v := r.uint()
				s.ConfirmInMs = &v
			}
		}
	})
	if s.Config == nil && r.err == nil {
		r.fail("config is required")
	}
	return s
}

// DecodeEvent decodes type 75.
func DecodeEvent(b []byte) (*Event, error) {
	e := &Event{}
	err := decodeWith(b, func(r *dec) {
		if n := r.array(); n != 2 && r.err == nil {
			r.fail("a union is [tag, value]")
			return
		}
		switch tag := r.uint(); tag {
		case adminiface.EventSnapshot:
			e.Snapshot = r.snapshot()
		case adminiface.EventRevision:
			ev := &RevisionEvent{}
			r.structFields(3, func(i int) {
				switch i {
				case 0:
					ev.Revision = r.uint()
				case 1:
					ev.State = RevisionState(r.uint())
				case 2:
					if !r.null() {
						v := r.uint()
						ev.ConfirmInMs = &v
					}
				}
			})
			e.Revision = ev
		case adminiface.EventNode:
			ev := &NodeEvent{}
			r.structFields(4, func(i int) {
				switch i {
				case 0:
					ev.Node = r.text()
				case 1:
					ev.Revision = r.uint()
				case 2:
					ev.State = NodeState(r.uint())
				case 3:
					if !r.null() {
						m := r.text()
						ev.Message = &m
					}
				}
			})
			e.Node = ev
		default:
			r.skip(1)
			r.fail("unknown event variant %d", tag)
		}
	})
	return e, err
}

// DecodeProblems decodes type 73, or the dynamic [72, problems].
func DecodeProblems(b []byte) ([]Problem, error) {
	var ps []Problem
	err := decodeWith(b, func(r *dec) {
		n := r.array()
		if n == 2 && !r.d.Done() {
			if m, _ := r.d.PeekMajor(); m == cbor.MajorUint {
				if r.uint() != adminiface.TypeProblems {
					r.fail("details are not Problems")
					return
				}
				n = r.array()
			}
		}
		ps = make([]Problem, 0, n)
		for i := 0; i < n && r.err == nil; i++ {
			var p Problem
			r.structFields(2, func(j int) {
				switch j {
				case 0:
					k := r.array()
					p.Path = make([]string, 0, k)
					for x := 0; x < k && r.err == nil; x++ {
						p.Path = append(p.Path, r.text())
					}
				case 1:
					p.Message = r.text()
				}
			})
			ps = append(ps, p)
		}
	})
	return ps, err
}

// CommitRequest is type 69.
type CommitRequest struct {
	Base            uint64
	Config          *Config
	ConfirmWithinMs uint64
}

// Encode encodes the request.
func (c *CommitRequest) Encode() []byte {
	return appendStruct(nil, uintv(c.Base), c.Config.Encode(), uintv(c.ConfirmWithinMs))
}

// DecodeCommitRequest decodes type 69 (and type 70, which is its prefix).
func DecodeCommitRequest(b []byte) (*CommitRequest, error) {
	c := &CommitRequest{}
	seen := 0
	err := decodeWith(b, func(r *dec) {
		r.structFields(3, func(i int) {
			seen++
			switch i {
			case 0:
				c.Base = r.uint()
			case 1:
				c.Config = r.config()
			case 2:
				c.ConfirmWithinMs = r.uint()
			}
		})
	})
	if err == nil && c.Config == nil {
		err = &DecodeError{Msg: "config is required"}
	}
	return c, err
}

// EncodeValidateRequest encodes type 70.
func EncodeValidateRequest(base uint64, c *Config) []byte {
	return appendStruct(nil, uintv(base), c.Encode())
}

// EncodeSecret encodes type 73.
func EncodeSecret(name string, value []byte) []byte {
	return appendStruct(nil, text(name), bstr(value))
}

// DecodeSecret decodes type 72.
func DecodeSecret(b []byte) (string, []byte, error) {
	var name string
	var value []byte
	seen := 0
	err := decodeWith(b, func(r *dec) {
		r.structFields(2, func(i int) {
			seen++
			switch i {
			case 0:
				name = r.text()
			case 1:
				value = r.bytes()
			}
		})
	})
	if err == nil && seen < 2 {
		err = errors.New("admin: a Secret needs a name and a value")
	}
	return name, value, err
}

// EncodeStrings encodes list<string> (Names).
func EncodeStrings(ss []string) []byte {
	dst := cbor.AppendArrayHead(nil, len(ss))
	for _, s := range ss {
		dst = cbor.AppendText(dst, s)
	}
	return dst
}

// DecodeStrings decodes list<string>.
func DecodeStrings(b []byte) ([]string, error) {
	var out []string
	err := decodeWith(b, func(r *dec) {
		n := r.array()
		out = make([]string, 0, n)
		for i := 0; i < n && r.err == nil; i++ {
			out = append(out, r.text())
		}
	})
	return out, err
}

// DecodeUint, DecodeText and DecodeBytes decode a bare value.
func DecodeUint(b []byte) (uint64, error) {
	var v uint64
	err := decodeWith(b, func(r *dec) { v = r.uint() })
	return v, err
}

// DecodeText decodes a text string.
func DecodeText(b []byte) (string, error) {
	var v string
	err := decodeWith(b, func(r *dec) { v = r.text() })
	return v, err
}

// DecodeBytes decodes a byte string.
func DecodeBytes(b []byte) ([]byte, error) {
	var v []byte
	err := decodeWith(b, func(r *dec) { v = r.bytes() })
	return v, err
}
