package wire

import (
	"fmt"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

// Params keys (section 5.4).
const (
	ParamMaxMessageSize     = "maxMessageSize"
	ParamMaxInlineBytes     = "maxInlineBytes"
	ParamMaxConcurrentCalls = "maxConcurrentCalls"
	ParamMaxStreams         = "maxStreams"
	ParamSharedCredit       = "sharedCredit"
	ParamLeaseCredit        = "leaseCredit"
	ParamIdleTimeoutMs      = "idleTimeoutMs"
)

// Defaults (sections 4.1, 5.4).
const (
	DefaultMaxMessageSize      = 1 << 20
	DefaultMaxInlineBytes      = 64 << 10
	DefaultMaxConcurrentCalls  = 100
	DefaultMaxStreamsInWelcome = 16 // leased streams the client may open
	DefaultMaxStreamsInHello   = 4  // leased streams the server may open
	DefaultSharedCredit        = 64 << 10
	DefaultLeaseCredit         = 1 << 20
	DefaultIdleTimeoutMs       = 30000
)

var paramKeys = []string{ParamMaxMessageSize, ParamMaxInlineBytes, ParamMaxConcurrentCalls,
	ParamMaxStreams, ParamSharedCredit, ParamLeaseCredit, ParamIdleTimeoutMs}

// Params is the limits map a peer imposes on the other: Hello.params bind
// the server, Welcome.params bind the client. Known keys hold uints; a
// missing key means the default. Unknown keys are preserved in Extra.
type Params struct {
	values map[string]uint64
	// Extra holds keys this revision does not define.
	Extra map[string]cbor.Raw
}

// Get returns a key's value and whether it is present.
func (p Params) Get(key string) (uint64, bool) {
	v, ok := p.values[key]
	return v, ok
}

// Set sets a known key.
func (p *Params) Set(key string, v uint64) {
	if p.values == nil {
		p.values = map[string]uint64{}
	}
	p.values[key] = v
}

// Unset removes a key, so the default applies.
func (p *Params) Unset(key string) { delete(p.values, key) }

// Len is the number of keys present.
func (p Params) Len() int { return len(p.values) + len(p.Extra) }

// Limits are params with defaults applied.
type Limits struct {
	MaxMessageSize, MaxInlineBytes, MaxConcurrentCalls, MaxStreams uint64
	SharedCredit, LeaseCredit, IdleTimeoutMs                       uint64
}

// DefaultLimits returns the defaults for params sent by the given role:
// maxStreams defaults to 4 in Hello (sent by the client) and 16 in Welcome.
func DefaultLimits(sender Role) Limits {
	l := Limits{
		MaxMessageSize:     DefaultMaxMessageSize,
		MaxInlineBytes:     DefaultMaxInlineBytes,
		MaxConcurrentCalls: DefaultMaxConcurrentCalls,
		MaxStreams:         DefaultMaxStreamsInWelcome,
		SharedCredit:       DefaultSharedCredit,
		LeaseCredit:        DefaultLeaseCredit,
		IdleTimeoutMs:      DefaultIdleTimeoutMs,
	}
	if sender == Client {
		l.MaxStreams = DefaultMaxStreamsInHello
	}
	return l
}

// Limits applies the defaults for params sent by the given role.
func (p Params) Limits(sender Role) Limits {
	l := DefaultLimits(sender)
	for k, v := range p.values {
		switch k {
		case ParamMaxMessageSize:
			l.MaxMessageSize = v
		case ParamMaxInlineBytes:
			l.MaxInlineBytes = v
		case ParamMaxConcurrentCalls:
			l.MaxConcurrentCalls = v
		case ParamMaxStreams:
			l.MaxStreams = v
		case ParamSharedCredit:
			l.SharedCredit = v
		case ParamLeaseCredit:
			l.LeaseCredit = v
		case ParamIdleTimeoutMs:
			l.IdleTimeoutMs = v
		}
	}
	return l
}

// BelowDefaults reports whether any limit is below its default; a client
// does not start optimistically against such a server (section 5.3).
func (l Limits) BelowDefaults(sender Role) bool {
	d := DefaultLimits(sender)
	return l.MaxMessageSize < d.MaxMessageSize || l.MaxInlineBytes < d.MaxInlineBytes ||
		l.MaxConcurrentCalls < d.MaxConcurrentCalls || l.MaxStreams < d.MaxStreams ||
		l.SharedCredit < d.SharedCredit || l.LeaseCredit < d.LeaseCredit ||
		l.IdleTimeoutMs < d.IdleTimeoutMs
}

// IdleTimeout returns the idle timeout both peers use: the smaller one.
func IdleTimeout(a, b Limits) uint64 {
	if a.IdleTimeoutMs < b.IdleTimeoutMs {
		return a.IdleTimeoutMs
	}
	return b.IdleTimeoutMs
}

func isParamKey(k string) bool {
	for _, x := range paramKeys {
		if x == k {
			return true
		}
	}
	return false
}

// AppendTo appends the params map in Core Deterministic key order.
func (p Params) AppendTo(dst []byte) []byte {
	m := TextMap{}
	for k, v := range p.Extra {
		m[k] = v
	}
	for k, v := range p.values {
		m[k] = cbor.AppendUint(nil, v)
	}
	return m.AppendTo(dst)
}

func readParams(d *cbor.Decoder) (Params, error) {
	m, err := readTextMap(d)
	if err != nil {
		return Params{}, err
	}
	var p Params
	for k, v := range m {
		if !isParamKey(k) {
			if p.Extra == nil {
				p.Extra = map[string]cbor.Raw{}
			}
			p.Extra[k] = v
			continue
		}
		vd := cbor.NewDecoder(v)
		u, err := vd.Uint()
		if err != nil {
			return Params{}, fmt.Errorf("wire: params %q must be a uint", k)
		}
		p.Set(k, u)
	}
	return p, nil
}

// Minimums a received params map must respect (section 5.4).
const (
	MinMaxMessageSize     = 16384
	MinMaxInlineBytes     = 16384
	MinSharedCredit       = 16384
	MinLeaseCredit        = 16384
	MinMaxConcurrentCalls = 1
)

// ParamError reports a received params value below its minimum. A peer
// that receives one closes the session with GoAway(invalid_argument).
type ParamError struct {
	Key   string
	Value uint64
	Min   uint64
}

func (e *ParamError) Error() string {
	return fmt.Sprintf("wire: params %s = %d is below the minimum %d", e.Key, e.Value, e.Min)
}

// ParamMinimum returns the minimum for a params key, and false for keys
// without one (maxStreams, idleTimeoutMs and unknown keys).
func ParamMinimum(key string) (uint64, bool) {
	switch key {
	case ParamMaxMessageSize:
		return MinMaxMessageSize, true
	case ParamMaxInlineBytes:
		return MinMaxInlineBytes, true
	case ParamSharedCredit:
		return MinSharedCredit, true
	case ParamLeaseCredit:
		return MinLeaseCredit, true
	case ParamMaxConcurrentCalls:
		return MinMaxConcurrentCalls, true
	}
	return 0, false
}

// Validate checks received params against the minimums of section 5.4:
// maxMessageSize, maxInlineBytes, sharedCredit and leaseCredit at least
// 16384 and maxConcurrentCalls at least 1. Unknown keys (Extra) are
// ignored. It returns a *ParamError for the first offending key in the
// order of section 5.4; the receiver then sends GoAway(invalid_argument)
// (status.InvalidArgument) and closes the session.
func (p Params) Validate() error {
	for _, k := range paramKeys {
		v, ok := p.values[k]
		if !ok {
			continue
		}
		if min, has := ParamMinimum(k); has && v < min {
			return &ParamError{Key: k, Value: v, Min: min}
		}
	}
	return nil
}

// ValidateParams is Params.Validate as a function.
func ValidateParams(p Params) error { return p.Validate() }
