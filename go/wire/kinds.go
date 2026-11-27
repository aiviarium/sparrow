package wire

import "fmt"

// Kind is a message kind, the first element of every envelope (3.3).
type Kind uint64

// Message kinds defined by this revision.
const (
	KindHello        Kind = 0
	KindWelcome      Kind = 1
	KindReady        Kind = 2
	KindSchemaUpdate Kind = 3
	KindSchemaAck    Kind = 4
	KindAuthRefresh  Kind = 5
	KindAuthStatus   Kind = 6
	KindPing         Kind = 7
	KindPong         Kind = 8
	KindGoAway       Kind = 9
	KindRequest      Kind = 16
	KindResponse     Kind = 17
	KindItem         Kind = 18
	KindEnd          Kind = 19
	KindError        Kind = 20
	KindProgress     Kind = 21
	KindHeaders      Kind = 22
	KindCancel       Kind = 23
	KindCredit       Kind = 24
	KindBytes        Kind = 25
)

var kindNames = map[Kind]string{
	KindHello: "Hello", KindWelcome: "Welcome", KindReady: "Ready",
	KindSchemaUpdate: "SchemaUpdate", KindSchemaAck: "SchemaAck", KindAuthRefresh: "AuthRefresh",
	KindAuthStatus: "AuthStatus", KindPing: "Ping", KindPong: "Pong", KindGoAway: "GoAway",
	KindRequest: "Request", KindResponse: "Response", KindItem: "Item", KindEnd: "End",
	KindError: "Error", KindProgress: "Progress", KindHeaders: "Headers", KindCancel: "Cancel",
	KindCredit: "Credit", KindBytes: "Bytes",
}

func (k Kind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return fmt.Sprintf("Kind(%d)", uint64(k))
}

// Known reports whether this revision defines the kind.
func (k Kind) Known() bool { _, ok := kindNames[k]; return ok }

// IsCall reports whether the kind is a call message (16-25), whose second
// element is a call ID.
func (k Kind) IsCall() bool { return k >= KindRequest && k <= KindBytes }

// Owner is who allocates a range of kinds.
type Owner int

const (
	OwnerCore Owner = iota
	OwnerProfile
	OwnerInvalid
)

func (o Owner) String() string {
	return [...]string{"core", "profile", "invalid"}[o]
}

// Action is what a receiver does with a message of a kind it does not know.
type Action int

const (
	// CloseProtocolError: close the session with protocol_error.
	CloseProtocolError Action = iota
	// Ignore the message.
	Ignore
)

func (a Action) String() string {
	if a == Ignore {
		return "ignore"
	}
	return "close_protocol_error"
}

// KindRange returns the owner of a kind and what to do if it is unknown
// (section 3.3): 0-47 core / close, 48-63 core / ignore, 64-111 profile /
// close, 112-127 profile / ignore, 128 and above invalid / close.
func KindRange(kind uint64) (Owner, Action) {
	switch {
	case kind <= 47:
		return OwnerCore, CloseProtocolError
	case kind <= 63:
		return OwnerCore, Ignore
	case kind <= 111:
		return OwnerProfile, CloseProtocolError
	case kind <= 127:
		return OwnerProfile, Ignore
	}
	return OwnerInvalid, CloseProtocolError
}
