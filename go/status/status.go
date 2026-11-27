// Package status holds the Sparrow status codes (section 8) and their
// mapping onto transport close and reset codes.
//
// Codes 0-16 match gRPC. Core codes are the reserved sigils 0-31; 23-31 are
// reserved for later core versions. Stream resets and transport closes
// carry core codes only; application error sigils (64 and up) travel only
// in an Error message.
package status

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Code is a status sigil.
type Code uint64

// Core status codes.
const (
	OK                 Code = 0
	Cancelled          Code = 1
	Unknown            Code = 2
	InvalidArgument    Code = 3
	DeadlineExceeded   Code = 4
	NotFound           Code = 5
	AlreadyExists      Code = 6
	PermissionDenied   Code = 7
	ResourceExhausted  Code = 8
	FailedPrecondition Code = 9
	Aborted            Code = 10
	OutOfRange         Code = 11
	Unimplemented      Code = 12
	Internal           Code = 13
	Unavailable        Code = 14
	DataLoss           Code = 15
	Unauthenticated    Code = 16
	ProtocolError      Code = 17
	SchemaMismatch     Code = 18
	UnsupportedVersion Code = 19
	NotReady           Code = 20
	GoingAway          Code = 21
	MessageTooLarge    Code = 22

	// MaxCore is the highest core code, reserved ones included.
	MaxCore Code = 31
)

// Retry says whether and how a caller may retry after a status.
type Retry int

const (
	RetryNotApplicable Retry = iota // ok
	RetryNo
	RetryMaybe
	RetryLongerDeadline
	RetryBackoff
	RetryYes
	RetryAfterReauth
	RetryAfterSchemaReload
	RetryNewSession
)

type info struct {
	name  string
	retry Retry
}

var table = [...]info{
	{"ok", RetryNotApplicable},
	{"cancelled", RetryNo},
	{"unknown", RetryMaybe},
	{"invalid_argument", RetryNo},
	{"deadline_exceeded", RetryLongerDeadline},
	{"not_found", RetryNo},
	{"already_exists", RetryNo},
	{"permission_denied", RetryNo},
	{"resource_exhausted", RetryBackoff},
	{"failed_precondition", RetryNo},
	{"aborted", RetryYes},
	{"out_of_range", RetryNo},
	{"unimplemented", RetryNo},
	{"internal", RetryNo},
	{"unavailable", RetryBackoff},
	{"data_loss", RetryNo},
	{"unauthenticated", RetryAfterReauth},
	{"protocol_error", RetryNo},
	{"schema_mismatch", RetryAfterSchemaReload},
	{"unsupported_version", RetryNo},
	{"not_ready", RetryYes},
	{"going_away", RetryNewSession},
	{"message_too_large", RetryNo},
}

// IsCore reports whether c is a core code (0-31, reserved ones included).
func (c Code) IsCore() bool { return c <= MaxCore }

// IsDefined reports whether this revision defines c (0-22).
func (c Code) IsDefined() bool { return int(c) < len(table) && c <= MaxCore }

// Name returns the code's name, "(reserved)" for 23-31 and "" for
// application codes.
func (c Code) Name() string {
	switch {
	case c.IsDefined():
		return table[c].name
	case c.IsCore():
		return "(reserved)"
	}
	return ""
}

func (c Code) String() string {
	if c.IsDefined() {
		return table[c].name
	}
	return fmt.Sprintf("status(%d)", uint64(c))
}

// Retry returns the retry advice for a defined core code; RetryNo for
// others.
func (c Code) Retry() Retry {
	if c.IsDefined() {
		return table[c].retry
	}
	return RetryNo
}

// ByName returns the core code with the given name.
func ByName(name string) (Code, bool) {
	for i, e := range table {
		if e.name == name {
			return Code(i), true
		}
	}
	return 0, false
}

// Carrier is where a status is carried (section 8).
type Carrier int

const (
	InError Carrier = iota
	InCancel
	InGoAway
	InAuthStatus
	InWebTransportStreamReset
	InWebTransportSessionClose
	InWebSocketClose
)

// AllowedIn reports whether c may be carried there: Error carries any
// status sigil of the method's facet; everything else core codes only.
func (c Code) AllowedIn(where Carrier) bool {
	if where == InError {
		return true
	}
	return c.IsCore()
}

// Close reason limits in bytes of UTF-8.
const (
	MaxWebSocketReason    = 123
	MaxWebTransportReason = 1024
)

// WebSocket close codes.
const (
	WebSocketNormal     = 1000
	webSocketStatusBase = 4000
)

// WebSocketCloseCode maps a core code to a WebSocket close code: 1000 for
// ok, otherwise 4000 + the code, for all core codes 0-31.
func WebSocketCloseCode(c Code) (int, error) {
	if !c.IsCore() {
		return 0, fmt.Errorf("status: %d is not a core code", uint64(c))
	}
	if c == OK {
		return WebSocketNormal, nil
	}
	return webSocketStatusBase + int(c), nil
}

// FromWebSocketCloseCode maps a WebSocket close code back. Codes outside
// the mapping return false; a receiver treats them as unavailable.
func FromWebSocketCloseCode(code int) (Code, bool) {
	switch {
	case code == WebSocketNormal:
		return OK, true
	case code > webSocketStatusBase && code <= webSocketStatusBase+int(MaxCore):
		return Code(code - webSocketStatusBase), true
	}
	return 0, false
}

// WebTransportCode maps a core code to a WebTransport stream reset or
// session close code, which is the code itself (browsers limit stream
// reset codes to 0-255).
func WebTransportCode(c Code) (uint32, error) {
	if !c.IsCore() {
		return 0, fmt.Errorf("status: %d is not a core code", uint64(c))
	}
	return uint32(c), nil
}

// FromWebTransportCode maps a WebTransport error code back to a core code.
func FromWebTransportCode(code uint32) (Code, bool) {
	if code > uint32(MaxCore) {
		return 0, false
	}
	return Code(code), true
}

// TruncateReason shortens a close reason to at most max bytes, cutting at a
// UTF-8 character boundary. Invalid UTF-8 is replaced first.
func TruncateReason(reason string, max int) string {
	if !utf8.ValidString(reason) {
		reason = strings.ToValidUTF8(reason, "\uFFFD")
	}
	if len(reason) <= max {
		return reason
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut]
}
