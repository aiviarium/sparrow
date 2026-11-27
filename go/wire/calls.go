package wire

import "errors"

// NotificationID is the call ID of notifications, which get no reply.
const NotificationID = 0

// CallerOf returns which role assigned a non-zero call ID: client IDs are
// even and server IDs odd (section 7.1).
func CallerOf(callID uint64) Role {
	if callID%2 == 0 {
		return Client
	}
	return Server
}

// ValidCallID reports whether a caller of the given role may use the ID.
// ID 0 is a notification for either role.
func ValidCallID(caller Role, callID uint64) bool {
	return callID == NotificationID || CallerOf(callID) == caller
}

// CheckOptimistic checks the rules of section 5.3 for an optimistic Hello:
// exactly one protocol version and a cached schema hash.
func (m *Hello) CheckOptimistic() error {
	if !m.Optimistic {
		return nil
	}
	if len(m.Versions) != 1 {
		return errors.New("wire: an optimistic Hello lists exactly one protocol version")
	}
	if m.KnownSchema == nil {
		return errors.New("wire: an optimistic Hello names its cached schema")
	}
	return nil
}
