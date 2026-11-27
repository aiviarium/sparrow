package main

var statusNames = []string{
	"ok", "cancelled", "unknown", "invalid_argument", "deadline_exceeded", "not_found",
	"already_exists", "permission_denied", "resource_exhausted", "failed_precondition", "aborted",
	"out_of_range", "unimplemented", "internal", "unavailable", "data_loss", "unauthenticated",
	"protocol_error", "schema_mismatch", "unsupported_version", "not_ready", "going_away", "message_too_large",
}

// Section 8: stream resets and transport closes carry core codes only.
// WebSocket: 1000 for ok, otherwise 4000 + the core status code.
func wsClose(status int) int {
	if status == 0 {
		return 1000
	}
	return 4000 + status
}

func statusVectors() O {
	var entries []any
	for i, n := range statusNames {
		entries = append(entries, o("status", i, "name", n,
			"websocket_close_code", wsClose(i),
			"webtransport_session_close_code", i,
			"webtransport_stream_reset_code", i))
	}
	var reserved []any
	for i := 23; i <= 31; i++ {
		reserved = append(reserved, o("status", i, "name", "(reserved)", "websocket_close_code", wsClose(i),
			"note", "Reserved for later core versions. Mapped by the same rule if a later version defines it; a peer of this revision never sends it."))
	}
	return o("area", "status", "vectors", []any{
		o(
			"name", "status/close-codes",
			"description", "Core status codes (section 8) and how each is carried by a WebTransport stream reset, a WebTransport session close and a WebSocket close.",
			"spec", "5.6, 8",
			"type", "status_table",
			"websocket_reason_max_bytes", 123,
			"webtransport_reason_max_bytes", 1024,
			"entries", entries,
		),
		o(
			"name", "status/reserved-23-31",
			"description", "Codes 23-31 are reserved for later core versions.",
			"spec", "8",
			"type", "status_reserved",
			"entries", reserved,
		),
		o(
			"name", "status/application-error-not-transport",
			"description", "An application error sigil (here conflict, 65, of part 16) travels only in an Error message; stream resets and transport closes carry core codes only, and Cancel, GoAway and AuthStatus carry core codes only.",
			"spec", "8",
			"type", "status_scope",
			"status", sgConflct,
			"allowed_in", []any{"Error"},
			"not_allowed_in", []any{"Cancel", "GoAway", "AuthStatus", "webtransport_stream_reset", "webtransport_session_close", "websocket_close"},
		),
	})
}
