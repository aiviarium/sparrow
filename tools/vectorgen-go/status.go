package main

import "strings"

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
			"note", "Reserved for later core versions; the WebSocket mapping covers all core codes 0-31 (section 8)."))
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
			"name", "status/close-reason-truncation",
			"description", "A sender shortens a close reason that is too long at a character boundary (section 8): the longest UTF-8 prefix that fits and ends on a character boundary. The reason here mixes 1-, 2- and 3-byte characters.",
			"spec", "8",
			"type", "reason_truncation",
			"cases", []any{
				truncCase("websocket", 123, "x"+longReason),
				truncCase("webtransport", 1024, longReason),
			},
		),
		o(
			"name", "status/application-error-not-transport",
			"description", "An application error sigil (here conflict, 65, of facet 16) travels only in an Error message; stream resets and transport closes carry core codes only, and Cancel, GoAway and AuthStatus carry core codes only.",
			"spec", "8",
			"type", "status_scope",
			"status", sgConflct,
			"allowed_in", []any{"Error"},
			"not_allowed_in", []any{"Cancel", "GoAway", "AuthStatus", "webtransport_stream_reset", "webtransport_session_close", "websocket_close"},
		),
	})
}

var longReason = strings.Repeat("Wartung läuft – Neustart ", 45)

// truncUTF8 returns the longest prefix of s of at most n bytes that ends on
// a character boundary.
func truncUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n]
}

func truncCase(where string, max int, reason string) O {
	t := truncUTF8(reason, max)
	if len(t) == max {
		panic("truncation case does not cut inside a character")
	}
	return o("binding", where, "max_bytes", max, "reason_utf8", reason, "reason_length", len(reason),
		"truncated_utf8", t, "truncated_length", len(t))
}
