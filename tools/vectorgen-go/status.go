package main

import "strconv"

var statusNames = []string{
	"ok", "cancelled", "unknown", "invalid_argument", "deadline_exceeded", "not_found",
	"already_exists", "permission_denied", "resource_exhausted", "failed_precondition", "aborted",
	"out_of_range", "unimplemented", "internal", "unavailable", "data_loss", "unauthenticated",
	"protocol_error", "schema_mismatch", "unsupported_version", "not_ready", "going_away", "message_too_large",
}

// Section 8: WebSocket close code is 4000 + status for core codes 0-31;
// any other status uses 4002 (unknown) with the status in the reason.
func wsClose(status int) (int, any) {
	if status >= 0 && status <= 31 {
		return 4000 + status, nil
	}
	return 4002, strconv.Itoa(status)
}

func statusVectors() O {
	var entries []any
	row := func(status int, name, note string) {
		code, reason := wsClose(status)
		var reset any = status
		if status > 255 {
			reset = nil
		}
		e := o("status", status, "name", name,
			"websocket_close_code", code, "websocket_close_reason_prefix", reason,
			"webtransport_session_close_code", status,
			"webtransport_stream_reset_code", reset)
		if note != "" {
			e = append(e, kv{"note", note})
		}
		entries = append(entries, e)
	}
	for i, n := range statusNames {
		row(i, n, "")
	}
	for i := 23; i <= 31; i++ {
		row(i, "(reserved)", "Reserved for later core versions; still in the core range 0-31.")
	}
	row(sgQuota, "acme.notes.quota_exceeded", "Non-core (method error sigil from the example schema).")
	row(sgConflct, "acme.notes.conflict", "Non-core (method error sigil from the example schema).")
	row(1000, "(application sigil 1000)", "Non-core and above 255: no WebTransport stream reset code (see SPEC-ISSUES.md).")
	return o("area", "status", "vectors", []any{o(
		"name", "status/close-codes",
		"description", "Status codes (section 8) and how each is carried when a transport is closed or a stream is reset. websocket_close_reason_prefix is null when the close code alone identifies the status.",
		"spec", "5.6, 8",
		"type", "status_table",
		"entries", entries,
	)})
}
