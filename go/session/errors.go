package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/status"
)

// Error is a call or session failure with a status code. Handlers return
// it to answer with Error(code, message, details); callers receive it when
// the callee answered with Error, when the call failed locally, or when the
// session ended.
type Error struct {
	Code    status.Code
	Message string
	// Details is the raw Error.details value (nil = null).
	Details cbor.Raw
	// NotDispatched is set when the callee certainly did not run the call:
	// the session closed before Welcome (non-optimistic), or an optimistic
	// start was rejected (5.2, 5.3). Such a call may be retried as is.
	NotDispatched bool
	// Remote is set when the status came from the peer (an Error, Cancel
	// or GoAway message), not from a local decision.
	Remote bool
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "sparrow: " + e.Code.String()
	}
	return fmt.Sprintf("sparrow: %v: %s", e.Code, e.Message)
}

// Errorf returns an *Error with a formatted message.
func Errorf(code status.Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Code returns the status of err: the code of an *Error, cancelled or
// deadline_exceeded for context errors, ok for nil and unknown otherwise.
func Code(err error) status.Code {
	if err == nil {
		return status.OK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return status.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return status.Cancelled
	}
	return status.Unknown
}

// asError converts any error into an *Error.
func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: Code(err), Message: err.Error()}
}

// Sentinel errors for local misuse.
var (
	// ErrHalfClosed is returned when sending on a half of a call that is
	// already finished (or after the peer finished first and End was sent
	// on the caller's behalf).
	ErrHalfClosed = errors.New("sparrow: this half of the call is finished")
	// ErrCallEnded is returned when using a call that has ended.
	ErrCallEnded = errors.New("sparrow: call ended")
	// ErrWrongDirection is returned when sending a message kind the local
	// role of the call may not send.
	ErrWrongDirection = errors.New("sparrow: message kind not allowed in this direction")
)
