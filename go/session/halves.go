package session

import "github.com/aiviarium/sparrow/go/wire"

// halves tracks the two halves of a call (section 7.1). The caller's half
// is finished by the Request unless the method has flag 0x8 (then by End or
// Cancel; Cancel always finishes it); the callee's half by Response unless
// the method has flag 0x10 (then by End); Error finishes it at any time.
type halves struct {
	inputEnds, outputEnds  bool
	callerDone, calleeDone bool
}

func newHalves(flags uint64) halves {
	return halves{inputEnds: flags&0x8 != 0, outputEnds: flags&0x10 != 0}
}

// ended reports whether both halves are finished.
func (h *halves) ended() bool { return h.callerDone && h.calleeDone }

// callerMaySend reports whether the caller may send a message of kind k
// now. Cancel is allowed while the callee's half is open even after the
// caller's own half is finished (a unary call can be cancelled).
func (h *halves) callerMaySend(k wire.Kind) bool {
	switch k {
	case wire.KindCancel:
		return !h.calleeDone
	case wire.KindItem, wire.KindBytes, wire.KindEnd:
		return !h.callerDone
	case wire.KindCredit:
		return !h.calleeDone
	}
	return false
}

// calleeMaySend reports whether the callee may send a message of kind k.
func (h *halves) calleeMaySend(k wire.Kind) bool {
	switch k {
	case wire.KindResponse, wire.KindItem, wire.KindBytes, wire.KindEnd,
		wire.KindError, wire.KindProgress, wire.KindHeaders:
		return !h.calleeDone
	case wire.KindCredit:
		return !h.callerDone
	}
	return false
}

// isCallerKind reports whether a caller may ever send kind k.
func isCallerKind(k wire.Kind) bool {
	switch k {
	case wire.KindItem, wire.KindEnd, wire.KindCancel, wire.KindCredit, wire.KindBytes:
		return true
	}
	return false
}

// isCalleeKind reports whether a callee may ever send kind k.
func isCalleeKind(k wire.Kind) bool {
	switch k {
	case wire.KindResponse, wire.KindItem, wire.KindEnd, wire.KindError,
		wire.KindProgress, wire.KindHeaders, wire.KindCredit, wire.KindBytes:
		return true
	}
	return false
}

// callerMsg applies a caller message (other than Request and Credit) and
// reports whether it finished the caller's half.
func (h *halves) callerMsg(k wire.Kind) bool {
	if h.callerDone {
		return false
	}
	switch k {
	case wire.KindCancel:
		h.callerDone = true
	case wire.KindEnd:
		// End finishes the half of a 0x8 method; for other methods the
		// half was already finished by the Request.
		h.callerDone = true
	default:
		return false
	}
	return true
}

// request applies the Request itself.
func (h *halves) request() {
	if !h.inputEnds {
		h.callerDone = true
	}
}

// calleeMsg applies a callee message and reports whether it finished the
// callee's half.
func (h *halves) calleeMsg(k wire.Kind) bool {
	if h.calleeDone {
		return false
	}
	switch k {
	case wire.KindError:
		h.calleeDone = true
	case wire.KindResponse:
		if h.outputEnds {
			return false
		}
		h.calleeDone = true
	case wire.KindEnd:
		if !h.outputEnds {
			return false
		}
		h.calleeDone = true
	default:
		return false
	}
	return true
}
