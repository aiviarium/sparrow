package wire

import (
	"errors"
	"fmt"
	"math"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

// CountedBytes returns how many bytes a message counts against its call's
// credit (section 7.4): an Item or Progress counts the length of its whole
// CBOR data item without the length prefix (encodedLen); a Bytes message
// counts the length of its data; every other message counts nothing.
func CountedBytes(m Message, encodedLen int) uint64 {
	switch x := m.(type) {
	case *Item, *Progress:
		return uint64(encodedLen)
	case *Bytes:
		return uint64(len(x.Data))
	}
	return 0
}

// CountedBytesRaw is CountedBytes for an encoded message, without decoding
// its payload. b must be a valid message (see Decode).
func CountedBytesRaw(b []byte) (uint64, error) {
	kind, _, err := PeekCall(b)
	if err != nil {
		return 0, err
	}
	switch kind {
	case KindItem, KindProgress:
		return uint64(len(b)), nil
	case KindBytes:
		d := cbor.NewDecoder(b)
		if _, err := d.ArrayHead(); err != nil {
			return 0, err
		}
		for i := 0; i < 3; i++ { // kind, call_id, token
			if err := d.Skip(); err != nil {
				return 0, err
			}
		}
		data, err := d.Bytes()
		if err != nil {
			return 0, err
		}
		return uint64(len(data)), nil
	}
	return 0, nil
}

// InitialCredit returns the credit one direction of a call starts with:
// the receiver's sharedCredit on the shared lane or leaseCredit on a leased
// stream. For the callee's half the caller may replace it with the credit
// metadata key, passed here as override (nil if absent).
func InitialCredit(receiver Limits, leased bool, override *uint64) uint64 {
	if override != nil {
		return *override
	}
	if leased {
		return receiver.LeaseCredit
	}
	return receiver.SharedCredit
}

// ErrNoCredit is returned when a message is sent or received while the
// remaining credit is zero or negative; for a receiver this is a protocol
// violation (section 7.4).
var ErrNoCredit = errors.New("wire: no credit left")

// CreditWindow tracks the credit of one direction of one call. The same
// accounting runs on both sides: the sender to decide when it may send,
// the receiver to detect violations.
//
// A message may be sent whenever the remaining credit is above zero, even
// if it is larger; the credit then goes negative until more is granted.
type CreditWindow struct {
	remaining int64
}

// NewCreditWindow returns a window with the given initial credit.
func NewCreditWindow(initial uint64) *CreditWindow {
	return &CreditWindow{remaining: clampInt64(initial)}
}

// Remaining returns the remaining credit, which can be negative.
func (w *CreditWindow) Remaining() int64 { return w.remaining }

// CanSend reports whether the remaining credit is above zero.
func (w *CreditWindow) CanSend() bool { return w.remaining > 0 }

// Consume accounts for a message of n counted bytes. It fails with
// ErrNoCredit, leaving the window unchanged, if no credit is left. A
// message that counts zero bytes always passes.
func (w *CreditWindow) Consume(n uint64) error {
	if n == 0 {
		return nil
	}
	if w.remaining <= 0 {
		return fmt.Errorf("%w (remaining %d)", ErrNoCredit, w.remaining)
	}
	have := uint64(w.remaining) // remaining > 0 here
	if n <= have {
		w.remaining = int64(have - n)
	} else if deficit := n - have; deficit >= 1<<63 {
		w.remaining = math.MinInt64
	} else {
		w.remaining = -int64(deficit)
	}
	return nil
}

// Grant adds credit; grants add up (saturating at MaxInt64).
func (w *CreditWindow) Grant(n uint64) {
	add := clampInt64(n)
	if w.remaining > 0 && add > math.MaxInt64-w.remaining {
		w.remaining = math.MaxInt64
		return
	}
	w.remaining += add
}

func clampInt64(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}
