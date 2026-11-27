package pipe

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func TestFraming(t *testing.T) {
	a, b := net.Pipe()
	c := New(b)
	lane, _ := c.SharedLane(nil)
	go func() {
		// A non-shortest length prefix (2-byte form of 3) is accepted.
		_, _ = a.Write([]byte{0x40, 0x03, 0x82, 0x01, 0x02})
		_, _ = a.Write(wire.AppendFrame(nil, bytes.Repeat([]byte{1}, 70000)))
		_, _ = a.Write([]byte{0x00}) // an empty frame
		_ = a.Close()
	}()
	m, err := lane.ReadMessage()
	if err != nil || !bytes.Equal(m, []byte{0x82, 0x01, 0x02}) {
		t.Fatalf("%x %v", m, err)
	}
	c.SetReadLimit(1000)
	var tl *wire.TooLargeError
	if _, err := lane.ReadMessage(); !errors.As(err, &tl) {
		t.Fatalf("got %v", err)
	}
}

func TestEOF(t *testing.T) {
	a, b := net.Pipe()
	c := New(b)
	lane, _ := c.SharedLane(nil)
	go func() {
		_, _ = a.Write(wire.AppendFrame(nil, []byte{0xf6}))
		_ = a.Close()
	}()
	if m, err := lane.ReadMessage(); err != nil || m[0] != 0xf6 {
		t.Fatalf("%x %v", m, err)
	}
	if _, err := lane.ReadMessage(); err != io.EOF {
		t.Fatalf("got %v", err)
	}
	<-c.Done()
	if c.Leases() {
		t.Fatal("a pipe has no leased streams")
	}
}
