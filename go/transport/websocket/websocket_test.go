package websocket

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ws "github.com/coder/websocket"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func serve(t *testing.T, o *AcceptOptions) (string, chan *Conn) {
	ch := make(chan *Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Accept(w, r, o)
		if err != nil {
			return
		}
		ch <- c
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), ch
}

func TestCloseCodes(t *testing.T) {
	for _, tc := range []struct {
		code   status.Code
		wsCode int
	}{{status.OK, 1000}, {status.GoingAway, 4021}, {status.SchemaMismatch, 4018}, {status.Code(30), 4030}} {
		url, ch := serve(t, nil)
		c, err := Dial(context.Background(), url, nil)
		if err != nil {
			t.Fatal(err)
		}
		s := <-ch
		got := make(chan error, 1)
		go func() {
			sl, _ := s.SharedLane(context.Background())
			_, err := sl.ReadMessage()
			got <- err
		}()
		reason := strings.Repeat("ü", 100) // 200 bytes
		_ = c.Close(tc.code, reason)
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("no close")
		}
		ce, ok := s.Err().(*transport.CloseError)
		if !ok || ce.Code != tc.code || !ce.Remote || len(ce.Reason) > 123 || !strings.HasPrefix(reason, ce.Reason) {
			t.Fatalf("%v: got %#v", tc.code, s.Err())
		}
		if n, _ := status.WebSocketCloseCode(tc.code); n != tc.wsCode {
			t.Fatalf("mapping %v -> %d", tc.code, n)
		}
	}
}

func TestMessages(t *testing.T) {
	url, ch := serve(t, nil)
	c, err := Dial(context.Background(), url, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	cl, _ := c.SharedLane(context.Background())
	sl, _ := s.SharedLane(context.Background())
	big := make([]byte, 300000)
	big[0] = 0x9f
	if err := cl.WriteMessage(big); err != nil {
		t.Fatal(err)
	}
	if b, err := sl.ReadMessage(); err != nil || len(b) != len(big) {
		t.Fatalf("%d %v", len(b), err)
	}
	s.SetReadLimit(1000)
	_ = cl.WriteMessage(make([]byte, 1001))
	var tl *wire.TooLargeError
	if _, err := sl.ReadMessage(); !errors.As(err, &tl) {
		t.Fatalf("got %v", err)
	}
	// A text message is a protocol error.
	_ = c.Underlying().Write(context.Background(), ws.MessageText, []byte("hi"))
	var pe *transport.ProtocolError
	if _, err := sl.ReadMessage(); !errors.As(err, &pe) {
		t.Fatalf("got %v", err)
	}
}

func TestUpgradeChecks(t *testing.T) {
	url, _ := serve(t, &AcceptOptions{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "https://ok.example" }})
	h := http.Header{}
	h.Set("Origin", "https://evil.example")
	if _, err := Dial(context.Background(), url, &DialOptions{Header: h}); err == nil {
		t.Fatal("bad origin accepted")
	}
	h.Set("Origin", "https://ok.example")
	if _, err := Dial(context.Background(), url, &DialOptions{Header: h}); err != nil {
		t.Fatal(err)
	}
	// The default check refuses a cross-origin request.
	url2, _ := serve(t, nil)
	h.Set("Origin", "https://evil.example")
	if _, err := Dial(context.Background(), url2, &DialOptions{Header: h}); err == nil {
		t.Fatal("cross-origin accepted by default")
	}
	// The subprotocol is required.
	if _, _, err := ws.Dial(context.Background(), url2, nil); err == nil {
		t.Fatal("accepted without the sparrow.v1 subprotocol")
	}
}
