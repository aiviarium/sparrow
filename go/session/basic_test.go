package session

import (
	"context"
	"testing"
	"time"
)

func TestUnaryAllBindings(t *testing.T) {
	t.Parallel()
	for _, b := range allBindings() {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandlers()
			cli, _ := stdPair(t, b, h, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := cli.Unary(ctx, tFacet, mEcho, "hello", nil)
			if err != nil {
				t.Fatal(err)
			}
			if out != "hello" {
				t.Fatalf("got %v", out)
			}
		})
	}
}
