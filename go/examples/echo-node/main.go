// Command echo-node is an example Sparrow node. By default it speaks on its
// standard input and output, as a process a hub starts (sections 4.7 and
// 10.2); with -url it dials a hub over WebTransport or WebSocket instead.
// Logs go to standard error.
//
// It publishes one facet named after the node ID (default "echo") with a
// service Echo:
//
//	echo(string) -> string                 unary, idempotent
//	reverse(string) -> string              unary
//	count(uint) -> stream uint             1..n, then End
//	sum(stream uint) -> uint
//	chat(stream string) -> stream string   echoes each message
//	upload(bytes stream) -> uint           number of bytes received
//	download(uint) -> bytes stream         n bytes
//	whoami(unit) -> string                 the principal the hub named
//	log(string)                            notification, written to stderr
//	fail(string) -> unit                   fails with the error "echo_failed"
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func main() {
	id := flag.String("id", "echo", "node ID; the facet is named after it")
	url := flag.String("url", "", "hub URL (https:// WebTransport, ws:// or wss:// WebSocket); empty for stdio")
	credential := flag.String("credential", "", "link credential, sent as [\"link\", credential] when dialing")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	opts := node.Options{ID: *id, Logger: log}
	if *credential != "" {
		opts.Auth = &wire.Auth{Scheme: "link", Credentials: cbor.AppendText(nil, *credential)}
	}
	n := node.New(opts)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if _, err := n.Add(ctx, Facet(*id, n, log)); err != nil {
		log.Error("add facet", "err", err)
		os.Exit(1)
	}
	var err error
	if *url == "" {
		err = n.RunStdio(ctx)
	} else if err = n.Dial(ctx, *url, node.DialOptions{}); err == nil {
		err = n.Wait(ctx)
	}
	if err != nil && err != context.Canceled {
		log.Error("session ended", "err", err)
		os.Exit(1)
	}
}

// Facet builds the echo facet for node n.
func Facet(name string, n *node.Node, log *slog.Logger) *node.Facet {
	b := node.NewFacet(name, "1.0.0")
	failed := b.ErrorCode("echo_failed")
	svc := b.Service("Echo")
	svc.Method("echo", node.String, node.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		return c.Input()
	}, node.Idempotent())
	svc.Method("reverse", node.String, node.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		r := []rune(in.(string))
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r), nil
	})
	svc.Method("count", node.Uint, node.Stream(node.Uint), func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		for i := uint64(1); i <= in.(uint64); i++ {
			if err := c.Send(ctx, i); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	svc.Method("sum", node.Stream(node.Uint), node.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		var sum uint64
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return sum, nil
			}
			if err != nil {
				return nil, err
			}
			sum += v.(uint64)
		}
	})
	svc.Method("chat", node.Stream(node.String), node.Stream(node.String), func(ctx context.Context, c *session.ServerCall) (any, error) {
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			if err := c.Send(ctx, v); err != nil {
				return nil, err
			}
		}
	})
	svc.Method("upload", node.ByteStream(), node.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		k, err := io.Copy(io.Discard, c.Reader(0))
		return uint64(k), err
	})
	svc.Method("download", node.Uint, node.ByteStream(), func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		w := c.Writer(ctx, 0)
		chunk := []byte(strings.Repeat("sparrow!", 512))
		left := int(in.(uint64))
		for left > 0 {
			k := min(left, len(chunk))
			if _, err := w.Write(chunk[:k]); err != nil {
				return nil, err
			}
			left -= k
		}
		return nil, w.Close()
	})
	svc.Method("whoami", node.Unit, node.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		p, ok := n.Principal(c)
		if !ok {
			return "", nil
		}
		return p, nil
	})
	svc.Notification("log", node.String, func(ctx context.Context, c *session.ServerCall) error {
		v, err := c.Input()
		if err == nil {
			log.Info("log", "text", v)
		}
		return nil
	})
	svc.Method("fail", node.String, node.Unit, func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, _ := c.Input()
		return nil, &session.Error{Code: failed, Message: fmt.Sprint(in)}
	}, node.Errors(uint64(failed)))
	return b.MustBuild()
}
