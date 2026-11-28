package hub

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
)

func requireStress(t *testing.T) {
	t.Helper()
	if os.Getenv("SPARROW_STRESS") == "" {
		t.Skip("set SPARROW_STRESS=1 to run stress tests")
	}
}

func newFileWorker(t *testing.T, f *fixture, binding string) *nd.Node {
	t.Helper()
	b := nd.NewFacet("files", "1.0.0")
	svc := b.Service("Files")
	svc.Method("ping", nd.String, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
		return c.Input()
	}, nd.Idempotent())
	svc.Method("upload", nd.ByteStream(), nd.Uint, func(ctx context.Context, c *session.ServerCall) (any, error) {
		n, err := io.Copy(io.Discard, c.Reader(0))
		return uint64(n), err
	})
	svc.Method("download", nd.Uint, nd.ByteStream(), func(ctx context.Context, c *session.ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		w := c.Writer(ctx, 0)
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = byte(i)
		}
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
	n := nd.New(nd.Options{Auth: linkAuth("files-cred"), Logger: testLogger(t)})
	if _, err := n.Add(tctx(t), b.MustBuild()); err != nil {
		t.Fatal(err)
	}
	if err := n.Dial(tctx(t), f.url(binding), nd.DialOptions{CertHashes: [][]byte{f.certHash}}); err != nil {
		t.Fatal(err)
	}
	f.onCleanup(n.Close)
	waitNode(t, f.h, "files", true)
	return n
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), d...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(float64(len(cp)-1) * p)
	return cp[idx]
}

// TestStressLargeFileAndConcurrentRPC streams a 64 MiB download and a 64 MiB
// upload through sparrow-hub over both WebTransport and WebSocket while firing
// concurrent small RPCs on the same session, verifying throughput, responsive
// RPC latency, and bounded memory (no full-file buffering in the hub).
func TestStressLargeFileAndConcurrentRPC(t *testing.T) {
	requireStress(t)
	const fileSize = 64 << 20 // 64 MiB

	for _, binding := range transports {
		t.Run(binding, func(t *testing.T) {
			f := newFixture(t, nil)
			f.secret("files-1", "files-cred")
			f.commit(&admin.Config{
				Nodes:      map[string]*admin.NodeConfig{"files": dialInConfig("files-1")},
				Extensions: policy(grant("user:alice", "files", "use")),
			})
			_ = newFileWorker(t, f, binding)
			cli := f.client(binding, aliceToken)
			waitFacet(t, cli, "files")

			runtime.GC()
			var beforeMem runtime.MemStats
			runtime.ReadMemStats(&beforeMem)
			baseGoroutines := runtime.NumGoroutine()

			// Helper: run concurrent ping RPCs while fn() executes.
			runWithPings := func(label string, fn func() error) {
				t.Helper()
				ctx, cancel := context.WithCancel(tctx(t))
				defer cancel()
				var (
					mu        sync.Mutex
					latencies []time.Duration
					pingErr   error
					wg        sync.WaitGroup
				)
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; ctx.Err() == nil; i++ {
						t0 := time.Now()
						v, err := cli.Call(ctx, "files", "ping", fmt.Sprintf("%s-%d", label, i))
						if err != nil {
							if ctx.Err() != nil {
								return
							}
							mu.Lock()
							if pingErr == nil {
								pingErr = err
							}
							mu.Unlock()
							return
						}
						if v != fmt.Sprintf("%s-%d", label, i) {
							mu.Lock()
							if pingErr == nil {
								pingErr = fmt.Errorf("bad ping reply: %v", v)
							}
							mu.Unlock()
							return
						}
						mu.Lock()
						latencies = append(latencies, time.Since(t0))
						mu.Unlock()
						time.Sleep(5 * time.Millisecond)
					}
				}()

				start := time.Now()
				err := fn()
				elapsed := time.Since(start)
				cancel()
				wg.Wait()

				if err != nil {
					t.Fatalf("%s failed: %v", label, err)
				}
				if pingErr != nil {
					t.Fatalf("%s concurrent ping failed: %v", label, pingErr)
				}
				mbps := float64(fileSize) / (1024 * 1024) / elapsed.Seconds()
				t.Logf("%s/%s: 64 MiB in %v (%.1f MiB/s) | %d concurrent pings: p50=%v p95=%v max=%v",
					binding, label, elapsed.Round(time.Millisecond), mbps,
					len(latencies), percentile(latencies, 0.50), percentile(latencies, 0.95), percentile(latencies, 1.0))
			}

			// 1. 64 MiB download
			runWithPings("download", func() error {
				ctx := tctx(t)
				cc, err := cli.Open(ctx, "files", "download", uint64(fileSize), nil)
				if err != nil {
					return err
				}
				n, err := io.Copy(io.Discard, cc.Reader(0))
				if err != nil {
					return err
				}
				if err := cc.Wait(ctx); err != nil {
					return err
				}
				if n != fileSize {
					return fmt.Errorf("downloaded %d bytes, want %d", n, fileSize)
				}
				return nil
			})

			// 2. 64 MiB upload
			runWithPings("upload", func() error {
				ctx := tctx(t)
				cc, err := cli.Open(ctx, "files", "upload", nil, nil)
				if err != nil {
					return err
				}
				w := cc.Writer(ctx, 0)
				chunk := make([]byte, 64<<10)
				left := fileSize
				for left > 0 {
					k := min(left, len(chunk))
					if _, err := w.Write(chunk[:k]); err != nil {
						return err
					}
					left -= k
				}
				if err := w.Close(); err != nil {
					return err
				}
				res, err := cc.Response(ctx)
				if err != nil {
					return err
				}
				if res.(uint64) != fileSize {
					return fmt.Errorf("uploaded %v bytes, want %d", res, fileSize)
				}
				return nil
			})

			runtime.GC()
			var afterMem runtime.MemStats
			runtime.ReadMemStats(&afterMem)
			heapDelta := int64(afterMem.HeapInuse) - int64(beforeMem.HeapInuse)
			t.Logf("%s: heap delta after 128 MiB transferred = %.2f MiB, goroutines %d -> %d",
				binding, float64(heapDelta)/(1024*1024), baseGoroutines, runtime.NumGoroutine())
			if heapDelta > 32<<20 {
				t.Fatalf("%s: excessive heap growth %.2f MiB (expected streaming, not buffering)", binding, float64(heapDelta)/(1024*1024))
			}
			testutil.Eventually(t, 5*time.Second, func() bool {
				return f.h.Stats().ActiveCalls == 0
			}, "hub still has active calls: %+v", f.h.Stats())
		})
	}
}

// TestStressManyClientsAndSchemaChurn connects 40 simultaneous clients (20
// WebTransport, 20 WebSocket) issuing concurrent RPCs and 256 KiB downloads
// while the dialed-in node dynamically adds and removes facets.
func TestStressManyClientsAndSchemaChurn(t *testing.T) {
	requireStress(t)
	const numClients = 40

	creds := make([]Credential, numClients)
	for i := 0; i < numClients; i++ {
		creds[i] = Credential{
			Token:     fmt.Sprintf("tok-%d", i),
			Principal: fmt.Sprintf("user:u%d", i),
			Groups:    []string{"group:users"},
		}
	}
	f := newFixture(t, func(o *Options) {
		o.Tokens = append(o.Tokens, creds...)
	})
	f.secret("files-1", "files-cred")
	f.commit(&admin.Config{
		Nodes:      map[string]*admin.NodeConfig{"files": dialInConfig("files-1")},
		Extensions: policy(grant("group:users", "files", "use"), grant("group:users", "files.*", "use")),
	})
	worker := newFileWorker(t, f, "webtransport")

	clients := make([]*nd.Node, numClients)
	for i := 0; i < numClients; i++ {
		b := "webtransport"
		if i%2 == 1 {
			b = "websocket"
		}
		clients[i] = f.client(b, creds[i].Token)
	}
	for _, cli := range clients {
		waitFacet(t, cli, "files")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var (
		wg        sync.WaitGroup
		totalRPCs atomic.Int64
		totalMB   atomic.Int64
		errMu     sync.Mutex
		firstErr  error
	)
	recordErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	start := time.Now()
	// Background traffic from all 40 clients.
	for i, cli := range clients {
		wg.Add(1)
		go func(id int, c *nd.Node) {
			defer wg.Done()
			for round := 0; round < 5; round++ {
				v, err := c.Call(ctx, "files", "ping", fmt.Sprintf("u%d-%d", id, round))
				if err != nil {
					recordErr(fmt.Errorf("client %d ping %d: %w", id, round, err))
					return
				}
				if v != fmt.Sprintf("u%d-%d", id, round) {
					recordErr(fmt.Errorf("client %d bad reply: %v", id, v))
					return
				}
				totalRPCs.Add(1)

				cc, err := c.Open(ctx, "files", "download", uint64(256<<10), nil)
				if err != nil {
					recordErr(fmt.Errorf("client %d download open: %w", id, err))
					return
				}
				n, err := io.Copy(io.Discard, cc.Reader(0))
				if err != nil {
					recordErr(fmt.Errorf("client %d download read: %w", id, err))
					return
				}
				if err := cc.Wait(ctx); err != nil {
					recordErr(fmt.Errorf("client %d download wait: %w", id, err))
					return
				}
				if n != 256<<10 {
					recordErr(fmt.Errorf("client %d short download %d", id, n))
					return
				}
				totalMB.Add(n)
			}
		}(i, cli)
	}

	// Concurrent SchemaUpdate churn on the worker node.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k := 0; k < 6; k++ {
			name := fmt.Sprintf("files.f%d", k)
			b := nd.NewFacet(name, "1.0.0")
			b.Service("Dyn").Method("hi", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
				return name, nil
			})
			if _, err := worker.Add(ctx, b.MustBuild()); err != nil {
				recordErr(fmt.Errorf("add %s: %w", name, err))
				return
			}
			time.Sleep(30 * time.Millisecond)
			if err := worker.Remove(ctx, name); err != nil {
				recordErr(fmt.Errorf("remove %s: %w", name, err))
				return
			}
		}
		// Leave one final dynamic facet present for all clients to verify.
		b := nd.NewFacet("files.final", "1.0.0")
		b.Service("Dyn").Method("hi", nd.Unit, nd.String, func(ctx context.Context, c *session.ServerCall) (any, error) {
			return "ok", nil
		})
		if _, err := worker.Add(ctx, b.MustBuild()); err != nil {
			recordErr(fmt.Errorf("add files.final: %w", err))
		}
	}()

	wg.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	for i, cli := range clients {
		testutil.Eventually(t, 5*time.Second, func() bool {
			return cli.Session().PeerFacet("files.final") != nil
		}, "client %d did not receive files.final SchemaUpdate", i)
	}
	testutil.Eventually(t, 5*time.Second, func() bool {
		return f.h.Stats().ActiveCalls == 0
	}, "hub still has active calls: %+v", f.h.Stats())
	t.Logf("%d clients completed %d RPCs + %.1f MiB across 6 SchemaUpdate churn rounds in %v",
		numClients, totalRPCs.Load(), float64(totalMB.Load())/(1024*1024), time.Since(start).Round(time.Millisecond))
}

// TestStressCancelAndDisconnectStorm opens 32 concurrent 32 MiB downloads;
// half are cancelled mid-flight and half have their client session closed
// mid-flight. Verifies hub & node return to 0 open calls with no leaks.
func TestStressCancelAndDisconnectStorm(t *testing.T) {
	requireStress(t)
	f := newFixture(t, nil)
	f.secret("files-1", "files-cred")
	f.commit(&admin.Config{
		Nodes:      map[string]*admin.NodeConfig{"files": dialInConfig("files-1")},
		Extensions: policy(grant("user:alice", "files", "use")),
	})
	_ = newFileWorker(t, f, "webtransport")

	const total = 32
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			binding := "webtransport"
			if idx%2 == 1 {
				binding = "websocket"
			}
			cli := f.client(binding, aliceToken)
			waitFacet(t, cli, "files")
			ctx, cancel := context.WithCancel(tctx(t))
			defer cancel()
			cc, err := cli.Open(ctx, "files", "download", uint64(32<<20), nil)
			if err != nil {
				return
			}
			// Read 256 KiB so the transfer is actively streaming through the hub.
			_, _ = io.CopyN(io.Discard, cc.Reader(0), 256<<10)
			if idx < total/2 {
				_ = cc.Cancel(status.Cancelled)
				_ = cc.Wait(tctx(t))
			} else {
				_ = cli.Session().Conn().Close(status.Unavailable, "abrupt disconnect")
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && f.h.Stats().ActiveCalls != 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if st := f.h.Stats(); st.ActiveCalls != 0 {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("hub leaked active calls after cancel/disconnect storm: %+v\n--- GOROUTINES ---\n%s", st, buf[:n])
	}

	// Verify hub + node are still healthy immediately afterward.
	cli := f.client("webtransport", aliceToken)
	waitFacet(t, cli, "files")
	v, err := cli.Call(tctx(t), "files", "ping", "alive")
	if err != nil || v != "alive" {
		t.Fatalf("post-storm ping failed: %v %v", v, err)
	}
	t.Logf("32 mid-flight cancels/disconnects cleaned up cleanly; ActiveCalls=%d", f.h.Stats().ActiveCalls)
}
