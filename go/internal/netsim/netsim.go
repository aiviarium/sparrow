// Package netsim puts bad networks between the peers of a test: a UDP proxy
// (for QUIC / WebTransport) that drops, delays, reorders, duplicates and
// black-holes datagrams and can rebind its upstream port like a NAT, and a
// TCP proxy (for WebSocket) that splits writes into tiny chunks, delays
// them, stalls and resets connections mid-stream.
//
// Random faults come from a seeded generator, so the fault decisions of a
// run can be repeated: Seed returns the seed a test should use and logs it
// ($NETSIM_SEED overrides it). Goroutine scheduling and the kernel still
// vary between runs, so the packets a decision applies to can differ.
package netsim

import (
	"errors"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Seed returns the fault seed of a test: $NETSIM_SEED if set, else a hash
// of the test's name, so every run of a test makes the same decisions. It
// logs the seed.
func Seed(t testing.TB) uint64 {
	if s := os.Getenv("NETSIM_SEED"); s != "" {
		if v, err := strconv.ParseUint(s, 0, 64); err == nil {
			t.Logf("netsim seed %d (NETSIM_SEED)", v)
			return v
		}
	}
	h := fnv.New64a()
	h.Write([]byte(t.Name()))
	v := h.Sum64()
	t.Logf("netsim seed %d (rerun with NETSIM_SEED=%d)", v, v)
	return v
}

// rng is a goroutine-safe seeded generator.
type rng struct {
	mu sync.Mutex
	r  *rand.Rand
}

func newRNG(seed uint64) *rng { return &rng{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))} }

func (g *rng) float() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.r.Float64()
}

func (g *rng) intn(n int) int {
	if n <= 1 {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.r.IntN(n)
}

func (g *rng) jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return time.Duration(g.r.Int64N(int64(d) + 1))
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

// Faults are the datagram faults of a UDPProxy, applied to each direction.
type Faults struct {
	// Drop, Duplicate and Reorder are probabilities per datagram. A
	// reordered datagram is held back by ReorderDelay (default 5 ms) on
	// top of its latency, so later ones overtake it.
	Drop, Duplicate, Reorder float64
	ReorderDelay             time.Duration
	// Latency is added to every datagram, plus up to Jitter more.
	Latency, Jitter time.Duration
	// BlackHole drops everything: the link is dead.
	BlackHole bool
}

// UDPStats count what a UDPProxy did.
type UDPStats struct {
	Forwarded, Dropped, Duplicated, Reordered int64
}

// UDPProxy forwards datagrams between clients and one target address. Each
// client gets its own upstream socket, as behind a NAT.
type UDPProxy struct {
	t      testing.TB
	ln     *net.UDPConn
	target *net.UDPAddr
	rng    *rng

	mu     sync.Mutex
	faults [2]Faults // by Direction
	flows  map[string]*flow
	closed bool

	forwarded, dropped, duplicated, reordered atomic.Int64
	wg                                        sync.WaitGroup
}

type flow struct {
	client *net.UDPAddr
	up     *net.UDPConn
}

// NewUDPProxy listens on 127.0.0.1 and forwards to target. It is closed
// when the test ends.
func NewUDPProxy(t testing.TB, target string, seed uint64) *UDPProxy {
	t.Helper()
	ta, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &UDPProxy{t: t, ln: ln, target: ta, rng: newRNG(seed), flows: map[string]*flow{}}
	p.wg.Add(1)
	go p.fromClients()
	t.Cleanup(p.Close)
	return p
}

// Addr is the address clients send to.
func (p *UDPProxy) Addr() string { return p.ln.LocalAddr().String() }

// Direction is one way through a proxy.
type Direction int

const (
	ToTarget   Direction = iota // from the clients to the target
	FromTarget                  // from the target back to the clients
)

// SetFaults replaces the faults of both directions.
func (p *UDPProxy) SetFaults(f Faults) {
	p.mu.Lock()
	p.faults = [2]Faults{f, f}
	p.mu.Unlock()
}

// SetFaultsDir replaces the faults of one direction.
func (p *UDPProxy) SetFaultsDir(d Direction, f Faults) {
	p.mu.Lock()
	p.faults[d] = f
	p.mu.Unlock()
}

// SetBlackHole turns the dead link on or off in both directions, keeping
// the other faults.
func (p *UDPProxy) SetBlackHole(on bool) {
	p.mu.Lock()
	p.faults[ToTarget].BlackHole = on
	p.faults[FromTarget].BlackHole = on
	p.mu.Unlock()
}

// Stats returns the counters.
func (p *UDPProxy) Stats() UDPStats {
	return UDPStats{Forwarded: p.forwarded.Load(), Dropped: p.dropped.Load(),
		Duplicated: p.duplicated.Load(), Reordered: p.reordered.Load()}
}

// Rebind gives every client a new upstream socket, as a NAT that lost its
// mapping: the target sees the same peers arrive from new ports.
func (p *UDPProxy) Rebind() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.flows {
		up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			p.t.Errorf("netsim: rebind: %v", err)
			return
		}
		old := f.up
		f.up = up
		_ = old.Close()
		p.wg.Add(1)
		go p.fromTarget(f, up)
	}
}

// Close stops the proxy and waits for its goroutines.
func (p *UDPProxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	_ = p.ln.Close()
	for _, f := range p.flows {
		_ = f.up.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

// deliver applies the faults to one datagram and sends it (now or later).
func (p *UDPProxy) deliver(dir Direction, b []byte, send func([]byte)) {
	p.mu.Lock()
	f := p.faults[dir]
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return
	}
	if f.BlackHole || (f.Drop > 0 && p.rng.float() < f.Drop) {
		p.dropped.Add(1)
		return
	}
	n := 1
	if f.Duplicate > 0 && p.rng.float() < f.Duplicate {
		n = 2
		p.duplicated.Add(1)
	}
	for i := 0; i < n; i++ {
		d := f.Latency + p.rng.jitter(f.Jitter)
		if f.Reorder > 0 && p.rng.float() < f.Reorder {
			rd := f.ReorderDelay
			if rd <= 0 {
				rd = 5 * time.Millisecond
			}
			d += rd
			p.reordered.Add(1)
		}
		p.forwarded.Add(1)
		if d <= 0 {
			send(b)
			continue
		}
		c := append([]byte(nil), b...)
		time.AfterFunc(d, func() { send(c) })
	}
}

func (p *UDPProxy) fromClients() {
	defer p.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := p.ln.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.mu.Lock()
		f, ok := p.flows[from.String()]
		if !ok && !p.closed {
			up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				p.mu.Unlock()
				continue
			}
			f = &flow{client: from, up: up}
			p.flows[from.String()] = f
			p.wg.Add(1)
			go p.fromTarget(f, up)
		}
		p.mu.Unlock()
		if f == nil {
			continue
		}
		p.deliver(ToTarget, buf[:n], func(b []byte) {
			p.mu.Lock()
			up := f.up
			p.mu.Unlock()
			_, _ = up.WriteToUDP(b, p.target)
		})
	}
}

func (p *UDPProxy) fromTarget(f *flow, up *net.UDPConn) {
	defer p.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, _, err := up.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p.deliver(FromTarget, buf[:n], func(b []byte) { _, _ = p.ln.WriteToUDP(b, f.client) })
	}
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

// TCPFaults are the stream faults of a TCPProxy, applied to each
// direction.
type TCPFaults struct {
	// MaxChunk splits every write into pieces of 1 to MaxChunk bytes (0:
	// forward what was read at once).
	MaxChunk int
	// ChunkDelay plus up to ChunkJitter is waited before a piece, with
	// probability DelayRate (0 means every piece).
	ChunkDelay, ChunkJitter time.Duration
	DelayRate               float64
	// ResetAfter resets a connection (RST to both sides) once that many
	// bytes have crossed it, both directions counted: mid-frame,
	// mid-message. 0 never resets.
	ResetAfter int64
}

// TCPProxy forwards connections to one target address.
type TCPProxy struct {
	t      testing.TB
	ln     net.Listener
	target string
	rng    *rng

	mu      sync.Mutex
	faults  TCPFaults
	stalled bool
	resume  chan struct{} // closed when a stall ends
	conns   map[*tcpPair]struct{}
	closed  bool
	resets  atomic.Int64
	wg      sync.WaitGroup
}

type tcpPair struct {
	client, server *net.TCPConn
	bytes          atomic.Int64 // forwarded, both directions
	once           sync.Once
}

// NewTCPProxy listens on 127.0.0.1 and forwards to target. It is closed
// when the test ends.
func NewTCPProxy(t testing.TB, target string, seed uint64) *TCPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &TCPProxy{t: t, ln: ln, target: target, rng: newRNG(seed), conns: map[*tcpPair]struct{}{}, resume: make(chan struct{})}
	close(p.resume)
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(p.Close)
	return p
}

// Addr is the address clients connect to.
func (p *TCPProxy) Addr() string { return p.ln.Addr().String() }

// SetFaults replaces the faults.
func (p *TCPProxy) SetFaults(f TCPFaults) {
	p.mu.Lock()
	p.faults = f
	p.mu.Unlock()
}

// Stall stops forwarding in both directions (the bytes stay queued in the
// proxy and the kernel) until Resume.
func (p *TCPProxy) Stall() {
	p.mu.Lock()
	if !p.stalled {
		p.stalled = true
		p.resume = make(chan struct{})
	}
	p.mu.Unlock()
}

// Resume ends a stall.
func (p *TCPProxy) Resume() {
	p.mu.Lock()
	if p.stalled {
		p.stalled = false
		close(p.resume)
	}
	p.mu.Unlock()
}

// Resets is the number of connections the proxy reset.
func (p *TCPProxy) Resets() int64 { return p.resets.Load() }

// ResetAll resets every open connection now.
func (p *TCPProxy) ResetAll() {
	p.mu.Lock()
	cs := make([]*tcpPair, 0, len(p.conns))
	for c := range p.conns {
		cs = append(cs, c)
	}
	p.mu.Unlock()
	for _, c := range cs {
		p.reset(c)
	}
}

func (p *TCPProxy) reset(c *tcpPair) {
	c.once.Do(func() {
		p.resets.Add(1)
		for _, k := range []*net.TCPConn{c.client, c.server} {
			_ = k.SetLinger(0) // close sends RST
			_ = k.Close()
		}
		p.mu.Lock()
		delete(p.conns, c)
		p.mu.Unlock()
	})
}

// Close stops the proxy, resets its connections and waits for its
// goroutines.
func (p *TCPProxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	_ = p.ln.Close()
	p.mu.Unlock()
	p.Resume()
	p.ResetAll()
	p.wg.Wait()
}

func (p *TCPProxy) accept() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		s, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		pair := &tcpPair{client: c.(*net.TCPConn), server: s.(*net.TCPConn)}
		_ = pair.client.SetNoDelay(true)
		_ = pair.server.SetNoDelay(true)
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = c.Close()
			_ = s.Close()
			return
		}
		p.conns[pair] = struct{}{}
		p.wg.Add(2)
		p.mu.Unlock()
		go p.pipe(pair, pair.client, pair.server)
		go p.pipe(pair, pair.server, pair.client)
	}
}

func (p *TCPProxy) wait() bool {
	p.mu.Lock()
	ch, closed := p.resume, p.closed
	p.mu.Unlock()
	<-ch
	return !closed
}

func (p *TCPProxy) pipe(c *tcpPair, from, to *net.TCPConn) {
	defer p.wg.Done()
	buf := make([]byte, 32<<10)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			if !p.forward(c, to, buf[:n]) {
				p.reset(c)
				return
			}
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.reset(c)
				return
			}
			_ = to.CloseWrite() // a clean end: pass the half-close on
			return
		}
	}
}

// forward writes b to the other side under the faults; false means the
// connection is to be reset.
func (p *TCPProxy) forward(c *tcpPair, to *net.TCPConn, b []byte) bool {
	for len(b) > 0 {
		if !p.wait() {
			return false
		}
		p.mu.Lock()
		f := p.faults
		p.mu.Unlock()
		k := len(b)
		if f.MaxChunk > 0 {
			k = 1 + p.rng.intn(f.MaxChunk)
			if k > len(b) {
				k = len(b)
			}
		}
		if f.ResetAfter > 0 {
			left := f.ResetAfter - c.bytes.Load()
			if left <= 0 {
				return false
			}
			if int64(k) > left {
				k = int(left)
			}
		}
		if f.DelayRate == 0 || p.rng.float() < f.DelayRate {
			if d := f.ChunkDelay + p.rng.jitter(f.ChunkJitter); d > 0 {
				time.Sleep(d) // the simulated link's delay
			}
		}
		if _, err := to.Write(b[:k]); err != nil {
			return false
		}
		c.bytes.Add(int64(k))
		b = b[k:]
	}
	return true
}
