package admin

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
)

// Applier switches the hub to a document (section 2.2). Apply is called
// once at start with the persisted document and then after every change,
// one call at a time, in revision order. It must return promptly and
// reconcile in the background; it may call Manager.NodeEvent, but no other
// Manager method.
type Applier interface {
	Apply(cfg *Config, revision uint64)
}

// Options configure a Manager.
type Options struct {
	Store *Store
	// Clock drives confirmation deadlines; nil is the wall clock.
	Clock session.Clock
	// Extension validates hub-specific extensions (see ValidateEnv); nil
	// supports none.
	Extension func(node, key string, value []byte) error
	// WatchQueue is how many events a watcher may fall behind before it is
	// ended with resource_exhausted (section 4); default 256.
	WatchQueue int
	Logger     *slog.Logger
}

// Files of the data directory (section 2.4).
const (
	fileState     = "state.cbor"   // [revision, document]: the last confirmed document
	fileHighWater = "highwater"    // the highest revision handed out
	filePending   = "pending.cbor" // [revision]: a commit is pending
	dirSecrets    = "secrets"
)

// Manager holds the administration state: the applied document and its
// revision, the pending commit, stored secrets, and watchers.
type Manager struct {
	o     Options
	store *Store
	clock session.Clock
	log   *slog.Logger

	opMu    sync.Mutex // serializes changes of the applied document
	applier Applier

	mu           sync.Mutex
	rev          uint64
	doc          *Config
	state        RevisionState
	confirmedRev uint64
	confirmedDoc *Config // the rollback target while pending
	hw           uint64
	deadline     time.Time
	timer        session.Timer
	secrets      map[string][]byte
	nodes        map[string]NodeEvent
	watchers     map[*watcher]struct{}
}

// NewManager opens the persisted state. A commit that was pending when the
// hub stopped is rolled back: its rollback target becomes the next
// revision, already confirmed (section 2.3).
func NewManager(o Options) (*Manager, error) {
	if o.Store == nil {
		return nil, errors.New("admin: a Store is required")
	}
	if o.WatchQueue <= 0 {
		o.WatchQueue = 256
	}
	m := &Manager{o: o, store: o.Store, clock: o.Clock, log: o.Logger, doc: EmptyConfig(), state: Confirmed,
		secrets: map[string][]byte{}, nodes: map[string]NodeEvent{}, watchers: map[*watcher]struct{}{}}
	if m.clock == nil {
		m.clock = session.RealClock{}
	}
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) load() error {
	s := m.store
	if b, err := s.Read(fileState); err == nil {
		rev, doc, err := decodeState(b)
		if err != nil {
			return fmt.Errorf("admin: %s: %w", fileState, err)
		}
		m.rev, m.doc = rev, doc
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.confirmedRev, m.confirmedDoc = m.rev, m.doc
	m.hw = m.rev
	if b, err := s.Read(fileHighWater); err == nil {
		hw, err := DecodeUint(b)
		if err != nil {
			return fmt.Errorf("admin: %s: %w", fileHighWater, err)
		}
		m.hw = max(hw, m.rev)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	names, err := s.List(dirSecrets)
	if err != nil {
		return err
	}
	for _, n := range names {
		v, err := s.Read(dirSecrets + "/" + n)
		if err != nil {
			return err
		}
		m.secrets[n] = v
	}
	if b, err := s.Read(filePending); err == nil {
		p, err := DecodeUint(b)
		if err == nil && p > m.rev {
			// Restart while a commit was pending: roll back (2.3).
			rev := m.hw + 1
			if err := m.persistHighWater(rev); err != nil {
				return err
			}
			if err := m.persistState(rev, m.doc); err != nil {
				return err
			}
			m.log.Info("rolled back a commit pending at restart", "pending", p, "revision", rev)
			m.rev, m.confirmedRev = rev, rev
		}
		if err := s.Remove(filePending); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func encodeState(rev uint64, doc *Config) []byte {
	b := cbor.AppendArrayHead(nil, 2)
	b = cbor.AppendUint(b, rev)
	return doc.AppendTo(b)
}

func decodeState(b []byte) (uint64, *Config, error) {
	var rev uint64
	var doc *Config
	err := decodeWith(b, func(r *dec) {
		if r.array() != 2 && r.err == nil {
			r.fail("state is [revision, document]")
			return
		}
		rev = r.uint()
		doc = r.config()
	})
	return rev, doc, err
}

func (m *Manager) persistHighWater(hw uint64) error {
	if err := m.store.Write(fileHighWater, cbor.AppendUint(nil, hw)); err != nil {
		return err
	}
	m.hw = hw
	return nil
}

func (m *Manager) persistState(rev uint64, doc *Config) error {
	return m.store.Write(fileState, encodeState(rev, doc))
}

// Start applies the current document and makes the manager call a on every
// later change.
func (m *Manager) Start(a Applier) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	m.applier = a
	doc, rev := m.doc, m.rev
	m.mu.Unlock()
	a.Apply(doc.Clone(), rev)
}

func (m *Manager) apply(doc *Config, rev uint64) {
	if m.applier != nil {
		m.applier.Apply(doc.Clone(), rev)
	}
}

// Applied returns the applied revision, document and state.
func (m *Manager) Applied() (uint64, *Config, RevisionState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rev, m.doc.Clone(), m.state
}

// HighWater returns the highest revision handed out.
func (m *Manager) HighWater() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hw
}

// SecretValue returns a stored secret's value.
func (m *Manager) SecretValue(name string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.secrets[name]
	return v, ok
}

func (m *Manager) env() ValidateEnv {
	return ValidateEnv{
		SecretExists: func(n string) bool { _, ok := m.SecretValue(n); return ok },
		SecretValue:  m.SecretValue,
		Extension:    m.o.Extension,
	}
}

// ValidateDoc validates a document without the revision check.
func (m *Manager) ValidateDoc(c *Config) []Problem { return Validate(c, m.env()) }

func errAborted(msg string) error { return &session.Error{Code: status.Aborted, Message: msg} }
func errNotFound(n uint64) error {
	return &session.Error{Code: status.NotFound, Message: fmt.Sprintf("revision %d is not current", n)}
}

func (m *Manager) confirmInLocked() *uint64 {
	if m.state != Pending {
		return nil
	}
	left := m.deadline.Sub(m.clock.Now()).Milliseconds()
	if left < 0 {
		left = 0
	}
	v := uint64(left)
	return &v
}

// Get returns the applied snapshot.
func (m *Manager) Get() *Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &Snapshot{Revision: m.rev, Config: m.doc.Clone(), State: m.state, ConfirmInMs: m.confirmInLocked()}
}

// Validate validates a document against the current revision: a stale
// base fails with aborted.
func (m *Manager) Validate(base uint64, c *Config) ([]Problem, error) {
	m.mu.Lock()
	rev := m.rev
	m.mu.Unlock()
	if base != rev {
		return nil, errAborted(fmt.Sprintf("base revision %d is not current (%d)", base, rev))
	}
	return m.ValidateDoc(c), nil
}

// Commit validates and applies a document (sections 2, 2.2, 2.3).
func (m *Manager) Commit(req *CommitRequest) (uint64, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	if m.state != Pending && req.Config.Equal(m.doc) {
		rev := m.rev
		m.mu.Unlock()
		return rev, nil
	}
	if m.state == Pending {
		rev := m.rev
		m.mu.Unlock()
		return 0, errAborted(fmt.Sprintf("revision %d is pending confirmation", rev))
	}
	if req.Base != m.rev {
		rev := m.rev
		m.mu.Unlock()
		return 0, errAborted(fmt.Sprintf("base revision %d is not current (%d)", req.Base, rev))
	}
	m.mu.Unlock()
	if ps := m.ValidateDoc(req.Config); len(ps) > 0 {
		return 0, &session.Error{Code: status.FailedPrecondition, Message: fmt.Sprintf("the document is invalid: %d problem(s), first %v", len(ps), ps[0]), Details: ProblemsDetails(ps)}
	}
	doc := req.Config.Clone()
	m.mu.Lock()
	rev := m.hw + 1
	// The high-water mark is recorded before commit returns (2.4).
	if err := m.persistHighWater(rev); err != nil {
		m.mu.Unlock()
		return 0, &session.Error{Code: status.Internal, Message: "cannot persist the revision: " + err.Error()}
	}
	if req.ConfirmWithinMs == 0 {
		if err := m.persistState(rev, doc); err != nil {
			m.mu.Unlock()
			return 0, &session.Error{Code: status.Internal, Message: "cannot persist the document: " + err.Error()}
		}
		m.rev, m.doc, m.state = rev, doc, Confirmed
		m.confirmedRev, m.confirmedDoc = rev, doc
		m.publishLocked(&Event{Revision: &RevisionEvent{Revision: rev, State: Confirmed}})
	} else {
		// A pending commit is never persisted as confirmed: only a marker,
		// so a restart rolls it back (2.3, 2.4).
		if err := m.store.Write(filePending, cbor.AppendUint(nil, rev)); err != nil {
			m.mu.Unlock()
			return 0, &session.Error{Code: status.Internal, Message: "cannot persist the pending marker: " + err.Error()}
		}
		m.rev, m.doc, m.state = rev, doc, Pending
		m.deadline = m.clock.Now().Add(time.Duration(req.ConfirmWithinMs) * time.Millisecond)
		m.timer = m.clock.AfterFunc(time.Duration(req.ConfirmWithinMs)*time.Millisecond, func() { m.deadlinePassed(rev) })
		m.publishLocked(&Event{Revision: &RevisionEvent{Revision: rev, State: Pending, ConfirmInMs: m.confirmInLocked()}})
	}
	m.mu.Unlock()
	m.apply(doc, rev)
	return rev, nil
}

func (m *Manager) deadlinePassed(rev uint64) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	if m.rev != rev || m.state != Pending {
		m.mu.Unlock()
		return
	}
	doc, nrev, err := m.rollbackLocked()
	m.mu.Unlock()
	if err != nil {
		m.log.Error("rollback at the deadline failed", "err", err)
		return
	}
	m.log.Info("commit not confirmed in time: rolled back", "revision", rev, "new", nrev)
	m.apply(doc, nrev)
}

// rollbackLocked applies the rollback target as the next revision, already
// confirmed (2.3). mu and opMu are held.
func (m *Manager) rollbackLocked() (*Config, uint64, error) {
	pending := m.rev
	rev := m.hw + 1
	if err := m.persistHighWater(rev); err != nil {
		return nil, 0, err
	}
	if err := m.persistState(rev, m.confirmedDoc); err != nil {
		return nil, 0, err
	}
	if err := m.store.Remove(filePending); err != nil {
		return nil, 0, err
	}
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.rev, m.doc, m.state = rev, m.confirmedDoc, Confirmed
	m.confirmedRev = rev
	m.publishLocked(&Event{Revision: &RevisionEvent{Revision: pending, State: RolledBack}})
	m.publishLocked(&Event{Revision: &RevisionEvent{Revision: rev, State: Confirmed}})
	return m.doc, rev, nil
}

// Confirm confirms revision n (2.3).
func (m *Manager) Confirm(n uint64) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	if m.rev != n {
		m.mu.Unlock()
		return errNotFound(n)
	}
	if m.state == Confirmed {
		m.mu.Unlock()
		return nil
	}
	if !m.clock.Now().Before(m.deadline) {
		// The deadline has passed; its timer has not run yet. The hub
		// decides atomically at the deadline: roll back now.
		doc, nrev, err := m.rollbackLocked()
		m.mu.Unlock()
		if err == nil {
			m.apply(doc, nrev)
		}
		return errNotFound(n)
	}
	if err := m.persistState(n, m.doc); err != nil {
		m.mu.Unlock()
		return &session.Error{Code: status.Internal, Message: "cannot persist the document: " + err.Error()}
	}
	if err := m.store.Remove(filePending); err != nil {
		m.log.Warn("cannot remove the pending marker", "err", err)
	}
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.state = Confirmed
	m.confirmedRev, m.confirmedDoc = n, m.doc
	m.publishLocked(&Event{Revision: &RevisionEvent{Revision: n, State: Confirmed}})
	m.mu.Unlock()
	return nil
}

// Rollback rolls the pending revision n back at once and returns the new
// revision (2.3).
func (m *Manager) Rollback(n uint64) (uint64, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	if m.rev != n || m.state != Pending {
		m.mu.Unlock()
		return 0, errNotFound(n)
	}
	doc, rev, err := m.rollbackLocked()
	m.mu.Unlock()
	if err != nil {
		return 0, &session.Error{Code: status.Internal, Message: "rollback failed: " + err.Error()}
	}
	m.apply(doc, rev)
	return rev, nil
}

// referencedLocked reports whether the applied document or, while a commit
// is pending, its rollback target refers to a secret (2.1).
func (m *Manager) referencedLocked(secret string) bool {
	docs := []*Config{m.doc}
	if m.state == Pending {
		docs = append(docs, m.confirmedDoc)
	}
	for _, d := range docs {
		if References(d)[secret] {
			return true
		}
	}
	return false
}

// SetSecret stores a secret under a new name (2.1).
func (m *Manager) SetSecret(name string, value []byte) error {
	if !ValidSecretName(name) {
		return &session.Error{Code: status.InvalidArgument, Message: fmt.Sprintf("secret name %q does not follow the node-ID grammar", name)}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[name]; ok {
		return &session.Error{Code: status.AlreadyExists, Message: fmt.Sprintf("secret %q exists; store a new name to rotate it", name)}
	}
	if err := m.store.Write(dirSecrets+"/"+name, value); err != nil {
		return &session.Error{Code: status.Internal, Message: err.Error()}
	}
	m.secrets[name] = append([]byte{}, value...)
	return nil
}

// DeleteSecret deletes a secret that nothing refers to.
func (m *Manager) DeleteSecret(name string) error {
	m.opMu.Lock() // not while a commit is being validated
	defer m.opMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[name]; !ok {
		return nil
	}
	if m.referencedLocked(name) {
		return &session.Error{Code: status.FailedPrecondition, Message: fmt.Sprintf("secret %q is still referenced", name)}
	}
	if err := m.store.Remove(dirSecrets + "/" + name); err != nil {
		return &session.Error{Code: status.Internal, Message: err.Error()}
	}
	delete(m.secrets, name)
	return nil
}

// ListSecrets returns the secret names.
func (m *Manager) ListSecrets() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.secrets))
	for n := range m.secrets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// NodeEvent records a node's state and sends it to every watcher (section
// 4). A Removed node is reported once and forgotten.
func (m *Manager) NodeEvent(ev NodeEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.nodes[ev.Node]; ok && old.State == ev.State && old.Revision == ev.Revision && strPtrEq(old.Message, ev.Message) {
		return
	}
	if ev.State == Removed {
		// One removed event, and the node is not reported again (4).
		if _, ok := m.nodes[ev.Node]; !ok {
			return
		}
		delete(m.nodes, ev.Node)
	} else {
		m.nodes[ev.Node] = ev
	}
	e := ev
	m.publishLocked(&Event{Node: &e})
}

// NodeStates returns the last state of every node.
func (m *Manager) NodeStates() map[string]NodeEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]NodeEvent, len(m.nodes))
	for k, v := range m.nodes {
		out[k] = v
	}
	return out
}

func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ---------------------------------------------------------------------------
// Watch
// ---------------------------------------------------------------------------

type watcher struct {
	ch     chan []byte
	lagged bool
	done   chan struct{}
}

// Watch subscribes to the event stream: the first event is a full
// Snapshot, followed by the current state of every node (so a new watcher
// knows them), then every RevisionEvent and NodeEvent in order. The
// returned channel is closed when the watcher falls more than WatchQueue
// events behind (lagged() then reports true) or cancel is called.
func (m *Manager) Watch() (events <-chan []byte, lagged func() bool, cancel func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := &watcher{ch: make(chan []byte, m.o.WatchQueue+len(m.nodes)+1), done: make(chan struct{})}
	snap := &Event{Snapshot: &Snapshot{Revision: m.rev, Config: m.doc.Clone(), State: m.state, ConfirmInMs: m.confirmInLocked()}}
	w.ch <- snap.Encode()
	ids := make([]string, 0, len(m.nodes))
	for id := range m.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ev := m.nodes[id]
		w.ch <- (&Event{Node: &ev}).Encode()
	}
	m.watchers[w] = struct{}{}
	var once sync.Once
	cancel = func() {
		once.Do(func() {
			m.mu.Lock()
			if _, ok := m.watchers[w]; ok {
				delete(m.watchers, w)
				close(w.ch)
			}
			m.mu.Unlock()
		})
	}
	lagged = func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return w.lagged
	}
	return w.ch, lagged, cancel
}

func (m *Manager) publishLocked(e *Event) {
	b := e.Encode()
	for w := range m.watchers {
		select {
		case w.ch <- b:
		default:
			w.lagged = true
			delete(m.watchers, w)
			close(w.ch)
		}
	}
}

// Watchers returns the number of active watchers (for tests).
func (m *Manager) Watchers() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.watchers)
}
