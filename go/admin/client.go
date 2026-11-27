package admin

import (
	"context"
	"errors"
	"io"

	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Client calls a hub's sparrow.hub.admin facet over a session.
type Client struct {
	S       *session.Session
	FacetID uint64
}

// NewClient finds the facet named name (default sparrow.hub.admin) in the
// session's peer schema.
func NewClient(s *session.Session, name string) (*Client, error) {
	if name == "" {
		name = adminiface.Name
	}
	f := s.PeerFacet(name)
	if f == nil {
		return nil, &session.Error{Code: status.Unimplemented, Message: "the peer lists no facet " + name}
	}
	return &Client{S: s, FacetID: f.ID}, nil
}

func (c *Client) unary(ctx context.Context, method uint64, in []byte) (cbor.Raw, error) {
	if in == nil {
		in = cbor.Null
	}
	cc, err := c.S.OpenRaw(ctx, session.RawRequest{FacetID: c.FacetID, MethodID: method, Input: in}, nil)
	if err != nil {
		return nil, err
	}
	return cc.ResponseRaw(ctx)
}

// Get returns the applied snapshot.
func (c *Client) Get(ctx context.Context) (*Snapshot, error) {
	b, err := c.unary(ctx, adminiface.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	return DecodeSnapshot(b)
}

// Validate validates a document against base.
func (c *Client) Validate(ctx context.Context, base uint64, cfg *Config) ([]Problem, error) {
	b, err := c.unary(ctx, adminiface.MethodValidate, EncodeValidateRequest(base, cfg))
	if err != nil {
		return nil, err
	}
	return DecodeProblems(b)
}

// Commit commits a document and returns the new revision. For an invalid
// document the error is a *session.Error with code failed_precondition;
// ProblemsOf extracts the problems.
func (c *Client) Commit(ctx context.Context, base uint64, cfg *Config, confirmWithinMs uint64) (uint64, error) {
	b, err := c.unary(ctx, adminiface.MethodCommit, (&CommitRequest{Base: base, Config: cfg, ConfirmWithinMs: confirmWithinMs}).Encode())
	if err != nil {
		return 0, err
	}
	return DecodeUint(b)
}

// ProblemsOf returns the problems in an Error's details, if any.
func ProblemsOf(err error) []Problem {
	var e *session.Error
	if !errors.As(err, &e) || e.Details == nil {
		return nil
	}
	ps, _ := DecodeProblems(e.Details)
	return ps
}

// Confirm confirms revision n.
func (c *Client) Confirm(ctx context.Context, n uint64) error {
	_, err := c.unary(ctx, adminiface.MethodConfirm, cbor.AppendUint(nil, n))
	return err
}

// Rollback rolls back pending revision n and returns the new revision.
func (c *Client) Rollback(ctx context.Context, n uint64) (uint64, error) {
	b, err := c.unary(ctx, adminiface.MethodRollback, cbor.AppendUint(nil, n))
	if err != nil {
		return 0, err
	}
	return DecodeUint(b)
}

// SetSecret stores a secret.
func (c *Client) SetSecret(ctx context.Context, name string, value []byte) error {
	_, err := c.unary(ctx, adminiface.MethodSetSecret, EncodeSecret(name, value))
	return err
}

// DeleteSecret deletes a secret.
func (c *Client) DeleteSecret(ctx context.Context, name string) error {
	_, err := c.unary(ctx, adminiface.MethodDeleteSecret, cbor.AppendText(nil, name))
	return err
}

// ListSecrets lists secret names.
func (c *Client) ListSecrets(ctx context.Context) ([]string, error) {
	b, err := c.unary(ctx, adminiface.MethodListSecrets, nil)
	if err != nil {
		return nil, err
	}
	return DecodeStrings(b)
}

// Watcher is a running watch.
type Watcher struct {
	cc *session.ClientCall
}

// Watch starts a watch.
func (c *Client) Watch(ctx context.Context) (*Watcher, error) {
	cc, err := c.S.OpenRaw(ctx, session.RawRequest{FacetID: c.FacetID, MethodID: adminiface.MethodWatch, Input: cbor.Null}, nil)
	if err != nil {
		return nil, err
	}
	return &Watcher{cc: cc}, nil
}

// Next returns the next event; io.EOF when the hub ended the watch
// normally, or the hub's error (resource_exhausted for a lagging watcher).
func (w *Watcher) Next(ctx context.Context) (*Event, error) {
	for {
		m, err := w.cc.RecvRaw(ctx)
		if err != nil {
			return nil, err
		}
		switch x := m.Message.(type) {
		case *wire.Item:
			return DecodeEvent(x.Value)
		case *wire.End:
			return nil, io.EOF
		case *wire.Error:
			return nil, &session.Error{Code: status.Code(x.Status), Message: x.Message, Details: x.Details, Remote: true}
		}
	}
}

// Close cancels the watch.
func (w *Watcher) Close() { _ = w.cc.Cancel(status.Cancelled) }
