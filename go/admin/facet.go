package admin

import (
	"context"

	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Handler returns the handler of the sparrow.hub.admin facet. The caller
// has authorized the call (Hub Profile 10.4).
func (m *Manager) Handler() session.Handler {
	mux := methodMux{}
	h := func(id uint64, f func(ctx context.Context, in []byte) ([]byte, error)) {
		mux[id] = session.HandlerFunc(func(ctx context.Context, c *session.ServerCall) (any, error) {
			out, err := f(ctx, c.Request().Input)
			if err != nil {
				return nil, err
			}
			return nil, c.RespondRaw(ctx, out)
		})
	}
	badInput := func(err error) error { return &session.Error{Code: status.InvalidArgument, Message: err.Error()} }
	h(adminiface.MethodGet, func(ctx context.Context, in []byte) ([]byte, error) {
		return m.Get().AppendTo(nil), nil
	})
	h(adminiface.MethodValidate, func(ctx context.Context, in []byte) ([]byte, error) {
		req, err := DecodeCommitRequest(in)
		if err != nil {
			return nil, badInput(err)
		}
		ps, err := m.Validate(req.Base, req.Config)
		if err != nil {
			return nil, err
		}
		return EncodeProblems(ps), nil
	})
	h(adminiface.MethodCommit, func(ctx context.Context, in []byte) ([]byte, error) {
		req, err := DecodeCommitRequest(in)
		if err != nil {
			return nil, badInput(err)
		}
		rev, err := m.Commit(req)
		if err != nil {
			return nil, err
		}
		return cbor.AppendUint(nil, rev), nil
	})
	h(adminiface.MethodConfirm, func(ctx context.Context, in []byte) ([]byte, error) {
		n, err := DecodeUint(in)
		if err != nil {
			return nil, badInput(err)
		}
		if err := m.Confirm(n); err != nil {
			return nil, err
		}
		return cbor.Null, nil
	})
	h(adminiface.MethodRollback, func(ctx context.Context, in []byte) ([]byte, error) {
		n, err := DecodeUint(in)
		if err != nil {
			return nil, badInput(err)
		}
		rev, err := m.Rollback(n)
		if err != nil {
			return nil, err
		}
		return cbor.AppendUint(nil, rev), nil
	})
	h(adminiface.MethodSetSecret, func(ctx context.Context, in []byte) ([]byte, error) {
		name, value, err := DecodeSecret(in)
		if err != nil {
			return nil, badInput(err)
		}
		if err := m.SetSecret(name, value); err != nil {
			return nil, err
		}
		return cbor.Null, nil
	})
	h(adminiface.MethodDeleteSecret, func(ctx context.Context, in []byte) ([]byte, error) {
		name, err := DecodeText(in)
		if err != nil {
			return nil, badInput(err)
		}
		if err := m.DeleteSecret(name); err != nil {
			return nil, err
		}
		return cbor.Null, nil
	})
	h(adminiface.MethodListSecrets, func(ctx context.Context, in []byte) ([]byte, error) {
		return EncodeStrings(m.ListSecrets()), nil
	})
	mux[adminiface.MethodWatch] = session.HandlerFunc(m.serveWatch)
	return mux
}

// methodMux routes by method ID, whatever facet ID the hub gave the facet.
type methodMux map[uint64]session.Handler

func (mm methodMux) ServeCall(ctx context.Context, c *session.ServerCall) {
	h := mm[c.MethodID()]
	if h == nil {
		if !c.Notification() {
			_ = c.Fail(session.Errorf(status.Unimplemented, "sparrow.hub.admin has no method %d", c.MethodID()))
		}
		return
	}
	h.ServeCall(ctx, c)
}

func (m *Manager) serveWatch(ctx context.Context, c *session.ServerCall) (any, error) {
	events, lagged, cancel := m.Watch()
	defer cancel()
	for {
		select {
		case b, ok := <-events:
			if !ok {
				if lagged() {
					return nil, &session.Error{Code: status.ResourceExhausted, Message: "the watch fell too far behind; start a new one"}
				}
				return nil, nil
			}
			if err := c.SendRaw(ctx, (&wire.Item{Value: b}).AppendTo(nil)); err != nil {
				return nil, err
			}
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
}
