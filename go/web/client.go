package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/websign"
)

// Client talks to a host's Web Profile endpoints as a browser client does.
type Client struct {
	// Base is the host's origin, e.g. "https://app.example.com".
	Base string
	HTTP *http.Client
	// Authorize adds the client's normal HTTP authentication (a cookie
	// jar in HTTP works too).
	Authorize func(*http.Request)
}

// HTTPError is a non-2xx answer.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("web: HTTP %d: %s", e.Status, strings.TrimSpace(e.Body))
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) resolve(ref string) (string, error) {
	b, err := url.Parse(c.Base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

func (c *Client) do(ctx context.Context, method, ref string, body any) ([]byte, http.Header, error) {
	u, err := c.resolve(ref)
	if err != nil {
		return nil, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Authorize != nil {
		c.Authorize(req)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, resp.Header, &HTTPError{Status: resp.StatusCode, Body: string(b)}
	}
	return b, resp.Header, nil
}

// Connect posts a connect request (9.1).
func (c *Client) Connect(ctx context.Context, info ClientInfo, knownSchemaHash []byte) (*ConnectResponse, error) {
	req := ConnectRequest{Client: &info}
	if knownSchemaHash != nil {
		req.KnownSchemaHash = EncodeHash(knownSchemaHash)
	}
	b, _, err := c.do(ctx, http.MethodPost, ConnectPath, req)
	if err != nil {
		return nil, err
	}
	var r ConnectResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Refresh posts the refresh form for the endpoint the client is connected
// to and returns the new ticket (9.2).
func (c *Client) Refresh(ctx context.Context, endpoint string) (string, error) {
	req := map[string]any{"refresh": map[string]string{"endpoint": endpoint}}
	b, _, err := c.do(ctx, http.MethodPost, ConnectPath, req)
	if err != nil {
		return "", err
	}
	var r RefreshResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return "", err
	}
	if r.Ticket == "" {
		return "", errors.New("web: the refresh answer holds no ticket")
	}
	return r.Ticket, nil
}

// Schema fetches a schema resource and checks it against its hash (9.3).
func (c *Client) Schema(ctx context.Context, ref string, hash []byte) (*schema.Schema, []byte, error) {
	b, _, err := c.do(ctx, http.MethodGet, ref, nil)
	if err != nil {
		return nil, nil, err
	}
	sc, err := schema.DecodeSchema(b)
	if err != nil {
		return nil, nil, err
	}
	h, err := sc.Hash()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(h, hash) {
		return nil, nil, errors.New("web: the schema does not match its hash")
	}
	return sc, b, nil
}

// File fetches a module or asset file and checks its bytes against the
// signed hash (9.6: before running any module). It also returns the
// response headers (Cache-Control).
func (c *Client) File(ctx context.Context, ref string, hash []byte) ([]byte, http.Header, error) {
	b, hdr, err := c.do(ctx, http.MethodGet, ref, nil)
	if err != nil {
		return nil, hdr, err
	}
	if !bytes.Equal(websign.FileHash(b), hash) {
		return nil, hdr, errors.New("web: the file does not match its signed hash")
	}
	return b, hdr, nil
}

// ---------------------------------------------------------------------------
// Accepting modules (9.4, 9.5)
// ---------------------------------------------------------------------------

// State is what a client keeps between snapshots: the highest booted
// version of each module (rollback protection) and the revocation list
// with the highest seq it has seen (9.5). Neither can add trusted keys.
type State struct {
	Rollback   websign.Rollback
	Revocation *websign.Revocation
}

// Loader decides which modules of a schema a client accepts.
type Loader struct {
	// Roots are the root public keys built into the client.
	Roots [][]byte
	// HostAPI is the client's host API version.
	HostAPI string
	// State is the client's stored state (nil: a fresh client).
	State *State
	// Now is the time of acceptance (certificate expiry); default
	// time.Now.
	Now func() time.Time
	// AllowUnsigned accepts modules without a valid signature. Only a
	// development build may set it (9.5).
	AllowUnsigned bool
}

// Reasons a Loader rejects a module besides the websign verdicts.
const (
	ReasonHostAPI  = "host_api_mismatch"
	ReasonRollback = "rollback"
)

// Accept returns the modules of a schema the client loads and the ones it
// rejects, with the reason each rejection reports in moduleRejected. It
// also updates the State's revocation list.
func (l *Loader) Accept(sc *schema.Schema) (accepted []*Entry, rejected []Rejection) {
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	if l.State == nil {
		l.State = &State{}
	}
	v := &websign.Verifier{Roots: l.Roots, Now: now().Unix()}
	if raw, ok := sc.Annotations[AnnKeys]; ok {
		d := cbor.NewDecoder(raw)
		if n, err := d.ArrayHead(); err == nil {
			for i := 0; i < n; i++ {
				cr, err := d.Raw()
				if err != nil {
					break
				}
				if c, err := websign.DecodeCertificate(cr); err == nil {
					v.Certificates = append(v.Certificates, c)
				}
			}
		}
	}
	var lists []*websign.Revocation
	if l.State.Revocation != nil {
		lists = append(lists, l.State.Revocation)
	}
	if raw, ok := sc.Annotations[AnnRevoked]; ok {
		if r, err := websign.DecodeRevocation(raw); err == nil {
			lists = append(lists, r)
		}
	}
	// Only a list signed by a root key counts; the highest seq is kept.
	l.State.Revocation = websign.SelectRevocation(l.Roots, lists...)
	v.Revocation = l.State.Revocation
	entries, bad := SchemaEntries(sc)
	rejected = append(rejected, bad...)
	for _, e := range entries {
		rej := func(reason string) {
			rejected = append(rejected, Rejection{Facet: e.Facet, ID: e.ID(), Version: e.Version(), Reason: reason})
		}
		if r, err := ParseRange(e.HostAPI); err != nil || !r.Contains(l.HostAPI) {
			rej(ReasonHostAPI)
			continue
		}
		if reason := v.Verify(e.Module); reason != websign.ReasonOK && !l.AllowUnsigned {
			rej(string(reason))
			continue
		}
		if ok, err := l.State.Rollback.Allowed(e.ID(), e.Version()); err != nil || !ok {
			rej(ReasonRollback)
			continue
		}
		accepted = append(accepted, e)
	}
	return accepted, rejected
}

// ---------------------------------------------------------------------------
// Offline snapshots (9.6)
// ---------------------------------------------------------------------------

// Snapshot is everything a client needs to boot without a network (9.6):
// { schemaHash, schema, props, modules: [web-module], files: {hash =>
// bytes}, createdAt }.
type Snapshot struct {
	SchemaHash []byte
	Schema     []byte   // the schema's canonical encoding
	Props      cbor.Raw // Welcome.props, or nil
	Modules    []*Entry
	Files      map[string][]byte // hash -> bytes
	CreatedAt  int64             // tag 1, integer seconds
}

// NewSnapshot builds a snapshot from a schema, its accepted modules and
// their files, which must all be present and match their hashes.
func NewSnapshot(sc *schema.Schema, props cbor.Raw, modules []*Entry, files map[string][]byte, at time.Time) (*Snapshot, error) {
	h, err := sc.Hash()
	if err != nil {
		return nil, err
	}
	b, err := sc.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{SchemaHash: h, Schema: b, Props: props, Modules: modules, Files: map[string][]byte{}, CreatedAt: at.Unix()}
	for _, f := range Files(modules) {
		data, ok := files[string(f.Hash)]
		if !ok {
			return nil, fmt.Errorf("web: snapshot: file %s of module %s is missing", EncodeHash(f.Hash), f.Entry.ID())
		}
		s.Files[string(f.Hash)] = data
	}
	return s, s.Verify()
}

// Verify checks a snapshot before it boots: the schema matches its hash,
// and every module and asset file is present and matches its signed hash
// (9.6, boot step 1).
func (s *Snapshot) Verify() error {
	sc, err := schema.DecodeSchema(s.Schema)
	if err != nil {
		return fmt.Errorf("web: snapshot schema: %v", err)
	}
	h, err := sc.Hash()
	if err != nil || !bytes.Equal(h, s.SchemaHash) {
		return errors.New("web: snapshot schema does not match its hash")
	}
	for _, f := range Files(s.Modules) {
		data, ok := s.Files[string(f.Hash)]
		if !ok {
			return fmt.Errorf("web: snapshot: file %s is missing", EncodeHash(f.Hash))
		}
		if !bytes.Equal(websign.FileHash(data), f.Hash) {
			return fmt.Errorf("web: snapshot: file %s does not match its hash", EncodeHash(f.Hash))
		}
	}
	return nil
}

// Encode returns the snapshot as a canonical CBOR map.
func (s *Snapshot) Encode() ([]byte, error) {
	var b []byte
	b = cbor.AppendMapHead(b, 6)
	// Canonical key order: shorter keys first, then bytewise.
	keys := []string{"files", "props", "schema", "modules", "createdAt", "schemaHash"}
	cbor.SortTextKeys(keys)
	for _, k := range keys {
		b = cbor.AppendText(b, k)
		switch k {
		case "files":
			hs := make([]string, 0, len(s.Files))
			for h := range s.Files {
				hs = append(hs, h)
			}
			sort.Strings(hs) // equal lengths: bytewise is canonical
			b = cbor.AppendMapHead(b, len(hs))
			for _, h := range hs {
				b = cbor.AppendBytes(cbor.AppendBytes(b, []byte(h)), s.Files[h])
			}
		case "props":
			if s.Props == nil {
				b = cbor.AppendNull(b)
			} else {
				b = cbor.AppendRaw(b, s.Props)
			}
		case "schema":
			b = cbor.AppendBytes(b, s.Schema)
		case "modules":
			b = cbor.AppendArrayHead(b, len(s.Modules))
			for _, e := range s.Modules {
				raw, err := e.Module.Encode()
				if err != nil {
					return nil, err
				}
				b = cbor.AppendRaw(b, raw)
			}
		case "createdAt":
			b = cbor.AppendTime(b, cbor.Unix(s.CreatedAt))
		case "schemaHash":
			b = cbor.AppendBytes(b, s.SchemaHash)
		}
	}
	return cbor.Canonical(b, cbor.Options{NoFloats: true})
}

// DecodeSnapshot decodes Encode's form and verifies it.
func DecodeSnapshot(b []byte) (*Snapshot, error) {
	if err := cbor.Validate(b, cbor.Options{}); err != nil {
		return nil, err
	}
	d := cbor.NewDecoder(b)
	n, err := d.MapHead()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Files: map[string][]byte{}}
	for i := 0; i < n; i++ {
		k, err := d.Text()
		if err != nil {
			return nil, err
		}
		switch k {
		case "schemaHash":
			s.SchemaHash, err = d.Bytes()
		case "schema":
			s.Schema, err = d.Bytes()
		case "props":
			if d.PeekNull() {
				err = d.Null()
			} else {
				s.Props, err = d.Raw()
			}
		case "modules":
			var m int
			if m, err = d.ArrayHead(); err == nil {
				for j := 0; j < m && err == nil; j++ {
					var raw cbor.Raw
					if raw, err = d.Raw(); err == nil {
						var e *Entry
						if e, err = DecodeEntry(raw); err == nil {
							s.Modules = append(s.Modules, e)
						}
					}
				}
			}
		case "files":
			var m int
			if m, err = d.MapHead(); err == nil {
				for j := 0; j < m && err == nil; j++ {
					var h, data []byte
					if h, err = d.Bytes(); err == nil {
						data, err = d.Bytes()
						s.Files[string(h)] = data
					}
				}
			}
		case "createdAt":
			var t cbor.Time
			t, err = d.Time()
			s.CreatedAt = t.Sec
		default:
			err = d.Skip()
		}
		if err != nil {
			return nil, fmt.Errorf("web: snapshot %s: %v", k, err)
		}
	}
	return s, s.Verify()
}

// Snapshots keeps a client's current snapshot and the one previous
// snapshot it keeps for rollback (9.6 step 5), with the State.
type Snapshots struct {
	Current, Previous *Snapshot
	booted            bool
	State             State
}

// Install makes a new snapshot current; the old one is kept until the new
// one has booted once.
func (s *Snapshots) Install(n *Snapshot) error {
	if err := n.Verify(); err != nil {
		return err // a half-written or corrupted snapshot is never used
	}
	if s.Current != nil && s.booted {
		s.Previous = s.Current
	}
	s.Current, s.booted = n, false
	return nil
}

// Booted records that the current snapshot booted: from now on lower
// versions of its modules are rejected (9.5), and the previous snapshot
// is the one kept for rollback.
func (s *Snapshots) Booted() error {
	if s.Current == nil {
		return errors.New("web: no snapshot")
	}
	for _, e := range s.Current.Modules {
		if err := s.State.Rollback.Record(e.ID(), e.Version()); err != nil {
			return err
		}
	}
	s.booted = true
	return nil
}

// RollBack returns to the previous snapshot after a bad update. The
// previous snapshot is exempt from rollback protection.
func (s *Snapshots) RollBack() error {
	if s.Previous == nil {
		return errors.New("web: no previous snapshot")
	}
	s.Current, s.Previous, s.booted = s.Previous, nil, true
	return nil
}
