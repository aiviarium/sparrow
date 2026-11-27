// Command sparrow-admin drives a hub's sparrow.hub.admin facet
// (spec/hub-admin.md) over an ordinary session.
//
//	sparrow-admin -url URL -token TOKEN [-cert-hash HEX] COMMAND [ARGS]
//
// Commands:
//
//	get                              print the applied snapshot (JSON)
//	validate FILE                    validate a document (JSON) against the current revision
//	commit FILE [-confirm-within MS] [-confirm]
//	                                 commit a document; with -confirm, confirm it over a new session
//	confirm N                        confirm revision N
//	rollback N                       roll pending revision N back
//	set-secret NAME VALUE|@FILE|-    store a secret (- reads standard input)
//	delete-secret NAME
//	list-secrets
//	watch                            print events as JSON lines until interrupted
//
// Documents use the JSON form of admin.Config; a top-level "policy" list of
// [principal, facet, level] is accepted as the reference hub's ref.policy.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/hub"
	"github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/wire"
)

type opts struct {
	url      string
	token    string
	certHash []byte
	facet    string
	timeout  time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sparrow-admin:", err)
		var e *exitError
		if errors.As(err, &e) {
			os.Exit(e.code)
		}
		os.Exit(1)
	}
}

type exitError struct{ code int }

func (e *exitError) Error() string { return "usage" }

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("sparrow-admin", flag.ContinueOnError)
	var o opts
	var tokenFile, certHash string
	fs.StringVar(&o.url, "url", os.Getenv("SPARROW_URL"), "hub URL: https:// (WebTransport), ws:// or wss:// (WebSocket)")
	fs.StringVar(&o.token, "token", os.Getenv("SPARROW_TOKEN"), "bearer credential")
	fs.StringVar(&tokenFile, "token-file", "", "read the bearer credential from a file")
	fs.StringVar(&certHash, "cert-hash", os.Getenv("SPARROW_CERT_HASH"), "pin the server certificate by its SHA-256 (hex), for self-signed development hubs")
	fs.StringVar(&o.facet, "facet", "", "facet name (default sparrow.hub.admin; <peer>/sparrow.hub.admin for a peer's)")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "timeout per command (not for watch)")
	if err := fs.Parse(args); err != nil {
		return &exitError{2}
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return err
		}
		o.token = strings.TrimSpace(string(b))
	}
	if certHash != "" {
		h, err := hex.DecodeString(certHash)
		if err != nil {
			return fmt.Errorf("-cert-hash: %v", err)
		}
		o.certHash = h
	}
	rest := fs.Args()
	if len(rest) == 0 || o.url == "" {
		fmt.Fprintln(os.Stderr, "usage: sparrow-admin -url URL -token TOKEN COMMAND [ARGS]")
		return &exitError{2}
	}
	cmd, cargs := rest[0], rest[1:]
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if cmd != "watch" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}
	c, closeFn, err := o.connect(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	out := json.NewEncoder(stdout)
	out.SetIndent("", "  ")
	need := func(n int) error {
		if len(cargs) < n {
			return fmt.Errorf("%s needs %d argument(s)", cmd, n)
		}
		return nil
	}
	switch cmd {
	case "get":
		s, err := c.Get(ctx)
		if err != nil {
			return err
		}
		return out.Encode(snapshotJSON(s))
	case "validate":
		if err := need(1); err != nil {
			return err
		}
		doc, err := readDoc(cargs[0])
		if err != nil {
			return err
		}
		s, err := c.Get(ctx)
		if err != nil {
			return err
		}
		ps, err := c.Validate(ctx, s.Revision, doc)
		if err != nil {
			return err
		}
		if err := out.Encode(problemsJSON(ps)); err != nil {
			return err
		}
		if len(ps) > 0 {
			return &exitError{3}
		}
		return nil
	case "commit":
		cf := flag.NewFlagSet("commit", flag.ContinueOnError)
		within := cf.Uint64("confirm-within", 0, "confirmation deadline in ms (0: confirmed at once)")
		confirm := cf.Bool("confirm", false, "confirm the commit over a new session")
		if err := cf.Parse(cargs); err != nil || cf.NArg() != 1 {
			return errors.New("commit [-confirm-within MS] [-confirm] FILE")
		}
		doc, err := readDoc(cf.Arg(0))
		if err != nil {
			return err
		}
		s, err := c.Get(ctx)
		if err != nil {
			return err
		}
		rev, err := c.Commit(ctx, s.Revision, doc, *within)
		if err != nil {
			if ps := admin.ProblemsOf(err); len(ps) > 0 {
				_ = out.Encode(problemsJSON(ps))
			}
			return err
		}
		if *confirm && *within > 0 {
			// A new session shows that new connections still work (2.3).
			c2, close2, err := o.connect(ctx)
			if err != nil {
				return fmt.Errorf("revision %d committed, but cannot connect again to confirm it: %v", rev, err)
			}
			defer close2()
			if err := c2.Confirm(ctx, rev); err != nil {
				return fmt.Errorf("confirm %d: %v", rev, err)
			}
		}
		return out.Encode(map[string]uint64{"revision": rev})
	case "confirm", "rollback":
		if err := need(1); err != nil {
			return err
		}
		n, err := strconv.ParseUint(cargs[0], 10, 64)
		if err != nil {
			return err
		}
		if cmd == "confirm" {
			return c.Confirm(ctx, n)
		}
		rev, err := c.Rollback(ctx, n)
		if err != nil {
			return err
		}
		return out.Encode(map[string]uint64{"revision": rev})
	case "set-secret":
		if err := need(2); err != nil {
			return err
		}
		v := []byte(cargs[1])
		switch {
		case cargs[1] == "-":
			if v, err = io.ReadAll(stdin); err != nil {
				return err
			}
		case strings.HasPrefix(cargs[1], "@"):
			if v, err = os.ReadFile(cargs[1][1:]); err != nil {
				return err
			}
		}
		return c.SetSecret(ctx, cargs[0], v)
	case "delete-secret":
		if err := need(1); err != nil {
			return err
		}
		return c.DeleteSecret(ctx, cargs[0])
	case "list-secrets":
		ns, err := c.ListSecrets(ctx)
		if err != nil {
			return err
		}
		return out.Encode(ns)
	case "watch":
		w, err := c.Watch(ctx)
		if err != nil {
			return err
		}
		line := json.NewEncoder(stdout)
		for {
			e, err := w.Next(ctx)
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			if err != nil {
				return err
			}
			if err := line.Encode(eventJSON(e)); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func (o *opts) connect(ctx context.Context) (*admin.Client, func(), error) {
	n := node.New(node.Options{Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, o.token)}})
	do := node.DialOptions{}
	if o.certHash != nil {
		do.CertHashes = [][]byte{o.certHash}
		hash := o.certHash
		do.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("no certificate")
				}
				sum := sha256.Sum256(raw[0])
				if subtle.ConstantTimeCompare(sum[:], hash) != 1 {
					return errors.New("the certificate does not match -cert-hash")
				}
				return nil
			},
		}}}
	}
	if err := n.Dial(ctx, o.url, do); err != nil {
		return nil, nil, err
	}
	c, err := admin.NewClient(n.Session(), o.facet)
	if err != nil {
		n.Close()
		return nil, nil, err
	}
	// GoAway and the transport's close reach the hub before the program
	// exits; otherwise the hub sees the connection go only at its idle
	// timeout.
	return c, func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		n.Shutdown(sctx)
	}, nil
}

// readDoc reads a document in the JSON form, with the "policy" shorthand.
func readDoc(path string) (*admin.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var extra struct {
		Policy [][3]string `json:"policy"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	delete(m, "policy")
	b, _ = json.Marshal(m)
	var c admin.Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Nodes == nil {
		c.Nodes = map[string]*admin.NodeConfig{}
	}
	if extra.Policy != nil {
		gs := make([]hub.Grant, 0, len(extra.Policy))
		for _, p := range extra.Policy {
			l, err := hub.ParseLevel(p[2])
			if err != nil {
				return nil, err
			}
			gs = append(gs, hub.Grant{Principal: p[0], Facet: p[1], Level: l})
		}
		if c.Extensions == nil {
			c.Extensions = map[string][]byte{}
		}
		c.Extensions[hub.PolicyExtension] = hub.EncodeGrants(gs)
	}
	return &c, nil
}

func configJSON(c *admin.Config) any {
	b, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if v, ok := c.Extensions[hub.PolicyExtension]; ok {
		if gs, err := hub.ParseGrants(v); err == nil {
			ps := make([][3]string, 0, len(gs))
			for _, g := range gs {
				ps = append(ps, [3]string{g.Principal, g.Facet, g.Level.String()})
			}
			m["policy"] = ps
			if ex, ok := m["extensions"].(map[string]any); ok {
				delete(ex, hub.PolicyExtension)
				if len(ex) == 0 {
					delete(m, "extensions")
				}
			}
		}
	}
	return m
}

func snapshotJSON(s *admin.Snapshot) any {
	m := map[string]any{"revision": s.Revision, "state": s.State.String(), "config": configJSON(s.Config)}
	if s.ConfirmInMs != nil {
		m["confirmInMs"] = *s.ConfirmInMs
	}
	return m
}

func problemsJSON(ps []admin.Problem) any {
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, map[string]any{"path": p.Path, "message": p.Message})
	}
	return out
}

func eventJSON(e *admin.Event) any {
	switch {
	case e.Snapshot != nil:
		return map[string]any{"snapshot": snapshotJSON(e.Snapshot)}
	case e.Revision != nil:
		m := map[string]any{"revision": e.Revision.Revision, "state": e.Revision.State.String()}
		if e.Revision.ConfirmInMs != nil {
			m["confirmInMs"] = *e.Revision.ConfirmInMs
		}
		return map[string]any{"revision": m}
	default:
		m := map[string]any{"node": e.Node.Node, "revision": e.Node.Revision, "state": e.Node.State.String()}
		if e.Node.Message != nil {
			m["message"] = *e.Node.Message
		}
		return map[string]any{"node": m}
	}
}
