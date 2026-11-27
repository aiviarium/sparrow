package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/websign"
)

// ---------------------------------------------------------------------------
// Fixtures: the signing vectors (TEST-ONLY keys)
// ---------------------------------------------------------------------------

type signingFixture struct {
	root      ed25519.PrivateKey
	roots     [][]byte
	now       time.Time
	certs     []cbor.Raw
	lists     map[string]cbor.Raw // revocation vectors
	modules   map[string]cbor.Raw // module vectors: entry CBOR
	files     map[string][]byte   // module vectors: file bytes
	cssFile   []byte
	cssHashed []byte
}

func loadSigning(t *testing.T) *signingFixture {
	t.Helper()
	f, err := vectors.Load("signing.json")
	if err != nil {
		t.Fatal(err)
	}
	var ctx struct {
		Roots []string `json:"root_public_keys"`
		Now   int64    `json:"now"`
	}
	if err := json.Unmarshal(f.Header["verification_context"], &ctx); err != nil {
		t.Fatal(err)
	}
	s := &signingFixture{now: time.Unix(ctx.Now, 0), lists: map[string]cbor.Raw{}, modules: map[string]cbor.Raw{}, files: map[string][]byte{}}
	for _, r := range ctx.Roots {
		b, _ := hex.DecodeString(r)
		s.roots = append(s.roots, b)
	}
	for _, v := range f.Vectors {
		switch v.Type {
		case "key":
			if v.Name == "key/root-01" {
				s.root = ed25519.NewKeyFromSeed(v.Hex("seed"))
			}
		case "certificate":
			s.certs = append(s.certs, v.Hex("certificate_cbor"))
		case "revocation":
			s.lists[v.Name] = v.Hex("revocation_cbor")
		case "module":
			s.modules[v.Name] = v.Hex("entry_cbor")
			s.files[v.Name] = []byte(v.String("file_utf8"))
		case "file_hash":
			s.cssFile = []byte(v.String("file_utf8"))
			s.cssHashed = v.Hex("hash")
		}
	}
	return s
}

func list(items ...cbor.Raw) cbor.Raw {
	b := cbor.AppendArrayHead(nil, len(items))
	for _, i := range items {
		b = cbor.AppendRaw(b, i)
	}
	return b
}

func facetWith(id uint64, name string, modules ...cbor.Raw) schema.Facet {
	f := schema.Facet{ID: id, Name: name, Version: "1.0.0", Types: []schema.TypeDef{}, Sigils: []schema.Sigil{},
		Retired: []schema.Retired{}, Annotations: schema.Annotations{},
		Services: []schema.Service{{ID: 0, Name: "S", Annotations: schema.Annotations{}, Methods: []schema.Method{
			{ID: 0, Name: "m", Input: schema.Named(schema.TypeUnit), Output: schema.Named(schema.TypeString), Errors: []uint64{}, Annotations: schema.Annotations{}},
		}}}}
	if len(modules) > 0 {
		f.Annotations[AnnModules] = list(modules...)
	}
	return f
}

func schemaWith(top schema.Annotations, fs ...schema.Facet) *schema.Schema {
	sc := &schema.Schema{Format: schema.Format, Name: "test", Version: "1", Facets: fs, Annotations: schema.Annotations{}}
	for k, v := range top {
		sc.Annotations[k] = v
	}
	return sc.Canonical()
}

// signedEntry signs a module entry for a file with key.
func signedEntry(t *testing.T, id, version, hostAPI string, file []byte, key ed25519.PrivateKey) cbor.Raw {
	t.Helper()
	h := websign.FileHash(file)
	m := &websign.Module{ID: id, Version: version, Hash: h, Fields: map[string]cbor.Raw{
		"id": cbor.AppendText(nil, id), "version": cbor.AppendText(nil, version), "hash": cbor.AppendBytes(nil, h),
		"url": cbor.AppendText(nil, FileName(h, "js")), "deps": cbor.AppendArrayHead(nil, 0), "hostApi": cbor.AppendText(nil, hostAPI),
	}}
	if err := websign.SignModule(m, key); err != nil {
		t.Fatal(err)
	}
	raw, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// Tickets (9.2)
// ---------------------------------------------------------------------------

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTickets(t *testing.T, clk *fakeClock, aud string) *Tickets {
	_, k, _ := ed25519.GenerateKey(nil)
	return &Tickets{Key: k, Audience: aud, Now: clk.now}
}

func alice(clk *fakeClock) *Login {
	return &Login{Principal: "user:alice", Groups: []string{"group:eng"}, Session: "sid-1", Expires: clk.t.Add(time.Hour)}
}

func TestTickets(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	tk := newTickets(t, clk, "edge-1")
	tok, c, err := tk.Issue(alice(clk))
	if err != nil {
		t.Fatal(err)
	}
	if c.Expires-c.IssuedAt > 60 || c.Audience != "edge-1" || c.Subject != "user:alice" || c.LoginSession != "sid-1" || c.ID == "" ||
		c.SessionExpires != clk.t.Add(time.Hour).Unix() {
		t.Fatalf("claims %+v", c)
	}
	// The header says EdDSA.
	hb, _ := b64.DecodeString(strings.Split(tok, ".")[0])
	if !strings.Contains(string(hb), `"alg":"EdDSA"`) {
		t.Fatalf("header %s", hb)
	}
	if _, err := tk.Verify(tok); err != nil {
		t.Fatal(err)
	}
	// Single use.
	if _, err := tk.Verify(tok); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replay: %v", err)
	}
	// Expiry: exp passed.
	tok2, _, _ := tk.Issue(alice(clk))
	clk.t = clk.t.Add(46 * time.Second)
	if _, err := tk.Verify(tok2); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	// Wrong audience: another edge's ticket.
	other := &Tickets{Key: tk.Key, Audience: "edge-2", Now: clk.now}
	tok3, _, _ := other.Issue(alice(clk))
	if _, err := tk.Verify(tok3); err == nil || !strings.Contains(err.Error(), "another edge") {
		t.Fatalf("audience: %v", err)
	}
	// Wrong signature: another key, or a changed payload.
	forger := newTickets(t, clk, "edge-1")
	tok4, _, _ := forger.Issue(alice(clk))
	if _, err := tk.Verify(tok4); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("foreign key: %v", err)
	}
	tok5, _, _ := tk.Issue(alice(clk))
	parts := strings.Split(tok5, ".")
	pb, _ := b64.DecodeString(parts[1])
	pb = bytes.Replace(pb, []byte("user:alice"), []byte("user:admin"), 1)
	if _, err := tk.Verify(parts[0] + "." + b64.EncodeToString(pb) + "." + parts[2]); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// alg none.
	none := b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."
	if _, err := tk.Verify(none); err == nil {
		t.Fatal("alg none accepted")
	}
	// A ticket presentable for more than 60 s.
	long := &Tickets{Key: tk.Key, Audience: "edge-1", Now: clk.now, Lifetime: 10 * time.Minute}
	tok6, c6, _ := long.Issue(alice(clk))
	if c6.Expires-c6.IssuedAt > 60 {
		t.Fatal("Lifetime is not capped at 60 s")
	}
	_ = tok6
	forged := signClaims(tk.Key, Claims{Subject: "user:alice", LoginSession: "s", Audience: "edge-1", IssuedAt: clk.t.Unix(),
		Expires: clk.t.Unix() + 120, ID: "x", SessionExpires: clk.t.Unix() + 3600})
	if _, err := tk.Verify(forged); err == nil || !strings.Contains(err.Error(), "60 s") {
		t.Fatalf("long exp: %v", err)
	}
	// The login session ended.
	l := alice(clk)
	l.Expires = clk.t.Add(10 * time.Second)
	tok7, _, _ := tk.Issue(l)
	clk.t = clk.t.Add(11 * time.Second)
	if _, err := tk.Verify(tok7); err == nil {
		t.Fatal("ticket of an ended login session accepted")
	}
}

func signClaims(k ed25519.PrivateKey, c Claims) string {
	h, _ := json.Marshal(jwtHeader{Alg: "EdDSA", Typ: "JWT"})
	p, _ := json.Marshal(c)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return in + "." + b64.EncodeToString(ed25519.Sign(k, []byte(in)))
}

// ---------------------------------------------------------------------------
// The HTTP server (9.1, 9.3)
// ---------------------------------------------------------------------------

type fakeHost struct {
	byPrincipal map[string]*schema.Schema
}

func (h *fakeHost) SchemaFor(p string, groups []string) (*schema.Schema, error) {
	if s, ok := h.byPrincipal[p]; ok {
		return s, nil
	}
	return h.byPrincipal[""], nil
}

type memModules map[string][]byte

func (m memModules) Open(h []byte) ([]byte, bool) { b, ok := m[string(h)]; return b, ok }

type webFixture struct {
	srv     *Server
	ts      *httptest.Server
	clk     *fakeClock
	host    *fakeHost
	files   memModules
	private []byte // a module only alice sees
	public  []byte // a module everyone sees
	asset   []byte
}

func newWebFixture(t *testing.T) *webFixture {
	sf := loadSigning(t)
	clk := &fakeClock{t: sf.now}
	privFile := []byte("export default () => 'private'")
	pubFile := []byte("export default () => 'public'")
	priv := signedEntry(t, "acme.notes.ui", "1.0.0", "^3.1", privFile, sf.root)
	pub := signedEntry(t, "acme.charts.ui", "1.0.0", "^3.1", pubFile, sf.root)
	everyone := schemaWith(nil, facetWith(16, "acme.charts", pub))
	aliceSc := schemaWith(nil, facetWith(16, "acme.charts", pub, sf.modules["module/acme-charts"]), facetWith(17, "acme.notes", priv))
	files := memModules{string(websign.FileHash(privFile)): privFile, string(websign.FileHash(pubFile)): pubFile,
		string(sf.cssHashed): sf.cssFile}
	host := &fakeHost{byPrincipal: map[string]*schema.Schema{"": everyone, "user:alice": aliceSc}}
	tk := newTickets(t, clk, "edge-1")
	f := &webFixture{clk: clk, host: host, files: files, private: websign.FileHash(privFile), public: websign.FileHash(pubFile), asset: sf.cssHashed}
	auth := &StaticTokens{Tokens: []StaticToken{{Token: "alice-token", Principal: "user:alice"}, {Token: "bob-token", Principal: "user:bob"}}, Now: clk.now}
	srv, err := NewServer(ServerOptions{Tickets: tk, Auth: auth, Host: host, Modules: files, MinHostAPI: "3.0.0",
		Endpoints:      Endpoints{WebTransport: "https://edge-1/sparrow/wt", WebSocket: "wss://edge-1/sparrow/ws"},
		AllowedOrigins: []string{"https://app.example"}, CertHashes: [][]byte{bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	f.ts = httptest.NewServer(srv)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *webFixture) do(t *testing.T, method, path, token, ctype, origin, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, f.ts.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestConnect(t *testing.T) {
	t.Parallel()
	f := newWebFixture(t)
	const js = "application/json"
	body := `{"client": {"name": "sparrow-web", "version": "1.4.0", "hostApi": "3.2.0"}, "knownSchemaHash": "AbC"}`
	if r := f.do(t, "POST", ConnectPath, "", js, "", body); r.StatusCode != 401 {
		t.Fatalf("no login: %d", r.StatusCode)
	}
	if r := f.do(t, "POST", ConnectPath, "alice-token", "text/plain", "", body); r.StatusCode != 415 {
		t.Fatalf("not JSON: %d", r.StatusCode)
	}
	if r := f.do(t, "GET", ConnectPath, "alice-token", js, "", ""); r.StatusCode != 405 {
		t.Fatalf("GET: %d", r.StatusCode)
	}
	if r := f.do(t, "POST", ConnectPath, "alice-token", js, "https://evil.example", body); r.StatusCode != 403 {
		t.Fatalf("foreign origin: %d", r.StatusCode)
	}
	old := `{"client": {"name": "sparrow-web", "version": "1.0.0", "hostApi": "2.9.0"}}`
	if r := f.do(t, "POST", ConnectPath, "alice-token", js, "", old); r.StatusCode != 426 {
		t.Fatalf("old hostApi: %d", r.StatusCode)
	}
	r := f.do(t, "POST", ConnectPath, "alice-token", "application/json; charset=utf-8", "https://app.example", body)
	raw, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 {
		t.Fatalf("%d %s", r.StatusCode, raw)
	}
	if r.Header.Get("Access-Control-Allow-Origin") != "https://app.example" || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", r.Header)
	}
	// WebTransport first, WebSocket fallback.
	if i, j := bytes.Index(raw, []byte(`"webtransport"`)), bytes.Index(raw, []byte(`"websocket"`)); i < 0 || j < i {
		t.Fatalf("endpoint order: %s", raw)
	}
	var cr ConnectResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		t.Fatal(err)
	}
	h, _ := f.host.byPrincipal["user:alice"].Hash()
	if cr.SchemaHash != EncodeHash(h) || cr.SchemaURL != SchemaPath+EncodeHash(h) || len(cr.ProtocolVersions) != 1 || cr.ProtocolVersions[0] != 1 {
		t.Fatalf("response %+v", cr)
	}
	if len(cr.ServerCertificateHashes) != 1 || cr.ServerCertificateHashes[0] != EncodeHash(bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("cert hashes %v", cr.ServerCertificateHashes)
	}
	c, err := f.srv.Tickets().Verify(cr.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user:alice" || c.Audience != "edge-1" || c.ExpiresAt().Format(time.RFC3339) != cr.TicketExpiresAt ||
		c.SessionExpiresAt().UTC().Format(time.RFC3339) != cr.SessionExpiresAt {
		t.Fatalf("claims %+v vs %+v", c, cr)
	}
	// The refresh form: only a new ticket, same sub and sid.
	r = f.do(t, "POST", ConnectPath, "alice-token", js, "", `{"refresh": {"endpoint": "wss://edge-1/sparrow/ws"}}`)
	raw, _ = io.ReadAll(r.Body)
	var rr map[string]any
	if err := json.Unmarshal(raw, &rr); err != nil || r.StatusCode != 200 || len(rr) != 1 {
		t.Fatalf("refresh %d %s", r.StatusCode, raw)
	}
	c2, err := f.srv.Tickets().Verify(rr["ticket"].(string))
	if err != nil || c2.Subject != c.Subject || c2.LoginSession != c.LoginSession || c2.ID == c.ID {
		t.Fatalf("refreshed %+v %v", c2, err)
	}
	if r := f.do(t, "POST", ConnectPath, "alice-token", js, "", `{"refresh": {"endpoint": "wss://edge-9/sparrow/ws"}}`); r.StatusCode != 400 {
		t.Fatalf("refresh for another edge: %d", r.StatusCode)
	}
	// CORS preflight.
	if r := f.do(t, "OPTIONS", ConnectPath, "", "", "https://app.example", ""); r.StatusCode != 204 || !strings.Contains(r.Header.Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Fatalf("preflight %d %v", r.StatusCode, r.Header)
	}
}

func TestConnectCookieNeedsOrigin(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Now()}
	auth := AuthenticatorFunc(func(r *http.Request) (*Login, error) {
		if _, err := r.Cookie("session"); err != nil {
			return nil, ErrNoLogin
		}
		return &Login{Principal: "user:alice", Session: "c1", Expires: clk.t.Add(time.Hour), Cookie: true}, nil
	})
	srv, _ := NewServer(ServerOptions{Tickets: newTickets(t, clk, "e"), Auth: auth, Host: &fakeHost{byPrincipal: map[string]*schema.Schema{"": schemaWith(nil)}},
		AllowedOrigins: []string{"https://app.example"}})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	post := func(origin string) int {
		req, _ := http.NewRequest("POST", ts.URL+ConnectPath, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "session", Value: "x"})
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if c := post(""); c != 403 {
		t.Fatalf("cookie login without Origin: %d", c)
	}
	if c := post("https://app.example"); c != 200 {
		t.Fatalf("cookie login with an allowed Origin: %d", c)
	}
}

func TestSchemaResource(t *testing.T) {
	t.Parallel()
	f := newWebFixture(t)
	h, _ := f.host.byPrincipal["user:alice"].Hash()
	path := SchemaPath + EncodeHash(h)
	if r := f.do(t, "GET", path, "", "", "", ""); r.StatusCode != 401 {
		t.Fatalf("no login: %d", r.StatusCode)
	}
	r := f.do(t, "GET", path, "alice-token", "", "", "")
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/cbor" || r.Header.Get("Cache-Control") != "private, max-age=31536000, immutable" {
		t.Fatalf("%d %v", r.StatusCode, r.Header)
	}
	sc, err := schema.DecodeSchema(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := sc.Hash(); !bytes.Equal(got, h) {
		t.Fatal("served schema does not match its hash")
	}
	// Alice's schema is never served to bob; unknown hashes are 404.
	if r := f.do(t, "GET", path, "bob-token", "", "", ""); r.StatusCode != 404 {
		t.Fatalf("bob got alice's schema: %d", r.StatusCode)
	}
	if r := f.do(t, "GET", SchemaPath+EncodeHash(append([]byte{1}, make([]byte, 32)...)), "alice-token", "", "", ""); r.StatusCode != 404 {
		t.Fatalf("unknown: %d", r.StatusCode)
	}
	// Through the client, with the hash check.
	cl := &Client{Base: f.ts.URL, Authorize: func(r *http.Request) { r.Header.Set("Authorization", "Bearer alice-token") }}
	if _, _, err := cl.Schema(context.Background(), path, h); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cl.Schema(context.Background(), path, append([]byte{1}, make([]byte, 32)...)); err == nil {
		t.Fatal("hash mismatch not detected by the client")
	}
}

func TestModuleResources(t *testing.T) {
	t.Parallel()
	f := newWebFixture(t)
	pub := FileName(f.public, "js")
	priv := FileName(f.private, "js")
	// A module every user may load is public, and needs no login.
	r := f.do(t, "GET", pub, "", "", "", "")
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" || r.Header.Get("Content-Type") != "text/javascript" {
		t.Fatalf("public: %d %v", r.StatusCode, r.Header)
	}
	// A module only alice sees is private, and needs her login.
	if r := f.do(t, "GET", priv, "", "", "", ""); r.StatusCode != 401 {
		t.Fatalf("private without login: %d", r.StatusCode)
	}
	if r := f.do(t, "GET", priv, "bob-token", "", "", ""); r.StatusCode != 404 {
		t.Fatalf("private for bob: %d", r.StatusCode)
	}
	r = f.do(t, "GET", priv, "alice-token", "", "", "")
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "private, max-age=31536000, immutable" {
		t.Fatalf("private for alice: %d %v", r.StatusCode, r.Header)
	}
	// An asset, by its own extension; a wrong extension is 404.
	r = f.do(t, "GET", FileName(f.asset, "css"), "alice-token", "", "", "")
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "text/css" {
		t.Fatalf("asset: %d %v", r.StatusCode, r.Header)
	}
	if r := f.do(t, "GET", FileName(f.private, "css"), "alice-token", "", "", ""); r.StatusCode != 404 {
		t.Fatalf("wrong extension: %d", r.StatusCode)
	}
	// A store whose bytes do not match the hash is never served.
	f.files[string(f.private)] = []byte("tampered")
	if r := f.do(t, "GET", priv, "alice-token", "", "", ""); r.StatusCode != 500 {
		t.Fatalf("hash mismatch served: %d", r.StatusCode)
	}
	// The client checks too.
	cl := &Client{Base: f.ts.URL}
	if _, hdr, err := cl.File(context.Background(), pub, f.public); err != nil || hdr.Get("Cache-Control") == "" {
		t.Fatal(err)
	}
	if _, _, err := cl.File(context.Background(), pub, f.private); err == nil {
		t.Fatal("client accepted bytes that do not match the signed hash")
	}
}

// ---------------------------------------------------------------------------
// Accepting modules (9.4, 9.5)
// ---------------------------------------------------------------------------

func entryNames(es []*Entry) string {
	var s []string
	for _, e := range es {
		s = append(s, e.ID()+"@"+e.Version())
	}
	return strings.Join(s, ",")
}

func reasons(rs []Rejection) map[string]string {
	m := map[string]string{}
	for _, r := range rs {
		m[r.ID] = r.Reason
	}
	return m
}

func TestLoaderVerdicts(t *testing.T) {
	t.Parallel()
	sf := loadSigning(t)
	top := schema.Annotations{AnnKeys: list(sf.certs...), AnnRevoked: sf.lists["revocation/list-3"]}
	sc := schemaWith(top,
		facetWith(16, "acme.charts", sf.modules["module/acme-charts"]),
		facetWith(17, "acme.core", sf.modules["module/acme-core"]),
		facetWith(18, "beta.tools", sf.modules["module/revoked-key"]),
		facetWith(19, "gamma.reports", sf.modules["module/expired-cert"]),
		facetWith(20, "acme.charts2"),
	)
	l := &Loader{Roots: sf.roots, HostAPI: "3.2.0", Now: func() time.Time { return sf.now }}
	acc, rej := l.Accept(sc)
	if entryNames(acc) != "acme.charts.ui@1.4.2,acme.core.boot@3.1.0" {
		t.Fatalf("accepted %s, rejected %v", entryNames(acc), rej)
	}
	rs := reasons(rej)
	if rs["beta.tools"] != string(websign.ReasonKeyRevoked) || rs["gamma.reports"] != string(websign.ReasonCertificateExpired) {
		t.Fatalf("rejected %v", rej)
	}
	// A tampered entry fails its signature.
	sc2 := schemaWith(top, facetWith(16, "acme.charts", sf.modules["module/tampered"]))
	if _, rej := l.Accept(sc2); reasons(rej)["acme.charts.ui"] != string(websign.ReasonBadModuleSignature) {
		t.Fatalf("tampered: %v", rej)
	}
	// hostApi outside the module's range.
	old := &Loader{Roots: sf.roots, HostAPI: "2.0.0", Now: l.Now}
	if _, rej := old.Accept(sc); reasons(rej)["acme.charts.ui"] != ReasonHostAPI {
		t.Fatalf("hostApi: %v", rej)
	}
	// A module out of its facet's scope: the facet contributes nothing.
	sc3 := schemaWith(top, facetWith(16, "acme.notes", sf.modules["module/acme-charts"]))
	if acc, rej := l.Accept(sc3); len(acc) != 0 || len(rej) != 1 || !strings.Contains(rej[0].Reason, "invalid_modules") {
		t.Fatalf("scope: %s %v", entryNames(acc), rej)
	}
	if err := CheckFacet(&sc3.Facets[0]); err == nil {
		t.Fatal("the hub accepted a module outside the facet's scope")
	}
}

func TestRevocationState(t *testing.T) {
	t.Parallel()
	sf := loadSigning(t)
	certs := list(sf.certs...)
	l := &Loader{Roots: sf.roots, HostAPI: "3.2.0", Now: func() time.Time { return sf.now }}
	mods := []schema.Facet{facetWith(17, "acme.core", sf.modules["module/acme-core"]), facetWith(18, "beta.tools", sf.modules["module/revoked-key"])}
	// Roots cannot be revoked: a list naming the root key still applies to
	// the rest (beta), and the root-signed module stays accepted.
	acc, rej := l.Accept(schemaWith(schema.Annotations{AnnKeys: certs, AnnRevoked: sf.lists["revocation/lists-root"]}, mods...))
	if entryNames(acc) != "acme.core.boot@3.1.0" || reasons(rej)["beta.tools"] != string(websign.ReasonKeyRevoked) {
		t.Fatalf("root list: %s %v", entryNames(acc), rej)
	}
	if l.State.Revocation.Seq != 4 {
		t.Fatalf("seq %d", l.State.Revocation.Seq)
	}
	// The list with the highest seq is kept: a later schema without a
	// list, or with an older one (seq 3), does not unrevoke beta.
	for _, ann := range []schema.Annotations{{AnnKeys: certs}, {AnnKeys: certs, AnnRevoked: sf.lists["revocation/list-3"]}} {
		_, rej := l.Accept(schemaWith(ann, mods...))
		if reasons(rej)["beta.tools"] != string(websign.ReasonKeyRevoked) || l.State.Revocation.Seq != 4 {
			t.Fatalf("revocation lost: %v seq %d", rej, l.State.Revocation.Seq)
		}
	}
	// A forged list (not signed by a root) does not count.
	fresh := &Loader{Roots: sf.roots, HostAPI: "3.2.0", Now: l.Now}
	_, rej = fresh.Accept(schemaWith(schema.Annotations{AnnKeys: certs, AnnRevoked: sf.lists["revocation/forged"]}, mods...))
	if _, revoked := reasons(rej)["beta.tools"]; revoked || fresh.State.Revocation != nil {
		t.Fatalf("forged list counted: %v", rej)
	}
}

func TestRollbackAndSnapshots(t *testing.T) {
	t.Parallel()
	sf := loadSigning(t)
	at := sf.now
	v1, v2 := []byte("export default () => 1"), []byte("export default () => 2")
	e1 := signedEntry(t, "acme.core.app", "1.2.0", "^3", v1, sf.root)
	e2 := signedEntry(t, "acme.core.app", "1.3.0", "^3", v2, sf.root)
	sc1 := schemaWith(nil, facetWith(16, "acme.core", e1))
	sc2 := schemaWith(nil, facetWith(16, "acme.core", e2))
	files := map[string][]byte{string(websign.FileHash(v1)): v1, string(websign.FileHash(v2)): v2}
	var store Snapshots
	l := &Loader{Roots: sf.roots, HostAPI: "3.0.0", State: &store.State, Now: func() time.Time { return at }}
	snap := func(sc *schema.Schema) *Snapshot {
		acc, rej := l.Accept(sc)
		if len(rej) != 0 {
			t.Fatalf("rejected %v", rej)
		}
		s, err := NewSnapshot(sc, nil, acc, files, at)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Version 1.3.0 boots.
	s2 := snap(sc2)
	if err := store.Install(s2); err != nil {
		t.Fatal(err)
	}
	if err := store.Booted(); err != nil {
		t.Fatal(err)
	}
	// Afterwards the lower version is rejected.
	if acc, rej := l.Accept(sc1); len(acc) != 0 || reasons(rej)["acme.core.app"] != ReasonRollback {
		t.Fatalf("rollback: %s %v", entryNames(acc), rej)
	}
	// A snapshot round-trips through its CBOR form and is verified.
	b, err := s2.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSnapshot(b)
	if err != nil || !bytes.Equal(back.SchemaHash, s2.SchemaHash) || len(back.Modules) != 1 || back.CreatedAt != at.Unix() {
		t.Fatalf("round trip: %v", err)
	}
	// A snapshot whose file bytes do not match is refused.
	bad := *back
	bad.Files = map[string][]byte{string(websign.FileHash(v2)): []byte("evil")}
	if err := bad.Verify(); err == nil {
		t.Fatal("tampered snapshot verified")
	}
	if err := store.Install(&bad); err == nil {
		t.Fatal("tampered snapshot installed")
	}
	// The one previous snapshot is kept for rollback: install a newer
	// one, and roll back to 1.3.0 before it boots.
	e3 := signedEntry(t, "acme.core.app", "1.4.0", "^3", v1, sf.root)
	s3 := snap(schemaWith(nil, facetWith(16, "acme.core", e3)))
	if err := store.Install(s3); err != nil {
		t.Fatal(err)
	}
	if err := store.RollBack(); err != nil || store.Current != s2 {
		t.Fatalf("rollback to the previous snapshot: %v", err)
	}
}

func TestParseTopLevel(t *testing.T) {
	t.Parallel()
	sf := loadSigning(t)
	m := func(kv ...any) []byte {
		b := cbor.AppendMapHead(nil, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			b = cbor.AppendRaw(cbor.AppendText(b, kv[i].(string)), kv[i+1].(cbor.Raw))
		}
		return b
	}
	good := m(AnnKeys, list(sf.certs[0]), AnnRevoked, sf.lists["revocation/list-3"], AnnApply, cbor.Raw(cbor.AppendText(nil, "reload")), "web.layout", cbor.Raw(cbor.AppendUint(nil, 1)))
	anns, err := ParseTopLevel(good, sf.roots)
	if err != nil || len(anns) != 4 {
		t.Fatalf("%v %v", anns, err)
	}
	for _, bad := range [][]byte{
		m("sparrow.x", cbor.Raw(cbor.AppendUint(nil, 1))),
		m(AnnModules, list()),
		m(AnnApply, cbor.Raw(cbor.AppendText(nil, "now"))),
		m(AnnRevoked, sf.lists["revocation/forged"]),
		m(AnnKeys, cbor.Raw(cbor.AppendUint(nil, 1))),
	} {
		if _, err := ParseTopLevel(bad, sf.roots); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}

func TestRanges(t *testing.T) {
	t.Parallel()
	cases := []struct {
		r  string
		in []string
		ex []string
	}{
		{"^3.1", []string{"3.1.0", "3.9.9"}, []string{"3.0.9", "4.0.0", "3.2.0-beta"}},
		{"^0.2.3", []string{"0.2.3", "0.2.9"}, []string{"0.3.0"}},
		{"~3.1", []string{"3.1.5"}, []string{"3.2.0"}},
		{">=3.0.0 <4", []string{"3.5.0"}, []string{"4.0.0", "2.9.9"}},
		{"3.x || 5", []string{"3.0.1", "5.2.0"}, []string{"4.0.0"}},
		{"*", []string{"1.0.0"}, nil},
		{"3.2.0-rc.1", []string{"3.2.0-rc.1"}, []string{"3.2.0"}},
	}
	for _, c := range cases {
		r, err := ParseRange(c.r)
		if err != nil {
			t.Fatalf("%s: %v", c.r, err)
		}
		for _, v := range c.in {
			if !r.Contains(v) {
				t.Errorf("%s should contain %s", c.r, v)
			}
		}
		for _, v := range c.ex {
			if r.Contains(v) {
				t.Errorf("%s should not contain %s", c.r, v)
			}
		}
	}
	if _, err := ParseRange("banana"); err == nil {
		t.Fatal("bad range parsed")
	}
}
