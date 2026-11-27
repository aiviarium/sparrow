# Browser end-to-end test

`client.html` and `sparrow-mini.js` are a minimal browser client (a few lines of CBOR and the
handshake, no library): `POST /sparrow/connect` for a ticket, then a WebTransport session pinned
with `serverCertificateHashes` and a WebSocket session (`sparrow.v1`), each with `Hello`, `Welcome`,
`Ready` and one unary call to the echo node.

```sh
e2e/browser/run.sh        # = SPARROW_BROWSER=1 go test -run TestBrowser -v ./cmd/sparrow-hub
```

`go/cmd/sparrow-hub/browser_test.go` starts the `sparrow-hub` binary with the Web Profile on (an
echo node that dials in and one the hub dials, both `examples/echo-node` processes; self-signed
10-day ECDSA certificate) and runs `run.cjs`, which
launches headless Chromium with Playwright (`require('playwright')`). The page is served from
`http://127.0.0.1` so it is a secure context in the same local address space as the hub: a page
whose address space Chromium cannot place (for example one fulfilled by request interception) has
its WebTransport and WebSocket connections to 127.0.0.1 refused with
`ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`.
