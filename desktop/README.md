# Sparrow Desktop (Wails v2 + Embedded Local Hub)

Runs the immutable `@aiviarium/sparrow-client` empty hull inside a native Wails desktop window backed by an **in-process local Sparrow hub** (`desktop/localhub`):

- **Local services:** Native Go services attach directly to the embedded hub (includes a built-in `desktop` facet with `annotations["app.locality"] = "local"`).
- **1-hop federation over WebTransport:** Configure one or more remote Sparrow hubs as peers; their facets appear as `<peer-id>/<facet>` and their signed `web.modules` are proxied, hash-verified, and cached on disk for offline reloads.
- **WebTransport + WebSocket:**
  - **Local hub ↔ remote hubs (Go ↔ Go):** Always uses HTTP/3 **WebTransport** (with SPKI pinning) on Linux, macOS, and Windows.
  - **WebView ↔ local hub (`127.0.0.1`):** Advertises both WebTransport (`serverCertificateHashes`) and WebSocket with a per-launch random bearer token. WebView2 (Windows/Chromium) connects over **WebTransport**; WebKitGTK (Linux) and WKWebView (macOS) automatically fall back to loopback WebSocket.

## Build & Run

```sh
# 1. Build JS client bundles and stage them into desktop/frontend/dist/vendor/
(cd ../ts && npm run build)
(cd ../client && npm run build)
node frontend/build.mjs

# 2. Run pure-Go localhub tests (no GTK/Wails required)
go test -v ./localhub

# 3. Build the Wails desktop binary (Linux with WebKitGTK 4.1)
go build -tags desktop,production,webkit2_41 -o sparrow-desktop .

# Or with Wails CLI (macOS / Windows / Linux):
wails dev
wails build
```

## Optional Config (`SPARROW_DESKTOP_CONFIG` or `~/.config/sparrow-desktop/config.json`)

```json
{
  "dataDir": "/path/to/data",
  "modulesDir": "/path/to/local-modules",
  "rootKeys": ["<64-char-hex-ed25519-pubkey>"],
  "peers": [
    {
      "id": "remote",
      "url": "https://hub.example.com:4433/sparrow/wt",
      "pin": "<64-char-hex-spki-sha256>",
      "credential": "<peer-link-credential>",
      "webBaseUrl": "https://hub.example.com"
    }
  ]
}
```
