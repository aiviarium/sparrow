// Real headless Chromium browser E2E test (set SPARROW_BROWSER=1 to run).
// Exercises the full browser runtime against real sparrow-hub, sparrow-admin,
// and echo-node processes:
//   - real window.fetch (CORS + Authorization), real WebCrypto Ed25519
//   - real HTTP/3 WebTransport (default, with serverCertificateHashes) + leased streams
//   - real WebSocket fallback when WebTransport is disabled
//   - real blob: URL ESM import() and hash-verified host.assets.url() CSS loading
//   - real IndexedDBSnapshotStore persistence + reload optimistic start
//   - live SchemaUpdate hot-dispose & hot-reload, plus Alice/Bob policy isolation
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { homedir, tmpdir } from 'node:os';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { cbor, sha256 } from '@aiviarium/sparrow';
import { encodeHash, fileHash } from '../src/index.js';
import { eventually } from './helpers.js';

const ROOT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const GO_DIR = join(ROOT_DIR, 'go');

function findChromium(): string | undefined {
  if (process.env.SPARROW_CHROMIUM && existsSync(process.env.SPARROW_CHROMIUM)) {
    return process.env.SPARROW_CHROMIUM;
  }
  const pwDir = join(homedir(), '.cache', 'ms-playwright');
  if (existsSync(pwDir)) {
    for (const d of readdirSync(pwDir).filter((x) => x.startsWith('chromium-')).sort().reverse()) {
      const candidate = join(pwDir, d, 'chrome-linux64', 'chrome');
      if (existsSync(candidate)) return candidate;
    }
  }
  for (const p of ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser']) {
    if (existsSync(p)) return p;
  }
  return undefined;
}

const chromeBin = findChromium();
const runBrowser = Boolean(process.env.SPARROW_BROWSER) && Boolean(chromeBin) && !process.env.SPARROW_SKIP_GO;

function keyPairFromSeed(seedByte: number) {
  const seed = new Uint8Array(32).fill(seedByte);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  const kid = sha256(pub).subarray(0, 16);
  return { priv, pub, kid };
}

function buildSignedModule(
  id: string,
  version: string,
  deps: string[],
  code: string,
  priv: ReturnType<typeof createPrivateKey>,
  kid: Uint8Array,
  assets: Array<{ path: string; hash: Uint8Array }> = [],
) {
  const bytes = new TextEncoder().encode(code);
  const hash = fileHash(bytes);
  const unsigned = {
    id,
    version,
    hash,
    url: `/sparrow/mods/${encodeHash(hash)}.js`,
    deps,
    hostApi: '^3.1',
    ...(assets.length ? { assets } : {}),
  };
  const sig = new Uint8Array(
    nodeSign(null, cbor.canonical(cbor.encode(['sparrow-module-v1', unsigned]), { noFloats: true }), priv),
  );
  return { bytes, hash, entry: { ...unsigned, sig: [kid, sig] } };
}

async function launchCDP(bin: string, profileDir: string) {
  const proc = spawn(
    bin,
    ['--headless=new', '--no-sandbox', '--disable-gpu', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`, 'about:blank'],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let wsUrl = '';
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('Chrome did not print DevTools URL')), 15_000);
    proc.stderr.on('data', (d) => {
      const m = d.toString().match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) {
        wsUrl = m[1];
        clearTimeout(t);
        resolve();
      }
    });
    proc.on('exit', (code) => {
      clearTimeout(t);
      reject(new Error(`Chrome exited early (${code})`));
    });
  });
  const port = new URL(wsUrl).port;
  const targets = (await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json())) as Array<{
    type: string;
    webSocketDebuggerUrl: string;
  }>;
  const page = targets.find((t) => t.type === 'page')!;
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise<void>((resolve) => {
    ws.onopen = () => resolve();
  });

  let seq = 0;
  const pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>();
  const errors: string[] = [];

  ws.onmessage = (ev) => {
    const msg = JSON.parse(String(ev.data));
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id)!;
      pending.delete(msg.id);
      if (msg.error) p.reject(new Error(msg.error.message));
      else p.resolve(msg.result);
      return;
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      const d = msg.params.exceptionDetails;
      errors.push(`${d.text} ${d.exception?.description ?? ''}`.trim());
    } else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
      errors.push(String(msg.params.entry.text));
    }
  };

  const send = (method: string, params: Record<string, unknown> = {}) => {
    const id = ++seq;
    ws.send(JSON.stringify({ id, method, params }));
    return new Promise<any>((resolve, reject) => pending.set(id, { resolve, reject }));
  };

  const evalJS = async <T = any>(expression: string): Promise<T> => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    }
    return r.result.value as T;
  };

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Log.enable');

  return {
    send,
    evalJS,
    errors,
    close() {
      ws.close();
      proc.kill('SIGTERM');
    },
  };
}

describe.skipIf(!runBrowser)('real Chromium browser E2E (WebTransport + WebSocket + IndexedDB + blob ESM)', () => {
  let workDir = '';
  let hubBin = '';
  let adminBin = '';
  let echoBin = '';
  const procs: ChildProcess[] = [];

  beforeAll(() => {
    workDir = mkdtempSync(join(tmpdir(), 'sparrow-browser-e2e-'));
    const binDir = join(workDir, 'bin');
    mkdirSync(binDir, { recursive: true });
    hubBin = join(binDir, 'sparrow-hub');
    adminBin = join(binDir, 'sparrow-admin');
    echoBin = join(binDir, 'echo-node');
    execFileSync('go', ['build', '-o', hubBin, './cmd/sparrow-hub'], { cwd: GO_DIR, stdio: 'inherit' });
    execFileSync('go', ['build', '-o', adminBin, './cmd/sparrow-admin'], { cwd: GO_DIR, stdio: 'inherit' });
    execFileSync('go', ['build', '-o', echoBin, './examples/echo-node'], { cwd: GO_DIR, stdio: 'inherit' });
  }, 180_000);

  afterAll(async () => {
    for (const p of procs) {
      if (!p.killed && p.exitCode === null) p.kill('SIGTERM');
    }
    await new Promise((r) => setTimeout(r, 200));
    for (const p of procs) {
      if (p.exitCode === null) p.kill('SIGKILL');
    }
    if (workDir) rmSync(workDir, { recursive: true, force: true });
  });

  it('connects over WebTransport by default, falls back to WebSocket, loads signed blob ESM + CSS assets, persists IndexedDB snapshots, and reconciles live SchemaUpdates', async () => {
    const { priv, pub, kid } = keyPairFromSeed(1);
    const modsDir = join(workDir, 'mods');
    const dataDir = join(workDir, 'data');
    mkdirSync(modsDir, { recursive: true });
    mkdirSync(dataDir, { recursive: true });

    const cssBytes = new TextEncoder().encode('.feat-badge { color: rgb(52, 211, 153); }\n');
    const cssHash = fileHash(cssBytes);
    writeFileSync(join(modsDir, 'feat.css'), cssBytes);

    const shellCode = `
      export default function register(host) {
        const root = host.shared.mount;
        root.innerHTML = '<div id="slots"></div>';
        const slots = root.querySelector('#slots');
        const map = new Map();
        host.provide('shell.ui', {
          add(id, html) {
            const el = document.createElement('div');
            el.dataset.mod = id;
            el.innerHTML = html;
            slots.appendChild(el);
            map.set(id, el);
            return () => { el.remove(); map.delete(id); };
          },
          count() { return map.size; },
        });
        host.onDispose(() => { root.innerHTML = ''; });
      }
    `;
    const featCode = `
      export default async function register(host) {
        const cssUrl = await host.assets.url('feat.css');
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = cssUrl;
        document.head.appendChild(link);
        const who = await host.session.call('feat', 'whoami');
        const rev = await host.session.call('feat', 'reverse', 'Sparrow');
        const remove = host.get('shell.ui').add(host.module.id, '<span class="feat-badge">' + who + ':' + rev + '</span>');
        host.onDispose(() => { remove(); link.remove(); });
      }
    `;

    const shellMod = buildSignedModule('shell.app', '1.0.0', [], shellCode, priv, kid);
    const featMod = buildSignedModule('feat.ui', '1.0.0', ['shell.app'], featCode, priv, kid, [{ path: 'feat.css', hash: cssHash }]);
    writeFileSync(join(modsDir, 'shell.app.js'), shellMod.bytes);
    writeFileSync(join(modsDir, 'feat.ui.js'), featMod.bytes);
    const shellCbor = join(workDir, 'shell.cbor');
    const featCbor = join(workDir, 'feat.cbor');
    writeFileSync(shellCbor, cbor.encode([shellMod.entry]));
    writeFileSync(featCbor, cbor.encode([featMod.entry]));

    const hubCfg = join(workDir, 'hub.json');
    const addrFile = join(workDir, 'addrs.json');
    writeFileSync(
      hubCfg,
      JSON.stringify({
        webtransport: '127.0.0.1:0',
        websocket: '127.0.0.1:0',
        websocketPlain: true,
        selfSigned: true,
        dataDir,
        bootstrap: [{ principal: 'user:admin', credential: 'admin-secret' }],
        tokens: [
          { token: 'alice-token', principal: 'user:alice', groups: ['group:all', 'group:beta'] },
          { token: 'bob-token', principal: 'user:bob', groups: ['group:all'] },
        ],
        web: { modulesDir: modsDir, rootKeys: [cbor.toHex(pub)], minHostApi: '3.0.0' },
        allowedOrigins: ['*'],
        log: 'warn',
      }),
    );

    procs.push(spawn(hubBin, ['-config', hubCfg, '-addr-file', addrFile], { stdio: 'ignore' }));
    await eventually(() => existsSync(addrFile), 'hub addr file', 15_000);
    const addrs = JSON.parse(readFileSync(addrFile, 'utf8')) as { websocket: string; webtransport: string; web: string };

    const runAdmin = (args: string[]) =>
      execFileSync(adminBin, ['-url', addrs.websocket, '-token', 'admin-secret', ...args], { encoding: 'utf8' });
    runAdmin(['set-secret', 'shell-cred', 'shell-secret']);
    runAdmin(['set-secret', 'feat-cred', 'feat-secret']);

    const commit = (featEnabled: boolean) => {
      const p = join(workDir, `doc-${Date.now()}.json`);
      writeFileSync(
        p,
        JSON.stringify({
          nodes: {
            shell: { link: { credential: 'shell-cred' } },
            feat: { link: { credential: 'feat-cred' }, enabled: featEnabled },
          },
          policy: [
            ['group:all', 'shell', 'use'],
            ['group:beta', 'feat', 'use'],
          ],
        }),
      );
      runAdmin(['commit', p]);
    };
    commit(true);

    procs.push(spawn(echoBin, ['-id', 'shell', '-hub', addrs.websocket, '-credential', 'shell-secret', '-web-modules', shellCbor, '-backoff', '50ms'], { stdio: 'ignore' }));
    procs.push(spawn(echoBin, ['-id', 'feat', '-hub', addrs.websocket, '-credential', 'feat-secret', '-web-modules', featCbor, '-backoff', '50ms'], { stdio: 'ignore' }));

    const html = `<!doctype html><html><head><meta charset="utf-8" />
      <script type="importmap">{"imports":{"@aiviarium/sparrow":"/ts/dist/index.js","@aiviarium/sparrow-client":"/client/dist/index.js"}}</script>
      </head><body><div id="mount"></div><script type="module">
        import { cbor } from '@aiviarium/sparrow';
        import { IndexedDBSnapshotStore, createHull } from '@aiviarium/sparrow-client';
        window.bootHull = async ({ token, storeName, disableWT }) => {
          if (window._hull) await window._hull.stop();
          const rootKey = cbor.fromHex(${JSON.stringify(cbor.toHex(pub))});
          const hull = createHull({
            baseUrl: ${JSON.stringify(addrs.web)},
            hostApi: '3.2.0',
            rootKeys: [rootKey],
            shared: { mount: document.getElementById('mount') },
            snapshotStore: new IndexedDBSnapshotStore(storeName),
            WebTransport: disableWT ? undefined : globalThis.WebTransport,
            connectTransport: disableWT
              ? async (ep, opts) => {
                  const { connectBrowserTransport } = await import('@aiviarium/sparrow-client');
                  return connectBrowserTransport({ websocket: ep.websocket }, opts);
                }
              : undefined,
            authorize: ({ headers }) => { headers.Authorization = 'Bearer ' + token; },
            reconnect: false,
          });
          window._hull = hull;
          await hull.start();
          return { binding: hull.state.binding, modules: hull.loadedModules().map((m) => m.id) };
        };
      </script></body></html>`;

    const MIME: Record<string, string> = { '.js': 'text/javascript', '.html': 'text/html', '.map': 'application/json' };
    const srv = http.createServer((req, res) => {
      const u = (req.url || '/').split('?')[0];
      if (u === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
      }
      if (u === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
      }
      if (u.startsWith('/ts/dist/') || u.startsWith('/client/dist/')) {
        const fp = join(ROOT_DIR, u);
        if (existsSync(fp)) {
          res.writeHead(200, { 'Content-Type': MIME[extname(fp)] ?? 'application/octet-stream' });
          res.end(readFileSync(fp));
          return;
        }
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const pagePort = (srv.address() as { port: number }).port;

    const cdp = await launchCDP(chromeBin!, join(workDir, 'chrome-profile'));
    try {
      await cdp.send('Page.navigate', { url: `http://127.0.0.1:${pagePort}/` });
      await new Promise((r) => setTimeout(r, 400));

      // 1. Alice connects over WebTransport (default) and boots shell.app + feat.ui + feat.css.
      const r1 = await cdp.evalJS<{ binding: string; modules: string[] }>(`window.bootHull({ token: 'alice-token', storeName: 'alice-db', disableWT: false })`);
      expect(r1.binding).toBe('webtransport');
      const waitText = async (substr: string) => {
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline) {
          const t = await cdp.evalJS<string>(`document.getElementById('mount').innerText`);
          if (t.includes(substr)) return t;
          await new Promise((r) => setTimeout(r, 100));
        }
        throw new Error(`timed out waiting for ${substr}`);
      };
      await waitText('user:alice:worrapS');
      const color = await cdp.evalJS<string>(`getComputedStyle(document.querySelector('.feat-badge')).color`);
      expect(color).toBe('rgb(52, 211, 153)');

      // 2. Disable feat on hub -> hot-dispose in browser.
      commit(false);
      {
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline) {
          const mods = await cdp.evalJS<string[]>(`window._hull.loadedModules().map((m) => m.id)`);
          if (mods.length === 1 && mods[0] === 'shell.app') break;
          await new Promise((r) => setTimeout(r, 100));
        }
        expect(await cdp.evalJS<string[]>(`window._hull.loadedModules().map((m) => m.id)`)).toEqual(['shell.app']);
      }

      // 3. Re-enable feat -> hot-reload in browser.
      commit(true);
      await waitText('user:alice:worrapS');

      // 4. Bob connects over WebSocket fallback -> only sees shell.app.
      const rBob = await cdp.evalJS<{ binding: string; modules: string[] }>(`window.bootHull({ token: 'bob-token', storeName: 'bob-db', disableWT: true })`);
      expect(rBob.binding).toBe('websocket');
      expect(rBob.modules).toEqual(['shell.app']);

      // 5. Alice reloads from IndexedDBSnapshotStore + optimistic start over WebTransport.
      const rReload = await cdp.evalJS<{ binding: string; modules: string[] }>(`window.bootHull({ token: 'alice-token', storeName: 'alice-db', disableWT: false })`);
      expect(rReload.binding).toBe('webtransport');
      expect(rReload.modules).toEqual(['shell.app', 'feat.ui']);

      expect(cdp.errors).toEqual([]);
    } finally {
      cdp.close();
      srv.close();
    }
  }, 60_000);
});
