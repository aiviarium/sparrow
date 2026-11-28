// Real headless Chromium browser stress test (set SPARROW_STRESS=1 to run).
// Not run in default CI (`npm test`). Exercises real browser WebTransport and
// WebSocket fallback through sparrow-hub to a dialed-in echo-node under heavy
// file transfers and concurrency:
//   - 32 MiB file upload + 32 MiB file download while firing 50 concurrent UI RPCs
//   - 8 concurrent 4 MiB downloads + 20 concurrent RPCs (leased-stream pooling)
//   - 10 mid-flight cancelled 16 MiB downloads + health check afterward
//   - Zero uncaught page/console errors
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
const runStress = Boolean(process.env.SPARROW_STRESS) && Boolean(chromeBin) && !process.env.SPARROW_SKIP_GO;

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
  code: string,
  priv: ReturnType<typeof createPrivateKey>,
  kid: Uint8Array,
) {
  const bytes = new TextEncoder().encode(code);
  const hash = fileHash(bytes);
  const unsigned = {
    id,
    version,
    hash,
    url: `/sparrow/mods/${encodeHash(hash)}.js`,
    deps: [],
    hostApi: '^3.1',
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

  let nextId = 1;
  const pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();
  const errors: string[] = [];

  ws.onmessage = (ev) => {
    const msg = JSON.parse(String(ev.data));
    if (msg.id) {
      const p = pending.get(msg.id);
      if (p) {
        pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error.message));
        else p.resolve(msg.result);
      }
      return;
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      errors.push(`exception: ${msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text}`);
    } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      errors.push(`console.error: ${msg.params.args.map((a: any) => a.value ?? a.description).join(' ')}`);
    }
  };

  const cdp = (method: string, params: Record<string, unknown> = {}) =>
    new Promise<any>((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });

  await cdp('Runtime.enable');
  await cdp('Page.enable');

  const evalJS = async <T = any>(expression: string): Promise<T> => {
    const r = await cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    }
    return r.result.value as T;
  };

  return {
    cdp,
    evalJS,
    errors,
    async close() {
      try { ws.close(); } catch { /* ignore */ }
      try { proc.kill('SIGKILL'); } catch { /* ignore */ }
    },
  };
}

describe.skipIf(!runStress)('real Chromium browser stress test (file transfers + concurrency)', () => {
  let tmp: string;
  let hubProc: ChildProcess;
  let filesProc: ChildProcess;
  let httpSrv: http.Server;
  let uiPort: number;
  let hubHttpUrl: string;
  let chrome: Awaited<ReturnType<typeof launchCDP>>;

  beforeAll(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'sparrow-stress-'));
    const binDir = join(tmp, 'bin');
    const storeDir = join(tmp, 'store');
    const modsDir = join(tmp, 'mods');
    const profileDir = join(tmp, 'chrome-profile');
    mkdirSync(binDir, { recursive: true });
    mkdirSync(storeDir, { recursive: true });
    mkdirSync(modsDir, { recursive: true });
    mkdirSync(profileDir, { recursive: true });

    const hubBin = join(binDir, 'sparrow-hub');
    const adminBin = join(binDir, 'sparrow-admin');
    const echoBin = join(binDir, 'echo-node');
    execFileSync('go', ['build', '-o', hubBin, './cmd/sparrow-hub'], { cwd: GO_DIR, stdio: 'pipe' });
    execFileSync('go', ['build', '-o', adminBin, './cmd/sparrow-admin'], { cwd: GO_DIR, stdio: 'pipe' });
    execFileSync('go', ['build', '-o', echoBin, './examples/echo-node'], { cwd: GO_DIR, stdio: 'pipe' });

    const root = keyPairFromSeed(0x31);
    const stressMod = buildSignedModule(
      'files.app',
      '1.0.0',
      `export default function register(host) {
        window.__stressHost = host;
        host.onDispose(() => { window.__stressHost = null; });
      }`,
      root.priv,
      root.kid,
    );
    writeFileSync(join(modsDir, `${encodeHash(stressMod.hash)}.js`), stressMod.bytes);
    writeFileSync(join(tmp, 'files-mods.cbor'), cbor.encode([stressMod.entry]));

    // Start static server for the hull page + dist bundles.
    httpSrv = http.createServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
      }
      if (urlPath === '/' || urlPath === '/index.html') {
        const rootHex = Buffer.from(root.pub).toString('hex');
        const html = `<!doctype html><html><body><script type="importmap">
{"imports":{"@aiviarium/sparrow":"/sparrow/index.js","@aiviarium/sparrow/websocket":"/sparrow/transport/websocket.js","@aiviarium/sparrow/webtransport":"/sparrow/transport/webtransport.js","@aiviarium/sparrow-client":"/client/index.js"}}
</script><script type="module">
import { createHull } from '@aiviarium/sparrow-client';
const hexToBytes = (h) => { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i*2, i*2+2), 16); return b; };
window.__rootKey = hexToBytes('${rootHex}');
window.__hubUrl = '${hubHttpUrl}';
window.__hull = null;
window.__origWT = window.WebTransport;
window.__connect = async (mode) => {
  if (window.__hull) { await window.__hull.stop(); window.__hull = null; }
  if (mode === 'ws') { window.WebTransport = undefined; } else { window.WebTransport = window.__origWT; }
  const h = createHull({
    baseUrl: window.__hubUrl,
    rootKeys: [window.__rootKey],
    authorize: ({ headers }) => { headers.Authorization = 'Bearer alice-tok'; },
    hostApi: '3.1.0',
    reconnect: false,
  });
  window.__hull = h;
  await h.start();
  return h.state.binding;
};
window.__ready = true;
</script></body></html>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
      }
      let filePath = '';
      if (urlPath.startsWith('/sparrow/')) filePath = join(ROOT_DIR, 'ts', 'dist', urlPath.slice('/sparrow/'.length));
      else if (urlPath.startsWith('/client/')) filePath = join(ROOT_DIR, 'client', 'dist', urlPath.slice('/client/'.length));
      if (!filePath || !existsSync(filePath)) {
        res.writeHead(404);
        res.end('not found');
        return;
      }
      const ct = extname(filePath) === '.js' ? 'application/javascript; charset=utf-8' : 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': ct });
      res.end(readFileSync(filePath));
    });
    await new Promise<void>((resolve) => httpSrv.listen(0, '127.0.0.1', () => resolve()));
    uiPort = (httpSrv.address() as { port: number }).port;

    const addrFile = join(tmp, 'addrs.json');
    const hubCfg = {
      webtransport: '127.0.0.1:0',
      websocket: '127.0.0.1:0',
      websocketPlain: true,
      selfSigned: true,
      dataDir: storeDir,
      bootstrap: [{ principal: 'user:admin', credential: 'admin-tok' }],
      tokens: [{ token: 'alice-tok', principal: 'user:alice' }],
      web: { modulesDir: modsDir, rootKeys: [cbor.toHex(root.pub)], minHostApi: '3.0.0' },
      allowedOrigins: ['*'],
      log: 'warn',
    };
    const cfgPath = join(tmp, 'hub.json');
    writeFileSync(cfgPath, JSON.stringify(hubCfg, null, 2));

    hubProc = spawn(hubBin, ['-config', cfgPath, '-addr-file', addrFile], { stdio: 'ignore' });
    await eventually(() => existsSync(addrFile), 'hub addr file', 15_000);
    const addrs = JSON.parse(readFileSync(addrFile, 'utf8')) as { websocket: string; webtransport: string; web: string; pin: string };
    hubHttpUrl = addrs.web;

    const runAdmin = (args: string[]) =>
      execFileSync(adminBin, ['-url', addrs.websocket, '-token', 'admin-tok', ...args], { encoding: 'utf8' });
    runAdmin(['set-secret', 'files-sec', 'files-cred']);
    const docPath = join(tmp, 'doc.json');
    writeFileSync(
      docPath,
      JSON.stringify({
        nodes: { files: { link: { credential: 'files-sec' } } },
        policy: [['user:alice', 'files', 'use']],
      }),
    );
    runAdmin(['commit', docPath]);

    filesProc = spawn(
      echoBin,
      ['-id', 'files', '-hub', addrs.websocket, '-credential', 'files-cred', '-web-modules', join(tmp, 'files-mods.cbor'), '-backoff', '50ms'],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    let filesErr = '';
    filesProc.stderr!.on('data', (d) => { filesErr += d.toString(); });

    chrome = await launchCDP(chromeBin!, profileDir);
    await chrome.cdp('Page.navigate', { url: `http://127.0.0.1:${uiPort}/` });
    for (let i = 0; i < 100; i++) {
      if (await chrome.evalJS<boolean>('Boolean(window.__ready)')) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    const t0 = await chrome.evalJS<string>(`window.__connect('wt')`);
    expect(t0).toBe('webtransport');
    let hasFiles = false;
    for (let i = 0; i < 100; i++) {
      if (await chrome.evalJS<boolean>(`Boolean(window.__hull?.session?.peerFacet('files'))`)) {
        hasFiles = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    if (!hasFiles) throw new Error(`files facet not present (echo-node stderr: ${filesErr})`);
  }, 60_000);

  afterAll(async () => {
    if (chrome) await chrome.close();
    try { filesProc?.kill('SIGTERM'); } catch { /* ignore */ }
    try { hubProc?.kill('SIGTERM'); } catch { /* ignore */ }
    try { httpSrv?.close(); } catch { /* ignore */ }
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  for (const mode of ['wt', 'ws'] as const) {
    it(`streams 32 MiB upload/download + concurrent UI RPCs + burst + cancel storm over ${mode === 'wt' ? 'WebTransport' : 'WebSocket'}`, async () => {
      const transport = await chrome.evalJS<string>(`window.__connect('${mode}')`);
      expect(transport).toBe(mode === 'wt' ? 'webtransport' : 'websocket');

      const report = await chrome.evalJS<{
        dlBytes: number;
        dlMs: number;
        dlPings: number;
        dlPingP95: number;
        ulBytes: number;
        ulMs: number;
        ulPings: number;
        ulPingP95: number;
        burstTotal: number;
        burstRpcs: number;
        burstMs: number;
        cancelAlive: string;
      }>(`(async () => {
        const sess = window.__hull.session;
        if (!sess.peerFacet('files')) throw new Error('files facet not present');
        const SIZE = 32 * 1024 * 1024;
        const p95 = (arr) => {
          if (!arr.length) return 0;
          const s = [...arr].sort((a, b) => a - b);
          return Math.round(s[Math.floor((s.length - 1) * 0.95)] * 10) / 10;
        };

        async function runWithConcurrentPings(fn) {
          let running = true;
          const lats = [];
          const pinger = (async () => {
            let i = 0;
            while (running && i < 50) {
              const t0 = performance.now();
              const r = await sess.call('files', 'echo', 'ping-' + i);
              if (r !== 'ping-' + i) throw new Error('bad ping reply: ' + r);
              lats.push(performance.now() - t0);
              i++;
              await new Promise((res) => setTimeout(res, 10));
            }
          })();
          const t0 = performance.now();
          const res = await fn();
          const ms = performance.now() - t0;
          running = false;
          await pinger;
          return { res, ms, pings: lats.length, p95: p95(lats) };
        }

        // 1. 32 MiB download with concurrent UI RPCs
        const dl = await runWithConcurrentPings(async () => {
          const call = sess.open('files', 'download', SIZE);
          let got = 0;
          for await (const chunk of call.byteChunks(0)) got += chunk.byteLength;
          await call.result();
          return got;
        });

        // 2. 32 MiB upload with concurrent UI RPCs
        const ul = await runWithConcurrentPings(async () => {
          const call = sess.open('files', 'upload', null);
          const block = new Uint8Array(256 * 1024);
          let left = SIZE;
          while (left > 0) {
            const k = Math.min(left, block.byteLength);
            await call.sendBytes(0, k === block.byteLength ? block : block.subarray(0, k), left === k);
            left -= k;
          }
          await call.end();
          return await call.result();
        });

        // 3. Burst: 8 concurrent 4 MiB downloads + 20 concurrent RPCs
        const bt0 = performance.now();
        const dlPromises = Array.from({ length: 8 }, async () => {
          const call = sess.open('files', 'download', 4 * 1024 * 1024);
          let got = 0;
          for await (const chunk of call.byteChunks(0)) got += chunk.byteLength;
          await call.result();
          return got;
        });
        const rpcPromises = Array.from({ length: 20 }, (_, i) =>
          sess.call('files', 'echo', 'burst-' + i).then((r) => {
            if (r !== 'burst-' + i) throw new Error('bad burst reply');
            return 1;
          }),
        );
        const [dls, rpcs] = await Promise.all([Promise.all(dlPromises), Promise.all(rpcPromises)]);
        const burstMs = performance.now() - bt0;

        // 4. Cancel storm: 10 concurrent 16 MiB downloads cancelled after 256 KiB
        await Promise.all(Array.from({ length: 10 }, async () => {
          const call = sess.open('files', 'download', 16 * 1024 * 1024);
          let got = 0;
          try {
            for await (const chunk of call.byteChunks(0)) {
              got += chunk.byteLength;
              if (got >= 256 * 1024) {
                call.cancel();
                break;
              }
            }
          } catch {
            // expected on cancel
          }
          try { await call.result(); } catch { /* expected */ }
        }));

        const cancelAlive = await sess.call('files', 'echo', 'still-alive');
        return {
          dlBytes: dl.res,
          dlMs: Math.round(dl.ms),
          dlPings: dl.pings,
          dlPingP95: dl.p95,
          ulBytes: ul.res,
          ulMs: Math.round(ul.ms),
          ulPings: ul.pings,
          ulPingP95: ul.p95,
          burstTotal: dls.reduce((a, b) => a + b, 0),
          burstRpcs: rpcs.length,
          burstMs: Math.round(burstMs),
          cancelAlive,
        };
      })()`);

      const dlMBs = (32 / (report.dlMs / 1000)).toFixed(1);
      const ulMBs = (32 / (report.ulMs / 1000)).toFixed(1);
      const burstMBs = (32 / (report.burstMs / 1000)).toFixed(1);
      console.log(
        `[browser stress ${transport}] ` +
          `download 32 MiB: ${report.dlMs}ms (${dlMBs} MiB/s, ${report.dlPings} pings p95=${report.dlPingP95}ms) | ` +
          `upload 32 MiB: ${report.ulMs}ms (${ulMBs} MiB/s, ${report.ulPings} pings p95=${report.ulPingP95}ms) | ` +
          `8x4 MiB burst + 20 RPCs: ${report.burstMs}ms (${burstMBs} MiB/s)`,
      );

      expect(report.dlBytes).toBe(32 * 1024 * 1024);
      expect(report.ulBytes).toBe(32 * 1024 * 1024);
      expect(report.burstTotal).toBe(32 * 1024 * 1024);
      expect(report.burstRpcs).toBe(20);
      expect(report.cancelAlive).toBe('still-alive');
      expect(chrome.errors).toEqual([]);
    }, 120_000);
  }
});
