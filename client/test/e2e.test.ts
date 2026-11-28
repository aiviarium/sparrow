// End-to-end test against real sparrow-hub, sparrow-admin, and echo-node processes:
// - Hub starts with Web Profile enabled, root keys, and two concurrent users (alice & bob).
// - Dial-in node "shell" ships a signed primary shell module ("shell.app") providing a UI registry capability.
// - Both alice and bob connect concurrently with Hull and boot "shell.app".
// - Dynamically register & dial in a second node "feat" via sparrow.hub.admin shipping "feat.ui" (deps: ["shell.app"]).
// - alice receives SchemaUpdate, fetches/verifies/loads "feat.ui" over HTTP, registers a contribution into "shell.app",
//   and executes an RPC call to backend node "feat". bob (no grant on "feat") does not see or load "feat.ui".
// - Disabling "feat" via sparrow.hub.admin cleanly disposes "feat.ui" and removes its UI contribution on alice.
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { cbor, sha256 } from '@aiviarium/sparrow';
import {
  createHull,
  encodeHash,
  fileHash,
  type ModuleEntry,
  type ModuleImporter,
} from '../src/index.js';
import { eventually } from './helpers.js';

const ROOT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const GO_DIR = join(ROOT_DIR, 'go');
const skip = Boolean(process.env.SPARROW_SKIP_GO);

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
  };
  const sig = new Uint8Array(
    nodeSign(null, cbor.canonical(cbor.encode(['sparrow-module-v1', unsigned]), { noFloats: true }), priv),
  );
  return { bytes, hash, entry: { ...unsigned, sig: [kid, sig] } };
}

const dataUrlImporter: ModuleImporter = async (_entry: ModuleEntry, bytes: Uint8Array) => {
  const url = `data:text/javascript;base64,${Buffer.from(bytes).toString('base64')}`;
  return (await import(url)) as { default: any };
};

describe.skipIf(skip)('E2E with sparrow-hub, sparrow-admin, and echo-node', () => {
  let workDir = '';
  let hubBin = '';
  let adminBin = '';
  let echoBin = '';
  const procs: ChildProcess[] = [];

  beforeAll(() => {
    workDir = mkdtempSync(join(tmpdir(), 'sparrow-client-e2e-'));
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
      if (!p.killed && p.exitCode === null) {
        p.kill('SIGTERM');
      }
    }
    await new Promise((r) => setTimeout(r, 200));
    for (const p of procs) {
      if (p.exitCode === null) p.kill('SIGKILL');
    }
    if (workDir) rmSync(workDir, { recursive: true, force: true });
  });

  function spawnManaged(bin: string, args: string[]): { proc: ChildProcess; stderr: () => string } {
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let errLog = '';
    child.stderr?.on('data', (d) => {
      errLog += d.toString();
    });
    procs.push(child);
    return { proc: child, stderr: () => errLog };
  }

  function runAdmin(wsUrl: string, args: string[]): string {
    return execFileSync(adminBin, ['-url', wsUrl, '-token', 'admin-secret', ...args], {
      encoding: 'utf8',
    });
  }

  it('hosts primary shell module + dynamically dialed feature module for multiple concurrent users', async () => {
    const { priv, pub, kid } = keyPairFromSeed(1);
    const modsDir = join(workDir, 'mods');
    const dataDir = join(workDir, 'data');
    mkdirSync(modsDir, { recursive: true });
    mkdirSync(dataDir, { recursive: true });

    // 1. Primary shell module ("shell.app"): exposes a framework-agnostic UI contribution registry via host.provide.
    const shellCode = `
      export default function register(host) {
        const contributions = new Map();
        const registry = {
          add(id, data) {
            contributions.set(id, data);
            return () => contributions.delete(id);
          },
          list() {
            return Array.from(contributions.entries());
          },
          principal: host.shared.userLabel,
        };
        host.provide('shell.ui', registry);
      }
    `;
    const shellMod = buildSignedModule('shell.app', '1.0.0', [], shellCode, priv, kid);
    writeFileSync(join(modsDir, 'shell.app.js'), shellMod.bytes);
    const shellCborPath = join(workDir, 'shell-modules.cbor');
    writeFileSync(shellCborPath, cbor.encode([shellMod.entry]));

    // 2. Feature module ("feat.ui"): depends on "shell.app", calls its own backend facet ("feat:echo"),
    //    and registers a contribution into "shell.ui".
    const featCode = `
      export default async function register(host) {
        const reply = await host.session.call('feat', 'echo', 'hello-from-' + host.shared.userLabel);
        const ui = host.get('shell.ui');
        if (!ui) throw new Error('shell.ui capability missing');
        const remove = ui.add(host.module.id, { reply, facet: host.module.facet });
        host.onDispose(() => remove());
      }
    `;
    const featMod = buildSignedModule('feat.ui', '1.0.0', ['shell.app'], featCode, priv, kid);
    writeFileSync(join(modsDir, 'feat.ui.js'), featMod.bytes);
    const featCborPath = join(workDir, 'feat-modules.cbor');
    writeFileSync(featCborPath, cbor.encode([featMod.entry]));

    // 3. Start sparrow-hub with plain HTTP/WebSocket listener and Web Profile enabled.
    const hubCfgPath = join(workDir, 'hub.json');
    const addrPath = join(workDir, 'addrs.json');
    writeFileSync(
      hubCfgPath,
      JSON.stringify({
        websocket: '127.0.0.1:0',
        websocketPlain: true,
        dataDir,
        bootstrap: [{ principal: 'user:admin', credential: 'admin-secret' }],
        tokens: [
          { token: 'alice-token', principal: 'user:alice', groups: ['group:all', 'group:beta'] },
          { token: 'bob-token', principal: 'user:bob', groups: ['group:all'] },
        ],
        web: {
          modulesDir: modsDir,
          rootKeys: [cbor.toHex(pub)],
          minHostApi: '3.0.0',
        },
        allowedOrigins: ['*'],
        log: 'warn',
        shutdownGraceMs: 2000,
        connectTimeoutMs: 5000,
      }),
    );

    const hubProc = spawnManaged(hubBin, ['-config', hubCfgPath, '-addr-file', addrPath]);
    await eventually(() => {
      try {
        JSON.parse(readFileSync(addrPath, 'utf8'));
        return true;
      } catch {
        return false;
      }
    }, `sparrow-hub addr file (${hubProc.stderr()})`, 15_000);

    const addrs = JSON.parse(readFileSync(addrPath, 'utf8')) as { websocket: string; web: string };

    // 4. Configure secrets and initial node "shell" (visible to group:all).
    runAdmin(addrs.websocket, ['set-secret', 'shell-cred', 'shell-secret']);
    runAdmin(addrs.websocket, ['set-secret', 'feat-cred', 'feat-secret']);

    const doc1Path = join(workDir, 'doc1.json');
    writeFileSync(
      doc1Path,
      JSON.stringify({
        nodes: {
          shell: { link: { credential: 'shell-cred' } },
        },
        policy: [
          ['group:all', 'shell', 'use'],
          ['group:beta', 'feat', 'use'],
        ],
      }),
    );
    const commit1 = JSON.parse(runAdmin(addrs.websocket, ['commit', '-confirm-within', '10000', '-confirm', doc1Path]));
    expect(commit1.revision).toBe(1);

    // Start "shell" dial-in node.
    spawnManaged(echoBin, [
      '-id', 'shell',
      '-hub', addrs.websocket,
      '-credential', 'shell-secret',
      '-web-modules', shellCborPath,
      '-backoff', '50ms',
      '-backoff-max', '200ms',
    ]);

    // 5. Connect two concurrent users via Hull (alice & bob).
    const makeUserHull = (token: string, label: string) =>
      createHull({
        baseUrl: addrs.web,
        hostApi: '3.2.0',
        rootKeys: [pub],
        shared: { userLabel: label },
        authorize: ({ headers }) => {
          headers.Authorization = `Bearer ${token}`;
        },
        WebSocket: WebSocket as unknown as new (url: string, p?: string | string[]) => any,
        importer: dataUrlImporter,
        reconnect: false,
      });

    // Wait until hub lists the shell node before booting clients (or hull handles SchemaUpdate dynamically too).
    const alice = makeUserHull('alice-token', 'alice');
    const bob = makeUserHull('bob-token', 'bob');

    await Promise.all([alice.start(), bob.start()]);

    await eventually(
      () => alice.loadedModules().some((m) => m.id === 'shell.app') && bob.loadedModules().some((m) => m.id === 'shell.app'),
      'both users booted shell.app',
      15_000,
    );

    const aliceShell = alice.capabilities.get<{ list(): Array<[string, any]> }>('shell.ui')!;
    const bobShell = bob.capabilities.get<{ list(): Array<[string, any]> }>('shell.ui')!;
    expect(aliceShell.list()).toEqual([]);
    expect(bobShell.list()).toEqual([]);

    // 6. Dynamically install a new feature node "feat" via sparrow.hub.admin and dial it in.
    const doc2Path = join(workDir, 'doc2.json');
    writeFileSync(
      doc2Path,
      JSON.stringify({
        nodes: {
          shell: { link: { credential: 'shell-cred' } },
          feat: { link: { credential: 'feat-cred' } },
        },
        policy: [
          ['group:all', 'shell', 'use'],
          ['group:beta', 'feat', 'use'],
        ],
      }),
    );
    const commit2 = JSON.parse(runAdmin(addrs.websocket, ['commit', '-confirm-within', '10000', '-confirm', doc2Path]));
    expect(commit2.revision).toBe(2);

    spawnManaged(echoBin, [
      '-id', 'feat',
      '-hub', addrs.websocket,
      '-credential', 'feat-secret',
      '-web-modules', featCborPath,
      '-backoff', '50ms',
      '-backoff-max', '200ms',
    ]);

    // alice (in group:beta) receives SchemaUpdate, fetches/verifies feat.ui, runs RPC to feat, and registers UI contribution.
    await eventually(() => aliceShell.list().length === 1, 'alice feat.ui registered into shell.ui', 15_000);
    expect(alice.loadedModules().map((m) => m.id)).toEqual(['shell.app', 'feat.ui']);
    expect(aliceShell.list()).toEqual([['feat.ui', { reply: 'hello-from-alice', facet: 'feat' }]]);

    // bob (not in group:beta) must NOT see or load feat.ui.
    expect(bob.loadedModules().map((m) => m.id)).toEqual(['shell.app']);
    expect(bobShell.list()).toEqual([]);

    // 7. Disable "feat" via sparrow.hub.admin -> alice cleanly disposes feat.ui and removes its contribution.
    const doc3Path = join(workDir, 'doc3.json');
    writeFileSync(
      doc3Path,
      JSON.stringify({
        nodes: {
          shell: { link: { credential: 'shell-cred' } },
          feat: { link: { credential: 'feat-cred' }, enabled: false },
        },
        policy: [
          ['group:all', 'shell', 'use'],
          ['group:beta', 'feat', 'use'],
        ],
      }),
    );
    runAdmin(addrs.websocket, ['commit', doc3Path]);

    await eventually(() => alice.loadedModules().length === 1, 'alice feat.ui disposed on disable', 15_000);
    expect(alice.loadedModules().map((m) => m.id)).toEqual(['shell.app']);
    expect(aliceShell.list()).toEqual([]);

    await Promise.all([alice.stop(), bob.stop()]);
  }, 60_000);
});
