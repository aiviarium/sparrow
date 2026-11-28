import { describe, expect, it } from 'vitest';
import {
  FacetBuilder,
  Session,
  Status,
  T,
  cbor,
  makeSchema,
  memPair,
  schema as spSchema,
  sha256,
} from '@aiviarium/sparrow';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import {
  MemorySnapshotStore,
  createHull,
  createSnapshot,
  decodeModuleEntry,
  encodeHash,
  fileHash,
  type FetchLike,
  type ModuleFactory,
  type ModuleHost,
  type ModuleImporter,
} from '../src/index.js';
import { eventually } from './helpers.js';

function rootKeys() {
  const seed = new Uint8Array(32).fill(9);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  const kid = sha256(pub).subarray(0, 16);
  return { priv, pub, kid };
}

function makeSignedModule(
  id: string,
  version: string,
  deps: string[] = [],
  extra: Record<string, unknown> = {},
) {
  const { priv, kid } = rootKeys();
  const code = `// ${id}@${version}`;
  const bytes = new TextEncoder().encode(code);
  const hash = fileHash(bytes);
  const unsigned = {
    id,
    version,
    hash,
    url: `/sparrow/mods/${encodeHash(hash)}.js`,
    deps,
    hostApi: '^3.1',
    ...extra,
  };
  const sig = new Uint8Array(nodeSign(null, cbor.canonical(cbor.encode(['sparrow-module-v1', unsigned]), { noFloats: true }), priv));
  return {
    id,
    version,
    bytes,
    hash,
    rawEntry: { ...unsigned, sig: [kid, sig] },
  };
}

function buildTestServer(initialFacets: ReturnType<FacetBuilder['build']>[], topAnn: Record<string, unknown> = {}) {
  const webF = spSchema.webFacet();
  let currentSchema = makeSchema('app', '1.0.0', [webF, ...initialFacets], topAnn);
  const files = new Map<string, Uint8Array>();
  const rejectedReports: Array<string[]> = [];
  const authRefreshCalls: string[] = [];
  let activeSrv: Session | undefined;
  let ticketCounter = 0;

  const fetchMock: FetchLike = async (url, init) => {
    const headers = { get: () => null };
    if (url.endsWith('/sparrow/connect')) {
      const body = JSON.parse(init?.body ?? '{}');
      if (body.refresh) {
        return {
          ok: true,
          status: 200,
          headers,
          text: async () => '',
          json: async () => ({ ticket: `refreshed-${++ticketCounter}` }),
          arrayBuffer: async () => new ArrayBuffer(0),
        };
      }
      const scHash = spSchema.schemaHash(currentSchema);
      return {
        ok: true,
        status: 200,
        headers,
        text: async () => '',
        json: async () => ({
          ticket: `ticket-${++ticketCounter}`,
          ticketExpiresAt: '2026-11-28T20:00:00Z',
          sessionExpiresAt: '2026-11-29T04:00:00Z',
          endpoints: { websocket: 'wss://mock.local/sparrow/ws' },
          protocolVersions: [1],
          schemaHash: encodeHash(scHash),
          schemaUrl: `/sparrow/schema/${encodeHash(scHash)}`,
          serverCertificateHashes: null,
        }),
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    }
    if (url.includes('/sparrow/mods/')) {
      const name = url.split('/sparrow/mods/')[1];
      const hs = name.split('.')[0];
      const bytes = files.get(hs);
      if (!bytes) {
        return { ok: false, status: 404, headers, text: async () => 'not found', json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
      }
      return { ok: true, status: 200, headers, text: async () => '', json: async () => ({}), arrayBuffer: async () => bytes.slice().buffer };
    }
    return { ok: false, status: 404, headers, text: async () => 'not found', json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
  };

  // Helper so Session.accept runs concurrently with Session.connect:
  const connectTransportConcurrent = async () => {
    const [cliConn, srvConn] = memPair();
    const srvPromise = Session.accept(srvConn, {
      schema: currentSchema,
      props: { appName: 'Sparrow Test' },
      handlers: {
        'sparrow.web': {
          moduleRejected: (args: string[]) => {
            rejectedReports.push(args);
          },
        },
        'feat.notes': {
          list: () => ['note-1', 'note-2'],
        },
      },
      onAuthRefresh: (_s, auth) => {
        authRefreshCalls.push(String(auth.credentials));
        return Math.floor(Date.now() / 1000) + 3600;
      },
    });
    void srvPromise.then((s) => {
      activeSrv = s;
    });
    return { conn: cliConn, binding: 'websocket' as const, endpoint: 'wss://mock.local/sparrow/ws' };
  };

  return {
    files,
    rejectedReports,
    authRefreshCalls,
    fetchMock,
    connectTransport: connectTransportConcurrent,
    get session() {
      return activeSrv;
    },
    async updateSchema(nextFacets: ReturnType<FacetBuilder['build']>[], nextTopAnn: Record<string, unknown> = {}) {
      currentSchema = makeSchema('app', '1.0.0', [webF, ...nextFacets], nextTopAnn);
      if (activeSrv) await activeSrv.updateSchema(currentSchema);
    },
    addFile(hash: Uint8Array, bytes: Uint8Array) {
      files.set(encodeHash(hash), bytes);
    },
    async closeServer() {
      if (activeSrv) await activeSrv.close();
    },
  };
}

describe('Hull empty shell & module lifecycle', () => {
  it('boots primary shell module + dependent feature modules, handles hot add/remove and RPC', async () => {
    const { pub } = rootKeys();
    const shellMod = makeSignedModule('shell.app', '1.0.0');
    const notesMod = makeSignedModule('feat.notes.ui', '1.0.0', ['shell.app']);

    const shellFacet = new FacetBuilder('shell.app', '1.0.0', {
      id: 16,
      annotations: { 'web.modules': [shellMod.rawEntry] },
    }).build();

    const notesFb = new FacetBuilder('feat.notes', '1.0.0', {
      id: 17,
      annotations: { 'web.modules': [notesMod.rawEntry] },
    });
    notesFb.service('Notes').method('list', T.unit, [0, T.string]);
    const notesFacet = notesFb.build();

    const srv = buildTestServer([shellFacet]);
    srv.addFile(shellMod.hash, shellMod.bytes);
    srv.addFile(notesMod.hash, notesMod.bytes);

    const events: string[] = [];
    const contributions = new Map<string, { items: string[] }>();

    const factories: Record<string, ModuleFactory> = {
      'shell.app': (host: ModuleHost) => {
        events.push(`boot:${host.module.id}`);
        expect(host.shared.solid).toBe('solid2-mock');
        expect(host.props.appName).toBe('Sparrow Test');
        const api = {
          registerItem(id: string, items: string[]) {
            contributions.set(id, { items });
            return () => contributions.delete(id);
          },
        };
        host.provide('shell.ui', api);
        return () => {
          events.push(`dispose:${host.module.id}`);
        };
      },
      'feat.notes.ui': async (host: ModuleHost) => {
        events.push(`boot:${host.module.id}`);
        const items = (await host.session!.call('feat.notes', 'list')) as string[];
        const ui = host.get<{ registerItem(id: string, items: string[]): () => void }>('shell.ui')!;
        expect(ui).toBeDefined();
        const stop = ui.registerItem(host.module.id, items);
        host.onDispose(() => {
          stop();
          events.push(`dispose:${host.module.id}`);
        });
      },
    };

    const importer: ModuleImporter = async (entry) => factories[entry.id];

    const hull = createHull({
      baseUrl: 'https://mock.local',
      hostApi: '3.2.0',
      rootKeys: [pub],
      shared: { solid: 'solid2-mock' },
      fetch: srv.fetchMock,
      connectTransport: srv.connectTransport,
      importer,
      reconnect: false,
    });

    await hull.start();
    expect(hull.loadedModules().map((m) => m.id)).toEqual(['shell.app']);
    expect(events).toEqual(['boot:shell.app']);

    // Dynamically dial in feat.notes -> SchemaUpdate arrives -> feat.notes.ui loads after shell.app.
    await srv.updateSchema([shellFacet, notesFacet]);
    await eventually(() => hull.loadedModules().length === 2, 'feat.notes.ui loaded');
    expect(contributions.get('feat.notes.ui')).toEqual({ items: ['note-1', 'note-2'] });

    // Trigger AuthStatus warning -> Hull refreshes ticket over /sparrow/connect and sends AuthRefresh.
    srv.session!.sendAuthStatus(Status.ok, Math.floor(Date.now() / 1000) + 30);
    await eventually(() => srv.authRefreshCalls.length === 1, 'AuthRefresh delivered');
    expect(srv.authRefreshCalls[0]).toBe('refreshed-2');

    // Remove feat.notes -> feat.notes.ui disposes cleanly and removes its UI contribution.
    await srv.updateSchema([shellFacet]);
    await eventually(() => hull.loadedModules().length === 1, 'feat.notes.ui disposed');
    expect(contributions.has('feat.notes.ui')).toBe(false);
    expect(events).toContain('dispose:feat.notes.ui');

    await hull.stop();
    expect(events).toContain('dispose:shell.app');
    await srv.closeServer();
  });

  it('reports rejected modules via sparrow.web:moduleRejected and honors web.apply="prompt"', async () => {
    const { pub } = rootKeys();
    const shellMod = makeSignedModule('shell.app', '1.0.0');
    const badHostMod = makeSignedModule('feat.bad.ui', '1.0.0', [], { hostApi: '^9.0' });
    const goodMod = makeSignedModule('feat.good.ui', '1.0.0', ['shell.app']);

    const shellFacet = new FacetBuilder('shell.app', '1.0.0', {
      id: 16,
      annotations: { 'web.modules': [shellMod.rawEntry] },
    }).build();
    const badFacet = new FacetBuilder('feat.bad', '1.0.0', {
      id: 17,
      annotations: { 'web.modules': [badHostMod.rawEntry] },
    }).build();
    const goodFacet = new FacetBuilder('feat.good', '1.0.0', {
      id: 18,
      annotations: { 'web.modules': [goodMod.rawEntry] },
    }).build();

    const srv = buildTestServer([shellFacet, badFacet], { 'web.apply': 'prompt' });
    srv.addFile(shellMod.hash, shellMod.bytes);
    srv.addFile(badHostMod.hash, badHostMod.bytes);
    srv.addFile(goodMod.hash, goodMod.bytes);

    let pendingCount = 0;
    const hull = createHull({
      baseUrl: 'https://mock.local',
      hostApi: '3.2.0',
      rootKeys: [pub],
      fetch: srv.fetchMock,
      connectTransport: srv.connectTransport,
      importer: async () => () => {},
      reconnect: false,
      onUpdateAvailable: () => {
        pendingCount++;
      },
    });

    await hull.start();
    expect(hull.loadedModules().map((m) => m.id)).toEqual(['shell.app']);
    await eventually(() => srv.rejectedReports.length === 1, 'moduleRejected notification sent');
    expect(srv.rejectedReports[0]).toEqual(['feat.bad.ui', '1.0.0', 'host_api_mismatch']);

    // Update schema while web.apply == 'prompt': new module waits until applyPendingUpdate().
    await srv.updateSchema([shellFacet, goodFacet], { 'web.apply': 'prompt' });
    await eventually(() => pendingCount === 1, 'onUpdateAvailable fired');
    expect(hull.loadedModules().map((m) => m.id)).toEqual(['shell.app']);

    await hull.applyPendingUpdate();
    expect(hull.loadedModules().map((m) => m.id)).toEqual(['shell.app', 'feat.good.ui']);

    await hull.stop();
    await srv.closeServer();
  });

  it('boots offline from snapshotStore and rolls back if newest snapshot fails', async () => {
    const { pub } = rootKeys();
    const m1 = makeSignedModule('shell.app', '1.0.0');
    const m2 = makeSignedModule('shell.app', '2.0.0');

    const f1 = new FacetBuilder('shell.app', '1.0.0', { id: 16, annotations: { 'web.modules': [m1.rawEntry] } }).build();
    const f2 = new FacetBuilder('shell.app', '2.0.0', { id: 16, annotations: { 'web.modules': [m2.rawEntry] } }).build();

    const s1 = createSnapshot(
      makeSchema('app', '1.0.0', [f1]),
      null,
      [decodeModuleEntry(m1.rawEntry, 'shell.app')],
      new Map([[cbor.toHex(m1.hash), m1.bytes]]),
      100,
    );
    const s2 = createSnapshot(
      makeSchema('app', '2.0.0', [f2]),
      null,
      [decodeModuleEntry(m2.rawEntry, 'shell.app')],
      new Map([[cbor.toHex(m2.hash), m2.bytes]]),
      200,
    );

    const store = new MemorySnapshotStore();
    const { Snapshots } = await import('../src/index.js');
    const snaps = new Snapshots();
    snaps.install(s1);
    snaps.booted();
    snaps.install(s2); // installed but not yet booted -> v2.0.0 fails on boot -> roll back to s1!
    await store.save(snaps.exportStored());

    const bootedVersions: string[] = [];
    const hull = createHull({
      baseUrl: 'https://mock.local',
      hostApi: '3.2.0',
      rootKeys: [pub],
      snapshotStore: store,
      // Offline: fetch fails
      fetch: async () => {
        throw new Error('offline');
      },
      importer: async (entry) => {
        if (entry.version === '2.0.0') {
          return () => {
            throw new Error('broken v2');
          };
        }
        return () => {
          bootedVersions.push(entry.version);
        };
      },
      reconnect: false,
    });

    await expect(hull.start()).rejects.toThrow(/offline/);
    expect(bootedVersions).toEqual(['1.0.0']);
    expect(hull.loadedModules().map((m) => `${m.id}@${m.version}`)).toEqual(['shell.app@1.0.0']);
    await hull.stop();
  });
});
