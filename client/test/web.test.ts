import { describe, expect, it } from 'vitest';
import { cbor, FacetBuilder, makeSchema, schema as spSchema, sha256 } from '@aiviarium/sparrow';
import {
  HttpError,
  LoaderReason,
  ModuleLoader,
  WebClient,
  decodeHash,
  encodeHash,
  extractSchemaModules,
  extractTopLevelWeb,
  fileHash,
  parseRange,
  rangeContains,
  type FetchLike,
} from '../src/index.js';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';

function keyPairFromSeed(seedByte: number) {
  const seed = new Uint8Array(32).fill(seedByte);
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    seed,
  ]);
  const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const pubSpki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = new Uint8Array(pubSpki.subarray(pubSpki.length - 32));
  return { priv, pub };
}

function signEntry(
  id: string,
  version: string,
  code: string,
  priv: ReturnType<typeof createPrivateKey>,
  _pub: Uint8Array,
  extra: Record<string, unknown> = {},
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
    ...extra,
  };
  const signedInput = cbor.canonical(cbor.encode(['sparrow-module-v1', unsigned]), { noFloats: true });
  const sig = new Uint8Array(nodeSign(null, signedInput, priv));
  return { bytes, hash, unsigned, sig };
}

describe('hostApi semver ranges', () => {
  it('supports ^, ~, comparators, wildcards and ||', () => {
    expect(rangeContains(parseRange('^3.1'), '3.1.0')).toBe(true);
    expect(rangeContains(parseRange('^3.1'), '3.9.4')).toBe(true);
    expect(rangeContains(parseRange('^3.1'), '4.0.0')).toBe(false);
    expect(rangeContains(parseRange('^3.1'), '3.0.9')).toBe(false);
    expect(rangeContains(parseRange('~3.1.2'), '3.1.9')).toBe(true);
    expect(rangeContains(parseRange('~3.1.2'), '3.2.0')).toBe(false);
    expect(rangeContains(parseRange('^0.2.3 || >=1.0.0 <2.0.0'), '0.2.9')).toBe(true);
    expect(rangeContains(parseRange('^0.2.3 || >=1.0.0 <2.0.0'), '1.5.0')).toBe(true);
    expect(rangeContains(parseRange('^0.2.3 || >=1.0.0 <2.0.0'), '0.3.0')).toBe(false);
    expect(rangeContains(parseRange('*'), '1.2.3')).toBe(true);
  });
});

describe('WebClient', () => {
  it('handles connect, refresh, schema hash verification, file hash verification, and HTTP errors', async () => {
    const fb = new FacetBuilder('acme.notes', '1.0.0', { id: 16 });
    const sc = makeSchema('app', '1.0.0', [fb.build()]);
    const scBytes = spSchema.encodeSchema(sc);
    const scHash = spSchema.schemaHash(sc);
    const modBytes = new TextEncoder().encode('export default function() {}');
    const modHash = fileHash(modBytes);

    const fetchMock: FetchLike = async (url, init) => {
      const headers = { get: () => null };
      if (url.endsWith('/sparrow/connect')) {
        const body = JSON.parse(init?.body ?? '{}');
        if (init?.headers?.Authorization !== 'Bearer alice') {
          return { ok: false, status: 401, headers, text: async () => 'unauthorized', json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
        }
        if (body.refresh) {
          return { ok: true, status: 200, headers, text: async () => '', json: async () => ({ ticket: 'new-ticket' }), arrayBuffer: async () => new ArrayBuffer(0) };
        }
        if (body.client?.hostApi === '1.0.0') {
          return { ok: false, status: 426, headers, text: async () => 'upgrade required', json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0) };
        }
        return {
          ok: true,
          status: 200,
          headers,
          text: async () => '',
          json: async () => ({
            ticket: 't1',
            ticketExpiresAt: '2026-11-28T20:00:00Z',
            sessionExpiresAt: '2026-11-29T04:00:00Z',
            endpoints: { websocket: 'wss://example.com/sparrow/ws' },
            protocolVersions: [1],
            schemaHash: encodeHash(scHash),
            schemaUrl: `/sparrow/schema/${encodeHash(scHash)}`,
            serverCertificateHashes: null,
          }),
          arrayBuffer: async () => new ArrayBuffer(0),
        };
      }
      if (url.includes('/sparrow/schema/')) {
        return {
          ok: true,
          status: 200,
          headers,
          text: async () => '',
          json: async () => ({}),
          arrayBuffer: async () => scBytes.slice().buffer,
        };
      }
      if (url.includes('/sparrow/mods/bad')) {
        const bad = new TextEncoder().encode('tampered');
        return { ok: true, status: 200, headers, text: async () => '', json: async () => ({}), arrayBuffer: async () => bad.buffer };
      }
      return { ok: true, status: 200, headers, text: async () => '', json: async () => ({}), arrayBuffer: async () => modBytes.slice().buffer };
    };

    let token = 'bad';
    const client = new WebClient({
      baseUrl: 'https://example.com',
      fetch: fetchMock,
      authorize: ({ headers }) => {
        headers.Authorization = `Bearer ${token}`;
      },
    });

    await expect(client.connect({ hostApi: '3.2.0' })).rejects.toMatchObject({ status: 401 });
    token = 'alice';
    await expect(client.connect({ hostApi: '1.0.0' })).rejects.toMatchObject({ status: 426 });

    const resp = await client.connect({ hostApi: '3.2.0' }, scHash);
    expect(resp.ticket).toBe('t1');
    expect(await client.refresh('wss://example.com/sparrow/ws')).toBe('new-ticket');

    const fetchedSchema = await client.fetchSchema(resp.schemaUrl, decodeHash(resp.schemaHash));
    expect(fetchedSchema.schema.facets[0].name).toBe('acme.notes');
    await expect(client.fetchSchema(resp.schemaUrl, new Uint8Array(33))).rejects.toThrow(/hash/);

    const fetchedFile = await client.fetchFile(`/sparrow/mods/${encodeHash(modHash)}.js`, modHash);
    expect(fetchedFile.bytes).toEqual(modBytes);
    await expect(client.fetchFile('/sparrow/mods/bad.js', modHash)).rejects.toThrow(/hash/);
  });

  it('binds globalThis.fetch so browsers do not throw Illegal invocation', async () => {
    const orig = (globalThis as { fetch?: unknown }).fetch;
    let seenThis: unknown;
    (globalThis as { fetch?: unknown }).fetch = function (this: unknown) {
      seenThis = this;
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: { get: () => null },
        text: async () => '',
        json: async () => ({ ticket: 'ok' }),
        arrayBuffer: async () => new ArrayBuffer(0),
      });
    };
    try {
      const client = new WebClient({ baseUrl: 'https://example.com' });
      expect(await client.refresh('wss://example.com/sparrow/ws')).toBe('ok');
      expect(seenThis).toBe(globalThis);
    } finally {
      (globalThis as { fetch?: unknown }).fetch = orig;
    }
  });
});

describe('ModuleLoader & scoping', () => {
  it('accepts signed modules, rejects hostApi mismatch and out-of-scope modules', async () => {
    const { priv, pub } = keyPairFromSeed(1);
    const kid = sha256(pub).subarray(0, 16);

    const m1 = signEntry('acme.notes.ui', '1.0.0', 'export default () => {}', priv, pub);
    const m2 = signEntry('acme.notes.old', '1.0.0', 'export default () => {}', priv, pub, { hostApi: '^1.0' });
    const m3 = signEntry('other.ui', '1.0.0', 'export default () => {}', priv, pub);

    const fb1 = new FacetBuilder('acme.notes', '1.0.0', {
      id: 16,
      annotations: {
        'web.modules': [
          { ...m1.unsigned, sig: [kid, m1.sig] },
          { ...m2.unsigned, sig: [kid, m2.sig] },
        ],
      },
    });
    const fb2 = new FacetBuilder('acme.bad', '1.0.0', {
      id: 17,
      annotations: {
        'web.modules': [{ ...m3.unsigned, sig: [kid, m3.sig] }],
      },
    });
    const sc = spSchema.decodeSchema(
      spSchema.encodeSchema(makeSchema('app', '1.0.0', [fb1.build(), fb2.build()], { 'web.apply': 'prompt', 'web.title': 'Demo' })),
    );

    const top = extractTopLevelWeb(sc);
    expect(top.apply).toBe('prompt');
    expect(top.config).toEqual({ 'web.title': 'Demo' });

    const extracted = extractSchemaModules(sc);
    expect(extracted.entries).toHaveLength(2);
    expect(extracted.rejected).toHaveLength(1);

    const loader = new ModuleLoader({ roots: [pub], hostApi: '3.2.0' });
    const res = await loader.accept(sc);
    expect(res.accepted.map((m) => m.id)).toEqual(['acme.notes.ui']);
    expect(res.rejected.map((r) => r.reason)).toContain(LoaderReason.hostApiMismatch);
  });
});
