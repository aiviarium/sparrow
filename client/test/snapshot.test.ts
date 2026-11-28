import { describe, expect, it } from 'vitest';
import { cbor, FacetBuilder, makeSchema, schema as spSchema, sha256 } from '@aiviarium/sparrow';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import {
  MemorySnapshotStore,
  Snapshots,
  createSnapshot,
  decodeModuleEntry,
  decodeSnapshot,
  decodeSnapshotProps,
  encodeHash,
  encodeSnapshot,
  fileHash,
  verifySnapshot,
} from '../src/index.js';

function rootKeys() {
  const seed = new Uint8Array(32).fill(7);
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pub = new Uint8Array(spki.subarray(spki.length - 32));
  const kid = sha256(pub).subarray(0, 16);
  return { priv, pub, kid };
}

function signedMod(id: string, version: string, code: string) {
  const { priv, kid } = rootKeys();
  const bytes = new TextEncoder().encode(code);
  const hash = fileHash(bytes);
  const unsigned = { id, version, hash, url: `/sparrow/mods/${encodeHash(hash)}.js`, deps: [], hostApi: '^3.1' };
  const sig = new Uint8Array(nodeSign(null, cbor.canonical(cbor.encode(['sparrow-module-v1', unsigned]), { noFloats: true }), priv));
  return { entry: decodeModuleEntry({ ...unsigned, sig: [kid, sig] }, id), bytes, hash };
}

describe('Snapshot & Snapshots', () => {
  it('encodes, decodes, and verifies snapshots canonically', () => {
    const m = signedMod('acme.ui', '1.0.0', 'export default () => {}');
    const fb = new FacetBuilder('acme.ui', '1.0.0', { id: 16 });
    const sc = makeSchema('app', '1.0.0', [fb.build()]);
    const files = new Map([[cbor.toHex(m.hash), m.bytes]]);
    const snap = createSnapshot(sc, { title: 'Sparrow' }, [m.entry], files, 1795737600);

    const raw = encodeSnapshot(snap);
    const decoded = decodeSnapshot(raw);
    expect(cbor.bytesEqual(decoded.schemaHash, snap.schemaHash)).toBe(true);
    expect(decodeSnapshotProps(decoded)).toEqual({ title: 'Sparrow' });
    expect(verifySnapshot(decoded).facets[0].name).toBe('acme.ui');

    // Tampered file fails verification.
    decoded.files.set(cbor.toHex(m.hash), new TextEncoder().encode('tampered'));
    expect(() => verifySnapshot(decoded)).toThrow(/hash/);
  });

  it('tracks rollback versions and supports rolling back to previous snapshot', async () => {
    const m1 = signedMod('acme.ui', '1.0.0', 'export default () => 1');
    const m2 = signedMod('acme.ui', '2.0.0', 'export default () => 2');
    const fb = new FacetBuilder('acme.ui', '1.0.0', { id: 16 });
    const sc = makeSchema('app', '1.0.0', [fb.build()]);

    const s1 = createSnapshot(sc, null, [m1.entry], new Map([[cbor.toHex(m1.hash), m1.bytes]]), 100);
    const s2 = createSnapshot(sc, null, [m2.entry], new Map([[cbor.toHex(m2.hash), m2.bytes]]), 200);

    const snaps = new Snapshots();
    snaps.install(s1);
    snaps.booted();
    expect(snaps.rollback.allowed('acme.ui', '1.0.0')).toBe(true);
    expect(snaps.rollback.allowed('acme.ui', '0.9.0')).toBe(false);

    snaps.install(s2);
    expect(snaps.previous).toBeDefined();
    // Before booted(), rollback is still at 1.0.0; rolling back restores s1.
    const back = snaps.rollBack();
    expect(back.createdAt).toBe(100);

    // Round-trip through MemorySnapshotStore.
    snaps.install(s2);
    snaps.booted();
    expect(snaps.rollback.allowed('acme.ui', '1.5.0')).toBe(false);

    const store = new MemorySnapshotStore();
    await store.save(snaps.exportStored());
    const restored = Snapshots.fromStored((await store.load())!);
    expect(restored.current?.createdAt).toBe(200);
    expect(restored.rollback.allowed('acme.ui', '1.5.0')).toBe(false);
  });
});
