// Conformance tests for all 55 vectors in test-vectors/signing.json.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { cbor, sha256 } from '@aiviarium/sparrow';
import {
  Verifier,
  compareVersions,
  decodeCertificate,
  decodeModuleRecord,
  decodeRevocation,
  encodeCertificate,
  encodeModuleRecord,
  encodeRevocation,
  facetWebKeys,
  fileHash,
  keyId,
  moduleInFacet,
  selectRevocation,
  signedBytes,
  verifySignature,
  Rollback,
} from '../src/index.js';

const VECTORS_DIR = process.env.SPARROW_VECTORS ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'test-vectors');
const doc = JSON.parse(readFileSync(join(VECTORS_DIR, 'signing.json'), 'utf8')) as {
  verification_context: { root_public_keys: string[]; now: number };
  vectors: Array<Record<string, any>>;
};

function fromTJ(t: any): unknown {
  if (t === null || typeof t === 'boolean' || typeof t === 'string' || typeof t === 'number') return t;
  if (Array.isArray(t)) return t.map(fromTJ);
  if ('$int' in t) {
    const b = BigInt(t.$int);
    return b >= BigInt(-Number.MAX_SAFE_INTEGER) && b <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : b;
  }
  if ('$bytes' in t) return cbor.fromHex(t.$bytes);
  if ('$tag' in t) return new cbor.Tag(t.$tag, fromTJ(t.value));
  if ('$map' in t) return new Map(t.$map.map(([k, v]: [any, any]) => [fromTJ(k), fromTJ(v)]));
  return new Map(Object.entries(t).map(([k, v]) => [k, fromTJ(v)]));
}

const byName = new Map(doc.vectors.map((v) => [v.name as string, v]));
const keyById = new Map<string, Uint8Array>();
for (const v of doc.vectors) {
  if (v.type === 'key') keyById.set(v.key_id, cbor.fromHex(v.public_key));
}

let checked = 0;

afterAll(() => {
  console.log(`signing vector coverage: ${checked}/${doc.vectors.length} vectors checked`);
});

describe('signing.json conformance', () => {
  for (const v of doc.vectors) {
    it(v.name, async () => {
      checked++;
      switch (v.type) {
        case 'key': {
          const pub = cbor.fromHex(v.public_key);
          expect(cbor.toHex(sha256(pub))).toBe(v.sha256_public_key);
          expect(cbor.toHex(keyId(pub))).toBe(v.key_id);
          break;
        }
        case 'certificate': {
          const unsignedRaw = cbor.encode(fromTJ(v.unsigned));
          const sb = signedBytes(v.domain, unsignedRaw);
          expect(cbor.toHex(sb)).toBe(v.signed_bytes);
          const certBytes = cbor.fromHex(v.certificate_cbor);
          const cert = decodeCertificate(certBytes);
          expect(cbor.toHex(encodeCertificate(cert))).toBe(v.certificate_cbor);
          const rootPub = keyById.get(cbor.toHex(cert.rootKeyId))!;
          expect(await verifySignature(rootPub, v.domain, unsignedRaw, cbor.fromHex(v.signature))).toBe(true);
          break;
        }
        case 'revocation': {
          const unsignedRaw = cbor.encode(fromTJ(v.unsigned));
          const sb = signedBytes(v.domain, unsignedRaw);
          expect(cbor.toHex(sb)).toBe(v.signed_bytes);
          const revBytes = cbor.fromHex(v.revocation_cbor);
          const rev = decodeRevocation(revBytes);
          expect(cbor.toHex(encodeRevocation(rev))).toBe(v.revocation_cbor);
          break;
        }
        case 'module': {
          const fileBytes = new TextEncoder().encode(v.file_utf8);
          expect(cbor.toHex(fileHash(fileBytes))).toBe(v.file_hash);
          const unsignedRaw = cbor.encode(fromTJ(v.unsigned));
          expect(cbor.toHex(signedBytes(v.domain, unsignedRaw))).toBe(v.signed_bytes);
          const modBytes = cbor.fromHex(v.entry_cbor);
          const mod = decodeModuleRecord(modBytes);
          expect(cbor.toHex(encodeModuleRecord(mod))).toBe(v.entry_cbor);
          break;
        }
        case 'file_hash': {
          const fileBytes = new TextEncoder().encode(v.file_utf8);
          expect(cbor.toHex(fileHash(fileBytes))).toBe(v.hash);
          break;
        }
        case 'verify': {
          const roots = doc.verification_context.root_public_keys.map((h) => cbor.fromHex(h));
          const certs = doc.vectors
            .filter((x) => x.type === 'certificate')
            .map((x) => decodeCertificate(cbor.fromHex(x.certificate_cbor)));
          const revVec = byName.get(v.revocation)!;
          const rev = await selectRevocation(roots, [decodeRevocation(cbor.fromHex(revVec.revocation_cbor))]);
          const verifier = new Verifier({
            roots,
            certificates: certs,
            revocation: rev,
            nowSeconds: doc.verification_context.now,
          });
          const modVec = byName.get(v.module)!;
          const mod = decodeModuleRecord(cbor.fromHex(modVec.entry_cbor));
          const reason = await verifier.verify(mod);
          expect(reason === 'ok').toBe(v.expected_valid);
          expect(reason).toBe(v.expected_reason);
          break;
        }
        case 'module_scope': {
          expect(moduleInFacet(v.facet_name, v.module_id)).toBe(v.expected_valid);
          break;
        }
        case 'facet_web_keys': {
          const res = facetWebKeys(Object.keys(v.facet_annotations));
          expect(res.honoured.sort()).toEqual([...v.honoured_web_keys].sort());
          expect(res.ignored.sort()).toEqual([...v.ignored_web_keys].sort());
          break;
        }
        default:
          throw new Error(`unhandled signing vector type: ${v.type}`);
      }
    });
  }

  it('covers semver 2.0 precedence and rollback', () => {
    expect(compareVersions('1.0.0-alpha', '1.0.0-alpha.1')).toBe(-1);
    expect(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.beta')).toBe(-1);
    expect(compareVersions('1.0.0-alpha.beta', '1.0.0-beta')).toBe(-1);
    expect(compareVersions('1.0.0-beta', '1.0.0-beta.2')).toBe(-1);
    expect(compareVersions('1.0.0-beta.2', '1.0.0-beta.11')).toBe(-1);
    expect(compareVersions('1.0.0-beta.11', '1.0.0-rc.1')).toBe(-1);
    expect(compareVersions('1.0.0-rc.1', '1.0.0')).toBe(-1);
    expect(compareVersions('1.0.0+build1', '1.0.0+build2')).toBe(0);

    const rb = new Rollback();
    rb.record('a.b', '1.2.0');
    expect(rb.allowed('a.b', '1.2.0')).toBe(true);
    expect(rb.allowed('a.b', '1.3.0')).toBe(true);
    expect(rb.allowed('a.b', '1.1.9')).toBe(false);
  });
});
