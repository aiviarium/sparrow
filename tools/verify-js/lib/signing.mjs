// Independent Ed25519 / key_id / module acceptance logic (section 9.5),
// using Node's crypto only.

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { concat, encTJ, hex, unhex, u8eq } from './cbor.mjs';

const PKCS8_ED25519_PREFIX = unhex('302e020100300506032b657004220420');
const SPKI_ED25519_PREFIX = unhex('302a300506032b6570032100');

export const DOMAIN = {
  module: 'sparrow-module-v1',
  cert: 'sparrow-cert-v1',
  revoked: 'sparrow-revoked-v1',
};

export function privateKeyFromSeed(seed) {
  return createPrivateKey({ key: Buffer.from(concat(PKCS8_ED25519_PREFIX, seed)), format: 'der', type: 'pkcs8' });
}

export function publicKeyRaw(privateKey) {
  const der = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return new Uint8Array(der.subarray(der.length - 32));
}

const publicKeyObject = (raw) =>
  createPublicKey({ key: Buffer.from(concat(SPKI_ED25519_PREFIX, raw)), format: 'der', type: 'spki' });

export const sha256 = (b) => new Uint8Array(createHash('sha256').update(b).digest());
export const keyId = (pub) => sha256(pub).subarray(0, 16);
export const fileHash = (b) => concat([0x01], sha256(b));

/** Domain string as raw UTF-8, then the canonical CBOR of the unsigned value. */
export const signedBytes = (domain, unsignedTJ) => concat(Buffer.from(domain, 'utf8'), encTJ(unsignedTJ));

export const ed25519Sign = (seed, msg) => new Uint8Array(sign(null, Buffer.from(msg), privateKeyFromSeed(seed)));
export const ed25519Verify = (pub, msg, sig) => verify(null, Buffer.from(msg), publicKeyObject(pub), Buffer.from(sig));

const bytesOf = (t) => unhex(t.$bytes);

/**
 * Accept or reject a module entry (tjson map with 'sig').
 * ctx: { roots: [Uint8Array], webKeys: [certificate tjson], revoked: revocation tjson, now: number }
 */
export function verifyModule(entry, ctx) {
  const roots = new Map(ctx.roots.map((p) => [hex(keyId(p)), p]));
  const revoked = new Set();
  const [seq, ids, rootId, rsig] = ctx.revoked;
  const rp = roots.get(hex(bytesOf(rootId)));
  if (rp && ed25519Verify(rp, signedBytes(DOMAIN.revoked, [seq, ids, rootId]), bytesOf(rsig))) {
    for (const id of ids) revoked.add(hex(bytesOf(id)));
  }
  const [kidT, sigT] = entry.sig;
  const kid = hex(bytesOf(kidT));
  if (revoked.has(kid)) return 'key_revoked';
  let key = roots.get(kid);
  if (!key) {
    let reason = 'unknown_key';
    for (const c of ctx.webKeys) {
      const pub = bytesOf(c[0]);
      if (hex(keyId(pub)) !== kid) continue;
      const root = roots.get(hex(bytesOf(c[3])));
      const ns = c[1];
      if (!root) reason = 'unknown_root';
      else if (!ed25519Verify(root, signedBytes(DOMAIN.cert, c.slice(0, 4)), bytesOf(c[4]))) reason = 'bad_certificate_signature';
      else if (!ns.endsWith('.')) reason = 'namespace_missing_trailing_dot';
      else if (ctx.now >= c[2].value) reason = 'certificate_expired';
      else if (!entry.id.startsWith(ns)) reason = 'namespace_not_covered';
      else { key = pub; break; }
    }
    if (!key) return reason;
  }
  const { sig, ...unsigned } = entry;
  if (!ed25519Verify(key, signedBytes(DOMAIN.module, unsigned), bytesOf(sigT))) return 'bad_module_signature';
  return 'ok';
}

export { u8eq };
