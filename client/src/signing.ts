// Sparrow Web Profile module signing, certificates, revocation lists, semver
// 2.0 precedence, hostApi ranges, and rollback protection (spec 9.4, 9.5).
// Mirrors go/websign and go/web/modules.go range parsing.

import { cbor, sha256 } from '@aiviarium/sparrow';

export const DOMAIN_MODULE = 'sparrow-module-v1';
export const DOMAIN_CERT = 'sparrow-cert-v1';
export const DOMAIN_REVOKED = 'sparrow-revoked-v1';
export const KEY_ID_LEN = 16;

export const VerifyReason = {
  ok: 'ok',
  badModuleSignature: 'bad_module_signature',
  unknownKey: 'unknown_key',
  unknownRoot: 'unknown_root',
  badCertSignature: 'bad_certificate_signature',
  namespaceNoDot: 'namespace_missing_trailing_dot',
  certificateExpired: 'certificate_expired',
  namespaceNotCovered: 'namespace_not_covered',
  keyRevoked: 'key_revoked',
} as const;

export type VerifyReason = (typeof VerifyReason)[keyof typeof VerifyReason];

const CERT_RANK: Partial<Record<VerifyReason, number>> = {
  [VerifyReason.unknownKey]: 0,
  [VerifyReason.unknownRoot]: 1,
  [VerifyReason.badCertSignature]: 2,
  [VerifyReason.namespaceNoDot]: 3,
  [VerifyReason.certificateExpired]: 4,
  [VerifyReason.namespaceNotCovered]: 5,
};

/** Ed25519 signature verifier hook. */
export type SignatureVerifier = (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => Promise<boolean> | boolean;

type SubtleLike = {
  importKey(format: string, keyData: Uint8Array, algorithm: string, extractable: boolean, usages: string[]): Promise<unknown>;
  verify(algorithm: string, key: unknown, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
};

/** Default Ed25519 verifier backed by WebCrypto (browsers and Node 20+). */
export async function verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const subtle = (globalThis as { crypto?: { subtle?: SubtleLike } }).crypto?.subtle;
  if (!subtle) throw new Error('websign: WebCrypto SubtleCrypto is unavailable; pass a custom verify hook');
  try {
    const key = await subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
    return await subtle.verify('Ed25519', key, signature, message);
  } catch {
    return false;
  }
}

/** First 16 bytes of SHA-256 of a raw 32-byte Ed25519 public key (9.5). */
export function keyId(pub: Uint8Array): Uint8Array {
  return sha256(pub).subarray(0, KEY_ID_LEN);
}

/** File hash in schema-hash format: 0x01 || SHA-256(data) (9.4). */
export function fileHash(data: Uint8Array): Uint8Array {
  const h = sha256(data);
  const out = new Uint8Array(1 + h.length);
  out[0] = 0x01;
  out.set(h, 1);
  return out;
}

/** Canonical CBOR of [domain, value] that a signature covers (9.5). */
export function signedBytes(domain: string, unsignedRaw: Uint8Array): Uint8Array {
  const encoded = cbor.encode([domain, new cbor.Raw(unsignedRaw)]);
  return cbor.canonical(encoded, { noFloats: true });
}

/** Checks a signature over unsignedRaw under domain. */
export async function verifySignature(
  pub: Uint8Array,
  domain: string,
  unsignedRaw: Uint8Array,
  sig: Uint8Array,
  verify: SignatureVerifier = verifyEd25519,
): Promise<boolean> {
  if (pub.length !== 32 || sig.length !== 64) return false;
  let bytes: Uint8Array;
  try {
    bytes = signedBytes(domain, unsignedRaw);
  } catch {
    return false;
  }
  return await verify(pub, bytes, sig);
}

// ---------------------------------------------------------------------------
// Certificates and revocation lists (9.5)
// ---------------------------------------------------------------------------

/** [publisher_key, namespace, expires, root_key_id, root_sig] */
export interface Certificate {
  publisherKey: Uint8Array;
  namespace: string;
  /** Integer epoch seconds (tag 1). */
  expires: number;
  rootKeyId: Uint8Array;
  rootSig: Uint8Array;
}

export function unsignedCertificate(c: Pick<Certificate, 'publisherKey' | 'namespace' | 'expires' | 'rootKeyId'>): Uint8Array {
  if (!Number.isInteger(c.expires)) throw new Error('websign: certificate expires must be integer seconds');
  return cbor.encode([c.publisherKey, c.namespace, new cbor.Tag(cbor.TAG_EPOCH_TIME, c.expires), c.rootKeyId]);
}

export function encodeCertificate(c: Certificate): Uint8Array {
  return cbor.encode([
    c.publisherKey,
    c.namespace,
    new cbor.Tag(cbor.TAG_EPOCH_TIME, c.expires),
    c.rootKeyId,
    c.rootSig,
  ]);
}

export function decodeCertificate(raw: Uint8Array): Certificate {
  cbor.validate(raw, { noFloats: true });
  const r = new cbor.Reader(raw);
  const n = r.arrayHead();
  if (n !== 5) throw new Error(`websign: certificate has ${n} elements, want 5`);
  const publisherKey = r.bytes().slice();
  const namespace = r.text();
  const tag = r.tag();
  if (tag !== cbor.TAG_EPOCH_TIME) throw new Error('websign: certificate expires must have tag 1');
  const maj = r.peekMajor();
  if (maj !== cbor.MAJOR_UINT && maj !== cbor.MAJOR_NEG) throw new Error('websign: expires must be integer seconds');
  const exp = r.int();
  if (typeof exp === 'bigint') throw new Error('websign: expires outside safe integer range');
  const rootKeyId = r.bytes().slice();
  const rootSig = r.bytes().slice();
  if (!r.done) throw new Error('websign: trailing bytes in certificate');
  return { publisherKey, namespace, expires: exp, rootKeyId, rootSig };
}

/** [seq, [* key_id], root_key_id, root_sig] */
export interface Revocation {
  seq: number;
  keyIds: Uint8Array[];
  rootKeyId: Uint8Array;
  rootSig: Uint8Array;
}

export function unsignedRevocation(rev: Pick<Revocation, 'seq' | 'keyIds' | 'rootKeyId'>): Uint8Array {
  return cbor.encode([rev.seq, rev.keyIds, rev.rootKeyId]);
}

export function encodeRevocation(rev: Revocation): Uint8Array {
  return cbor.encode([rev.seq, rev.keyIds, rev.rootKeyId, rev.rootSig]);
}

export function decodeRevocation(raw: Uint8Array): Revocation {
  cbor.validate(raw, { noFloats: true });
  const r = new cbor.Reader(raw);
  const n = r.arrayHead();
  if (n !== 4) throw new Error(`websign: revocation list has ${n} elements, want 4`);
  const seq = r.uintNumber();
  const k = r.arrayHead();
  const keyIds: Uint8Array[] = [];
  for (let i = 0; i < k; i++) keyIds.push(r.bytes().slice());
  const rootKeyId = r.bytes().slice();
  const rootSig = r.bytes().slice();
  if (!r.done) throw new Error('websign: trailing bytes in revocation');
  return { seq, keyIds, rootKeyId, rootSig };
}

// ---------------------------------------------------------------------------
// Module entries (9.4)
// ---------------------------------------------------------------------------

/** Signed web-module entry, preserving all raw CBOR fields for signature checking. */
export interface ModuleRecord {
  id: string;
  version: string;
  hash: Uint8Array;
  keyId: Uint8Array;
  sig: Uint8Array;
  /** Every map entry as raw CBOR bytes, including unknown keys and sig. */
  fields: Map<string, Uint8Array>;
}

export function decodeModuleRecord(raw: Uint8Array): ModuleRecord {
  cbor.validate(raw, { noFloats: true });
  const r = new cbor.Reader(raw);
  const n = r.mapHead();
  const fields = new Map<string, Uint8Array>();
  for (let i = 0; i < n; i++) {
    const k = r.text();
    fields.set(k, r.raw().slice());
  }
  if (!r.done) throw new Error('websign: trailing bytes in module entry');
  const textField = (k: string): string => {
    const v = fields.get(k);
    if (!v) throw new Error(`websign: module has no "${k}"`);
    const fr = new cbor.Reader(v);
    const s = fr.text();
    if (!fr.done) throw new Error(`websign: bad field "${k}"`);
    return s;
  };
  const id = textField('id');
  const version = textField('version');
  textField('url');
  textField('hostApi');
  if (!fields.has('deps')) throw new Error('websign: module has no "deps"');
  const hv = fields.get('hash');
  if (!hv) throw new Error('websign: module has no "hash"');
  const hash = new cbor.Reader(hv).bytes().slice();
  const sv = fields.get('sig');
  if (!sv) throw new Error('websign: module has no "sig"');
  const sr = new cbor.Reader(sv);
  const sk = sr.arrayHead();
  if (sk !== 2) throw new Error('websign: sig must be [key_id, signature]');
  const modKeyId = sr.bytes().slice();
  const sig = sr.bytes().slice();
  return { id, version, hash, keyId: modKeyId, sig, fields };
}

export function unsignedModuleRecord(m: Pick<ModuleRecord, 'fields'>): Uint8Array {
  const entries = new Map<string, cbor.Raw>();
  for (const [k, v] of m.fields) {
    if (k !== 'sig') entries.set(k, new cbor.Raw(v));
  }
  return cbor.canonical(cbor.encode(entries), { noFloats: true });
}

export function encodeModuleRecord(m: ModuleRecord): Uint8Array {
  const entries = new Map<string, cbor.Raw>();
  for (const [k, v] of m.fields) {
    entries.set(k, new cbor.Raw(v));
  }
  entries.set('sig', new cbor.Raw(cbor.encode([m.keyId, m.sig])));
  return cbor.canonical(cbor.encode(entries), { noFloats: true });
}

// ---------------------------------------------------------------------------
// Acceptance (9.5)
// ---------------------------------------------------------------------------

/**
 * Selects the revocation list with the highest seq among those signed by a root key.
 * Lists not signed by a root key are ignored.
 */
export async function selectRevocation(
  roots: readonly Uint8Array[],
  lists: ReadonlyArray<Revocation | null | undefined>,
  verify: SignatureVerifier = verifyEd25519,
): Promise<Revocation | undefined> {
  const rootById = new Map<string, Uint8Array>();
  for (const r of roots) {
    rootById.set(cbor.toHex(keyId(r)), r);
  }
  let best: Revocation | undefined;
  for (const l of lists) {
    if (!l) continue;
    const pub = rootById.get(cbor.toHex(l.rootKeyId));
    if (!pub) continue;
    const ok = await verifySignature(pub, DOMAIN_REVOKED, unsignedRevocation(l), l.rootSig, verify);
    if (!ok) continue;
    if (!best || l.seq > best.seq) best = l;
  }
  return best;
}

export interface VerifierOptions {
  roots: readonly Uint8Array[];
  certificates?: readonly Certificate[];
  revocation?: Revocation;
  /** Epoch seconds at acceptance time; default Math.floor(Date.now() / 1000). */
  nowSeconds?: number;
  verify?: SignatureVerifier;
}

export class Verifier {
  private readonly rootsById = new Map<string, Uint8Array>();
  readonly certificates: readonly Certificate[];
  readonly revocation?: Revocation;
  readonly nowSeconds: number;
  readonly verifyFn: SignatureVerifier;

  constructor(opts: VerifierOptions) {
    for (const r of opts.roots) {
      this.rootsById.set(cbor.toHex(keyId(r)), r);
    }
    this.certificates = opts.certificates ?? [];
    this.revocation = opts.revocation;
    this.nowSeconds = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
    this.verifyFn = opts.verify ?? verifyEd25519;
  }

  private findRoot(id: Uint8Array): Uint8Array | undefined {
    return this.rootsById.get(cbor.toHex(id));
  }

  private isRevoked(id: Uint8Array): boolean {
    if (!this.revocation || this.findRoot(id)) return false; // root keys cannot be revoked
    return this.revocation.keyIds.some((k) => cbor.bytesEqual(k, id));
  }

  async certificateValid(c: Certificate, moduleId: string): Promise<VerifyReason> {
    const root = this.findRoot(c.rootKeyId);
    if (!root) return VerifyReason.unknownRoot;
    if (!(await verifySignature(root, DOMAIN_CERT, unsignedCertificate(c), c.rootSig, this.verifyFn))) {
      return VerifyReason.badCertSignature;
    }
    if (!c.namespace.endsWith('.')) return VerifyReason.namespaceNoDot;
    if (this.nowSeconds >= c.expires) return VerifyReason.certificateExpired;
    if (!moduleId.startsWith(c.namespace)) return VerifyReason.namespaceNotCovered;
    return VerifyReason.ok;
  }

  async verify(m: ModuleRecord): Promise<VerifyReason> {
    let key = this.findRoot(m.keyId);
    if (!key) {
      if (this.isRevoked(m.keyId)) return VerifyReason.keyRevoked;
      let reason: VerifyReason = VerifyReason.unknownKey;
      for (const c of this.certificates) {
        if (!cbor.bytesEqual(keyId(c.publisherKey), m.keyId)) continue;
        const r = await this.certificateValid(c, m.id);
        if (r !== VerifyReason.ok) {
          if ((CERT_RANK[r] ?? -1) > (CERT_RANK[reason] ?? -1)) reason = r;
          continue;
        }
        key = c.publisherKey;
        break;
      }
      if (!key) return reason;
    }
    let u: Uint8Array;
    try {
      u = unsignedModuleRecord(m);
    } catch {
      return VerifyReason.badModuleSignature;
    }
    const ok = await verifySignature(key, DOMAIN_MODULE, u, m.sig, this.verifyFn);
    return ok ? VerifyReason.ok : VerifyReason.badModuleSignature;
  }
}

// ---------------------------------------------------------------------------
// Semver 2.0, hostApi ranges, rollback, and facet web.* keys (9.4, 9.5)
// ---------------------------------------------------------------------------

export interface Semver {
  major: bigint;
  minor: bigint;
  patch: bigint;
  pre: string[];
  build: string;
}

function isNumeric(s: string): boolean {
  if (!s) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

function validIdents(s: string, pre: boolean): boolean {
  for (const id of s.split('.')) {
    if (!id) return false;
    for (let i = 0; i < id.length; i++) {
      const c = id.charCodeAt(i);
      const ok = (c >= 48 && c <= 57) || (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || c === 45;
      if (!ok) return false;
    }
    if (pre && isNumeric(id) && id.length > 1 && id[0] === '0') return false;
  }
  return true;
}

export function parseVersion(s: string): Semver {
  let rest = s;
  let build = '';
  let pre: string[] = [];
  const plus = rest.indexOf('+');
  if (plus >= 0) {
    build = rest.slice(plus + 1);
    rest = rest.slice(0, plus);
    if (!validIdents(build, false)) throw new Error(`websign: bad build metadata in ${JSON.stringify(s)}`);
  }
  const dash = rest.indexOf('-');
  if (dash >= 0) {
    const p = rest.slice(dash + 1);
    rest = rest.slice(0, dash);
    if (!validIdents(p, true)) throw new Error(`websign: bad pre-release in ${JSON.stringify(s)}`);
    pre = p.split('.');
  }
  const parts = rest.split('.');
  if (parts.length !== 3) throw new Error(`websign: ${JSON.stringify(s)} is not MAJOR.MINOR.PATCH`);
  const nums: bigint[] = [];
  for (const p of parts) {
    if (!isNumeric(p) || (p.length > 1 && p[0] === '0')) {
      throw new Error(`websign: bad version number ${JSON.stringify(p)} in ${JSON.stringify(s)}`);
    }
    const n = BigInt(p);
    if (n >= 1n << 64n) throw new Error(`websign: version number overflow in ${JSON.stringify(s)}`);
    nums.push(n);
  }
  return { major: nums[0], minor: nums[1], patch: nums[2], pre, build };
}

function cmpBig(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareParsedVersions(a: Semver, b: Semver): number {
  let c = cmpBig(a.major, b.major);
  if (c !== 0) return c;
  c = cmpBig(a.minor, b.minor);
  if (c !== 0) return c;
  c = cmpBig(a.patch, b.patch);
  if (c !== 0) return c;
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1;
  if (b.pre.length === 0) return -1;
  for (let i = 0; i < a.pre.length && i < b.pre.length; i++) {
    const x = a.pre[i];
    const y = b.pre[i];
    const xn = isNumeric(x);
    const yn = isNumeric(y);
    if (xn && yn) {
      if (x.length !== y.length) return x.length < y.length ? -1 : 1;
      if (x !== y) return x < y ? -1 : 1;
    } else if (xn) {
      return -1;
    } else if (yn) {
      return 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return a.pre.length < b.pre.length ? -1 : a.pre.length > b.pre.length ? 1 : 0;
}

export function compareVersions(a: string, b: string): number {
  return compareParsedVersions(parseVersion(a), parseVersion(b));
}

interface Comparator {
  op: '=' | '>' | '>=' | '<' | '<=';
  v: Semver;
}

export interface SemverRange {
  sets: Comparator[][];
}

const U64_MAX = (1n << 64n) - 1n;

function parsePartial(s: string): { v: Semver; given: number } {
  const v: Semver = { major: 0n, minor: 0n, patch: 0n, pre: [], build: '' };
  if (s === '*' || s === 'x' || s === 'X') return { v, given: 0 };
  const dash = s.indexOf('-');
  const core = dash >= 0 ? s.slice(0, dash) : s;
  const parts = core.split('.');
  if (parts.length > 3) throw new Error(`bad version ${JSON.stringify(s)}`);
  const nums: [bigint, bigint, bigint] = [0n, 0n, 0n];
  let given = 0;
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p === 'x' || p === 'X' || p === '*') break;
    if (!isNumeric(p)) throw new Error(`bad version ${JSON.stringify(s)}`);
    const n = BigInt(p);
    if (n > U64_MAX) throw new Error(`bad version ${JSON.stringify(s)}`);
    nums[i] = n;
    given++;
  }
  if (dash >= 0) {
    if (given !== 3) throw new Error(`bad version ${JSON.stringify(s)}`);
    return { v: parseVersion(s), given: 3 };
  }
  v.major = nums[0];
  v.minor = nums[1];
  v.patch = nums[2];
  return { v, given };
}

function bump(v: Semver, part: number): Semver | null {
  if (part === 0) return v.major === U64_MAX ? null : { major: v.major + 1n, minor: 0n, patch: 0n, pre: [], build: '' };
  if (part === 1) return v.minor === U64_MAX ? null : { major: v.major, minor: v.minor + 1n, patch: 0n, pre: [], build: '' };
  return v.patch === U64_MAX ? null : { major: v.major, minor: v.minor, patch: v.patch + 1n, pre: [], build: '' };
}

function between(v: Semver, part: number): Comparator[] {
  const u = bump(v, part);
  return u ? [{ op: '>=', v }, { op: '<', v: u }] : [{ op: '>=', v }];
}

function parseComparator(f: string): Comparator[] {
  let op = '';
  for (const p of ['>=', '<=', '>', '<', '=', '^', '~']) {
    if (f.startsWith(p)) {
      op = p;
      f = f.slice(p.length);
      break;
    }
  }
  const { v, given } = parsePartial(f);
  const zero: Semver = { major: 0n, minor: 0n, patch: 0n, pre: [], build: '' };
  switch (op) {
    case '':
    case '=':
      if (given === 0) return [{ op: '>=', v: zero }];
      if (given === 3) return [{ op: '=', v }];
      return between(v, given - 1);
    case '^':
      if (given === 0) return [{ op: '>=', v: zero }];
      if (v.major > 0n || given === 1) return between(v, 0);
      if (v.minor > 0n || given === 2) return between(v, 1);
      return between(v, 2);
    case '~':
      if (given === 0) return [{ op: '>=', v: zero }];
      return between(v, given === 1 ? 0 : 1);
    case '>=':
    case '<':
      return [{ op, v }];
    case '>':
      if (given < 3 && given > 0) {
        const u = bump(v, given - 1);
        if (u) return [{ op: '>=', v: u }];
        return [{ op: '>', v: { major: U64_MAX, minor: U64_MAX, patch: U64_MAX, pre: [], build: '' } }];
      }
      return [{ op: '>', v }];
    case '<=':
      if (given < 3 && given > 0) {
        const u = bump(v, given - 1);
        if (u) return [{ op: '<', v: u }];
        return [{ op: '>=', v: zero }];
      }
      return [{ op: '<=', v }];
    default:
      throw new Error(`bad comparator ${JSON.stringify(f)}`);
  }
}

export function parseRange(s: string): SemverRange {
  const trimmed = s.trim();
  if (!trimmed) throw new Error('empty range');
  const sets: Comparator[][] = [];
  for (const alt of trimmed.split('||')) {
    const set: Comparator[] = [];
    for (const f of alt.trim().split(/\s+/)) {
      if (!f) continue;
      set.push(...parseComparator(f));
    }
    if (set.length === 0) throw new Error(`empty alternative in ${JSON.stringify(s)}`);
    sets.push(set);
  }
  return { sets };
}

export function rangeContains(range: SemverRange, version: string): boolean {
  let v: Semver;
  try {
    v = parseVersion(version);
  } catch {
    return false;
  }
  for (const set of range.sets) {
    let ok = true;
    let preAllowed = v.pre.length === 0;
    for (const c of set) {
      const k = compareParsedVersions(v, c.v);
      switch (c.op) {
        case '=':
          ok = ok && k === 0;
          break;
        case '>':
          ok = ok && k > 0;
          break;
        case '>=':
          ok = ok && k >= 0;
          break;
        case '<':
          ok = ok && k < 0;
          break;
        case '<=':
          ok = ok && k <= 0;
          break;
      }
      if (c.v.pre.length > 0 && c.v.major === v.major && c.v.minor === v.minor && c.v.patch === v.patch) {
        preAllowed = true;
      }
    }
    if (ok && preAllowed) return true;
  }
  return false;
}

/** Records the highest booted version of each module for rollback protection (9.5). */
export class Rollback {
  private readonly highest = new Map<string, Semver>();

  constructor(initial?: Record<string, string>) {
    if (initial) {
      for (const [id, ver] of Object.entries(initial)) this.record(id, ver);
    }
  }

  record(id: string, version: string): void {
    const v = parseVersion(version);
    const cur = this.highest.get(id);
    if (!cur || compareParsedVersions(v, cur) > 0) {
      this.highest.set(id, v);
    }
  }

  allowed(id: string, version: string): boolean {
    const v = parseVersion(version);
    const cur = this.highest.get(id);
    return !cur || compareParsedVersions(v, cur) >= 0;
  }

  toJSON(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [id, v] of this.highest) {
      const pre = v.pre.length ? `-${v.pre.join('.')}` : '';
      const build = v.build ? `+${v.build}` : '';
      out[id] = `${v.major}.${v.minor}.${v.patch}${pre}${build}`;
    }
    return out;
  }
}

/** Splits a facet's web.* keys into honoured (only web.modules) and ignored (9.4). */
export function facetWebKeys(keys: readonly string[]): { honoured: string[]; ignored: string[] } {
  const honoured: string[] = [];
  const ignored: string[] = [];
  for (const k of keys) {
    if (k === 'web.modules') honoured.push(k);
    else if (k.startsWith('web.')) ignored.push(k);
  }
  return { honoured, ignored };
}
