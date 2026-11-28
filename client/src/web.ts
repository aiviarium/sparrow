// Sparrow Web Profile HTTP client, schema module extraction, and module loader
// (spec 9.1, 9.3, 9.4, 9.5). Mirrors go/web/client.go and go/web/modules.go.

import { cbor, schema as spSchema, type Facet, type Schema } from '@aiviarium/sparrow';
import {
  Rollback,
  Verifier,
  VerifyReason,
  decodeCertificate,
  decodeModuleRecord,
  decodeRevocation,
  fileHash,
  parseRange,
  parseVersion,
  rangeContains,
  selectRevocation,
  type Certificate,
  type ModuleRecord,
  type Revocation,
  type SignatureVerifier,
} from './signing.js';

export const CONNECT_PATH = '/sparrow/connect';
export const SCHEMA_PATH = '/sparrow/schema/';
export const MODS_PATH = '/sparrow/mods/';

export const ANN_MODULES = 'web.modules';
export const ANN_KEYS = 'web.keys';
export const ANN_REVOKED = 'web.revoked';
export const ANN_APPLY = 'web.apply';

export type ApplyMode = 'hot' | 'reload' | 'prompt';

// ---------------------------------------------------------------------------
// Base64url (no padding)
// ---------------------------------------------------------------------------

export function encodeHash(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function decodeHash(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('web: invalid base64url hash');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---------------------------------------------------------------------------
// Module scoping and schema extraction (9.4)
// ---------------------------------------------------------------------------

/** Strips an optional "<peer-id>/" prefix from a federated facet name (10.8). */
export function splitPeerFacet(name: string): { peer: string; local: string } {
  const i = name.indexOf('/');
  return i >= 0 ? { peer: name.slice(0, i), local: name.slice(i + 1) } : { peer: '', local: name };
}

/** Reports whether s follows the module-id grammar (same as node IDs). */
export function isModuleId(s: string): boolean {
  return spSchema.isNodeId(s);
}

/**
 * Reports whether a facet may ship a module with moduleId in web.modules (9.4):
 * equals the unprefixed facet name or starts with it and a dot.
 */
export function moduleInFacet(facetName: string, moduleId: string): boolean {
  if (!isModuleId(moduleId)) return false;
  const { local } = splitPeerFacet(facetName);
  return moduleId === local || moduleId.startsWith(`${local}.`);
}

export interface AssetRef {
  path: string;
  hash: Uint8Array;
}

export interface ModuleEntry {
  facet: string;
  record: ModuleRecord;
  id: string;
  version: string;
  hash: Uint8Array;
  url: string;
  deps: string[];
  hostApi: string;
  assets: AssetRef[];
  load: 'eager' | 'lazy';
}

export interface ModuleRejection {
  facet: string;
  id: string;
  version: string;
  reason: string;
}

function asString(v: unknown, what: string): string {
  if (typeof v !== 'string') throw new Error(`web: ${what} must be a string`);
  return v;
}

function asBytes(v: unknown, what: string): Uint8Array {
  if (!(v instanceof Uint8Array)) throw new Error(`web: ${what} must be bytes`);
  return v;
}

function getField(obj: unknown, key: string): unknown {
  if (obj instanceof Map) return obj.get(key);
  if (obj && typeof obj === 'object') return (obj as Record<string, unknown>)[key];
  return undefined;
}

function hasField(obj: unknown, key: string): boolean {
  if (obj instanceof Map) return obj.has(key);
  if (obj && typeof obj === 'object') return Object.prototype.hasOwnProperty.call(obj, key);
  return false;
}

/** Decodes a single web-module entry from raw CBOR bytes or a decoded CBOR map. */
export function decodeModuleEntry(input: Uint8Array | Map<unknown, unknown> | Record<string, unknown>, facet = ''): ModuleEntry {
  const raw = input instanceof Uint8Array ? input : cbor.encode(input);
  const record = decodeModuleRecord(raw);
  if (!isModuleId(record.id)) throw new Error(`web: module id ${JSON.stringify(record.id)} does not follow the module-id grammar`);
  parseVersion(record.version);
  if (record.hash.length !== 33 || record.hash[0] !== 0x01) {
    throw new Error(`web: module ${record.id}: hash must be 0x01 || SHA-256`);
  }

  const decoded = cbor.decode(raw, { noFloats: true });
  const url = asString(getField(decoded, 'url'), 'url');
  const hostApi = asString(getField(decoded, 'hostApi'), 'hostApi');
  parseRange(hostApi);

  const rawDeps = getField(decoded, 'deps');
  if (!Array.isArray(rawDeps)) throw new Error(`web: module ${record.id}: deps must be a list of module ids`);
  const deps: string[] = [];
  for (const d of rawDeps) {
    if (typeof d !== 'string' || !isModuleId(d)) {
      throw new Error(`web: module ${record.id}: deps must be a list of module ids`);
    }
    deps.push(d);
  }

  const assets: AssetRef[] = [];
  if (hasField(decoded, 'assets')) {
    const rawAssets = getField(decoded, 'assets');
    if (!Array.isArray(rawAssets)) throw new Error(`web: module ${record.id}: assets must be a list`);
    for (const a of rawAssets) {
      const p = asString(getField(a, 'path'), 'asset.path');
      const h = asBytes(getField(a, 'hash'), 'asset.hash');
      if (!p || h.length !== 33 || h[0] !== 0x01) {
        throw new Error(`web: module ${record.id}: asset must have path and 0x01||SHA-256 hash`);
      }
      assets.push({ path: p, hash: h });
    }
  }

  let load: 'eager' | 'lazy' = 'eager';
  if (hasField(decoded, 'load')) {
    const l = getField(decoded, 'load');
    if (l !== 'eager' && l !== 'lazy') throw new Error(`web: module ${record.id}: load must be "eager" or "lazy"`);
    load = l;
  }

  return {
    facet,
    record,
    id: record.id,
    version: record.version,
    hash: record.hash,
    url,
    deps,
    hostApi,
    assets,
    load,
  };
}

/** Extracts and scope-checks web.modules from a single facet (9.4). */
export function extractFacetModules(facet: Facet): ModuleEntry[] {
  const raw = facet.annotations[ANN_MODULES];
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new Error(`web: facet ${facet.name}: web.modules must be a list of web-module entries`);
  }
  const out: ModuleEntry[] = [];
  for (let i = 0; i < raw.length; i++) {
    const entry = decodeModuleEntry(raw[i] as Uint8Array | Map<unknown, unknown> | Record<string, unknown>, facet.name);
    if (!moduleInFacet(facet.name, entry.id)) {
      throw new Error(`web: facet ${facet.name} may not ship module ${JSON.stringify(entry.id)} (9.4)`);
    }
    out.push(entry);
  }
  return out;
}

/** Gathers modules from all facets of a schema, reporting malformed or out-of-scope entries. */
export function extractSchemaModules(sc: Schema): { entries: ModuleEntry[]; rejected: ModuleRejection[] } {
  const entries: ModuleEntry[] = [];
  const rejected: ModuleRejection[] = [];
  for (const f of sc.facets) {
    try {
      entries.push(...extractFacetModules(f));
    } catch (e) {
      rejected.push({
        facet: f.name,
        id: f.name,
        version: f.version,
        reason: `invalid_modules: ${(e as Error).message}`,
      });
    }
  }
  return { entries, rejected };
}

export interface FileRef {
  hash: Uint8Array;
  ext: string;
  entry: ModuleEntry;
}

function extOf(p: string): string {
  const clean = p.split('?')[0].split('#')[0];
  const slash = clean.lastIndexOf('/');
  const base = slash >= 0 ? clean.slice(slash + 1) : clean;
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1) : '';
}

export function moduleFiles(entries: readonly ModuleEntry[]): FileRef[] {
  const out: FileRef[] = [];
  for (const entry of entries) {
    out.push({ hash: entry.hash, ext: extOf(entry.url) || 'js', entry });
    for (const a of entry.assets) {
      out.push({ hash: a.hash, ext: extOf(a.path), entry });
    }
  }
  return out;
}

export interface TopLevelWebAnnotations {
  certificates: Certificate[];
  revocation?: Revocation;
  apply: ApplyMode;
  config: Record<string, unknown>;
}

/** Reads top-level web.* annotations from a schema (9.4, 9.5, 9.6). */
export function extractTopLevelWeb(sc: Schema): TopLevelWebAnnotations {
  const certificates: Certificate[] = [];
  let revocation: Revocation | undefined;
  let apply: ApplyMode = 'hot';
  const config: Record<string, unknown> = {};

  const rawKeys = sc.annotations[ANN_KEYS];
  if (Array.isArray(rawKeys)) {
    for (const k of rawKeys) {
      try {
        const bytes = k instanceof Uint8Array ? k : cbor.encode(k);
        certificates.push(decodeCertificate(bytes));
      } catch {
        // invalid cert entry skipped; cannot sign anything
      }
    }
  }

  const rawRev = sc.annotations[ANN_REVOKED];
  if (rawRev !== undefined) {
    try {
      const bytes = rawRev instanceof Uint8Array ? rawRev : cbor.encode(rawRev);
      revocation = decodeRevocation(bytes);
    } catch {
      // malformed revocation ignored
    }
  }

  const rawApply = sc.annotations[ANN_APPLY];
  if (rawApply === 'hot' || rawApply === 'reload' || rawApply === 'prompt') {
    apply = rawApply;
  }

  for (const [k, v] of Object.entries(sc.annotations)) {
    if (k.startsWith('web.') && k !== ANN_KEYS && k !== ANN_REVOKED && k !== ANN_APPLY && k !== ANN_MODULES) {
      config[k] = v;
    }
  }

  return { certificates, revocation, apply, config };
}

// ---------------------------------------------------------------------------
// ModuleLoader (9.4, 9.5)
// ---------------------------------------------------------------------------

export interface LoaderState {
  rollback: Rollback;
  revocation?: Revocation;
}

export interface ModuleLoaderOptions {
  roots: readonly Uint8Array[];
  hostApi: string;
  state?: LoaderState;
  nowSeconds?: () => number;
  allowUnsigned?: boolean;
  verify?: SignatureVerifier;
}

export const LoaderReason = {
  hostApiMismatch: 'host_api_mismatch',
  rollback: 'rollback',
} as const;

export class ModuleLoader {
  readonly roots: readonly Uint8Array[];
  readonly hostApi: string;
  readonly state: LoaderState;
  readonly nowSeconds: () => number;
  readonly allowUnsigned: boolean;
  readonly verify?: SignatureVerifier;

  constructor(opts: ModuleLoaderOptions) {
    this.roots = opts.roots;
    this.hostApi = opts.hostApi;
    this.state = opts.state ?? { rollback: new Rollback() };
    this.nowSeconds = opts.nowSeconds ?? (() => Math.floor(Date.now() / 1000));
    this.allowUnsigned = opts.allowUnsigned ?? false;
    this.verify = opts.verify;
  }

  /**
   * Filters a schema's modules by hostApi, signature/cert/revocation, and rollback.
   * Updates state.revocation with the highest-seq root-signed revocation list seen.
   */
  async accept(sc: Schema): Promise<{ accepted: ModuleEntry[]; rejected: ModuleRejection[] }> {
    const top = extractTopLevelWeb(sc);
    const rev = await selectRevocation(this.roots, [this.state.revocation, top.revocation], this.verify);
    this.state.revocation = rev;

    const verifier = new Verifier({
      roots: this.roots,
      certificates: top.certificates,
      revocation: rev,
      nowSeconds: this.nowSeconds(),
      verify: this.verify,
    });

    const { entries, rejected } = extractSchemaModules(sc);
    const accepted: ModuleEntry[] = [];

    for (const e of entries) {
      const rej = (reason: string) => rejected.push({ facet: e.facet, id: e.id, version: e.version, reason });
      let rangeOk = false;
      try {
        rangeOk = rangeContains(parseRange(e.hostApi), this.hostApi);
      } catch {
        rangeOk = false;
      }
      if (!rangeOk) {
        rej(LoaderReason.hostApiMismatch);
        continue;
      }
      const sigReason = await verifier.verify(e.record);
      if (sigReason !== VerifyReason.ok && !this.allowUnsigned) {
        rej(sigReason);
        continue;
      }
      if (!this.state.rollback.allowed(e.id, e.version)) {
        rej(LoaderReason.rollback);
        continue;
      }
      accepted.push(e);
    }

    return { accepted, rejected };
  }
}

// ---------------------------------------------------------------------------
// HTTP Client (9.1, 9.2, 9.3)
// ---------------------------------------------------------------------------

export interface ClientInfo {
  name?: string;
  version?: string;
  hostApi: string;
}

export interface ConnectResponse {
  ticket: string;
  ticketExpiresAt: string;
  sessionExpiresAt: string;
  endpoints: {
    webtransport?: string;
    websocket?: string;
  };
  protocolVersions: number[];
  schemaHash: string;
  schemaUrl: string;
  serverCertificateHashes: string[] | null;
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
  ) {
    super(`web: HTTP ${status}: ${body.trim()}`);
    this.name = 'HttpError';
  }
}

export type FetchLike = (input: string, init?: RequestInitLike) => Promise<ResponseLike>;

export interface RequestInitLike {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  credentials?: 'include' | 'same-origin' | 'omit';
  signal?: AbortSignal;
}

export interface ResponseLike {
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
  json(): Promise<unknown>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface WebClientOptions {
  baseUrl: string;
  fetch?: FetchLike;
  credentials?: 'include' | 'same-origin' | 'omit';
  authorize?: (req: { url: string; headers: Record<string, string> }) => void | Promise<void>;
}

export class WebClient {
  readonly baseUrl: string;
  private readonly fetchFn: FetchLike;
  private readonly credentials?: 'include' | 'same-origin' | 'omit';
  private readonly authorize?: WebClientOptions['authorize'];

  constructor(opts: WebClientOptions) {
    this.baseUrl = opts.baseUrl;
    const globalFetch = (globalThis as { fetch?: FetchLike }).fetch;
    const f = opts.fetch ?? (globalFetch ? globalFetch.bind(globalThis) : undefined);
    if (!f) throw new Error('web: global fetch is unavailable; pass opts.fetch');
    this.fetchFn = f;
    this.credentials = opts.credentials;
    this.authorize = opts.authorize;
  }

  resolve(ref: string): string {
    return new URL(ref, this.baseUrl).toString();
  }

  private async request(method: string, ref: string, body?: unknown, signal?: AbortSignal): Promise<ResponseLike> {
    const url = this.resolve(ref);
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.authorize) await this.authorize({ url, headers });
    const res = await this.fetchFn(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: this.credentials,
      signal,
    });
    if (!res.ok) {
      throw new HttpError(res.status, await res.text());
    }
    return res;
  }

  async connect(info: ClientInfo, knownSchemaHash?: Uint8Array, signal?: AbortSignal): Promise<ConnectResponse> {
    const body: Record<string, unknown> = { client: info };
    if (knownSchemaHash) body.knownSchemaHash = encodeHash(knownSchemaHash);
    const res = await this.request('POST', CONNECT_PATH, body, signal);
    return (await res.json()) as ConnectResponse;
  }

  async refresh(endpoint: string, signal?: AbortSignal): Promise<string> {
    const res = await this.request('POST', CONNECT_PATH, { refresh: { endpoint } }, signal);
    const data = (await res.json()) as { ticket?: string };
    if (!data.ticket) throw new Error('web: refresh response holds no ticket');
    return data.ticket;
  }

  async fetchSchema(ref: string, expectedHash: Uint8Array, signal?: AbortSignal): Promise<{ schema: Schema; raw: Uint8Array }> {
    const res = await this.request('GET', ref, undefined, signal);
    const raw = new Uint8Array(await res.arrayBuffer());
    const sc = spSchema.decodeSchema(raw, { maxBytes: 8 << 20 });
    const h = spSchema.schemaHash(sc);
    if (!cbor.bytesEqual(h, expectedHash)) {
      throw new Error('web: fetched schema does not match its expected hash');
    }
    return { schema: sc, raw };
  }

  async fetchFile(
    ref: string,
    expectedHash: Uint8Array,
    signal?: AbortSignal,
  ): Promise<{ bytes: Uint8Array; cacheControl: string | null }> {
    const res = await this.request('GET', ref, undefined, signal);
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (!cbor.bytesEqual(fileHash(bytes), expectedHash)) {
      throw new Error(`web: file ${ref} does not match its signed hash`);
    }
    return { bytes, cacheControl: res.headers.get('cache-control') };
  }
}
