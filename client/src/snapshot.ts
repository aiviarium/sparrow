// Offline snapshots (spec 9.6): canonical CBOR snapshot encoding,
// verification, rollback state machine, and storage adapters.
// Mirrors go/web/client.go Snapshot / Snapshots.

import { cbor, schema as spSchema, type Schema } from '@aiviarium/sparrow';
import {
  Rollback,
  decodeRevocation,
  encodeRevocation,
  fileHash,
  type Revocation,
} from './signing.js';
import { decodeModuleEntry, encodeHash, moduleFiles, type ModuleEntry } from './web.js';

export interface Snapshot {
  schemaHash: Uint8Array;
  /** Canonical CBOR encoding of the schema. */
  schema: Uint8Array;
  /** Welcome.props encoded as CBOR, or null. */
  props: Uint8Array | null;
  modules: ModuleEntry[];
  /** Keyed by hex(hash) -> raw file bytes. */
  files: Map<string, Uint8Array>;
  /** Integer epoch seconds (tag 1). */
  createdAt: number;
}

export function createSnapshot(
  sc: Schema,
  props: Record<string, unknown> | null,
  modules: readonly ModuleEntry[],
  files: ReadonlyMap<string, Uint8Array>,
  createdAtSeconds = Math.floor(Date.now() / 1000),
): Snapshot {
  const canonical = spSchema.canonicalSchema(sc);
  const schemaBytes = spSchema.schemaCanonicalBytes(canonical);
  const hash = spSchema.schemaHash(canonical);
  const propsRaw = props ? cbor.encode(props) : null;
  const copy = new Map<string, Uint8Array>();

  for (const f of moduleFiles(modules)) {
    const hex = cbor.toHex(f.hash);
    const data = files.get(hex);
    if (!data) {
      throw new Error(`web: snapshot: file ${encodeHash(f.hash)} of module ${f.entry.id} is missing`);
    }
    copy.set(hex, data.slice());
  }

  const snap: Snapshot = {
    schemaHash: hash,
    schema: schemaBytes,
    props: propsRaw,
    modules: [...modules],
    files: copy,
    createdAt: Math.trunc(createdAtSeconds),
  };
  verifySnapshot(snap);
  return snap;
}

/** Verifies schema hash and every referenced module/asset file hash (9.6 boot step 1). */
export function verifySnapshot(s: Snapshot): Schema {
  const sc = spSchema.decodeSchema(s.schema, { maxBytes: 8 << 20 });
  const h = spSchema.schemaHash(sc);
  if (!cbor.bytesEqual(h, s.schemaHash)) {
    throw new Error('web: snapshot schema does not match its hash');
  }
  for (const f of moduleFiles(s.modules)) {
    const hex = cbor.toHex(f.hash);
    const data = s.files.get(hex);
    if (!data) {
      throw new Error(`web: snapshot: file ${encodeHash(f.hash)} is missing`);
    }
    if (!cbor.bytesEqual(fileHash(data), f.hash)) {
      throw new Error(`web: snapshot: file ${encodeHash(f.hash)} does not match its hash`);
    }
  }
  return sc;
}

export function decodeSnapshotProps(s: Snapshot): Record<string, unknown> {
  if (!s.props) return {};
  const v = cbor.decode(s.props);
  if (v instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, val] of v) {
      if (typeof k === 'string') out[k] = val;
    }
    return out;
  }
  if (v && typeof v === 'object') return v as Record<string, unknown>;
  return {};
}

export function encodeSnapshot(s: Snapshot): Uint8Array {
  const filesMap = new Map<Uint8Array, Uint8Array>();
  for (const [hex, data] of s.files) {
    filesMap.set(cbor.fromHex(hex), data);
  }
  const mods = s.modules.map((m) => {
    const entries = new Map<string, cbor.Raw>();
    for (const [k, v] of m.record.fields) entries.set(k, new cbor.Raw(v));
    entries.set('sig', new cbor.Raw(cbor.encode([m.record.keyId, m.record.sig])));
    return entries;
  });
  const doc = {
    schemaHash: s.schemaHash,
    schema: s.schema,
    props: s.props ? new cbor.Raw(s.props) : null,
    modules: mods,
    files: filesMap,
    createdAt: new cbor.Tag(cbor.TAG_EPOCH_TIME, s.createdAt),
  };
  return cbor.canonical(cbor.encode(doc), { noFloats: true });
}

export function decodeSnapshot(bytes: Uint8Array): Snapshot {
  cbor.validate(bytes, {});
  const r = new cbor.Reader(bytes);
  const n = r.mapHead();
  let schemaHash: Uint8Array | undefined;
  let schemaBytes: Uint8Array | undefined;
  let props: Uint8Array | null = null;
  let modules: ModuleEntry[] = [];
  const files = new Map<string, Uint8Array>();
  let createdAt = 0;

  for (let i = 0; i < n; i++) {
    const k = r.text();
    switch (k) {
      case 'schemaHash':
        schemaHash = r.bytes().slice();
        break;
      case 'schema':
        schemaBytes = r.bytes().slice();
        break;
      case 'props':
        if (r.peekNull()) r.null();
        else props = r.raw().slice();
        break;
      case 'modules': {
        const m = r.arrayHead();
        modules = [];
        for (let j = 0; j < m; j++) {
          const entry = decodeModuleEntry(r.raw());
          modules.push(entry);
        }
        break;
      }
      case 'files': {
        const m = r.mapHead();
        for (let j = 0; j < m; j++) {
          const h = r.bytes();
          const data = r.bytes().slice();
          files.set(cbor.toHex(h), data);
        }
        break;
      }
      case 'createdAt': {
        const tag = r.tag();
        if (tag !== cbor.TAG_EPOCH_TIME) throw new Error('web: snapshot createdAt must have tag 1');
        const t = r.int();
        if (typeof t === 'bigint') throw new Error('web: snapshot createdAt out of safe range');
        createdAt = t;
        break;
      }
      default:
        r.skip();
    }
  }

  if (!schemaHash || !schemaBytes) throw new Error('web: snapshot missing schema or schemaHash');
  const snap: Snapshot = { schemaHash, schema: schemaBytes, props, modules, files, createdAt };
  verifySnapshot(snap);
  return snap;
}

// ---------------------------------------------------------------------------
// Rollback state machine (9.5, 9.6)
// ---------------------------------------------------------------------------

export interface StoredSnapshots {
  current?: Uint8Array;
  previous?: Uint8Array;
  rollback?: Record<string, string>;
  revocation?: Uint8Array;
  booted?: boolean;
}

export class Snapshots {
  current?: Snapshot;
  previous?: Snapshot;
  private isBooted = false;
  rollback = new Rollback();
  revocation?: Revocation;

  get bootedOnce(): boolean {
    return this.isBooted;
  }

  install(next: Snapshot): void {
    verifySnapshot(next);
    if (this.current && this.isBooted) {
      this.previous = this.current;
    }
    this.current = next;
    this.isBooted = false;
  }

  booted(): void {
    if (!this.current) throw new Error('web: no snapshot');
    for (const e of this.current.modules) {
      this.rollback.record(e.id, e.version);
    }
    this.isBooted = true;
  }

  rollBack(): Snapshot {
    if (!this.previous) throw new Error('web: no previous snapshot');
    this.current = this.previous;
    this.previous = undefined;
    this.isBooted = true;
    return this.current;
  }

  exportStored(): StoredSnapshots {
    return {
      current: this.current ? encodeSnapshot(this.current) : undefined,
      previous: this.previous ? encodeSnapshot(this.previous) : undefined,
      rollback: this.rollback.toJSON(),
      revocation: this.revocation ? encodeRevocation(this.revocation) : undefined,
      booted: this.isBooted,
    };
  }

  static fromStored(stored: StoredSnapshots): Snapshots {
    const s = new Snapshots();
    if (stored.rollback) s.rollback = new Rollback(stored.rollback);
    if (stored.revocation) {
      try {
        s.revocation = decodeRevocation(stored.revocation);
      } catch {
        // ignore corrupted revocation; next verified schema restores it
      }
    }
    if (stored.current) {
      try {
        s.current = decodeSnapshot(stored.current);
      } catch {
        s.current = undefined;
      }
    }
    if (stored.previous) {
      try {
        s.previous = decodeSnapshot(stored.previous);
      } catch {
        s.previous = undefined;
      }
    }
    s.isBooted = Boolean(s.current && stored.booted);
    return s;
  }
}

// ---------------------------------------------------------------------------
// Snapshot Stores (IndexedDB for browsers, Memory for tests)
// ---------------------------------------------------------------------------

export interface SnapshotStore {
  load(): Promise<StoredSnapshots | null>;
  save(data: StoredSnapshots): Promise<void>;
  clear(): Promise<void>;
}

export class MemorySnapshotStore implements SnapshotStore {
  private data: StoredSnapshots | null = null;

  async load(): Promise<StoredSnapshots | null> {
    return this.data;
  }

  async save(data: StoredSnapshots): Promise<void> {
    this.data = data;
  }

  async clear(): Promise<void> {
    this.data = null;
  }
}

type IDBFactoryLike = {
  open(name: string, version?: number): {
    result: {
      objectStoreNames: { contains(n: string): boolean };
      createObjectStore(n: string): void;
      transaction(store: string, mode: 'readonly' | 'readwrite'): {
        objectStore(n: string): {
          get(key: string): { result: unknown; onsuccess: (() => void) | null; onerror: (() => void) | null };
          put(val: unknown, key: string): void;
          delete(key: string): void;
        };
        oncomplete: (() => void) | null;
        onerror: (() => void) | null;
        error: unknown;
      };
      close(): void;
    };
    error: unknown;
    onupgradeneeded: (() => void) | null;
    onsuccess: (() => void) | null;
    onerror: (() => void) | null;
  };
};

/**
 * Browser IndexedDB snapshot store (spec 9.6: atomic single-transaction writes).
 */
export class IndexedDBSnapshotStore implements SnapshotStore {
  constructor(
    private readonly dbName = 'sparrow-snapshots',
    private readonly key = 'state',
    private readonly idb: IDBFactoryLike | undefined = (globalThis as { indexedDB?: IDBFactoryLike }).indexedDB,
  ) {}

  private open(): Promise<ReturnType<IDBFactoryLike['open']>['result']> {
    if (!this.idb) return Promise.reject(new Error('snapshot: indexedDB is unavailable'));
    return new Promise((resolve, reject) => {
      const req = this.idb!.open(this.dbName, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains('snapshots')) {
          req.result.createObjectStore('snapshots');
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error('snapshot: indexedDB open failed'));
    });
  }

  async load(): Promise<StoredSnapshots | null> {
    const db = await this.open();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction('snapshots', 'readonly');
        const req = tx.objectStore('snapshots').get(this.key);
        req.onsuccess = () => resolve((req.result as StoredSnapshots | undefined) ?? null);
        req.onerror = () => reject(tx.error ?? new Error('snapshot: indexedDB read failed'));
      });
    } finally {
      db.close();
    }
  }

  async save(data: StoredSnapshots): Promise<void> {
    const db = await this.open();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction('snapshots', 'readwrite');
        tx.objectStore('snapshots').put(data, this.key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error ?? new Error('snapshot: indexedDB write failed'));
      });
    } finally {
      db.close();
    }
  }

  async clear(): Promise<void> {
    const db = await this.open();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction('snapshots', 'readwrite');
        tx.objectStore('snapshots').delete(this.key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error ?? new Error('snapshot: indexedDB delete failed'));
      });
    } finally {
      db.close();
    }
  }
}
