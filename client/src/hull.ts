// The minimal, design-agnostic empty hull and glue kernel (spec 4.8, 5.3,
// 5.5, 9.1-9.6, 10.3). Connects to a Sparrow hub, verifies and topologically
// loads signed ESM modules (including a primary shell module and dynamically
// dialed-in feature modules), reconciles live SchemaUpdates, and provides a
// shared runtime bag + capability registry without imposing UI or CSS opinions.

import {
  Session,
  SparrowError,
  Status,
  cbor,
  realClock,
  type Clock,
  type Conn,
  type Facet,
  type Params,
  type Schema,
} from '@aiviarium/sparrow';
import { type SignatureVerifier } from './signing.js';
import {
  MemorySnapshotStore,
  Snapshots,
  createSnapshot,
  decodeSnapshotProps,
  verifySnapshot,
  type Snapshot,
  type SnapshotStore,
} from './snapshot.js';
import {
  connectBrowserTransport,
  type BrowserTransportOptions,
  type BrowserTransportResult,
  type TransportEndpoints,
} from './transport.js';
import {
  MODS_PATH,
  ModuleLoader,
  WebClient,
  decodeHash,
  encodeHash,
  extractTopLevelWeb,
  moduleFiles,
  type ApplyMode,
  type ClientInfo,
  type FetchLike,
  type ModuleEntry,
  type ModuleRejection,
  type WebClientOptions,
} from './web.js';

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'offline' | 'stopped';

export interface ConnectionState {
  status: ConnectionStatus;
  binding?: 'webtransport' | 'websocket' | 'custom';
  endpoint?: string;
  session?: Session;
  error?: Error;
}

export type ModuleDisposer = void | (() => void | Promise<void>) | { dispose?: () => void | Promise<void> };
export type ModuleFactory = (host: ModuleHost) => ModuleDisposer | Promise<ModuleDisposer>;

export type ModuleImporter = (
  entry: ModuleEntry,
  bytes: Uint8Array,
  assets: ModuleAssets,
) => Promise<ModuleFactory | { default: ModuleFactory }>;

export interface LoadedModuleInfo {
  id: string;
  version: string;
  facet: string;
  hash: Uint8Array;
  load: 'eager' | 'lazy';
}

export interface PendingUpdateInfo {
  apply: ApplyMode;
  schema: Schema;
  hash: Uint8Array;
  accepted: ModuleEntry[];
  rejected: ModuleRejection[];
}

export interface ModuleAssets {
  get(path: string): Promise<Uint8Array>;
  url(path: string): Promise<string>;
}

export interface ModuleHost {
  readonly module: {
    readonly id: string;
    readonly version: string;
    readonly facet: string;
    readonly entry: ModuleEntry;
  };
  readonly session: Session | undefined;
  readonly schema: Schema;
  readonly props: Readonly<Record<string, unknown>>;
  readonly config: Readonly<Record<string, unknown>>;
  /** Host-embedded shared runtimes (e.g. SolidJS), frozen so modules never bundle duplicates (9.4). */
  readonly shared: Readonly<Record<string, unknown>>;
  facets(): Facet[];
  facet(nameOrId: string | number): Facet | undefined;
  implementationsOf(interfaceHash: Uint8Array): Facet[];
  defaultFor(interfaceHash: Uint8Array): Facet | undefined;
  provide<T>(key: string, value: T): () => void;
  get<T>(key: string): T | undefined;
  onCapability<T>(key: string, cb: (value: T | undefined) => void): () => void;
  readonly assets: ModuleAssets;
  loadLazy(id: string): Promise<LoadedModuleInfo>;
  onSchemaChange(cb: (schema: Schema) => void): () => void;
  onConnectionChange(cb: (state: ConnectionState) => void): () => void;
  onDispose(cb: () => void | Promise<void>): () => void;
}

/**
 * Design-agnostic capability bus: lets a baked-in shell or a primary shell
 * module expose its contribution API (e.g. routes, nav, panels) to dialed-in
 * feature modules without coupling the hull to any UI framework.
 */
export class CapabilityRegistry {
  private readonly values = new Map<string, unknown>();
  private readonly listeners = new Map<string, Set<(value: unknown) => void>>();

  provide<T>(key: string, value: T): () => void {
    this.values.set(key, value);
    this.emit(key, value);
    let active = true;
    return () => {
      if (!active) return;
      active = false;
      if (this.values.get(key) === value) {
        this.values.delete(key);
        this.emit(key, undefined);
      }
    };
  }

  get<T>(key: string): T | undefined {
    return this.values.get(key) as T | undefined;
  }

  has(key: string): boolean {
    return this.values.has(key);
  }

  on<T>(key: string, cb: (value: T | undefined) => void): () => void {
    let set = this.listeners.get(key);
    if (!set) {
      set = new Set();
      this.listeners.set(key, set);
    }
    const fn = cb as (value: unknown) => void;
    set.add(fn);
    if (this.values.has(key)) {
      cb(this.values.get(key) as T);
    }
    return () => {
      set?.delete(fn);
      if (set && set.size === 0) this.listeners.delete(key);
    };
  }

  private emit(key: string, value: unknown): void {
    const set = this.listeners.get(key);
    if (!set) return;
    for (const fn of [...set]) {
      fn(value);
    }
  }
}

export interface HullOptions {
  baseUrl: string;
  hostApi: string;
  client?: Omit<ClientInfo, 'hostApi'>;
  rootKeys: readonly Uint8Array[];
  allowUnsigned?: boolean;
  shared?: Record<string, unknown>;
  authorize?: WebClientOptions['authorize'];
  credentials?: WebClientOptions['credentials'];
  fetch?: FetchLike;
  snapshotStore?: SnapshotStore;
  importer?: ModuleImporter;
  connectTransport?: (endpoints: TransportEndpoints, opts: BrowserTransportOptions) => Promise<BrowserTransportResult>;
  serverCertificateHashes?: Uint8Array[];
  WebSocket?: BrowserTransportOptions['WebSocket'];
  WebTransport?: BrowserTransportOptions['WebTransport'];
  webTransportTimeoutMs?: number;
  optimistic?: boolean;
  reconnect?: boolean | { minDelayMs?: number; maxDelayMs?: number };
  now?: () => number;
  clock?: Clock;
  verify?: SignatureVerifier;
  onUpdateAvailable?: (info: PendingUpdateInfo) => void;
  onModulesChanged?: (modules: LoadedModuleInfo[]) => void;
  onModuleError?: (err: { id: string; version: string; reason: string; error?: unknown }) => void;
  onConnectionChange?: (state: ConnectionState) => void;
  onSchemaChange?: (schema: Schema) => void;
}

const MIME_BY_EXT: Record<string, string> = {
  js: 'text/javascript',
  mjs: 'text/javascript',
  css: 'text/css',
  json: 'application/json',
  svg: 'image/svg+xml',
  wasm: 'application/wasm',
};

function mimeForPath(p: string): string {
  const clean = p.split('?')[0].split('#')[0];
  const dot = clean.lastIndexOf('.');
  const ext = dot > 0 ? clean.slice(dot + 1).toLowerCase() : '';
  return MIME_BY_EXT[ext] ?? 'application/octet-stream';
}

/** Default browser ESM importer using hash-verified blob: URLs (spec 9.6). */
export const blobModuleImporter: ModuleImporter = async (_entry, bytes) => {
  const URLCtor = (globalThis as { URL?: { createObjectURL?: (b: unknown) => string; revokeObjectURL?: (u: string) => void } }).URL;
  const BlobCtor = (globalThis as { Blob?: new (parts: unknown[], opts?: { type?: string }) => unknown }).Blob;
  if (!URLCtor?.createObjectURL || !BlobCtor) {
    throw new Error('hull: blob: URL import is unavailable in this environment; pass opts.importer');
  }
  const url = URLCtor.createObjectURL(new BlobCtor([bytes], { type: 'text/javascript' }));
  try {
    return (await import(/* @vite-ignore */ url)) as ModuleFactory | { default: ModuleFactory };
  } finally {
    URLCtor.revokeObjectURL?.(url);
  }
};

interface ActiveModule {
  entry: ModuleEntry;
  disposers: Array<() => void | Promise<void>>;
  deps: string[];
}

interface PendingSnapshotUpdate {
  apply: ApplyMode;
  schema: Schema;
  props: Record<string, unknown>;
  accepted: ModuleEntry[];
  rejected: ModuleRejection[];
  files: Map<string, Uint8Array>;
  snapshot: Snapshot;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return cbor.bytesEqual(a, b);
}

/**
 * Topologically orders modules so every dependency loads before its dependents.
 * Reports modules with missing dependencies or dependency cycles.
 */
function topoOrder(entries: readonly ModuleEntry[]): {
  ordered: ModuleEntry[];
  bad: Array<{ entry: ModuleEntry; reason: string }>;
} {
  const byId = new Map<string, ModuleEntry>();
  const duplicates: Array<{ entry: ModuleEntry; reason: string }> = [];
  for (const e of entries) {
    if (byId.has(e.id)) {
      duplicates.push({ entry: e, reason: 'duplicate_module_id' });
    } else {
      byId.set(e.id, e);
    }
  }

  const state = new Map<string, 'visiting' | 'visited' | 'failed'>();
  const ordered: ModuleEntry[] = [];
  const bad: Array<{ entry: ModuleEntry; reason: string }> = [...duplicates];

  const visit = (id: string, stack: string[]): boolean => {
    const st = state.get(id);
    if (st === 'visited') return true;
    if (st === 'failed') return false;
    if (st === 'visiting') return false;
    const entry = byId.get(id);
    if (!entry) return false;

    state.set(id, 'visiting');
    for (const dep of entry.deps) {
      if (stack.includes(dep) || dep === id) {
        state.set(id, 'failed');
        bad.push({ entry, reason: 'dependency_cycle' });
        return false;
      }
      if (!byId.has(dep)) {
        state.set(id, 'failed');
        bad.push({ entry, reason: `missing_dependency: ${dep}` });
        return false;
      }
      if (!visit(dep, [...stack, id])) {
        state.set(id, 'failed');
        bad.push({ entry, reason: `failed_dependency: ${dep}` });
        return false;
      }
    }
    state.set(id, 'visited');
    ordered.push(entry);
    return true;
  };

  for (const e of byId.values()) {
    visit(e.id, []);
  }

  return { ordered, bad };
}

export class Hull {
  readonly capabilities = new CapabilityRegistry();
  readonly shared: Readonly<Record<string, unknown>>;
  readonly web: WebClient;

  private readonly opts: HullOptions;
  private readonly store: SnapshotStore;
  private readonly importer: ModuleImporter;
  private readonly clock: Clock;
  private readonly nowMs: () => number;
  private readonly connectTransportFn: NonNullable<HullOptions['connectTransport']>;
  private readonly transportPref = new Map<string, 'webtransport' | 'websocket'>();

  private snapshots = new Snapshots();
  private loader: ModuleLoader;
  private currentSchema: Schema = { format: 2, name: '', version: '', facets: [], annotations: {} };
  private currentProps: Record<string, unknown> = {};
  private currentConfig: Record<string, unknown> = {};
  private currentAccepted = new Map<string, ModuleEntry>();
  private currentFiles = new Map<string, Uint8Array>();
  private active = new Map<string, ActiveModule>();
  private loadOrder: string[] = [];
  private pendingUpdate?: PendingSnapshotUpdate;

  private connState: ConnectionState = { status: 'disconnected' };
  private activeSession?: Session;
  private activeEndpoint?: string;
  private activeBinding?: 'webtransport' | 'websocket' | 'custom';
  private refreshInFlight = false;
  private knownParams?: Params;
  private consecutiveOptFailures = 0;
  private hasBootedSession = false;
  private stopped = false;
  private started = false;
  private reconnectTimer?: unknown;
  private reconcileChain: Promise<void> = Promise.resolve();
  private schemaListeners = new Set<(schema: Schema) => void>();
  private connListeners = new Set<(state: ConnectionState) => void>();

  constructor(opts: HullOptions) {
    this.opts = opts;
    this.shared = Object.freeze({ ...(opts.shared ?? {}) });
    this.web = new WebClient({
      baseUrl: opts.baseUrl,
      fetch: opts.fetch,
      authorize: opts.authorize,
      credentials: opts.credentials,
    });
    this.store = opts.snapshotStore ?? new MemorySnapshotStore();
    this.importer = opts.importer ?? blobModuleImporter;
    this.clock = opts.clock ?? realClock;
    this.nowMs = opts.now ?? (() => this.clock.now());
    this.connectTransportFn = opts.connectTransport ?? connectBrowserTransport;
    this.loader = new ModuleLoader({
      roots: opts.rootKeys,
      hostApi: opts.hostApi,
      state: { rollback: this.snapshots.rollback, revocation: this.snapshots.revocation },
      nowSeconds: () => Math.floor(this.nowMs() / 1000),
      allowUnsigned: opts.allowUnsigned,
      verify: opts.verify,
    });
  }

  get state(): ConnectionState {
    return this.connState;
  }

  get session(): Session | undefined {
    return this.activeSession;
  }

  get schema(): Schema {
    return this.currentSchema;
  }

  get props(): Readonly<Record<string, unknown>> {
    return this.currentProps;
  }

  get config(): Readonly<Record<string, unknown>> {
    return this.currentConfig;
  }

  get snapshotState(): Snapshots {
    return this.snapshots;
  }

  loadedModules(): LoadedModuleInfo[] {
    return this.loadOrder
      .map((id) => this.active.get(id))
      .filter((m): m is ActiveModule => Boolean(m))
      .map((m) => ({
        id: m.entry.id,
        version: m.entry.version,
        facet: m.entry.facet,
        hash: m.entry.hash,
        load: m.entry.load,
      }));
  }

  /** Starts the hull: boots from any verified offline snapshot, then connects online. */
  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    this.stopped = false;
    await this.bootOfflineSnapshot();
    if (this.stopped) return;
    await this.connectOnce(true);
  }

  /** Stops the hull, closes any active session, and disposes all loaded modules. */
  async stop(): Promise<void> {
    this.stopped = true;
    if (this.reconnectTimer !== undefined) {
      this.clock.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    const s = this.activeSession;
    this.activeSession = undefined;
    if (s && s.isOpen) {
      await s.close(Status.going_away, 'client stopped');
    }
    await this.reconcileChain;
    await this.disposeAllModules();
    this.setConnState({ status: 'stopped' });
  }

  /** Applies a queued update when web.apply is "prompt" or "reload". */
  async applyPendingUpdate(): Promise<void> {
    const p = this.pendingUpdate;
    if (!p) return;
    this.pendingUpdate = undefined;
    await this.commitReconcile(p);
  }

  /** Loads an accepted lazy module (and its accepted dependencies) on demand. */
  async loadLazy(id: string): Promise<LoadedModuleInfo> {
    if (this.active.has(id)) {
      const m = this.active.get(id)!;
      return { id: m.entry.id, version: m.entry.version, facet: m.entry.facet, hash: m.entry.hash, load: m.entry.load };
    }
    const entry = this.currentAccepted.get(id);
    if (!entry) throw new Error(`hull: module ${JSON.stringify(id)} is not present in the current schema`);

    // Gather transitive dependencies.
    const needed = new Map<string, ModuleEntry>();
    const gather = (cur: ModuleEntry) => {
      if (needed.has(cur.id)) return;
      needed.set(cur.id, cur);
      for (const depId of cur.deps) {
        const dep = this.currentAccepted.get(depId);
        if (!dep) throw new Error(`hull: missing dependency ${JSON.stringify(depId)} for ${JSON.stringify(cur.id)}`);
        gather(dep);
      }
    };
    gather(entry);

    const { ordered, bad } = topoOrder([...needed.values()]);
    if (bad.length > 0) {
      throw new Error(`hull: cannot load ${id}: ${bad[0].reason}`);
    }

    // Ensure files are fetched & verified.
    await this.ensureFiles(ordered, this.currentFiles);
    for (const e of ordered) {
      if (!this.active.has(e.id)) {
        await this.loadOneModule(e, this.currentFiles);
      }
    }
    this.opts.onModulesChanged?.(this.loadedModules());
    const loaded = this.active.get(id)!;
    return { id: loaded.entry.id, version: loaded.entry.version, facet: loaded.entry.facet, hash: loaded.entry.hash, load: loaded.entry.load };
  }

  onSchemaChange(cb: (schema: Schema) => void): () => void {
    this.schemaListeners.add(cb);
    return () => this.schemaListeners.delete(cb);
  }

  onConnectionChange(cb: (state: ConnectionState) => void): () => void {
    this.connListeners.add(cb);
    return () => this.connListeners.delete(cb);
  }

  // -------------------------------------------------------------------------
  // Offline snapshot boot (9.6)
  // -------------------------------------------------------------------------

  private async bootOfflineSnapshot(): Promise<void> {
    const stored = await this.store.load();
    if (!stored) return;
    this.snapshots = Snapshots.fromStored(stored);
    this.loader = new ModuleLoader({
      roots: this.opts.rootKeys,
      hostApi: this.opts.hostApi,
      state: { rollback: this.snapshots.rollback, revocation: this.snapshots.revocation },
      nowSeconds: () => Math.floor(this.nowMs() / 1000),
      allowUnsigned: this.opts.allowUnsigned,
      verify: this.opts.verify,
    });
    const cur = this.snapshots.current;
    if (!cur) return;

    const tryBoot = async (snap: Snapshot): Promise<boolean> => {
      try {
        const sc = verifySnapshot(snap);
        const props = decodeSnapshotProps(snap);
        const top = extractTopLevelWeb(sc);
        const { accepted } = await this.loader.accept(sc);
        await this.applyLoadedSet(sc, props, top.config, accepted, snap.files, false, true);
        this.setConnState({ status: 'offline' });
        return true;
      } catch {
        return false;
      }
    };

    if (await tryBoot(cur)) {
      if (!this.snapshots.bootedOnce) {
        this.snapshots.booted();
        await this.persistSnapshots();
      }
      return;
    }

    // Bad snapshot: roll back to the previous snapshot if present (9.6 step 5).
    if (this.snapshots.previous) {
      await this.disposeAllModules();
      const prev = this.snapshots.rollBack();
      if (await tryBoot(prev)) {
        await this.persistSnapshots();
      }
    }
  }

  private async persistSnapshots(): Promise<void> {
    this.snapshots.revocation = this.loader.state.revocation;
    await this.store.save(this.snapshots.exportStored());
  }

  // -------------------------------------------------------------------------
  // Connection & auth lifecycle (9.1, 9.2, 5.2, 5.3, 5.5)
  // -------------------------------------------------------------------------

  private async connectOnce(initial: boolean): Promise<void> {
    if (this.stopped) return;
    this.setConnState({ status: 'connecting' });

    try {
      const cached = this.snapshots.current;
      const info: ClientInfo = {
        name: this.opts.client?.name ?? 'sparrow-hull',
        version: this.opts.client?.version ?? '0.1.0',
        hostApi: this.opts.hostApi,
      };
      const resp = await this.web.connect(info, cached?.schemaHash);
      if (this.stopped) return;

      const remoteHash = decodeHash(resp.schemaHash);
      const cachedMatches = Boolean(cached && sameBytes(cached.schemaHash, remoteHash));
      const canOptimistic =
        (this.opts.optimistic ?? true) &&
        cachedMatches &&
        this.consecutiveOptFailures < 2 &&
        (!this.knownParams || !belowServerDefaults(this.knownParams));

      const certHashes =
        resp.serverCertificateHashes?.map(decodeHash) ?? this.opts.serverCertificateHashes;

      const tr = await this.connectTransportFn(resp.endpoints, {
        serverCertificateHashes: certHashes,
        WebSocket: this.opts.WebSocket,
        WebTransport: this.opts.WebTransport,
        webTransportTimeoutMs: this.opts.webTransportTimeoutMs,
        preferenceCache: this.transportPref,
      });

      if (this.stopped) {
        await tr.conn.close(Status.going_away, 'stopped');
        return;
      }

      const knownSchema = cached ? verifySnapshot(cached) : undefined;
      let latestParams: Params | undefined;
      let latestSchema: Schema | undefined;

      const sess = await Session.connect(tr.conn, {
        auth: { scheme: 'bearer', credentials: resp.ticket },
        knownSchema,
        knownParams: this.knownParams,
        optimistic: canOptimistic,
        clock: this.clock,
        fetchSchema: async (loc, hash) => {
          const res = await this.web.fetchSchema(loc || resp.schemaUrl, hash);
          return res.schema;
        },
        onServerSchema: (_hash, sc, params) => {
          latestSchema = sc;
          latestParams = params;
          this.knownParams = params;
        },
        onPeerSchemaUpdate: (_s, u) => {
          // 6.6 rule 1 / 10.3: return immediately so SchemaAck goes out before module downloads.
          this.enqueueSchema(u.schema, this.currentProps, false);
        },
        onAuthStatus: (s, status, expiresAt) => {
          const nowSec = Math.floor(this.nowMs() / 1000);
          if (status === Status.ok && expiresAt !== null && expiresAt - nowSec <= 120 && !this.refreshInFlight && this.activeEndpoint) {
            void this.refreshSessionAuth(s, this.activeEndpoint);
          }
        },
      });

      if (this.stopped) {
        await sess.close(Status.going_away, 'stopped');
        return;
      }

      this.consecutiveOptFailures = 0;
      this.activeSession = sess;
      this.activeEndpoint = tr.endpoint;
      this.activeBinding = tr.binding;

      const sc = sess.peerSchema ?? latestSchema;
      const props = (sess.welcome?.props ?? this.currentProps) as Record<string, unknown>;
      if (latestParams) this.knownParams = latestParams;

      this.setConnState({
        status: 'connected',
        binding: tr.binding,
        endpoint: tr.endpoint,
        session: sess,
      });

      if (sc) {
        await this.enqueueSchema(sc, props, !this.hasBootedSession);
        this.hasBootedSession = true;
      }

      void sess.closed.then((info) => {
        if (this.activeSession === sess) {
          this.activeSession = undefined;
          this.activeEndpoint = undefined;
        }
        if (this.stopped) return;
        const go = sess.goAwayReceived;
        if (go && (go.status === Status.schema_mismatch || go.status === Status.failed_precondition)) {
          this.consecutiveOptFailures++;
        }
        this.setConnState({
          status: 'disconnected',
          error: new SparrowError(info.code, info.reason, undefined, { remote: info.remote }),
        });
        this.scheduleReconnect(go?.retryAfterMs ?? undefined);
      });
    } catch (err) {
      if (err instanceof SparrowError && err.notDispatched && err.status === Status.schema_mismatch) {
        this.consecutiveOptFailures++;
      }
      if (this.stopped) return;
      this.setConnState({
        status: this.snapshots.current ? 'offline' : 'disconnected',
        error: err as Error,
      });
      if (initial && !this.opts.reconnect) {
        throw err;
      }
      this.scheduleReconnect();
    }
  }

  private async refreshSessionAuth(sess: Session, endpoint: string): Promise<void> {
    if (this.refreshInFlight) return;
    this.refreshInFlight = true;
    try {
      const ticket = await this.web.refresh(endpoint);
      if (sess.isOpen && !sess.isDraining) {
        sess.refreshAuth({ scheme: 'bearer', credentials: ticket });
      }
    } catch (err) {
      this.opts.onModuleError?.({
        id: 'sparrow.web',
        version: '1.0.0',
        reason: 'auth_refresh_failed',
        error: err,
      });
    } finally {
      this.refreshInFlight = false;
    }
  }

  private scheduleReconnect(retryAfterMs?: number): void {
    if (this.stopped) return;
    const rc = this.opts.reconnect;
    if (rc === false) return;
    const min = typeof rc === 'object' && rc.minDelayMs !== undefined ? rc.minDelayMs : 500;
    const max = typeof rc === 'object' && rc.maxDelayMs !== undefined ? rc.maxDelayMs : 30_000;
    const base = retryAfterMs !== undefined ? retryAfterMs : min + Math.floor(Math.random() * Math.min(min, max - min + 1));
    const delay = Math.min(max, Math.max(0, base));
    if (this.reconnectTimer !== undefined) this.clock.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = this.clock.setTimeout(() => {
      this.reconnectTimer = undefined;
      void this.connectOnce(false);
    }, delay);
  }

  // -------------------------------------------------------------------------
  // Schema reconciliation & module lifecycle (9.4, 9.6)
  // -------------------------------------------------------------------------

  private enqueueSchema(sc: Schema, props: Record<string, unknown>, initialBoot: boolean): Promise<void> {
    this.reconcileChain = this.reconcileChain.then(
      () => this.reconcileSchema(sc, props, initialBoot),
      () => this.reconcileSchema(sc, props, initialBoot),
    );
    return this.reconcileChain;
  }

  private async reconcileSchema(sc: Schema, props: Record<string, unknown>, initialBoot: boolean): Promise<void> {
    if (this.stopped) return;
    const top = extractTopLevelWeb(sc);
    const { accepted, rejected } = await this.loader.accept(sc);
    this.reportRejections(rejected);

    // Ensure files for accepted modules (eager + assets, and keep existing snapshot files).
    const files = new Map<string, Uint8Array>(this.currentFiles);
    if (this.snapshots.current) {
      for (const [k, v] of this.snapshots.current.files) {
        if (!files.has(k)) files.set(k, v);
      }
    }

    const validModules: ModuleEntry[] = [];
    for (const entry of accepted) {
      try {
        await this.ensureFiles([entry], files);
        validModules.push(entry);
      } catch (err) {
        const rej: ModuleRejection = {
          facet: entry.facet,
          id: entry.id,
          version: entry.version,
          reason: `fetch_failed: ${(err as Error).message}`,
        };
        this.reportRejections([rej]);
        this.opts.onModuleError?.({ id: entry.id, version: entry.version, reason: rej.reason, error: err });
      }
    }

    const snap = createSnapshot(sc, props, validModules, files, Math.floor(this.nowMs() / 1000));
    this.snapshots.install(snap);
    await this.persistSnapshots();

    const update: PendingSnapshotUpdate = {
      apply: top.apply,
      schema: sc,
      props,
      accepted: validModules,
      rejected,
      files,
      snapshot: snap,
    };

    if (initialBoot || top.apply === 'hot' || this.active.size === 0) {
      this.pendingUpdate = undefined;
      await this.commitReconcile(update);
    } else {
      this.pendingUpdate = update;
      this.opts.onUpdateAvailable?.({
        apply: top.apply,
        schema: sc,
        hash: snap.schemaHash,
        accepted: validModules,
        rejected,
      });
    }
  }

  private async commitReconcile(u: PendingSnapshotUpdate): Promise<void> {
    const top = extractTopLevelWeb(u.schema);
    await this.applyLoadedSet(u.schema, u.props, top.config, u.accepted, u.files, true);
    this.snapshots.booted();
    await this.persistSnapshots();
  }

  private async ensureFiles(entries: readonly ModuleEntry[], files: Map<string, Uint8Array>): Promise<void> {
    for (const f of moduleFiles(entries)) {
      const hex = cbor.toHex(f.hash);
      if (files.has(hex)) continue;
      const ref = f.entry.hash === f.hash ? f.entry.url : `${MODS_PATH}${encodeHash(f.hash)}${f.ext ? '.' + f.ext : ''}`;
      const res = await this.web.fetchFile(ref, f.hash);
      files.set(hex, res.bytes);
    }
  }

  private async applyLoadedSet(
    sc: Schema,
    props: Record<string, unknown>,
    config: Record<string, unknown>,
    accepted: readonly ModuleEntry[],
    files: Map<string, Uint8Array>,
    notifySchema: boolean,
    strict = false,
  ): Promise<void> {
    this.currentSchema = sc;
    this.currentProps = { ...props };
    this.currentConfig = { ...config };
    this.currentFiles = new Map(files);
    this.currentAccepted = new Map(accepted.map((e) => [e.id, e]));

    const eagerEntries = accepted.filter((e) => e.load === 'eager');
    const { ordered, bad } = topoOrder(eagerEntries);
    if (bad.length > 0) {
      this.reportRejections(
        bad.map((b) => ({ facet: b.entry.facet, id: b.entry.id, version: b.entry.version, reason: b.reason })),
      );
    }

    // Also keep any already-loaded lazy modules if still accepted & unchanged.
    const desired = new Map<string, ModuleEntry>(ordered.map((e) => [e.id, e]));
    for (const id of this.loadOrder) {
      const cur = this.active.get(id);
      if (cur && cur.entry.load === 'lazy') {
        const next = this.currentAccepted.get(id);
        if (next && next.deps.every((d) => desired.has(d) || this.currentAccepted.has(d))) {
          desired.set(id, next);
        }
      }
    }

    const { ordered: finalOrder } = topoOrder([...desired.values()]);

    // Determine which modules must be disposed: removed, changed hash/version, or whose dependency changed.
    const needsReload = new Set<string>();
    for (const e of finalOrder) {
      const cur = this.active.get(e.id);
      if (!cur || !sameBytes(cur.entry.hash, e.hash) || cur.entry.version !== e.version || cur.entry.facet !== e.facet) {
        needsReload.add(e.id);
      } else if (e.deps.some((d) => needsReload.has(d))) {
        needsReload.add(e.id);
      }
    }

    // Dispose removed or invalidated modules in reverse load order.
    for (let i = this.loadOrder.length - 1; i >= 0; i--) {
      const id = this.loadOrder[i];
      if (!desired.has(id) || needsReload.has(id)) {
        await this.disposeOneModule(id);
      }
    }

    if (notifySchema) {
      for (const cb of [...this.schemaListeners]) cb(sc);
      this.opts.onSchemaChange?.(sc);
    }

    // Load new/reloaded modules in topological order.
    for (const e of finalOrder) {
      if (!this.active.has(e.id)) {
        try {
          await this.loadOneModule(e, files);
        } catch (err) {
          this.reportRejections([{ facet: e.facet, id: e.id, version: e.version, reason: `load_failed: ${(err as Error).message}` }]);
          this.opts.onModuleError?.({ id: e.id, version: e.version, reason: 'load_failed', error: err });
          if (strict) throw err;
        }
      }
    }

    this.opts.onModulesChanged?.(this.loadedModules());
  }

  private async loadOneModule(entry: ModuleEntry, files: ReadonlyMap<string, Uint8Array>): Promise<void> {
    const bytes = files.get(cbor.toHex(entry.hash));
    if (!bytes) throw new Error(`missing bytes for ${entry.id}`);

    const disposers: Array<() => void | Promise<void>> = [];
    const blobUrls: string[] = [];

    const assets: ModuleAssets = {
      get: async (assetPath) => {
        const ref = entry.assets.find((a) => a.path === assetPath);
        if (!ref) throw new Error(`module ${entry.id}: unknown asset ${JSON.stringify(assetPath)}`);
        const hex = cbor.toHex(ref.hash);
        const existing = this.currentFiles.get(hex) ?? files.get(hex);
        if (existing) return existing;
        const clean = assetPath.split('?')[0].split('#')[0];
        const dot = clean.lastIndexOf('.');
        const ext = dot > 0 ? clean.slice(dot + 1) : 'bin';
        const fetched = await this.web.fetchFile(`${MODS_PATH}${encodeHash(ref.hash)}.${ext}`, ref.hash);
        this.currentFiles.set(hex, fetched.bytes);
        return fetched.bytes;
      },
      url: async (assetPath) => {
        const data = await assets.get(assetPath);
        const URLCtor = (globalThis as { URL?: { createObjectURL?: (b: unknown) => string; revokeObjectURL?: (u: string) => void } }).URL;
        const BlobCtor = (globalThis as { Blob?: new (parts: unknown[], opts?: { type?: string }) => unknown }).Blob;
        if (!URLCtor?.createObjectURL || !BlobCtor) {
          throw new Error('hull: URL.createObjectURL is unavailable in this environment');
        }
        const u = URLCtor.createObjectURL(new BlobCtor([data], { type: mimeForPath(assetPath) }));
        blobUrls.push(u);
        return u;
      },
    };

    const host = this.makeHost(entry, assets, disposers);
    const loaded = await this.importer(entry, bytes, assets);
    const factory = typeof loaded === 'function' ? loaded : loaded.default;
    if (typeof factory !== 'function') {
      throw new Error(`module ${entry.id} does not export a default register(host) function`);
    }

    const inst = await factory(host);
    if (typeof inst === 'function') {
      disposers.push(inst);
    } else if (inst && typeof inst === 'object' && typeof inst.dispose === 'function') {
      disposers.push(() => inst.dispose!());
    }

    disposers.push(() => {
      const URLCtor = (globalThis as { URL?: { revokeObjectURL?: (u: string) => void } }).URL;
      for (const u of blobUrls) URLCtor?.revokeObjectURL?.(u);
    });

    this.active.set(entry.id, { entry, disposers, deps: [...entry.deps] });
    this.loadOrder.push(entry.id);
  }

  private async disposeOneModule(id: string): Promise<void> {
    const m = this.active.get(id);
    if (!m) return;
    this.active.delete(id);
    const idx = this.loadOrder.indexOf(id);
    if (idx >= 0) this.loadOrder.splice(idx, 1);

    for (let i = m.disposers.length - 1; i >= 0; i--) {
      try {
        await m.disposers[i]();
      } catch (err) {
        this.opts.onModuleError?.({ id: m.entry.id, version: m.entry.version, reason: 'dispose_failed', error: err });
      }
    }
  }

  private async disposeAllModules(): Promise<void> {
    for (let i = this.loadOrder.length - 1; i >= 0; i--) {
      await this.disposeOneModule(this.loadOrder[i]);
    }
  }

  private makeHost(entry: ModuleEntry, assets: ModuleAssets, disposers: Array<() => void | Promise<void>>): ModuleHost {
    const hull = this;
    return {
      module: Object.freeze({ id: entry.id, version: entry.version, facet: entry.facet, entry }),
      get session() {
        return hull.activeSession;
      },
      get schema() {
        return hull.currentSchema;
      },
      get props() {
        return hull.currentProps;
      },
      get config() {
        return hull.currentConfig;
      },
      shared: hull.shared,
      facets() {
        return hull.currentSchema.facets;
      },
      facet(nameOrId) {
        return typeof nameOrId === 'number'
          ? hull.currentSchema.facets.find((f) => f.id === nameOrId)
          : hull.currentSchema.facets.find((f) => f.name === nameOrId);
      },
      implementationsOf(interfaceHash) {
        return hull.currentSchema.facets.filter(
          (f) => f.implements !== null && sameBytes(f.implements, interfaceHash),
        );
      },
      defaultFor(interfaceHash) {
        const defaults = hull.currentSchema.annotations['sparrow.defaults'];
        let facetId: number | undefined;
        if (defaults instanceof Map) {
          for (const [k, v] of defaults) {
            if (k instanceof Uint8Array && sameBytes(k, interfaceHash) && typeof v === 'number') {
              facetId = v;
              break;
            }
          }
        }
        return facetId !== undefined ? hull.currentSchema.facets.find((f) => f.id === facetId) : undefined;
      },
      provide<T>(key: string, value: T) {
        const stop = hull.capabilities.provide(key, value);
        disposers.push(stop);
        return stop;
      },
      get<T>(key: string) {
        return hull.capabilities.get<T>(key);
      },
      onCapability<T>(key: string, cb: (value: T | undefined) => void) {
        const stop = hull.capabilities.on(key, cb);
        disposers.push(stop);
        return stop;
      },
      assets,
      loadLazy: (id) => hull.loadLazy(id),
      onSchemaChange(cb) {
        const stop = hull.onSchemaChange(cb);
        disposers.push(stop);
        return stop;
      },
      onConnectionChange(cb) {
        const stop = hull.onConnectionChange(cb);
        disposers.push(stop);
        return stop;
      },
      onDispose(cb) {
        disposers.push(cb);
        return () => {
          const i = disposers.indexOf(cb);
          if (i >= 0) disposers.splice(i, 1);
        };
      },
    };
  }

  private reportRejections(rejs: readonly ModuleRejection[]): void {
    const s = this.activeSession;
    if (!s || !s.isOpen || s.isDraining || !s.peerFacet('sparrow.web')) return;
    for (const r of rejs) {
      try {
        s.notify('sparrow.web', 'moduleRejected', [r.id, r.version, r.reason]);
      } catch {
        // best-effort notification
      }
    }
  }

  private setConnState(st: ConnectionState): void {
    this.connState = st;
    for (const cb of [...this.connListeners]) cb(st);
    this.opts.onConnectionChange?.(st);
  }
}

function belowServerDefaults(p: Params): boolean {
  if (p.maxMessageSize !== undefined && p.maxMessageSize < 1 << 20) return true;
  if (p.maxInlineBytes !== undefined && p.maxInlineBytes < 64 << 10) return true;
  if (p.maxConcurrentCalls !== undefined && p.maxConcurrentCalls < 100) return true;
  if (p.maxStreams !== undefined && p.maxStreams < 16) return true;
  if (p.sharedCredit !== undefined && p.sharedCredit < 64 << 10) return true;
  if (p.leaseCredit !== undefined && p.leaseCredit < 1 << 20) return true;
  if (p.idleTimeoutMs !== undefined && p.idleTimeoutMs < 30_000) return true;
  return false;
}

export function createHull(opts: HullOptions): Hull {
  return new Hull(opts);
}
