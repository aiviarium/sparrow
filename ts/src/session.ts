// One Sparrow session in either role (spec sections 5, 7 and 8) over a
// transport Conn that has only the shared lane (pipe, WebSocket, in-memory).
//
// The client side: Session.connect(conn, options) sends Hello (with an
// optional client schema), loads the server's schema from Welcome and sends
// Ready. The server side: Session.accept(conn, options) waits for Hello,
// checks it, sends Welcome and resolves once Ready has arrived. Both sides
// then serve calls to their own facets (options.handlers) and call the peer's
// (call, stream, notify, open).

import { Raw, bytesEqual, decode, encode } from './cbor.js';
import {
  SchemaError,
  SchemaState,
  WEB_FACET_ID,
  canonicalSchema,
  decodeDelta,
  decodeSchema,
  diff,
  encodeDelta,
  encodeSchema,
  findMethod,
  findMethodByName,
  isByteStream,
  isStream,
  schemaDepth,
  T,
  type Facet,
  type Method,
  type Schema,
  type TypeRef,
  type Delta,
} from './schema.js';
import { MAX_CORE_STATUS, Status, describeStatus, isCoreStatus, statusByName, statusName, truncateReason, type StatusName } from './status.js';
import { ConnClosedError, type CloseInfo, type Conn } from './transport.js';
import { Codec, type DynamicValue } from './value.js';
import {
  CreditWindow,
  DecodeError,
  NOTIFICATION_ID,
  NULL_ITEM,
  TooLargeError,
  UnknownKindError,
  belowDefaults,
  callerOf,
  checkParams,
  countedBytes,
  decodeMessage,
  defaultLimits,
  encodeMessage,
  initialCredit,
  limitsOf,
  metaCredit,
  metaDeadline,
  metaPrincipal,
  MetaKeys,
  type Auth,
  type CallMessage,
  type GoAway,
  type Hello,
  type Limits,
  type Message,
  type MetaKey,
  type Metadata,
  type Params,
  type Request,
  type Role,
  type SchemaOffer,
  type TextMap,
  type Welcome,
} from './wire.js';

export const PROTOCOL_VERSION = 1;

/** Defaults of the timers (5.2, 5.6, 6.6, 7.5) and limits of the session. */
export const SessionDefaults = {
  helloTimeoutMs: 10_000,
  schemaAckTimeoutMs: 10_000,
  cancelGiveUpMs: 5_000,
  cancelBrokenMs: 30_000,
  gracePeriodMs: 30_000,
  lingerMs: 1_000,
  /** Shared-lane data the server buffers after Hello until the credential is verified (5.2). */
  preAuthLimit: 64 << 10,
  maxClientSchemaSize: 64 << 10,
  maxClientSchemaDepth: 32,
  /** Byte tokens one sender may open in a call (7.8). */
  maxTokens: 64,
  /** Largest Bytes chunk on the shared lane (7.8). */
  sharedChunk: 16 << 10,
  /** Notifications handled at once; more are dropped (7.3, best-effort). */
  maxNotifications: 64,
} as const;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * A call or session failure with a status. Handlers throw it to answer with
 * Error(status, message, details); callers receive it when the callee
 * answered with Error, when the call failed locally or when the session ended.
 */
export class SparrowError extends Error {
  /** The status sigil: a core code (section 8) or an error sigil of the method's facet; -1 until resolved. */
  status: number;
  /** The status name: a core name such as "not_found", or the facet's error sigil name. */
  code: string;
  /**
   * Error.details. Thrown by a handler: { type, value } is sent as a dynamic
   * value of the method's facet (type is a TypeId or a type name); any other
   * value in the generic CBOR representation as it is. Received: a dynamic
   * value decoded as { type, typeName, value } when it decodes with the
   * facet, otherwise the generic CBOR value.
   */
  details?: unknown;
  /** The encoded details as received. */
  detailsRaw?: Uint8Array;
  /** The status came from the peer (Error, Cancel or GoAway). */
  remote: boolean;
  /** The callee certainly did not run the call (5.2, 5.3); it may be retried as is. */
  notDispatched: boolean;

  constructor(status: number | StatusName | string, message?: string, details?: unknown, opts: { remote?: boolean; notDispatched?: boolean } = {}) {
    const num = typeof status === 'number' ? status : (statusByName(status) ?? -1);
    const name = typeof status === 'string' ? status : describeStatus(status);
    super(message ? `sparrow: ${name}: ${message}` : `sparrow: ${name}`);
    this.name = 'SparrowError';
    this.status = num;
    this.code = name;
    this.details = details;
    this.remote = opts.remote ?? false;
    this.notDispatched = opts.notDispatched ?? false;
    this.rawMessage = message ?? '';
  }

  /** The message without the status prefix. */
  rawMessage: string;
}

function asSparrowError(e: unknown): SparrowError {
  if (e instanceof SparrowError) return e;
  if (e instanceof SchemaError) return new SparrowError(Status.invalid_argument, e.message);
  return new SparrowError(Status.unknown, e instanceof Error ? e.message : String(e));
}

/** The status of an error: its SparrowError status, or unknown. */
export function statusOf(e: unknown): number {
  return e instanceof SparrowError ? e.status : Status.unknown;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/** What a handler gets besides its input. */
export interface CallContext {
  readonly session: Session;
  readonly callId: number;
  readonly facet: Facet;
  readonly method: Method;
  /** Aborted on Cancel, when the deadline passes, when the call ends or when the session ends. */
  readonly signal: AbortSignal;
  /** Request metadata (keys are sigils or text, values in the generic CBOR representation). */
  readonly metadata: Metadata;
  /** When the caller stops waiting (epoch ms), from the deadline key. */
  readonly deadline?: number;
  /** The session's authenticated principal (server side), else the principal metadata key, else "". */
  readonly principal: string;
  /** True for a notification: nothing is sent back. */
  readonly notification: boolean;
  /** Sends Progress (counted against credit). */
  progress(done: number, total?: number | null, note?: string | null): Promise<void>;
  /** Sends Headers, before the first Item or Bytes. */
  sendHeaders(md?: MetadataInit): void;
  /** Sends one output stream item (server or bidi stream), waiting for credit. */
  send(item: unknown): Promise<void>;
  /** Sets the trailers of the final End. */
  setTrailers(md: MetadataInit): void;
  /** Sends output byte data for a token (0 for a whole-value [4] output). */
  sendBytes(token: number, data: Uint8Array, fin?: boolean): Promise<void>;
  /** Collects input byte data for a token (0 for a whole-value [4] input) until its final chunk. */
  bytes(token: number): Promise<Uint8Array>;
}

/**
 * A handler. Its input is the decoded Request input, or, for a method whose
 * input is a stream ([3, T]), an AsyncIterable of the decoded items. Its
 * result finishes the call: for a stream output, return an (async) iterable
 * of items, or send them with ctx.send and return nothing; otherwise return
 * the output value. Throw a SparrowError to answer with Error.
 */
export type Handler = (input: any, ctx: CallContext) => unknown;

/** Handlers keyed by facet name (or ID), then method name ("method" or "Service.method", or ID). */
export type HandlerMap = Record<string, Record<string, Handler>>;

/** Routes calls to handlers by facet and method, by name or ID. */
export class Router {
  private entries = new Map<string, Handler>();
  private fallbackHandler?: Handler;

  /** Registers a handler; facet and method are names or IDs. */
  handle(facet: string | number, method: string | number, h: Handler): this {
    this.entries.set(`${facet}\u0000${method}`, h);
    return this;
  }

  /** Registers every handler of a map. */
  add(map: HandlerMap): this {
    for (const [f, ms] of Object.entries(map)) for (const [m, h] of Object.entries(ms)) this.handle(f, m, h);
    return this;
  }

  /** The handler for calls nothing else matches. */
  fallback(h: Handler): this {
    this.fallbackHandler = h;
    return this;
  }

  /** Finds the handler for a method of a facet. */
  resolve(facet: Facet, serviceName: string | undefined, method: Method): Handler | undefined {
    for (const f of [facet.name, String(facet.id)]) {
      for (const m of [method.name, serviceName ? `${serviceName}.${method.name}` : undefined, String(method.id)]) {
        if (m === undefined) continue;
        const h = this.entries.get(`${f}\u0000${m}`);
        if (h) return h;
      }
    }
    return this.fallbackHandler;
  }
}

/** Metadata as given by applications: a Map, or an object of text keys. */
export type MetadataInit = Metadata | Record<string, unknown>;

function toMetadata(md: MetadataInit | undefined | null): Metadata {
  if (!md) return new Map();
  if (md instanceof Map) return new Map(md);
  return new Map(Object.entries(md).filter(([, v]) => v !== undefined));
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface SessionOptions {
  /** This peer's schema: the server's goes in Welcome, the client's (optional) inline in Hello. */
  schema?: Schema;
  /** Serves calls to this peer's facets. */
  handlers?: Router | HandlerMap;
  /** The limits this peer imposes on the other (5.4). */
  params?: Params;
  caps?: TextMap;
  /** Diagnostics. */
  log?: (msg: string) => void;

  // --- client
  /** Protocol versions offered, preferred first; default [1]. */
  versions?: number[];
  /** The credential sent in Hello, e.g. { scheme: "bearer", credentials: "..." }. */
  auth?: Auth;
  /** The cached server schema, offered as known_schema. */
  knownSchema?: Schema;
  /** The cached Welcome.params of that server; an optimistic start is refused if they are below the defaults. */
  knownParams?: Params;
  /** Send Hello, Ready and the first calls in one flight (5.3); needs knownSchema. */
  optimistic?: boolean;
  /** Loads a schema offered out of band ([3, hash, location]). */
  fetchSchema?: (location: string, hash: Uint8Array) => Promise<Schema>;
  /** Called with the server's schema and params after Welcome, to update a cache. */
  onServerSchema?: (hash: Uint8Array, schema: Schema, params: Params) => void;
  /** Called for every AuthStatus the server sends. */
  onAuthStatus?: (s: Session, status: number, expiresAt: number | null) => void;

  // --- server
  /** Verifies Hello.auth and returns the principal; a throw closes with GoAway(unauthenticated) or its SparrowError status. */
  authenticate?: (hello: Hello) => string | Promise<string>;
  /** May reject the client schema (a throw closes with GoAway(invalid_argument) or its status). */
  acceptClientSchema?: (principal: string, schema: Schema) => void | Promise<void>;
  /** Returns an older schema of this server by hash, so a Delta offer can be sent. */
  schemaByHash?: (hash: Uint8Array) => Schema | undefined;
  /** Returns a location to offer the schema out of band instead of inline. */
  offerLocation?: (hash: Uint8Array) => string | undefined;
  /** Welcome.props. */
  props?: TextMap;
  /** Limit on Hello.client_schema; default 64 KiB, negative for none. */
  maxClientSchemaSize?: number;
  /** Handles AuthRefresh: return the expiry (epoch seconds) or null; a throw closes with GoAway(unauthenticated). */
  onAuthRefresh?: (s: Session, auth: Auth) => number | null | Promise<number | null>;

  // --- both
  /** Called after a peer SchemaUpdate is applied and before SchemaAck is sent. */
  onPeerSchemaUpdate?: (s: Session, u: { epoch: number; hash: Uint8Array; delta: Delta; schema: Schema }) => void | Promise<void>;
  /** Called when the peer sends GoAway. */
  onGoAway?: (s: Session, g: GoAway) => void;
  helloTimeoutMs?: number;
  schemaAckTimeoutMs?: number;
  cancelGiveUpMs?: number;
  cancelBrokenMs?: number;
  gracePeriodMs?: number;
  /** How long open calls may still finish after the peer ended the connection; default 1 s. */
  lingerMs?: number;
}

/** Options of one call. */
export interface CallOptions {
  /** Cancels the call (Cancel(cancelled)). */
  signal?: AbortSignal;
  /** Sends the deadline key and cancels with deadline_exceeded when it passes. */
  timeoutMs?: number;
  /** Request metadata: text keys for applications; sigil keys 32-47 are core keys. */
  metadata?: MetadataInit;
  /** The credit key: initial credit for the callee's half, replacing sharedCredit. */
  credit?: number;
  /** Called for every Progress. */
  onProgress?: (p: { done: number; total: number | null; note: string | null }) => void;
  /** Called with the Headers metadata. */
  onHeaders?: (md: Metadata) => void;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

class Waiter {
  private list: (() => void)[] = [];
  wait(): Promise<void> {
    return new Promise((r) => this.list.push(r));
  }
  wake(): void {
    const l = this.list;
    this.list = [];
    for (const f of l) f();
  }
}

type Timer = ReturnType<typeof setTimeout>;

const noop = () => {};

function isCallerKind(k: number): boolean {
  return k === 18 || k === 19 || k === 23 || k === 24 || k === 25;
}

function isCalleeKind(k: number): boolean {
  return k === 17 || k === 18 || k === 19 || k === 20 || k === 21 || k === 22 || k === 24 || k === 25;
}

interface TokenBuf {
  chunks: Uint8Array[];
  fin: boolean;
  /** Bytes buffered and not yet handed to the application. */
  size: number;
}

/** @internal One call, from either side. */
export class CallState {
  id = 0;
  facet?: Facet;
  service?: string;
  method?: Method;
  codec?: Codec;
  inputEnds: boolean;
  outputEnds: boolean;
  callerDone = false;
  calleeDone = false;
  ended = false;
  counted = false;
  sendWin: CreditWindow;
  recvWin: CreditWindow;
  recvInit: number;
  unacked = 0;
  items: { raw: Uint8Array; n: number }[] = [];
  tokens = new Map<number, TokenBuf>();
  sentTokens = new Set<number>();
  recvTokens = new Set<number>();
  headers?: Metadata;
  trailers?: Metadata;
  response?: Uint8Array;
  peerError?: SparrowError;
  localErr?: SparrowError;
  inputEnded = false;
  cancelSent = false;
  cancelRecv = false;
  cancelCode: number = Status.cancelled;
  waiter = new Waiter();
  abort?: AbortController;
  timers: Timer[] = [];
  metadata: Metadata = new Map();
  myTrailers?: Metadata;
  headersSent = false;
  dataSent = false;
  onProgress?: CallOptions['onProgress'];
  onHeaders?: CallOptions['onHeaders'];

  constructor(
    readonly caller: boolean,
    readonly facetId: number,
    readonly methodId: number,
    flags: number,
    sendInit: number,
    recvInit: number,
  ) {
    this.inputEnds = (flags & 0x8) !== 0;
    this.outputEnds = (flags & 0x10) !== 0;
    this.sendWin = new CreditWindow(sendInit);
    this.recvWin = new CreditWindow(recvInit);
    this.recvInit = recvInit;
  }

  peerHalfDone(): boolean {
    return this.caller ? this.calleeDone : this.callerDone;
  }

  wake(): void {
    this.waiter.wake();
  }
}

type HState = 'awaitHello' | 'handshaking' | 'awaitWelcome' | 'awaitReady' | 'open';

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/** One Sparrow session. */
export class Session {
  readonly role: Role;
  private readonly conn: Conn;
  private readonly opts: SessionOptions;
  private readonly router: Router;
  private hs: HState;
  private nextId: number;
  private calls = new Map<number, CallState>();
  private inOpen = 0;
  private outOpen = 0;
  private slotWaiter = new Waiter();
  private local?: SchemaState;
  private peer?: SchemaState;
  private publishedFlags = new Map<string, number>();
  private codecs = new WeakMap<Facet, Codec>();
  private localLimits: Limits;
  private peerLimits: Limits;
  private lastRecv = Date.now();
  private pingSent = false;
  private pingNonce = 0;
  private idleTimer?: Timer;
  private sessionTimers = new Set<Timer>();
  private preAuth: Uint8Array[] = [];
  private preAuthLen = 0;
  private notifying = 0;
  private optimistic = false;
  private optReject = false;
  private welcomeDone = false;
  private readyDone = false;
  private sentPreWelcome = 0;
  private welcomeWaiter = new Waiter();
  private ackWaiter = new Waiter();
  private localAcked = 0;
  private pendingFacets = new Map<number, number>();
  private draining = false;
  private goAwaySent?: GoAway;
  private goAwayRecv?: GoAway;
  private isClosed = false;
  private closeInfo?: CloseInfo & { error: SparrowError };
  private closedResolve!: (i: CloseInfo) => void;
  private handshake: { resolve: () => void; reject: (e: SparrowError) => void } | null = null;
  private helloMsg?: Hello;
  private welcomeMsg?: Welcome;
  private principalName = '';
  private sessionIdBytes?: Uint8Array;
  private peerUpdates: Promise<void> = Promise.resolve();

  /** Resolves when the session has ended, with how it ended. */
  readonly closed: Promise<CloseInfo>;

  private constructor(conn: Conn, opts: SessionOptions, role: Role) {
    this.conn = conn;
    this.opts = opts;
    this.role = role;
    this.hs = role === 'client' ? 'awaitWelcome' : 'awaitHello';
    this.nextId = role === 'client' ? 2 : 1;
    this.router = opts.handlers instanceof Router ? opts.handlers : new Router().add(opts.handlers ?? {});
    this.localLimits = limitsOf(opts.params ?? {}, role);
    this.peerLimits = defaultLimits(role === 'client' ? 'server' : 'client');
    this.closed = new Promise((r) => (this.closedResolve = r));
  }

  // -------------------------------------------------------------------------
  // Handshake
  // -------------------------------------------------------------------------

  /**
   * Runs the client side of the handshake (5.2): sends Hello and, unless the
   * start is optimistic, waits for Welcome and sends Ready.
   */
  static connect(conn: Conn, opts: SessionOptions = {}): Promise<Session> {
    const s = new Session(conn, opts, 'client');
    return s.clientStart();
  }

  /** Runs the server side of the handshake: waits for Hello, sends Welcome, resolves once Ready arrived. */
  static accept(conn: Conn, opts: SessionOptions = {}): Promise<Session> {
    const s = new Session(conn, opts, 'server');
    return s.serverStart();
  }

  private clientStart(): Promise<Session> {
    const o = this.opts;
    if (o.schema) {
      try {
        this.setLocal(SchemaState.create(canonicalSchema(o.schema)));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    const hello: Hello = {
      kind: 0,
      versions: o.versions?.length ? [...o.versions] : [PROTOCOL_VERSION],
      caps: o.caps ?? {},
      auth: o.auth ?? null,
      knownSchema: null,
      clientSchema: null,
      params: o.params ?? {},
      optimistic: false,
    };
    let knownHash: Uint8Array | null = null;
    if (o.knownSchema) {
      try {
        knownHash = SchemaState.create(canonicalSchema(o.knownSchema)).hash;
      } catch (e) {
        return Promise.reject(e);
      }
      hello.knownSchema = knownHash;
    }
    if (this.local) hello.clientSchema = { hash: this.local.hash, schema: encodeSchema(this.local.schema) };
    if (o.optimistic) {
      if (!o.knownSchema || !knownHash) return Promise.reject(new Error('session: an optimistic start needs knownSchema'));
      if (o.knownParams && belowDefaults(limitsOf(o.knownParams, 'server'), 'server')) {
        return Promise.reject(new Error('session: the cached server limits are below the defaults; start normally'));
      }
      hello.optimistic = true;
      hello.versions = hello.versions.slice(0, 1);
      this.peer = SchemaState.create(canonicalSchema(o.knownSchema));
      this.optimistic = true;
    }
    this.helloMsg = hello;
    const p = new Promise<Session>((resolve, reject) => {
      this.handshake = { resolve: () => resolve(this), reject };
    });
    this.startConn();
    try {
      this.write(encodeMessage(hello));
      if (this.optimistic) {
        this.write(encodeMessage({ kind: 2, schemaHash: knownHash! }));
        this.readyDone = true;
        this.finishHandshake();
      }
    } catch (e) {
      this.terminate(Status.unavailable, 'cannot send Hello', false);
    }
    return p;
  }

  private serverStart(): Promise<Session> {
    const sc = this.opts.schema ?? { format: 2, name: '', version: '', facets: [], annotations: {} };
    try {
      this.setLocal(SchemaState.create(canonicalSchema(sc)));
    } catch (e) {
      return Promise.reject(e);
    }
    const p = new Promise<Session>((resolve, reject) => {
      this.handshake = { resolve: () => resolve(this), reject };
    });
    this.helloTimer = this.timer(this.opts.helloTimeoutMs ?? SessionDefaults.helloTimeoutMs, () => {
      if (this.hs === 'awaitHello') this.terminate(Status.deadline_exceeded, 'no Hello within the timeout', false);
    });
    this.startConn();
    return p;
  }

  private finishHandshake(): void {
    const h = this.handshake;
    this.handshake = null;
    this.armIdle();
    h?.resolve();
  }

  private startConn(): void {
    this.conn.setReadLimit(this.localLimits.maxMessageSize);
    this.conn.start({
      message: (b) => this.onMessage(b),
      error: (e) => {
        if (e instanceof TooLargeError) this.fail(Status.message_too_large, e.message);
        else this.fail(Status.protocol_error, e.message);
      },
      close: (info) => this.transportEnded(info),
    });
  }

  private async serverHandshake(h: Hello): Promise<void> {
    const reject = (code: number, reason: string, versions: number[] | null = null) => {
      this.sendGoAwayAndClose(code, reason, null, versions);
    };
    if (!h.versions.includes(PROTOCOL_VERSION)) return reject(Status.unsupported_version, 'no common protocol version', [PROTOCOL_VERSION]);
    if (h.optimistic && (h.versions.length !== 1 || !h.knownSchema)) {
      return reject(Status.protocol_error, 'an optimistic Hello lists exactly one version and names its cached schema');
    }
    const pe = checkParams(h.params);
    if (pe) return reject(Status.invalid_argument, pe.message);
    let principal = '';
    if (this.opts.authenticate) {
      try {
        principal = await this.opts.authenticate(h);
      } catch (e) {
        const se = e instanceof SparrowError && isCoreStatus(e.status) ? e.status : Status.unauthenticated;
        return reject(se, e instanceof Error ? e.message : String(e));
      }
      if (this.isClosed) return;
    }
    let clientState: SchemaState | undefined;
    if (h.clientSchema) {
      const max = this.opts.maxClientSchemaSize ?? SessionDefaults.maxClientSchemaSize;
      if (max > 0 && h.clientSchema.schema.length > max) return reject(Status.invalid_argument, 'client schema larger than the limit');
      try {
        const cs = decodeSchema(h.clientSchema.schema);
        if (max > 0 && schemaDepth(cs) > SessionDefaults.maxClientSchemaDepth) throw new Error('type references nested deeper than 32 levels');
        clientState = SchemaState.create(cs);
        if (!bytesEqual(clientState.hash, h.clientSchema.hash)) throw new Error('client schema hash does not match');
      } catch (e) {
        return reject(Status.invalid_argument, `invalid client schema: ${(e as Error).message}`);
      }
      if (this.opts.acceptClientSchema) {
        try {
          await this.opts.acceptClientSchema(principal, clientState.schema);
        } catch (e) {
          const se = e instanceof SparrowError && isCoreStatus(e.status) ? e.status : Status.invalid_argument;
          return reject(se, e instanceof Error ? e.message : String(e));
        }
        if (this.isClosed) return;
      }
    }
    const local = this.local!;
    const hash = local.hash;
    const offer = this.makeOffer(local, hash, h.knownSchema);
    const sid = new Uint8Array(16);
    globalThis.crypto.getRandomValues(sid);
    const w: Welcome = {
      kind: 1,
      version: PROTOCOL_VERSION,
      caps: this.opts.caps ?? {},
      sessionId: sid,
      props: this.opts.props ?? {},
      serverSchema: offer,
      params: this.opts.params ?? {},
    };
    try {
      this.write(encodeMessage(w));
    } catch {
      return;
    }
    this.principalName = principal;
    this.sessionIdBytes = sid;
    this.welcomeMsg = w;
    this.peer = clientState;
    this.peerLimits = limitsOf(h.params, 'client');
    this.welcomeDone = true;
    this.hs = 'awaitReady';
    const queued = this.preAuth;
    this.preAuth = [];
    if (h.optimistic) {
      if (!bytesEqual(h.knownSchema, hash)) {
        this.sendGoAwayAndClose(Status.schema_mismatch, 'the cached schema is out of date', 0, null);
        return;
      }
      if (belowDefaults(this.localLimits, 'server')) {
        this.sendGoAwayAndClose(Status.failed_precondition, "this server's limits are below the defaults", 0, null);
        return;
      }
    }
    for (const b of queued) this.onMessage(b);
  }

  private makeOffer(local: SchemaState, hash: Uint8Array, known: Uint8Array | null): SchemaOffer {
    if (known && bytesEqual(known, hash)) return { form: 0, hash };
    if (known && this.opts.schemaByHash) {
      const old = this.opts.schemaByHash(known);
      if (old) {
        try {
          return { form: 1, hash, from: known, delta: encodeDelta(diff(old, local.schema)) };
        } catch {
          // fall through to a full offer
        }
      }
    }
    const loc = this.opts.offerLocation?.(hash);
    if (loc !== undefined) return { form: 3, hash, location: loc };
    return { form: 2, hash, schema: encodeSchema(local.schema) };
  }

  private async clientWelcome(w: Welcome): Promise<void> {
    const fail = (code: number, reason: string) => {
      this.sendGoAwayAndClose(code, reason, null, null);
    };
    const hello = this.helloMsg!;
    if (!hello.versions.includes(w.version)) return fail(Status.unsupported_version, 'server chose a version this client did not offer');
    const pe = checkParams(w.params);
    if (pe) return fail(Status.invalid_argument, pe.message);
    let st: SchemaState;
    try {
      const sc = await this.loadOffer(w.serverSchema);
      st = SchemaState.create(sc);
    } catch (e) {
      return fail(Status.schema_mismatch, `cannot load the server schema: ${(e as Error).message}`);
    }
    if (this.isClosed) return;
    if (!bytesEqual(st.hash, w.serverSchema.hash)) return fail(Status.schema_mismatch, 'server schema hash does not match the offer');
    this.opts.onServerSchema?.(st.hash, st.schema, w.params);
    this.welcomeMsg = w;
    this.sessionIdBytes = w.sessionId;
    this.peerLimits = limitsOf(w.params, 'server');
    if (this.optimistic && (!bytesEqual(hello.knownSchema, st.hash) || belowDefaults(this.peerLimits, 'server'))) {
      // The server follows with GoAway(schema_mismatch | failed_precondition); none of the calls ran (5.3).
      this.optReject = true;
    } else {
      this.peer = st;
    }
    this.welcomeDone = true;
    this.hs = 'open';
    this.welcomeWaiter.wake();
    this.slotWaiter.wake();
    const queued = this.preAuth;
    this.preAuth = [];
    if (!this.optimistic) {
      try {
        this.write(encodeMessage({ kind: 2, schemaHash: st.hash }));
      } catch {
        return;
      }
      this.readyDone = true;
      this.finishHandshake();
    }
    for (const b of queued) this.onMessage(b);
  }

  private async loadOffer(o: SchemaOffer): Promise<Schema> {
    const known = this.opts.knownSchema;
    switch (o.form) {
      case 0:
        if (!known) throw new Error('server offered Unchanged but no schema is cached');
        return canonicalSchema(known);
      case 1: {
        if (!known) throw new Error('server offered a delta but no schema is cached');
        const base = SchemaState.create(canonicalSchema(known));
        if (!bytesEqual(base.hash, o.from)) throw new Error('delta is from a schema this client does not have');
        return base.apply(decodeDelta(o.delta)).schema;
      }
      case 2:
        return decodeSchema(o.schema, { maxBytes: 8 << 20 });
      case 3:
        if (!this.opts.fetchSchema) throw new Error('server offered the schema out of band and no fetchSchema is configured');
        return canonicalSchema(await this.opts.fetchSchema(o.location, o.hash));
    }
  }

  // -------------------------------------------------------------------------
  // Facts
  // -------------------------------------------------------------------------

  /** The authenticated principal (server side). */
  get principal(): string {
    return this.principalName;
  }

  /** Welcome.session_id. */
  get sessionId(): Uint8Array | undefined {
    return this.sessionIdBytes;
  }

  get hello(): Hello | undefined {
    return this.helloMsg;
  }

  get welcome(): Welcome | undefined {
    return this.welcomeMsg;
  }

  /** The peer's current schema (undefined if the peer published none). */
  get peerSchema(): Schema | undefined {
    return this.peer?.schema;
  }

  /** The peer's schema epoch. */
  get peerEpoch(): number {
    return this.peer?.epoch ?? 0;
  }

  /** This side's current schema. */
  get localSchema(): Schema | undefined {
    return this.local?.schema;
  }

  /** The limits this side imposes on the peer and the peer's limits on this side. */
  get limits(): { local: Limits; peer: Limits } {
    return { local: { ...this.localLimits }, peer: { ...this.peerLimits } };
  }

  /** Set once GoAway was sent or received. */
  get isDraining(): boolean {
    return this.draining;
  }

  get isOpen(): boolean {
    return !this.isClosed;
  }

  /** The GoAway the peer sent, if any. */
  get goAwayReceived(): GoAway | undefined {
    return this.goAwayRecv;
  }

  /** Open calls (both directions), for tests and diagnostics. */
  get openCalls(): number {
    return this.calls.size;
  }

  /** Finds a facet of the peer's schema by name or ID. */
  peerFacet(facet: string | number): Facet | undefined {
    const s = this.peer?.schema;
    if (!s) return undefined;
    return typeof facet === 'number' ? s.facets.find((f) => f.id === facet) : s.facets.find((f) => f.name === facet);
  }

  /** The value codec of a facet of the peer's schema (to encode or decode values by hand). */
  peerCodec(facet: string | number): Codec | undefined {
    const f = this.peerFacet(facet);
    return f ? this.codecFor(f) : undefined;
  }

  private codecFor(f: Facet): Codec {
    let c = this.codecs.get(f);
    if (!c) {
      c = new Codec(f, { validate: false });
      this.codecs.set(f, c);
    }
    return c;
  }

  private setLocal(st: SchemaState): void {
    this.local = st;
    for (const f of st.schema.facets) {
      for (const s of f.services) for (const m of s.methods) this.publishedFlags.set(`${f.id}:${m.id}`, m.flags);
    }
  }

  private log(msg: string): void {
    this.opts.log?.(`sparrow ${this.role}: ${msg}`);
  }

  // -------------------------------------------------------------------------
  // Writing
  // -------------------------------------------------------------------------

  private write(b: Uint8Array): void {
    if (this.isClosed) throw this.closedError();
    try {
      this.conn.send(b);
    } catch (e) {
      if (e instanceof ConnClosedError) {
        this.terminate(Status.unavailable, 'connection closed', true);
        throw this.closedError();
      }
      throw e;
    }
  }

  private timer(ms: number, f: () => void): Timer {
    const t = setTimeout(() => {
      this.sessionTimers.delete(t);
      f();
    }, ms);
    this.sessionTimers.add(t);
    return t;
  }

  private closedError(): SparrowError {
    const why = this.closeInfo?.reason;
    return new SparrowError(Status.unavailable, why ? `session closed: ${why}` : 'session closed', undefined, {
      notDispatched: this.role === 'client' && ((!this.welcomeDone && !this.optimistic) || this.optReject),
    });
  }

  // -------------------------------------------------------------------------
  // Reading
  // -------------------------------------------------------------------------

  private onMessage(b: Uint8Array): void {
    this.lastRecv = Date.now();
    this.pingSent = false;
    if (this.isClosed) return;
    if (this.hs === 'handshaking') {
      // The server buffers while the credential is checked (5.2); the client while it loads the offered
      // schema, except a GoAway, which ends the handshake at once.
      if (this.role === 'client') {
        let g: Message | undefined;
        try {
          g = decodeMessage(b);
        } catch {
          g = undefined;
        }
        if (g?.kind === 9) {
          this.onGoAway(g);
          return;
        }
      }
      this.preAuthLen += b.length;
      if (this.role === 'server' && this.preAuthLen > SessionDefaults.preAuthLimit) {
        this.fail(Status.resource_exhausted, 'more than 64 KiB before the credential was verified');
        return;
      }
      this.preAuth.push(b);
      return;
    }
    let m: Message;
    try {
      m = decodeMessage(b);
    } catch (e) {
      if (e instanceof UnknownKindError && e.action === 'ignore') return;
      this.fail(Status.protocol_error, (e as Error).message);
      return;
    }
    if (this.hs === 'awaitHello') {
      if (m.kind !== 0) {
        this.fail(Status.protocol_error, 'the first message must be Hello');
        return;
      }
      this.helloMsg = m;
      this.hs = 'handshaking';
      if (this.helloTimer) {
        clearTimeout(this.helloTimer);
        this.sessionTimers.delete(this.helloTimer);
      }
      void this.serverHandshake(m).catch((e) => this.fail(Status.internal, (e as Error).message));
      return;
    }
    if (this.hs === 'awaitWelcome') {
      if (m.kind === 1) {
        this.hs = 'handshaking';
        void this.clientWelcome(m).catch((e) => this.fail(Status.internal, (e as Error).message));
        return;
      }
      if (m.kind === 9) {
        this.onGoAway(m);
        return;
      }
      if (!(this.optimistic && m.kind >= 16)) {
        this.fail(Status.protocol_error, `expected Welcome, got kind ${m.kind}`);
        return;
      }
    }
    switch (m.kind) {
      case 0:
      case 1:
        this.fail(Status.protocol_error, `unexpected ${m.kind === 0 ? 'Hello' : 'Welcome'}`);
        return;
      case 2:
        this.onReady(m.schemaHash);
        return;
      case 3:
        this.onSchemaUpdate(m.epoch, m.hash, m.delta);
        return;
      case 4:
        this.onSchemaAck(m.epoch);
        return;
      case 5:
        this.onAuthRefresh(m.auth);
        return;
      case 6:
        if (this.role !== 'client') {
          this.fail(Status.protocol_error, 'AuthStatus sent by the client');
          return;
        }
        this.opts.onAuthStatus?.(this, m.status, m.expiresAt);
        return;
      case 7:
        try {
          this.write(encodeMessage({ kind: 8, nonce: m.nonce }));
        } catch {
          // closed
        }
        return;
      case 8:
        return;
      case 9:
        this.onGoAway(m);
        return;
      case 16:
        this.onRequest(m, b);
        return;
      default:
        this.deliver(m, b);
    }
  }

  private onReady(hash: Uint8Array): void {
    if (this.role !== 'server') {
      this.fail(Status.protocol_error, 'Ready sent by the server');
      return;
    }
    if (this.readyDone) {
      this.fail(Status.protocol_error, 'a second Ready');
      return;
    }
    if (!bytesEqual(hash, this.local!.hash)) {
      this.sendGoAwayAndClose(Status.schema_mismatch, 'Ready names a different schema', null, null);
      return;
    }
    this.readyDone = true;
    this.hs = 'open';
    this.finishHandshake();
  }

  private transportEnded(info: CloseInfo): void {
    if (this.isClosed) return;
    let code: number = Status.unavailable;
    let reason = info.reason || 'connection closed';
    let remote = true;
    if (this.goAwayRecv) {
      code = this.goAwayRecv.status;
      reason = this.goAwayRecv.reason;
    } else if (this.goAwaySent) {
      code = this.goAwaySent.status;
      reason = this.goAwaySent.reason;
      remote = false;
    } else if (info.code !== Status.ok) {
      code = info.code;
    }
    if (this.calls.size === 0 || (this.role === 'client' && !this.welcomeDone)) {
      this.terminate(code, reason, remote);
      return;
    }
    // Calls still open get a moment to finish (5.6).
    this.draining = true;
    this.timer(this.opts.lingerMs ?? SessionDefaults.lingerMs, () => this.terminate(code, reason, remote));
    this.lingerCode = { code, reason, remote };
  }

  private lingerCode?: { code: number; reason: string; remote: boolean };
  private helloTimer?: Timer;

  // -------------------------------------------------------------------------
  // Control messages
  // -------------------------------------------------------------------------

  private armIdle(): void {
    const idle = Math.min(this.localLimits.idleTimeoutMs, this.peerLimits.idleTimeoutMs);
    if (!(idle > 0) || this.isClosed) return;
    const tick = Math.max(1, Math.floor(idle / 4));
    this.idleTimer = setTimeout(() => {
      this.idleTimer = undefined;
      if (this.isClosed) return;
      const since = Date.now() - this.lastRecv;
      const cur = Math.min(this.localLimits.idleTimeoutMs, this.peerLimits.idleTimeoutMs);
      if (since >= cur) {
        this.fail(Status.unavailable, 'idle timeout');
        return;
      }
      if (since >= cur / 2 && !this.pingSent) {
        this.pingSent = true;
        this.ping();
      }
      this.armIdle();
    }, tick);
    // The idle check alone never keeps a Node process alive.
    (this.idleTimer as { unref?: () => void }).unref?.();
  }

  /** Sends a Ping; the Pong only refreshes liveness. */
  ping(): void {
    try {
      this.write(encodeMessage({ kind: 7, nonce: ++this.pingNonce }));
    } catch {
      // closed
    }
  }

  private onAuthRefresh(a: Auth): void {
    if (this.role !== 'server') {
      this.fail(Status.protocol_error, 'AuthRefresh sent by the server');
      return;
    }
    const h = this.opts.onAuthRefresh;
    if (!h) {
      this.trySend({ kind: 6, status: Status.unimplemented, expiresAt: null });
      return;
    }
    void (async () => {
      try {
        const exp = await h(this, a);
        this.trySend({ kind: 6, status: Status.ok, expiresAt: exp ?? null });
      } catch (e) {
        this.goAway(Status.unauthenticated, (e as Error).message);
      }
    })();
  }

  /** Sends AuthRefresh with a fresh credential (client). */
  refreshAuth(a: Auth): void {
    if (this.role !== 'client') throw new Error('session: only the client refreshes its credential');
    this.write(encodeMessage({ kind: 5, auth: a }));
  }

  /** Sends AuthStatus (server): the result of a refresh, or a warning that the credential expires soon. */
  sendAuthStatus(status: number, expiresAt: number | null): void {
    if (this.role !== 'server') throw new Error('session: only the server sends AuthStatus');
    this.write(encodeMessage({ kind: 6, status, expiresAt }));
  }

  private trySend(m: Message): void {
    try {
      this.write(encodeMessage(m));
    } catch {
      // closed
    }
  }

  // -------------------------------------------------------------------------
  // Schema updates (6.6)
  // -------------------------------------------------------------------------

  private onSchemaUpdate(epoch: number, hash: Uint8Array, rawDelta: Uint8Array): void {
    const cur = this.peer;
    if (!cur) {
      this.fail(Status.schema_mismatch, 'SchemaUpdate from a peer that published no schema');
      return;
    }
    let next: SchemaState;
    let d: Delta;
    try {
      d = decodeDelta(rawDelta);
      next = cur.applyUpdate(epoch, hash, d);
    } catch (e) {
      this.fail(Status.schema_mismatch, (e as Error).message);
      return;
    }
    this.peer = next;
    const ack = async () => {
      if (this.opts.onPeerSchemaUpdate) {
        try {
          await this.opts.onPeerSchemaUpdate(this, { epoch, hash, delta: d, schema: next.schema });
        } catch (e) {
          this.fail(e instanceof SparrowError && isCoreStatus(e.status) ? e.status : Status.schema_mismatch, (e as Error).message);
          return;
        }
      }
      this.trySend({ kind: 4, epoch });
    };
    this.peerUpdates = this.peerUpdates.then(ack, ack);
  }

  private onSchemaAck(epoch: number): void {
    if (!this.local || epoch > this.local.epoch) {
      this.fail(Status.protocol_error, 'SchemaAck for an epoch never sent');
      return;
    }
    if (epoch > this.localAcked) {
      this.localAcked = epoch;
      for (const [f, e] of this.pendingFacets) if (e <= epoch) this.pendingFacets.delete(f);
    }
    this.ackWaiter.wake();
  }

  /**
   * Publishes a new version of this side's schema (6.6): sends SchemaUpdate
   * at the next epoch and holds back later callee messages of calls to the
   * facets it adds or replaces until the peer acknowledges it. Resolves at
   * the ack; without one in time the session closes with
   * GoAway(schema_mismatch).
   */
  async updateSchema(nw: Schema, opts: { ackTimeoutMs?: number } = {}): Promise<void> {
    if (this.isClosed) throw this.closedError();
    const cur = this.local;
    if (!cur) throw new Error('session: this side published no schema in the handshake');
    if (this.role === 'server' && !this.welcomeDone) throw new Error('session: the handshake is not complete');
    const d = diff(cur.schema, nw);
    const next = cur.apply(d);
    const epoch = next.epoch;
    this.setLocal(next);
    for (const op of d) if (op.op === 'put') this.pendingFacets.set(op.facet.id, epoch);
    const t = this.timer(opts.ackTimeoutMs ?? this.opts.schemaAckTimeoutMs ?? SessionDefaults.schemaAckTimeoutMs, () => {
      if (this.localAcked < epoch && !this.isClosed) this.fail(Status.schema_mismatch, 'SchemaAck did not arrive in time');
    });
    this.write(encodeMessage({ kind: 3, epoch, hash: next.hash, delta: encodeDelta(d) }));
    await this.waitEpoch(epoch);
    clearTimeout(t);
    this.sessionTimers.delete(t);
  }

  private async waitEpoch(epoch: number): Promise<void> {
    while (this.localAcked < epoch) {
      if (this.isClosed) throw this.closedError();
      await this.ackWaiter.wait();
    }
  }

  private async gate(c: CallState): Promise<void> {
    const e = this.pendingFacets.get(c.facetId);
    if (e !== undefined && e > this.localAcked) await this.waitEpoch(e);
  }

  // -------------------------------------------------------------------------
  // Shutdown (5.6)
  // -------------------------------------------------------------------------

  /**
   * Starts a graceful shutdown: no new calls, running calls continue until
   * they finish or the grace period ends, then the transport is closed.
   */
  goAway(status: number = Status.going_away, reason = '', retryAfterMs: number | null = null): void {
    if (this.goAwaySent || this.isClosed) return;
    const g: GoAway = { kind: 9, status, reason: truncateReason(reason, 1024), retryAfterMs, versions: null };
    this.goAwaySent = g;
    this.draining = true;
    this.slotWaiter.wake();
    this.trySend(g);
    this.timer(this.opts.gracePeriodMs ?? SessionDefaults.gracePeriodMs, () => this.terminate(status, reason, false));
    if (this.calls.size === 0) this.drained();
  }

  /** Ends the session at once with GoAway(status) and closes the transport; running calls fail with unavailable. */
  close(status: number = Status.going_away, reason = ''): Promise<CloseInfo> {
    this.sendGoAwayAndClose(status, reason, null, null);
    return this.closed;
  }

  private onGoAway(g: GoAway): void {
    if (this.goAwayRecv) return;
    this.goAwayRecv = g;
    this.draining = true;
    this.slotWaiter.wake();
    try {
      this.opts.onGoAway?.(this, g);
    } catch (e) {
      this.log(`onGoAway: ${(e as Error).message}`);
    }
    const notDispatched = this.role === 'client' && (this.optReject || !this.welcomeDone);
    if (notDispatched) {
      const err = new SparrowError(g.status, g.reason, undefined, { remote: true, notDispatched: true });
      for (const c of [...this.calls.values()]) this.failCall(c, err);
      this.terminate(g.status, g.reason, true, err);
      return;
    }
    if (this.role === 'server' && !this.readyDone) {
      this.terminate(g.status, g.reason, true);
      return;
    }
    this.timer(this.opts.gracePeriodMs ?? SessionDefaults.gracePeriodMs, () => this.terminate(g.status, g.reason, true));
    if (this.calls.size === 0) this.drained();
  }

  private drained(): void {
    if (this.goAwaySent) this.terminate(this.goAwaySent.status, this.goAwaySent.reason, false);
    else if (this.goAwayRecv) this.terminate(this.goAwayRecv.status, this.goAwayRecv.reason, true);
    else if (this.lingerCode) this.terminate(this.lingerCode.code, this.lingerCode.reason, this.lingerCode.remote);
  }

  /** GoAway(code) and close: a session-level error (8). */
  private fail(code: number, reason: string): void {
    this.log(`session failed: ${describeStatus(code)}: ${reason}`);
    this.sendGoAwayAndClose(code, reason, null, null);
  }

  private sendGoAwayAndClose(code: number, reason: string, retry: number | null, versions: number[] | null): void {
    if (this.isClosed) return;
    if (!this.goAwaySent) {
      const g: GoAway = { kind: 9, status: isCoreStatus(code) ? code : Status.internal, reason: truncateReason(reason, 1024), retryAfterMs: retry, versions };
      this.goAwaySent = g;
      this.draining = true;
      this.trySend(g);
    }
    this.terminate(code, reason, false);
  }

  /** Closes the session: every open call fails, the transport is closed, closed resolves. */
  private terminate(code: number, reason: string, remote: boolean, callErr?: SparrowError): void {
    if (this.isClosed) return;
    this.isClosed = true;
    this.draining = true;
    const notDispatched = this.role === 'client' && ((!this.welcomeDone && !this.optimistic) || this.optReject);
    const err = new SparrowError(code, reason, undefined, { remote, notDispatched: notDispatched || callErr?.notDispatched });
    this.closeInfo = { code, reason, remote, error: err };
    for (const t of this.sessionTimers) clearTimeout(t);
    this.sessionTimers.clear();
    if (this.idleTimer) clearTimeout(this.idleTimer);
    const ce = callErr ?? new SparrowError(Status.unavailable, `session closed: ${reason}`, undefined, { notDispatched });
    for (const c of [...this.calls.values()]) this.failCall(c, ce);
    this.calls.clear();
    this.slotWaiter.wake();
    this.welcomeWaiter.wake();
    this.ackWaiter.wake();
    const h = this.handshake;
    this.handshake = null;
    h?.reject(callErr ?? (this.goAwayRecv && !this.welcomeDone ? new SparrowError(this.goAwayRecv.status, this.goAwayRecv.reason, undefined, { remote: true, notDispatched: true }) : err));
    const info = { code, reason, remote };
    void this.conn.close(isCoreStatus(code) && code <= MAX_CORE_STATUS ? code : Status.internal, reason).finally(() => this.closedResolve(info));
  }

  // -------------------------------------------------------------------------
  // Calls: common
  // -------------------------------------------------------------------------

  private sendCallMsg(c: CallState, m: CallMessage): void {
    const b = encodeMessage(m);
    if (b.length > this.peerLimits.maxMessageSize) {
      throw new SparrowError(Status.message_too_large, `a message of ${b.length} bytes exceeds the peer's maxMessageSize ${this.peerLimits.maxMessageSize}`);
    }
    this.applySent(c, m.kind);
    this.write(b);
    if (c.ended) this.endCall(c);
  }

  /** Applies a message this side sends to the halves of the call. */
  private applySent(c: CallState, k: number): void {
    if (c.caller) {
      if (k === 23) {
        c.cancelSent = true;
        c.callerDone = true;
      } else if (k === 19) c.callerDone = true;
    } else {
      let fin = false;
      if (k === 20) fin = true;
      else if (k === 17 && !c.outputEnds) fin = true;
      else if (k === 19 && c.outputEnds) fin = true;
      if (fin && !c.calleeDone) {
        c.calleeDone = true;
        // The callee stops counting and forgets the call at its own final message (7.1, 7.6).
        this.uncount(c);
        if (!c.callerDone) {
          this.calls.delete(c.id);
          c.ended = true;
        }
      }
    }
    if (c.callerDone && c.calleeDone) c.ended = true;
    c.wake();
  }

  /** Sends a counted message (Item, Progress, Bytes), waiting while no credit is left (7.4). */
  private async sendCounted(c: CallState, m: CallMessage, check: () => void): Promise<void> {
    for (;;) {
      check();
      if (this.isClosed) throw this.closedError();
      const b = encodeMessage(m);
      const n = countedBytes(m, b.length);
      if (c.sendWin.canSend(n)) {
        if (b.length > this.peerLimits.maxMessageSize) {
          throw new SparrowError(Status.message_too_large, `a message of ${b.length} bytes exceeds the peer's maxMessageSize`);
        }
        c.sendWin.consume(n);
        this.write(b);
        return;
      }
      await c.waiter.wait();
    }
  }

  private grant(c: CallState, n: number): void {
    if (n <= 0) return;
    c.unacked += n;
    const half = Math.max(1, Math.floor(c.recvInit / 2));
    if (c.unacked >= half && !c.peerHalfDone() && !c.ended) {
      const g = c.unacked;
      c.unacked = 0;
      c.recvWin.grant(g);
      this.trySend({ kind: 24, callId: c.id, amount: g });
    }
  }

  private deliver(m: CallMessage, b: Uint8Array): void {
    const c = this.calls.get(m.callId);
    if (!c) return; // unknown or ended call: ignored (7.1)
    const k = m.kind;
    const fromCaller = !c.caller;
    if ((fromCaller && !isCallerKind(k)) || (!fromCaller && !isCalleeKind(k))) {
      this.violation(c, `a message of kind ${k} in the wrong direction`);
      return;
    }
    if (m.kind === 24) {
      c.sendWin.grant(m.amount);
      c.wake();
      return;
    }
    const lateCancel = fromCaller && k === 23 && !c.cancelRecv && !c.calleeDone;
    if (c.peerHalfDone() && !lateCancel) return;
    const n = countedBytes(m, b.length);
    if (n > 0 && !c.recvWin.consume(n)) {
      this.violation(c, 'sent with no credit left');
      return;
    }
    if (m.kind === 25) {
      if (!c.recvTokens.has(m.token)) {
        if (c.recvTokens.size >= SessionDefaults.maxTokens) {
          this.violation(c, 'more than 64 byte tokens in one call');
          return;
        }
        c.recvTokens.add(m.token);
      }
      let tb = c.tokens.get(m.token);
      if (!tb) {
        tb = { chunks: [], fin: false, size: 0 };
        c.tokens.set(m.token, tb);
      }
      if (!tb.fin) {
        tb.chunks.push(m.data.slice());
        tb.size += m.data.length;
        tb.fin = m.fin;
      } else this.grant(c, n);
    }
    if (fromCaller) this.fromCaller(c, m, b, n);
    else this.fromCallee(c, m, b, n);
    if (c.callerDone && c.calleeDone && !c.ended) c.ended = true;
    c.wake();
    if (c.ended) this.endCall(c);
  }

  private fromCaller(c: CallState, m: CallMessage, b: Uint8Array, n: number): void {
    switch (m.kind) {
      case 18:
        c.items.push({ raw: m.value, n });
        return;
      case 19:
        c.callerDone = true;
        c.inputEnded = true;
        c.trailers = m.trailers;
        return;
      case 23: {
        const code = m.status === Status.ok ? Status.cancelled : m.status;
        c.callerDone = true;
        c.inputEnded = true;
        c.cancelRecv = true;
        const e = new SparrowError(code, 'cancelled by the caller', undefined, { remote: true });
        c.localErr ??= e;
        c.abort?.abort(e);
        if (!c.calleeDone) {
          // Answered at once; the handler's later result is ignored (7.5).
          this.trySendError(c, new SparrowError(code, 'cancelled'));
        }
        return;
      }
    }
    void b;
  }

  private fromCallee(c: CallState, m: CallMessage, b: Uint8Array, n: number): void {
    void b;
    switch (m.kind) {
      case 22:
        if (!c.headers) {
          c.headers = m.metadata;
          try {
            c.onHeaders?.(m.metadata);
          } catch (e) {
            this.log(`onHeaders: ${(e as Error).message}`);
          }
        }
        return;
      case 17:
        c.response = m.output;
        if (!c.outputEnds) c.calleeDone = true;
        break;
      case 18:
        c.items.push({ raw: m.value, n });
        return;
      case 21:
        this.grant(c, n);
        try {
          c.onProgress?.({ done: m.done, total: m.total, note: m.note });
        } catch (e) {
          this.log(`onProgress: ${(e as Error).message}`);
        }
        return;
      case 19:
        if (!c.outputEnds) return;
        c.trailers = m.trailers;
        c.calleeDone = true;
        break;
      case 20:
        c.peerError = this.remoteError(c, m.status, m.message, m.details);
        c.calleeDone = true;
        break;
      default:
        return;
    }
    if (c.calleeDone && !c.callerDone) {
      // The callee finished first: the caller sends End next, with no further Item or Bytes (7.1).
      try {
        this.sendCallMsg(c, { kind: 19, callId: c.id, trailers: new Map() });
      } catch {
        // closed
      }
    }
  }

  private remoteError(c: CallState, status: number, message: string, details: Uint8Array | null): SparrowError {
    let name = statusName(status) as string | undefined;
    if (!name && c.facet) name = c.facet.sigils.find((s) => s.id === status)?.name;
    const e = new SparrowError(status, message, undefined, { remote: true });
    e.code = name ?? describeStatus(status);
    if (details) {
      e.detailsRaw = details;
      let decoded: unknown;
      let ok = false;
      if (c.codec) {
        try {
          const d = c.codec.decode(T.dynamic, details, { trusted: true }) as DynamicValue;
          const td = c.facet!.types.find((t) => t.id === d.type);
          decoded = { type: d.type, typeName: td?.name ?? describeBuiltin(d.type as number), value: d.value };
          ok = true;
        } catch {
          ok = false;
        }
      }
      if (!ok) {
        try {
          decoded = decode(details);
        } catch {
          decoded = undefined;
        }
      }
      e.details = decoded;
    }
    return e;
  }

  /** The peer broke a rule inside a call (7.4, 8): Error(protocol_error) as callee, Cancel(protocol_error) as caller. */
  private violation(c: CallState, why: string): void {
    this.log(`call ${c.id}: protocol error: ${why}`);
    const e = new SparrowError(Status.protocol_error, why);
    c.localErr ??= e;
    c.abort?.abort(e);
    if (c.caller) {
      if (!c.calleeDone && !c.cancelSent) {
        try {
          this.sendCallMsg(c, { kind: 23, callId: c.id, status: Status.protocol_error });
        } catch {
          // closed
        }
        this.armGiveUp(c);
      }
    } else if (!c.calleeDone) {
      this.trySendError(c, e);
    }
    c.wake();
  }

  private trySendError(c: CallState, e: SparrowError): void {
    if (c.calleeDone) return;
    let status = e.status;
    if (status < 0) {
      const sg = c.facet?.sigils.find((s) => s.name === e.code && s.kind === 1);
      status = sg ? sg.id : Status.unknown;
    }
    let details: Uint8Array | null = null;
    if (e.details !== undefined) {
      try {
        details = this.encodeDetails(c, e.details);
      } catch (x) {
        this.log(`cannot encode error details: ${(x as Error).message}`);
      }
    }
    const msg: CallMessage = { kind: 20, callId: c.id, status, message: e.rawMessage, details };
    // Core errors without details carry no IDs of the facet; they need not wait for a schema ack.
    const needsGate = !isCoreStatus(status) || details !== null;
    if (needsGate && this.pendingFacets.has(c.facetId)) {
      void this.gate(c).then(
        () => this.trySendCall(c, msg),
        () => {},
      );
      return;
    }
    this.trySendCall(c, msg);
  }

  private trySendCall(c: CallState, m: CallMessage): void {
    if (c.calleeDone && !c.caller) return;
    try {
      this.sendCallMsg(c, m);
    } catch (e) {
      if (e instanceof SparrowError && e.status === Status.message_too_large && !c.caller) {
        try {
          this.sendCallMsg(c, { kind: 20, callId: c.id, status: Status.message_too_large, message: e.rawMessage, details: null });
        } catch {
          // closed
        }
      }
    }
  }

  private encodeDetails(c: CallState, d: unknown): Uint8Array {
    if (d instanceof Raw) return d.bytes;
    if (d && typeof d === 'object' && !(d instanceof Map) && !Array.isArray(d) && 'type' in d && 'value' in d && c.codec) {
      const dv = d as DynamicValue;
      if (c.codec.typeId(dv.type) !== undefined) return c.codec.encode(T.dynamic, { type: dv.type, value: dv.value });
    }
    return encode(d);
  }

  private uncount(c: CallState): void {
    if (!c.counted) return;
    c.counted = false;
    if (c.caller) {
      this.outOpen--;
      this.slotWaiter.wake();
    } else this.inOpen--;
  }

  private endCall(c: CallState): void {
    c.ended = true;
    if (this.calls.get(c.id) === c) this.calls.delete(c.id);
    for (const t of c.timers) clearTimeout(t);
    c.timers = [];
    this.uncount(c);
    if (!c.caller && c.abort && !c.abort.signal.aborted) c.abort.abort(new SparrowError(Status.cancelled, 'the call ended'));
    c.wake();
    if (this.draining && this.calls.size === 0) this.drained();
  }

  private failCall(c: CallState, e: SparrowError): void {
    c.localErr ??= e;
    c.abort?.abort(e);
    c.ended = true;
    for (const t of c.timers) clearTimeout(t);
    c.timers = [];
    this.uncount(c);
    if (this.calls.get(c.id) === c) this.calls.delete(c.id);
    c.wake();
  }

  private armGiveUp(c: CallState): void {
    const giveUp = this.opts.cancelGiveUpMs ?? SessionDefaults.cancelGiveUpMs;
    const broken = this.opts.cancelBrokenMs ?? SessionDefaults.cancelBrokenMs;
    const t = setTimeout(() => {
      if (c.ended || c.calleeDone) return;
      c.localErr ??= new SparrowError(c.cancelCode, 'no answer to Cancel');
      c.items = [];
      c.wake();
      // On the shared lane the call keeps counting until its final message; after cancelBrokenMs the peer is broken (7.5).
      const t2 = setTimeout(() => {
        if (!c.ended && !c.calleeDone) this.fail(Status.protocol_error, 'a Cancel went unanswered for 30 s');
      }, Math.max(0, broken - giveUp));
      c.timers.push(t2);
    }, giveUp);
    c.timers.push(t);
  }

  // -------------------------------------------------------------------------
  // Calls: callee side
  // -------------------------------------------------------------------------

  private lookupLocal(facetId: number, methodId: number): { facet?: Facet; method?: Method; service?: string } {
    const f = this.local?.facet(facetId);
    if (!f) return {};
    const m = findMethod(f, methodId);
    return { facet: f, method: m?.method, service: m?.service.name };
  }

  private onRequest(r: Request, b: Uint8Array): void {
    void b;
    if (this.role === 'server' && this.goAwaySent && !this.readyDone) return; // a rejected optimistic start dispatches nothing (5.3)
    const { facet, method, service } = this.lookupLocal(r.facetId, r.methodId);
    let flags = this.publishedFlags.get(`${r.facetId}:${r.methodId}`) ?? 0;
    if (method) flags = method.flags;
    if (r.callId === NOTIFICATION_ID) {
      this.onNotification(r, facet, method, service);
      return;
    }
    if (callerOf(r.callId) === this.role) {
      this.fail(Status.protocol_error, "Request with a call ID of this side's parity");
      return;
    }
    if (this.calls.has(r.callId)) {
      this.fail(Status.protocol_error, 'Request for a call ID that is open');
      return;
    }
    const sendInit = initialCredit(this.peerLimits, false, metaCredit(r.metadata));
    const recvInit = initialCredit(this.localLimits, false);
    const c = new CallState(false, r.facetId, r.methodId, flags, sendInit, recvInit);
    c.id = r.callId;
    c.facet = facet;
    c.method = method;
    c.service = service;
    c.metadata = r.metadata;
    if (!c.inputEnds) c.callerDone = true;
    if (facet && method) c.codec = this.codecFor(facet);
    this.calls.set(c.id, c);
    let reject: SparrowError | undefined;
    if (this.role === 'server' && !this.readyDone) reject = new SparrowError(Status.not_ready, 'call before Ready');
    else if (this.draining) reject = new SparrowError(Status.going_away, 'the session is shutting down');
    else if (!method) reject = new SparrowError(Status.unimplemented, `facet ${r.facetId} has no method ${r.methodId}`);
    else if (method.flags & 0x2) {
      reject = new SparrowError(Status.invalid_argument, `method ${r.methodId} of facet ${r.facetId} is a notification; send it with call ID 0`);
    } else if (this.inOpen >= this.localLimits.maxConcurrentCalls) reject = new SparrowError(Status.resource_exhausted, 'maxConcurrentCalls reached');
    else {
      this.inOpen++;
      c.counted = true;
    }
    if (reject) {
      this.trySendError(c, reject);
      return;
    }
    const h = this.router.resolve(facet!, service, method!);
    if (!h) {
      this.trySendError(c, new SparrowError(Status.unimplemented, `no handler for ${facet!.name}.${method!.name}`));
      return;
    }
    c.abort = new AbortController();
    const dl = metaDeadline(r.metadata);
    let deadline: number | undefined;
    if (dl !== undefined) {
      deadline = Date.now() + dl;
      c.timers.push(
        setTimeout(() => {
          const e = new SparrowError(Status.deadline_exceeded, 'deadline exceeded');
          c.abort?.abort(e);
          if (!c.calleeDone) this.trySendError(c, e);
        }, dl),
      );
    }
    void this.serve(c, h, r, deadline);
  }

  private makeContext(c: CallState, deadline: number | undefined, notification: boolean): CallContext {
    const s = this;
    const checkOut = () => {
      if (c.calleeDone || c.ended) throw c.localErr ?? new SparrowError(Status.cancelled, 'the call has ended');
    };
    return {
      session: this,
      callId: c.id,
      facet: c.facet!,
      method: c.method!,
      signal: c.abort?.signal ?? new AbortController().signal,
      metadata: c.metadata,
      deadline,
      principal: this.principalName || metaPrincipal(c.metadata) || '',
      notification,
      async progress(done, total, note) {
        if (notification) return;
        await s.gate(c);
        await s.sendCounted(c, { kind: 21, callId: c.id, done, total: total ?? null, note: note ?? null }, checkOut);
      },
      sendHeaders(md) {
        if (notification || c.headersSent || c.dataSent) return;
        checkOut();
        c.headersSent = true;
        s.sendCallMsg(c, { kind: 22, callId: c.id, metadata: toMetadata(md) });
      },
      async send(item) {
        if (notification) throw new SparrowError(Status.internal, 'a notification sends nothing back');
        const out = c.method!.output;
        if (!isStream(out)) throw new SparrowError(Status.internal, "the method's output is not a stream");
        // The facet's current definition: after an acknowledged update an item may use new IDs.
        const cur = s.local?.facet(c.facetId);
        const codec = cur ? s.codecFor(cur) : c.codec!;
        const raw = codec.encode(out[1], item);
        await s.gate(c);
        c.dataSent = true;
        await s.sendCounted(c, { kind: 18, callId: c.id, value: raw }, checkOut);
      },
      setTrailers(md) {
        c.myTrailers = toMetadata(md);
      },
      async sendBytes(token, data, fin = true) {
        if (notification) throw new SparrowError(Status.internal, 'a notification sends nothing back');
        await s.gate(c);
        c.dataSent = true;
        await s.sendBytesChunks(c, token, data, fin, checkOut);
      },
      bytes(token) {
        return s.collectBytes(c, token);
      },
    };
  }

  private async serve(c: CallState, h: Handler, r: Request, deadline: number | undefined): Promise<void> {
    const ctx = this.makeContext(c, deadline, false);
    const m = c.method!;
    try {
      let input: unknown;
      if (isStream(m.input)) input = this.inputItems(c, m.input[1]);
      else if (isByteStream(m.input)) input = null;
      else input = c.codec!.decode(m.input, r.input, { trusted: true });
      let out = await h(input, ctx);
      if (c.calleeDone) return;
      if (isStream(m.output)) {
        if (out !== undefined && out !== null) {
          if (typeof (out as AsyncIterable<unknown>)[Symbol.asyncIterator] === 'function' || typeof (out as Iterable<unknown>)[Symbol.iterator] === 'function') {
            for await (const item of out as AsyncIterable<unknown>) {
              if (c.calleeDone) return;
              await ctx.send(item);
            }
          } else throw new SparrowError(Status.internal, 'a stream handler returns an iterable of items or nothing');
        }
        await this.gate(c);
        if (c.calleeDone) return;
        this.sendCallMsg(c, { kind: 19, callId: c.id, trailers: c.myTrailers ?? new Map() });
        return;
      }
      if (isByteStream(m.output)) {
        if (out instanceof Uint8Array) await ctx.sendBytes(0, out, true);
        await this.gate(c);
        if (c.calleeDone) return;
        this.sendCallMsg(c, { kind: 19, callId: c.id, trailers: c.myTrailers ?? new Map() });
        return;
      }
      if (m.output === T.unit && out === undefined) out = null;
      let raw: Uint8Array;
      try {
        raw = c.codec!.encode(m.output, out);
      } catch (e) {
        throw new SparrowError(Status.internal, `cannot encode the output: ${(e as Error).message}`);
      }
      await this.gate(c);
      if (c.calleeDone) return;
      this.sendCallMsg(c, { kind: 17, callId: c.id, output: raw });
      if (c.outputEnds && !c.calleeDone) this.sendCallMsg(c, { kind: 19, callId: c.id, trailers: c.myTrailers ?? new Map() });
    } catch (e) {
      if (c.calleeDone || this.isClosed) return;
      const se = asSparrowError(e);
      if (se.status === Status.message_too_large || !(e instanceof SparrowError)) this.log(`call ${c.id} (${c.facet?.name}.${m.name}): ${se.message}`);
      this.trySendError(c, se);
    }
  }

  /** The input items of a stream input, pulled with credit. */
  private async *inputItems(c: CallState, t: TypeRef): AsyncGenerator<unknown> {
    for (;;) {
      if (c.items.length) {
        const it = c.items.shift()!;
        this.grant(c, it.n);
        yield c.codec!.decode(t, it.raw, { trusted: true });
        continue;
      }
      if (c.cancelRecv || c.localErr) throw c.localErr ?? new SparrowError(Status.cancelled, 'cancelled');
      if (c.inputEnded || c.callerDone || c.ended) return;
      await c.waiter.wait();
    }
  }

  private async collectBytes(c: CallState, token: number): Promise<Uint8Array> {
    for (;;) {
      const tb = c.tokens.get(token);
      if (tb?.fin) {
        let n = 0;
        for (const x of tb.chunks) n += x.length;
        const out = new Uint8Array(n);
        let off = 0;
        for (const x of tb.chunks) {
          out.set(x, off);
          off += x.length;
        }
        this.grant(c, tb.size);
        tb.size = 0;
        return out;
      }
      if (c.localErr) throw c.localErr;
      if (c.peerError) throw c.peerError;
      if (c.peerHalfDone() || c.ended) throw new SparrowError(Status.data_loss, `byte token ${token} was cut off or never sent`);
      await c.waiter.wait();
    }
  }

  private async sendBytesChunks(c: CallState, token: number, data: Uint8Array, fin: boolean, check: () => void): Promise<void> {
    if (!c.sentTokens.has(token)) {
      if (c.sentTokens.size >= SessionDefaults.maxTokens) throw new SparrowError(Status.resource_exhausted, 'a sender may open at most 64 byte tokens per call');
      c.sentTokens.add(token);
    }
    const chunk = Math.min(SessionDefaults.sharedChunk, this.peerLimits.maxMessageSize - 64);
    let off = 0;
    do {
      const part = data.subarray(off, Math.min(data.length, off + chunk));
      off += part.length;
      const last = off >= data.length;
      await this.sendCounted(c, { kind: 25, callId: c.id, token, data: part, fin: fin && last }, check);
    } while (off < data.length);
  }

  private onNotification(r: Request, facet: Facet | undefined, method: Method | undefined, service: string | undefined): void {
    if ((this.role === 'server' && !this.readyDone) || this.draining) return;
    if (!facet || !method || !(method.flags & 0x2)) return; // dropped (7.1)
    const h = this.router.resolve(facet, service, method);
    if (!h) return;
    if (this.notifying >= SessionDefaults.maxNotifications) {
      this.log('dropped a notification: too many in flight');
      return;
    }
    const c = new CallState(false, r.facetId, r.methodId, method.flags, 0, 0);
    c.facet = facet;
    c.method = method;
    c.service = service;
    c.metadata = r.metadata;
    c.codec = this.codecFor(facet);
    c.callerDone = c.calleeDone = c.ended = true;
    c.abort = new AbortController();
    this.notifying++;
    void (async () => {
      try {
        const input = c.codec!.decode(method.input, r.input, { trusted: true });
        await h(input, this.makeContext(c, undefined, true));
      } catch (e) {
        this.log(`notification ${facet.name}.${method.name}: ${(e as Error).message}`);
      } finally {
        this.notifying--;
      }
    })();
  }

  // -------------------------------------------------------------------------
  // Calls: caller side
  // -------------------------------------------------------------------------

  private resolveMethod(facet: string | number, method: string | number): { f: Facet; m: Method } {
    if (!this.peer) {
      throw new SparrowError(Status.unimplemented, this.role === 'server' ? 'the client published no schema' : 'no server schema', undefined, { notDispatched: true });
    }
    const f = this.peerFacet(facet);
    if (!f) throw new SparrowError(Status.unimplemented, `the peer has no facet ${JSON.stringify(facet)}`, undefined, { notDispatched: true });
    const m = typeof method === 'number' ? findMethod(f, method) : findMethodByName(f, method);
    if (!m) throw new SparrowError(Status.unimplemented, `facet ${f.name} has no method ${JSON.stringify(method)}`, undefined, { notDispatched: true });
    return { f, m: m.method };
  }

  /**
   * Starts a call and returns its low-level handle. The Request is sent at
   * once when a concurrency slot is free, otherwise once one frees up.
   */
  open(facet: string | number, method: string | number, input?: unknown, opts: CallOptions = {}): ClientCall {
    return new ClientCall(this, facet, method, input, opts);
  }

  /** @internal Creates and sends the Request of a ClientCall. */
  async startCall(facet: string | number, method: string | number, input: unknown, opts: CallOptions): Promise<CallState> {
    const { f, m } = this.resolveMethod(facet, method);
    if (m.flags & 0x2) throw new SparrowError(Status.invalid_argument, 'use notify for a notification method', undefined, { notDispatched: true });
    const codec = this.codecFor(f);
    let raw: Uint8Array;
    if (isStream(m.input) || isByteStream(m.input)) raw = NULL_ITEM;
    else {
      try {
        raw = codec.encode(m.input, m.input === T.unit && input === undefined ? null : input);
      } catch (e) {
        throw new SparrowError(Status.invalid_argument, (e as Error).message, undefined, { notDispatched: true });
      }
    }
    // A concurrency slot (7.6).
    for (;;) {
      if (this.isClosed) {
        const g = this.goAwayRecv;
        const e = g ? new SparrowError(g.status, g.reason, undefined, { remote: true }) : this.closedError();
        e.notDispatched = true;
        throw e;
      }
      if (this.draining) throw new SparrowError(Status.going_away, 'the session is shutting down', undefined, { notDispatched: true });
      if (this.outOpen < this.peerLimits.maxConcurrentCalls) break;
      await this.slotWaiter.wait();
      if (opts.signal?.aborted) throw new SparrowError(Status.cancelled, 'cancelled', undefined, { notDispatched: true });
    }
    if (this.optimistic && !this.welcomeDone) {
      while (!this.welcomeDone && this.sentPreWelcome + raw.length + 64 > SessionDefaults.preAuthLimit && this.sentPreWelcome > 0) {
        if (this.isClosed) throw this.closedError();
        await this.welcomeWaiter.wait();
      }
      this.sentPreWelcome += raw.length + 64;
    }
    const md = toMetadata(opts.metadata);
    if (opts.credit !== undefined) md.set(MetaKeys.credit, opts.credit);
    if (opts.timeoutMs !== undefined && !md.has(MetaKeys.deadline)) md.set(MetaKeys.deadline, Math.max(0, Math.ceil(opts.timeoutMs)));
    const recvInit = metaCredit(md) ?? initialCredit(this.localLimits, false);
    const c = new CallState(true, f.id, m.id, m.flags, initialCredit(this.peerLimits, false), recvInit);
    c.facet = f;
    c.method = m;
    c.codec = codec;
    c.metadata = md;
    c.onProgress = opts.onProgress;
    c.onHeaders = opts.onHeaders;
    c.counted = true;
    this.outOpen++;
    c.id = this.nextId;
    this.nextId += 2;
    if (!c.inputEnds) c.callerDone = true;
    const b = encodeMessage({ kind: 16, callId: c.id, facetId: f.id, methodId: m.id, metadata: md, input: raw });
    if (b.length > this.peerLimits.maxMessageSize) {
      this.uncount(c);
      throw new SparrowError(Status.message_too_large, `a Request of ${b.length} bytes exceeds the peer's maxMessageSize`, undefined, { notDispatched: true });
    }
    this.calls.set(c.id, c);
    try {
      this.write(b);
    } catch (e) {
      this.failCall(c, asSparrowError(e));
      throw e;
    }
    return c;
  }

  /** @internal */
  async sendInputItem(c: CallState, item: unknown): Promise<void> {
    const t = c.method!.input;
    if (!isStream(t)) throw new SparrowError(Status.internal, "the method's input is not a stream");
    const raw = c.codec!.encode(t[1], item);
    await this.sendCounted(c, { kind: 18, callId: c.id, value: raw }, () => {
      if (c.localErr) throw c.localErr;
      if (c.callerDone || c.ended) throw new SparrowError(Status.cancelled, "the caller's half is finished");
    });
  }

  /** @internal */
  async sendInputBytes(c: CallState, token: number, data: Uint8Array, fin: boolean): Promise<void> {
    await this.sendBytesChunks(c, token, data, fin, () => {
      if (c.localErr) throw c.localErr;
      if (c.callerDone || c.ended) throw new SparrowError(Status.cancelled, "the caller's half is finished");
    });
  }

  /** @internal Finishes the caller's half with End. */
  endInput(c: CallState, trailers?: MetadataInit): void {
    if (c.callerDone || c.ended) return;
    try {
      this.sendCallMsg(c, { kind: 19, callId: c.id, trailers: toMetadata(trailers) });
    } catch {
      // closed
    }
  }

  /** @internal Cancels a call (7.5). */
  cancelCall(c: CallState, code: number = Status.cancelled): void {
    if (c.ended || c.calleeDone || c.cancelSent) return;
    c.cancelCode = code;
    try {
      this.sendCallMsg(c, { kind: 23, callId: c.id, status: isCoreStatus(code) ? code : Status.cancelled });
    } catch {
      return;
    }
    this.armGiveUp(c);
  }

  /** @internal */
  async nextOutput(c: CallState): Promise<{ value: unknown; done: false } | { value: undefined; done: true }> {
    const t = c.method!.output;
    for (;;) {
      if (c.items.length) {
        const it = c.items.shift()!;
        this.grant(c, it.n);
        if (!isStream(t)) throw new SparrowError(Status.internal, 'the method has no output stream');
        return { value: c.codec!.decode(t[1], it.raw, { trusted: true }), done: false };
      }
      if (c.localErr) throw c.localErr;
      if (c.peerError) throw c.peerError;
      if (c.calleeDone) return { value: undefined, done: true };
      if (c.ended) throw this.closedError();
      await c.waiter.wait();
    }
  }

  /** @internal Waits for the callee's final message; returns the Response output (encoded) if any. */
  async finalOf(c: CallState): Promise<Uint8Array | undefined> {
    for (;;) {
      if (c.response && (!c.outputEnds || c.calleeDone) && !c.peerError) return c.response;
      if (c.localErr) throw c.localErr;
      if (c.peerError) throw c.peerError;
      if (c.calleeDone) return c.response;
      if (c.ended) throw this.closedError();
      await c.waiter.wait();
    }
  }

  /** @internal */
  async headersOf(c: CallState): Promise<Metadata> {
    for (;;) {
      if (c.headers) return c.headers;
      if (c.items.length || c.response || c.calleeDone || c.tokens.size || c.localErr || c.ended) return c.headers ?? new Map();
      await c.waiter.wait();
    }
  }

  /** @internal */
  bytesOf(c: CallState, token: number): Promise<Uint8Array> {
    return this.collectBytes(c, token);
  }

  /** @internal */
  decodeOutput(c: CallState, raw: Uint8Array): unknown {
    return c.codec!.decode(c.method!.output, raw, { trusted: true });
  }

  /**
   * Makes a call and resolves with its output: for a unary or client-stream
   * method (input is then an Iterable or AsyncIterable of items), or an
   * upload ([4] input: input is a Uint8Array) or download ([4] output: the
   * result is a Uint8Array).
   */
  async call(facet: string | number, method: string | number, input?: unknown, opts: CallOptions = {}): Promise<unknown> {
    const cc = this.open(facet, method, input, opts);
    return cc.result();
  }

  /**
   * Makes a call whose output is a stream (server or bidi stream) and returns
   * it as an AsyncIterable of the output items. For a bidi stream, input is an
   * Iterable or AsyncIterable of the input items.
   */
  stream(facet: string | number, method: string | number, input?: unknown, opts: CallOptions = {}): ClientCall {
    return this.open(facet, method, input, opts);
  }

  /** Sends a notification (call ID 0, no reply, best-effort). */
  notify(facet: string | number, method: string | number, input?: unknown, opts: { metadata?: MetadataInit } = {}): void {
    const { f, m } = this.resolveMethod(facet, method);
    if (!(m.flags & 0x2)) throw new SparrowError(Status.invalid_argument, `${f.name}.${m.name} is not a notification`);
    if (this.draining || this.isClosed) throw new SparrowError(Status.going_away, 'the session is shutting down');
    const raw = this.codecFor(f).encode(m.input, m.input === T.unit && input === undefined ? null : input);
    this.write(encodeMessage({ kind: 16, callId: 0, facetId: f.id, methodId: m.id, metadata: toMetadata(opts.metadata), input: raw }));
  }
}

function describeBuiltin(id: number): string {
  return Object.keys(T)[id] ?? String(id);
}

// ---------------------------------------------------------------------------
// ClientCall
// ---------------------------------------------------------------------------

function isIterable(x: unknown): x is Iterable<unknown> | AsyncIterable<unknown> {
  return (
    x !== null &&
    typeof x === 'object' &&
    !(x instanceof Uint8Array) &&
    (typeof (x as AsyncIterable<unknown>)[Symbol.asyncIterator] === 'function' || typeof (x as Iterable<unknown>)[Symbol.iterator] === 'function')
  );
}

/**
 * A call this side makes. Iterate it for the output items of a stream
 * output; await result() for a unary output. For a stream input, either pass
 * an (async) iterable as input, or call send() and end().
 */
export class ClientCall implements AsyncIterable<unknown> {
  private readonly session: Session;
  private readonly started: Promise<CallState>;
  private state?: CallState;
  private readonly opts: CallOptions;
  private settled = false;
  private abortListener?: () => void;
  private timeoutTimer?: Timer;
  /** Rejects once the call fails; used to race waits. */
  private readonly failure: Promise<never>;
  private fail!: (e: SparrowError) => void;

  /** Resolves with the Headers metadata (empty if the callee sent none before its data). */
  readonly headers: Promise<Metadata>;
  /** Resolves with the trailers of the callee's End (empty for a Response). */
  readonly trailers: Promise<Metadata>;

  constructor(session: Session, facet: string | number, method: string | number, input: unknown, opts: CallOptions) {
    this.session = session;
    this.opts = opts;
    this.failure = new Promise<never>((_, rej) => (this.fail = rej));
    this.failure.catch(noop);
    this.started = (async () => {
      if (opts.signal?.aborted) throw new SparrowError(Status.cancelled, 'cancelled', undefined, { notDispatched: true });
      return session.startCall(facet, method, input, opts);
    })();
    this.started.catch(noop);
    if (opts.signal) {
      this.abortListener = () => this.abortWith(new SparrowError(Status.cancelled, 'cancelled', undefined, {}), Status.cancelled);
      opts.signal.addEventListener('abort', this.abortListener, { once: true });
    }
    if (opts.timeoutMs !== undefined) {
      this.timeoutTimer = setTimeout(() => this.abortWith(new SparrowError(Status.deadline_exceeded, 'deadline exceeded'), Status.deadline_exceeded), opts.timeoutMs);
    }
    this.started.then(
      (c) => {
        this.state = c;
        if (input !== undefined && input !== null && (isStream(c.method!.input) || isByteStream(c.method!.input))) void this.pumpInput(c, input);
        else if (isByteStream(c.method!.input) && (input === undefined || input === null)) {
          // nothing to send yet: the application uses sendBytes and end
        }
      },
      (e) => this.fail(asSparrowError(e)),
    );
    this.headers = this.wrap((c) => session.headersOf(c));
    this.headers.catch(noop);
    this.trailers = this.wrap(async (c) => {
      await session.finalOf(c);
      return c.trailers ?? new Map();
    });
    this.trailers.catch(noop);
  }

  private wrap<X>(f: (c: CallState) => Promise<X>): Promise<X> {
    const p = (async () => f(await this.started))();
    return Promise.race([p, this.failure]).finally(() => this.maybeDone());
  }

  private maybeDone(): void {
    const c = this.state;
    if (c && (c.ended || c.calleeDone)) this.cleanup();
  }

  private cleanup(): void {
    if (this.settled) return;
    this.settled = true;
    if (this.abortListener) this.opts.signal?.removeEventListener('abort', this.abortListener);
    if (this.timeoutTimer) clearTimeout(this.timeoutTimer);
  }

  private abortWith(e: SparrowError, code: number): void {
    if (this.settled) return;
    this.fail(e);
    void this.started.then(
      (c) => this.session.cancelCall(c, code),
      noop,
    );
    this.cleanup();
  }

  private async pumpInput(c: CallState, input: unknown): Promise<void> {
    try {
      if (isByteStream(c.method!.input)) {
        if (input instanceof Uint8Array) await this.session.sendInputBytes(c, 0, input, true);
        else if (isIterable(input)) {
          for await (const chunk of input as AsyncIterable<Uint8Array>) await this.session.sendInputBytes(c, 0, chunk, false);
          await this.session.sendInputBytes(c, 0, new Uint8Array(0), true);
        } else throw new SparrowError(Status.invalid_argument, 'a byte-stream input is a Uint8Array or an iterable of chunks');
      } else {
        if (!isIterable(input)) throw new SparrowError(Status.invalid_argument, 'a stream input is an Iterable or AsyncIterable of items');
        for await (const item of input as AsyncIterable<unknown>) {
          if (c.callerDone || c.ended) return;
          await this.session.sendInputItem(c, item);
        }
      }
      this.session.endInput(c);
    } catch (e) {
      if (c.callerDone || c.ended) return;
      const se = asSparrowError(e);
      this.fail(se);
      this.session.cancelCall(c, se.status === Status.deadline_exceeded ? Status.deadline_exceeded : Status.cancelled);
    }
  }

  /** The call ID, once the Request is sent. */
  get id(): number | undefined {
    return this.state?.id;
  }

  /** Sends one input stream item, waiting for credit. */
  async send(item: unknown): Promise<void> {
    const c = await Promise.race([this.started, this.failure]);
    await Promise.race([this.session.sendInputItem(c, item), this.failure]);
  }

  /** Sends input byte data for a token (0 for a whole-value [4] input). */
  async sendBytes(token: number, data: Uint8Array, fin = true): Promise<void> {
    const c = await Promise.race([this.started, this.failure]);
    await Promise.race([this.session.sendInputBytes(c, token, data, fin), this.failure]);
  }

  /** Finishes the caller's half with End (stream or byte input). */
  async end(trailers?: MetadataInit): Promise<void> {
    const c = await Promise.race([this.started, this.failure]);
    this.session.endInput(c, trailers);
  }

  /** Cancels the call: Cancel(status) to the callee; pending waits reject with cancelled. */
  cancel(status: number = Status.cancelled): void {
    this.abortWith(new SparrowError(status, 'cancelled'), status);
  }

  /**
   * Resolves with the output: the Response value of a unary or client-stream
   * method, the token-0 bytes of a [4] output. For a stream output it waits
   * for End and resolves with undefined (items not read are dropped).
   */
  async result(): Promise<unknown> {
    return this.wrap(async (c) => {
      const out = c.method!.output;
      if (isStream(out)) {
        for (;;) {
          const r = await this.session.nextOutput(c);
          if (r.done) return undefined;
        }
      }
      if (isByteStream(out)) {
        const data = await this.session.bytesOf(c, 0);
        await this.session.finalOf(c);
        return data;
      }
      const raw = await this.session.finalOf(c);
      if (!raw) throw new SparrowError(Status.protocol_error, 'the call ended without a Response');
      return this.session.decodeOutput(c, raw);
    });
  }

  /** Collects the data of an output byte token. */
  bytes(token: number): Promise<Uint8Array> {
    return this.wrap((c) => this.session.bytesOf(c, token));
  }

  /** The output items; throws the callee's SparrowError if it answered with Error. */
  [Symbol.asyncIterator](): AsyncIterator<unknown> {
    let done = false;
    return {
      next: async () => {
        if (done) return { value: undefined, done: true };
        const r = await this.wrap((c) => this.session.nextOutput(c));
        if (r.done) done = true;
        return r;
      },
      return: async () => {
        if (!done) {
          done = true;
          const c = this.state;
          if (c && !c.calleeDone && !c.ended) this.cancel();
        }
        return { value: undefined, done: true };
      },
    };
  }
}
