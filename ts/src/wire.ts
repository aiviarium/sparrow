// The Sparrow wire format: QUIC varints and length-prefixed framing (4.1),
// the message envelope and kind ranges (3.3), typed messages for every kind
// of sections 5.4, 5.5 and 7.2, metadata and params maps, and credit
// accounting (7.4).
//
// Payload fields (input, output, value, details, schemas, deltas) stay
// encoded (Uint8Array views of the received message), so they can be decoded
// with the right schema type or forwarded byte for byte.

import {
  CborError,
  MAJOR_TEXT,
  MAJOR_NEG,
  MAJOR_UINT,
  Reader,
  Tag,
  TAG_EPOCH_TIME,
  Writer,
  decodeNext,
  validate,
  type DecodeOptions,
} from './cbor.js';
import { isCoreStatus } from './status.js';

// ---------------------------------------------------------------------------
// Varints and framing (4.1)
// ---------------------------------------------------------------------------

/** The largest value a QUIC varint holds (2^62 - 1). */
export const MAX_VARINT = (1n << 62n) - 1n;

/** Encodes v as the shortest QUIC variable-length integer (RFC 9000, 16). */
export function encodeVarint(v: number | bigint): Uint8Array {
  if (typeof v === 'number') {
    if (!Number.isInteger(v) || v < 0) throw new RangeError(`varint ${v} out of range`);
    if (v < 64) return Uint8Array.of(v);
    if (v < 16384) return Uint8Array.of(0x40 | (v >> 8), v & 0xff);
    if (v < 2 ** 30) return Uint8Array.of(0x80 | (v >>> 24), (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
    v = BigInt(v);
  }
  if (v < 0n || v > MAX_VARINT) throw new RangeError(`varint ${v} out of range`);
  if (v < 1n << 30n) return encodeVarint(Number(v));
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v);
  out[0] |= 0xc0;
  return out;
}

/** Decodes a varint in any valid (possibly non-minimal) form; null if b is too short. */
export function decodeVarint(b: Uint8Array, off = 0): { value: number | bigint; length: number } | null {
  if (off >= b.length) return null;
  const len = 1 << (b[off] >> 6);
  if (off + len > b.length) return null;
  if (len <= 4) {
    let v = b[off] & 0x3f;
    for (let i = 1; i < len; i++) v = v * 256 + b[off + i];
    return { value: v, length: len };
  }
  let v = BigInt(b[off] & 0x3f);
  for (let i = 1; i < 8; i++) v = (v << 8n) | BigInt(b[off + i]);
  return { value: v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v, length: 8 };
}

/** Returns msg preceded by its length as a shortest-form varint. */
export function frame(msg: Uint8Array): Uint8Array {
  const p = encodeVarint(msg.length);
  const out = new Uint8Array(p.length + msg.length);
  out.set(p);
  out.set(msg, p.length);
  return out;
}

/** A message longer than maxMessageSize (maps to message_too_large). */
export class TooLargeError extends Error {
  constructor(
    readonly size: number | bigint,
    readonly max: number,
  ) {
    super(`wire: message of ${size} bytes exceeds maxMessageSize ${max}`);
    this.name = 'TooLargeError';
  }
}

/** A malformed frame (an empty frame cannot hold a CBOR item). */
export class FramingError extends Error {
  constructor(message: string) {
    super(`wire: ${message}`);
    this.name = 'FramingError';
  }
}

/**
 * Splits a byte stream into length-prefixed messages. A message longer than
 * maxMessageSize is rejected from its prefix, before its body is buffered.
 */
export class FrameDecoder {
  private chunks: Uint8Array[] = [];
  private buffered = 0;
  maxMessageSize: number;

  constructor(maxMessageSize = DEFAULTS.maxMessageSize) {
    this.maxMessageSize = maxMessageSize;
  }

  /** Bytes received but not yet returned as a message. */
  get pending(): number {
    return this.buffered;
  }

  /**
   * A framing error found after the messages the last push returned: the
   * stream is unusable from there on. Deliver those messages, then fail.
   */
  error?: TooLargeError | FramingError;

  /**
   * Adds received bytes and returns the messages now complete. A bad frame
   * (TooLargeError, FramingError; the length is checked before any of the
   * body is buffered) is thrown at once when no message precedes it in this
   * push; otherwise the messages before it are returned and the error is
   * left in error (and thrown by every later push).
   */
  push(chunk: Uint8Array): Uint8Array[] {
    if (this.error) throw this.error;
    if (chunk.length) {
      this.chunks.push(chunk);
      this.buffered += chunk.length;
    }
    const out: Uint8Array[] = [];
    for (;;) {
      if (!this.buffered) break;
      const head = this.peek(Math.min(8, this.buffered));
      const v = decodeVarint(head);
      if (!v) break;
      const n = v.value;
      let bad: TooLargeError | FramingError | undefined;
      if (n === 0) bad = new FramingError('empty frame');
      else if (typeof n === 'bigint' || n > this.maxMessageSize) bad = new TooLargeError(n, this.maxMessageSize);
      if (bad) {
        this.error = bad;
        this.chunks = [];
        this.buffered = 0;
        if (!out.length) throw bad;
        break;
      }
      if (this.buffered < v.length + (n as number)) break;
      this.take(v.length);
      out.push(this.take(n as number));
    }
    return out;
  }

  private peek(n: number): Uint8Array {
    if (this.chunks[0].length >= n) return this.chunks[0].subarray(0, n);
    const out = new Uint8Array(n);
    let off = 0;
    for (const c of this.chunks) {
      const k = Math.min(c.length, n - off);
      out.set(c.subarray(0, k), off);
      off += k;
      if (off === n) break;
    }
    return out;
  }

  private take(n: number): Uint8Array {
    this.buffered -= n;
    const first = this.chunks[0];
    if (first.length > n) {
      this.chunks[0] = first.subarray(n);
      return first.subarray(0, n);
    }
    if (first.length === n) {
      this.chunks.shift();
      return first;
    }
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const c = this.chunks[0];
      const k = Math.min(c.length, n - off);
      out.set(c.subarray(0, k), off);
      off += k;
      if (k === c.length) this.chunks.shift();
      else this.chunks[0] = c.subarray(k);
    }
    return out;
  }
}

/** Stream header bytes (4.1); used by bindings with leased streams, not by pipe or WebSocket. */
export const HEADER_SHARED_LANE = 0x00;
export const HEADER_LEASED = 0x01;

export type Role = 'client' | 'server';

/**
 * Classifies a stream header byte (4.1): 0x00 opens the shared lane (only
 * from the client, only once), 0x01 a leased stream, 0x40-0x7F are reserved
 * for profiles, anything else is a protocol_error.
 */
export function classifyStreamHeader(
  b: number,
  opener: Role,
  sharedLaneOpen: boolean,
): 'shared_lane' | 'leased_stream' | 'profile_reserved' | 'protocol_error' {
  if (b === HEADER_SHARED_LANE) return opener === 'client' && !sharedLaneOpen ? 'shared_lane' : 'protocol_error';
  if (b === HEADER_LEASED) return 'leased_stream';
  if (b >= 0x40 && b <= 0x7f) return 'profile_reserved';
  return 'protocol_error';
}

// ---------------------------------------------------------------------------
// Kinds (3.3)
// ---------------------------------------------------------------------------

export const Kind = {
  Hello: 0,
  Welcome: 1,
  Ready: 2,
  SchemaUpdate: 3,
  SchemaAck: 4,
  AuthRefresh: 5,
  AuthStatus: 6,
  Ping: 7,
  Pong: 8,
  GoAway: 9,
  Request: 16,
  Response: 17,
  Item: 18,
  End: 19,
  Error: 20,
  Progress: 21,
  Headers: 22,
  Cancel: 23,
  Credit: 24,
  Bytes: 25,
} as const;

export type KindName = keyof typeof Kind;

const KIND_NAMES = new Map<number, KindName>(Object.entries(Kind).map(([k, v]) => [v, k as KindName]));

/** The name of a kind this revision defines. */
export function kindName(kind: number): KindName | undefined {
  return KIND_NAMES.get(kind);
}

/** Reports whether a kind is a call message (16-25), whose second element is a call ID. */
export function isCallKind(kind: number): boolean {
  return kind >= 16 && kind <= 25;
}

/**
 * Who owns a range of kinds and what a receiver does with an unknown one
 * (3.3): 0-47 core / close, 48-63 core / ignore, 64-111 profile / close,
 * 112-127 profile / ignore, 128 and up invalid / close.
 */
export function kindRange(kind: number): { owner: 'core' | 'profile' | 'invalid'; action: 'close_protocol_error' | 'ignore' } {
  if (kind <= 47) return { owner: 'core', action: 'close_protocol_error' };
  if (kind <= 63) return { owner: 'core', action: 'ignore' };
  if (kind <= 111) return { owner: 'profile', action: 'close_protocol_error' };
  if (kind <= 127) return { owner: 'profile', action: 'ignore' };
  return { owner: 'invalid', action: 'close_protocol_error' };
}

// ---------------------------------------------------------------------------
// Params (5.4)
// ---------------------------------------------------------------------------

/** Limits with defaults applied. */
export interface Limits {
  maxMessageSize: number;
  maxInlineBytes: number;
  maxConcurrentCalls: number;
  maxStreams: number;
  sharedCredit: number;
  leaseCredit: number;
  idleTimeoutMs: number;
}

export const PARAM_KEYS = [
  'maxMessageSize',
  'maxInlineBytes',
  'maxConcurrentCalls',
  'maxStreams',
  'sharedCredit',
  'leaseCredit',
  'idleTimeoutMs',
] as const;

export type ParamKey = (typeof PARAM_KEYS)[number];

/** A params map as sent: known keys hold uints, unknown keys are kept and ignored. */
export type Params = { [K in ParamKey]?: number } & { [extra: string]: unknown };

/** Defaults (4.1, 5.4); maxStreams is 16 in Welcome and 4 in Hello. */
export const DEFAULTS = {
  maxMessageSize: 1 << 20,
  maxInlineBytes: 64 << 10,
  maxConcurrentCalls: 100,
  maxStreamsInWelcome: 16,
  maxStreamsInHello: 4,
  sharedCredit: 64 << 10,
  leaseCredit: 1 << 20,
  idleTimeoutMs: 30000,
} as const;

/** Minimums a received params map must respect (5.4). */
export const PARAM_MINIMUMS: Partial<Record<ParamKey, number>> = {
  maxMessageSize: 16384,
  maxInlineBytes: 16384,
  sharedCredit: 16384,
  leaseCredit: 16384,
  maxConcurrentCalls: 1,
};

/** The default limits for params sent by a role (Hello by the client, Welcome by the server). */
export function defaultLimits(sender: Role): Limits {
  return {
    maxMessageSize: DEFAULTS.maxMessageSize,
    maxInlineBytes: DEFAULTS.maxInlineBytes,
    maxConcurrentCalls: DEFAULTS.maxConcurrentCalls,
    maxStreams: sender === 'client' ? DEFAULTS.maxStreamsInHello : DEFAULTS.maxStreamsInWelcome,
    sharedCredit: DEFAULTS.sharedCredit,
    leaseCredit: DEFAULTS.leaseCredit,
    idleTimeoutMs: DEFAULTS.idleTimeoutMs,
  };
}

/** Applies the defaults for params sent by a role. */
export function limitsOf(p: Params, sender: Role): Limits {
  const l = defaultLimits(sender);
  for (const k of PARAM_KEYS) {
    const v = p[k];
    if (typeof v === 'number') l[k] = v;
  }
  return l;
}

/** Reports whether any limit is below its default (5.3: no optimistic start then). */
export function belowDefaults(l: Limits, sender: Role): boolean {
  const d = defaultLimits(sender);
  return PARAM_KEYS.some((k) => l[k] < d[k]);
}

/** A received params value below its minimum; the receiver sends GoAway(invalid_argument). */
export class ParamError extends Error {
  constructor(
    readonly key: string,
    readonly value: number,
    readonly min: number,
  ) {
    super(`wire: params ${key} = ${value} is below the minimum ${min}`);
    this.name = 'ParamError';
  }
}

/** Checks received params against the minimums of 5.4, returning the first offending key in spec order. */
export function checkParams(p: Params): ParamError | null {
  for (const k of PARAM_KEYS) {
    const min = PARAM_MINIMUMS[k];
    const v = p[k];
    if (min !== undefined && typeof v === 'number' && v < min) return new ParamError(k, v, min);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Metadata (7.2)
// ---------------------------------------------------------------------------

/** A metadata or trailers key: a sigil (uint) or a text string. */
export type MetaKey = number | bigint | string;

/** Metadata or trailers, {* symbol => any}, with values in the generic CBOR representation. */
export type Metadata = Map<MetaKey, unknown>;

/** Core metadata keys (7.2). */
export const MetaKeys = {
  deadline: 32,
  trace: 33,
  reserved: 34,
  credit: 35,
  context: 36,
  principal: 37,
} as const;

function metaUint(md: Metadata | null | undefined, k: number): number | undefined {
  const v = md?.get(k);
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === 'bigint' && v >= 0n) return Number.MAX_SAFE_INTEGER;
  return undefined;
}

/** The deadline key in milliseconds, if present and a uint. */
export function metaDeadline(md: Metadata | null | undefined): number | undefined {
  return metaUint(md, MetaKeys.deadline);
}

/** The credit key in bytes, if present and a uint. */
export function metaCredit(md: Metadata | null | undefined): number | undefined {
  return metaUint(md, MetaKeys.credit);
}

/** The principal key (Hub Profile), if present and a string. */
export function metaPrincipal(md: Metadata | null | undefined): string | undefined {
  const v = md?.get(MetaKeys.principal);
  return typeof v === 'string' ? v : undefined;
}

/** The call context key (Hub Profile), if present and bytes. */
export function metaContext(md: Metadata | null | undefined): Uint8Array | undefined {
  const v = md?.get(MetaKeys.context);
  return v instanceof Uint8Array ? v : undefined;
}

// ---------------------------------------------------------------------------
// Messages (5.4, 5.5, 7.2)
// ---------------------------------------------------------------------------

export type Int = number | bigint;

/** auth = [scheme, credentials]. */
export interface Auth {
  scheme: string;
  credentials: unknown;
}

/** A text-keyed map such as caps or props, values in the generic CBOR representation. */
export type TextMap = Record<string, unknown>;

export type SchemaOffer =
  | { form: 0; hash: Uint8Array }
  | { form: 1; hash: Uint8Array; from: Uint8Array; delta: Uint8Array }
  | { form: 2; hash: Uint8Array; schema: Uint8Array }
  | { form: 3; hash: Uint8Array; location: string };

export interface Hello {
  kind: 0;
  versions: number[];
  caps: TextMap;
  auth: Auth | null;
  knownSchema: Uint8Array | null;
  /** [2, hash, schema]: the client's schema, inline (schema still encoded). */
  clientSchema: { hash: Uint8Array; schema: Uint8Array } | null;
  params: Params;
  optimistic: boolean;
}
export interface Welcome {
  kind: 1;
  version: number;
  caps: TextMap;
  sessionId: Uint8Array;
  props: TextMap;
  serverSchema: SchemaOffer;
  params: Params;
}
export interface Ready {
  kind: 2;
  schemaHash: Uint8Array;
}
export interface SchemaUpdate {
  kind: 3;
  epoch: number;
  hash: Uint8Array;
  delta: Uint8Array;
}
export interface SchemaAck {
  kind: 4;
  epoch: number;
}
export interface AuthRefresh {
  kind: 5;
  auth: Auth;
}
export interface AuthStatus {
  kind: 6;
  status: number;
  /** Epoch seconds (tag 1), or null. */
  expiresAt: number | null;
}
export interface Ping {
  kind: 7;
  nonce: Int;
}
export interface Pong {
  kind: 8;
  nonce: Int;
}
export interface GoAway {
  kind: 9;
  status: number;
  reason: string;
  retryAfterMs: number | null;
  versions: number[] | null;
}
export interface Request {
  kind: 16;
  callId: number;
  facetId: number;
  methodId: number;
  metadata: Metadata;
  input: Uint8Array;
}
export interface Response {
  kind: 17;
  callId: number;
  output: Uint8Array;
}
export interface Item {
  kind: 18;
  callId: number;
  value: Uint8Array;
}
export interface End {
  kind: 19;
  callId: number;
  trailers: Metadata;
}
export interface ErrorMsg {
  kind: 20;
  callId: number;
  status: number;
  message: string;
  details: Uint8Array | null;
}
export interface Progress {
  kind: 21;
  callId: number;
  done: number;
  total: number | null;
  note: string | null;
}
export interface Headers {
  kind: 22;
  callId: number;
  metadata: Metadata;
}
export interface Cancel {
  kind: 23;
  callId: number;
  status: number;
}
export interface Credit {
  kind: 24;
  callId: number;
  amount: number;
}
export interface BytesMsg {
  kind: 25;
  callId: number;
  token: number;
  data: Uint8Array;
  fin: boolean;
}

export type CallMessage = Request | Response | Item | End | ErrorMsg | Progress | Headers | Cancel | Credit | BytesMsg;
export type Message =
  | Hello
  | Welcome
  | Ready
  | SchemaUpdate
  | SchemaAck
  | AuthRefresh
  | AuthStatus
  | Ping
  | Pong
  | GoAway
  | CallMessage;

/** The encoded CBOR of null, the input of a Request for a stream or byte-stream input. */
export const NULL_ITEM = Uint8Array.of(0xf6);

function textMap(w: Writer, m: TextMap | null | undefined): void {
  w.value(m ?? {});
}

function metadata(w: Writer, m: Metadata | null | undefined): void {
  w.map(m ? m.entries() : [], m ? m.size : 0);
}

function uints(w: Writer, xs: number[]): void {
  w.arrayHead(xs.length);
  for (const x of xs) w.uint(x);
}

function auth(w: Writer, a: Auth): void {
  w.arrayHead(2);
  w.text(a.scheme);
  w.value(a.credentials);
}

function params(w: Writer, p: Params | null | undefined): void {
  const e = Object.entries(p ?? {}).filter(([, v]) => v !== undefined);
  w.map(e, e.length);
}

function timeSeconds(w: Writer, t: number): void {
  w.tag(TAG_EPOCH_TIME);
  if (Number.isInteger(t)) w.int(t);
  else w.float(t);
}

/** Encodes a message. */
export function encodeMessage(m: Message): Uint8Array {
  const w = new Writer(32);
  writeMessage(w, m);
  return w.finish();
}

/** Encodes a message into a writer. */
export function writeMessage(w: Writer, m: Message): void {
  switch (m.kind) {
    case 0:
      w.arrayHead(8);
      w.uint(0);
      uints(w, m.versions);
      textMap(w, m.caps);
      if (m.auth) auth(w, m.auth);
      else w.null();
      if (m.knownSchema) w.byteString(m.knownSchema);
      else w.null();
      if (m.clientSchema) {
        w.arrayHead(3);
        w.uint(2);
        w.byteString(m.clientSchema.hash);
        w.bytes(m.clientSchema.schema);
      } else w.null();
      params(w, m.params);
      w.bool(m.optimistic);
      return;
    case 1: {
      w.arrayHead(7);
      w.uint(1);
      w.uint(m.version);
      textMap(w, m.caps);
      w.byteString(m.sessionId);
      textMap(w, m.props);
      const o = m.serverSchema;
      switch (o.form) {
        case 0:
          w.arrayHead(2);
          w.uint(0);
          w.byteString(o.hash);
          break;
        case 1:
          w.arrayHead(4);
          w.uint(1);
          w.byteString(o.hash);
          w.byteString(o.from);
          w.bytes(o.delta);
          break;
        case 2:
          w.arrayHead(3);
          w.uint(2);
          w.byteString(o.hash);
          w.bytes(o.schema);
          break;
        case 3:
          w.arrayHead(3);
          w.uint(3);
          w.byteString(o.hash);
          w.text(o.location);
          break;
      }
      params(w, m.params);
      return;
    }
    case 2:
      w.arrayHead(2);
      w.uint(2);
      w.byteString(m.schemaHash);
      return;
    case 3:
      w.arrayHead(4);
      w.uint(3);
      w.uint(m.epoch);
      w.byteString(m.hash);
      w.bytes(m.delta);
      return;
    case 4:
      w.arrayHead(2);
      w.uint(4);
      w.uint(m.epoch);
      return;
    case 5:
      w.arrayHead(2);
      w.uint(5);
      auth(w, m.auth);
      return;
    case 6:
      w.arrayHead(3);
      w.uint(6);
      w.uint(m.status);
      if (m.expiresAt === null) w.null();
      else timeSeconds(w, m.expiresAt);
      return;
    case 7:
    case 8:
      w.arrayHead(2);
      w.uint(m.kind);
      w.uint(m.nonce);
      return;
    case 9:
      w.arrayHead(5);
      w.uint(9);
      w.uint(m.status);
      w.text(m.reason);
      if (m.retryAfterMs === null) w.null();
      else w.uint(m.retryAfterMs);
      if (m.versions === null) w.null();
      else uints(w, m.versions);
      return;
    case 16:
      w.arrayHead(6);
      w.uint(16);
      w.uint(m.callId);
      w.uint(m.facetId);
      w.uint(m.methodId);
      metadata(w, m.metadata);
      w.bytes(m.input);
      return;
    case 17:
      w.arrayHead(3);
      w.uint(17);
      w.uint(m.callId);
      w.bytes(m.output);
      return;
    case 18:
      w.arrayHead(3);
      w.uint(18);
      w.uint(m.callId);
      w.bytes(m.value);
      return;
    case 19:
    case 22:
      w.arrayHead(3);
      w.uint(m.kind);
      w.uint(m.callId);
      metadata(w, m.kind === 19 ? m.trailers : m.metadata);
      return;
    case 20:
      w.arrayHead(5);
      w.uint(20);
      w.uint(m.callId);
      w.uint(m.status);
      w.text(m.message);
      if (m.details) w.bytes(m.details);
      else w.null();
      return;
    case 21:
      w.arrayHead(5);
      w.uint(21);
      w.uint(m.callId);
      w.uint(m.done);
      if (m.total === null) w.null();
      else w.uint(m.total);
      if (m.note === null) w.null();
      else w.text(m.note);
      return;
    case 23:
    case 24:
      w.arrayHead(3);
      w.uint(m.kind);
      w.uint(m.callId);
      w.uint(m.kind === 23 ? m.status : m.amount);
      return;
    case 25:
      w.arrayHead(5);
      w.uint(25);
      w.uint(m.callId);
      w.uint(m.token);
      w.byteString(m.data);
      w.bool(m.fin);
      return;
  }
  throw new Error(`wire: cannot encode kind ${(m as { kind: number }).kind}`);
}

/** A malformed message; maps to protocol_error. */
export class DecodeError extends Error {
  constructor(
    message: string,
    readonly kind?: number,
  ) {
    super(kind === undefined ? `wire: malformed message: ${message}` : `wire: malformed ${kindName(kind) ?? kind}: ${message}`);
    this.name = 'DecodeError';
  }
}

/** A message of a kind this revision does not define; action says what to do (3.3). */
export class UnknownKindError extends Error {
  readonly owner: 'core' | 'profile' | 'invalid';
  readonly action: 'close_protocol_error' | 'ignore';
  constructor(readonly kind: number | bigint) {
    const r = kindRange(typeof kind === 'bigint' ? 1000 : kind);
    super(`wire: unknown message kind ${kind} (${r.owner} range, ${r.action})`);
    this.name = 'UnknownKindError';
    this.owner = r.owner;
    this.action = r.action;
  }
}

const ARITY: Record<number, number> = {
  0: 8,
  1: 7,
  2: 2,
  3: 4,
  4: 2,
  5: 2,
  6: 3,
  7: 2,
  8: 2,
  9: 5,
  16: 6,
  17: 3,
  18: 3,
  19: 3,
  20: 5,
  21: 5,
  22: 3,
  23: 3,
  24: 3,
  25: 5,
};

class Fields {
  constructor(
    readonly r: Reader,
    readonly cbor: DecodeOptions,
  ) {}
  uint(): number {
    return this.r.uintNumber();
  }
  /** A uint clamped to Number.MAX_SAFE_INTEGER (credit amounts, progress counts). */
  uintClamped(): number {
    const v = this.r.uint();
    return typeof v === 'bigint' ? Number.MAX_SAFE_INTEGER : v;
  }
  coreStatus(): number {
    const v = this.uint();
    if (!isCoreStatus(v)) throw new CborError(`${v} is not a core status code`);
    return v;
  }
  nullable<T>(f: () => T): T | null {
    if (this.r.peekNull()) {
      this.r.null();
      return null;
    }
    return f();
  }
  generic(): unknown {
    return decodeNext(this.r, this.cbor, 2);
  }
  uints(nonEmpty: boolean): number[] {
    const n = this.r.arrayHead();
    if (nonEmpty && n === 0) throw new CborError('must not be empty');
    const out: number[] = [];
    for (let i = 0; i < n; i++) out.push(this.uint());
    return out;
  }
  textMap(): TextMap {
    const n = this.r.mapHead();
    const out: TextMap = {};
    for (let i = 0; i < n; i++) {
      const k = this.r.text();
      Object.defineProperty(out, k, { value: this.generic(), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  params(): Params {
    const m = this.textMap();
    for (const k of PARAM_KEYS) {
      if (!(k in m)) continue;
      const v = m[k];
      if (typeof v === 'bigint' && v >= 0n) m[k] = Number.MAX_SAFE_INTEGER;
      else if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) throw new CborError(`params ${k} must be a uint`);
    }
    return m as Params;
  }
  metadata(): Metadata {
    const n = this.r.mapHead();
    const out: Metadata = new Map();
    for (let i = 0; i < n; i++) {
      const maj = this.r.peekMajor();
      let k: MetaKey;
      if (maj === MAJOR_UINT) k = this.r.uint();
      else if (maj === MAJOR_TEXT) k = this.r.text();
      else throw new CborError('metadata key is not a symbol', this.r.off);
      out.set(k, this.generic());
    }
    return out;
  }
  auth(): Auth {
    const n = this.r.arrayHead();
    if (n !== 2) throw new CborError(`auth has ${n} elements, want 2`);
    return { scheme: this.r.text(), credentials: this.generic() };
  }
  time(): number {
    const t = this.r.tag();
    if (t !== TAG_EPOCH_TIME) throw new CborError('expected tag 1');
    const m = this.r.peekMajor();
    if (m === MAJOR_UINT || m === MAJOR_NEG) {
      // Integer seconds are held as a number: beyond 2^53 - 1 they would change.
      const at = this.r.off;
      const v = this.r.int();
      if (typeof v === 'bigint') throw new CborError(`integer ${v} is too large`, at);
      return v;
    }
    return this.r.float();
  }
  offer(): SchemaOffer {
    const n = this.r.arrayHead();
    if (n === 0) throw new CborError('empty schema offer');
    const form = this.uint();
    const want = [2, 4, 3, 3][form];
    if (want === undefined) throw new CborError(`unknown schema offer ${form}`);
    if (n !== want) throw new CborError(`offer ${form} has ${n} elements, want ${want}`);
    const hash = this.r.bytes();
    switch (form) {
      case 0:
        return { form: 0, hash };
      case 1:
        return { form: 1, hash, from: this.r.bytes(), delta: this.r.raw() };
      case 2:
        return { form: 2, hash, schema: this.r.raw() };
      default:
        return { form: 3, hash, location: this.r.text() };
    }
  }
}

/**
 * Decodes one message, validating it against 3.1 first. Payload fields are
 * views into b. Throws DecodeError or UnknownKindError.
 */
export function decodeMessage(b: Uint8Array, o: DecodeOptions = {}): Message {
  try {
    validate(b, o);
  } catch (e) {
    throw new DecodeError((e as Error).message);
  }
  const r = new Reader(b);
  let n: number;
  let kind: number | bigint;
  try {
    n = r.arrayHead();
    if (n === 0) throw new CborError('empty envelope');
    kind = r.uint();
  } catch (e) {
    throw new DecodeError((e as Error).message);
  }
  if (typeof kind === 'bigint' || ARITY[kind] === undefined) throw new UnknownKindError(kind);
  if (n !== ARITY[kind]) throw new DecodeError(`envelope has ${n} elements, want ${ARITY[kind]}`, kind);
  const f = new Fields(r, o);
  try {
    return fields(kind, f);
  } catch (e) {
    throw new DecodeError((e as Error).message, kind);
  }
}

function fields(kind: number, f: Fields): Message {
  const r = f.r;
  switch (kind) {
    case 0:
      return {
        kind: 0,
        versions: f.uints(true),
        caps: f.textMap(),
        auth: f.nullable(() => f.auth()),
        knownSchema: f.nullable(() => r.bytes()),
        clientSchema: f.nullable(() => {
          const n = r.arrayHead();
          if (n !== 3) throw new CborError(`client_schema has ${n} elements, want 3`);
          const form = f.uint();
          if (form !== 2) throw new CborError(`client_schema form ${form}, want 2 (inline)`);
          return { hash: r.bytes(), schema: r.raw() };
        }),
        params: f.params(),
        optimistic: r.bool(),
      };
    case 1:
      return {
        kind: 1,
        version: f.uint(),
        caps: f.textMap(),
        sessionId: r.bytes(),
        props: f.textMap(),
        serverSchema: f.offer(),
        params: f.params(),
      };
    case 2:
      return { kind: 2, schemaHash: r.bytes() };
    case 3:
      return { kind: 3, epoch: f.uint(), hash: r.bytes(), delta: r.raw() };
    case 4:
      return { kind: 4, epoch: f.uint() };
    case 5:
      return { kind: 5, auth: f.auth() };
    case 6:
      return { kind: 6, status: f.coreStatus(), expiresAt: f.nullable(() => f.time()) };
    case 7:
    case 8:
      return { kind, nonce: r.uint() } as Ping | Pong;
    case 9:
      return {
        kind: 9,
        status: f.coreStatus(),
        reason: r.text(),
        retryAfterMs: f.nullable(() => f.uintClamped()),
        versions: f.nullable(() => f.uints(false)),
      };
    case 16:
      return { kind: 16, callId: f.uint(), facetId: f.uint(), methodId: f.uint(), metadata: f.metadata(), input: r.raw() };
    case 17:
      return { kind: 17, callId: f.uint(), output: r.raw() };
    case 18:
      return { kind: 18, callId: f.uint(), value: r.raw() };
    case 19:
      return { kind: 19, callId: f.uint(), trailers: f.metadata() };
    case 20:
      return {
        kind: 20,
        callId: f.uint(),
        status: f.uint(),
        message: r.text(),
        details: f.nullable(() => r.raw()),
      };
    case 21:
      return {
        kind: 21,
        callId: f.uint(),
        done: f.uintClamped(),
        total: f.nullable(() => f.uintClamped()),
        note: f.nullable(() => r.text()),
      };
    case 22:
      return { kind: 22, callId: f.uint(), metadata: f.metadata() };
    case 23:
      return { kind: 23, callId: f.uint(), status: f.coreStatus() };
    case 24:
      return { kind: 24, callId: f.uint(), amount: f.uintClamped() };
    case 25:
      return { kind: 25, callId: f.uint(), token: f.uint(), data: r.bytes(), fin: r.bool() };
  }
  throw new UnknownKindError(kind);
}

/** The tag-1 value of a timestamp in seconds, as the generic representation holds it. */
export function epochTag(seconds: number): Tag {
  return new Tag(TAG_EPOCH_TIME, seconds);
}

/** The ID of call notifications. */
export const NOTIFICATION_ID = 0;

/** The role that assigns a call ID: client IDs are even, server IDs odd (7.1). */
export function callerOf(callId: number): Role {
  return callId % 2 === 0 ? 'client' : 'server';
}

// ---------------------------------------------------------------------------
// Credit (7.4)
// ---------------------------------------------------------------------------

/**
 * The bytes a message counts against its call direction's credit: an Item or
 * Progress counts the length of its whole encoding (without the length
 * prefix), a Bytes message the length of its data, every other message 0.
 */
export function countedBytes(m: Message, encodedLength: number): number {
  if (m.kind === 18 || m.kind === 21) return encodedLength;
  if (m.kind === 25) return m.data.length;
  return 0;
}

/** The credit one direction of a call starts with (7.4). */
export function initialCredit(receiver: Limits, leased: boolean, override?: number): number {
  if (override !== undefined) return override;
  return leased ? receiver.leaseCredit : receiver.sharedCredit;
}

/**
 * The credit of one direction of one call. The same arithmetic runs on both
 * sides: the sender decides when it may send, the receiver detects
 * violations. A message may be sent whenever the remaining credit is above
 * zero, even if it is larger; the credit then goes negative.
 */
export class CreditWindow {
  remaining: number;
  constructor(initial: number) {
    this.remaining = Math.min(initial, Number.MAX_SAFE_INTEGER);
  }
  /** Whether a message counting n bytes may be sent now (n = 0 is never held back). */
  canSend(n: number): boolean {
    return n === 0 || this.remaining > 0;
  }
  /** Accounts for n counted bytes; false (window unchanged) if no credit is left. */
  consume(n: number): boolean {
    if (n === 0) return true;
    if (this.remaining <= 0) return false;
    this.remaining -= n;
    return true;
  }
  grant(n: number): void {
    this.remaining = Math.min(this.remaining + n, Number.MAX_SAFE_INTEGER);
  }
}
