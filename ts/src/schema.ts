// The Sparrow facet model (spec section 6): types for schemas, facets, type
// definitions, services, methods, sigils and interfaces; their CBOR codec;
// canonical form and hashes (6.6); validation (6.1-6.6); the compatibility
// check between versions of a facet (6.7); interface conformance on wire
// shapes (6.5); deltas and per-session schema state (6.6); the built-in facet
// 1, sparrow.web (9.4); and a facet builder.

import { CborError, bytesEqual, containsFloat, decode, encode, stripSelfDescribed, type DecodeOptions } from './cbor.js';
import { sha256 } from './sha256.js';

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

export const SCHEMA_FORMAT = 2;

/** Built-in TypeIds (6.3). */
export const T = {
  unit: 0,
  bool: 1,
  int: 2,
  uint: 3,
  float32: 4,
  float64: 5,
  string: 6,
  bytes: 7,
  timestamp: 8,
  uuid: 9,
  dynamic: 10,
  symbol: 11,
} as const;

export const BUILTIN_NAMES = Object.keys(T) as (keyof typeof T)[];
export const MAX_BUILTIN_TYPE = 11;
export const FIRST_FREE_TYPE_ID = 64;
export const FIRST_FREE_SIGIL = 64;
export const FIRST_FREE_FACET_ID = 16;
export const WEB_FACET_ID = 1;
export const WEB_FACET_NAME = 'sparrow.web';

/**
 * A type reference (6.3), in its wire shape: a TypeId, [0, T] list,
 * [1, K, V] map, [2, T] optional, [3, T] stream (only as a method's whole
 * input or output) or [4] byte stream.
 */
export type TypeRef = number | [0, TypeRef] | [1, TypeRef, TypeRef] | [2, TypeRef] | [3, TypeRef] | [4];

/** Type reference constructors. */
export const list = (t: TypeRef): TypeRef => [0, t];
export const mapOf = (k: TypeRef, v: TypeRef): TypeRef => [1, k, v];
export const optional = (t: TypeRef): TypeRef => [2, t];
export const stream = (t: TypeRef): TypeRef => [3, t];
export const byteStream = (): TypeRef => [4];

/** Reports whether a reference is [3, T]. */
export function isStream(t: TypeRef): t is [3, TypeRef] {
  return Array.isArray(t) && t[0] === 3;
}

/** Reports whether a reference is [4]. */
export function isByteStream(t: TypeRef): t is [4] {
  return Array.isArray(t) && t[0] === 4;
}

/** Profile-defined metadata, {* tstr => any}; values in the generic CBOR representation. */
export type Annotations = Record<string, unknown>;

export const FieldFlags = { optional: 0x1, deprecated: 0x2, removed: 0x4 } as const;
export const StructFlags = { sparse: 0x1 } as const;
export const MethodFlags = { idempotent: 0x1, notification: 0x2, shared: 0x4, inputEnds: 0x8, outputEnds: 0x10 } as const;
export const SigilKind = { enumValue: 0, error: 1, symbol: 2 } as const;
/** ID spaces of `retired` entries and conformance mismatches. */
export const Space = { type: 0, service: 1, method: 2, sigil: 3 } as const;

/** A struct field or union variant: [tag, name, type, flags, annotations]. */
export interface Field {
  tag: number;
  name: string;
  type: TypeRef;
  flags: number;
  annotations: Annotations;
}

export interface StructDef {
  kind: 'struct';
  id: number;
  name: string;
  fields: Field[];
  /** 0x1 sparse. */
  flags: number;
  annotations: Annotations;
}
export interface EnumDef {
  kind: 'enum';
  id: number;
  name: string;
  /** Sigil IDs of the values. */
  values: number[];
  annotations: Annotations;
}
export interface UnionDef {
  kind: 'union';
  id: number;
  name: string;
  variants: Field[];
  annotations: Annotations;
}
export interface AliasDef {
  kind: 'alias';
  id: number;
  name: string;
  target: TypeRef;
  annotations: Annotations;
}
export type TypeDef = StructDef | EnumDef | UnionDef | AliasDef;

const KIND_CODES = { struct: 0, enum: 1, union: 2, alias: 3 } as const;
const KIND_BY_CODE = ['struct', 'enum', 'union', 'alias'] as const;

/** [id, name, input, output, errors, flags, annotations]. */
export interface Method {
  id: number;
  name: string;
  input: TypeRef;
  output: TypeRef;
  errors: number[];
  flags: number;
  annotations: Annotations;
}

export interface Service {
  id: number;
  name: string;
  methods: Method[];
  annotations: Annotations;
}

export interface Sigil {
  id: number;
  name: string;
  /** 0 enum value, 1 error code, 2 symbol. */
  kind: number;
  annotations: Annotations;
}

export interface Facet {
  id: number;
  name: string;
  version: string;
  types: TypeDef[];
  services: Service[];
  sigils: Sigil[];
  /** Hash of the interface this facet implements, or null. */
  implements: Uint8Array | null;
  /** [space, id] entries. */
  retired: [number, number][];
  annotations: Annotations;
}

export interface Interface {
  name: string;
  version: string;
  types: TypeDef[];
  services: Service[];
  sigils: Sigil[];
}

export interface Schema {
  format: number;
  name: string;
  version: string;
  facets: Facet[];
  annotations: Annotations;
}

export type DeltaOp =
  | { op: 'put'; facet: Facet }
  | { op: 'remove'; facetId: number }
  | { op: 'annotations'; annotations: Annotations }
  | { op: 'version'; version: string };
export type Delta = DeltaOp[];

/** The members of a struct or union, or [] for other kinds. */
export function members(t: TypeDef): Field[] {
  return t.kind === 'struct' ? t.fields : t.kind === 'union' ? t.variants : [];
}

export function isSparse(t: TypeDef): boolean {
  return t.kind === 'struct' && (t.flags & StructFlags.sparse) !== 0;
}

export function isRemoved(f: Field): boolean {
  return (f.flags & FieldFlags.removed) !== 0;
}

export function isOptional(f: Field): boolean {
  return (f.flags & FieldFlags.optional) !== 0;
}

/** Finds a method by ID in any service of the facet. */
export function findMethod(f: Facet, id: number): { method: Method; service: Service } | undefined {
  for (const s of f.services) for (const m of s.methods) if (m.id === id) return { method: m, service: s };
  return undefined;
}

/**
 * Finds a method by name: "method" or "Service.method". Throws if a bare
 * name is ambiguous.
 */
export function findMethodByName(f: Facet, name: string): { method: Method; service: Service } | undefined {
  let found: { method: Method; service: Service } | undefined;
  for (const s of f.services) {
    for (const m of s.methods) {
      if (`${s.name}.${m.name}` === name) return { method: m, service: s };
      if (m.name === name) {
        if (found) throw new Error(`schema: method name ${JSON.stringify(name)} is ambiguous in facet ${f.name}`);
        found = { method: m, service: s };
      }
    }
  }
  return found;
}

export function findType(f: { types: TypeDef[] }, id: number): TypeDef | undefined {
  return f.types.find((t) => t.id === id);
}

export function findSigil(f: { sigils: Sigil[] }, id: number): Sigil | undefined {
  return f.sigils.find((s) => s.id === id);
}

export function typeIndex(types: TypeDef[]): Map<number, TypeDef> {
  return new Map(types.map((t) => [t.id, t]));
}

/** The major version: the first number of version, 0 included (6.7). */
export function major(version: string): string {
  const i = version.indexOf('.');
  return i < 0 ? version : version.slice(0, i);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** A schema error. code is a stable identifier (the test vectors' vocabulary). */
export class SchemaError extends Error {
  constructor(
    readonly code: string,
    readonly detail: string,
  ) {
    super(`schema: ${code}: ${detail}`);
    this.name = 'SchemaError';
  }
}

const err = (code: string, detail: string) => new SchemaError(code, detail);

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

function annotationsTree(a: Annotations | undefined | null): Map<string, unknown> {
  return new Map(Object.entries(a ?? {}));
}

export function typeRefTree(t: TypeRef): unknown {
  if (typeof t === 'number') return t;
  if (!Array.isArray(t)) throw err('bad_type_ref', `not a type reference: ${String(t)}`);
  switch (t[0]) {
    case 0:
    case 2:
    case 3:
      return [t[0], typeRefTree(t[1])];
    case 1:
      return [1, typeRefTree(t[1]), typeRefTree(t[2])];
    case 4:
      return [4];
  }
  throw err('bad_type_ref', `unknown type-ref form ${(t as unknown[])[0]}`);
}

function fieldTree(f: Field): unknown {
  return [f.tag, f.name, typeRefTree(f.type), f.flags, annotationsTree(f.annotations)];
}

function typeDefTree(t: TypeDef): unknown {
  const k = KIND_CODES[t.kind];
  switch (t.kind) {
    case 'struct':
      return [k, t.id, t.name, t.fields.map(fieldTree), t.flags, annotationsTree(t.annotations)];
    case 'enum':
      return [k, t.id, t.name, [...t.values], annotationsTree(t.annotations)];
    case 'union':
      return [k, t.id, t.name, t.variants.map(fieldTree), annotationsTree(t.annotations)];
    case 'alias':
      return [k, t.id, t.name, typeRefTree(t.target), annotationsTree(t.annotations)];
  }
  throw err('malformed', `unknown type-def kind ${(t as { kind: string }).kind}`);
}

function methodTree(m: Method): unknown {
  return [m.id, m.name, typeRefTree(m.input), typeRefTree(m.output), [...m.errors], m.flags, annotationsTree(m.annotations)];
}

function serviceTree(s: Service): unknown {
  return [s.id, s.name, s.methods.map(methodTree), annotationsTree(s.annotations)];
}

function sigilTree(s: Sigil): unknown {
  return [s.id, s.name, s.kind, annotationsTree(s.annotations)];
}

export function facetTree(f: Facet): unknown {
  return [
    f.id,
    f.name,
    f.version,
    f.types.map(typeDefTree),
    f.services.map(serviceTree),
    f.sigils.map(sigilTree),
    f.implements ?? null,
    f.retired.map(([s, id]) => [s, id]),
    annotationsTree(f.annotations),
  ];
}

export function interfaceTree(i: Interface): unknown {
  return [i.name, i.version, i.types.map(typeDefTree), i.services.map(serviceTree), i.sigils.map(sigilTree)];
}

export function schemaTree(s: Schema): unknown {
  return [s.format, s.name, s.version, s.facets.map(facetTree), annotationsTree(s.annotations)];
}

export function deltaTree(d: Delta): unknown {
  return d.map((op) => {
    switch (op.op) {
      case 'put':
        return [0, facetTree(op.facet)];
      case 'remove':
        return [1, op.facetId];
      case 'annotations':
        return [2, annotationsTree(op.annotations)];
      case 'version':
        return [3, op.version];
    }
    throw err('unknown_delta_op', `delta op ${(op as { op: string }).op}`);
  });
}

/** Encodes a schema as it is (list order kept; maps in deterministic order). */
export function encodeSchema(s: Schema): Uint8Array {
  return encode(schemaTree(s));
}
export function encodeFacet(f: Facet): Uint8Array {
  return encode(facetTree(f));
}
export function encodeInterface(i: Interface): Uint8Array {
  return encode(interfaceTree(i));
}
export function encodeDelta(d: Delta): Uint8Array {
  return encode(deltaTree(d));
}
export function encodeTypeRef(t: TypeRef): Uint8Array {
  return encode(typeRefTree(t));
}

// --- decoding from the generic tree

function arr(v: unknown, what: string, ...want: number[]): unknown[] {
  if (!Array.isArray(v)) throw err('malformed', `${what}: expected an array`);
  if (want.length && !want.includes(v.length)) throw err('malformed', `${what}: array of ${v.length} elements, want ${want.join(' or ')}`);
  return v;
}

function uintOf(v: unknown, what: string): number {
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === 'bigint') throw err('malformed', `${what}: ${v} is beyond 2^53 - 1`);
  throw err('malformed', `${what}: expected a uint`);
}

function textOf(v: unknown, what: string): string {
  if (typeof v !== 'string') throw err('malformed', `${what}: expected a text string`);
  return v;
}

function annotationsOf(v: unknown, what: string): Annotations {
  if (!(v instanceof Map)) throw err('malformed', `${what}: expected a map`);
  const out: Annotations = {};
  for (const [k, x] of v) {
    if (typeof k !== 'string') throw err('malformed', `${what}: keys must be text`);
    Object.defineProperty(out, k, { value: x, enumerable: true, writable: true, configurable: true });
  }
  return out;
}

export function typeRefOf(v: unknown): TypeRef {
  if (typeof v === 'number') return uintOf(v, 'type-ref');
  if (typeof v === 'bigint') throw err('malformed', `type-ref: ${v} is beyond 2^53 - 1`);
  if (!Array.isArray(v)) throw err('malformed', 'type-ref: expected a uint or an array');
  if (v.length === 0) throw err('bad_type_ref', 'empty type-ref');
  const op = uintOf(v[0], 'type-ref form');
  const arity: Record<number, number> = { 0: 2, 1: 3, 2: 2, 3: 2, 4: 1 };
  if (arity[op] !== v.length) throw err('bad_type_ref', `type-ref form ${op} with ${v.length} elements`);
  switch (op) {
    case 0:
    case 2:
    case 3:
      return [op, typeRefOf(v[1])] as TypeRef;
    case 1:
      return [1, typeRefOf(v[1]), typeRefOf(v[2])];
    default:
      return [4];
  }
}

function fieldsOf(v: unknown, what: string): Field[] {
  return arr(v, what).map((x) => {
    const f = arr(x, 'field', 5);
    return {
      tag: uintOf(f[0], 'field tag'),
      name: textOf(f[1], 'field name'),
      type: typeRefOf(f[2]),
      flags: uintOf(f[3], 'field flags'),
      annotations: annotationsOf(f[4], 'field annotations'),
    };
  });
}

function typeDefOf(v: unknown): TypeDef {
  const t = arr(v, 'type-def', 5, 6);
  const k = uintOf(t[0], 'type-def kind');
  const kind = KIND_BY_CODE[k];
  if (!kind) throw err('malformed', `unknown type-def kind ${k}`);
  const want = kind === 'struct' ? 6 : 5;
  if (t.length !== want) throw err('malformed', `${kind} type-def has ${t.length} elements, want ${want}`);
  const id = uintOf(t[1], 'type id');
  const name = textOf(t[2], 'type name');
  switch (kind) {
    case 'struct':
      return { kind, id, name, fields: fieldsOf(t[3], 'fields'), flags: uintOf(t[4], 'struct flags'), annotations: annotationsOf(t[5], 'type annotations') };
    case 'union':
      return { kind, id, name, variants: fieldsOf(t[3], 'variants'), annotations: annotationsOf(t[4], 'type annotations') };
    case 'enum':
      return { kind, id, name, values: arr(t[3], 'enum values').map((x) => uintOf(x, 'enum value')), annotations: annotationsOf(t[4], 'type annotations') };
    default:
      return { kind: 'alias', id, name, target: typeRefOf(t[3]), annotations: annotationsOf(t[4], 'type annotations') };
  }
}

function methodOf(v: unknown): Method {
  const m = arr(v, 'method', 7);
  return {
    id: uintOf(m[0], 'method id'),
    name: textOf(m[1], 'method name'),
    input: typeRefOf(m[2]),
    output: typeRefOf(m[3]),
    errors: arr(m[4], 'method errors').map((x) => uintOf(x, 'method error')),
    flags: uintOf(m[5], 'method flags'),
    annotations: annotationsOf(m[6], 'method annotations'),
  };
}

function serviceOf(v: unknown): Service {
  const s = arr(v, 'service', 4);
  return {
    id: uintOf(s[0], 'service id'),
    name: textOf(s[1], 'service name'),
    methods: arr(s[2], 'methods').map(methodOf),
    annotations: annotationsOf(s[3], 'service annotations'),
  };
}

function sigilOf(v: unknown): Sigil {
  const s = arr(v, 'sigil', 4);
  return { id: uintOf(s[0], 'sigil id'), name: textOf(s[1], 'sigil name'), kind: uintOf(s[2], 'sigil kind'), annotations: annotationsOf(s[3], 'sigil annotations') };
}

export function facetOf(v: unknown): Facet {
  const f = arr(v, 'facet', 9);
  const impl = f[6];
  if (impl !== null && !(impl instanceof Uint8Array)) throw err('malformed', 'implements: expected bytes or null');
  return {
    id: uintOf(f[0], 'facet id'),
    name: textOf(f[1], 'facet name'),
    version: textOf(f[2], 'facet version'),
    types: arr(f[3], 'types').map(typeDefOf),
    services: arr(f[4], 'services').map(serviceOf),
    sigils: arr(f[5], 'sigils').map(sigilOf),
    implements: impl as Uint8Array | null,
    retired: arr(f[7], 'retired').map((x) => {
      const r = arr(x, 'retired entry', 2);
      return [uintOf(r[0], 'retired space'), uintOf(r[1], 'retired id')] as [number, number];
    }),
    annotations: annotationsOf(f[8], 'facet annotations'),
  };
}

export function interfaceOf(v: unknown): Interface {
  const i = arr(v, 'interface', 5);
  return {
    name: textOf(i[0], 'interface name'),
    version: textOf(i[1], 'interface version'),
    types: arr(i[2], 'types').map(typeDefOf),
    services: arr(i[3], 'services').map(serviceOf),
    sigils: arr(i[4], 'sigils').map(sigilOf),
  };
}

export function schemaOf(v: unknown): Schema {
  const s = arr(v, 'schema', 5);
  const format = uintOf(s[0], 'schema format');
  if (format !== SCHEMA_FORMAT) throw err('unsupported_format', `schema format ${format}, want ${SCHEMA_FORMAT}`);
  return {
    format,
    name: textOf(s[1], 'schema name'),
    version: textOf(s[2], 'schema version'),
    facets: arr(s[3], 'facets').map(facetOf),
    annotations: annotationsOf(s[4], 'schema annotations'),
  };
}

export function deltaOf(v: unknown): Delta {
  return arr(v, 'delta').map((x) => {
    const o = arr(x, 'delta-op', 2);
    const op = uintOf(o[0], 'delta-op kind');
    switch (op) {
      case 0:
        return { op: 'put', facet: facetOf(o[1]) };
      case 1:
        return { op: 'remove', facetId: uintOf(o[1], 'removed facet id') };
      case 2:
        return { op: 'annotations', annotations: annotationsOf(o[1], 'delta annotations') };
      case 3:
        return { op: 'version', version: textOf(o[1], 'delta version') };
    }
    throw err('unknown_delta_op', `delta op ${op}`);
  });
}

/** Limits on a schema document. Clients SHOULD cap server schemas at 8 MiB, servers client schemas at 64 KiB. */
export interface SchemaLimits {
  maxBytes?: number;
  maxDepth?: number;
}

function decodeDoc(b: Uint8Array, o: SchemaLimits = {}): unknown {
  if (o.maxBytes && b.length > o.maxBytes) throw err('too_large', `document of ${b.length} bytes exceeds the limit of ${o.maxBytes}`);
  try {
    const opts: DecodeOptions = { maxDepth: o.maxDepth ?? 64 };
    return decode(b, opts);
  } catch (e) {
    if (e instanceof CborError) throw err('malformed', e.message);
    throw e;
  }
}

/** Decodes a schema document (a leading tag 55799 is skipped). Does not validate; see validateSchema. */
export function decodeSchema(b: Uint8Array, o: SchemaLimits = {}): Schema {
  return schemaOf(decodeDoc(stripSelfDescribed(b), o));
}
export function decodeFacet(b: Uint8Array): Facet {
  return facetOf(decodeDoc(b));
}
export function decodeInterface(b: Uint8Array): Interface {
  return interfaceOf(decodeDoc(b));
}
export function decodeDelta(b: Uint8Array): Delta {
  return deltaOf(decodeDoc(b));
}

// ---------------------------------------------------------------------------
// Copies and canonical form (6.6)
// ---------------------------------------------------------------------------

function cloneRef(t: TypeRef): TypeRef {
  return typeof t === 'number' ? t : (t.map((x, i) => (i === 0 ? x : cloneRef(x as TypeRef))) as TypeRef);
}
const cloneAnn = (a: Annotations | undefined): Annotations => ({ ...(a ?? {}) });
const cloneField = (f: Field): Field => ({ ...f, type: cloneRef(f.type), annotations: cloneAnn(f.annotations) });

export function cloneTypeDef(t: TypeDef): TypeDef {
  switch (t.kind) {
    case 'struct':
      return { ...t, fields: t.fields.map(cloneField), annotations: cloneAnn(t.annotations) };
    case 'union':
      return { ...t, variants: t.variants.map(cloneField), annotations: cloneAnn(t.annotations) };
    case 'enum':
      return { ...t, values: [...t.values], annotations: cloneAnn(t.annotations) };
    case 'alias':
      return { ...t, target: cloneRef(t.target), annotations: cloneAnn(t.annotations) };
  }
}

export function cloneMethod(m: Method): Method {
  return { ...m, input: cloneRef(m.input), output: cloneRef(m.output), errors: [...m.errors], annotations: cloneAnn(m.annotations) };
}

function cloneService(s: Service): Service {
  return { ...s, methods: s.methods.map(cloneMethod), annotations: cloneAnn(s.annotations) };
}

const cloneSigil = (s: Sigil): Sigil => ({ ...s, annotations: cloneAnn(s.annotations) });

export function cloneFacet(f: Facet): Facet {
  return {
    ...f,
    types: f.types.map(cloneTypeDef),
    services: f.services.map(cloneService),
    sigils: f.sigils.map(cloneSigil),
    implements: f.implements ? f.implements.slice() : null,
    retired: f.retired.map(([a, b]) => [a, b] as [number, number]),
    annotations: cloneAnn(f.annotations),
  };
}

export function cloneSchema(s: Schema): Schema {
  return { ...s, facets: s.facets.map(cloneFacet), annotations: cloneAnn(s.annotations) };
}

const byId = <X extends { id: number }>(a: X, b: X) => a.id - b.id;
const byTag = (a: Field, b: Field) => a.tag - b.tag;
const num = (a: number, b: number) => a - b;

function sortDefs(types: TypeDef[], services: Service[], sigils: Sigil[]): void {
  types.sort(byId);
  for (const t of types) {
    if (t.kind === 'struct') t.fields.sort(byTag);
    else if (t.kind === 'union') t.variants.sort(byTag);
    else if (t.kind === 'enum') t.values.sort(num);
  }
  services.sort(byId);
  for (const s of services) {
    s.methods.sort(byId);
    for (const m of s.methods) m.errors.sort(num);
  }
  sigils.sort(byId);
}

/** A sorted deep copy of the facet (6.6). */
export function canonicalFacet(f: Facet): Facet {
  const c = cloneFacet(f);
  sortDefs(c.types, c.services, c.sigils);
  c.retired.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  return c;
}

export function canonicalInterface(i: Interface): Interface {
  const c: Interface = { ...i, types: i.types.map(cloneTypeDef), services: i.services.map(cloneService), sigils: i.sigils.map(cloneSigil) };
  sortDefs(c.types, c.services, c.sigils);
  return c;
}

/** A sorted deep copy of the schema, facets sorted by ID. */
export function canonicalSchema(s: Schema): Schema {
  const c = { ...s, facets: s.facets.map(canonicalFacet), annotations: cloneAnn(s.annotations) };
  c.facets.sort(byId);
  return c;
}

/** The Core Deterministic Encoding of the canonical facet. */
export function facetCanonicalBytes(f: Facet): Uint8Array {
  return encode(facetTree(canonicalFacet(f)));
}

/** What a facet hash covers: the canonical facet with id 0 and name "". */
export function facetHashInput(f: Facet): Uint8Array {
  const c = canonicalFacet(f);
  c.id = 0;
  c.name = '';
  return encode(facetTree(c));
}

/** 0x01 || SHA-256(b). */
export function hashBytes(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(33);
  out[0] = 0x01;
  out.set(sha256(b), 1);
  return out;
}

export function facetHash(f: Facet): Uint8Array {
  return hashBytes(facetHashInput(f));
}

export function interfaceCanonicalBytes(i: Interface): Uint8Array {
  return encode(interfaceTree(canonicalInterface(i)));
}

export function interfaceHash(i: Interface): Uint8Array {
  return hashBytes(interfaceCanonicalBytes(i));
}

export function schemaCanonicalBytes(s: Schema): Uint8Array {
  return encode(schemaTree(canonicalSchema(s)));
}

/** [format, name, version, [* [facet_id, facet_name, facet_hash]], annotations], facets sorted by ID. */
export function schemaHashInputTree(s: Schema): unknown {
  const c = canonicalSchema(s);
  return [c.format, c.name, c.version, c.facets.map((f) => [f.id, f.name, facetHash(f)]), annotationsTree(c.annotations)];
}

export function schemaHashInput(s: Schema): Uint8Array {
  return encode(schemaHashInputTree(s));
}

export function schemaHash(s: Schema): Uint8Array {
  return hashBytes(schemaHashInput(s));
}

// ---------------------------------------------------------------------------
// Names (6.1)
// ---------------------------------------------------------------------------

const NODE_ID = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

/** [a-z0-9-]+(\.[a-z0-9-]+)*: node IDs, facet names and module ids. */
export function isNodeId(s: string): boolean {
  return NODE_ID.test(s);
}

/** A facet name: the node-ID grammar, optionally prefixed with "<peer-id>/" by a hub (10.8). */
export function isFacetName(s: string): boolean {
  const i = s.indexOf('/');
  if (i < 0) return isNodeId(s);
  return isNodeId(s.slice(0, i)) && isNodeId(s.slice(i + 1));
}

export function isAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) >= 0x80) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function annFloat(a: Annotations): boolean {
  return Object.values(a ?? {}).some(containsFloat);
}

function defsHaveFloat(types: TypeDef[], services: Service[], sigils: Sigil[]): boolean {
  for (const t of types) {
    if (annFloat(t.annotations)) return true;
    for (const f of members(t)) if (annFloat(f.annotations)) return true;
  }
  for (const s of services) {
    if (annFloat(s.annotations)) return true;
    for (const m of s.methods) if (annFloat(m.annotations)) return true;
  }
  return sigils.some((s) => annFloat(s.annotations));
}

function checkAsciiNames(where: string, types: TypeDef[], services: Service[], sigils: Sigil[]): void {
  const bad = (kind: string, n: string) => err('invalid_name', `${where}: ${kind} name ${JSON.stringify(n)} is not ASCII`);
  for (const t of types) {
    if (!isAscii(t.name)) throw bad('type', t.name);
    for (const f of members(t)) if (!isAscii(f.name)) throw bad('field or variant', f.name);
  }
  for (const s of services) {
    if (!isAscii(s.name)) throw bad('service', s.name);
    for (const m of s.methods) if (!isAscii(m.name)) throw bad('method', m.name);
  }
  for (const s of sigils) if (!isAscii(s.name)) throw bad('sigil', s.name);
}

interface Index {
  types: Map<number, TypeDef>;
  sigils: Map<number, Sigil>;
  methods: Map<number, Method>;
  services: Map<number, Service>;
}

/** Reports whether [4] is reachable from r, following the facet's types (tombstones excepted). */
export function reachesByteStream(r: TypeRef, types: Map<number, TypeDef>, seen = new Set<number>()): boolean {
  if (typeof r !== 'number') {
    switch (r[0]) {
      case 4:
        return true;
      case 1:
        return reachesByteStream(r[1], types, seen) || reachesByteStream(r[2], types, seen);
      default:
        return reachesByteStream(r[1], types, seen);
    }
  }
  const t = types.get(r);
  if (!t || seen.has(r)) return false;
  seen.add(r);
  if (t.kind === 'alias') return reachesByteStream(t.target, types, seen);
  return members(t).some((f) => !isRemoved(f) && reachesByteStream(f.type, types, seen));
}

/** Whether a method half with this type must end with End: a stream, or [4] reachable. */
export function needsEnd(r: TypeRef, types: Map<number, TypeDef>): boolean {
  return isStream(r) || reachesByteStream(r, types);
}

function validateDefs(where: string, types: TypeDef[], services: Service[], sigils: Sigil[], retired: [number, number][]): Index {
  checkAsciiNames(where, types, services, sigils);
  const ret = new Set<string>();
  for (const [sp, id] of retired) {
    if (sp > Space.sigil) throw err('bad_retired_entry', `${where}: retired space ${sp}`);
    ret.add(`${sp}:${id}`);
  }
  const isRet = (sp: number, id: number) => ret.has(`${sp}:${id}`);
  const ix: Index = { types: new Map(), sigils: new Map(), methods: new Map(), services: new Map() };
  for (const t of types) {
    if (t.id < FIRST_FREE_TYPE_ID) throw err('reserved_id', `${where}: type ${t.id} is reserved`);
    if (ix.types.has(t.id)) throw err('duplicate_id', `${where}: type ${t.id}`);
    if (isRet(Space.type, t.id)) throw err('retired_id_reused', `${where}: type ${t.id} is retired`);
    if (!(t.kind in KIND_CODES)) throw err('malformed', `${where}: type ${t.id} has an unknown kind`);
    ix.types.set(t.id, t);
  }
  for (const s of sigils) {
    if (s.id < FIRST_FREE_SIGIL) throw err('reserved_id', `${where}: sigil ${s.id} is reserved`);
    if (ix.sigils.has(s.id)) throw err('duplicate_id', `${where}: sigil ${s.id}`);
    if (isRet(Space.sigil, s.id)) throw err('retired_id_reused', `${where}: sigil ${s.id} is retired`);
    if (s.kind > SigilKind.symbol) throw err('bad_sigil_kind', `${where}: sigil ${s.id} has kind ${s.kind}`);
    ix.sigils.set(s.id, s);
  }
  // Sigil names are unique within a facet or interface (6.5).
  const sigilNames = new Set<string>();
  for (const s of sigils) {
    if (sigilNames.has(s.name)) throw err('duplicate_sigil_name', `${where}: sigil ${s.id} is named ${JSON.stringify(s.name)} like another`);
    sigilNames.add(s.name);
  }
  for (const s of services) {
    if (ix.services.has(s.id)) throw err('duplicate_id', `${where}: service ${s.id}`);
    if (isRet(Space.service, s.id)) throw err('retired_id_reused', `${where}: service ${s.id} is retired`);
    ix.services.set(s.id, s);
    for (const m of s.methods) {
      if (ix.methods.has(m.id)) throw err('duplicate_id', `${where}: method ${m.id} appears twice`);
      if (isRet(Space.method, m.id)) throw err('retired_id_reused', `${where}: method ${m.id} is retired`);
      ix.methods.set(m.id, m);
    }
  }
  const checkRef = (r: TypeRef, at: string, top: boolean): void => {
    if (typeof r === 'number') {
      if (r >= 12 && r <= 31) throw err('reserved_type_id', `${at} references type ${r}; TypeIds 12-31 are reserved for later built-ins`);
      if (r <= MAX_BUILTIN_TYPE || ix.types.has(r)) return;
      throw err('dangling_reference', `${at} references type ${r}, not defined in this facet`);
    }
    switch (r[0]) {
      case 0:
      case 2:
        checkRef(r[1], at, false);
        return;
      case 1:
        checkRef(r[1], at, false);
        checkRef(r[2], at, false);
        return;
      case 3:
        if (!top) throw err('stream_type_misplaced', `${at}: [3, T] is only allowed as a method's whole input or output`);
        checkRef(r[1], at, false);
        return;
      case 4:
        return;
    }
    throw err('bad_type_ref', at);
  };
  const enumOf = new Map<number, number>(); // kind-0 sigil -> the enum listing it
  for (const t of types) {
    const at = `${where}: type ${t.id}`;
    if (t.kind === 'struct' || t.kind === 'union') {
      const tags = new Set<number>();
      for (const f of members(t)) {
        if (tags.has(f.tag)) throw err('duplicate_id', `${at}: tag ${f.tag} appears twice`);
        tags.add(f.tag);
        if (isRemoved(f)) continue;
        checkRef(f.type, at, false);
      }
    } else if (t.kind === 'enum') {
      const seen = new Set<number>();
      for (const v of t.values) {
        if (seen.has(v)) throw err('duplicate_id', `${at} lists sigil ${v} twice`);
        seen.add(v);
        const s = ix.sigils.get(v);
        if (!s || s.kind !== SigilKind.enumValue) throw err('dangling_reference', `${at} lists sigil ${v}, not a kind-0 sigil of this facet`);
        // A kind-0 sigil is a value of exactly one enum (6.5).
        const other = enumOf.get(v);
        if (other !== undefined) throw err('sigil_in_two_enums', `${at} lists sigil ${v}, a value of type ${other} too`);
        enumOf.set(v, t.id);
      }
    } else {
      checkRef(t.target, at, false);
    }
  }
  for (const s of services) {
    for (const m of s.methods) {
      const at = `${where}: method ${m.id}`;
      checkRef(m.input, at, true);
      checkRef(m.output, at, true);
      for (const e of m.errors) {
        if (e < 32) continue;
        const sg = ix.sigils.get(e);
        if (!sg || sg.kind !== SigilKind.error) throw err('dangling_reference', `${at} lists error ${e}, not a kind-1 sigil of this facet`);
      }
      if (m.flags & MethodFlags.notification) {
        if (m.output !== T.unit) throw err('invalid_notification', `${at}: a notification (flag 0x2) must have output unit`);
        if (reachesByteStream(m.input, ix.types)) throw err('invalid_notification', `${at}: a notification (flag 0x2) must not have [4] in its input`);
      }
      if (needsEnd(m.input, ix.types) && !(m.flags & MethodFlags.inputEnds)) {
        throw err('missing_end_flag', `${at}: input is a stream or reaches [4], so flag 0x8 is required`);
      }
      if (needsEnd(m.output, ix.types) && !(m.flags & MethodFlags.outputEnds)) {
        throw err('missing_end_flag', `${at}: output is a stream or reaches [4], so flag 0x10 is required`);
      }
    }
  }
  return ix;
}

function validateFacetIndex(f: Facet): Index {
  const where = `facet ${f.id}`;
  if (annFloat(f.annotations) || defsHaveFloat(f.types, f.services, f.sigils)) throw err('float_in_canonical_data', `${where} contains a float`);
  if (!isFacetName(f.name)) throw err('invalid_name', `${where}: facet name ${JSON.stringify(f.name)} does not match the facet-name grammar`);
  return validateDefs(where, f.types, f.services, f.sigils, f.retired);
}

/** Checks one facet on its own (no floats, name grammar, definitions); not the facet-ID rules. */
export function validateFacet(f: Facet): void {
  validateFacetIndex(f);
}

/** Checks an interface: its definitions, and that it holds exactly what its services reach (6.5). */
export function validateInterface(i: Interface): void {
  if (defsHaveFloat(i.types, i.services, i.sigils)) throw err('float_in_canonical_data', 'interface contains a float');
  const ix = validateDefs('interface', i.types, i.services, i.sigils, []);
  const seenT = new Set<number>();
  const seenS = new Set<number>();
  const walk = (r: TypeRef): void => {
    if (typeof r !== 'number') {
      if (r[0] === 4) return;
      if (r[0] === 1) {
        walk(r[1]);
        walk(r[2]);
        return;
      }
      walk(r[1]);
      return;
    }
    const t = ix.types.get(r);
    if (!t || seenT.has(r)) return;
    seenT.add(r);
    if (t.kind === 'enum') for (const v of t.values) seenS.add(v);
    else if (t.kind === 'alias') walk(t.target);
    else for (const f of members(t)) if (!isRemoved(f)) walk(f.type);
  };
  for (const m of ix.methods.values()) {
    walk(m.input);
    walk(m.output);
    for (const e of m.errors) seenS.add(e);
  }
  for (const t of i.types) if (!seenT.has(t.id)) throw err('interface_not_closed', `type ${t.id} is not reached from the interface's services`);
  for (const s of i.sigils) if (!seenS.has(s.id)) throw err('interface_not_closed', `sigil ${s.id} is not reached from the interface's services`);
}

/**
 * Checks a received schema document (6.6 rule 3, 6.1): the format, no floats,
 * facets listed sorted by ID (unless allowUnsorted), unique facet IDs and
 * names, no reserved facet ID but 1, facet 1 matching sparrow.web, and every
 * facet valid.
 */
export function validateSchema(s: Schema, o: { allowUnsorted?: boolean } = {}): void {
  if (s.format !== SCHEMA_FORMAT) throw err('unsupported_format', `schema format ${s.format}, want ${SCHEMA_FORMAT}`);
  if (annFloat(s.annotations)) throw err('float_in_canonical_data', 'schema contains a float');
  for (const f of s.facets) {
    if (annFloat(f.annotations) || defsHaveFloat(f.types, f.services, f.sigils)) throw err('float_in_canonical_data', 'schema contains a float');
  }
  if (!o.allowUnsorted) {
    for (let i = 1; i < s.facets.length; i++) {
      const a = s.facets[i - 1].id;
      const b = s.facets[i].id;
      if (a === b) throw err('duplicate_facet_id', `facet ${b}`);
      if (a > b) throw err('facets_not_sorted', `facet ${b} listed after facet ${a}`);
    }
  }
  const ids = new Set<number>();
  const names = new Set<string>();
  for (const f of s.facets) {
    if (ids.has(f.id)) throw err('duplicate_facet_id', `facet ${f.id}`);
    if (names.has(f.name)) throw err('duplicate_facet_name', JSON.stringify(f.name));
    ids.add(f.id);
    names.add(f.name);
    if (f.id < FIRST_FREE_FACET_ID && f.id !== WEB_FACET_ID) {
      throw err('reserved_facet_id', `facet ${f.id} (${JSON.stringify(f.name)}): IDs 0 and 2-15 MUST NOT appear`);
    }
    if (f.id === WEB_FACET_ID && !isWebFacet(f)) {
      throw err('facet1_mismatch', 'facet 1 does not match the definition of sparrow.web by name and facet hash');
    }
    validateFacet(f);
  }
}

/** The deepest type-reference nesting in a schema (servers MAY reject client schemas above 32). */
export function schemaDepth(s: Schema): number {
  let max = 0;
  const ref = (r: TypeRef, d: number) => {
    if (d > max) max = d;
    if (typeof r !== 'number') for (let i = 1; i < r.length; i++) ref(r[i] as TypeRef, d + 1);
  };
  for (const f of s.facets) {
    for (const t of f.types) {
      for (const x of members(t)) ref(x.type, 1);
      if (t.kind === 'alias') ref(t.target, 1);
    }
    for (const sv of f.services) {
      for (const m of sv.methods) {
        ref(m.input, 1);
        ref(m.output, 1);
      }
    }
  }
  return max;
}

// ---------------------------------------------------------------------------
// sparrow.web (9.4)
// ---------------------------------------------------------------------------

/** A fresh copy of facet 1, sparrow.web. */
export function webFacet(): Facet {
  return {
    id: WEB_FACET_ID,
    name: WEB_FACET_NAME,
    version: '1.0.0',
    types: [],
    services: [
      {
        id: 0,
        name: 'Client',
        methods: [{ id: 0, name: 'moduleRejected', input: [0, T.string], output: T.unit, errors: [], flags: MethodFlags.notification, annotations: {} }],
        annotations: {},
      },
    ],
    sigils: [],
    implements: null,
    retired: [],
    annotations: {},
  };
}

let webHash: Uint8Array | undefined;

export function webFacetHash(): Uint8Array {
  webHash ??= facetHash(webFacet());
  return webHash.slice();
}

export function isWebFacet(f: Facet): boolean {
  return f.name === WEB_FACET_NAME && bytesEqual(facetHash(f), webFacetHash());
}

// ---------------------------------------------------------------------------
// Compatibility (6.7)
// ---------------------------------------------------------------------------

function refEqual(a: TypeRef, b: TypeRef): boolean {
  return bytesEqual(encodeTypeRef(a), encodeTypeRef(b));
}

/** Checks that nw may replace old in place (6.7 with 6.6 rule 2). Throws SchemaError. */
export function checkCompatible(old: Facet, nw: Facet): void {
  const id = old.id;
  if (old.name !== nw.name) throw err('facet_renamed', `facet ${id}: ${JSON.stringify(old.name)} -> ${JSON.stringify(nw.name)}`);
  if (major(old.version) !== major(nw.version)) {
    throw err('major_version_changed', `facet ${id}: ${old.version} -> ${nw.version}; a new major version is a new facet`);
  }
  const newRet = new Set(nw.retired.map(([s, x]) => `${s}:${x}`));
  for (const [s, x] of old.retired) {
    if (!newRet.has(`${s}:${x}`)) throw err('retired_not_carried_over', `facet ${id}: retired [${s}, ${x}] missing`);
  }
  const oi = validateFacetIndex(old);
  const ni = validateFacetIndex(nw);
  const dropped = (sp: number, x: number) => {
    if (!newRet.has(`${sp}:${x}`)) throw err('dropped_id_not_retired', `facet ${id}: [${sp}, ${x}] was removed but is not in retired`);
  };
  const sorted = <V>(m: Map<number, V>) => [...m.keys()].sort(num);
  for (const tid of sorted(oi.types)) {
    const nt = ni.types.get(tid);
    if (!nt) dropped(Space.type, tid);
    else typeCompatible(id, oi.types.get(tid)!, nt);
  }
  for (const sid of sorted(oi.services)) if (!ni.services.has(sid)) dropped(Space.service, sid);
  const fixed = MethodFlags.notification | MethodFlags.inputEnds | MethodFlags.outputEnds;
  for (const mid of sorted(oi.methods)) {
    const om = oi.methods.get(mid)!;
    const nm = ni.methods.get(mid);
    if (!nm) {
      dropped(Space.method, mid);
      continue;
    }
    if (!refEqual(om.input, nm.input) || !refEqual(om.output, nm.output) || (om.flags & fixed) !== (nm.flags & fixed)) {
      throw err('incompatible_change', `facet ${id}: method ${mid} changed input, output or flags 0x2/0x8/0x10`);
    }
  }
  for (const sid of sorted(oi.sigils)) {
    const ns = ni.sigils.get(sid);
    if (!ns) dropped(Space.sigil, sid);
    else if (ns.kind !== oi.sigils.get(sid)!.kind) throw err('incompatible_change', `facet ${id}: sigil ${sid} changed kind`);
  }
}

function typeCompatible(fid: number, ot: TypeDef, nt: TypeDef): void {
  const bad = (m: string) => err('incompatible_change', `facet ${fid}: type ${ot.id}: ${m}`);
  if (ot.kind !== nt.kind) throw bad('kind changed');
  if (ot.kind === 'enum' && nt.kind === 'enum') {
    const nv = new Set(nt.values);
    for (const v of ot.values) if (!nv.has(v)) throw bad(`enum value ${v} removed`);
    return;
  }
  if (ot.kind === 'alias' && nt.kind === 'alias') {
    if (!refEqual(ot.target, nt.target)) throw bad('alias target changed');
    return;
  }
  const isStruct = ot.kind === 'struct';
  if (isStruct && (isSparse(ot) !== isSparse(nt))) throw bad('sparse flag changed');
  const newM = new Map(members(nt).map((f) => [f.tag, f]));
  const oldM = new Set<number>();
  for (const of of members(ot)) {
    oldM.add(of.tag);
    const nf = newM.get(of.tag);
    if (!nf) throw bad(`tag ${of.tag} disappeared (removed members stay as tombstones)`);
    const oRem = isRemoved(of);
    const nRem = isRemoved(nf);
    if (oRem && !nRem) throw bad(`tag ${of.tag} reused after removal`);
    if (oRem && nRem) {
      if (!refEqual(of.type, nf.type) || of.flags !== nf.flags) throw bad(`tombstone ${of.tag} changed its type or flags`);
    } else if (nRem) {
      if (isStruct && !isOptional(of)) throw bad(`required field ${of.tag} removed`);
      if (!refEqual(of.type, nf.type)) throw bad(`tag ${of.tag} changed type as it became a tombstone`);
    } else {
      if (!refEqual(of.type, nf.type)) throw bad(`tag ${of.tag} changed type`);
      if (isStruct && isOptional(of) && !isOptional(nf)) throw bad(`field ${of.tag} made required`);
      if (isStruct && !isOptional(of) && isOptional(nf)) throw bad(`required field ${of.tag} made optional`);
    }
  }
  if (isStruct) {
    for (const nf of members(nt)) {
      if (!oldM.has(nf.tag) && !isOptional(nf) && !isRemoved(nf)) throw bad(`new field ${nf.tag} is required`);
    }
  }
}

// ---------------------------------------------------------------------------
// Interface conformance (6.5)
// ---------------------------------------------------------------------------

function typeShape(t: TypeDef): Uint8Array {
  const c = cloneTypeDef(t);
  sortDefs([c], [], []);
  c.name = '';
  c.annotations = {};
  for (const f of members(c)) {
    f.name = '';
    f.annotations = {};
    if (c.kind === 'struct') f.flags &= ~FieldFlags.deprecated;
  }
  return encode(typeDefTree(c));
}

function serviceShape(s: Service): Uint8Array {
  return encode([s.id, '', new Map()]);
}

function methodShape(m: Method): Uint8Array {
  const c = cloneMethod(m);
  c.errors.sort(num);
  c.name = '';
  c.annotations = {};
  c.flags &= ~(MethodFlags.idempotent | MethodFlags.shared);
  return encode(methodTree(c));
}

function sigilShape(s: Sigil): Uint8Array {
  return encode(sigilTree({ ...s, name: '', annotations: {} }));
}

/**
 * Whether a facet implements an interface: returns the first mismatch as
 * [space, id] (types, then each service followed by its methods, then
 * sigils), or null when it conforms.
 */
export function conforms(f: Facet, iface: Interface): [number, number] | null {
  const fc = canonicalFacet(f);
  const ic = canonicalInterface(iface);
  const ft = typeIndex(fc.types);
  for (const t of ic.types) {
    const x = ft.get(t.id);
    if (!x || !bytesEqual(typeShape(t), typeShape(x))) return [Space.type, t.id];
  }
  for (const s of ic.services) {
    const fs = fc.services.find((x) => x.id === s.id);
    if (!fs || !bytesEqual(serviceShape(s), serviceShape(fs))) return [Space.service, s.id];
    for (const m of s.methods) {
      const fm = fs.methods.find((x) => x.id === m.id);
      if (!fm || !bytesEqual(methodShape(m), methodShape(fm))) return [Space.method, m.id];
    }
  }
  for (const s of ic.sigils) {
    const x = fc.sigils.find((y) => y.id === s.id);
    if (!x || !bytesEqual(sigilShape(s), sigilShape(x))) return [Space.sigil, s.id];
  }
  return null;
}

/** Checks a facet's implements claim against an interface. */
export function verifyImplements(f: Facet, iface: Interface): void {
  if (!f.implements) return;
  if (!bytesEqual(interfaceHash(iface), f.implements)) throw err('implements_mismatch', `facet ${f.id} claims another interface`);
  const m = conforms(f, iface);
  if (m) throw err('implements_mismatch', `facet ${f.id}: [${m[0]}, ${m[1]}] does not match the interface`);
}

// ---------------------------------------------------------------------------
// Schema state and deltas (6.6)
// ---------------------------------------------------------------------------

/**
 * A peer's schema as tracked within one session: the canonical schema, its
 * epoch, and the last version of every facet removed during the session.
 * Immutable: apply returns a new state.
 */
export class SchemaState {
  readonly schema: Schema;
  readonly epoch: number;
  private readonly removed: Map<number, Facet>;
  private hashCache?: Uint8Array;

  private constructor(s: Schema, epoch: number, removed: Map<number, Facet>) {
    this.schema = s;
    this.epoch = epoch;
    this.removed = removed;
  }

  /** Starts tracking a schema at epoch 0; validates it as a received document. */
  static create(s: Schema, o: { allowUnsorted?: boolean } = {}): SchemaState {
    validateSchema(s, o);
    return new SchemaState(canonicalSchema(s), 0, new Map());
  }

  get hash(): Uint8Array {
    this.hashCache ??= schemaHash(this.schema);
    return this.hashCache;
  }

  /** IDs of facets removed during the session and not added back, sorted. */
  removedFacetIds(): number[] {
    return [...this.removed.keys()].sort(num);
  }

  facet(id: number): Facet | undefined {
    return this.schema.facets.find((f) => f.id === id);
  }

  facetByName(name: string): Facet | undefined {
    return this.schema.facets.find((f) => f.name === name);
  }

  /** Applies a delta (compatibility, the re-add rule, validity of the result) at the next epoch. */
  apply(d: Delta): SchemaState {
    const removed = new Map(this.removed);
    const s = cloneSchema(this.schema);
    for (const op of d) {
      switch (op.op) {
        case 'put': {
          const f = canonicalFacet(op.facet);
          const i = s.facets.findIndex((x) => x.id === f.id);
          if (i >= 0) {
            checkCompatible(s.facets[i], f);
            s.facets[i] = f;
            break;
          }
          const last = removed.get(f.id);
          if (last) {
            if (last.name !== f.name || major(last.version) !== major(f.version)) {
              throw err(
                'removed_facet_mismatch',
                `facet ${f.id} was ${JSON.stringify(last.name)} ${last.version}; it may only come back with the same name and major version`,
              );
            }
            checkCompatible(last, f);
            removed.delete(f.id);
          }
          s.facets.push(f);
          break;
        }
        case 'remove': {
          const i = s.facets.findIndex((x) => x.id === op.facetId);
          if (i < 0) throw err('unknown_facet', `facet ${op.facetId}`);
          removed.set(op.facetId, s.facets[i]);
          s.facets.splice(i, 1);
          break;
        }
        case 'annotations':
          s.annotations = { ...op.annotations };
          break;
        case 'version':
          s.version = op.version;
          break;
        default:
          throw err('unknown_delta_op', `delta op ${(op as { op: string }).op}`);
      }
    }
    const c = canonicalSchema(s);
    validateSchema(c);
    return new SchemaState(c, this.epoch + 1, removed);
  }

  /** Applies a SchemaUpdate: the epoch must be the next one and the new hash must match. */
  applyUpdate(epoch: number, hash: Uint8Array, d: Delta): SchemaState {
    if (epoch !== this.epoch + 1) throw err('epoch_mismatch', `epoch ${epoch} after ${this.epoch}`);
    const n = this.apply(d);
    if (!bytesEqual(n.hash, hash)) throw err('hash_mismatch', 'the schema hash after the delta differs from the update');
    return n;
  }
}

/** A delta turning old into nw: removals, then added or changed facets, then annotations and version. */
export function diff(old: Schema, nw: Schema): Delta {
  const oc = canonicalSchema(old);
  const nc = canonicalSchema(nw);
  const d: Delta = [];
  for (const f of oc.facets) if (!nc.facets.some((x) => x.id === f.id)) d.push({ op: 'remove', facetId: f.id });
  for (const f of nc.facets) {
    const of = oc.facets.find((x) => x.id === f.id);
    if (of && bytesEqual(facetCanonicalBytes(of), facetCanonicalBytes(f))) continue;
    d.push({ op: 'put', facet: cloneFacet(f) });
  }
  if (!bytesEqual(encode(annotationsTree(oc.annotations)), encode(annotationsTree(nc.annotations)))) {
    d.push({ op: 'annotations', annotations: { ...nc.annotations } });
  }
  if (oc.version !== nc.version) d.push({ op: 'version', version: nc.version });
  return d;
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/** A field or variant for the builder. */
export interface FieldSpec {
  name: string;
  type: TypeRef;
  flags?: number;
  tag?: number;
  annotations?: Annotations;
}

/** A required field (tags follow the previous one unless set). */
export function field(name: string, type: TypeRef, opts: { tag?: number; annotations?: Annotations; deprecated?: boolean } = {}): FieldSpec {
  return { name, type, tag: opts.tag, annotations: opts.annotations, flags: opts.deprecated ? FieldFlags.deprecated : 0 };
}

/** An optional field. */
export function optionalField(name: string, type: TypeRef, opts: { tag?: number; annotations?: Annotations; deprecated?: boolean } = {}): FieldSpec {
  return { ...field(name, type, opts), flags: FieldFlags.optional | (opts.deprecated ? FieldFlags.deprecated : 0) };
}

/** A union variant. */
export function variant(name: string, type: TypeRef = T.unit, opts: { tag?: number; annotations?: Annotations } = {}): FieldSpec {
  return { name, type, tag: opts.tag, annotations: opts.annotations, flags: 0 };
}

export interface MethodOptions {
  /** Fix the method ID; otherwise IDs follow in order within the facet. */
  id?: number;
  idempotent?: boolean;
  /** Flag 0x4: calls run on the shared lane (a hint). */
  shared?: boolean;
  /** Error sigils (IDs, or names of error codes defined with errorCode) beyond the core set. */
  errors?: (number | string)[];
  annotations?: Annotations;
}

/**
 * Builds a facet. IDs are assigned in order (types and sigils from 64,
 * services and methods from 0) unless fixed; keep the order stable, or fix
 * the IDs, so they stay stable across restarts (6.6).
 */
export class FacetBuilder {
  private f: Facet;
  private nextType = FIRST_FREE_TYPE_ID;
  private nextSigil = FIRST_FREE_SIGIL;
  private nextService = 0;
  private nextMethod = 0;

  constructor(name: string, version: string, opts: { id?: number; annotations?: Annotations } = {}) {
    this.f = {
      id: opts.id ?? 0,
      name,
      version,
      types: [],
      services: [],
      sigils: [],
      implements: null,
      retired: [],
      annotations: { ...(opts.annotations ?? {}) },
    };
  }

  /** Fixes the facet ID (16 and up). */
  id(id: number): this {
    this.f.id = id;
    return this;
  }

  annotate(key: string, value: unknown): this {
    this.f.annotations[key] = value;
    return this;
  }

  implementsInterface(hash: Uint8Array): this {
    this.f.implements = hash;
    return this;
  }

  /** Records retired IDs, for a facet that removed definitions. */
  retire(space: number, ...ids: number[]): this {
    for (const id of ids) this.f.retired.push([space, id]);
    return this;
  }

  private typeId(id?: number): number {
    const v = id ?? this.nextType;
    if (v >= this.nextType) this.nextType = v + 1;
    return v;
  }

  private fields(specs: FieldSpec[]): Field[] {
    let next = 0;
    return specs.map((s) => {
      const tag = s.tag ?? next;
      next = tag + 1;
      return { tag, name: s.name, type: s.type, flags: s.flags ?? 0, annotations: { ...(s.annotations ?? {}) } };
    });
  }

  /** Defines a struct; returns its TypeId. */
  struct(name: string, fields: FieldSpec[], opts: { id?: number; annotations?: Annotations } = {}): number {
    const id = this.typeId(opts.id);
    this.f.types.push({ kind: 'struct', id, name, fields: this.fields(fields), flags: 0, annotations: { ...(opts.annotations ?? {}) } });
    return id;
  }

  /** Defines a sparse struct (encoded as a map from tag to value). */
  sparseStruct(name: string, fields: FieldSpec[], opts: { id?: number; annotations?: Annotations } = {}): number {
    const id = this.typeId(opts.id);
    this.f.types.push({ kind: 'struct', id, name, fields: this.fields(fields), flags: StructFlags.sparse, annotations: { ...(opts.annotations ?? {}) } });
    return id;
  }

  /** Defines a union. */
  union(name: string, variants: FieldSpec[], opts: { id?: number; annotations?: Annotations } = {}): number {
    const id = this.typeId(opts.id);
    this.f.types.push({ kind: 'union', id, name, variants: this.fields(variants), annotations: { ...(opts.annotations ?? {}) } });
    return id;
  }

  /** Defines a named alias (needed to send a composite as dynamic). */
  alias(name: string, target: TypeRef, opts: { id?: number; annotations?: Annotations } = {}): number {
    const id = this.typeId(opts.id);
    this.f.types.push({ kind: 'alias', id, name, target, annotations: { ...(opts.annotations ?? {}) } });
    return id;
  }

  private sigil(name: string, kind: number, id?: number): number {
    const v = id ?? this.nextSigil;
    if (v >= this.nextSigil) this.nextSigil = v + 1;
    this.f.sigils.push({ id: v, name, kind, annotations: {} });
    return v;
  }

  /**
   * Defines an enum; each value becomes a kind-0 sigil named `<name>.<value>`
   * (core 6.5), so two enums can both have a value `none`. Returns the TypeId
   * and the sigils, keyed by value name.
   */
  enum(name: string, values: string[], opts: { id?: number; annotations?: Annotations } = {}): { type: number; values: Record<string, number> } {
    const sig: Record<string, number> = {};
    const ids = values.map((v) => (sig[v] = this.sigil(`${name}.${v}`, SigilKind.enumValue)));
    const id = this.typeId(opts.id);
    this.f.types.push({ kind: 'enum', id, name, values: ids, annotations: { ...(opts.annotations ?? {}) } });
    return { type: id, values: sig };
  }

  /** Defines an application error code (kind-1 sigil); throw new SparrowError(name or id, ...). */
  errorCode(name: string, opts: { id?: number } = {}): number {
    return this.sigil(name, SigilKind.error, opts.id);
  }

  /** Defines an interned symbol (kind-2 sigil). */
  symbol(name: string, opts: { id?: number } = {}): number {
    return this.sigil(name, SigilKind.symbol, opts.id);
  }

  /** Starts a service. */
  service(name: string, opts: { id?: number; annotations?: Annotations } = {}): ServiceBuilder {
    const id = opts.id ?? this.nextService;
    if (id >= this.nextService) this.nextService = id + 1;
    const s: Service = { id, name, methods: [], annotations: { ...(opts.annotations ?? {}) } };
    this.f.services.push(s);
    return new ServiceBuilder(this, s);
  }

  /** @internal */
  addMethod(s: Service, name: string, input: TypeRef, output: TypeRef, flags: number, o: MethodOptions): number {
    const id = o.id ?? this.nextMethod;
    if (id >= this.nextMethod) this.nextMethod = id + 1;
    if (o.idempotent) flags |= MethodFlags.idempotent;
    if (o.shared) flags |= MethodFlags.shared;
    const types = typeIndex(this.f.types);
    if (needsEnd(input, types)) flags |= MethodFlags.inputEnds;
    if (needsEnd(output, types)) flags |= MethodFlags.outputEnds;
    const errors = (o.errors ?? []).map((e) => {
      if (typeof e === 'number') return e;
      const sg = this.f.sigils.find((x) => x.name === e && x.kind === SigilKind.error);
      if (!sg) throw new Error(`schema: no error code ${JSON.stringify(e)} in facet ${this.f.name}`);
      return sg.id;
    });
    s.methods.push({ id, name, input, output, errors, flags, annotations: { ...(o.annotations ?? {}) } });
    return id;
  }

  /** Validates and returns a copy of the facet. Flags 0x8 and 0x10 are set from the types at build time too. */
  build(): Facet {
    const f = cloneFacet(this.f);
    const types = typeIndex(f.types);
    for (const s of f.services) {
      for (const m of s.methods) {
        if (needsEnd(m.input, types)) m.flags |= MethodFlags.inputEnds;
        if (needsEnd(m.output, types)) m.flags |= MethodFlags.outputEnds;
      }
    }
    const probe = cloneFacet(f);
    if (probe.id === 0) probe.id = FIRST_FREE_FACET_ID;
    validateFacet(probe);
    return f;
  }
}

/** Adds methods to a service. */
export class ServiceBuilder {
  constructor(
    private readonly b: FacetBuilder,
    readonly service: Service,
  ) {}

  /** Adds a method; the call shape follows from the types ([3, T] makes a side a stream). Returns the method ID. */
  method(name: string, input: TypeRef, output: TypeRef, opts: MethodOptions = {}): number {
    return this.b.addMethod(this.service, name, input, output, 0, opts);
  }

  /** Adds a notification (flag 0x2, output unit). */
  notification(name: string, input: TypeRef, opts: MethodOptions = {}): number {
    return this.b.addMethod(this.service, name, input, T.unit, MethodFlags.notification, opts);
  }
}

/** Builds a schema document from facets (sorted by ID). */
export function makeSchema(name: string, version: string, facets: Facet[], annotations: Annotations = {}): Schema {
  return { format: SCHEMA_FORMAT, name, version, facets: [...facets].sort(byId), annotations: { ...annotations } };
}

