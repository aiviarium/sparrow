// @aiviarium/sparrow-rpc: Sparrow RPC for TypeScript.
//
// The main entry point is browser-safe (no Node built-ins). The pipe
// binding, which needs node:child_process, is in "@aiviarium/sparrow-rpc/pipe";
// the WebSocket and in-memory bindings are also exported here.

export * as cbor from './cbor.js';
export { Float, Raw, Tag, CborError } from './cbor.js';
export * as wire from './wire.js';
export * from './status.js';
export * as schema from './schema.js';
export {
  FacetBuilder,
  ServiceBuilder,
  SchemaError,
  SchemaState,
  T,
  field,
  optionalField,
  variant,
  list,
  mapOf,
  optional,
  stream,
  byteStream,
  makeSchema,
  type Facet,
  type Schema,
  type TypeRef,
  type Method,
  type MethodOptions,
} from './schema.js';
export { Codec, ValueError, uuidFromString, uuidToString, type DynamicValue, type UnionValue } from './value.js';
export { sha256, sha256Async } from './sha256.js';
export {
  Session,
  SparrowError,
  Router,
  ClientCall,
  PROTOCOL_VERSION,
  SessionDefaults,
  statusOf,
  realClock,
  type CallContext,
  type Clock,
  type CallOptions,
  type Handler,
  type HandlerMap,
  type MetadataInit,
  type SessionOptions,
} from './session.js';
export { ConnClosedError, type CloseInfo, type Conn, type ConnHandlers } from './transport.js';
export { memPair, type MemConnection } from './transport/mem.js';
export { SUBPROTOCOL, connectWebSocket, webSocketConn, type WebSocketLike } from './transport/websocket.js';
export type { Metadata, MetaKey, Params, Limits, Auth, GoAway, Hello, Welcome } from './wire.js';
export { MetaKeys } from './wire.js';
