// @aiviarium/sparrow: Sparrow for TypeScript.
//
// The main entry point is browser-safe (no Node built-ins). The pipe
// binding, which needs node:child_process, is in "@aiviarium/sparrow/pipe";
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
export { ConnClosedError, type CloseInfo, type Conn, type ConnHandlers, type Stream, type StreamCloseInfo, type StreamHandlers } from './transport.js';
export { memLeasedPair, memPair, type MemConnection, type MemLeasedConnection } from './transport/mem.js';
export { SUBPROTOCOL, connectWebSocket, webSocketConn, type WebSocketLike } from './transport/websocket.js';
export {
  connectWebTransport,
  webTransportConn,
  type ConnectWebTransportOptions,
  type WebTransportBidiStreamLike,
  type WebTransportConnOptions,
  type WebTransportConstructor,
  type WebTransportHash,
  type WebTransportLike,
} from './transport/webtransport.js';
export type { Metadata, MetaKey, Params, Limits, Auth, GoAway, Hello, Welcome } from './wire.js';
export { MetaKeys } from './wire.js';
