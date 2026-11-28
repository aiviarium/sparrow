// Browser transport selection (spec 4.8): tries WebTransport first with a
// short timeout, falls back to WebSocket, and remembers the winner per origin.

import {
  connectWebSocket,
  connectWebTransport,
  type Conn,
  type WebSocketLike,
  type WebTransportConstructor,
} from '@aiviarium/sparrow';

export interface TransportEndpoints {
  webtransport?: string;
  websocket?: string;
}

export interface BrowserTransportOptions {
  /** Timeout for the WebTransport attempt before falling back to WebSocket; default 3000 ms (4.8). */
  webTransportTimeoutMs?: number;
  /** Timeout for the WebSocket attempt; default 10000 ms. */
  webSocketTimeoutMs?: number;
  /** Pinned SHA-256 DER certificate hashes for self-signed WebTransport endpoints. */
  serverCertificateHashes?: Uint8Array[];
  /** Custom WebTransport constructor (for tests or polyfills). */
  WebTransport?: WebTransportConstructor;
  /** Custom WebSocket constructor (for Node <22 or tests). */
  WebSocket?: new (url: string, protocols?: string | string[]) => WebSocketLike;
  /** Per-origin cache of the last transport that succeeded ("webtransport" | "websocket"). */
  preferenceCache?: Map<string, 'webtransport' | 'websocket'>;
  signal?: AbortSignal;
}

export interface BrowserTransportResult {
  conn: Conn;
  binding: 'webtransport' | 'websocket';
  endpoint: string;
}

const defaultPreferenceCache = new Map<string, 'webtransport' | 'websocket'>();

function originKey(endpoints: TransportEndpoints): string {
  const raw = endpoints.webtransport ?? endpoints.websocket ?? '';
  try {
    return new URL(raw).origin;
  } catch {
    return raw;
  }
}

/**
 * Connects over WebTransport first (unless the origin cache prefers WebSocket),
 * falling back to WebSocket on error or timeout (spec 4.8).
 */
export async function connectBrowserTransport(
  endpoints: TransportEndpoints,
  opts: BrowserTransportOptions = {},
): Promise<BrowserTransportResult> {
  const cache = opts.preferenceCache ?? defaultPreferenceCache;
  const key = originKey(endpoints);
  const preferred = cache.get(key);

  const hasWT =
    Boolean(endpoints.webtransport) &&
    Boolean(opts.WebTransport ?? (globalThis as { WebTransport?: WebTransportConstructor }).WebTransport);
  const hasWS = Boolean(endpoints.websocket);

  const tryWT = async (): Promise<BrowserTransportResult> => {
    const url = endpoints.webtransport!;
    const conn = await connectWebTransport(url, {
      WebTransport: opts.WebTransport,
      serverCertificateHashes: opts.serverCertificateHashes,
      timeoutMs: opts.webTransportTimeoutMs ?? 3000,
      signal: opts.signal,
    });
    cache.set(key, 'webtransport');
    return { conn, binding: 'webtransport', endpoint: url };
  };

  const tryWS = async (): Promise<BrowserTransportResult> => {
    const url = endpoints.websocket!;
    const conn = await connectWebSocket(url, {
      WebSocket: opts.WebSocket,
      timeoutMs: opts.webSocketTimeoutMs ?? 10_000,
      signal: opts.signal,
    });
    cache.set(key, 'websocket');
    return { conn, binding: 'websocket', endpoint: url };
  };

  if (preferred === 'websocket' && hasWS) {
    try {
      return await tryWS();
    } catch (wsErr) {
      if (hasWT) {
        try {
          return await tryWT();
        } catch {
          throw wsErr;
        }
      }
      throw wsErr;
    }
  }

  if (hasWT) {
    try {
      return await tryWT();
    } catch (wtErr) {
      if (opts.signal?.aborted) throw wtErr;
      if (hasWS) return await tryWS();
      throw wtErr;
    }
  }

  if (hasWS) {
    return await tryWS();
  }

  throw new Error('transport: no usable WebTransport or WebSocket endpoint available');
}
