// Status codes (spec section 8) and their transport mappings.

/** Core status codes. Codes 0-16 match gRPC. */
export const Status = {
  ok: 0,
  cancelled: 1,
  unknown: 2,
  invalid_argument: 3,
  deadline_exceeded: 4,
  not_found: 5,
  already_exists: 6,
  permission_denied: 7,
  resource_exhausted: 8,
  failed_precondition: 9,
  aborted: 10,
  out_of_range: 11,
  unimplemented: 12,
  internal: 13,
  unavailable: 14,
  data_loss: 15,
  unauthenticated: 16,
  protocol_error: 17,
  schema_mismatch: 18,
  unsupported_version: 19,
  not_ready: 20,
  going_away: 21,
  message_too_large: 22,
} as const;

export type StatusName = keyof typeof Status;

/** The highest core status code; 23-31 are reserved for later core versions. */
export const MAX_CORE_STATUS = 31;

const NAMES: string[] = Object.keys(Status);

/** Retry advice from the table of section 8. */
export const RETRY: Record<StatusName, string> = {
  ok: '-',
  cancelled: 'no',
  unknown: 'maybe',
  invalid_argument: 'no',
  deadline_exceeded: 'with a longer deadline',
  not_found: 'no',
  already_exists: 'no',
  permission_denied: 'no',
  resource_exhausted: 'with backoff',
  failed_precondition: 'no',
  aborted: 'yes',
  out_of_range: 'no',
  unimplemented: 'no',
  internal: 'no',
  unavailable: 'with backoff',
  data_loss: 'no',
  unauthenticated: 'after re-auth',
  protocol_error: 'no',
  schema_mismatch: 'after reloading the schema',
  unsupported_version: 'no',
  not_ready: 'yes',
  going_away: 'yes, on a new session',
  message_too_large: 'no',
};

/** The name of a core status code, or undefined for reserved and non-core codes. */
export function statusName(code: number): StatusName | undefined {
  return NAMES[code] as StatusName | undefined;
}

/** A readable name for any status: the core name, or "status(N)". */
export function describeStatus(code: number): string {
  return statusName(code) ?? (code <= MAX_CORE_STATUS ? `reserved(${code})` : `status(${code})`);
}

/** Looks up a core status code by name. */
export function statusByName(name: string): number | undefined {
  return Object.prototype.hasOwnProperty.call(Status, name) ? Status[name as StatusName] : undefined;
}

/** Reports whether a code is a core code (0-31): only these travel in Cancel, GoAway, AuthStatus and closes. */
export function isCoreStatus(code: number): boolean {
  return Number.isInteger(code) && code >= 0 && code <= MAX_CORE_STATUS;
}

/** Longest close reasons: WebSocket close frames and WebTransport session closes. */
export const MAX_WEBSOCKET_REASON = 123;
export const MAX_WEBTRANSPORT_REASON = 1024;

/** The WebSocket close code for a core status: 1000 for ok, 4000 + code otherwise. */
export function webSocketCloseCode(code: number): number {
  if (!isCoreStatus(code)) throw new RangeError(`status ${code} is not a core code`);
  return code === 0 ? 1000 : 4000 + code;
}

/** The core status a WebSocket close code carries, if any. */
export function fromWebSocketCloseCode(code: number): number | undefined {
  if (code === 1000) return 0;
  if (code > 4000 && code <= 4000 + MAX_CORE_STATUS) return code - 4000;
  return undefined;
}

/** Cuts a reason to at most max bytes of UTF-8, at a character boundary. */
export function truncateReason(reason: string, max: number): string {
  const b = new TextEncoder().encode(reason);
  if (b.length <= max) return reason;
  let k = max;
  while (k > 0 && (b[k] & 0xc0) === 0x80) k--;
  return new TextDecoder().decode(b.subarray(0, k));
}
