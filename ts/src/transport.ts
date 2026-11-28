// The transport abstraction a session runs on. Every binding of this
// library has only the shared lane (pipe 4.7, WebSocket 4.6, in-memory), so
// a Conn moves whole messages on one ordered, bidirectional stream. Leased
// streams (WebTransport, 4.5) are not implemented.

/** How a connection ended. */
export interface CloseInfo {
  /** A core status code (pipe: always unavailable for a remote close; status travels in GoAway). */
  code: number;
  reason: string;
  /** Set when the peer ended the connection. */
  remote: boolean;
}

/** Callbacks a session installs on its connection. */
export interface ConnHandlers {
  /** One whole message, in order. The bytes belong to the receiver. */
  message(msg: Uint8Array): void;
  /**
   * A read failure that is the peer's fault and ends the session: a message
   * above the read limit (TooLargeError) or a malformed frame.
   */
  error(err: Error): void;
  /** The connection ended (the peer finished its direction, or it was closed). Called once. */
  close(info: CloseInfo): void;
}

/** How a leased stream ended. */
export interface StreamCloseInfo {
  /** Core status code (0 for a clean finish). */
  code: number;
  /** Set when the peer ended or reset its direction. */
  remote: boolean;
  /** Set when the stream ended by reset rather than a clean EOF/closeWrite. */
  reset: boolean;
}

/** Callbacks a session installs on a leased stream. */
export interface StreamHandlers {
  /** One whole message, in order. The bytes belong to the receiver. */
  message(msg: Uint8Array): void;
  /** A read failure that is the peer's fault (TooLargeError or FramingError). */
  error(err: Error): void;
  /** The stream ended (peer finished or reset, or locally reset/closed). Called once. */
  close(info: StreamCloseInfo): void;
}

/** One bidirectional leased stream (4.1, 4.2). */
export interface Stream {
  /** Starts delivering messages. Called once, by the session. */
  start(h: StreamHandlers): void;
  /** Sends one whole message. Throws ConnClosedError once write-closed or reset. */
  send(msg: Uint8Array): void;
  /** Sets the largest message accepted when reading. */
  setReadLimit(n: number): void;
  /** Finishes the local sending direction cleanly after queued writes. */
  closeWrite(): void;
  /** Aborts only the local sending direction with a core status code (4.2 rule 5). */
  resetWrite(code: number): void;
  /** Aborts both directions with a core status code. */
  reset(code: number): void;
  /** Set once the stream's sending direction is closed or reset. */
  readonly closed: boolean;
}

/** One transport connection carrying one session on its shared lane (and optionally leased streams). */
export interface Conn {
  /** The binding's name, for logs: "pipe", "websocket", "webtransport", "mem". */
  readonly binding: string;
  /** True when the binding supports leased streams (4.2). */
  readonly leases?: boolean;
  /** Starts delivering messages. Called once, by the session. */
  start(h: ConnHandlers): void;
  /** Sends one whole message. Throws ConnClosedError once the connection is closed. */
  send(msg: Uint8Array): void;
  /** Sets the largest message accepted when reading (this side's maxMessageSize). */
  setReadLimit(n: number): void;
  /** Opens a new leased stream (header 0x01). Only present when leases is true. */
  openStream?(): Promise<Stream>;
  /** Registers a callback for incoming peer-opened leased streams. Only present when leases is true. */
  onStream?(handler: (stream: Stream) => void): void;
  /**
   * Ends the connection. Graceful bindings first finish their own direction
   * and wait briefly for the peer to finish its own, so messages in flight are
   * not lost (5.6). WebSocket carries code and reason in the close frame; the
   * pipe binding carries neither. Idempotent.
   */
  close(code: number, reason: string): Promise<void>;
  /** Set once the connection is closed or closing. */
  readonly closed: boolean;
}

/** Sending on a closed connection. */
export class ConnClosedError extends Error {
  constructor(message = 'transport: connection closed') {
    super(message);
    this.name = 'ConnClosedError';
  }
}
