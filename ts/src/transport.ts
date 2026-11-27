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

/** One transport connection carrying one session on its shared lane. */
export interface Conn {
  /** The binding's name, for logs: "pipe", "websocket", "mem". */
  readonly binding: string;
  /** Starts delivering messages. Called once, by the session. */
  start(h: ConnHandlers): void;
  /** Sends one whole message. Throws ConnClosedError once the connection is closed. */
  send(msg: Uint8Array): void;
  /** Sets the largest message accepted when reading (this side's maxMessageSize). */
  setReadLimit(n: number): void;
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
