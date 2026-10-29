/**
 * The `code`s of {@link TailscaleError}s.
 *
 * Codes follow Node's conventions: library-specific codes are prefixed `ERR_TAILSCALE_`, and where
 * Node has an equivalent code (e.g. `ECONNRESET`), that's used instead.
 */
export const ErrorCode = {
  /** The control server rejected the auth key. Connect again with a valid key. */
  AuthKeyRejected: "ERR_TAILSCALE_AUTH_KEY_REJECTED",
  /** The key file could not be read or parsed. */
  KeyFileRead: "ERR_TAILSCALE_KEY_FILE_READ",
  /** The key file could not be written. */
  KeyFileWrite: "ERR_TAILSCALE_KEY_FILE_WRITE",
  /** An operation timed out. Retrying may succeed. */
  Timeout: "ERR_TAILSCALE_TIMEOUT",
  /** A connection was reset, or could not be established. Retrying may succeed. */
  ConnectionReset: "ECONNRESET",
  /** The request was rejected, e.g., sending to an IPv6 address from an IPv4 socket. */
  BadRequest: "ERR_TAILSCALE_BAD_REQUEST",
  /** The socket or device has been closed. */
  SocketClosed: "ERR_SOCKET_CLOSED",
  /** An internal error, likely a bug in this library. */
  Internal: "ERR_TAILSCALE_INTERNAL",
} as const;

/** The `code`s of {@link TailscaleError}s. */
export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * An error from a tailscale operation (as opposed to a problem with the arguments passed to it,
 * which are reported as `TypeError`s or `RangeError`s, like Node's own APIs).
 *
 * ```ts
 * try {
 *   await connect({ authKey });
 * } catch (e) {
 *   if (e instanceof TailscaleError && e.code === ErrorCode.AuthKeyRejected) { ... }
 * }
 * ```
 */
export class TailscaleError extends Error {
  /** What kind of error this is. */
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
  }

  static {
    this.prototype.name = "TailscaleError";
  }
}

const ERROR_CODES: ReadonlySet<string> = new Set(Object.values(ErrorCode));

// The native layer can't set an error's `code` directly, so prefixes it to the message instead (see
// `src/error.rs`).
const NATIVE_ERROR = /^([A-Z_]+): ([\s\S]*)$/;

/** Convert an error from the native layer to the error type the public API documents. */
export function convertError(e: unknown): unknown {
  if (!(e instanceof Error)) {
    return e;
  }

  const match = NATIVE_ERROR.exec(e.message);
  if (match === null) {
    return e;
  }

  const [, code = "", message = ""] = match;
  if (code === "ERR_INVALID_ARG_VALUE") {
    return argError(TypeError, code, message);
  }
  if (ERROR_CODES.has(code)) {
    return new TailscaleError(code as ErrorCode, message);
  }
  return e;
}

/** Create an argument error with a `code`, like Node's own argument errors. */
export function argError(
  type: TypeErrorConstructor | RangeErrorConstructor,
  code: string,
  message: string,
): Error & { code: string } {
  return Object.assign(new type(message), { code });
}

/** Whether `e` is the error which a closed socket rejects pending operations with. */
export function isClosedError(e: unknown): boolean {
  return e instanceof TailscaleError && e.code === ErrorCode.SocketClosed;
}
