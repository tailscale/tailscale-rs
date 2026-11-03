import { Duplex } from "node:stream";
import { inspect } from "node:util";

import * as native from "../native.js";
import { convertError, isClosedError } from "./errors.js";
import { call, formatAddress } from "./internal.js";
import type { AbortOptions, AddressInfo } from "./types.js";

/**
 * An established TCP connection, created by `Device.tcpConnect` or `TcpListener.accept`.
 *
 * This is a `stream.Duplex`, like `net.Socket`, so it can be piped, read with `for await`, wrapped
 * with `readline`, etc. Data is read as `Buffer`s.
 *
 * Calling `end()` closes the sending half of the connection once written data has been sent, but
 * data can still be read until the peer closes its half. As for a `net.Socket` with
 * `allowHalfOpen: false`, the stream ends its sending half automatically when the peer closes its
 * half.
 */
export class TcpStream extends Duplex {
  readonly #native: native.TcpStream;
  readonly #local: AddressInfo;
  readonly #remote: AddressInfo;

  private constructor(sock: native.TcpStream) {
    if (!(sock instanceof native.TcpStream)) {
      throw new TypeError("Illegal constructor");
    }
    super({ allowHalfOpen: false });
    this.#native = sock;
    this.#local = sock.localAddress();
    this.#remote = sock.remoteAddress();
  }

  /** @internal */
  static fromNative(sock: native.TcpStream): TcpStream {
    return new TcpStream(sock);
  }

  /** The local IP address. */
  get localAddress(): string {
    return this.#local.address;
  }

  /** The local port. */
  get localPort(): number {
    return this.#local.port;
  }

  /** The local address family. */
  get localFamily(): "IPv4" | "IPv6" {
    return this.#local.family;
  }

  /** The remote IP address. */
  get remoteAddress(): string {
    return this.#remote.address;
  }

  /** The remote port. */
  get remotePort(): number {
    return this.#remote.port;
  }

  /** The remote address family. */
  get remoteFamily(): "IPv4" | "IPv6" {
    return this.#remote.family;
  }

  /** The local address of the connection, like `net.Socket.address()`. */
  address(): AddressInfo {
    return { ...this.#local };
  }

  /** @internal */
  override _read(): void {
    // `_read` isn't called again until `push` is, so there's at most one `recv` in flight.
    this.#native.recv().then(
      (chunk) => this.push(chunk),
      (e: unknown) => {
        const err = convertError(e);
        if (isClosedError(err)) {
          // Closed locally, by `destroy()`.
          this.push(null);
        } else {
          this.destroy(err as Error);
        }
      },
    );
  }

  /** @internal */
  override _write(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.#native.sendAll(chunk).then(
      () => {
        callback();
      },
      (e: unknown) => {
        callback(convertError(e) as Error);
      },
    );
  }

  /** @internal */
  override _final(callback: (error?: Error | null) => void): void {
    this.#native.shutdown().then(
      () => {
        callback();
      },
      (e: unknown) => {
        callback(convertError(e) as Error);
      },
    );
  }

  /** @internal */
  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.#native.close();
    callback(error);
  }

  /** Describe this stream. */
  override toString(): string {
    return `tailscale.TcpStream(${formatAddress(this.#local)} -> ${formatAddress(this.#remote)})`;
  }

  [inspect.custom](): string {
    return this.toString();
  }
}

/**
 * A TCP listen socket, created by `Device.tcpListen`.
 *
 * Iterate over the listener to accept connections until it's closed:
 *
 * ```ts
 * for await (const conn of listener) { ... }
 * ```
 */
export class TcpListener implements AsyncIterable<TcpStream>, AsyncDisposable {
  readonly #native: native.TcpListener;
  readonly #address: AddressInfo;

  private constructor(listener: native.TcpListener) {
    if (!(listener instanceof native.TcpListener)) {
      throw new TypeError("Illegal constructor");
    }
    this.#native = listener;
    this.#address = listener.localAddress();
  }

  /** @internal */
  static fromNative(listener: native.TcpListener): TcpListener {
    return new TcpListener(listener);
  }

  /**
   * Accept a new incoming connection, waiting until one arrives.
   *
   * Rejects with a `TailscaleError` with code `ERR_SOCKET_CLOSED` if the listener is closed.
   */
  async accept(options: AbortOptions = {}): Promise<TcpStream> {
    const sock = await call((cancel) => this.#native.accept(cancel), options.signal);
    return TcpStream.fromNative(sock);
  }

  /** The local address this listener is listening on. */
  address(): AddressInfo {
    return { ...this.#address };
  }

  /**
   * Stop listening. Any pending `accept` is rejected, and iteration ends. Connections which have
   * already been accepted are unaffected.
   */
  close(): Promise<void> {
    this.#native.close();
    return Promise.resolve();
  }

  /** Accept connections until the listener is closed. Breaking out of the loop doesn't close it. */
  async *[Symbol.asyncIterator](): AsyncGenerator<TcpStream, void, undefined> {
    for (;;) {
      try {
        yield await this.accept();
      } catch (e) {
        if (isClosedError(e)) {
          return;
        }
        throw e;
      }
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  /** Describe this listener. */
  toString(): string {
    return `tailscale.TcpListener(${formatAddress(this.#address)})`;
  }

  [inspect.custom](): string {
    return this.toString();
  }
}
