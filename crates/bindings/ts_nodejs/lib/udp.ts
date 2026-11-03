import { inspect } from "node:util";

import * as native from "../native.js";
import { isClosedError } from "./errors.js";
import { call, checkAddress, checkData, formatAddress } from "./internal.js";
import type { AbortOptions, AddressInfo, SocketAddress } from "./types.js";

/** A datagram received from a {@link UdpSocket}. */
export interface Datagram {
  /** The datagram's payload. */
  data: Buffer;
  /** The address the datagram was sent from. */
  from: AddressInfo;
}

/**
 * A tailscale UDP socket, created by `Device.udpBind`.
 *
 * Iterate over the socket to receive datagrams until it's closed:
 *
 * ```ts
 * for await (const { data, from } of sock) { ... }
 * ```
 */
export class UdpSocket implements AsyncIterable<Datagram>, AsyncDisposable {
  readonly #native: native.UdpSocket;
  readonly #address: AddressInfo;

  private constructor(sock: native.UdpSocket) {
    if (!(sock instanceof native.UdpSocket)) {
      throw new TypeError("Illegal constructor");
    }
    this.#native = sock;
    this.#address = sock.localAddress();
  }

  /** @internal */
  static fromNative(sock: native.UdpSocket): UdpSocket {
    return new UdpSocket(sock);
  }

  /**
   * Send a datagram to the given address. Strings are sent UTF-8 encoded.
   *
   * `addr.address` must be an IP address: DNS lookup is not yet supported.
   */
  async sendTo(addr: SocketAddress, data: string | Uint8Array): Promise<void> {
    const nativeAddr = checkAddress(addr);
    const nativeData = checkData(data);
    return call(() => this.#native.sendTo(nativeAddr, nativeData));
  }

  /**
   * Receive a datagram from the socket.
   *
   * Rejects with a `TailscaleError` with code `ERR_SOCKET_CLOSED` if the socket is closed.
   */
  async recvFrom(options: AbortOptions = {}): Promise<Datagram> {
    return call((cancel) => this.#native.recvFrom(cancel), options.signal);
  }

  /** The local address this socket is bound to. */
  address(): AddressInfo {
    return { ...this.#address };
  }

  /** Close the socket. Any pending `recvFrom` is rejected, and iteration ends. */
  close(): Promise<void> {
    this.#native.close();
    return Promise.resolve();
  }

  /** Receive datagrams until the socket is closed. Breaking out of the loop doesn't close it. */
  async *[Symbol.asyncIterator](): AsyncGenerator<Datagram, void, undefined> {
    for (;;) {
      try {
        yield await this.recvFrom();
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

  /** Describe this socket. */
  toString(): string {
    return `tailscale.UdpSocket(${formatAddress(this.#address)})`;
  }

  [inspect.custom](): string {
    return this.toString();
  }
}
