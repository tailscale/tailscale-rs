import { inspect } from "node:util";

import * as native from "../native.js";
import { argError } from "./errors.js";
import { call, checkAddress, checkIp } from "./internal.js";
import { KeyState } from "./keys.js";
import { TcpListener, TcpStream } from "./tcp.js";
import type { AbortOptions, AddressInfo, SocketAddress } from "./types.js";
import { UdpSocket } from "./udp.js";

/** Options for {@link connect}. */
export interface ConnectOptions extends AbortOptions {
  /**
   * Path of a file to load the device's keys from. If the file doesn't exist, new keys are
   * generated and saved to it.
   */
  keyFile?: string;
  /** Auth key to authenticate with. Defaults to the `TS_AUTH_KEY` environment variable. */
  authKey?: string;
  /** URL of the control server to use instead of the default. */
  controlServerUrl?: string | URL;
  /** Hostname to request for this device. */
  hostname?: string;
  /** Tags to request for this device. */
  tags?: string[];
  /** Keys to use for this device, instead of loading them from `keyFile` or generating them. */
  keys?: KeyState;
  /** Whether this device should be ephemeral. */
  ephemeral?: boolean;
}

/** Info about a tailscale node. */
export interface NodeInfo {
  /** Node's id. A string, as it may not fit in a JS number. */
  id: string;
  /** Stable id. */
  stableId: string;
  /** The node's hostname. */
  hostname: string;
  /** The tailnet to which this node belongs. */
  tailnet?: string;
  /** This node's tags. */
  tags: string[];
  /** The node's tailnet IP addresses. */
  tailnetAddress: {
    /** IPv4 address. */
    ipv4: string;
    /** IPv6 address. */
    ipv6: string;
  };
  /** This node's home DERP region. */
  derpRegion?: number;
  /** This node's node key. */
  nodeKey: Buffer;
  /** This node's disco key. */
  discoKey?: Buffer;
  /** This node's machine key. */
  machineKey?: Buffer;
  /** The underlay addresses on which this node is reachable. */
  underlayAddresses: AddressInfo[];
}

/**
 * Connect to a tailnet.
 *
 * ```ts
 * await using dev = await connect({ keyFile: "tsrs_keys.json", authKey });
 * ```
 */
export async function connect(options: ConnectOptions = {}): Promise<Device> {
  const {
    keyFile,
    authKey = process.env.TS_AUTH_KEY,
    controlServerUrl,
    hostname,
    tags,
    keys,
    ephemeral,
    signal,
  } = options;

  if (keys !== undefined && !(keys instanceof KeyState)) {
    throw argError(TypeError, "ERR_INVALID_ARG_TYPE", "keys must be a KeyState");
  }

  const nativeOptions: native.ConnectOptions = {};
  if (keyFile !== undefined) nativeOptions.keyFile = keyFile;
  if (authKey !== undefined && authKey !== "") nativeOptions.authKey = authKey;
  // Throws `ERR_INVALID_URL` if invalid.
  if (controlServerUrl !== undefined)
    nativeOptions.controlServerUrl = new URL(controlServerUrl).href;
  if (hostname !== undefined) nativeOptions.hostname = hostname;
  if (tags !== undefined) nativeOptions.tags = tags;
  if (keys !== undefined) nativeOptions.keys = keys.raw;
  if (ephemeral !== undefined) nativeOptions.ephemeral = ephemeral;

  const dev = await call((cancel) => native.connect(nativeOptions, cancel), signal);
  return Device.fromNative(dev);
}

/** A device connected to a tailnet, created by {@link connect}. */
export class Device implements AsyncDisposable {
  readonly #native: native.Device;
  #closed = false;

  private constructor(dev: native.Device) {
    if (!(dev instanceof native.Device)) {
      throw new TypeError("Illegal constructor");
    }
    this.#native = dev;
  }

  /** @internal */
  static fromNative(dev: native.Device): Device {
    return new Device(dev);
  }

  /**
   * Bind a UDP socket to the given address.
   *
   * `addr.address` must be an IP address: DNS lookup is not yet supported.
   */
  async udpBind(addr: SocketAddress): Promise<UdpSocket> {
    const nativeAddr = checkAddress(addr);
    const sock = await call(() => this.#native.udpBind(nativeAddr));
    return UdpSocket.fromNative(sock);
  }

  /**
   * Listen for TCP connections on the given address.
   *
   * `addr.address` must be an IP address: DNS lookup is not yet supported.
   */
  async tcpListen(addr: SocketAddress): Promise<TcpListener> {
    const nativeAddr = checkAddress(addr);
    const listener = await call(() => this.#native.tcpListen(nativeAddr));
    return TcpListener.fromNative(listener);
  }

  /**
   * Open a TCP connection to the given address.
   *
   * `addr.address` must be an IP address: DNS lookup is not yet supported.
   */
  async tcpConnect(addr: SocketAddress, options: AbortOptions = {}): Promise<TcpStream> {
    const nativeAddr = checkAddress(addr);
    const sock = await call(
      (cancel) => this.#native.tcpConnect(nativeAddr, cancel),
      options.signal,
    );
    return TcpStream.fromNative(sock);
  }

  /** Get the device's IPv4 tailnet address. */
  async ipv4Address(): Promise<string> {
    return call(() => this.#native.ipv4Address());
  }

  /** Get the device's IPv6 tailnet address. */
  async ipv6Address(): Promise<string> {
    return call(() => this.#native.ipv6Address());
  }

  /**
   * Look up a peer by its name, which may be an unqualified hostname or a fully-qualified name.
   *
   * Resolves to `null` if there's no such peer.
   */
  async peerByName(name: string): Promise<NodeInfo | null> {
    if (typeof name !== "string") {
      throw argError(TypeError, "ERR_INVALID_ARG_TYPE", "name must be a string");
    }
    return call(() => this.#native.peerByName(name));
  }

  /** Get this device's node info. */
  async selfNode(): Promise<NodeInfo> {
    return call(() => this.#native.selfNode());
  }

  /**
   * Look up a peer by its tailnet IP address.
   *
   * Resolves to `null` if there's no such peer.
   */
  async peerByTailnetIp(ip: string): Promise<NodeInfo | null> {
    const checked = checkIp(ip, "ip");
    return call(() => this.#native.peerByTailnetIp(checked));
  }

  /**
   * Look up the peer(s) with the most specific route matching the given IP address.
   *
   * If more than one peer has the same route covering the address, more than one result may be
   * returned.
   */
  async peersWithRoute(ip: string): Promise<NodeInfo[]> {
    const checked = checkIp(ip, "ip");
    return call(() => this.#native.peersWithRoute(checked));
  }

  /**
   * Disconnect from the tailnet and shut the device down. Any pending operations are rejected.
   *
   * Sockets created by the device stop working, but should still be closed.
   */
  async close(): Promise<void> {
    this.#closed = true;
    await call(() => this.#native.close());
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  /** Describe this device. */
  toString(): string {
    return `tailscale.Device(${this.#closed ? "closed" : "open"})`;
  }

  [inspect.custom](): string {
    return this.toString();
  }
}
