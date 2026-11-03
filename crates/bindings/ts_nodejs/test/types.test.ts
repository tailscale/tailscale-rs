// Compile-time checks of the package's type definitions, enforced by `npm run typecheck`.
// The functions here are never called; they only need to type-check.

import type { Duplex } from "node:stream";
import { test } from "node:test";

import {
  type AddressInfo,
  connect,
  type ConnectOptions,
  type Datagram,
  Device,
  ErrorCode,
  KeyState,
  type NodeInfo,
  type SocketAddress,
  TailscaleError,
  TcpListener,
  TcpStream,
  UdpSocket,
} from "../dist/index.js";

type Equals<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
function assertType<T extends true>(): T | void {}

// Classes created by the library have no public constructor.
export function constructors(): void {
  // @ts-expect-error Device has a private constructor.
  new Device();
  // @ts-expect-error UdpSocket has a private constructor.
  new UdpSocket();
  // @ts-expect-error TcpListener has a private constructor.
  new TcpListener();
  // @ts-expect-error TcpStream has a private constructor.
  new TcpStream();

  new KeyState();
  new KeyState({ machine: new Uint8Array(32), networkLock: Buffer.alloc(32) });
}

// Internal members aren't part of the declared API.
export function internals(dev: Device, keys: KeyState): void {
  // @ts-expect-error Internal factory.
  Device.fromNative;
  // @ts-expect-error Internal accessor.
  keys.raw;
  void dev;
}

export async function api(): Promise<void> {
  assertType<Equals<ReturnType<typeof connect>, Promise<Device>>>();

  // Resources can be disposed of with `await using` (not used here, as Node 22 can't parse it).
  const disposables: AsyncDisposable[] = [] as (Device | UdpSocket | TcpListener | TcpStream)[];
  void disposables;

  const options: ConnectOptions = {
    keyFile: "keys.json",
    authKey: "tskey-auth-xyz",
    controlServerUrl: new URL("https://controlplane.tailscale.com"),
    hostname: "host",
    tags: ["tag:example"],
    keys: new KeyState(),
    ephemeral: true,
    signal: AbortSignal.timeout(1000),
  };
  const dev = await connect(options);
  await connect();
  // @ts-expect-error Options are passed as an object.
  await connect("keys.json", "tskey-auth-xyz");

  assertType<Equals<Awaited<ReturnType<Device["ipv4Address"]>>, string>>();
  assertType<Equals<Awaited<ReturnType<Device["peerByName"]>>, NodeInfo | null>>();
  assertType<Equals<Awaited<ReturnType<Device["peersWithRoute"]>>, NodeInfo[]>>();

  const addr: SocketAddress = { address: "100.64.0.1", port: 1234 };
  // @ts-expect-error Ports are numbers.
  await dev.udpBind({ address: "100.64.0.1", port: "1234" });

  const udp = await dev.udpBind(addr);
  await udp.sendTo(addr, Buffer.from("hi"));
  await udp.sendTo(addr, new Uint8Array([1, 2, 3]));
  await udp.sendTo(addr, "hi");
  const datagram: Datagram = await udp.recvFrom({ signal: AbortSignal.timeout(1000) });
  assertType<Equals<typeof datagram.data, Buffer>>();
  assertType<Equals<typeof datagram.from, AddressInfo>>();
  assertType<Equals<ReturnType<UdpSocket["address"]>, AddressInfo>>();
  for await (const { data } of udp) {
    assertType<Equals<typeof data, Buffer>>();
  }

  const listener = await dev.tcpListen(addr);
  for await (const conn of listener) {
    assertType<Equals<typeof conn, TcpStream>>();
  }
  const stream: Duplex = await listener.accept({ signal: AbortSignal.timeout(1000) });
  void stream;

  const conn = await dev.tcpConnect(addr, { signal: AbortSignal.timeout(1000) });
  assertType<Equals<typeof conn.remoteAddress, string>>();
  assertType<Equals<typeof conn.remotePort, number>>();
  assertType<Equals<ReturnType<TcpStream["address"]>, AddressInfo>>();
  conn.end("bye");

  const node = await dev.selfNode();
  assertType<Equals<typeof node.id, string>>();
  assertType<Equals<typeof node.tailnet, string | undefined>>();
  assertType<Equals<typeof node.tailnetAddress.ipv4, string>>();
  assertType<Equals<typeof node.nodeKey, Buffer>>();
  assertType<Equals<typeof node.underlayAddresses, AddressInfo[]>>();

  const keys = KeyState.fromJSON(new KeyState().toJSON());
  assertType<Equals<typeof keys.machine, Buffer>>();

  try {
    await dev.close();
  } catch (e) {
    if (e instanceof TailscaleError) {
      assertType<Equals<typeof e.code, ErrorCode>>();
    }
  }
  const code: ErrorCode = ErrorCode.AuthKeyRejected;
  const literal: ErrorCode = "ECONNRESET";
  // @ts-expect-error Unknown error code.
  const bad: ErrorCode = "NotAnErrorCode";
  void code;
  void literal;
  void bad;
}

test("type definitions type-check", () => {});
