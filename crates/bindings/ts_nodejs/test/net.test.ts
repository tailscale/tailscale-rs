// Tests which need a tailnet. Like the Rust tests, they only run if `TS_RS_TEST_NET=1`, and need a
// reusable auth key in `TS_RS_TEST_AUTHKEY`.

import assert from "node:assert/strict";
import { once } from "node:events";
import { after, before, test } from "node:test";
import { text } from "node:stream/consumers";

import { connect, type Device, ErrorCode, KeyState } from "../dist/index.js";

const authKey = process.env.TS_RS_TEST_AUTHKEY;
const skip = process.env.TS_RS_TEST_NET !== "1" || authKey === undefined;

let devices: Device[] = [];
let server: Device;
let client: Device;
let serverIp: string;

before(
  async () => {
    if (skip) return;
    const options = { authKey, ephemeral: true, signal: AbortSignal.timeout(60_000) };
    const results = await Promise.allSettled([
      connect({ ...options, keys: new KeyState() }),
      connect({ ...options, keys: new KeyState() }),
    ]);
    devices = results.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []));
    for (const r of results) if (r.status === "rejected") throw r.reason;
    [server, client] = devices as [Device, Device];
    serverIp = await server.ipv4Address();
  },
  { timeout: 90_000 },
);

after(async () => {
  await Promise.all(devices.map((dev) => dev.close()));
});

test("UDP datagrams are delivered", { skip, timeout: 30_000 }, async () => {
  const recv = await server.udpBind({ address: serverIp, port: 5000 });
  const send = await client.udpBind({ address: await client.ipv4Address(), port: 5000 });

  // Datagrams may be dropped while the devices find each other, so keep sending until one arrives.
  const interval = setInterval(() => void send.sendTo(recv.address(), "hello"), 200);
  try {
    const { data, from } = await recv.recvFrom();
    assert.equal(data.toString(), "hello");
    assert.deepEqual(from, send.address());
  } finally {
    clearInterval(interval);
    await send.close();
    await recv.close();
  }
});

test("closing a UDP socket ends iteration", { skip, timeout: 30_000 }, async () => {
  const sock = await server.udpBind({ address: serverIp, port: 5001 });
  const iteration = (async () => {
    for await (const _ of sock) {
      assert.fail("unexpected datagram");
    }
  })();
  const recv = assert.rejects(sock.recvFrom(), {
    name: "TailscaleError",
    code: ErrorCode.SocketClosed,
  });
  await sock.close();
  await iteration;
  await recv;
});

test("aborting recvFrom rejects with the signal's reason", { skip, timeout: 30_000 }, async () => {
  const sock = await server.udpBind({ address: serverIp, port: 5002 });
  try {
    await assert.rejects(sock.recvFrom({ signal: AbortSignal.timeout(100) }), {
      name: "TimeoutError",
    });
  } finally {
    await sock.close();
  }
});

test("TCP streams carry data both ways and end", { skip, timeout: 30_000 }, async () => {
  const listener = await server.tcpListen({ address: serverIp, port: 5003 });
  const echo = (async () => {
    for await (const conn of listener) {
      conn.pipe(conn);
    }
  })();

  const conn = await client.tcpConnect(listener.address(), { signal: AbortSignal.timeout(20_000) });
  assert.equal(conn.remoteAddress, serverIp);
  assert.equal(conn.remotePort, 5003);

  conn.write("hello, ");
  conn.write(Buffer.from("world"));
  let reply = "";
  for await (const chunk of conn) {
    reply += String(chunk);
    if (reply.length >= "hello, world".length) {
      // Breaking out of the loop destroys the stream, closing the connection.
      break;
    }
  }
  assert.equal(reply, "hello, world");
  assert.ok(conn.destroyed);

  await listener.close();
  await echo;
});

test("TCP streams end when the remote closes", { skip, timeout: 30_000 }, async () => {
  const listener = await server.tcpListen({ address: serverIp, port: 5004 });
  const accepted = listener.accept();
  const conn = await client.tcpConnect(listener.address());
  const remote = await accepted;

  remote.end("bye");
  assert.equal(await text(conn), "bye");
  await once(conn, "close");

  await listener.close();
});

test("TCP streams can still be read after end()", { skip, timeout: 30_000 }, async () => {
  const listener = await server.tcpListen({ address: serverIp, port: 5005 });
  const accepted = listener.accept();
  const conn = await client.tcpConnect(listener.address());
  const remote = await accepted;

  // The remote echoes what it receives, and ends once the client has.
  remote.pipe(remote);
  conn.end("hello");
  assert.equal(await text(conn), "hello");

  await listener.close();
});
