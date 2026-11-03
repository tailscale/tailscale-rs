#!/usr/bin/env -S node --experimental-strip-types
// A TCP echo server built with `tailscale-rs`. Sends back each line it receives, upper-cased.

import { createInterface } from "node:readline";
import { connect, type TcpStream } from "../../dist/index.js";

const [authKey, listenPort] = process.argv.slice(2);
if (authKey === undefined || listenPort === undefined) {
  console.error("usage: server.ts <auth_key> <listen_port>");
  process.exit(1);
}
const port = Number(listenPort);

// Connect to the tailnet:
const dev = await connect({ keyFile: "tsrs_keys_server.json", authKey });

// Listen on this device's IPv4 address:
const tailnetIpv4 = await dev.ipv4Address();
const listener = await dev.tcpListen({ address: tailnetIpv4, port });
console.log(`listening: ${listener.toString()}`);

// Close the listener on Ctrl-C, which ends the loop below.
process.once("SIGINT", () => void listener.close());

for await (const conn of listener) {
  void echo(conn);
}
await dev.close();

async function echo(conn: TcpStream): Promise<void> {
  console.log(`accepted: ${conn.toString()}`);
  try {
    // `TcpStream` is a `stream.Duplex`, so works with `readline`, `pipeline`, etc.
    for await (const line of createInterface({ input: conn, crlfDelay: Infinity })) {
      conn.write(`${line.toUpperCase()}\n`);
    }
    console.log(`closed: ${conn.toString()}`);
  } catch (e) {
    console.error(`error: ${conn.toString()}:`, e);
  }
}
