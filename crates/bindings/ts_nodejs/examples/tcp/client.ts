#!/usr/bin/env -S node --experimental-strip-types
// A TCP client built with `tailscale-rs`. Sends each line typed to the server, and prints its replies.

import { finished, pipeline } from "node:stream/promises";
import { connect } from "../../dist/index.js";

const [authKey, serverIp, serverPort] = process.argv.slice(2);
if (authKey === undefined || serverIp === undefined || serverPort === undefined) {
  console.error("usage: client.ts <auth_key> <server_ip> <server_port>");
  process.exit(1);
}

// Connect to the tailnet:
const dev = await connect({ keyFile: "tsrs_keys_client.json", authKey });

// Connect to the server, giving up after 10 seconds:
const conn = await dev.tcpConnect(
  { address: serverIp, port: Number(serverPort) },
  { signal: AbortSignal.timeout(10_000) },
);
console.log(`connected: ${conn.toString()}`);

// Send stdin to the server, and print its replies until the server closes the connection (which it
// does once stdin ends).
conn.pipe(process.stdout);
await Promise.all([pipeline(process.stdin, conn), finished(conn)]);
await dev.close();
