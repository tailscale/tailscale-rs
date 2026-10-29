#!/usr/bin/env -S node --experimental-strip-types
// A UDP receiver built with `tailscale-rs`. Receives datagrams from peers and prints their contents.

import { connect } from "../../dist/index.js";

const [authKey, bindPort] = process.argv.slice(2);
if (authKey === undefined || bindPort === undefined) {
  console.error("usage: recv.ts <auth_key> <bind_port>");
  process.exit(1);
}
const port = Number(bindPort);

// Connect to the tailnet:
const dev = await connect({ keyFile: "tsrs_keys_recv.json", authKey });

// Bind a UDP socket on this device's IPv4 address:
const tailnetIpv4 = await dev.ipv4Address();
const udpSock = await dev.udpBind({ address: tailnetIpv4, port });
console.log(`[${tailnetIpv4}:${port}] udp bound, local endpoint: ${udpSock.toString()}`);

// Print each message received.
let count = 0;
for await (const { data, from } of udpSock) {
  const tag = String(++count).padStart(4, "0");
  console.log(
    `[${tailnetIpv4}:${port}<-${from.address}:${from.port}|${tag}] received message: ${data.toString()}`,
  );
}
