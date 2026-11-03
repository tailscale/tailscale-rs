#!/usr/bin/env -S node --experimental-strip-types
// A UDP sender built with `tailscale-rs`. Sends a datagram to the given peer every second.

import { setTimeout as sleep } from "node:timers/promises";
import { connect, type SocketAddress } from "../../dist/index.js";

const BIND_PORT = 1234;
const MESSAGE = "HELLO";

const [authKey, peerIp, peerPort] = process.argv.slice(2);
if (authKey === undefined || peerIp === undefined || peerPort === undefined) {
  console.error("usage: send.ts <auth_key> <peer_ip> <peer_port>");
  process.exit(1);
}
const peer: SocketAddress = { address: peerIp, port: Number(peerPort) };

// Connect to the tailnet:
const dev = await connect({ keyFile: "tsrs_keys_send.json", authKey });

// Bind a UDP socket on this device's IPv4 address:
const tailnetIpv4 = await dev.ipv4Address();
const udpSock = await dev.udpBind({ address: tailnetIpv4, port: BIND_PORT });
console.log(`[${tailnetIpv4}:${BIND_PORT}] udp bound, local endpoint: ${udpSock.toString()}`);

// Send a message to the peer every second.
for (let count = 1; ; count++) {
  await udpSock.sendTo(peer, MESSAGE);
  const tag = String(count).padStart(4, "0");
  console.log(
    `[${tailnetIpv4}:${BIND_PORT}->${peer.address}:${peer.port}|${tag}] sent message: ${MESSAGE}`,
  );
  await sleep(1000);
}
