#!/usr/bin/env python3
"""
A UDP sender built with `tailscale-py`. Sends a datagram to the given peer every second.
"""
import argparse
import asyncio
import tailscale

BIND_PORT = 1234
MESSAGE = b'HELLO'

async def main(auth_key: str, peer_ip: str, peer_port: int) -> None:
    # Connect to the tailnet:
    dev = await tailscale.connect('key_file_send.json', auth_key)

    # Bind a UDP socket on this device's IPv4 address:
    tailnet_ipv4 = await dev.ipv4_addr()
    udp_sock = await dev.udp_bind((tailnet_ipv4, BIND_PORT))
    print(f"[{tailnet_ipv4}:{BIND_PORT}] udp bound, local endpoint: {udp_sock.local_endpoint_addr()}")

    # Send a message to the peer every second.
    count = 0
    while True:
        await udp_sock.sendto((peer_ip, peer_port), msg=MESSAGE)
        count += 1
        print(f"[{tailnet_ipv4}:{BIND_PORT}->{peer_ip}:{peer_port}|{count:04}] sent message: {MESSAGE}")
        await asyncio.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UDP sender built with `tailscale-py`",
        usage="TS_RS_EXPERIMENT=this_is_unstable_software %(prog)s [options]"
    )
    parser.add_argument("auth_key", help="auth key to register with tailnet")
    parser.add_argument("peer_ip", help="peer's tailnet IP address")
    parser.add_argument("peer_port", help="peer's UDP port", type=int)
    args = parser.parse_args()

    asyncio.run(main(args.auth_key, args.peer_ip, args.peer_port))