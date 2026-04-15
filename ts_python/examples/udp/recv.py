#!/usr/bin/env python3
"""
A UDP receiver built with `tailscale-py`. Receives datagrams from peers and prints their contents.
"""
import argparse
import asyncio
import tailscale

async def main(auth_key: str, bind_port: int) -> None:
    # Connect to the tailnet:
    dev = await tailscale.connect('key_file_recv.json', auth_key)

    # Bind a UDP socket on this device's IPv4 address:
    tailnet_ipv4 = await dev.ipv4_addr()
    udp_sock = await dev.udp_bind((tailnet_ipv4, bind_port))
    print(f"[{tailnet_ipv4}:{bind_port}] udp bound, local endpoint: {udp_sock.local_endpoint_addr()}")

    # Wait for a message and print it, then repeat.
    count = 0
    while True:
        (msg, remote) = await udp_sock.recvfrom()
        count += 1
        (peer_ip, peer_port) = (f"{remote[0]}", remote[1])
        print(f"[{tailnet_ipv4}:{bind_port}<-{peer_ip}:{peer_port}|{count:04}] received message: {msg}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UDP receiver built with `tailscale-py`",
        usage="TS_RS_EXPERIMENT=this_is_unstable_software %(prog)s [options]"
    )
    parser.add_argument("auth_key", help="auth key to register with tailnet")
    parser.add_argument("bind_port", help="local UDP port to bind", type=int)
    args = parser.parse_args()

    asyncio.run(main(args.auth_key, args.bind_port))