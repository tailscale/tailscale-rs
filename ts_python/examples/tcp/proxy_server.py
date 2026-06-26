#!/usr/bin/env python3
"""
A TCP tailnet-to-localhost proxy server built with `tailscale-py`.

Listens for incoming TCP connections from the tailnet on a given port, then connects to
a listening TCP socket on localhost on a given port and forwards data between the two
sockets.

Note that the localhost socket must already be open and listening by the time the first
incoming tailnet connection is established.
"""

import argparse
import asyncio
import logging
from pathlib import Path

import tailscale

LOGGER = logging.getLogger("proxy_server")
"""Logger for the TCP proxy server example."""


async def main(
        auth_key: str, key_file: Path, hostname: str, ts_port: int, lh_port: int
) -> None:
    # Connect to the tailnet:
    dev = await tailscale.connect(
        key_file.as_posix(),
        auth_key,
        hostname=hostname,
    )

    listen_addr = (await dev.ipv4_addr(), ts_port)
    target_addr = ("127.0.0.1", lh_port)

    LOGGER.info(
        f"proxying between {listen_addr[0]}:{listen_addr[1]} and {target_addr[0]}:{target_addr[1]}..."
    )
    server = await dev.tcp_proxy_server(listen_addr, target_addr)

    while True:
        try:
            LOGGER.info(
                f"awaiting connection..."
            )
            await server.accept_one()
            LOGGER.info("connection accepted")
        except ConnectionRefusedError:
            LOGGER.info(
                f"connection to {target_addr[0]}:{target_addr[1]} refused, retrying"
            )
            await asyncio.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A TCP tailnet-to-localhost proxy built with `tailscale-py`.",
        usage="TS_RS_EXPERIMENT=this_is_unstable_software %(prog)s [options]",
    )
    parser.add_argument(
        "-a",
        "--auth-key",
        help="auth key to register with tailnet; if not provided, assumed the device "
             "is already registered",
        type=str,
    )
    parser.add_argument(
        "-n",
        "--hostname",
        help="hostname to register device with",
        type=str,
        default="tailscale-py-tcp-proxy",
    )
    parser.add_argument(
        "-k",
        "--key-file",
        help="path to key state file; will be created if it doesn't exist",
        type=Path,
        default="tsrs_keys_tcp_proxy.json",
    )
    parser.add_argument(
        "-p",
        "--tailnet-port",
        help="tailnet TCP port to listen on/proxy to the localhost socket",
        type=int,
        default=8080,
    )
    parser.add_argument(
        "-l",
        "--localhost-port",
        help="localhost TCP port to connect/proxy to the tailnet (must already be "
             "listening)",
        type=int,
        default=8081,
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(
        main(
            args.auth_key,
            args.key_file,
            args.hostname,
            args.tailnet_port,
            args.localhost_port,
        )
    )
