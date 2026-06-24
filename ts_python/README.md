# `ts_python`

Python bindings for `tailscale-rs`.

At the moment, this exposes facilities for connecting to a tailnet and binding network sockets that
have access to the tailnet.

## Code Sample

```python
#!/usr/bin/env python3

import asyncio
import tailscale

async def main():
    # connect to the tailnet:
    dev = await tailscale.connect('tsrs_keys.json', "tskey-auth-$MY_AUTH_KEY")

    # bind a udp socket on this node's ipv4 address:
    tailnet_ipv4 = await dev.ipv4_addr()
    udp_sock = await dev.udp_bind((tailnet_ipv4, 1234))
    print(f'udp bound, local endpoint: {udp_sock.local_addr()}')

    # send a message to a peer once per second
    while True:
        await udp_sock.sendto(('1.2.3.4', 5678), msg=b"HELLO")
        print("sent message to peer")
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
```

To run this demo:

```console
$ TS_RS_EXPERIMENT=this_is_unstable_software python demo.py
```

## Building and Usage

The easiest way to get the library is through PyPI:

```shell
$ pip install tailscale-py
```

## Developing

This package uses [`uv`](). All other tooling (`maturin`, `ruff`, etc.) is managed by `uv`.

### Setup

1. Install an appropriate Rust toolchain for your platform. [See here](../README.md#msrv-and-edition)
   for supported toolchain versions.
2. [Install `uv`](https://docs.astral.sh/uv/getting-started/installation/).
3. Clone the `tailscale-rs` repository.
4. Create, activate, and populate a virtual environment for `ts_python` development:

```sh
# At the root of your tailscale-rs checkout:
~/tailscale-rs $ cd ts_python

# Create a virtual environment for ts_python development.
~/tailscale-rs/ts_python $ uv venv
...
Activate with: source .venv/bin/activate

# Activate the new virtual environment.
~/tailscale-rs/ts_python $ source .venv/bin/activate

# Install runtime and dev dependencies (for generating type stubs, testing, etc.).
(ts_python) ~/tailscale-rs/ts_python $ uv sync --dev
...
```

### Formatting

We use `ruff` (via `uv`) to format the Python in our codebase:

```sh
~/tailscale-rs/ts_python $ uv format --preview-features format
...
4 files reformatted
```

### Generating Type Stubs

The type stubs in `ts_python/python/tailscale/_internal.pyi` need to be generated any time the Rust
source code (in `ts_python/src/`) changes. To re-generate the stubs:

```sh
# Make sure ts_python is built/up-to-date and maturin is installed.
~/tailscale-rs/ts_python $ uv sync --dev
...
~/tailscale-rs/ts_python $ maturin generate-stubs --out python/tailscale
🍹 Building a mixed python/rust project
...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.09s

# The stubs are typically not properly formatted, so format them.
~/tailscale-rs/ts_python $ uv format --preview-features format
```

Currently, you need to **manually check the generated type stubs** and add any missing imports by
hand.