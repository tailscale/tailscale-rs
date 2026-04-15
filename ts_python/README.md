# `ts_python`

Python bindings for `tailscale-rs`.

At the moment, this exposes facilities for connecting to a tailnet and binding network sockets that
have access to the tailnet.

## Code Sample

```python
import asyncio
import tailscale


async def main():
    # connect to the tailnet:
    dev = await tailscale.connect('tsrs_state.json', "tskey-auth-$MY_AUTH_KEY")

    # bind a udp socket on this node's ipv4 address:
    tailnet_ipv4 = await dev.ipv4_addr()
    udp_sock = await dev.udp_bind((tailnet_ipv4, 1234))
    print(f'udp bound, local endpoint: {udp_sock.local_endpoint_addr()}')

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

We're not up on pypi, so you can't `pip install tailscale` yet. To use the module, you'll
need to build it. The best way to do that is with [`maturin`](https://www.maturin.rs/):

```sh
# In the project where you want to use the tailscale bindings:
$ python -m virtualenv .venv
$ . .venv/bin/activate
$ pip install maturin

# Then in tailscale-rs:
$ cd ~/tailscale-rs/ts_python # use your path to a local clone of tailscale-rs
$ maturin develop             # build and install python bindings into your virtualenv

$ python -c 'import tailscale' && echo "ready!" # bindings are available!
```

