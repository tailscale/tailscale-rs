# Examples

This directory contains Python examples that use `tailscale-py`.

## Requirements

For all the examples, you'll need:
- A working Python 3.12+ installation you can install packages into
- A [tailnet set up](https://tailscale.com/docs/how-to/quickstart) and Tailscale (the Go client)
  installed on your local machine
- Two [auth keys](https://tailscale.com/docs/features/access-control/auth-keys) registered for the
  tailnet, referred to as `$AUTH_KEY_1` and `$AUTH_KEY_2` in the examples 
    - For one-off keys, **do not** follow the "Register a node with the auth key" section! The
      examples take care of that for you
    - If you prefer, you can use a reusable auth key rather than two auth keys
- A tailnet policy configured to allow access between your local machine and the example code, and
between the examples themselves

Also note the `TS_RS_EXPERIMENT=this_is_unstable_software` environment variable is required for all
the examples below; for an explanation, see [the Caveats section of the README](../../README.md#caveats).

## [UDP](udp)

A UDP sender and receiver. The sender sends UDP datagrams to the receiver over the tailnet.