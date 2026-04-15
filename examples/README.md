# Examples

This directory contains code examples that use `tailscale-rs` from Rust.

## Requirements

For all the examples, you'll need:
- A working Rust development environment that meets the [MSRV](../README.md#msrv-and-edition)
- A [tailnet set up](https://tailscale.com/docs/how-to/quickstart) and Tailscale (the Go client)
installed on your local machine
- An [auth key](https://tailscale.com/docs/features/access-control/auth-keys) registered for the 
tailnet, referred to as `$AUTH_KEY` below
  - For one-off keys, **do not** follow the "Register a node with the auth key" section! The
examples take care of that for you
- A tailnet policy configured to allow access between your local machine and the example code

Also note the `TS_RS_EXPERIMENT=this_is_unstable_software` environment variable in all the examples
below; for an explanation, see [the Caveats section of the README](../README.md#caveats).

## Overview

Brief descriptions and links to each example.

### [Axum](axum)

An `axum`-based HTTP server that serves a simple webpage over the tailnet.

### [Peer Ping](peer_ping)

A UDP client that sends "hello" to a tailnet peer on a configurable interval.

### [TCP Echo](tcp_echo)

A TCP server that listens on the tailnet and echoes input back to the sender.
