# Examples

This directory contains code examples that use `tailscale-rs` from Rust.

## Requirements

For all of these examples, you'll need:
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

## Axum ([`axum/main.rs`](axum/main.rs))

An `axum`-based HTTP server that serves a simple webpage over the tailnet. This example requires
`tailscale-rs` to be compiled with the `axum` feature:

```sh
$ TS_RS_EXPERIMENT=this_is_unstable_software cargo run --example axum --features axum -- --auth-key $AUTH_KEY --key-file key_file.json
...
INFO axum: http server listening url=http://<tailnet IP>:80/index.html
```

To test, ensure your local Tailscale client is connected to the same tailnet as the `axum` example,
then visit "http://<tailnet IP>:80/index.html" in your browser.

If you can't connect, verify the tailnet policy is configured to allow your local machine access to
the example's tailnet IP address on TCP port 80.

## Peer Ping ([`peer_ping.rs`](peer_ping.rs))

A UDP client that sends "hello" to a tailnet peer on a configurable interval.

To run this example, it's easiest to first determine your local machine's tailnet IP address (with
`ip addr` or similar), then use netcat (`nc`) to listen for incoming messages from the running
example:

```sh
# Terminal 1
$ ip addr
...
2: tailscale0: ...
   inet <tailnet IP>
...
$ nc -lu <tailnet IP> 5678
```

Then, in another terminal, run the example:

```sh
# Terminal 2
$ TS_RS_EXPERIMENT=this_is_unstable_software cargo run --example peer_ping -- --auth-key $AUTH_KEY --key-file key_file.json --peer <tailnet IP>:5678 
...
INFO ts_runtime::multiderp: new home derp region selected region_id=1 latency_ms=12.223305702209473
...
```

Back in the first terminal, you should see "hello" messages appear! If not, verify the tailnet
policy allows the example's tailnet IP address to access your local machine on UDP port 5678. 

## TCP Echo ([`tcp_echo.rs`](tcp_echo.rs))

A TCP server that listens on the tailnet and echoes input back to the sender.

For this example, you can use `telnet` to test the server. First, start the example:

```sh
# Terminal 1
$ TS_RS_EXPERIMENT=this_is_unstable_software cargo run --example tcp_echo -- --auth-key $AUTH_KEY --key-file key_file.json 
...
INFO tcp_echo: listening_addr=<tailnet IP>:1234
...
```

Then, in another terminal, connect to it with `telnet`, type a message, and hit enter:

```sh
# Terminal 2
$ telnet <tailnet IP> 1234
Trying <tailnet IP>...
Connected to <tailnet IP>.
Escape character is '^]'.
hello, tailscale-rs!
hello, tailscale-rs!
```

After hitting enter, you should see your message echoed back to you in `telnet`!

> [!NOTE]
> You may see `telnet` echoing back each character you type, rather than requiring that you hit
> enter; this is good too! This has to deal with the `telnet` client's configuration and whether
> it uses "character at a time" or "old line by line" mode. 

If you can't connect to the example with `telnet`, verify the tailnet policy allows your local
machine to connect to the example's tailnet IP address on TCP port 1234.