# Tailscale

[![docs.rs](https://img.shields.io/docsrs/tailscale-rs)](https://docs.rs/tailscale-rs)
[![crates.io version](https://img.shields.io/crates/v/tailscale-rs)](https://crates.io/crates/tailscale-rs)

https://tailscale.com

This repository is an experimental, preview implementation of Tailscale components in Rust.

> [!CAUTION]
> This software is unstable and insecure.
>
> We welcome enthusiasm and interest, but please **do not** build production software using these
> libraries or rely on them for data privacy until we have a chance to batten down some hatches.
>
> See [caveats](#caveats) for more details.

## Getting Started

`tailscale-rs` isn't available on `crates.io` yet (Rust's package repository). To add it as a git
dependency, add this dependency line to your `Cargo.toml`:

```toml
[dependencies]
tailscale = { git = "ssh://git@github.com/tailscale/tailscale-rs.git" } # requires clone access
```

Examples of using the `tailscale` crate can be found in `examples/`.

For instructions on how to run tests, lints, etc., see [CONTRIBUTING.md](CONTRIBUTING.md).

### Axum example

To run the `axum` example, which runs an HTTP server on the tailnet hosting a simple test page:

```sh
$ cargo run --example axum -- -k $AUTH_KEY -s state.json
...
INFO axum: http server listening url=http://$TAILNET_IP:80/index.html
```

If your computer is running Tailscale on the same tailnet, you can visit
`http://$TAILNET_IP/index.html` in your browser to see the page.

### Code sample

Example binding a UDP socket and sending periodic pings:

```rust
use core::{
    time::Duration,
    net::Ipv4Addr,
    error::Error,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Open a new connection to tailscale
    let dev = tailscale::Device::new(
        Default::default(), // control config
        Some("YOUR_AUTH_KEY_HERE".to_owned()),
        Default::default(), // key state: WARNING, this creates a throwaway node identity
    ).await?;

    // Bind a UDP socket on our tailnet IP, port 1234
    let sock = dev.udp_bind((dev.ipv4().await?, 1234).into()).await?;

    // Send a packet containing "ping" to 100.64.0.1:5678 once per second
    loop {
        sock.send_to((Ipv4Addr::new(100, 64, 0, 1), 5678).into(), b"ping").await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
```

## Caveats

This software is still a work-in-progress! We are providing it in the open at this stage out of a
belief in open-source and to see where the community runs with it, but please be aware of a few
important considerations:

- This implementation contains unaudited cryptography and hasn't undergone a comprehensive security
  analysis. Conservatively, assume there could be a critical security hole meaning anything you send
  or receive could be in the clear on the public Internet.
- There are no compatibility guarantees at the moment. This is early-days software &mdash; we may
  break dependent code in order to get things right.
- We currently rely on DERP relays for all communication. Direct connections via NAT holepunching
  will be a seamless upgrade in the future, but for now, this puts a cap on data throughput.

## MSRV and Edition

The current MSRV is 1.93.1. The current edition is Rust 2024.

`tailscale-rs` has a rolling MSRV (Minimum Supported Rust Version) policy to support the current
and previous Rust compiler versions, and the latest
[edition of Rust](https://doc.rust-lang.org/edition-guide/editions/index.html).

We may lag the latest version/edition in rare cases for our dependencies to catch up and for us to
perform any necessary fixes.

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
