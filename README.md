# tailscale-rs

[![docs.rs](https://img.shields.io/docsrs/tailscale)](https://docs.rs/tailscale)
[![crates.io version](https://img.shields.io/crates/v/tailscale)](https://crates.io/crates/tailscale)

https://tailscale.com

`tailscale-rs` is a work-in-progress Tailscale library written in Rust, with language bindings to
C, Elixir, and Python.

> [!CAUTION]
> This software is unstable and insecure.
>
> We welcome enthusiasm and interest, but please **do not** build production software using these
> libraries or rely on it for data privacy until we have a chance to batten down some hatches
> and complete a third-party audit.
>
> See [Caveats](#caveats) for more details.

## Getting Started

The following instructions are for Rust! For other languages, see the language-specific README:
- [C](ts_ffi/README.md)
- [Elixir](ts_elixir/README.md)
- [Python](ts_python/README.md) 

Add this dependency line to your `Cargo.toml`:

```toml
[dependencies]
tailscale = { version = "0.2" }
```

Examples of using the `tailscale` crate can be found in [`examples/`](examples/README.md).

For instructions on how to run tests, lints, etc., see [CONTRIBUTING.md](CONTRIBUTING.md). For the high-level architecture and
repository layout, see [ARCHITECTURE.md](ARCHITECTURE.md).

### Code sample

A simple UDP client that periodically sends messages to a tailnet peer at `100.64.0.1:5678`:

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
- The `TS_RS_EXPERIMENT` environment variable is required to be set to `this_is_unstable_software`
  for all code linked against `tailscale-rs`; this includes Rust, C, Elixir, and Python code. We'll
  remove this requirement after a third-party code/cryptography audit and any necessary fixes.

## Versioning, Releases, and Compatability

We follow semver and aim to make a point release roughly monthly. Since we are pre-1.0, we make no
backwards-compatability guarantees. We are aiming to have a stable 1.0 release as soon as we can, but
we currently don't have a timeline.

## MSRV and Edition

The current MSRV is 1.93.1. The current edition is Rust 2024.

`tailscale-rs` has a rolling MSRV (Minimum Supported Rust Version) policy to support the current
and previous Rust compiler versions, and the latest
[edition of Rust](https://doc.rust-lang.org/edition-guide/editions/index.html).

We may lag the latest version/edition in rare cases for our dependencies to catch up and for us to
perform any necessary fixes.

## Platform Support

We support the following platforms and architectures:

- Linux (`x86_64`/`ARM64`)
- macOS (`ARM64`)

## Status

`tailscale-rs` is a work-in-progress - we're still rapidly iterating, fixing bugs, and adding new
features. We aim to keep this section up-to-date, but our [issue tracker](https://github.com/tailscale/tailscale-rs/issues)
is the best way to see the latest updates.

### Implemented

These are features that we currently implement:

- Basics
  - Create TCP and UDP sockets on the tailnet
  - Communicate with peers via public DERP relays
  - Communicate with the Tailscale Go client, `tsnet`, and `libtailscale`
- Language support
  - Rust API
  - C, Elixir, and Python bindings

### Coming Soon

These are features or efforts we have in the pipeline and are actively working towards, but provide
no guarantees on timeline or completion:

- Direct connections (NAT traversal, STUN, and Disco)
- Peer lookups (addressing peers by hostname)
- Third-party code and cryptography audit
- Official Windows support

### Unsupported

This is an incomplete list of features in the Tailscale Go client, `tsnet`, and/or `libtailscale`
that we currently *do not* support. We'd like to add all of these eventually! If there's something
on this list you'd like to see supported, or something _not_ on this list you're not sure about,
please open an issue!

<details>
<summary>
Unsupported features
</summary>

- Networking
  - Peer relays
  - Exit Nodes (either being one, or using one)
  - MagicDNS
  - Private DERP relays
  - Split DNS
  - Subnet Routers (either being one, or using one)
- Platforms
  - AIX
  - Android
  - BSDs
  - iOS
  - Plan9
  - QNAP
  - Synology DSM
- Observability
  - Client Metrics
  - Endpoint Collection
  - Device Posture Collection
  - Log Streaming
  - Network Flow Logs
- Other Features
  - Application Capabilities
  - Automatic Key Rotation
  - HTTPS Certificates
  - Kubernetes
  - Mullvad VPN
  - Node Sharing
  - Taildrive
  - Taildrop
  - Tailnet Lock
  - Tailscale Funnel
  - Tailscale Serve
  - Tailscale SSH
  - Tailscale Services
  - Webhooks
- Any other features not listed in "Implemented" or "Coming Soon"

</details>

## Legal

WireGuard is a registered trademark of Jason A. Donenfeld.
