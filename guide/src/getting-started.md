# Getting started

tailscale-rs is a library for implementing Tailscale clients. It is written in Rust and is available as a Rust crate. It has bindings for the following languages:

- [C](https://github.com/tailscale/tailscale-rs/blob/main/crates/bindings/ts_ffi/README.md)
- [Elixir](https://github.com/tailscale/tailscale-rs/blob/main/crates/bindings/ts_elixir/README.md)
- [Python](https://github.com/tailscale/tailscale-rs/blob/main/crates/bindings/ts_python/README.md)

The following instructions are for Rust, see the links above for other languages.

You'll need Rust installed on your system. Then to add tailscale-rs as a dependency to your project, use `cargo add tailscale`, or add `tailscale = { version = "0.7" }` to your dependencies in `Cargo.toml`.


### Code sample

Here's a small example, a simple UDP client that periodically sends messages to a tailnet peer (at `100.64.0.1:5678`). You'll need an existing tailnet (see these [docs](https://tailscale.com/docs/how-to/quickstart) for how to get one setup) and to create an [auth key](https://tailscale.com/docs/features/access-control/auth-keys) to access it.

In `Cargo.toml`:

```toml
{{#include ../examples/udp-ping/Cargo.toml}}
```

In `src/main.rs`:

```rust
{{#include ../examples/udp-ping/src/main.rs}}
```

More examples of using the tailscale-rs can be found in the [repository](https://github.com/tailscale/tailscale-rs/blob/main/examples).
