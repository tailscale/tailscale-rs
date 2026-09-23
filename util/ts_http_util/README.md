# ts_http_util

A collection of utilities for working with HTTP/1.1 and HTTP/2 client connections over plaintext
or TLS streams. Built on top of [`http`], [`hyper`], and [`tokio`] for use with [`tailscale`].

This crate is tailored for our needs, and is probably a poor fit for other use cases. If you're
looking for a general-purpose HTTP client crate, we recommend using [`hyper`] directly, or
looking at [`reqwest`] or [`ureq`].

[`reqwest`]: https://docs.rs/reqwest/latest

[`ureq`]: https://docs.rs/ureq/latest

[`tailscale`]: https://docs.rs/tailscale/latest
