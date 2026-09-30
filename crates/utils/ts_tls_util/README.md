# ts_tls_util

A small set of utility functions for establishing Transport Layer Security
(TLS) streams over existing transport-layer connections. Built on top of [`rustls`],
[`tokio_rustls`], and [`webpki_roots`] for use with [`tailscale`].

This crate is tailored for our needs, and is probably a poor fit for other use cases. If you're
looking for a general-purpose TLS crate, we recommend using [`rustls`] and/or [`tokio_rustls`]
directly, or [`native-tls`].

[`native-tls`]: https://docs.rs/native-tls/latest

[`rustls`]: https://docs.rs/rustls/latest

[`tailscale`]: https://docs.rs/tailscale/latest

## Root Certificates

`ts_tls_util` uses [`webpki_roots::TLS_SERVER_ROOTS`] as the set of root certificates to form
a root-of-trust. These are the same root certificates trusted by Mozilla. This crate currently
**does not** check Certificate Revocation Lists (CRLs) to determine if any of the root
certificates have been revoked.
