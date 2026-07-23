# Changelog

Record breaking or significant changes here. All dates are UTC.

## Unreleased - August 2026

Put changes for the upcoming release here!

- **Breaking** (Rust API, lang bindings, ts_control): Support for `ephemeral`
  config option. This was previously effectively hardcoded to `true`, the default
  is now `false` (tailscale-rs nodes are _not_ ephemeral unless you explicitly
  configure them to be).
  [#292](https://github.com/tailscale/tailscale-rs/pull/292).
- **Security** (C bindings): Don't log private keys in `ts_load_key_file`. Previously
  loaded keys were logged at INFO priority. These logs aren't persisted or streamed
  anywhere by default, so this is only a concern in non-default configurations. Users
  of the C bindings who persisted logs should provision new nodes with fresh keys and
  invalidate existing credentials.

## [0.4.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.4.0) - 2026-07-08

- Added (Rust API): Experimental support for user-defined tailnet SSH servers using
  [`russh`](https://docs.rs/russh/latest/russh/) and (optionally)
  [`ratatui`](https://docs.rs/ratatui/latest/ratatui/).
  [#178](https://github.com/tailscale/tailscale-rs/pull/178).
- Added (ts_netmon): Monitor network interface changes across Linux and Windows (macOS coming in a
  future release).
  [#214](https://github.com/tailscale/tailscale-rs/pull/214).
- Added (ts_kv_store): Transactional KV store for future use by multiple components (peer tracker,
  control client, etc.).
  [#208](https://github.com/tailscale/tailscale-rs/pull/208).
  [#223](https://github.com/tailscale/tailscale-rs/pull/223).
  [#228](https://github.com/tailscale/tailscale-rs/pull/228).
  [#241](https://github.com/tailscale/tailscale-rs/pull/241).
  [#252](https://github.com/tailscale/tailscale-rs/pull/252).
  [#263](https://github.com/tailscale/tailscale-rs/pull/263).
  [#265](https://github.com/tailscale/tailscale-rs/pull/265).
- Added (ts_control*, ts_derp, ts_runtime): Handling of various peer change messages from the
  control plane.
  [#185](https://github.com/tailscale/tailscale-rs/pull/185).
  [#248](https://github.com/tailscale/tailscale-rs/pull/248).
- Added (ts_runtime): STUN protocol support and periodic STUN checks.
  [#234](https://github.com/tailscale/tailscale-rs/pull/234).
  [#244](https://github.com/tailscale/tailscale-rs/pull/244).
- Added (ts_tunnel): Cleanup of expired sessions that no longer receive traffic.
  [#264](https://github.com/tailscale/tailscale-rs/pull/264).
- Added (ts_python): Type stubs for the `tailscale-py` package, along with minor improvements to
  documentation.
  [#211](https://github.com/tailscale/tailscale-rs/pull/211).
  [#247](https://github.com/tailscale/tailscale-rs/pull/247).
- Fixed (ts_keys, ts_noise): Private key types are properly zeroized on drop and are now passed by
  reference rather than Copy.
  [#221](https://github.com/tailscale/tailscale-rs/pull/221).
  [#245](https://github.com/tailscale/tailscale-rs/pull/245).
  [#249](https://github.com/tailscale/tailscale-rs/pull/249).
  [#251](https://github.com/tailscale/tailscale-rs/pull/251).
- Fixed (ts_packetfilter_serde): `IpRange::Wildcard.iter_prefixes()` now covers the full `::/0`
  IPv6 address space. Thanks to @immanuwell for the report!
  [#212](https://github.com/tailscale/tailscale-rs/pull/212).
- Fixed (ts_netstack_smoltcp{_core}): Overlay network stack now returns an error on IP version
  mismatch between local/remote endpoints instead of panicking.
  [#213](https://github.com/tailscale/tailscale-rs/pull/213).
- Fixed (ts_netstack_smoltcp_core): TCP accept loop now correctly handles CLOSE_WAIT transitions and
  half-open sockets that transition back to the LISTEN state.
  [#200](https://github.com/tailscale/tailscale-rs/pull/200).
  [#239](https://github.com/tailscale/tailscale-rs/pull/239).
- Fixed (ts_runtime): DERP connectivity is now re-established after a control client reconnect.
  [#242](https://github.com/tailscale/tailscale-rs/pull/242).

## [0.3.3](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.3) - 2026-05-20

- Fixed: don't generate `tailscale.h` on publish.
  [#196](https://github.com/tailscale/tailscale-rs/pull/196).
- Fixed: Elixir CI/CD publishing infrastructure.
  [#197](https://github.com/tailscale/tailscale-rs/pull/197).

## [0.3.2](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.2) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: removed `std` dependency from `ts_netstack_smoltcp_core`.
  [#194](https://github.com/tailscale/tailscale-rs/pull/194).

## [0.3.1](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.1) - 2026-05-20

Partial release; this version is tagged and published to PyPI, but was not published to crates.io or hex.pm.

- Fixed: Python CI/CD publishing infrastructure.
  [#191](https://github.com/tailscale/tailscale-rs/pull/191).
- Fixed: Rust CI/CD publishing infrastructure.
  [#193](https://github.com/tailscale/tailscale-rs/pull/193).

## [0.3.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.0) - 2026-05-19

Internal release; this version is tagged, but was not published to any package repositories.

- **Breaking** (Rust API): exports `config`, `netstack`, and `keys` modules and moves some functionality
  from the crate root to these modules. Replaces `load_key_file` with `Config::default_with_key_file`.
  Exports a few more types so fewer users will have to depend on internal crates.
  [#105](https://github.com/tailscale/tailscale-rs/pull/105).
- **Breaking** (Rust API, ts_netstack_smoltcp, ts_control): errors have been refactored, some minor
  changes to APIs around errors.
  [#154](https://github.com/tailscale/tailscale-rs/pull/154).
- Added (Rust API): load configuration options from environment variables. Adds `config::auth_key_from_env`
  and `config::Config::default_from_env`.
  [#97](https://github.com/tailscale/tailscale-rs/pull/97).
- Added (Rust API, Python, Elixir): `Device::self_node`.
  [#147](https://github.com/tailscale/tailscale-rs/pull/147).
- Added (Python and Elixir bindings): optional configuration parameters.
  [#140](https://github.com/tailscale/tailscale-rs/pull/140)
  and [#148](https://github.com/tailscale/tailscale-rs/pull/148).
- Fixed (ts_netstack_smoltcp): big improvement to TCP accept performance.
  [#141](https://github.com/tailscale/tailscale-rs/pull/141).
- Updated MSRV to 1.94.1.
  [#181](https://github.com/tailscale/tailscale-rs/pull/181).

## [0.2.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.2.0) - 2026-04-15

Initial public release.

## 0.1.0

Hello, world!
