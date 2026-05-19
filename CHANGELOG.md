# Changelog

Record breaking or significant changes here. All dates are UTC.

## Unreleased - June 2026

## [0.3.1](https://github.com/tailscale/tailscale-rs/releases/tag/v0.3.1) - 2026-05-20

- Minor fixes to CI/CD publishing infrastructure.

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
  [#140](https://github.com/tailscale/tailscale-rs/pull/140) and [#148](https://github.com/tailscale/tailscale-rs/pull/148).
- Fixed (ts_netstack_smoltcp): big improvement to TCP accept performance.
  [#141](https://github.com/tailscale/tailscale-rs/pull/141).
- Updated MSRV to 1.94.1.
  [#181](https://github.com/tailscale/tailscale-rs/pull/181).

## [0.2.0](https://github.com/tailscale/tailscale-rs/releases/tag/v0.2.0) - 2026-04-15

Initial public release.

## 0.1.0

Hello, world!
