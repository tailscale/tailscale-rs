# AGENTS.md

- This project is written in Rust.
- Follow the guidelines in CONTRIBUTING.md.
- Use GitHub markdown for docs, summaries of your work, etc.
- Commits must be signed off by the user in the form `Signed-off-by: "COMMITTER" <COMMITTER_EMAIL>`.
- When submitting a PR or filing an issue, include the text `Created using AGENT_NAME` where AGENT_NAME is your name.

## Repository layout

- The root package is the `tailscale` crate (the Rust API, `src/`), with examples in `examples/` and
  integration tests in `tests/`.
- Other crates live under `crates/`, grouped by function: `bindings/` (`ts_ffi`, `ts_python`,
  `ts_elixir`), `control_plane/`, `net/` (`overlay/`, `underlay/`, `protocol/`, plus `ts_dataplane`
  and `ts_transport`), `data_structures/`, `kv_store/`, `capabilities/`, `utils/`, and
  `ts_runtime`. Repo tooling lives in `tools/` (`checks`, `ts_devtools`).
- See ARCHITECTURE.md for what each crate does.

## Workspace conventions

- When adding a crate, add it to `[workspace] members` and `[workspace.dependencies]` in the
  root `Cargo.toml` (with `version` for published crates). Its manifest must use the workspace
  `version`, `edition`, `license`, etc. and set `[lints] workspace = true`; `cargo run -p checks`
  enforces the lints setting.
- `missing_docs` is on: minimally document all public items, and give each crate a `//!` crate doc.

## Checking your work

- `bin/check` runs the same checks as CI. Pass `-p <crate>` to limit it to one crate while
  iterating, then run it unscoped before you finish.
- Formatting uses nightly rustfmt (`cargo +nightly fmt`) with the settings in `.rustfmt.toml`.
- Clippy runs with `-D warnings` and `--all-features`, so code behind features (e.g. `axum`,
  `ssh`) must be warning-free too.
- Tests run with `cargo nextest`; doc tests run separately with `cargo test --doc`.

## Commits and changes

- Commit subjects use `<area>: <short lowercase summary>`, where the area is a crate or
  subsystem, e.g. `ts_util: add runtime-checked Fn{,Mut} converters` or `runtime/stun: use
  correct socket`. Keep the body short and explain why.
- Record breaking or significant user-facing changes under `Unreleased` in CHANGELOG.md, in the
  same change.

## Code style

- In tests, match on existing or macro-generated types directly (with small helper functions if
  needed) rather than adding new types just for assertions.
- For time-dependent async tests, use Tokio paused time (`#[tokio::test(start_paused = true)]`
  with the `test-util` dev-dependency feature), and shrink timeout/retry constants under
  `#[cfg(test)]` so those paths run quickly and deterministically.
