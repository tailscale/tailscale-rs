# Contributing

This document covers development environment tooling, issue reporting, contribution guidelines, and coding standards.
See [ARCHITECTURE.md](ARCHITECTURE.md) for the high-level architecture and repository layout.

## Getting Started

We use a few `cargo` components/plugins in our development workflow you should install first:

- `cargo clippy`: Installed by default if you're using `rustup`; can also be installed with
  `rustup component add clippy [--toolchain=<name>]`.
- `cargo deny`: Install with `cargo install --locked cargo-deny`.
- `cargo machete`: Install with `cargo install --locked cargo-machete`.
- `cargo nextest`: [Installation Instructions](https://nexte.st/docs/installation/pre-built-binaries/)
- `cargo vet`: Install with `cargo install --locked cargo-vet`.

Formatting, linting, dependency checking, and testing:

```sh
# Verify that all files are formatted properly:
$ cargo +nightly fmt --check
# Format any incorrectly-formatted files:
$ cargo +nightly fmt
# Lint the codebase with clippy:
$ cargo clippy
# Verify dependency licenses are compatible, and have no outstanding security issues:
$ cargo deny check
# Detect any unused dependencies in the workspace:
$ cargo machete --with-metadata
# Determine how many of our third-party dependencies have been audited:
$ cargo vet 
# Run all the tests in the codebase, including in doc comments:
# NOTE: cargo nextest doesn't support doc tests at time of writing
$ cargo nextest run --locked --workspace --all-features && cargo test --locked --workspace --doc --all-features
```

Or you can run `bin/check`, which runs all of the above.

The GitHub Actions CI/CD pipeline will fail if any of the formatting/linting/dependency/testing checks fail, except `cargo vet`, which is not run in the pipeline.

## Issues

Issues reporting bugs, security issues, or performance issues, requesting reasonable feature requests, or suggesting improvements are welcome. Issues which can't or won't be addressed will be closed, this doesn't mean the issue is invalid and we appreciate you taking the time to file the issue. We do request that all issues are polite, well-explained, and (for bugs) contain full steps to reproduce. Please also read the guidelines on AI-assisted contributions below.

To report a potentially exploitable vulnerability, please send private email to security@tailscale.com rather than filing an issue. Tailscale staff will triage the issue, and work with you on a coordinated disclosure timeline.


## Pull requests

Currently, we are not requesting external code or docs contributions. If you would like to get involved with the project, please contact the maintainers (e.g., by filing an issue) before sending a PR.

We require [Developer Certificate of Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin) Signed-off-by lines in commits.


## AI-assisted contributions

We do not judge contributions (PRs, issues, etc.) based on the tools used to create them. We do ask that if you use AI in any material way, that you specify how it was used and how the code is verified to be correct in the issue or PR comments to help the reviewer. We expect authors to take responsibility for the quality of their contributions whether or not AI is used (e.g., code and prose should be self-reviewed, code should be documented and tested, etc.). Please respect the time and energy of reviewers and maintainers by ensuring quality to the best of your ability.


## Coding guidelines

### Code style

We strive to use standard, idiomatic Rust, following community best practices.

We check Rustfmt and Clippy in CI, and all PRs must pass these checks before being merged.


### Dependencies

We want to balance making use of the Rust ecosystem with the inherent supply chain security risk. There is no perfect solution here, so we aim to do the best that we can reasonably do, and stay inline with Rust community best practices.

Using and adding dependencies is acceptable, but we strive to keep the dependency tree small (i.e., we accept that adding dependencies is a trade-off). As well as considering where a dependency should be added at all (see below), consider the following:

- Use the minimal necessary set of features for dependencies; use optional dependencies and have dependency features depend on our features where possible.
- Prefer dev-dependencies to regular dependencies where possible.
- Consider reimplementing trivial functionality (esp if we only want to use a small part of a crate).


#### Adding dependencies

A PR which adds a dependency to the project should have a comment justifying the benefit of adding the dependency against potential risk. This should usually include:

- Why the new dependency is necessary (vs reimplementing similar functionality or using a crate which is already depended on).
- Are there alternative crates? Why is the chosen one the best alternative?
- How does adding the dependency change the transitive dependencies of the project (e.g., a crate which is already transitively depended on has a small impact, a crate with many dependencies of its own might have a large impact).
- To assess the risk of adding the dependency, consider:
  - Is the license compatible with ours?
  - Is it widely used (check crates.io) and widely known?
  - Does it provide a build script, procedural macros, or unsafe code? (Which are higher risk features).
  - How large is the dependency?
  - The reputation of the authors or stewarding organisation.
  - Is the dependency maintained (check the project repository) and well-managed (check project repository, CI, docs, website, etc.).
  - Is the API of the dependency fairly stable (check version number and release notes).
  - Is the dependency well-documented and well-tested.
  - Does the dependency have known issues (check using tools such as `cargo-vet` and `cargo-deny`).


#### Updating dependencies

We commit our Cargo.lock file. Dependency updates (`cargo update`) should be done in a dedicated PR rather than as part of a larger PR (if that is not possible, then the updates should at least be in a separate commit).

We aim to update our dependencies roughly monthly or more often if necessary due to a security announcement. When updating, run `cargo deny` and `cargo vet` to check for any issues with the new versions (as well as the usual lints and tests). Check for new transitive dependencies (we don't expect you to review these in detail, but have a quick look for anything suspicious). Use the latest version of all dependencies unless there is a good reason not to (and document that reason in a comment). If upgrading a dependency is impractical because using the latest version would require major changes to our code, file an issue so it's not forgotten.


### Error handling

We use `thiserror` for error handling. We tend to have a small number (often 0 or 1) of error enums per crate and aim for a 'medium' level of detail in our errors. We try to avoid nesting of our errors unless it is clearly necessary (i.e, avoid `#[from]`, `#[source]`, and `#[error(transparent)]`). Nesting errors from other crates is OK in internal errors and sometimes in
API errors (but in that case consider if the nested error is suitable for our API). We do not use `anyhow` or similar libraries, or follow the pattern of adding context to errors as they are re-thrown.

The design of errors in our API is work in progress. Our errors are not intended to be used as user-facing errors (i.e., programs using tailscale-rs will need to put some effort into error reporting); they are intended to be caught and handled, or used for debugging.


### Panics

Our goal is that our code should never panic (at least in the absence of hardware faults, cosmic rays, etc.). In particular, we do not expect the process or any thread to be supervised so that it can be restarted in the event of a panic. Always use `Result` for error handling rather than panicking.

However, we do not have a blanket ban on panicking. Try to follow these guidelines for panics:

- All functions, especially API functions, should prefer not to panic. In API functions, strongly prefer returning a `Result` or `Option` and letting the caller `unwrap`, rather than panicking internally.
- If a function can panic, that should be documented in its doc comments.
- 'Impossible' panics should only occur where the guarding invariant is local, simple, and documented (this includes indexing, `[...]`).
- We do not try to handle hardware or operating system issues such as out-of-memory errors, panicking is acceptable here.


### Unsafe code

Prefer safe code to unsafe code and strive to minimize use of unsafe. However, where necessary,
unsafe code is acceptable (the reasons why it is necessary should be documented). All unsafe code
should be well-commented with the invariants which must be maintained by programmers (tag such
comments with `SAFETY`).

Some guidelines for writing better unsafe code:

- You must follow Rust's soundness rules as documented in the standard library docs.
- Only use `unsafe` for Rust's memory safety invariants.
- Encapsulate unsafe code wherever possible; keep the scope of broken safety invariants as small as possible.
- Keep safety requirements as simple and local as possible.
- Consider the interaction of unsafe code with panicking, async cancellation, and concurrent control flow.


## Nix

We also provide a build with [Nix](https://nixos.org) which can handle cross-compilation. To install Nix, you can follow the instructions [here](https://nixos.org/download). You'll also need to enable the Flakes feature, as it's still considered experimental; add the following to your `nix.conf`:

```
experimental-features = nix-command flakes
```

To build:

```sh
# Build tailscale-rs (default)
$ nix build .#

# Build a specific crate
$ nix build .#$CRATE

# Examples are available under the .examples attribute
$ nix build .#$CRATE.examples
```

To cross-compile:

```sh
$ nix build .#cross.armv7l-linux.$CRATE
```

### Checks

Target-independent Rust checks (clippy, fmt, deny) and validation of the Nix structure can be run with:

```sh
$ nix flake check
```

## Releases

We aim for a roughly monthly release schedule. Releases are time-based, not feature-based. We will
make ad hoc patch releases as necessary.

Publishing releases is currently manual, but we are moving to a GitHub workflow.

Releases should be [tagged](https://github.com/tailscale/tailscale-rs/tags).

TODO describe how to make and publish a release.

Breaking or significant changes should be recorded in the [changelog](CHANGELOG.md) as part of the
PR making the change.
