#![doc = include_str!("../README.md")]

/// Check whether an environment variable is truthy (case-insensitive: `1`, `on`, `true`,
/// `yes`).
pub fn env_var_is_truthy(var_name: &str) -> bool {
    const TRUTHY_STRINGS: &[&str] = &["1", "true", "on", "yes"];

    std::env::var(var_name).is_ok_and(|mut s| {
        s.make_ascii_lowercase();

        TRUTHY_STRINGS.contains(&s.as_str())
    })
}

/// Report whether this is a Nix build.
///
/// Checks the `NIX_BUILD_TOP` env var.
pub fn in_nix_build() -> bool {
    std::env::var("NIX_BUILD_TOP").is_ok()
}

/// Returns `true` if tests that require network access should be run; `false` otherwise.
/// Tests must opt in to this behavior by checking this function.
///
/// Tests that call this function will only be run if the `TS_RS_TEST_NET` environment
/// variable is set to a "truthy" value ([`env_var_is_truthy`]).
pub fn run_net_tests() -> bool {
    env_var_is_truthy("TS_RS_TEST_NET")
}

/// Return the value of a test-specific Tailscale auth key, loaded from the
/// `TS_RS_TEST_AUTHKEY` environment variable.
///
/// The env var is specifically named to avoid collision with a client-oriented auth key and
/// to ensure the caller means the key to be used in tests.
pub fn auth_key() -> Option<String> {
    std::env::var("TS_RS_TEST_AUTHKEY").ok()
}
