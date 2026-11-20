//! Build script for the `tailscale` crate: embeds enabled features

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let mut features = vec![];
    for (k, _v) in std::env::vars() {
        if let Some(tail) = k.strip_prefix("CARGO_FEATURE_") {
            features.push(tail.to_lowercase().replace('_', "-"));
        }
    }
    features.sort();
    println!("cargo:rustc-env=TS_ENABLED_FEATURES={}", features.join(","));
}
