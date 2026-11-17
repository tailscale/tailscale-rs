//! Builder for `ts_ffi` invoking cbindgen.

use std::{env, path::PathBuf};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // builder.with_crate() will cause cbindgen to call `cargo metadata`.
    // Nested `cargo metadata` will fail during `cargo publish --dry-run` as it
    // won't have access to the local registry overlay cargo uses for dependency
    // resolution in that scenario.
    // As long as we export opaque types, cbindgen doesn't need to look at
    // dependencies anyway.
    let mut builder =
        cbindgen::Builder::new().with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap());
    for p in glob::glob(&format!("{}/src/**/*.rs", crate_dir)).unwrap() {
        builder = builder.with_src(p.unwrap());
    }
    let bindings = builder.generate().unwrap();

    // We're not supposed to generate anything outside of `OUT_DIR`, but it's useful
    // as a convenience. Turn it off with this var (for use with publish).
    if env::var("TS_FFI_BUILDRS_STRICT").is_err_and(|e| e == env::VarError::NotPresent) {
        bindings.write_to_file("tailscale.h");
    }

    let out = env::var("OUT_DIR").unwrap();
    let out = PathBuf::from(out);
    bindings.write_to_file(out.join("tailscale.h"));
}
