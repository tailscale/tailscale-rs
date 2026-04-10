{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";

    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  description = "tailscale-rs: tailscale client in rust";

  outputs = inputs: let
    systems = [
      "x86_64-linux"
      "aarch64-linux"
      "armv7l-linux"
      "aarch64-darwin"
    ];

    lib = inputs.nixpkgs.lib;

    # Use the Rust toolchain specified in rust-toolchain.toml.
    repoRustToolchain = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

    # Specifically used to provide `cargo +nightly fmt`
    nightlyFmtToolchain = pkgs: pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.minimal.override {
      extensions = ["rustfmt"];
    });

    importNixpkgs = { system, cross ? null }: import inputs.nixpkgs ({
      system = system;
      crossSystem = cross;

      overlays = [
        (import inputs.rust-overlay)

        (final: prev: {
          repo_toolchain = repoRustToolchain prev;
          nightly_fmt_toolchain = nightlyFmtToolchain prev;
        })

        (final: prev: {
          craneLib = (inputs.crane.mkLib prev).overrideToolchain (p: p.repo_toolchain);
          craneLibNightlyFmt = (inputs.crane.mkLib prev).overrideToolchain (p: p.nightly_fmt_toolchain);
        })
      ];
    });

    # If you include other assets in the build (e.g. via include_bytes!,
    # include_str!, or a dependency used in a build.rs), you must update this
    # -- these files are all that the `cargo build` for the workspace will be
    # able to see.
    #
    # NB: this is obviously not very selective, meaning crates may rebuild
    # spuriously, but better for now to avoid premature optimization.
    rustsrc = let
      filter = lib.fileset.unions [
        ./deny.toml
        ./.rustfmt.toml
        ./ts_netstack_smoltcp/examples/axum_tun
        ./examples/axum
        (lib.fileset.fileFilter (file: file.hasExt "rs") ./.)
        (lib.fileset.fileFilter (file: file.hasExt "json") ./.)
        (lib.fileset.fileFilter (file: file.name == "README.md") ./.)
        (lib.fileset.fileFilter (file: file.name == "prefixes.txt.gz") ./ts_bart)
        (lib.fileset.fileFilter (file: file.name == "Cargo.toml") ./.)
        (lib.fileset.fileFilter (file: file.name == "Cargo.lock") ./.)
        (lib.fileset.fileFilter (file: file.name == "config.toml") ./.)  # capture .cargo/config.toml
      ];

    in lib.fileset.toSource {
      root = ./.;
      fileset = filter;
    };

    # Output packages for a given `pkgs` expression.
    # As above, pulled out into a function so we can call it in the
    # packages.cross leaves.
    makePackages = pkgs: let
      deps = pkgs.callPackage ./nix/deps.nix {};

      rootToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      workspaceMembers = lib.sort lib.lessThan (lib.unique rootToml.workspace.members) ++ [ "./" ];

      crates = lib.map (memberPath: let
        cargoToml = ./. + "/${memberPath}/Cargo.toml";
        meta = pkgs.craneLib.crateNameFromCargoToml { cargoToml = cargoToml; };
        builtPkg = pkgs.callPackage ./nix/crate.nix {
          deps = deps;
          cargoToml = cargoToml;
          rustsrc = rustsrc;
        };
      in {
        name = meta.pname;
        value = builtPkg;
      })
        workspaceMembers;

      docs = pkgs.craneLib.cargoDoc (deps.buildDeps // {
        pname = "tailscale-rs-wksp";
        version = "dev";

        cargoArtifacts = deps;
        src = rustsrc;

        cargoExtraArgs = "--locked --workspace";
      });

      crates' = builtins.listToAttrs crates;

      workspace = pkgs.craneLib.buildPackage (deps.passthru.buildDeps // {
        pname = "tailscale-rs-wksp";
        version = "dev";

        src = rustsrc;

        cargoArtifacts = deps;
        cargoExtraArgs = "--workspace --all-targets --all-features";
        env.PYO3_NO_PYTHON = 1;
        env.PYO3_BUILD_EXTENSION_MODULE = 1;

        # don't run benches as part of check
        checkPhaseCargoCommand = "cargo test --profile release --all-features --workspace --examples --bins --lib --tests";

        passthru = {
          deps = deps;
        };
      });

    in crates' // ({
      deps = deps;
      docs = docs;
      doc = docs;
      workspace = workspace;
      default = workspace;
    });

  in inputs.flake-parts.lib.mkFlake { inputs = inputs; } {
    systems = systems;

    perSystem = { pkgs, system, lib, ... }: let
      packages = makePackages pkgs;

      # All the systems that are not us. Doesn't account for systems that might be architecture-
      # compatible (e.g. i686 -> x64).
      foreignSystems = builtins.filter (sys: sys != system) systems;

    in {
      _module.args = {
        # override nixpkgs with above closure -- sets overlays needed for rust
        pkgs = importNixpkgs { system = system; };
      };

      # Reexport nixpkgs (mostly for debugging)
      legacyPackages = pkgs;


      apps = let
        tailscale = {
          type = "app";
          program = "${packages.tailscale}/lib/tailscale";
        };
      in {
        tailscale = tailscale;
        default = tailscale;
      };

      packages = packages // {
        # flake-parts doesn't want attribute sets in packages -- this is an invalid dummy derivation
        # we use to hack its check so that we can `nix build .#cross.$CROSS_SYSTEM.$PACKAGE`.
        cross = (builtins.derivation {
          system = system;

          name = "placeholder";
          builder = "empty";
        }) // lib.genAttrs foreignSystems (cross: let
          crossPkgs = importNixpkgs {
            cross = cross;
            system = system;
          };
        in makePackages crossPkgs);
      };

      # Run these (as well as checking the flake for valid structure) with `nix flake check`.
      checks = let
        common = {
          pname = "tailscale-rs-wksp";
          version = "dev";
          src = rustsrc;

          env.PYO3_NO_PYTHON = 1;
          env.PYO3_BUILD_EXTENSION_MODULE = 1;
        };

      in {
        # Lint lib targets
        clippy_libs = pkgs.craneLib.cargoClippy (common // packages.deps.buildDeps // {
          cargoArtifacts = packages.deps;
          cargoExtraArgs = "--locked --workspace";
          cargoClippyExtraArgs = "--lib --all-features --no-deps -- -D warnings";
        });

        # Lint all other targets: these are separated to skip enforcing missing_docs for
        # targets that can't be part of public API.
        clippy_other_targets = pkgs.craneLib.cargoClippy (common // packages.deps.buildDeps // {
          cargoArtifacts = packages.deps;
          cargoExtraArgs = "--locked --workspace";
          cargoClippyExtraArgs = "--bins --tests --examples --benches --all-features --no-deps -- -D warnings -A missing_docs";
        });

        # See deny.toml -- various checks on dependencies
        deny = pkgs.craneLib.cargoDeny common;

        # Check code style
        fmt = pkgs.craneLibNightlyFmt.cargoFmt common;

        # Consults rustsec advisory db for reported vulnerabilities in dependencies
        audit = pkgs.craneLib.cargoAudit (common // {
          advisory-db = inputs.rust-advisory-db;
        });

        # This does the same as `cargo test`, it's just a pretty harness
        nextest = pkgs.craneLib.cargoNextest (common // packages.deps.buildDeps // {
          cargoArtifacts = packages.deps;
            partitions = 1;
            partitionType = "count";
            cargoExtraArgs = "--locked --workspace --all-features";
            cargoNextestPartitionsExtraArgs = "--no-tests=pass --show-progress=counter --no-fail-fast";
        });

        # Nextest can't run doctests, so run them separately
        docTest = pkgs.craneLib.cargoDocTest (common // packages.deps.buildDeps // {
            cargoArtifacts = packages.deps;
            cargoExtraArgs = "--locked --workspace --all-features";
        });

        docs = packages.docs;
      };

      # Builds a dev shell which you can enter with `nix develop .#`, or automatically
      # using direnv with use_flake
      devShells.default = pkgs.craneLib.devShell {
        inputsFrom = [ packages.tailscale ];

        packages = with pkgs; [
          cargo-audit
          cargo-deny
          cargo-nextest

          repo_toolchain

          cargo-flamegraph
          heaptrack
        ];
      };
    };
  };
}
