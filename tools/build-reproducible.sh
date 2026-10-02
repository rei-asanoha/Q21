#!/bin/sh
# Builds the release binary reproducibly.
#
# # The problem this script solves
#
# `cargo build --release` writes into the binary the absolute path of the
# source files of the vendored dependencies, so that panic messages say
# where the problem happened. Measured on a binary built without this script:
#
#   /home/you/q21/vendor/ml-dsa/src/signing.rs
#   /home/you/q21/vendor/ml-dsa/src/sampling.rs
#   ... nine paths in all
#
# Consequence: two people who compile the **same commit** in two different
# directories get two different binaries, hence two different SHA-256
# hashes. No one can then verify that the published file really comes from
# these sources; you have to trust whoever built it. This is exactly the hole
# that Bitcoin Core closed with Gitian and then with Guix.
#
# # What the script does
#
# It passes `--remap-path-prefix` to rustc, which replaces the prefix of the
# working directory with a fixed name, `/q21`. The binary no longer knows
# where it was built. The other paths it contains (`/rustc/<compiler
# hash>/library/...` and `/rust/deps/...`) are already neutralized by the
# Rust distribution itself and are identical on every machine with the same
# toolchain.
#
# `trim-paths` would do this in one line in `Cargo.toml`, but it is not
# stabilized in Cargo 1.95.0, the version pinned by `rust-toolchain.toml`.
# `--remap-path-prefix` has been stable since 2018.
#
# # Usage
#
#   ./tools/build-reproducible.sh
#   ./tools/build-reproducible.sh x86_64-unknown-linux-gnu
#
# The optional second argument is a target; without it, the current machine.
#
# # Checking that it works
#
#   ./tools/verify-reproducible.sh
#
# See REPRODUCING.md.

set -eu

TARGET="${1:-}"

# The project directory, wherever it is, as seen from this script. We do not
# assume that the user is at the root.
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$ROOT"

# `pwd -P`: the real path, with symbolic links resolved. That is the one cargo
# gives to rustc; remapping the unresolved path would match nothing.
#
# The destination name, `/q21`, is arbitrary but must be the same everywhere:
# it is what ends up in the binary. Do not change it without changing
# REPRODUCING.md, otherwise the published hashes will no longer match.
FLAGS="--remap-path-prefix=$ROOT=/q21"

# A `RUSTFLAGS` already set in the environment would silently replace ours:
# cargo does not combine them, it takes one OR the other. We refuse rather
# than produce a binary we believe is reproducible and is not.
if [ -n "${RUSTFLAGS:-}" ]; then
  echo "error: RUSTFLAGS is already set in the environment:" >&2
  echo "  RUSTFLAGS=$RUSTFLAGS" >&2
  echo "It would replace the reproducibility flags. Clear it:" >&2
  echo "  unset RUSTFLAGS" >&2
  exit 1
fi

echo "Project root: $ROOT"
echo "Remapping:    $ROOT -> /q21"
echo "Toolchain:    $(rustc --version)"
echo

if [ -n "$TARGET" ]; then
  RUSTFLAGS="$FLAGS" cargo build --locked --release --target "$TARGET"
  BINARY="target/$TARGET/release/q21"
else
  RUSTFLAGS="$FLAGS" cargo build --locked --release
  BINARY="target/release/q21"
fi

[ -f "$BINARY" ] || BINARY="$BINARY.exe"

echo
echo "Binary: $BINARY"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$BINARY"
else
  shasum -a 256 "$BINARY"
fi
