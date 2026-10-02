#!/bin/sh
# Proves that the build is reproducible: two directories, one hash.
#
# # What the script does
#
# 1. copies the project into two temporary directories of **different length
#    and depth**; this is what reveals the problem, because a path written
#    into a binary changes the size of the binary;
# 2. builds in each one with `build-reproducible.sh`;
# 3. compares the two SHA-256 hashes.
#
# If the two hashes are equal, the build is reproducible: a third party who
# rebuilds this commit will get the same file, byte for byte, and can compare
# it with the published hash. They no longer have to take anyone's word for
# it.
#
# # Usage
#
#   ./tools/verify-reproducible.sh
#
# Expect two full builds. On a modest machine, it takes a while; that is
# normal, there is no cache shared between the two (a shared cache would
# invalidate the proof).
#
# # What the script does NOT prove
#
# It compares two builds on the **same** machine, with the same system and
# the same compiler. It eliminates the "directory" variable. It says nothing
# about the "machine" variable: for that one, several people each have to
# build at home and announce their hash. That is the purpose of the
# attestations repository, described in REPRODUCING.md.

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)

BASE=$(mktemp -d)
A="$BASE/a"
B="$BASE/some/path/clearly/much/longer/and/deeper/b"

cleanup() { rm -rf "$BASE"; }
trap cleanup EXIT INT TERM

echo "Directory A: $A"
echo "Directory B: $B"
echo

mkdir -p "$A" "$B"

# We copy the sources, never `target/`: an artifact already compiled in the
# old directory would carry the old path and skew the measurement.
copy_sources() {
  tar -C "$ROOT" -cf - \
    --exclude=./target --exclude=./.git --exclude=./q21-data --exclude=./w2 \
    . | tar -C "$1" -xf -
}

echo "Copying to A..."; copy_sources "$A"
echo "Copying to B..."; copy_sources "$B"
echo

echo "=== Build A ==="
( cd "$A" && ./tools/build-reproducible.sh )
echo
echo "=== Build B ==="
( cd "$B" && ./tools/build-reproducible.sh )
echo

checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

SA=$(checksum "$A/target/release/q21")
SB=$(checksum "$B/target/release/q21")

echo "=== Result ==="
echo "A: $SA"
echo "B: $SB"
echo

if [ "$SA" = "$SB" ]; then
  echo "IDENTICAL: the build is reproducible."
  echo
  echo "Hash of this commit:"
  echo "  $SA"
  exit 0
else
  echo "DIFFERENT: the build is NOT reproducible."
  echo
  echo "To see where the difference comes from, look for the remaining absolute paths:"
  echo "  strings -n 12 \"$A/target/release/q21\" | grep '$A'"
  exit 1
fi
