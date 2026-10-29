#!/bin/bash
# Checks a Q21 release, every part of it, before anyone trusts it.
#
#   tools/verify-release.sh <assets folder> <tag> <commit> <public key> <attestations folder>
#
# - <assets folder>: the release's files, downloaded — the five archives,
#   SHA256SUMS and SHA256SUMS.minisig, and nothing else;
# - <tag>, <commit>: the version and the full hash of the commit it names;
# - <public key>: q21-release.pub;
# - <attestations folder>: the repository's `attestations/`, as `main` holds
#   it (threshold, builder-keys/, <tag>/).
#
# Used by the release workflows, before a release is made public and again
# when one is published by hand; and by anyone, at home, with the same
# arguments. Exit status 0 only if everything holds:
#
# 1. the folder holds exactly the expected files;
# 2. SHA256SUMS is signed by the key, and the trusted comment names this tag
#    and this commit;
# 3. every archive has the hash SHA256SUMS gives it;
# 4. the program inside every archive is the binary SHA256SUMS names for its
#    platform — the one independent builders rebuild — and so is the Windows
#    launcher. Without this, honest binary lines could sit next to the hash
#    of a different archive;
# 5. at least `threshold` independent attestations agree with those binary
#    hashes, and none disagrees.
#
# Needs bash, minisign, tar, unzip, and sha256sum or shasum.
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <assets folder> <tag> <commit> <public key> <attestations folder>" >&2
  exit 2
fi
REL=$1 TAG=$2 COMMIT=$3 KEY=$4 ATT=$5

fail() { echo "::error::$*"; exit 1; }
warn() { echo "::warning::$*"; }
sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
# The hash SHA256SUMS gives to a name, CR stripped; empty if none.
listed() { tr -d '\r' < "$REL/SHA256SUMS" | awk -v n="$1" '$2 == n {print $1; exit}'; }

PLATFORMS="linux-x86_64 linux-arm64 macos-arm64 macos-x86_64 windows-x86_64"
archive_of() { case "$1" in windows-*) echo "q21-$1.zip" ;; *) echo "q21-$1.tar.gz" ;; esac; }

# --- 1. Exactly the expected files: an extra one would be published unchecked.
EXPECTED="SHA256SUMS SHA256SUMS.minisig"
for P in $PLATFORMS; do EXPECTED="$EXPECTED $(archive_of "$P")"; done
for F in $EXPECTED; do
  [ -f "$REL/$F" ] || fail "$F is missing from the release"
done
for F in "$REL"/* "$REL"/.[!.]*; do
  [ -e "$F" ] || continue
  B=$(basename "$F")
  case " $EXPECTED " in
    *" $B "*) ;;
    *) fail "unexpected file in the release: $B (only the five archives, SHA256SUMS and its signature belong there)" ;;
  esac
done
echo "files: the expected seven, nothing else"

# --- 2. Who released it.
[ -f "$KEY" ] || fail "public key $KEY not found"
OUT=$(minisign -Vm "$REL/SHA256SUMS" -x "$REL/SHA256SUMS.minisig" -p "$KEY") \
  || fail "the signature of SHA256SUMS does NOT verify with $KEY"
COMMENT=$(printf '%s\n' "$OUT" | sed -n 's/^Trusted comment: //p')
WANTED="Q21 ${TAG} ${COMMIT} -- Rei Asanoha"
[ "$COMMENT" = "$WANTED" ] || fail "trusted comment \"$COMMENT\", expected \"$WANTED\""
echo "signature: valid — $COMMENT"

# --- 3 and 4. Every archive, and the programs inside it.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
for P in $PLATFORMS; do
  A=$(archive_of "$P")
  H=$(listed "$A")
  [ -n "$H" ] || fail "$A is not in SHA256SUMS"
  [ "$(sha "$REL/$A")" = "$H" ] || fail "$A does not have the hash SHA256SUMS gives it"
  BIN_H=$(listed "q21-$P")
  [ -n "$BIN_H" ] || fail "SHA256SUMS gives no binary hash for q21-$P"
  D="$WORK/$P"
  mkdir -p "$D"
  case "$A" in
    *.zip) unzip -q "$REL/$A" -d "$D"; PROGRAM="$D/q21.exe" ;;
    *) tar -xzf "$REL/$A" -C "$D"; PROGRAM="$D/q21" ;;
  esac
  [ -f "$PROGRAM" ] || fail "$A holds no program at its root"
  [ "$(sha "$PROGRAM")" = "$BIN_H" ] \
    || fail "the program inside $A is NOT the binary q21-$P listed in SHA256SUMS"
  if [ "$P" = windows-x86_64 ]; then
    LAUNCHER_H=$(listed "q21-wallet-$P")
    [ -n "$LAUNCHER_H" ] || fail "SHA256SUMS gives no hash for the launcher q21-wallet-$P"
    [ -f "$D/Q21 Wallet.exe" ] || fail "$A holds no Q21 Wallet.exe"
    [ "$(sha "$D/Q21 Wallet.exe")" = "$LAUNCHER_H" ] \
      || fail "Q21 Wallet.exe inside $A is NOT the launcher q21-wallet-$P listed in SHA256SUMS"
  fi
  rm -rf "$D"
  echo "archive $A: hash, program$([ "$P" = windows-x86_64 ] && echo ' and launcher') verified"
done

# --- 5. Independent rebuilds.
BINARY_NAMES=$(tr -d '\r' < "$REL/SHA256SUMS" | awk '$2 ~ /^q21-(wallet-)?[a-z]+-[a-z0-9_]+$/ {print $2}')
THRESHOLD=0
if [ -f "$ATT/threshold" ]; then
  T=$(tr -d ' \t\r\n' < "$ATT/threshold")
  printf '%s' "$T" | grep -qE '^[0-9]+$' || fail "$ATT/threshold must hold a single number, not \"$T\""
  THRESHOLD=$T
fi
if [ -n "$(find "$ATT" -type l 2>/dev/null | head -n 1)" ]; then
  fail "symbolic links under $ATT: refused"
fi
AGREE=0
SEEN_KEYS=" "
for D in "$ATT/$TAG"/*/; do
  [ -d "$D" ] || continue
  WHO=$(basename "$D")
  PUB="$ATT/builder-keys/$WHO.pub"
  if [ ! -f "$PUB" ] || [ ! -f "$D/SHA256SUMS" ] || [ ! -f "$D/SHA256SUMS.minisig" ]; then
    warn "attestation of $WHO incomplete (key, SHA256SUMS or signature missing): not counted"
    continue
  fi
  KEY_ID=$(sed -n 2p "$PUB" | tr -d '\r')
  case "$SEEN_KEYS" in
    *" $KEY_ID "*) warn "attestation of $WHO uses a key already counted: not counted again"; continue ;;
  esac
  AOUT=$(minisign -Vm "$D/SHA256SUMS" -p "$PUB" 2>/dev/null) || {
    warn "attestation of $WHO: signature invalid, not counted"; continue; }
  ACOMMENT=$(printf '%s\n' "$AOUT" | sed -n 's/^Trusted comment: //p')
  case "$ACOMMENT" in
    *"$TAG"*"$COMMIT"*) ;;
    *) warn "attestation of $WHO names another version or commit (\"$ACOMMENT\"): not counted"; continue ;;
  esac
  KNOWN=0
  while IFS= read -r LINE || [ -n "$LINE" ]; do
    LINE=$(printf '%s' "$LINE" | tr -d '\r')
    case "$LINE" in ''|\#*) continue ;; esac
    H=$(printf '%s\n' "$LINE" | awk '{print $1}')
    NAME=$(printf '%s\n' "$LINE" | awk '{print $2}' | sed 's/^\*//')
    if ! printf '%s\n' "$BINARY_NAMES" | grep -qxF -- "$NAME"; then
      warn "attestation of $WHO: line for \"$NAME\", not a binary of this release: ignored"
      continue
    fi
    if [ "$(listed "$NAME")" != "$H" ]; then
      fail "$WHO rebuilt $NAME as $H, which is NOT the released binary"
    fi
    KNOWN=$((KNOWN + 1))
  done < "$D/SHA256SUMS"
  if [ "$KNOWN" -eq 0 ]; then
    warn "attestation of $WHO states no hash of this release's binaries: not counted"
    continue
  fi
  echo "attestation: $WHO agrees ($KNOWN binaries)"
  SEEN_KEYS="$SEEN_KEYS$KEY_ID "
  AGREE=$((AGREE + 1))
done
echo "attestations: $AGREE independent, $THRESHOLD required"
[ "$AGREE" -ge "$THRESHOLD" ] \
  || fail "$AGREE attestation(s) for $TAG, $THRESHOLD required: wait for the builders (attestations/README.md)"

echo "RELEASE $TAG ($COMMIT): VERIFIED"
