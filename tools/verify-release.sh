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
# 4. inside every archive: the program is the binary SHA256SUMS names for its
#    platform — the one independent builders rebuild — and so is the Windows
#    launcher; every file that comes from the repository (documents,
#    bootstrap.txt, launcher scripts, Info.plist) is byte for byte the one of
#    the tagged commit; nothing else is there but Tor and the macOS bundle's
#    signature; no entry is a link, a duplicate (case ignored), an absolute
#    path or a `..`;
# 5. for every program, at least `threshold` independent attestations agree
#    with its hash, and none disagrees.
#
# What it cannot vouch for: the files of Tor (the Tor Project's bundle,
# checked against the Tor Project's signature when the archive is built) and
# the macOS launcher, re-signed inside its bundle. Both are covered by the
# release signature only. See REPRODUCING.md, section 6.
#
# Run it from a clone of the repository that holds the tagged commit: the
# files that come from the repository are compared with what a checkout of
# the tagged commit holds (`git cat-file --filters`).
#
# Needs bash, git, minisign, tar, unzip, zipinfo, and sha256sum or shasum.
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <assets folder> <tag> <commit> <public key> <attestations folder>" >&2
  exit 2
fi
REL=$1 TAG=$2 COMMIT=$3 KEY=$4 ATT=$5
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
VERSION=${TAG#v}

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
git -C "$REPO" cat-file -e "${COMMIT}^{commit}" 2>/dev/null \
  || fail "commit $COMMIT is not in the clone at $REPO: fetch the tags first"
find "$REL" -mindepth 1 | while IFS= read -r F; do
  B=$(basename "$F")
  if [ ! -f "$F" ] || [ -L "$F" ]; then fail "not a plain file in the release: $B"; fi
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
  # The entries, before anything is extracted: no link, no absolute path,
  # no `..`, no two names that a case-insensitive disk would merge.
  case "$A" in
    *.zip)
      NAMES=$(zipinfo -1 "$REL/$A")
      LONG=$(zipinfo "$REL/$A")
      if grep -q '^l' <<<"$LONG"; then fail "$A holds a symbolic link"; fi
      ;;
    *)
      NAMES=$(tar -tzf "$REL/$A")
      LONG=$(tar -tvzf "$REL/$A")
      if grep -q '^[lh]' <<<"$LONG"; then fail "$A holds a link"; fi
      ;;
  esac
  # A zip made on Windows may separate folders with backslashes: read as
  # slashes, as unzip does.
  # shellcheck disable=SC1003  # tr reads '\\' as one backslash
  NAMES=$(printf '%s\n' "$NAMES" | tr '\\' '/')
  # Never `producer | grep -q` under pipefail: grep leaves at the first
  # match, the producer dies of SIGPIPE, and the check reads as passed.
  if grep -qE '(^/|^[A-Za-z]:|(^|/)\.\.(/|$))' <<<"$NAMES"; then
    fail "$A holds an absolute path or a .."
  fi
  DUP=$(printf '%s\n' "$NAMES" | sed -e 's#^\./##' -e 's#/$##' | grep -v '^\.\{0,1\}$' \
    | tr '[:upper:]' '[:lower:]' | sort | uniq -d)
  [ -z "$DUP" ] || fail "$A holds entries that differ only by case, or twice: $DUP"
  case "$A" in
    # unzip says 1 for a warning — backslashes read as slashes —, more for
    # an error.
    *.zip) unzip -q "$REL/$A" -d "$D" || [ "$?" -eq 1 ] || fail "$A cannot be unpacked"
           PROGRAM="$D/q21.exe" ;;
    *) tar -xzf "$REL/$A" -C "$D"; PROGRAM="$D/q21" ;;
  esac
  [ -z "$(find "$D" -type l | head -n 1)" ] || fail "$A holds a symbolic link"
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
  # Every other file: from the repository, byte for byte; or Tor; or the
  # macOS bundle's own signature. Nothing else.
  # NUL-separated: a name holding a newline cannot pass for two allowed ones.
  ( cd "$D" && find . -type f -print0 ) | while IFS= read -r -d '' R; do
    R=${R#./}
    SOURCE=""
    case "$R" in
      q21|q21.exe|"Q21 Wallet.exe") continue ;;
      README.md|JOIN.md|WHITEPAPER.md|AUDIT.md|WALLET.md|REPRODUCING.md|SUCCESSION.md|TOR.md) SOURCE="$R" ;;
      bootstrap.txt|q21-data/bootstrap.txt) SOURCE=default-bootstrap.txt ;;
      "Q21 Wallet.command"|"Troubleshooting/Q21 Wallet - Terminal.command") SOURCE="Q21 Wallet.command" ;;
      "Troubleshooting/Q21 Wallet - console.bat") SOURCE="Q21 Wallet.bat" ;;
      "Q21 Wallet.app/Contents/Info.plist")
        git -C "$REPO" cat-file --filters "$COMMIT:packaging/macos/Info.plist" | sed "s/@VERSION@/$VERSION/g" > "$WORK/expected"
        cmp -s "$WORK/expected" "$D/$R" || fail "$A: $R differs from the repository's"
        continue ;;
      "Q21 Wallet.app/Contents/MacOS/q21-wallet"|"Q21 Wallet.app/Contents/_CodeSignature/CodeResources")
        case "$P" in macos-*) continue ;; esac ;;
      tor/README.txt)
        git -C "$REPO" cat-file --filters "$COMMIT:tools/TOR-IN-THIS-ARCHIVE.txt" > "$WORK/expected"
        head -c "$(wc -c < "$WORK/expected")" "$D/$R" | cmp -s - "$WORK/expected" \
          || fail "$A: tor/README.txt does not start with the repository's text"
        continue ;;
      tor/*)
        [ "$P" != linux-arm64 ] && continue ;;
    esac
    [ -n "$SOURCE" ] || fail "$A holds a file that belongs to no part of a release: $R"
    # As a checkout writes it: `.gitattributes` gives the .bat file CRLF.
    git -C "$REPO" cat-file --filters "$COMMIT:$SOURCE" > "$WORK/expected" \
      || fail "$A: $SOURCE is not in commit $COMMIT"
    cmp -s "$WORK/expected" "$D/$R" || fail "$A: $R differs from $SOURCE at $COMMIT"
  done
  rm -rf "$D"
  echo "archive $A: hash, program$([ "$P" = windows-x86_64 ] && echo ', launcher') and every other file verified"
done

# --- 5. Independent rebuilds.
BINARY_NAMES=$(tr -d '\r' < "$REL/SHA256SUMS" | awk '$2 ~ /^q21-(wallet-)?[a-z]+-[a-z0-9_]+$/ {print $2}')
THRESHOLD=0
if [ -f "$ATT/threshold" ]; then
  T=$(tr -d ' \t\r\n' < "$ATT/threshold")
  grep -qE '^[0-9]+$' <<<"$T" || fail "$ATT/threshold must hold a single number, not \"$T\""
  THRESHOLD=$T
fi
if [ -n "$(find "$ATT" -type l 2>/dev/null | head -n 1)" ]; then
  fail "symbolic links under $ATT: refused"
fi
AGREE=0
SEEN_KEYS=" "
: > "$WORK/agreed"
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
    H=$(printf '%s\n' "$LINE" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
    NAME=$(printf '%s\n' "$LINE" | awk '{print $2}' | sed 's/^\*//')
    if ! grep -qxF -- "$NAME" <<<"$BINARY_NAMES"; then
      warn "attestation of $WHO: line for \"$NAME\", not a binary of this release: ignored"
      continue
    fi
    if [ "$(listed "$NAME")" != "$H" ]; then
      fail "$WHO rebuilt $NAME as $H, which is NOT the released binary"
    fi
    KNOWN=$((KNOWN + 1))
    printf '%s %s\n' "$WHO" "$NAME" >> "$WORK/agreed.$WHO"
  done < "$D/SHA256SUMS"
  if [ "$KNOWN" -eq 0 ]; then
    warn "attestation of $WHO states no hash of this release's binaries: not counted"
    continue
  fi
  echo "attestation: $WHO agrees ($KNOWN binaries)"
  SEEN_KEYS="$SEEN_KEYS$KEY_ID "
  sort -u "$WORK/agreed.$WHO" >> "$WORK/agreed"
  AGREE=$((AGREE + 1))
done
echo "attestations: $AGREE independent; $THRESHOLD required for every program"
# Per program: two Linux attestations say nothing about the Windows binary.
for NAME in $BINARY_NAMES; do
  N=$(awk -v n="$NAME" '$2 == n' "$WORK/agreed" | wc -l | tr -d ' ')
  if [ "$N" -lt "$THRESHOLD" ]; then
    fail "$NAME: $N attestation(s), $THRESHOLD required: wait for the builders (attestations/README.md)"
  fi
  [ "$THRESHOLD" -eq 0 ] || echo "  $NAME: $N attestation(s)"
done

echo "RELEASE $TAG ($COMMIT): VERIFIED"
