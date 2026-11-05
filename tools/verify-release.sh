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
# 2. SHA256SUMS is signed by the key, the trusted comment names this tag
#    and this commit, and no file is named twice;
# 3. every archive has the hash SHA256SUMS gives it;
# 4. inside every archive: the program is the binary SHA256SUMS names for its
#    platform — the one independent builders rebuild — and so is the Windows
#    launcher; every file that comes from the repository (documents,
#    bootstrap.txt, launcher scripts, Info.plist) is byte for byte the one of
#    the tagged commit; nothing else is there but Tor and the macOS bundle's
#    signature; no entry is a link, an extended header (pax, GNU long
#    name), a duplicate (case ignored), an absolute path or a `..`;
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
# Needs bash, git, minisign, tar, gzip, od, dd, unzip, zipinfo, and sha256sum
# or shasum.
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
# A tar archive read header by header, strictly, and listed: every entry a
# plain file ('0', or NUL in old archives) or a folder ('5', size 0, name
# ending in '/'); each header's checksum right; each size field the eleven
# octal digits every tar writes; names printable ASCII. Prints the names, one
# per line; fails on anything else. Extended headers (pax 'x' and 'g', GNU
# 'L', 'K'...) and every irregular field are refused: tar programs do not all
# read them the same way, so the same archive could unpack one program for
# this check and another one on a user's Mac (red-team campaign 8).
strict_tar_names() {
  local T=$1 OFF=0 N=0 LEN LINE SIZE
  LEN=$(wc -c < "$T" | tr -d ' ')
  while [ $((OFF + 512)) -le "$LEN" ]; do
    N=$((N + 1))
    [ "$N" -le 100000 ] || return 1
    LINE=$(od -An -v -tu1 -j "$OFF" -N 512 "$T" | awk '
      { for (i = 1; i <= NF; i++) b[n++] = $i }
      END {
        if (n != 512) { print "BAD"; exit }
        zero = 1; for (i = 0; i < 512; i++) if (b[i] != 0) zero = 0
        if (zero) { print "END"; exit }
        sum = 0; for (i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 32 : b[i]
        # Checksum: six octal digits, then NUL and space.
        ck = 0; for (i = 148; i < 154; i++) { if (b[i] < 48 || b[i] > 55) { print "BAD"; exit }; ck = ck * 8 + b[i] - 48 }
        if (b[154] != 0 || b[155] != 32 || ck != sum) { print "BAD"; exit }
        # Size: eleven octal digits, then NUL or space.
        sz = 0; for (i = 124; i < 135; i++) { if (b[i] < 48 || b[i] > 55) { print "BAD"; exit }; sz = sz * 8 + b[i] - 48 }
        if (b[135] != 0 && b[135] != 32) { print "BAD"; exit }
        t = b[156]
        if (t != 0 && t != 48 && t != 53) { print "BAD"; exit }
        # The name: prefix "/" name, printable ASCII, NUL-padded.
        name = ""
        for (k = 0; k < 2; k++) {
          s = (k == 0) ? 345 : 0; e = (k == 0) ? 500 : 100; part = ""; ended = 0
          for (i = s; i < e; i++) {
            if (b[i] == 0) { ended = 1; continue }
            if (ended || b[i] < 32 || b[i] > 126) { print "BAD"; exit }
            part = part sprintf("%c", b[i])
          }
          if (k == 0 && part != "") name = part "/"
          if (k == 1) name = name part
        }
        if (name == "") { print "BAD"; exit }
        dir = (substr(name, length(name), 1) == "/")
        if (t == 53 && (!dir || sz != 0)) { print "BAD"; exit }
        if (t != 53 && dir) { print "BAD"; exit }
        print sz " " name
      }')
    case "$LINE" in
      END)
        # The end: nothing after but zeros.
        [ -z "$(tail -c +$((OFF + 1)) "$T" | tr -d '\000' | head -c 1)" ] || return 1
        return 0 ;;
      BAD|'') return 1 ;;
    esac
    SIZE=${LINE%% *}
    printf '%s\n' "${LINE#* }"
    OFF=$((OFF + 512 + (SIZE + 511) / 512 * 512))
  done
  return 1
}
# A zip archive whose every local header names what the central directory
# names, at the offsets it gives, with nothing between the entries: unzip
# reads the central directory, other programs (the tar of Windows) the local
# headers; both must see the same files (red-team campaign 8). Its names are
# printable ASCII, as in the tar archives, and every local header gives the
# central directory's compressed size, never a data descriptor: a program
# reading the local headers would otherwise cut the data elsewhere
# (red-team campaign 9).
strict_zip() {
  local Z=$1 EXPECT=0 COUNT=0 OFFSET NAME CSIZE DESC LNAME NLEN XLEN SIG LCSIZE LFLAG
  while IFS='|' read -r OFFSET CSIZE DESC NAME; do
    COUNT=$((COUNT + 1))
    [ "$OFFSET" = "$EXPECT" ] || return 1
    SIG=$(od -An -tx1 -j "$OFFSET" -N 4 "$Z" | tr -d ' \n')
    [ "$SIG" = 504b0304 ] || return 1
    XLEN=$(od -An -tu1 -j $((OFFSET + 28)) -N 2 "$Z" | awk '{print $1 + 256 * $2}')
    NLEN=$(od -An -tu1 -j $((OFFSET + 26)) -N 2 "$Z" | awk '{print $1 + 256 * $2}')
    LNAME=$(dd if="$Z" bs=1 skip=$((OFFSET + 30)) count="$NLEN" 2>/dev/null)
    [ "$LNAME" = "$NAME" ] || return 1
    if LC_ALL=C grep -q '[^ -~]' <<<"$LNAME"; then return 1; fi
    # No data descriptor: its sizes come after the data, where a program
    # reading the local headers cannot check them first. A release archive,
    # written to a file, never uses one (round 2 of red-team campaign 9).
    [ "$DESC" = no ] || return 1
    # ... in the local header as well, where the central directory may say
    # otherwise (round 3 of red-team campaign 9).
    LFLAG=$(od -An -tu1 -j $((OFFSET + 6)) -N 1 "$Z" | tr -d ' \n')
    case $LFLAG in ""|*[!0-9]*) return 1 ;; esac
    [ $((LFLAG & 8)) -eq 0 ] || return 1
    LCSIZE=$(od -An -tu1 -j $((OFFSET + 18)) -N 4 "$Z" \
      | awk '{print $1 + 256 * $2 + 65536 * $3 + 16777216 * $4}')
    [ "$LCSIZE" = "$CSIZE" ] || return 1
    EXPECT=$((OFFSET + 30 + NLEN + XLEN + CSIZE))
  done < <(zipinfo -v "$Z" | awk '
    /^Central directory entry #/ { if (have) print off "|" cs "|" ds "|" nm; have = 1; nm = ""; getline; getline; getline; while ($0 ~ /^  There are an extra/ || $0 == "") getline; sub(/^  /, ""); nm = $0 }
    /offset of local header from start of archive:/ { off = $NF }
    /^  compressed size:/ { cs = $3 }
    /extended local header:/ { ds = $NF }
    END { if (have) print off "|" cs "|" ds "|" nm }')
  [ "$COUNT" -gt 0 ] || return 1
  # The central directory comes right after the last entry.
  [ "$(od -An -tx1 -j "$EXPECT" -N 4 "$Z" | tr -d ' \n')" = 504b0102 ] || return 1
}

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
# One line per name: a second line for a program would let a check read the
# first and a rebuild match the second.
TWICE=$(tr -d '\r' < "$REL/SHA256SUMS" | awk 'NF && $1 !~ /^#/ {print $2}' | sort | uniq -d)
[ -z "$TWICE" ] || fail "SHA256SUMS names some files more than once: $TWICE"

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
      strict_zip "$REL/$A" \
        || fail "$A: its local headers do not name what its central directory names, or entries are hidden between them"
      NAMES=$(zipinfo -1 "$REL/$A")
      LONG=$(zipinfo "$REL/$A")
      if grep -q '^l' <<<"$LONG"; then fail "$A holds a symbolic link"; fi
      ;;
    *)
      gzip -dc < "$REL/$A" > "$WORK/raw.tar" || fail "$A is not a gzip archive"
      STRICT=$(strict_tar_names "$WORK/raw.tar") \
        || fail "$A holds an entry that is not a plain file or folder with regular headers (extended or link header, bad checksum or size field, irregular name)"
      rm -f "$WORK/raw.tar"
      NAMES=$(tar -tzf "$REL/$A")
      # What tar lists is exactly what the strict reading saw.
      [ "$STRICT" = "$NAMES" ] || fail "$A: tar lists other entries than its headers hold"
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
    # A warning (exit 1) is refused too: backslashes read as slashes, or a
    # local name that differs from the central one, are read otherwise by
    # other programs.
    *.zip) unzip -q "$REL/$A" -d "$D" || fail "$A cannot be unpacked without a warning"
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
