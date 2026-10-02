#!/bin/sh
# Pins each GitHub action of the workflows to the commit hash of its tag.
#
# Why: `uses: actions/checkout@v4` follows a tag, and a tag can be
# rewritten. Whoever takes over an action's repository (or its tag) gets
# their code run in the process that compiles the wallet, and therefore in
# the binary that holds the keys. A commit hash, on the other hand, does not
# move: that is what gets written here, with the tag as a comment to stay
# readable.
#
# Run it from the repository root, on a machine that can reach
# api.github.com (curl and python3 are enough). Then review the diff, and
# publish. Redo it when you want to follow a new version of an action:
# change the tag in the comment, run the script again.
set -eu

api() {
  curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/$1"
}

# Returns the commit hash designated by `owner/repo@tag`.
# An annotated tag points to a tag object, which we unwrap.
commit_hash() {
  repo="$1"; tag="$2"
  ref=$(api "repos/$repo/git/ref/tags/$tag")
  type=$(printf '%s' "$ref" | python3 -c 'import json,sys; print(json.load(sys.stdin)["object"]["type"])')
  sha=$(printf '%s' "$ref" | python3 -c 'import json,sys; print(json.load(sys.stdin)["object"]["sha"])')
  if [ "$type" = "tag" ]; then
    sha=$(api "repos/$repo/git/tags/$sha" | python3 -c 'import json,sys; print(json.load(sys.stdin)["object"]["sha"])')
  fi
  printf '%s' "$sha"
}

for f in .github/workflows/*.yml; do
  tmp="$f.pinned"
  cp "$f" "$tmp"
  # Each line `uses: owner/repo@tag` (no comment, so not pinned yet) or
  # `uses: owner/repo@<40 hex> # tag` (already pinned: we follow the tag in
  # the comment).
  grep -n 'uses: *[A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*@' "$f" | while IFS=: read -r line_no line; do
    repo=$(printf '%s' "$line" | sed -n 's/.*uses: *\([A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]*\)@.*/\1/p')
    target=$(printf '%s' "$line" | sed -n 's/.*uses: *[A-Za-z0-9_.-]*\/[A-Za-z0-9_.-]*@\([^ #]*\).*/\1/p')
    comment=$(printf '%s' "$line" | sed -n 's/.*# *\([^ ]*\).*/\1/p')
    if printf '%s' "$target" | grep -qE '^[0-9a-f]{40}$'; then
      tag="${comment:-}"
      [ -n "$tag" ] || { echo "  $repo: already pinned with no tag in a comment, left as is"; continue; }
    else
      tag="$target"
    fi
    case "$tag" in
      master|main) echo "  $repo@$tag: a branch, not a version; replace it by hand"; continue ;;
    esac
    sha=$(commit_hash "$repo" "$tag") || { echo "  $repo@$tag: not found"; continue; }
    indent=$(printf '%s' "$line" | sed -n 's/^\( *-\{0,1\} *\)uses:.*/\1/p')
    sed -i "${line_no}s|.*|${indent}uses: ${repo}@${sha} # ${tag}|" "$tmp"
    echo "  $repo@$tag -> $sha"
  done
  if cmp -s "$f" "$tmp"; then
    rm -f "$tmp"
  else
    mv "$tmp" "$f"
    echo "$f: pinned"
  fi
done
echo "Review the diff (git diff .github/workflows), then publish."
