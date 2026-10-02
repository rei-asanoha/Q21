# Reproducing the Q21 binary, and checking what you install

A SHA-256 hash published next to a file proves almost nothing. It is produced
on the same machine as the file, published in the same place, and replaced
along with it by anyone who takes control of the repository or of a step in
the build pipeline. A `minisign` signature (see SIGNING.md) proves more — it
says **who** built the file — but it does not say that this file matches the
published sources. A stolen key signs a booby-trapped binary just as well as
an honest one.

The only check that does not require trusting anyone is this one: **rebuild
the sources yourself and get exactly the same file, byte for byte.** If ten
people do it at home and announce the same hash, no key, no account, no
server has to be taken at its word anymore.

This is the property Bitcoin Core gave itself in 2011 with Gitian, then in
2021 with Guix, and the `bitcoin-core/guix.sigs` repository where each
builder files the hash they obtained. Q21 does the same thing, on a smaller
scale.

---

## 1 · Why a build is not reproducible by default

`cargo build --release` writes into the binary the absolute path of the
source files of the dependencies, so that panic messages say where the
problem happened. Measured on a Q21 binary built without precautions:

```
/home/you/q21/vendor/ml-dsa/src/signing.rs
/home/you/q21/vendor/ml-dsa/src/sampling.rs
/home/you/q21/vendor/ml-dsa/src/algebra.rs
/home/you/q21/vendor/hybrid-array/src/iter.rs
... nine paths in all
```

Two consequences, the second more serious than the first:

1. the published binary tells where it was built — hence the account name of
   the machine that produced it;
2. **two people who build the same commit in two different directories get
   two different binaries.** Their hashes differ. Verification by rebuilding
   becomes impossible: you can no longer tell "the file was modified" from
   "I don't have the same path as you".

The other paths the binary contains — `/rustc/<compiler
hash>/library/...` and `/rust/deps/...` — are already neutralized by the Rust
distribution itself. They are identical on every machine with the same
compiler version. This is why `rust-toolchain.toml` pins `1.95.0`: without
this pin, "stable" designates a different version every six weeks, and
nothing is comparable.

---

## 2 · What Q21 has put in place

| Piece | File | What it guarantees |
|---|---|---|
| frozen toolchain | `rust-toolchain.toml` | the same compiler, today and six months from now |
| frozen dependencies | `Cargo.lock` + `--locked` | the same versions, down to the patch |
| bundled sources | `vendor/` | no download, hence no source changing under your feet |
| `vendor/` checked | `vendor` job of `ci.yml` | `vendor/` is identical, byte for byte, to what crates.io serves for this `Cargo.lock` |
| paths removed | `tools/build-reproducible.sh` | the binary no longer knows in which directory it was built |
| automatic proof | `reproducible` job of `ci.yml` | two builds, two directories, a single hash — checked on every push |
| release safeguard | "No build path in the binary" step of `release.yml` | a release that has lost the remapping does not go out |

Cargo's `trim-paths` setting would do the job in one line in `Cargo.toml`.
It is **not** stabilized in Cargo 1.95.0, the pinned version:

```
feature `trim-paths` is required
The package requires the Cargo feature called `trim-paths`, but that
feature is not stabilized in this version of Cargo (1.95.0)
```

Q21 therefore uses `--remap-path-prefix`, stable since 2018, and sets it
through a script rather than in `Cargo.toml` — because the path to remap
depends on the machine and cannot be written in advance in a file of the
repository.

---

## 3 · Reproducing the binary — step by step

You need nothing other than `git` and the Rust toolchain. Count on a minute
of compilation on a desktop machine, about ten on a Raspberry Pi.

### Step 1 · Get the sources at the exact version

```bash
git clone https://github.com/<account>/q21.git
cd q21
git checkout v0.4.0        # or the published commit hash
```

**What you should see**

```
Note: switching to 'v0.4.0'.
You are in 'detached HEAD' state. ...
HEAD is now at <commit> ...
```

`detached HEAD` is not an error. It means "you are looking at a frozen
version and not at a branch that moves forward", which is exactly what we
want.

**If this fails** — `pathspec 'v0.4.0' did not match`: the tag does not
exist yet. Use the commit hash published with the release:
`git checkout <commit>`.

### Step 2 · Install the announced toolchain

```bash
rustup show
```

**What you should see** — `rustup` reads `rust-toolchain.toml` and installs
the right version by itself if it is missing:

```
active toolchain
----------------
name: 1.95.0-x86_64-unknown-linux-gnu
active because: overridden by '/home/you/q21/rust-toolchain.toml'
```

**The point to check**: `1.95.0`, and the mention of `rust-toolchain.toml`.
If you see `stable-x86_64-...` without that mention, your `rustup` is too old
to read the file; update it (`rustup self update`) and start again.

### Step 3 · Build

```bash
./tools/build-reproducible.sh
```

On Windows, in PowerShell, at the root of the repository:

```powershell
powershell -ExecutionPolicy Bypass -File tools\build-reproducible.ps1
```

**What you should see** — first the three header lines, which say what the
script is going to do:

```
Project root: /home/you/q21
Remapping:    /home/you/q21 -> /q21
Toolchain:    rustc 1.95.0 (59807616e 2026-04-14)

   Compiling zeroize v1.9.0
   Compiling hybrid-array v0.4.14
   ...
   Compiling ml-dsa v0.1.1
   Compiling q21-core v0.4.0 (/home/you/q21)
    Finished `release` profile [optimized] target(s) in 37.49s

Binary: target/release/q21
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  target/release/q21
```

The last line is the result. This is the hash to compare.

The 64 characters shown here are those of a specific version; **they change
with every commit**, since the binary changes. Never compare them with this
document: compare them with the `SHA256SUMS` published with the release you
are trying to verify, and with the attestations in the `attestations/`
folder.

**If this fails**

| Message | What it means | What to do |
|---|---|---|
| `error: RUSTFLAGS is already set in the environment:` | an environment variable would replace the reproducibility flags — cargo takes one **or** the other, it does not combine them | `unset RUSTFLAGS`, then run again |
| `error: the lock file needs to be updated` | `Cargo.lock` does not match the sources | you are not on the published commit; redo step 1 |
| `error: failed to get 'ml-dsa'` … `offline` | `vendor/` is missing or incomplete | `git status`; the `vendor/` folder is part of the repository and must be there |
| `error[E0658]` | the compiler is not the right one | redo step 2 |

### Step 4 · Compare with the published hash

The reference hash is published in two places that do not depend on each
other: in the release's `SHA256SUMS` file, signed by `SHA256SUMS.minisig`,
and in the attestations repository (`attestations/`, section 5 below).

```bash
sha256sum target/release/q21
```

**What you should see**: the same 64-character string as the published one.
Character for character — a hash that differs by a single sign designates an
entirely different file.

**If the hashes differ**, in this order:

1. check that you are on the same commit: `git rev-parse HEAD`;
2. check the compiler version: `rustc --version`;
3. check that the remapping took effect — **no** occurrence of your path
   must remain in the binary:

```bash
strings -a target/release/q21 | grep "$(pwd -P)" | head
```

**What you should see**: nothing at all. The command returns no line.

And what replaces them:

```bash
strings -a target/release/q21 | grep '^/q21' | sort -u
```

**What you should see**: eight or nine lines starting with `/q21/vendor/`,
identical on every machine.

4. if all of this matches and the hashes still differ, **say so publicly**:
   open an issue on the repository giving your system, your architecture,
   `rustc --version` and the hash you got. A reproducible disagreement is
   valuable information — either the published binary does not come from
   these sources, or the build still depends on a variable nobody has seen.
   Both deserve to be known.

---

## 4 · Checking reproducibility yourself, without publishing anything

The repository carries the test bench:

```bash
./tools/verify-reproducible.sh
```

It copies the sources into two temporary directories of different length and
depth, builds in each one with no shared cache, and compares.

**What you should see**, at the end:

```
=== Result ===
A: 85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5
B: 85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5

IDENTICAL: the build is reproducible.
```

**What this bench does not prove.** It compares two builds on the **same**
machine, with the same system and the same compiler. It eliminates the
"directory" variable, which was the only remaining variable measured on Q21.
It says nothing about the "machine" variable: a different distribution, a
different C library, a different architecture can still produce a different
binary — and that is normal, a Linux x86-64 binary has no reason to equal a
macOS ARM binary. The comparison is **per platform**, and it requires several
people. Hence the next section.

---

## 5 · Attesting: several people, one hash

A single builder, even honest, even careful, remains a single point of
trust. If their machine is compromised, their binary is booby-trapped and so
is their hash. Bitcoin Core's answer is to have several independent people
build and to publish what **each** of them obtains: the
`bitcoin-core/guix.sigs` repository contains one folder per version, one
subfolder per builder, and the signed hash that builder obtained. When twelve
builders out of twelve announce the same 64-character string, twelve machines
would have to be compromised at once to deceive anyone.

Q21 carries the same structure, empty, ready to receive attestations:
`attestations/`. Its procedure is in `attestations/README.md`: how to file
your public key, how to produce an attestation, how to check other people's.

The honest rule to remember, and it is worth saying clearly: **as long as the
only builder is the maintainer, reproducibility is an available tool, not an
obtained guarantee.** It becomes a guarantee the day a second person, who
does not depend on the first, files a matching attestation. The work done
here makes that day possible; it does not replace it.

---

## 6 · What remains out of reach

Three limits, stated in advance rather than discovered later.

**The toolchain itself is not reproduced.** Q21 trusts the `rustc` binaries
distributed by the Rust project. Rebuilding them from their sources — which
Guix does for Bitcoin Core — would require an infrastructure this project
does not have. The tradeoff is explicit: the compiler is pinned and
verifiable by its hash, but it is trusted.

**Cross-compilation is not used.** Each platform is built on its own machine
(`release.yml`), which avoids assumptions, but means that a Windows binary
cannot be checked from Linux. To check the binary for your system, you need
that system.

**Determinism is only measured on this project.** A dependency update can
introduce a `build.rs` that writes a date, a path, a machine name. The
`reproducible` job of `ci.yml` is there so that, on that day, the merge stops
instead of going through.

**The `.tar.gz` and `.zip` archives are not reproducible, and cannot be as
things stand.** An archive records for each file a modification date, an
owner and permissions, which depend on the machine and the moment: two
releases give two different archives even when the binary they contain is
identical. This is why the `SHA256SUMS` file published with each release
carries **two kinds of lines**, separated and labeled:

```
# Archives — download integrity. Not reproducible:
# an archive records dates, owners and permissions.
4b91…  q21-linux-x86_64.tar.gz
#
# Binaries — to compare after rebuilding (REPRODUCING.md).
# Same commit + same platform + same toolchain = same hash.
85092844…  q21-linux-x86_64
```

What you reproduce and compare is **the second kind**: the bare binary,
extracted from the archive or rebuilt by you. Comparing your rebuilt binary
with the hash of an archive cannot match, and it is the easiest mistake to
make here.

---

## 7 · Summary in four commands

```bash
git clone https://github.com/<account>/q21.git && cd q21
git checkout <published tag or hash>
./tools/build-reproducible.sh
sha256sum target/release/q21        # compare with the published hash
```

If the 64-character string matches, you have the proof — and not just the
assurance — that the published binary comes from these sources.
