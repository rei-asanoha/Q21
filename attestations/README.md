# Build attestations

For each published version of Q21, this folder collects the SHA-256 hash that
**each** person who rebuilt the sources obtained, together with their
signature.

It starts out empty. That is normal, and it is in fact the point: it is not
up to the maintainer to fill it alone.

---

## 1 · What it is for, on one page

Three checks are possible on a published binary, from weakest to strongest.

| Check | What it proves | What it does not prove |
|---|---|---|
| the attached SHA-256 hash | the file arrived intact | nothing about its origin — it is produced and published by the same person as the file |
| the `minisign` signature of `SHA256SUMS` | **who** built the file | that the file matches the published sources: a stolen key signs a booby-trapped binary just as well as an honest one |
| **several matching attestations** | the file really does come from these sources, and all of those machines would have to be compromised at once to publish a different one | nothing about the quality of the code itself |

The third is the only one that does not require trusting anyone in
particular. It requires two things:

1. that the build be **reproducible** — two people who build the same commit
   get the same file. This is done: see REPRODUCING.md, and the
   `reproducible` job of `ci.yml`, which checks it on every push;
2. that **several independent people** do it and publish their result. That
   is what this folder is for.

It is the mechanism of `bitcoin-core/guix.sigs`, on a smaller scale.

**What is true today, said plainly:** as long as the only builder is the
maintainer, reproducibility is an available tool, not an obtained guarantee.
An attestation filed by a person who does not depend on the maintainer — not
their machine, not their account, not their key — is what turns the one into
the other.

---

## 2 · Folder layout

```
attestations/
├── README.md                     ← this file
├── builder-keys/
│   ├── README.md                 ← how to file your key
│   └── <pseudonym>.pub           ← one minisign public key per builder
└── <version>/
    └── <pseudonym>/
        ├── SHA256SUMS            ← the hashes obtained by this builder
        └── SHA256SUMS.minisig    ← their signature of that file
```

Example of what it looks like once two people have been through:

```
attestations/
├── builder-keys/
│   ├── rei-asanoha.pub
│   └── someone-else.pub
└── v0.4.1/
    ├── rei-asanoha/
    │   ├── SHA256SUMS
    │   └── SHA256SUMS.minisig
    └── someone-else/
        ├── SHA256SUMS
        └── SHA256SUMS.minisig
```

The two `SHA256SUMS` files must be **identical line for line**. That is the
whole point.

### The `SHA256SUMS` format

Exactly what `sha256sum` outputs: the hash, two spaces, the file name. One
line per binary, the name without a path, sorted by name.

```
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  q21-linux-x86_64
d3f1...                                                            q21-linux-arm64
```

Only attest platforms you have **actually** built. A Linux x86-64 binary has
no reason to equal a macOS ARM binary: the comparison is made per platform,
never across platforms.

---

## 3 · Filing an attestation — step by step

### Step 1 · Rebuild, and get a hash

Follow REPRODUCING.md, sections 3.1 to 3.3. At the end, you have:

```
Binary: target/release/q21
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  target/release/q21
```

### Step 2 · Create your key, once

```bash
minisign -G -p <pseudonym>.pub -s <pseudonym>.key
```

**What you should see**

```
Please enter a password to protect the secret key.
Password:
Password (one more time):
Deriving a key from the password in order to encrypt the secret key... done
The secret key was saved as <pseudonym>.key - Keep it secret!
The public key was saved as <pseudonym>.pub - That one can be public!
```

The `.key` file never leaves your machine. The `.pub` file is meant to be
published.

### Step 3 · Write the hash file

In a working folder, a file named `SHA256SUMS`:

```
85092844ddfe376d049f7a997437e58324704e798e50452e30f10d5d2dcfb8d5  q21-linux-x86_64
```

### Step 4 · Sign that file

```bash
minisign -S -s <pseudonym>.key -m SHA256SUMS \
  -t "Q21 v0.4.1 <commit hash> reproduced by <pseudonym>"
```

**What you should see**: the password prompt, then nothing — silence means
success. A `SHA256SUMS.minisig` file appears next to it.

The `-t` text is a trusted comment, written into the signature and signed
with it. Put the version and the commit hash in it: this prevents a
signature from being replayed for another version.

### Step 5 · Check your own signature before publishing it

```bash
minisign -Vm SHA256SUMS -p <pseudonym>.pub
```

**What you should see**

```
Signature and comment signature verified
Trusted comment: Q21 v0.4.1 <commit> reproduced by <pseudonym>
```

**If you see** `Signature verification failed`: the `SHA256SUMS` file has
changed since it was signed. Redo step 4.

### Step 6 · Submit the files to the repository

Three files, at the three locations described in section 2:

```
attestations/builder-keys/<pseudonym>.pub
attestations/v0.4.1/<pseudonym>/SHA256SUMS
attestations/v0.4.1/<pseudonym>/SHA256SUMS.minisig
```

Then a pull request titled, for example,
"attestation v0.4.1 — <pseudonym>".

**Never modify** a folder bearing someone else's pseudonym. A pull request
that touches a third party's attestation must be refused on principle, even
if it looks harmless.

---

## 4 · Checking other people's attestations

You need no rights on the repository for this, and it is the most useful
thing a third party can do.

```bash
cd attestations/v0.4.1
for D in */; do
  P="../builder-keys/${D%/}.pub"
  printf '%-24s ' "${D%/}"
  minisign -Vm "$D/SHA256SUMS" -p "$P" >/dev/null 2>&1 \
    && echo "signature valid" || echo "SIGNATURE INVALID"
done
```

Then the check that matters — all the `SHA256SUMS` files must be identical:

```bash
sha256sum */SHA256SUMS
```

**What you should see**: the same hash on the left on every line.

```
9b1c...e7  rei-asanoha/SHA256SUMS
9b1c...e7  someone-else/SHA256SUMS
```

**If a hash differs**, one of the builders got a binary different from the
others. That is not necessarily malice — it may be a mislabeled platform, a
different commit, a different compiler. But it must be **said publicly** and
cleared up before a version is recommended. Open an issue on the repository
with the two files side by side.

---

## 5 · The rule on keys, declared in advance

A key filed in `builder-keys/` **authorizes nothing**. It allows neither
publishing, nor merging, nor deciding. Its only use is to link an
attestation to a stable identity, so that one can see that the same person
attests several versions in a row.

There is therefore no "trusted key" in Q21, and there never will be. See
SUCCESSION.md, the section on the absence of a master key: a key able to
impose something on the network is an architectural flaw, not a security
measure. Bitcoin had one — the alert key — and retired it in 2016 after
finding that it was a single point of compromise and a power that no one
should have held.

What counts for trust here is arithmetic, not hierarchy: the number of
independent people who announce the same hash.
