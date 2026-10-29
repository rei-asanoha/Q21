# Signing releases, and checking what you install

A SHA-256 hash proves that a file arrived intact. It does not prove **who**
released it: produced on the same machine as the archive and published in the
same place, it is replaced along with it by anyone who takes control of the
repository or of an action in the build pipeline. Before installing a binary
that holds keys, you need a proof that no one else can forge: a
**signature** made with a key that never leaves its holder.

Q21 uses [minisign](https://jedisct1.github.io/minisign/): a single file, no
infrastructure, a 56-character public key that fits in a README.

Two proofs, kept apart:

| Proof | Says | Made by |
|---|---|---|
| `SHA256SUMS.minisig` | **who** released these files | the maintainer, offline, with the key of `q21-release.pub` |
| `attestations/<version>/` | these binaries **come from these sources** | anyone who rebuilt them, each with their own key (`attestations/README.md`) |

The first is one person's statement. The second needs no trust in anyone in
particular, and it is what a release can be made to wait for: see section 5.

---

## 1 · Create the key, once, offline

On a machine you trust — a Mac or a Linux PC will do:

```bash
brew install minisign               # macOS
# sudo apt install -y minisign      # Debian, Ubuntu, Raspberry Pi OS
minisign -G -p q21-release.pub -s q21-release.key
```

`minisign` asks for a password for the secret key: choose a long one, write
it down on paper. Two files come out:

| File | What it is | Where it goes |
|---|---|---|
| `q21-release.pub` | the **public** key | at the root of the repository, in the README, in JOIN.md, and through at least one channel that does not depend on GitHub — a page on a domain you control, a signed message elsewhere |
| `q21-release.key` | the **secret** key, encrypted by the password | on the signing machine, and on one offline copy (a USB key in a drawer). **Never** in GitHub, never in a cloud folder, never in a message |

The second channel matters: if the repository were ever taken over, the
copy of the public key inside it would be replaced too. A copy elsewhere is
what lets people notice.

## 2 · Where the key lives: not in GitHub

Up to 0.5.0, the key was stored in GitHub (`MINISIGN_KEY`,
`MINISIGN_PASSWORD`) and signed on a shared build machine. Whoever took over
the GitHub account, or any third-party action in the pipeline, could then
have published a booby-trapped wallet with a valid signature. Since 0.5.1 the
pipeline never signs; it prepares a **draft** release, and the signature is
made on your own machine.

If those two secrets still exist — *Settings → Environments → release*, or
*Settings → Secrets and variables → Actions* — **delete them**. Nothing reads
them any more, and a secret that exists can leak.

## 3 · Releasing a version, step by step

1. **Tag** the version on `main` and push the tag. The pipeline refuses a tag
   that is not on `main`, or that disagrees with the version in `Cargo.toml`;
   it then runs the whole CI on that commit — tests on three systems,
   vendored sources, dependency policy, reproducibility — without cache, and
   only then builds.
2. The run ends with a **draft** release: the five archives and `SHA256SUMS`.
   Nobody but the repository's maintainers can see or download a draft. The
   log of its `SHA256SUMS` job prints the exact signing command.
3. On the draft's page, **download `SHA256SUMS`**.
4. **Recommended:** rebuild the binary of your platform yourself
   (`REPRODUCING.md`) and check that its hash is the line of `SHA256SUMS`
   that names your platform. You then sign what you have checked, not what a
   build machine told you.
5. **Sign**, in the folder holding `SHA256SUMS` and your key:

   ```bash
   minisign -S -s q21-release.key -m SHA256SUMS \
     -t "Q21 v<version> <full commit hash> -- Rei Asanoha"
   ```

   On Windows, in PowerShell, the same with `.\minisign.exe` and the command
   on one line. The trusted comment must be exactly this: the tag, the full
   40-character hash of the tagged commit, and the name. The pipeline refuses
   any other.
6. **Check your own signature:**

   ```bash
   minisign -Vm SHA256SUMS -p q21-release.pub
   ```

   → `Signature and comment signature verified`, then your comment.
7. **Attach** `SHA256SUMS.minisig` to the draft (*Edit* → drop the file →
   *Save draft*). Do **not** click *Publish*.
8. **Publish with the checks:** *Actions* tab → **Publish a signed release** →
   *Run workflow* → the tag (`v0.5.1`). It runs `tools/verify-release.sh` on
   the draft — exactly the seven expected files, the signature against
   `q21-release.pub`, the trusted comment naming this tag and its commit,
   every archive, the program inside every archive against its binary hash,
   and the attestations required by section 5 — and makes the release public
   only if everything holds. Nothing is public before it has been checked.
   If it stops, the release stays a draft: read the red line, fix, run again.

If a release is ever published with the website's *Publish* button instead,
the same checks run right after (the **Verify the published release** job),
and a failure sends it back to draft. That is a safety net for mistakes, not
a lock: for the minutes it takes, the release is public.

A run started by hand (*Actions → Release → Run workflow*) builds the same
files, unsigned, on the run's page only: for testing, never for installing.

## 4 · Check before installing

On the machine that will install — server, Raspberry Pi, PC, Mac —, with the
public key from the README (`RW…`, 56 characters):

```bash
minisign -Vm SHA256SUMS -P <public key>
sha256sum -c SHA256SUMS --ignore-missing
```

The first command must say `Signature and comment signature verified`, and
its trusted comment carries the tag, the commit and the name that signs the
project:

```
Trusted comment: Q21 v0.5.1 <commit hash> -- Rei Asanoha
```

This comment is **covered by the signature**: it can be neither rewritten nor
spoofed without the secret key. The name confers no authority — Q21 has no
governance — it only attests a constant origin from one release to the next.

**Read it, and refuse anything that does not look like it.** The second word
must be the version you meant to download; the third, the commit that version
was tagged on. The second command must say `OK` for the archive you
downloaded. **If either one fails, do not install**: this is not your
release.

**Everything at once, attestations included.** With all seven files of the
release in one folder and a clone of the repository:

```bash
tools/verify-release.sh <folder> v0.5.1 <commit hash> <your copy of the public key> attestations
```

It is the script the pipeline runs: it ends with `VERIFIED`, or stops on the
first thing that does not hold. Run it with the public key you obtained
elsewhere than from this repository, and it trusts the repository for
nothing but the attestations, which are each signed by their own builder.

On Windows, `minisign` can be downloaded from its author's releases page
(`minisign-…-win64.zip`); the check is the same in PowerShell, with
`.\minisign.exe`.

Once installed, `q21 version` says what the program is. The trusted comment
carries the version, but it is attached to the hash file, not to the binary:
six months later, faced with a `q21` found in some folder, this command is
what answers. It needs neither a data directory nor the network.

## 5 · More than one person: independent rebuilds

As long as one person signs, a stolen key or a coerced maintainer can still
publish something else. Bitcoin Core closed this by having **several
independent people** rebuild every release and sign what they got
(`bitcoin-core/guix.sigs`); no release is trusted on one signature.

Q21 has the same mechanism: `attestations/`. Anyone can rebuild a tagged
version (`REPRODUCING.md`), sign the binary hashes they obtained with their
own key, and file them by pull request (`attestations/README.md`). Their key
gives them no right over anything: it only links their attestations together.

The file `attestations/threshold` says how many such attestations, agreeing
with the release's binary hashes, the pipeline requires before a release may
be made public. It is `0` while nobody else rebuilds — the honest state,
said plainly. Raising it is a one-line pull request.

What a threshold of `2` does, and does not: it stops a release whose
programs differ from what independent people rebuilt — a stolen release key,
a compromised build machine, a coerced signer using the normal path. It does
not bind whoever administers this repository, who controls the pipeline,
the threshold and which builder keys are merged; nor does it cover what the
attestations do not list (REPRODUCING.md, section 6, says which files).
The check that binds nobody's word is the one a user runs at home, with
`tools/verify-release.sh` and keys obtained elsewhere — and, best of all, by
rebuilding.

An attestation is counted when its signature verifies with
`attestations/builder-keys/<name>.pub`, its trusted comment names the tag and
the commit, and every hash it states is the release's. A single hash that
differs stops the release: two honest rebuilds of the same commit cannot
disagree.

## 6 · The account that holds the repository

The signature no longer depends on GitHub; the code, the tags and the
release pages still do. In *Settings*:

| Where | What |
|---|---|
| your account → *Password and authentication* | two-factor authentication with a **security key or passkey**, not SMS; recovery codes on paper |
| *Rules → Rulesets → New tag ruleset* | target **all tags**; restrict creation, update and deletion to the maintainers |
| *Rules → Rulesets → New branch ruleset* | target `main`; block force pushes and deletion; require the CI checks |
| *Security → Private vulnerability reporting* | **Enable**: this is the channel `SECURITY.md` points to |

## 7 · If the key is lost or exposed

See `SECURITY.md`, the section on a compromised signing key. In short: say so
publicly at once, create a new key offline, publish its public half in the
repository **and** through the second channel of section 1, and change
`q21-release.pub`, the README and JOIN.md in the same commit (a test refuses
a key printed in one place and not the others).

## 8 · The actions of the build pipeline

The workflows call third-party actions (`actions/checkout`,
`Swatinem/rust-cache`…). Followed by a tag (`@v4`), they can be rewritten by
whoever controls that tag; pinned to a commit hash, they cannot. Every
`uses:` is pinned, with its version in a comment, and a test refuses one that
is not. To follow a newer version, change the version in the comment and run
`tools/pin-actions.sh` from a machine that reaches `api.github.com`; review
the diff before publishing. The Rust toolchain, for its part, is installed by
`rustup` at the version in `rust-toolchain.toml`, without any third-party
action.
