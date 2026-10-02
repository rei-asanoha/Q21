# Signing releases, and checking what you install

A SHA-256 hash proves that a file arrived intact. It does not prove **who**
built it: produced on the same machine as the archive and published in the
same place, it is replaced along with it by anyone who takes control of the
repository or of an action in the build pipeline. Before installing a binary
that holds keys, you need a proof that no one else can forge: a
**signature** made with a key that never leaves the operator.

Q21 uses [minisign](https://jedisct1.github.io/minisign/): a single file, no
infrastructure, a 56-character public key that fits in a README. The release
**fails** if the key is not configured: an unsigned release is not a release.

---

## 1 · Create the key, once, offline

On a trusted machine — the Raspberry Pi will do, or a Mac:

```bash
sudo apt install -y minisign        # Debian, Raspberry Pi OS
# brew install minisign             # macOS
minisign -G -p q21-release.pub -s q21-release.key
```

`minisign` asks for a password for the secret key: choose a long one, write
it down on paper. Two files come out:

| File | What it is | Where it goes |
|---|---|---|
| `q21-release.pub` | the **public** key | in the README, in the `q21-release.pub` file at the root of the repository, and through a second channel — a message, a page you control |
| `q21-release.key` | the **secret** key, encrypted by the password | in the repository's secrets, then nowhere else but an offline copy |

## 2 · Entrust the key to the release — in a protected environment

A **repository** secret is readable by any run started from the repository,
on any branch: anyone who can push a branch and click "Run workflow" — a
collaborator, a leaked token, a taken-over account — gets whatever they want
signed, or replaces the signing step with one that sends the key elsewhere.
This is why the key does not live in the repository secrets, but in a GitHub
**environment** that only the `sign` job uses, and that accepts only `main`
and `v*` tags.

In the GitHub repository: *Settings → Environments → New environment*, name
**`release`**, then:

| Setting | Value |
|---|---|
| *Required reviewers* | yourself — every release waits for your click |
| *Deployment branches and tags* | *Selected branches and tags*: `main`, and the pattern `v*` |
| *Environment secrets* → *Add secret* | `MINISIGN_KEY`: the full content of `q21-release.key` (two lines) |
| *Environment secrets* → *Add secret* | `MINISIGN_PASSWORD`: the password chosen at creation |

If both secrets already existed **at the repository level**, delete them
there once copied into the environment: as long as they remain there, the
protection is only apparent.

Then erase `q21-release.key` from the machine, or store it on offline media.
The public key, on the other hand, is meant to be seen: paste its second line
into the README.

The GitHub account that holds this environment must have **two-factor
authentication** enabled: in the last resort, it is what controls the
signature. An account recovery address is one more signing key.

## 3 · What the release produces

On every release, the **Signing** job gathers the hashes of all the archives
into `SHA256SUMS` and signs it: `SHA256SUMS.minisig`. Both are uploaded
together, in the `SHA256SUMS-signed` artifact.

Then it **cross-checks its own signature** with `q21-release.pub`, the public
key file versioned in the repository — the one people copy from the README.
This check closes two silent failures: a key changed in the secrets without
the repository following, and a subtly wrong secret. In both cases the
release would go out signed with a key that nobody can verify, and we would
only find out from a user's complaint. The release now fails instead.

If you ever rotate the key, the two therefore go together: the secret in the
GitHub environment, **and** `q21-release.pub` plus the README in the same
commit. The release pipeline will refuse any other combination.

## 4 · Check before installing

On the machine that will install — server, Raspberry Pi, PC, Mac —, with the
public key from the README (`RW…`, 56 characters):

```bash
minisign -Vm SHA256SUMS -P <public key>
sha256sum -c SHA256SUMS --ignore-missing
```

The first command must say `Signature and comment signature verified`, and
its trusted comment carries the tag, the commit of the build and the name
that signs the project:

```
Trusted comment: Q21 main <commit hash> -- Rei Asanoha
```

This comment is **covered by the signature**: it can be neither rewritten nor
spoofed without the secret key. The name confers no authority — Q21 has no
governance — it only attests a constant origin from one release to the next.

**Read it, and refuse anything that does not look like it.** The second word
must be `main` or a `v…` tag; the third, the hash of the commit you expected
(the one shown at the top of the run in the Actions tab). A comment that
names another branch, or a commit you have not reviewed, is a valid
signature of something you did not want: **do not install**. And never
install from a red run, even if the archives are there — a red run is a run
whose signature failed. The second command must say `OK` for the archive you
downloaded. **If either one fails, do not install**: this is not your
release.

On Windows, `minisign` can be downloaded from its author's releases page;
the check is the same in PowerShell.

Once installed, `q21 version` says what the program is. The trusted comment
carries the version, but it is attached to the hash file, not to the binary:
six months later, faced with a `q21` found in some folder, this command is
what answers. It needs neither a data directory nor the network.

## 5 · The actions of the build pipeline

The workflows call third-party actions (`actions/checkout`,
`Swatinem/rust-cache`…). Followed by a tag (`@v4`), they can be rewritten;
pinned to a commit hash, they cannot. The script `tools/pin-actions.sh`, run
from a machine that has access to `api.github.com`, rewrites every `uses:`
with the hash of its tag. Review the diff, publish. The Rust toolchain, for
its part, is installed by `rustup` at the version in `rust-toolchain.toml`,
without any third-party action.
