# Succession — what happens to Q21 without its maintainer

This document exists for a simple reason: a protocol that depends on one
person is not a protocol, it is a service. It is written **before** the
question arises, because a succession rule improvised on the day it is needed
is worth nothing — anyone can then declare themselves the successor, and
nobody has a criterion to decide.

It answers four questions, in this order:

1. what survives the maintainer, and what dies with them;
2. how a new maintainer is recognized;
3. how to start again, technically, without them;
4. why there is no master key, and why there never will be.

---

## 1 · What survives, what dies

Two things that are often confused must be kept apart: the **protocol** and
the **chain**.

### The protocol survives entirely

| Piece | Why it depends on no one |
|---|---|
| the code | published, licensed MIT OR Apache-2.0, clonable, modifiable, redistributable |
| the dependencies | bundled in `vendor/`, checked identical to crates.io by the `vendor` job — nothing to download, no server to reach |
| the compiler | pinned to `1.95.0` by `rust-toolchain.toml` |
| the genesis | `genesis_block(network)` is **entirely deterministic**: no external data, no build date, no randomness. Two machines compute it identically, forever |
| the entry point | **no** domain is compiled into the binary (`builtin_bootstrap` returns three empty lists, and the test `no_domain_is_compiled_into_the_binary` requires it). The binary never reaches any of the maintainer's infrastructure |
| telemetry | there is none. No outgoing call to anything that belongs to the maintainer: no statistics, no update check, no "ping" |
| verifiability of the binary | reproducible: anyone can rebuild and get the same hash (REPRODUCING.md) |

Practical consequence: the day the maintainer disappears — voluntarily,
accidentally, permanently — **nothing breaks in the code**. A node already
running keeps running. A binary already built keeps working. A person who has
a copy of the repository can build, start a node, and take over the protocol
without asking anyone for anything.

### The chain dies if nobody keeps a copy

This is the honest limit, and there is no elegant way around it.

A blockchain is data, not just a program. If the maintainer's server stops,
the Raspberry Pi is unplugged, the PC and the Mac stop mining, and **no other
machine** holds a copy of the blocks, then the history is lost. The protocol
survives; the chain does not. Someone could restart Q21 — but from genesis,
with an empty history, and the balances of the old chain would no longer
exist.

There is only one way to close this hole, and it cannot be written in code:
**several full nodes, on several machines, run by several people.** One full
node is enough to save the chain; two make it robust; ten make it hard to
kill.

What Q21 offers to keep this simple:

- a full node keeps the whole history by default (pruning is a choice, not
  the default setting);
- `q21 revalidate` lets anyone **re-check the whole chain from genesis**
  using another node's block file, without having to trust that node
  (section 3.4);
- no node has a special status. There is no privileged "maintainer's node"
  in the protocol.

**The sentence to remember**: the code is saved by its publication, the chain
is saved by its replication. The first is done. The second needs other
people.

---

## 2 · How a new maintainer is recognized

### The rule, declared here and in advance

Q21 has **no** succession mechanism in the protocol. No node asks any
authority who the maintainer is; no key confers any power over the network.
Succession is therefore a social fact, not a technical one — and the only
useful thing that can be done is to say in advance how one will recognize
that it has taken place.

Three criteria, which must all be met:

**1. Continuity through the chain of signed tags.** Every published version
is a signed git tag. The successor is the person whose key signs the next
tag, **and** whose key was announced in a tag signed by the previous key,
before the transition. It is a chain: each key is introduced by the previous
one, so that a key that appears without having been introduced is not a
succession, it is a claim.

The format of that announcement, in the tag message:

```
Q21 v0.3.0

This version introduces an additional maintainer key:
  minisign RWQf6lcT0yJ0...  <pseudonym>
It is authorized to sign tags from v0.4.0 onward.
```

**2. Reproducibility, which makes the chain verifiable without the key.**
Even if every key were lost or compromised, a version remains verifiable: its
sources are public, its build is reproducible, and anyone can confirm that
the published binary comes from those sources (REPRODUCING.md). The key
proves **who**; reproducibility proves **what**. The second matters more,
and that is deliberate.

**3. Adoption, which decides in the last resort.** No document can impose a
maintainer. What makes a version *the* version is that nodes run it. If two
people declare themselves successors, the network does not choose by
arbitration: it splits, and both chains exist as long as nodes follow them.
That is unpleasant to write, and it is the truth of every decentralized
protocol, Bitcoin included.

### If the chain of tags is broken

A real and foreseeable case: the maintainer disappears without having
introduced a successor. Then there is no legitimate successor, and one must
not be manufactured.

What is done instead — a **declared fork**, honestly named:

1. someone clones the repository and publishes it under their own name,
   saying clearly that it is a continuation and not the same hand;
2. they produce their own key, file it in `attestations/builder-keys/`, and
   sign their tags with it;
3. they do not claim continuity with the previous key, and do not rewrite
   the repository's history to give that appearance;
4. node operators decide, one by one, whether or not to follow. The protocol
   does not need them to agree: the chain does not change its rules, only the
   repository the binaries come from changes hands.

The point not to miss: **there is nothing to recover.** No account to take
over, no domain to transfer, no key to find for the network to work. It is
precisely because the binary contains no domain and reaches no
infrastructure that a succession can do without any inheritance.

### Signing commits and tags — how to do it

This part is optional for the code (the code is verified through
reproducibility), but it is what makes the chain of tags of the previous
section possible. It is done with a **pseudonymous** key, with no real name
and no real address.

The simplest way is an SSH key, which git has been able to use since version
2.34 and which avoids the whole GPG infrastructure.

```bash
# 1 · create the key, with a comment that says nothing personal
ssh-keygen -t ed25519 -C "Q21" -f ~/.ssh/q21-signature
```

**What you should see**

```
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/you/.ssh/q21-signature
Your public key has been saved in /home/you/.ssh/q21-signature.pub
```

```bash
# 2 · tell git to sign with it, for this repository only
git config gpg.format ssh
git config user.signingkey ~/.ssh/q21-signature.pub
git config commit.gpgsign true
git config tag.gpgsign true

# 3 · declare the key as authorized, in a file of the repository
printf 'Q21 %s\n' "$(cat ~/.ssh/q21-signature.pub)" > .git/allowed-signers
git config gpg.ssh.allowedSignersFile .git/allowed-signers
```

```bash
# 4 · check that a commit is properly signed
git log --show-signature -1
```

**What you should see**: a line `Good "git" signature for Q21`.

**If you see** `No principal matched`: the allowed-signers file is not found
or does not contain this key. Redo step 3.

Two warnings that matter for this project:

- the signing key must carry **no** real name, no real address, no machine
  name. The comment `-C "Q21"` replaces the `user@machine` that `ssh-keygen`
  puts by default, which would be a permanent and public identity leak;
- if you push the public key to your GitHub settings to get the *Verified*
  badge, it is tied to that account. That is a choice, not an obligation: a
  signature can be verified perfectly well without GitHub, with the
  `.git/allowed-signers` file above. The badge only adds GitHub's opinion on
  a proof that already exists.

---

## 3 · Starting again without the maintainer — step by step

This section is for the person who, one day, takes over Q21. It assumes they
have a copy of the repository and nothing else.

### 3.1 · Build

```bash
git clone <your copy of the repository> q21 && cd q21
rustup show                       # must report 1.95.0 via rust-toolchain.toml
./tools/build-reproducible.sh
```

**What you should see**, at the end:

```
Binary: target/release/q21
85092844...  target/release/q21
```

Nothing to download: `vendor/` carries all the sources of the dependencies.

### 3.2 · Check that the genesis is the expected one

```bash
./target/release/q21 genesis
```

**What you should see**: for each network, the `identifier` of the genesis
block. This identifier is **determined by the code alone**. It will be
identical on your machine and on any other machine building the same commit
— this is what makes it unnecessary to trust anyone to know where the chain
begins.

The genesis block carries a message, shown on the `message` line, inscribed
on launch day. It is a timestamp that could not be checked in advance:
nobody, not even the author, could have mined blocks before that text
existed.

### 3.3 · Find an entry point into the network

The binary contains **no** node address. This is deliberate: a domain
compiled into it would be a permanent dependency on an infrastructure, hence
on its owner. Two ways to supply one at run time:

```bash
# on the command line
./target/release/q21 node --bootstrap <address:port>

# or through a file, read at startup
echo "<address:port>" >> <datadir>/bootstrap.txt
```

See NETWORK.md. If no node answers anymore, there is no network to join: you
are in the case of section 1, "the chain dies".

### 3.4 · Re-check the whole chain from scratch, trusting no one

This is the command that makes taking over safe. It replays the entire
history from another node's block file, applying **all** the consensus
rules, and rejects whatever does not follow them.

```bash
./target/release/q21 --datadir <your datadir> revalidate \
  --blocks <path to the blocks.dat of a full node>
```

**What you should see**: progress by height, then a verdict. The important
point is that the node that gave you this file **does not need to be
honest**: if it modified a block, the revalidation rejects it. You only trust
the code you built yourself.

**If the revalidation fails at a given height**, the file supplied is
corrupted or falsified from that point on. Ask another node for another one
and compare the rejection heights: two sources that reject at the same place
point to a real problem in the chain; a single one that rejects points to
that source.

### 3.5 · Taking over the releases

1. create your `minisign` key (SIGNING.md, section 1);
2. publish the public key in the README, and its fingerprint through a second
   channel you control;
3. create the GitHub environment `release` with the two secrets (SIGNING.md,
   section 2);
4. file your builder key in `attestations/builder-keys/` and attest your
   first version (`attestations/README.md`, section 3);
5. **do not reuse the previous maintainer's key**, even if you inherited it.
   A key that changes hands without it being visible is worse than a new key:
   it passes off a transition as continuity.

---

## 4 · There is no master key, and there never will be

Bitcoin had an **alert key**. Satoshi had introduced it to be able to
broadcast an emergency message to every node, displayed in the interface.
The intention was good: to warn in case of a serious flaw.

What it became, in practice:

- a **single point of compromise**: whoever holds the key can make any
  message appear across the whole network, including "this version is
  dangerous, install this one";
- a **power that no one should have held**, exercised without mandate or
  oversight;
- a key of which, over the years, it was no longer known with certainty who
  had had a copy.

The alert system was removed from Bitcoin Core in 2016, and the key was
published to neutralize it for good. It is one of the rare cases where a
project publicly acknowledged that one of its security features was in fact
an architectural vulnerability.

**Q21 has none, and this absence is a decision, not an oversight.** It
implies, and this must be accepted:

- no message can be pushed to every node. A security alert spreads as it
  does for any software: through a publication that people go and read, not
  through a channel in the protocol;
- no update can be imposed. Each operator decides, which makes fixes slower
  to spread;
- no transaction can be reversed, no funds frozen, no address blacklisted.
  No key capable of that exists, so there is no key to steal, to claim, or
  to be compelled to produce.

What Q21 puts in its place, and which confers power on no one:

| Instead of | Q21 uses |
|---|---|
| an alert key | signed publications, which people choose to read |
| an update key | a reproducible build, which everyone checks |
| an authority that says which binary is good | several builders who announce the same hash |
| a recovery key over funds | nothing. A lost wallet is lost, and the paper backup code is the only recourse |

The limit declared elsewhere and recalled here, because it belongs to the
same subject: `MAX_REORG_DEPTH = 720` (twenty-four hours) prevents a rewrite
deeper than that threshold. It is **not** a protection against a 51 % attack
— the code says so in its own comments — it changes the nature of the
attack: instead of rewriting history, the attacker splits the network. No
key can arbitrate that split. This is consistent with everything above:
where there is no authority, there is no rescue.

---

## 5 · Summary

| Question | Short answer |
|---|---|
| Can the maintainer kill Q21 by stopping? | The code, no: it is published, self-contained, reproducible. The chain, yes — if they are the only one holding a copy. |
| What does the chain need to survive? | A single other full node, run by someone else. That is all, and nothing can replace it. |
| How is a successor recognized? | A key introduced in advance by a signed tag, a reproducible build, and adoption by the nodes. In reverse order of importance: adoption is what decides. |
| And if the chain of tags is broken? | Declared fork, new key, no claim to continuity. There is nothing to inherit for the protocol to work. |
| Is there a key capable of imposing anything? | No. Never. Bitcoin had one and retired it in 2016. |
