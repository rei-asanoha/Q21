# Q21

A peer-to-peer electronic cash system designed to survive Shor's algorithm,
and to be mined on the computer you already own.

```
Hard cap           21,000,001 units
Signatures         ML-DSA (FIPS 204), addresses carry a versioned scheme id
Proof of work      two-level memory-hard — 2 GiB for miners, 64 MiB for nodes
Emission           continuous decay, ~4-year half-life, 20,000-block ramp
Fork choice        cumulative work, rolling finality at 720 blocks
Network            plain TCP, compact block relay, anti-eclipse address book
Inspection         JSON-RPC + block explorer served by your own node
```

**Status: public testnet.** There is no mainnet, and `q21 init mainnet`
deliberately refuses to create one. Nothing here protects real value.

Over 900 tests. Zero clippy warnings across all binaries. One dependency —
ML-DSA from RustCrypto, vendored — and `--no-default-features` builds a core
with none at all.

| Document | What it covers |
|---|---|
| [WHITEPAPER.md](WHITEPAPER.md) | What Q21 fixes, how, and what it still assumes |
| [JOIN.md](JOIN.md) | Join the testnet in ten minutes, without ever opening a terminal |

The deeper documents (audits, red-team reports, server guides) are listed
[at the end](#repository-layout).

---

## Join the testnet

Download the archive for your system from the
[latest release](https://github.com/rei-asanoha/Q21/releases/latest), check it
(see [Verifying a release](#verifying-a-release)), unzip it, and double-click
the launcher — `Q21 Wallet.bat` on Windows, `Q21 Wallet.command`
on macOS, `./q21 wallet` on Linux. Your browser opens and walks you through
creating or restoring a wallet. The archive already contains the testnet entry
point; there is nothing to type.

[JOIN.md](JOIN.md) covers every step, including the warnings macOS and Windows
show for unsigned software, and how to become an entry point yourself.

## Build from source

```bash
cargo build --release          # ML-DSA is included by default
Q=$PWD/target/release/q21

# two local nodes on the regression network
mkdir a b
(cd a && $Q init regtest && $Q mine 40)
(cd b && $Q init regtest)

$Q --datadir a node --listen 127.0.0.1:21031 --mine    # terminal 1
$Q --datadir b node --connect 127.0.0.1:21031          # terminal 2

# local explorer, in a browser: http://127.0.0.1:21080
$Q --datadir a node --rpc 127.0.0.1:21080 --mine
```

Observed output (abridged):

```
height 40 (+40)  peers 1 (…)  mempool 0  blocks received 0  compacts 40 of which 40 without round trip  …
```

Forty blocks synchronized entirely through compact relay, with no round trip.
Not a single full `block` message was sent. (The wallet's web interface is
also available in French and Japanese.)

---

## Design, in short

### Post-quantum signatures, with a versioned scheme

The scheme id is written into the address itself, so adding a scheme is an
upgrade, never a break:

| id | scheme | public key | signature | mainnet |
|---:|--------|-----------:|----------:|:--------|
| 1 | ML-DSA-65 | 1,952 B | 3,309 B | yes |
| 2 | ML-DSA-87 | 2,592 B | 4,627 B | yes, default |
| 3 | SPHINCS+ | — | — | declared, not implemented |
| 4 | Lamport OTS | 16,384 B | 8,192 B | **forbidden** |

ML-DSA is not implemented here — writing your own lattice signature scheme is
malpractice. The core defines the interface and relies on RustCrypto's `ml-dsa`
0.1.1, without its `getrandom` and `pkcs8` features: a node verifies, it does
not sign. The sizes above are measured, and a key derived from a known seed is
compared byte for byte with RustCrypto's published PKCS#8 vector.

Verification on one core: about 5,200 signatures/s for ML-DSA-65 and 3,300 for
ML-DSA-87. A 2 MiB block carries at most ~380, so roughly 73 ms to verify.

Lamport one-time signatures stay available on test networks only. Their ban on
mainnet is a consensus rule, not advice.

### Compact relay is central, not an optimization

Witness data is 99% of a Q21 transaction — measured on a real 4-input
transaction: 98,584 bytes, 98,328 of them witness. Slow propagation means more
orphans, which means the best-connected miner earns more than its share of
hashpower: centralization. Compact relay attacks the cause. A 200-transaction
block weighs ~5 MiB; its compact announcement, under 2 KiB.

Short ids are six bytes and keyed — from the block header (so from the mining
nonce, unknown before the block exists) and from a per-sender nonce — so an
adversary cannot precompute colliding transactions. Reconstruction always ends
with a Merkle root check; any failure falls back to fetching the full block.

### A proof of work with no rental market

The memory-hard PoW was measured three times, and each measurement broke
something:

1. Hashing on every memory access made going memoryless only 1.63× more
   expensive. Fixed: one 256-bit modular addition per access.
2. Measured on the real 2 GiB table, dropping memory entirely cost only 2.86×.
   Fixed with an Ethash-style two-level structure: a 64 MiB cache, and table
   items that can only be computed by walking it 256 times. Skipping the table
   now multiplies memory bandwidth by 256 — which silicon does not create.
3. Carries never reached the low 32 bits of the state, and the next read index
   came from those bits alone: a 128 GiB lookup table could replace the whole
   walk. Fixed: the index now depends on all four state words, and every read
   is followed by four Feistel rounds.

The cost, stated plainly: a node now needs 64 MiB, and verifying a block takes
~660 µs instead of ~45 µs. `q21 pow mainnet` reruns the full measurement on your
machine. Details in [PHASE6.md](PHASE6.md) and at the top of
`src/memhard.rs`.

**This PoW has had no external cryptanalysis.** That is the main prerequisite
before any mainnet.

### 51% attacks: the honest answer

Full protection is mathematically impossible: rejecting the majority's chain
would require knowing who they are — an identity, hence an authority. `q21
security` and the `getsecurity` RPC spell it out.

A majority miner **can** reorganize recent blocks and censor. Even with 99%,
it **cannot** steal a coin without its key, mint beyond the subsidy, raise the
cap, or change a rule. Q21 adds cumulative-work fork choice, rolling finality at
720 blocks, and a depth penalty (+1% work per block beyond 6, capped at +25%).
The trade-off: a network partition longer than ~24 hours yields two chains that
will not reconcile on their own. A silent rewrite becomes a visible split.

### The cap is enforced twice

An adversarial audit found that uncle rewards were *added* to the subsidy and
that nothing ever compared cumulative emission with the cap: real maximum
emission was 44,099,999 units. Uncle rewards were removed. A block now emits
exactly its subsidy, and a separate consensus rule rejects any block that would
push cumulative emission past `MAX_SUPPLY`, whatever the schedule says. The
first-block reward is computed so that the infinite step-wise sum stays under
the cap, and that bound is checked at compile time.

The genesis coin pays the zero hash: nobody knows a preimage, so it can never
be spent. The founder does not pre-allocate anything.

### Keys

Randomness comes from the operating system's API on every platform, and the
program fails rather than use entropy of unknown quality. The seed is stored
encrypted and authenticated (Argon2id per RFC 9106, HMAC-SHA256), with `0600`
permissions. The backup code is Bech32m with a checksum: a test substitutes
every character with seven others, and all 400 typos are caught. The code is
never accepted as a command-line argument, because arguments end up in shell
history and in `/proc/<pid>/cmdline`.

### Your node, your explorer

The explorer and the JSON-RPC API are served by your own node, on loopback by
default, and load no external resource — no font, stylesheet or remote script.
Listening anywhere else requires a token, compared in constant time. Wallet
methods are disabled by default. Amounts never travel as floats: every amount
is returned both as an integer number of units and as a formatted string, and
the JSON parser rejects floats outright.

```bash
q21 node --rpc 127.0.0.1:21080
curl -sX POST localhost:21080/rpc -d '{"jsonrpc":"2.0","id":1,"method":"listmethods"}'
```

---

## Roadmap

| Phase | Status | Content |
|---|---|---|
| 1 | ✅ | Types, emission, SHA-256, Merkle, Bech32m, addresses, transactions, blocks |
| 2 | ✅ | Genesis, UTXO, validation, LWMA, miner, storage, wallet, CLI |
| 3 | ✅ | Memory-hard PoW, cumulative work, anti-reorg, benchmarks |
| 4 | ✅ | SipHash, mempool, compact relay, TCP, header-first sync |
| 5 | ✅ | JSON, HTTP, JSON-RPC, local explorer, unconfirmed chains |
| 6 | ✅ | Anti-ASIC measurement on 2 GiB — verdict, two-level fix, remeasure |
| 7 | ✅ | Durability: incremental startup, bounded memory, multi-threaded miner, anti-eclipse |
| 8 | ✅ | Adversarial audit: 11 real flaws fixed, encrypted wallet, cross-platform RNG |
| 8b | ⬜ | **External human audit**: PoW cryptanalysis, consensus review |
| 9 | ✅ | Public testnet: wallet-less node, name-based bootstrap, genesis check, one public entry point running. A second one, run by someone else, is still needed |
| 10 | ✅ | A desktop application, not a command line: setup and restore screens, mining from the page, network status |
| 11 | ⬜ | Mainnet — prerequisites: UTXO commitment and an external audit |

## Known limitations

- **`ml-dsa` 0.1.1 has not been formally audited.** It passes the reference
  vectors, but no public side-channel review covers it. Signing lives in the
  wallet, not in consensus, which limits the exposure without removing it.
- **SPHINCS+ is declared, not implemented.** A wallet requesting it is refused
  at construction time.
- **The PoW has no external cryptanalysis** (see above).
- **One public entry point.** The binary contains no address; the archive ships
  a plain-text `bootstrap.txt` naming the single current entry point. Until a
  second one is run by someone else, newcomers depend on it for their first
  contact — not for what they believe afterwards.
- **Inbound connections are capped per network group** (four per IPv4 `/16` or
  IPv6 `/64`, with eight slots always reserved for outbound). A whole household
  shares one public address, so a fifth device from the same home on the same
  entry point is turned away.
- **Burst mining** beyond ~7,200 blocks at once pushes timestamps past the
  2-hour tolerance.
- **Block archive pruning** (`node --prune`) keeps about eight days of block
  bodies; a pruned node cannot serve as an explorer.

---

## Verifying a release

Every release is signed with `minisign` (see [SIGNING.md](SIGNING.md)). The
public key — compare it with a copy obtained through a second
channel before trusting it:

```
RWQmIDC+1su+FM2i/NVEC2Fqba+3nhWzpTk02LM11NYhpnuts6gW/7zr
```

It is also in `q21-release.pub` at the repository root:

```bash
minisign -Vm SHA256SUMS -p q21-release.pub
sha256sum --ignore-missing -c SHA256SUMS
```

The release pipeline checks its own signature against this file before
publishing anything, so a key rotated in the secrets without this file
following would fail the release instead of shipping an unverifiable
signature. The trusted comment of each signature is covered by the signature:

```
Trusted comment: Q21 main <commit hash> -- Rei Asanoha
```

That name guarantees one thing only: a consistent origin from one release to
the next. It confers no authority. Q21 has no vote, no council and no kill
switch, and no protocol rule depends on who wrote it.
[SUCCESSION.md](SUCCESSION.md) describes what happens when that name
goes quiet.

The strongest check does not require trusting anyone: **rebuild** and get the
same hash. Builds are reproducible, and checked as such on every push:

```bash
./tools/build-reproducible.sh     # then compare with the published hash
./tools/verify-reproducible.sh    # two directories, one hash
```

Full procedure in [REPRODUCING.md](REPRODUCING.md). Independent builders can
record their result in `attestations/`.

---

## Repository layout

```
src/                 Consensus, networking, wallet, RPC and explorer.
                     consensus.rs holds every parameter; validate.rs every rule.
src/bin/q21.rs       Node, wallet, explorer and benchmarks
examples/            Mining benchmark, signature benchmark, century projection
tests/               Integration, attack and regression tests
tools/               Reproducible build scripts, action pinning, node monitor
vendor/              ml-dsa and its transitive dependencies (offline build,
                     checksums verified by cargo)
whitepaper/          Reference whitepaper: HTML page and PDF
attestations/        Independent build attestations, and how to file one

WHITEPAPER.md        Whitepaper
JOIN.md              Join in ten minutes
UPGRADING.md         Upgrading your wallet
NETWORK.md           Testnet entry points, and running one
SERVER.md            Setting up an entry point step by step (from a Mac)
SERVER-WINDOWS.md    Same, from PowerShell
MINING.md            Mining explained without jargon
WALLET.md            The wallet, and sixteen defects a first user found
EXPLORER.md          The explorer and the optional address index
PUBLIC-EXPLORER.md   Publishing the chain explorer over HTTPS
PHASE6.md            The anti-ASIC verdict
PHASE7.md            What lets a chain last
PROJECTION.md        The chain over a century, computed by consensus code
AUDIT.md             Adversarial audit: eleven real flaws
AUDIT-2026.md        The chain against the 2026 state of the art
AUDIT-EXPLORER.md    Penetration audit of the public explorer
RED-TEAM-2026*.md    Four red-team campaigns (the fourth: network hardening,
                     handler fuzzing, ML-DSA library review)
HARDENING.md         Hardening the machine that holds coins
SIGNING.md           Release signing
REPRODUCING.md       Reproducible builds
SUCCESSION.md        What happens to Q21 without its maintainer
CONTRIBUTING.md      Language policy (American English) and checks to run
```

---

## Reporting a flaw

A flaw — in the proof of work, consensus, or the wallet — goes to the
repository's [Issues](https://github.com/rei-asanoha/Q21/issues), ideally
before it is made public elsewhere. This is the project's only contact channel;
there is no email address. There is no bounty, no contract and no imposed
deadline: only an answer, a fix, and a regression test that will carry your
finding. Please write issues in English.

Research code. Not audited externally. License: MIT OR Apache-2.0.

**Rei Asanoha** — September 2026
