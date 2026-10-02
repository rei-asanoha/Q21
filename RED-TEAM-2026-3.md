# Third Q21 attack campaign — severity report

*Third adversarial pass, from a fresh angle and with a single goal: **create
money that should not exist, duplicate a block or a transaction so the chain
swallows it, or make two honest nodes diverge — that is, stall the chain.**
Where the first campaign targeted the uncle economics and the second targeted
sync and storage, this one attacks the monetary core: value conservation,
transaction uniqueness, the state commitment, signatures, and the seams between
these modules.*

*As the two previous times, no serious claim is described without being proven
against the real code. Three attacks were carried out end to end against a
real chain — not described, executed — and the file
`tests/attack_campaign3.rs` replays them.*

---

## On one page

This campaign **found no exploitable flaw** for money creation, duplication or
chain split. This is not a polite formula: it is the result after a
line-by-line reading of the eleven consensus modules and three attacks carried
all the way through. The monetary core — built and hardened over the two
previous campaigns — held up from an angle it had not yet faced.

Only two minor points, **neither affects money or consensus**: a network
protocol hygiene issue between test networks, and an inaccurate comment. The
first is left to your decision (it touches a test network, never production);
the second is fixed.

As after every campaign, **a single real open prerequisite** remains, and it is
not in this report because no self-audit campaign can close it: external
cryptanalysis of the proof-of-work mixing function.

| # | Severity | Topic | Status |
|---|---|---|---|
| 1 | ✅ none | Money creation (subsidy, fees, overflow, cap) | Repelled — end-to-end test |
| 2 | ✅ none | Block / transaction duplication (Merkle, txid, BIP30/34, malleability) | Repelled — analysis + existing tests |
| 3 | ✅ none | Signature replay (across inputs, across networks) | Repelled — end-to-end test |
| 4 | ✅ none | Consensus split (timewarp, overflows, non-determinism) | Repelled — already hardened, rechecked |
| 5 | 🟢 LOW | Testnet and regtest share the P2P network magic | Documented, no money/consensus impact |
| 6 | 🟢 LOW | "92 bytes" comment for a 160-byte header | Fixed |

---

## 1. Money creation — the main target

The most serious goal, attacked first. Three possible levers to bring an
unearned unit into existence: claim more than the subsidy, claim fees that
nobody pays, or make an addition overflow. All three are closed, and the
closure is proven by a real chain.

**Excessive subsidy.** A coinbase that claims a single indivisible unit more
than its subsidy is refused (`ExcessiveSubsidy`). Test:
`a_coinbase_claiming_one_unit_too_many_is_refused`.

**Phantom fees.** A block carries a real transaction with fee `F`; its coinbase
is entitled to `subsidy + F`. Claiming `subsidy + F + 1` — pocketing a fee the
block does not carry — is refused. The bound is exact, to the unit, because the
node recomputes the fees itself from the UTXO set and does not take the
coinbase at its word. Test: `a_coinbase_cannot_claim_phantom_fees`.

**Overflow and cap.** All amount arithmetic is checked
(`Amount::checked_*`, `checked_sum`); a sum of outputs that overflows `u64` is
refused before anything else, and a last line of defense — independent of the
subsidy, the fees and the uncles — refuses any block that would bring
cumulative emission above 21,000,001 Q21. The emission schedule itself is
bounded *by construction*: the theoretical infinite geometric sum stays under
the cap even before any rounding, and a reference implementation kept in the
code guarantees bit-for-bit equality. Already covered by `integration.rs`,
`emission.rs` and `audit_arith.rs`; rechecked line by line.

*What makes this family closed:* value conservation is checked per
transaction, the subsidy bound per block, and the absolute cap on top of it
all — three independent locks, the last of which holds even if the other two
turned out to be wrong. That has already happened, twice, and the cap held.

---

## 2. Block or transaction duplication

The goal: get two different bodies accepted under the same header, or get an
already-used identifier recreated to corrupt the UTXO set.

**Merkle root (CVE-2012-2459).** Q21 **promotes** the odd node instead of
duplicating it, and tags leaves and branches distinctly: two different
transaction lists cannot produce the same root, and an internal node cannot
pass itself off as a leaf. Closed by design.

**Transaction identifier.** The `txid` ignores the witness (the SegWit lesson:
a third party cannot change a transaction's identifier by retouching its
signature), but the **Merkle leaf commits to the witness** (`txid` **and**
`wtxid`): retouching a signature in a block in transit changes the root, so the
header rejects the block. One can neither malleate a txid nor slip a
substituted witness under a valid header.

**BIP 30 / BIP 34.** The coinbase commits to its height (its witness starts
with the height in 8 bytes, and a coinbase's `txid` includes that witness): two
coinbases at different heights necessarily have different identifiers. Two
identical coinbases can only coexist on competing branches, never in the active
chain, and being identical they corrupt no state during a reorg. The reorg ×
coinbase seam, the subtlest one, was followed step by step.

**Encoding.** Serialization admits only one form per object: canonical varints
(the long form of a small number is refused), no extra bytes (`expect_end`),
counts bounded by what the frame can hold and converted without 32-bit
truncation. No malleability vector at the wire level. Covered by `ser.rs` and
`fuzz_decoders.rs`.

---

## 3. Signature replay

The goal: make a signature count for something it never signed.

**Across inputs of the same transaction.** The signed hash commits to the
input index. Attack carried out end to end: two outputs locked by the **same
key**, a transaction that spends both, and the signature of input 0 copied onto
input 1. The honest spend (each input signed at its own index) is accepted; the
replay is refused (`InvalidSignature`). Test:
`a_signature_does_not_replay_from_one_input_to_the_other`.

**Across networks.** The signed hash commits to the network (through its
address prefix). A testnet signature is worthless on mainnet, and on the other
branch of a split. Covered by
`sighash_commits_to_network_and_spent_output`.

**The signature itself.** ML-DSA verification is delegated to RustCrypto's
`ml-dsa` crate — writing a lattice-based scheme yourself would be the
professional malpractice that section 4 of the white paper rules out. The node
fails **loudly** (`SchemeUnavailable`) rather than accept what it could not
verify, and the key hash binds the key to its scheme. SPHINCS+, declared but
not implemented, is refused everywhere as long as no backend exists (otherwise
it would burn unspendable funds — fixed in the 2nd campaign).

---

## 4. Consensus split — stalling the chain

The goal: make two honest nodes answer "is this block valid?" differently.
This was the ground covered by the two previous campaigns; this campaign
re-examined it rather than assuming it settled.

- **Timewarp / difficulty.** LWMA's solve time is **signed** and bounded
  **asymmetrically** (`[-6T, +4T]`): a timestamp manipulation turns against its
  author instead of collapsing the difficulty. The future-timestamp bound is
  ten minutes, not two hours. Hardened and measured in the 2nd campaign,
  rechecked.
- **Overflows under `overflow-checks` + `panic=abort`.** An arithmetic overflow
  in consensus would abort the process — a remote crash. The critical paths
  (emission, cumulative work, fees, vector capacity at adoption) saturate or
  refuse instead of overflowing. The only crash of this class found in the 2nd
  campaign (oversized snapshot capacity) is closed.
- **Non-determinism.** No consensus decision depends on the iteration order of
  a hash table: transactions and uncles are walked in vector order, and sets
  are used only for membership tests. Two nodes in the same state return the
  same verdict.
- **Path consistency.** The header-only check introduced in the 2nd campaign
  (`check_header`) is a **strict subset** of the checks in `submit`, extracted
  into shared functions: it cannot diverge from the full path. Reading a body
  back from disk requires a matching identifier and form — a forged body counts
  as "absent", never as a truth that would make the node diverge.

---

## 5. 🟢 LOW — Testnet and regtest share the P2P network magic

`magic_for` returns the mainnet magic for Mainnet, and **the testnet magic for
both testnet and regtest**. Two nodes, one on testnet and the other on regtest,
can therefore try to talk to each other at the wire level.

**Why this has no consequence for money or consensus:** the two networks have
**different genesis blocks** (their proof-of-work parameters differ: a 32 MiB
table versus 32 KiB), **different address prefixes** (`tq21` versus `rq21`),
and the signed hash commits to that prefix. A block from one fails the work
check on the other; a transaction from one has an invalid signature on the
other. No money, no block crosses over.

**The real effect** is limited to wasted handshakes and possible mutual bans
between a regtest node and a testnet node — and regtest is local and
disposable by nature: the two almost never meet.

**Recommendation:** giving regtest its own network magic (one constant and one
line in `magic_for`) would cleanly close the residue. I did **not** apply it on
my own: the magic is part of the wire protocol, and a protocol change — even on
a test network — calls for a deliberate decision, not a fix slipped into a
campaign. Saying so, and leaving the call to you, is the right place to set the
cursor.

---

## 6. 🟢 LOW — An inaccurate comment *(fixed)*

The `BlockHeader` comment announced "92 bytes"; the header is actually 160
(`BlockHeader::SIZE = 4+32+32+32+32+8+4+8+8`). No code consequence — the real
size comes from the constant, not from the comment — but an auditor reading
the header deserves an accurate figure. Fixed.

---

## What held — checked, not assumed

- **Value conservation and the cap** hold to the unit, proven by a real chain
  that tries to create one unit too many and fails.
- **The state commitment (3072-bit MuHash)** binds each output through its
  outpoint, its value, its scheme, its key, its height and its coinbase flag:
  no ownership move and no value alteration leaves the commitment unchanged.
  Since the 2nd campaign, the commitment that gets copied also binds the total
  issued.
- **Signatures** are delegated to a professional implementation, fail loudly
  when they cannot verify, and bind each signature to its input, its spent
  output and its network.
- **Serialization** admits only one form per object: no malleability, no
  allocation dictated by a stranger, no 32/64-bit divergence.
- **The mempool** refuses free relay, dust, spend conflicts and the unminable,
  and computes fees before any cryptography.

---

## Recommendation

For the third time, the core held, and this time from the most direct angle:
the money itself. No money-creation, duplication or split flaw survived the
review — because none was found. The two remaining points are minor and have
no effect on production: one is fixed, the other awaits your decision on a test
network.

The chain is, from the standpoint of what this type of audit can establish,
**ready to go into production** as far as its consensus rules and its money
are concerned.

Two prerequisites remain that are outside the scope of a self-audit, and that
must be met **before** genesis:

1. **External cryptanalysis of the proof-of-work mixing function.** No
   internal campaign replaces it; the white paper rightly marks it as the last
   lock before a calm genesis.
2. **Release signing (minisign)** and binary reproducibility, so that nobody
   has to trust the author for what they run.

And a note for launch day: when the anchor tables
(`fast_sync::builtin_anchors`, empty today) are filled in, their hashes must
be **state commitments** (MuHash + total issued bound together,
`state::state_commitment`), not the bare MuHash — the verification code already
expects them that way.
