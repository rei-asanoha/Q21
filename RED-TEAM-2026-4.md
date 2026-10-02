# Fourth Q21 campaign — network hardening and ML-DSA review

*Version 0.3.2. Two goals: close the network hardening list left open since
phase 8b, and scrutinize the library that verifies every signature on the
chain, RustCrypto's `ml-dsa` 0.1.1.*

*As with the previous campaigns, nothing serious is claimed without an
executable test against the real code. Each fix below has its test, and each
test was confirmed to **fail** on the code from before the fix.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| 1 | 🟠 MEDIUM | An anonymous peer got honest peers disconnected (invented bodies requested again) | Fixed — found by the fuzzer |
| 2 | 🟠 MEDIUM | Proof of work computed under the global lock | Fixed |
| 3 | 🟠 MEDIUM | Header requests served with no rate limit (×150 amplification) | Fixed |
| 4 | 🟠 MEDIUM | `--rpc-wallet` started without a token | Fixed |
| 5 | 🟡 MEDIUM-LOW | `addr` read before the handshake, with no rate limit | Fixed — found by the fuzzer |
| 6 | 🟡 LOW | Unrequested header batches treated as replies | Fixed |
| 7 | 🟡 LOW | `inv` read before the handshake | Fixed |
| 8 | 🟡 LOW | Variable-time randomness check on the seed | Fixed |
| 9 | ✅ none | ML-DSA verification: FIPS 204 conformance, malleability, published advisories | No defect |
| 10 | ℹ️ | Two reserves on the signing side, in the library's own code | Tracked as a prerequisite before any mainnet |

**No consensus defect was found.** The published security advisories for
`ml-dsa` are all already fixed in the bundled version, and no signature can be
modified by a third party without being rejected.

---

## 1. Invented bodies: an honest peer punished instead of the attacker

**Found by the fuzzing campaign.** A peer announced, through `inv`, blocks that
do not exist. Once the delivery deadline had passed, the node penalized the
announcer — that is intended — then **requested the same bodies again from the
first honest peer available**, recording them as "in flight" with that peer.
The honest peer could not deliver what does not exist: at the next deadline,
it lost fifty points. Two rounds were enough to disconnect it. By starting
over from a new connection, an attacker could strip a node of its honest
peers, which sets up an eclipse.

**Fix.** The repeated request goes out as a full block and is no longer
recorded as in flight: a peer that announced nothing is no longer bound to
deliver it. The peer that withheld is penalized as before, and a real withheld
body is still obtained elsewhere. Tests:
`an_honest_peer_is_not_punished_for_invented_bodies`, and the counter-test
`a_withheld_body_is_requested_again_and_adopted`.

## 2. Proof of work outside the global lock

A received block or compact announcement had its memory-hard hash computed
**under the global lock**. On the first block of an epoch, the whole cache for
the epoch also had to be built: several seconds on mainnet. During that time,
no peer was served any more, and the wallet stopped responding.

**Fix.** The lock is now taken only for the cheap checks: handshake,
announcement budget, attachment, difficulty, timestamp. The hash is computed
afterwards, with the lock released, and its verdict is kept in a bounded
registry (4,096 verdicts). Under the lock, the chain reads that verdict back
instead of recomputing it. No rule changes: every check is redone under the
lock, in the same order. Rejections are kept just like acceptances, so a false
header sent over and over costs only a lookup.

A header placed at an arbitrary height triggers no computation, even outside
the lock. The height selects the epoch, and an unknown epoch would cost a
whole cache.

Tests:

- `the_work_of_a_received_block_is_checked_outside_the_lock`: zero computation under the lock;
- `an_announcement_with_wrong_work_is_rejected_without_computing_under_the_lock`;
- `an_over_budget_announcement_computes_nothing`;
- `an_out_of_context_header_computes_nothing`.

What remains under the lock: verifying a block's signatures. It is only
reached after a **real** proof of work, which the sender therefore pays for.

## 3. Header requests: a bucket, and expected replies

A header request of a few dozen bytes got two thousand headers served, more
than 300 KiB, prepared under the global lock. An unknown locator was enough,
and the rate was not limited. It was the only service without a bucket.

**Fix.** Each peer has 8 requests up front, then one per second. That covers
a sync at two thousand blocks per second. A request beyond that is not served
and does not drop the connection.

In the other direction, a header batch received without having been requested
was treated as a reply: two thousand hashes under the lock, and the queue of
bodies to request was replaced. Now, each request sent opens a slot, at most
four per peer; each batch received consumes one. A batch received with no free
slot is not read and costs the sender 10 points.

Tests:

- `header_requests_are_bounded_by_a_bucket`;
- `an_unrequested_header_batch_is_ignored`;
- `reply_slots_are_bounded`;
- `bodies_in_flight_are_capped_per_peer`, adapted.

## 4. The RPC wallet requires a token

`q21 node --rpc 127.0.0.1:PORT --rpc-wallet` started without a token. The
server's guards (`Host` header, origin, `Content-Type`) stop a hostile web
page, not another program or another account on the same machine. Yet any of
them could call `sendtoaddress`.

**Fix.**

- `--rpc-wallet` is refused at startup without a token, and with a token
  shorter than 16 characters.
- An empty token is refused everywhere.
- The new option `--rpc-token-file <path>` reads the token from a file. On the
  command line, it would be readable by every account (`ps`, `/proc`). A file
  readable by other accounts is flagged.
- The desktop wallet is not affected: it already draws a 64-character token at
  each launch.

Tests: `the_rpc_wallet_requires_a_token`,
`the_token_is_read_from_a_file`, `tests/regression_rpc_wallet_without_token.rs`.

## 5 to 7. Addresses and announcements before the handshake

- **`addr` (found by the fuzzer).** It was the only expensive handler read
  without a handshake. When the address book is full, each address from an
  unknown group walks all 512 groups: a frame of a thousand addresses held the
  lock for about 8 ms, with no rate limit. Now, the frame is only read after
  the handshake, and each peer has a bucket: a thousand addresses up front (one
  full reply), then ten per second.
- **`inv`** is no longer read before the handshake. Once read, it made the node
  request bodies on behalf of an anonymous connection: that is the starting
  point of defect no. 1.
- An accepted transaction is now relayed only to peers that have completed the
  handshake, like any other announcement.

Tests: `an_addr_before_the_handshake_is_not_read`,
`received_addresses_are_bounded_by_a_bucket`,
`an_inv_before_the_handshake_is_not_read`.

Finally, all misbehavior scores saturate instead of overflowing. In
production, `overflow-checks` is enabled: an overflow there would stop the
node.

## The handler fuzzing campaign

Two tools, both replayable identically from a seed:

- **`tests_handler_fuzz`, at the heart of `src/net.rs`.** It sends `handle`
  messages of **every** type, built to land on the limits: huge counts that
  the decoder still accepts, headers chained onto the tip with real or fake
  work, incomplete handshakes, several interleaved peers, and from time to time
  a real valid block. After each message, it checks:
  - that there is no panic and no poisoned lock;
  - that every per-peer bound is respected;
  - that the chain only advances on truly valid blocks;
  - that an honest peer is still served at the end.
- **`tests/fuzz_tcp_handlers.rs`.** It sends altered frames over real sockets
  (flipped bits, lying lengths, wrong checksums, truncated frames or frames
  sent a trickle at a time), then checks that an honest peer still syncs.

The long campaigns totaled about 1.6 million structured messages and 78,000
TCP frames. Result: **no panic, no overflow, no bound crossed**. The only
defects found are nos. 1 and 5 above.

Targeted reading ruled out several suspicions, each with its test:

- the orphan counter does not overflow: the peer is disconnected at 3;
- extreme indices in `getblocktxn` or in the snapshot chunks get nothing
  served;
- an absurd compact reconstruction is rejected before any allocation.

## 9. Review of `ml-dsa` 0.1.1

**Conformance of verification to FIPS 204.**

- Lengths are checked before calling the library, then again by it.
- Hint decoding is strict: non-increasing counts, counts above ω, nonzero
  padding bytes and indices that are not strictly increasing are rejected.
- The bound on ‖z‖∞ is checked, and the challenge c̃ is compared in full.
- UseHint and Decompose were compared exhaustively, over all
  8,380,417 possible values, against a separately written reference
  implementation: no difference. Reintroducing the old "r0 = 0" defect makes
  60 differences appear, which shows the comparison can detect a discrepancy.
- The wallet signs and the node verifies exactly the same message (the
  transaction's signature hash), in pure ML-DSA with an empty context. This is
  proven end to end.

**Malleability.**

- All 3,309 + 4,627 bit-flip positions are rejected.
- Reordered, duplicated or moved hint indices, appended bytes and truncations
  are rejected as well.
- All 28,365 decodable variants re-encode identically.
- The transaction identifier excludes the witness. The only party able to
  produce another valid signature is the key holder, by signing again; a third
  party cannot.

**Published security advisories.** None affects the bundled version:

| Advisory | Bundled version affected? |
|---|---|
| RUSTSEC-2025-0144 / CVE-2026-22705 — variable-time division in Decompose | No: Barrett reduction, no hardware division in the binary |
| GHSA-5x2r-hc65-25f9 / CVE-2026-24850 — repeated hint indices accepted | No: strict comparison, "duplicate" case tested |
| GHSA-h37v-hp6w-2pp8 — UseHint when r0 = 0 | No: exhaustive comparison above |

**Vectors.** The public Wycheproof and ACVP vectors could not be downloaded on
the build machine; this remains to be done. Instead, 40 edge vectors built
independently of the library are tested
(`tests/vectors/mldsa/t1_zero_edges.txt`). Each invalid vector differs from a
valid one by a single wrong choice, and all 40 pass.

**Robustness.** 300,000 verifications on random or altered keys and
signatures: no panic, and a wrong length is rejected in under 100 ns.

**Randomness (no. 8, fixed).** The plausibility check in `rng.rs` indexed a
table by the value of each seed byte, and branched on it. It has been
rewritten with no memory access or branch that depends on the bytes.
Measurement: a 0.1 to 0.3% gap between repeated and random inputs, versus 40%
before.

**Reserves (no. 10).** The two reserves concern the library's own code on the
**signing** side (the wallet), with no effect on consensus or on
verification. They are tracked as a prerequisite before any mainnet: either an
upstream fix or a project-side patch. Their details are intentionally not
published while the library code is unpatched. In the meantime, a wallet
holding funds should run on a machine where you are the only user.

Tests: `tests/audit_mldsa.rs` (12 tests, plus a long campaign disabled by
default).

---

## What remains open

- **Wycheproof and ACVP vectors**: to be downloaded and run as soon as
  possible.
- **Fast-sync snapshot**: it is rebuilt under the lock, once per new tip. The
  cost grows with the UTXO set; to be addressed before the chain grows large.
- **Block signatures verified under the lock**: this is only reachable with a
  real proof of work. Caching verified signatures will be the next step.
- **ML-DSA signing-side reserves (no. 10)**: an upstream fix or a project-side
  patch, before any mainnet.
- **External cryptanalysis of the proof of work**: still the first
  prerequisite for mainnet.

Total after this version: **963 tests**, none failing. Clippy reports no
warnings, all binaries included.
