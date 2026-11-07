# Eleventh Q21 campaign — six reviewers and an organizer on 0.5.11 (0.5.11)

*The 0.5.11 release — final after campaign 10 — attacked again by six reviewers
with distinct ways of thinking, coordinated by an organizer: the **architect**
(consensus, reorganizations, the chain, eclipse and partition), the **cunning
one** (everything trusted without checking: the release and update chain, files
on disk, the server guides, a second account on the computer), the **ingenious
one** (multi-step attacks that chain channels, splices, names, contacts and
reorganizations), the **cartesian one** (every network message and every RPC
method, boundary by boundary, and resource bounds), the **cryptographer** (the
signature schemes, the post-quantum channel transport, the key-derivation and
keys at rest, the backup code) and the **human-factor one** (where the wallet's
own interface or the guide could let a person be fooled). They worked in two
rounds of attack and a verification pass, each round against the binary built
from the previous round's fixes.*

*The goal was to stop, isolate, slow, or confuse the chain or a wallet, or to
make a human act against their own interest. Rules, as in every campaign:
nothing that creates money, takes control, or touches a real network — every
attack ran in a local sandbox, and a finding is CONFIRMED only when it was run
against the real code or the real binary and became a test or a lab repro.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| H1 | 🟠 MEDIUM | A compact-block request was exempt from the node-wide serving budget *and* rebuilt (a hash over every transaction, plus the whole-block encode) under the one global lock on every request; a peer rotating block ids kept the node rebuilding with no aggregate cap across up to the peer limit | Fixed (rounds 1–2) |
| H2 | 🟠 MEDIUM | The contact book and the send address book folded look-alike scripts (Cyrillic, Greek, fullwidth) but not the letter ligatures the on-chain name rule folds (`rn`→`m`, `vv`→`w`, `cl`→`d`, `i`→`l`): "rnodern" beside "modern", "vvallet" beside "wallet", with no refusal or warning | Fixed |
| H3 | 🟠 MEDIUM | The update guide told a person to confirm the signing key only against files from the same repository (`README.md`, `SIGNING.md`): under a repository takeover all three are swapped together, so the check gave false confidence | Fixed |
| H4 | 🟡 LOW | The guide's "run it anyway" steps (SmartScreen, Gatekeeper, `xattr`) were not tied to verification: a person with an unverified look-alike was walked through disabling the very warnings that would have stopped it | Fixed |
| H5 | 🟡 LOW | `node.key` was written to a temporary file at the umask (0644) and restricted only after: a brief window in which another local account could read it | Fixed |
| H6 | 🟡 LOW | A node that refuses to start on a foreign or hard-linked data folder (0.5.11's check) was restarted every cycle by `monitor.sh` — a permanent restart loop that hid the real cause | Fixed |
| H7 | 🟡 LOW (display) | A reorganization that undid a close cleared the "came back" record but not the "did the addition happen" record, so an archive figure could briefly over-count | Fixed |
| T1 | test | No test failed when a user-facing string was translated into one language but not the other, so it would silently fall back to English | Fixed (a coverage test both ways) |

**No money creation, no theft, no signature forgery, and no remote takeover was
found.** The cap of 21,000,001, the emission, and the issued total against the
UTXO set after a reorganization and a restart were re-confirmed against the real
binary. The attacks found were about **slowing** the node (a serving amplifier)
and **confusing a person** (look-alike names, a weak step in the update guide);
all are fixed. The rules of block validity are unchanged since 0.5.6.

---

## H1. The compact-block serving amplifier (`cart`, `arch`)

A compact block is how a new tip travels: a header, a nonce, and a short
identifier for each transaction the receiver is expected to already hold. Since
campaign 10 it is **exempt from the node-wide serving budget**, so a fresh tip
never queues behind bulk block reads. Round 1 found the cost of *building* one —
a sip-hash over every transaction id, plus encoding the whole block to measure
it — was paid under the one global lock on **every** request, with nothing
bounding it across peers: every peer asking for the same new tip made the node
redo the work. Round 1 added a cache. Round 2 then **defeated** the first cache:
it held one block, and the handler served a compact block for *any* historical
id, so a peer rotating distinct ids missed the cache every time and restored the
amplifier, still with no aggregate cap.

**Fix (over the two rounds).**
- The node keeps the compact blocks it recently built, one per block, bounded to
  a handful more than the recent window; a burst of peers asking for the same
  new tip — or rotating over the few recent tips — shares one build. The sender
  nonce still rotates every second.
- The budget exemption is earned only by a **recent** tip (within six blocks of
  the active tip). A compact request for an older block — an initial catch-up, or
  an attacker rotating old ids — is still answered with a compact block (so
  catch-up still reconstructs empty blocks without a round trip), but its
  whole-block cost is **charged to the node-wide budget** like any bulk read.
  Past that budget, the next such request waits. A rotating-old-id flood is
  therefore throttled by the node-wide budget however many peers run it.

Tests: `a_compact_block_is_built_once_and_reused_for_a_burst`,
`rotating_compact_requests_are_bounded_and_old_ids_pay_the_node_wide_budget`.
Confirmed in the lab: new-tip propagation stays at about zero even under a
bulk-read drain, and the served compact block always matches the id requested
(no stale or wrong serve) — `arch/compact_probe.py`, `arch/lag.py`.

## H2. Look-alike names in the books (`human`)

The on-chain name system is airtight: a name is reduced to a **skeleton** —
look-alike digits read as letters, and `rn` as `m`, `vv` as `w`, `cl` as `d`,
`i` as `l` — and two names with the same skeleton cannot both be registered. The
wallet's **contact book** and **send address book** folded Unicode homoglyphs
(so a Cyrillic "аlice" is refused as "alice") but not those letter ligatures. So
a person could be led to save an attacker's address as "rnodern" right next to
their trusted "modern", or "vvallet" next to "wallet", with no refusal and no
warning — and then pick the look-alike and pay the attacker. This is the 2026
address- and name-poisoning class, and the inconsistency with the consensus rule
broke the person's reasonable mental model.

**Fix.** The books now fold the same letter ligatures (`rn`→`m`, `vv`→`w`,
`cl`→`d`, `i`→`l`) in both the refusal key and the warning key, matching the
on-chain rule. The **digit** reads the consensus skeleton also makes are left
out on purpose: a local book legitimately holds numbered names ("n6", "n8") that
are not an attack, whereas a letter ligature beside a trusted name is. Test:
`a_ligature_look_alike_contact_is_refused`.

## H3, H4. The update guide (`human`, `cunning`)

The guide a non-technical person follows (`JOIN.md`) had two weak steps.

- **H3.** It said to confirm the signing key by comparing it with the copy in
  `README.md` and `SIGNING.md`. Both ship in the same archive and repository as
  everything else, so in the exact attack the signature exists to counter — a
  repository or pipeline takeover — the attacker swaps the archive, the
  checksums, and those two files together, and all three key copies agree with
  the forged signature. The guide now tells the person to confirm the key
  against the copy the project publishes **away from GitHub**, and says plainly
  that this is the one check a repository takeover cannot defeat.
- **H4.** The "More info → Run anyway" / "Open Anyway" / `xattr` steps that get
  past the operating system's first-launch warnings were presented
  unconditionally. A victim who downloaded a trojaned look-alike would be walked,
  by legitimate-looking text, through disabling exactly those defenses. The steps
  are now gated on the verification having passed, with a line telling the person
  to go back and verify if they skipped it.

## H5, H6, H7. Smaller hardening

- **H5 (`crypto`).** `node.key` — which authenticates the node's own state
  snapshots — was created with `File::create` (umask, 0644) and restricted only
  after writing. It now uses the same create-already-private helper as every
  other private file, so there is no readable window. (No fund or signing key is
  involved; the impact was a narrow local-read window.)
- **H6 (`cunning`).** 0.5.11 refuses to start on a data folder owned by another
  account or holding a hard-linked file — a deliberate, documented stop. But the
  server's `monitor.sh` restarted the service every cycle, turning that stop into
  a permanent restart loop that hid the cause. `monitor.sh` now counts failed
  starts and, past a small cap with the unit in `failed`, stops restarting and
  calls for a human with the likely cause.
- **H7 (`ingenious`).** When a reorganization undoes a channel close, the node
  forgot what the close had paid us, but not the separate record of whether an
  unlocked addition had happened. A reclassified close could then read a stale
  record and the archive could briefly over-count. The node now clears both.
  Display only — no balance or payment depends on it.

## T1. A translation that falls back to English

The translation tables are keyed by the English source; a string translated into
one language but not the other falls back to English for that language's readers.
The existing tests checked only that every Japanese key had a French one. They
now check both directions, for the wallet page and the explorer, so a string
added in one language and forgotten in the other fails the build.

---

## Held, and re-confirmed

- **Money invariants** (cap, emission, UTXO against issued after a reorganization
  and a restart) — CONFIRMED against the real binary; a reorganization can only
  make a miner *burn* its own subsidy, never mint.
- **Eclipse / outbound monopolization** — refuted by construction: the alias map
  an attacker might flood gains an entry only when the node itself dials a
  configured address over Tor and sees a duplicate nonce from a configured peer;
  an inbound stranger creates none, and clearing the map opens no outbound slot
  and drops no real peer. Inbound is capped per group and leaves the outbound
  slots free.
- **The mempool and transaction relay** — a flood is rejected on cheap grounds
  before any cryptography, and the per-peer budget is charged in proportion to
  the verifications a transaction will actually cost, before the first one runs,
  with an early bail on the first bad input.
- **The release/verify chain** — the verify command fails closed on a renamed or
  wrong-architecture file; `verify-release.sh` checks the exact file set, the
  exact trusted comment, and every non-binary file against the tagged commit.
- **The cryptography** — ML-DSA and Lamport binding and domain separation; the
  post-quantum channel transport's transcript binding, replay/sequence across a
  reconnect (a fresh ephemeral key per session), and absence of a cleartext
  downgrade; Argon2id parameters and encrypt-then-MAC at rest; the fail-closed
  RNG; the backup-code flow. No weakness found beyond H5.
- **The on-chain name skeleton** against Unicode homoglyphs and mixed scripts —
  airtight.

## Open

What remains is a structural trade-off or carried from campaign 10:

- **No single node-wide CPU budget** for the work done under the one global lock
  (serving compact blocks, verifying transaction signatures). Each is bounded
  *per peer* — compact serving is now also recency-gated and cache-capped, and
  transaction verification is charged per peer before it runs — so no one peer
  can harm the node; the aggregate across the peer limit is the normal serving
  load the node is sized for. A single shared CPU budget would be the systemic
  answer and is a larger change, noted for a later release.
- **A node catching up from its only peer while that peer is drained** is slowed
  (it shares the node-wide serving rate), never stalled — re-confirmed bounded
  in campaign 10's round 7.
- **Leading-digit name impersonation** ("4lice" for "alice") is not folded in the
  local books, because folding digits there would make legitimate numbered names
  collide; the visible digit makes the impersonation weaker, and the on-chain
  name rule still refuses it at registration.
- Everything in campaign 10's "Open" section still stands: a majority of the
  hash power rewriting twelve blocks; the minority-partition trade-off; coinbase
  maturity (200) shorter than the reorganization limit (720), for the review of
  the rules before a main network; the display-only channel residuals.

## Deferred to the operator

- The channel-open preview shows two fee lines ("opening fee" and the "at most"
  worst case). The second was validated in campaign 10; three one-line wording
  options to make it plainer are proposed in the French delivery note, for the
  operator to choose before any change.

## Sound

The emission, the cap, and the issued total against the UTXO set after a
reorganization and a restart; block and transaction validity; the difficulty
adjustment; names across reorganizations; the release chain end to end; the
local account's guards; the channel journal, cooperative close, and splice
paths; the post-quantum transport and the keys at rest.
