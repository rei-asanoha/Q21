# Thirteenth Q21 campaign — a team of specialists on 0.6.0

*The 0.6.0 release — the long-maturity soft fork, final after campaign 12 — attacked again by a
team of seven specialists coordinated by an organizer who verified every finding against the real
code before any fix: the **consensus** specialist (block and transaction validity, forgery,
inflation, reorganizations), the **supply** specialist (the cap, the emission schedule, the 0.6.0
maturity transition across block 7000), the **cryptographer** (the signature schemes, domain
separation, the keys at rest, the signing key, the release trust path), the **denial-of-service**
specialist (asymmetric cost, serving budgets, the mempool, reachable panics), the **network**
specialist (eclipse, partition, address handling, the Tor transport), the **wallet** specialist
(funds, state, and whether the delivered wallet is the genuine one), and the **human-factor**
specialist (look-alike names, backup-code handling, the close and verify flows, the guides).*

*The goal, as in every campaign: to forge or inflate money, or to stop, isolate, slow, or confuse
the chain or a wallet, or to make a human act against their own interest. Rules, as always: local
regtest/lab sandboxes only; nothing touches any real network, server, Tor, mainnet, or third party;
a finding is confirmed only against the real code or the real binary; each confirmed node/wallet flaw
becomes a failing-without-the-fix test or a replayable lab script; no key or secret is ever printed.*

*Two passes: a first fan-out across the seven dimensions, then an adversarial re-test pass in which
each fix was attacked again, from a different angle, to try to make it fall.*

Target: 0.6.0 at commit `0839c5e`, branch `r20`. Fixes committed at `43c5cde`.

## The money and the core held

No forgery, inflation, double-spend, coinbase over-pay, fee double-collect, or maturity off-by-one
was found. The cap, the emission schedule, value conservation, reorganization accounting, and the
0.6.0 coinbase-maturity rule — including the 7000 boundary and every one of its eight call sites —
were traced in the code and exercised in the lab, and they hold. The soft fork is a true tightening:
a 0.5.x node follows a 0.6.0 chain and never has to accept a reward the new rule forbids; only a
non-upgraded miner can produce a block 0.6.0 rejects, orphaning its own block. The post-quantum
signatures, the domain separation between the transaction / channel / name / handshake contexts, the
keys at rest, and the release trust path are complete. The network heals a partition toward the
branch with more cumulative work and resists the eclipse and address-flood vectors of the prior
campaigns. None of this changed in 0.6.0, and none of it broke.

## Found and fixed

Nine items, all in the minor band (no critical, no high). Classified by severity:

### Medium

- **The Japanese interface called the backup code a "recovery phrase."** Two strings rendered the
  backup code as 復元フレーズ (the standard term for a BIP-39 *seed phrase*) while six others, the
  backup-test panel included, used バックアップコード. The backup code is the single most
  fund-critical concept; a Japanese reader told their wallet and their name-for-life are tied to a
  復元フレーズ, having only ever been shown a バックアップコード, could hunt for a seed phrase that
  does not exist or defer safeguarding the real backup. *Fix:* both strings now say バックアップコード.

### Low

- **A recent-tip compact block was cloned whole before the cache was consulted.** The serving handler
  read and cloned the entire block (`block_by_id`) *before* checking the compact-block cache, so a
  cache hit still paid a whole-block clone under the global lock — and a recent-tip compact is exempt
  from the node-wide serving budget, so N peers rotating recent-tip requests drove N × whole-block
  clones with no aggregate cap (measured ~69 MB/s of internal clone work, node-wide budget untouched).
  No slowdown of the node was observed (`getinfo` stayed ~2 ms), and correctness was never at risk,
  but a documented aggregate bound was exceeded. *Fix:* the cache is consulted first; a hit serves the
  cached compact and never touches the whole block. Re-test on the fixed binary: a compact-hit serve
  now costs ~84× less node CPU than a whole-block serve, and B/C still reconstruct A's tip bit-for-bit.

- **The wallet counted a frozen coinbase as "maturing."** `immature()` did not skip one-time keys that
  had already signed, unlike `spendable()`. If a one-time mining key-hash held both a coinbase and a
  spent payment, its still-immature coinbase — frozen forever, since signing again would reveal the
  key — was reported in the "maturing" total and as the next release, then silently vanished into the
  frozen total at maturity. Display only; no fund path affected. *Fix:* `immature()` now applies the
  same one-time guard as `spendable()`, so immature + spendable + frozen reconcile. Regression test
  `a_consumed_one_time_key_is_frozen_not_maturing` (verified failing without the fix).

- **The maturity countdown was one block short.** The "available in N blocks" badge computed
  `matureAt − height − confirmations`, one too few, so the last immature block read "available in
  0 blocks" while one block still remained. *Fix:* `+ 1` (blocks remaining = `matureAt − tip`, and
  `tip = height + confirmations − 1`).

- **The offline close dialog overstated the cooperative wait.** The two-choice offline close said a
  cooperative close "is complete in `funding_depth` blocks" (6 ≈ 12 min), while the confirm dialog
  correctly says the share returns after one confirmation (~2 min). The overstatement is safe
  (it never understates the close-alone delay) but it nudged an impatient user toward closing alone.
  *Fix:* the offline dialog now says "your share comes back after one confirmation," matching the
  confirm dialog; the French and Japanese patterns were updated to match.

- **French slipped from the formal to the informal "you" in two close dialogs**, and used a feminine
  article before the masculine noun for "backup code." Every other French string uses the formal
  form; the lapse sat exactly in the security-critical close-alone guidance, where an abrupt register
  shift reads as a tampered build. *Fix:* both dialogs use the formal form; the article is corrected.

### Info

- **WALLET.md said the releases were "neither signed nor notarized,"** which a careless reader could
  take as "no verification exists." The releases are not *OS*-code-signed (by Apple or Microsoft) but
  they *are* minisign-signed. *Fix:* the note now distinguishes OS code-signing from the minisign
  signature and points to SIGNING.md.

## Open (accepted this round, with rationale)

- **Inbound-seat churn (denial-of-service).** An abandoned inbound connection holds its seat until the
  ordinary idle timeout (`READ_TIMEOUT`, 120 s). This was first reported as a `push_wait` deadlock
  holding the reader; verification showed `push_wait` is in fact bounded by the writer's
  `WRITE_TIMEOUT` (30 s), whose `close()` wakes it, so the reader is never held longer than that, and
  the 120 s is the normal idle reap. The re-test pass then asked the real question — can an attacker
  deny an *honest newcomer* a seat? A camping (non-churning) attacker loses: its seats settle past the
  newcomer grace and are evicted for the honest peer. Only a continuous churn that keeps ≥23 seats
  under 60 s old, one seat per address group, never reusing a group within 600 s, can keep a node's
  inbound full — on the order of ~250 fresh address groups per 10-minute window, sustained. Even then
  it only degrades *inbound reachability* to newly-joining peers; the node keeps its reserved outbound
  slots and existing peers, and a blocked newcomer still syncs through its own outbound links. Rated
  **low** as a practical DoS; the reachability-degradation-under-massive-group-churn case is recorded
  as the one residual, alongside campaign 11's "no single node-wide CPU budget" item. (In the regtest
  lab the denial looked total only because loopback collapses every connection into one group and
  disables the redial budget — neither holds on a real network.)

- **The explorer's coinbase note** states "one day (720 blocks)" as the primary wording with a testnet
  footnote for the 200-block pre-7000 case, rather than computing the delay from the viewed
  transaction's own height. It errs in the safe direction (it never understates the wait) and is a
  read-only public viewer, so it is left as-is.

- **The signing key** lived in CI secrets up to 0.5.0 and must be rotated offline, with the old key
  treated as exposed, before the main network. Documented in SIGNING.md; an owner action at the
  mainnet cutover, not a code change.

## Sound (checked, no finding)

The emission and the cap against the UTXO set; block and transaction validity and the anti-inflation
gate; the 0.6.0 maturity rule in consensus, wallet, and display alike, across 6999/7000/7719/7720;
value and work sums against overflow; reorganization accounting and the undo of outputs created and
spent in one block; the ML-DSA verification core and scheme-binding; sighash construction against
malleability and cross-context replay; the channel reestablish and behind proofs; the key-derivation
seal and keys at rest; the backup-code handling; the served page's content-security policy, token
exchange, run binding, and cross-origin locks; the look-alike / payee-swap defense carried into the
send recap; the partition heal toward more cumulative work; the address-book flood and alias/nonce
defenses; the compact-block fallback and parking.
