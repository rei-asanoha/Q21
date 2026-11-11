# Fourteenth Q21 campaign — mainnet readiness, on 0.6.1

*The 0.6.1 release, deployed on the test network, reviewed as if the main network were launching
next: the architecture, a line-by-line reading of the code cut into forty units, the channel state
machine as a whole, every consensus rule end to end, the post-quantum posture, the wallet, the
servers, and the release chain. Five cross-cutting themes were held by senior specialists — the
post-quantum posture (T1), mainnet readiness (T2), the channel state machine across restart,
reorganization and restore (T3), consensus invariants end to end (T4), and the attacker who also
uses AI tools (T5) — and each finding was verified against the real code by a second, independent
reader before any fix.*

*The rule of this campaign: every flaw is measured, fixed, re-tested, and then attacked again by
specialists whose only task is to get around the fix. Four such rounds were run. The adversary to
imagine was always the same: a skilled human who also masters AI — who generates look-alike names
and fake guides at scale, automates fuzzing and exploit iteration, runs many cheap nodes, reads our
public repository and our red-team reports, and talks users, operators and their assistants into
acting against themselves. Rules, as always: local regtest labs only; nothing touches any real
network, server, Tor, or third party; no key or secret is ever printed; each confirmed flaw becomes
a test that fails without its fix.*

Target: 0.6.1 at commit `c6bb756`, branch `r20`. Fixes in 0.6.2.

## Summary

One **critical** flaw was found and fixed: a wallet restored from its backup code reused, on a new
channel with a former peer, the revocation secrets that peer already held. Attacking that fix found a
**high** one behind it (the old channel's funding output named again as the new channel's), and
attacking that fix found a second **high** one (the margin of the new check chosen by the funder).
All three are closed and each is guarded by a test that replays the attack.

The money held everywhere else: no forgery, inflation, double-spend, cap overrun, or consensus split
was found. The remaining findings are medium and below, plus a list of decisions the main network
must take before it exists (below, "Before the main network").

## Found and fixed

### Critical

- **A restored wallet's new channel shared its revocation secrets with the old one (T3-1).** Channel
  keys come from the wallet seed and from counters kept only in the channels folder. A wallet restored
  from its backup code starts those counters again, so a new channel with the same peer had the same
  keys, the same channel id and — the revocation root being derived from the seed and the channel id
  alone — the same revocation chain. The former peer already held every secret of the new channel:
  it could broadcast the new channel's first state as if revoked and sweep it all. Measured on a real
  chain between two managers: the peer swept 49.99997462 Q21. *Fix:* the revocation root is salted
  with 32 fresh random bytes drawn when the channel is created, written in its opening record before
  any signature leaves, and kept through compaction and restart. *Tests:* a new channel on the same
  keys shares no revocation secret with the old one; the salt survives a compaction and a restart;
  every form of the opening record reads back as written.

### High

- **The old channel's funding output could fund the new channel (B-T3-1-1, found attacking T3-1).**
  After a restore, a former peer could name the old channel's funding output, still unspent, as the
  funding of a new channel on the same keys, and take back with an old commitment the acceptor signed
  long ago everything it paid in the new one. An honest funder broadcasts only after the acceptor's
  signature, so the acceptor now writes down the tip it signs at, before the signature leaves, and
  forgets a channel whose funding confirmed at or below it. *Test:* the attack replayed opens the
  channel without the check and is refused with it.
- **The margin of that check was chosen by the funder (B5-1, found attacking B-T3-1-1).** The margin
  for a reorganization was the channel's funding depth, which the funder proposes (up to 2016 blocks):
  an old output that deep passed as new. *Fix:* the margin is the smaller of the channel's depth and
  the network's. *Test:* a deep funding depth does not widen the age check.
- **After a restore, nothing told the holder that channels were not restored (RT2-1).** A restored
  wallet has lost the journals that held the secrets punishing an old state: a former peer can close
  at an older state, and nothing can contest it. The restored screen said "nothing is lost". *Fix:*
  the restored screen, the command-line restore and WALLET.md say that channels are not in the code,
  that the other side closes on its own and needs nothing from the holder, that the holder's share of
  that close comes back by itself, and to open no new channel with that person before their close is
  confirmed. A peer that reestablishes a channel the wallet does not know is now named in the log,
  worded as a claim, bounded per peer and in all, so a stranger cannot fill the list and hide a real
  one (B6-2). *Tests:* the restored screen; the unknown channel is named once; made-up channels do not
  hide a real one. The root fix — channel backups — is a design item below.

### Medium

- **An older copy still countersigned the peer's close and updates (T3-2).** A wallet folder put back
  from an older copy, even once proven older, signed a cooperative close or an update the peer sent,
  settling the channel on stale balances, at once and unpunishable. *Fix:* such a copy signs nothing
  the peer sends — no update, no close, no splice step — until an in-step reestablish; the channel
  component ignores those messages on such a copy, and the state machine refuses them too. Attacking
  the fix found a stale copy completing its own pending splice (B3-1, fixed the same way) and a race
  between two sessions that could leave an in-step channel ignoring payments (R1-2, fixed). *Tests:*
  an older copy signs no close, no update, completes no pending addition; a restored older copy
  countersigns no close.
- **A node catching up with the chain could take a new channel (B2).** After a restore the node
  re-syncs from genesis and cannot yet tell an old channel's output, named again, from a new one.
  *Fix:* a node still catching up — its tip older than a day, or below the last anchor of the test
  network — answers no channel opening and signs no first funding, and says so once (R2-2). A
  regression of the first version of that fix (no exemption for regtest, R2-1) was caught by the next
  round and fixed. *Test:* a node catching up takes no channel; caught up, it does.
- **The official binary could start a main network (T2-2).** One line in `wallet.dat`
  (`network=mainnet`) passed every "the main network does not exist" refusal. *Fix:* a wallet file that
  names the main network, or an unknown one, is refused before anything is opened. *Test:* included.
- **Four ways a person could be talked into a loss (T5-3, T5-4, T5-9, B4-1).** The backup-code card
  now says that nobody but the holder ever needs the code — not a helper, the project, a website or
  an assistant — and the setup, restore and command-line screens say it too (B4-4). A contact
  verification this wallet did not start, with a caller that is not a contact verified before, is
  announced as such, and "The words match" needs a tick ("face to face, or on a call to or from a
  number I already had"); "The words differ" stays one click. The close-without-the-peer dialog
  always mentions a folder replaced by a copy and being told to close. *Tests:* included; French and
  Japanese texts.
- **The restore printed the backup code back (RT2-2).** A restore is what a script or a service
  runs, and its output ends up in logs. *Fix:* a restore says "the one you restored from — not shown
  again". *Test:* the restore's output does not contain the code.
- **Prefix search on a public explorer without an index read up to 2,001 whole blocks under one hold
  of the node's lock, outside every read budget (RT1-1).** *Fix:* block by block, within the public
  read budget, and charged; a window cut short answers only what it proved — from 16 characters (the
  length the page shows) the first hit is the answer and the scan stops there, two hits are
  ambiguous, and a shorter prefix is refused with a clear message instead of reading the whole budget
  for nothing (B7-3). *Tests:* no block is read under one lock hold; the cut rule; a public explorer
  still completes a transaction prefix.

### Low

- **The node's log quoted a peer's free-form user agent (T5-7, B4-5),** a sentence a stranger chose
  reaching an operator or an assistant the log is pasted into. Only user agents in the exact grammar
  of ours are quoted now; anything else is described by its length. A router's UPnP error code reaches
  the log as its digits only (B4-6).
- **The server guides anchored the signing key on the README (T5-8).** They now anchor it on the copy
  confirmed in JOIN.md, away from GitHub, pin no version in their prose, and say that a log line never
  tells the operator to run a command.
- **The send recap showed the address as one unbroken string (T5-6, B4-3).** It is shown in groups of
  eight, on Receive and in the recap, and a recipient that is not a contact is flagged.
- **The startup check of one-time keys declared verified the blocks it could not read (RT2-3).** On a
  node started from a snapshot or pruned, that lifted the send-time guard of a one-time-key wallet.
  The check now stops at the first missing block, resumes past what was already verified (B6-7), and
  says to open the wallet once on a node holding the whole chain. Test networks only: one-time keys
  are refused on the main network.
- **`getsupply`, a light call, walked the whole set of outputs at every call (RT1-2).** Computed once
  per tip now.
- **A public explorer echoed an unknown method name (RT1-4).** It no longer does; a local node still
  names it.
- **Regressions of this campaign's own fixes, found by the re-test rounds and fixed before release:**
  an honest funding taken for an old one when the block hook lagged the tip (R1-1); the regtest
  exemption above (R2-1); the silent refusal above (R2-2).

## Open, with rationale

- **The catching-up gate rests on the tip's age (B5-2, B6-5).** One fresh block on a restored node can
  make it look caught up. The anchor height closes it on the test network up to the last anchor; on a
  main network without anchors it is the timestamp alone. The robust check — the funding block's own
  timestamp against the signing time — needs block times in the channel component's depth oracle:
  planned for the main network.
- **A peer's claim that our copy is older stops the peer's own messages until an in-step reestablish
  (T3-2).** A lying peer can only stop its own payments and closes to us, which it could do anyway; our
  own payments and closing alone resume when the unproven claim lapses, as before.
- **The unknown-channel notice is in the node's log only (B6-4).** Showing it on the wallet page is a
  later change.
- **The JSON-RPC request `id` is echoed (B7-1),** as the protocol requires; it is a field, not a
  message.
- **Prefix search with an index, and busy addresses, are linear in history (RT1-3, B7-2).** A sorted
  index answers a prefix in logarithmic time; planned before the main network.
- **Liveness items of the channel engine (T3-3 to T3-6).** Waits that depend on the peer, sweeps
  announced once, silent dead ends of the watcher over bodies the node no longer holds: no funds at
  risk, recorded for the next channel release.
- **A restart can move a node onto a heavier branch the running node refused (T4-1).** The correct fix
  needs the finality state at the tree rebuild; it is a design item below, not a quick fix.

## Before the main network

These are decisions, not bugs of the test network; each is a condition of the launch.

1. **The genesis (T2-1, T2-3).** The main network's genesis is a public placeholder that anyone could
   mine ahead, and recomputing it at every start builds the whole 2 GiB mining table. The real genesis
   must be fixed at the launch, embedded as a constant, and never recomputed.
2. **Difficulty at the start (T2-4, T2-5).** A floor of 256 hashes and a timestamp ratchet let a short
   majority leave a young chain almost halted. Launch parameters and the timestamp rule need review.
3. **Launch-day topology and the partition rule (T2-7, T2-9).** Two entry points, no anchor, and a
   rule that cannot tell a split from a withheld chain. Anchors and the written procedure come first.
4. **Rule changes and separation of networks (T2-6, T2-8, T2-12).** One bootstrap file for all
   networks, regtest speaking with testnet's magic, no activation mechanism but a recompiled height,
   and only the address prefix separating chains.
5. **The page and the launcher are wired to the test network (T2-10).**
6. **Post-quantum release signature (T1-1).** The release chain is signed with Ed25519 alone; a
   quantum attacker could forge a release. Add an ML-DSA signature of the checksums, with the key
   ceremony of the main network.
7. **Other post-quantum items (T1-2 to T1-6).** The node identity key's several roles, MuHash's
   discrete-logarithm assumption, the node-to-node link in clear, the composite collision level, and
   the absence of a fallback signature scheme: documented, each with its plan.
8. **Channel backups (RT2-1, B6-1).** A restored wallet cannot defend its channels. An encrypted,
   automatic channel backup — or a per-instance value in the channel keys themselves — is the root fix.
9. **The signing key (T5-2) and the update procedure (T5-1).** An offline key with a named independent
   home, rotated before the launch, and an update procedure that reviews before it signs.

## Sound (checked, no finding)

The emission schedule and the cap against the set of outputs; block and transaction validity across
reorganization, restart, pruning and fast sync; the 0.6.0 maturity rule; value and work sums against
overflow; the ML-DSA verification core and the domain separation between transactions, channels,
names and handshakes; the keys at rest; the channel reestablish and behind proofs; the penalty path;
the served page's content-security policy, token exchange and origin locks; the look-alike and
payee-swap defenses; the address-book and alias defenses; the serving budgets of the public explorer.
A channel engine fuzzer driven by a hostile peer ran 20,000 rounds on the fixed code without a
failure.
