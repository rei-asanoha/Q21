# Eighth Q21 campaign — eight reviewers, four ways of thinking (0.5.9)

*The 0.5.9 candidate, attacked by eight reviewers, two for each way of
thinking: the architects (invariants, trust boundaries, shared resources),
the innovators (new paths through the features, the page, the channels), the
persevering (every branch of the code read in full, every restart and kill),
and the technicians (the release, Tor, the servers, the local machine).
Every area was covered: the chain, payment channels, the wallet and its page,
the servers, and the communication between nodes. They worked as a team on
one board; each fix was then attacked again, by its own finder and by a
reviewer of another area. Rules: nothing that creates money, takes control
of anything, or slows the real network — every attack ran in a local lab.*

*As in the previous campaigns, a finding is CONFIRMED only when it was run
against the real code or the real binary; every confirmed attack in the node
became a test, checked to fail without its fix.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| R1 | 🔴 CRITICAL | A release archive that two archive readers read differently passed `verify-release.sh` with an evil program inside | Fixed; three bypasses in round 2, all closed |
| R2 | 🔴 HIGH | A hash file naming the program twice passed the release workflow and the verifier | Fixed, re-checked |
| C1 | 🔴 HIGH | A wallet restored from a backup could be led to close a channel with a revoked state | Fixed; residual below |
| W1 | 🔴 HIGH | Another account on the same computer could take the wallet page's port and get the wallet | Fixed, re-checked on both launch paths |
| T1 | 🔴 HIGH | Another program could take the bundled Tor's SOCKS port, at start or after Tor stopped | Fixed, re-checked |
| N1 | 🔴 HIGH | A few address groups could hold every seat of an entry point | Fixed; a bypass in round 2, closed |
| N2 | 🔴 HIGH | One caller could fill an entry point's address book, then its onion book | Fixed; residual below |
| N3 | 🟠 MEDIUM/HIGH | After a deep reorganization, blocks of the new branch were missing from disk | Fixed; the first fix regressed, replaced |
| E1 | 🔴 HIGH | One HTTP/2 connection froze a public explorer behind the documented Caddy | Fixed in the guide; memory capped |
| D1 | 🟠 MEDIUM | 0.5.9's Tor-by-default could leak or be steered (three ways) | Fixed before release |
| T2 | 🟠 MEDIUM | The onion self-check could restart Tor in a loop | Fixed |
| W2 | 🟠 MEDIUM | "The words match" was not bound to the words shown | Fixed |
| C2 | 🟡 LOW-MEDIUM | A splice's coins stayed held after its channel ended | Fixed |
| W3 | 🟡 LOW | The call page painted one contact's status under another's panel | Fixed |
| P1 | 🟡 LOW | A spending policy was walked in full before the peer's budget was counted | Fixed |

**No money creation, no signature forgery, no remote crash, no chain split
was found.** The rules of the chain are unchanged since 0.5.6. Transactions,
signatures and the mempool were read in full and found sound; storage,
restarts and names too.

---

## R1, R2. The release

An archive can hold entries that GNU tar and libarchive (the `tar` of macOS
and Windows) read differently: a global header naming another file, a size
field with a space inside, a "folder" carrying data, a zip entry whose name
in the directory differs from the name in its own header. The verifier
checked what GNU tar and `unzip` saw; the user's computer extracted the
other reading — an evil program, past a valid signature and an independent
attestation. Separately, a hash file naming the program twice was accepted:
one line checked, the other compared by a rebuilder.

**Fix.** `tools/verify-release.sh` reads every tar header itself: a valid
checksum, canonical size fields, only files and folders (a folder has no
data, a name ending in a slash is a folder), printable names; its list must
equal `tar`'s. A zip must have each entry's own name equal to its directory
name, entries back to back, and `unzip` must exit without a warning. A hash
file naming a file twice is refused, in the workflow and in the verifier.
Re-checked with every variant built in both rounds, and with the real 0.5.8
archives, which pass.

## C1. A restored wallet and an older copy of its peer

A channel peer that kept an old copy of its own side could show it to a
wallet restored from a backup; the wallet saw "the peer is behind" and
closed by itself, with a state it had revoked, and lost the channel to the
penalty. **Fix.** A wallet never closes by itself on that claim: it warns,
and its holder closes from the page once they confirm the wallet was not
restored from a backup. **Residual:** a peer that answers exactly as the
restored copy expects, or says nothing, cannot be told apart by the copy
itself. WALLET.md now says it plainly: a copy of a data folder is never a
backup of a channel.

## W1, T1. The local computer

Between the moment the launcher chose the wallet page's port and the moment
the page served it, another account could listen there, and the browser
carried the launch token to it. The bundled Tor's SOCKS port had the same
gap, and again after Tor stopped. **Fix.** The page's port is held from its
choice until the page serves it, and the launcher checks that the wallet
itself answers. Tor picks its own SOCKS port and the node reads it from
Tor's log; when Tor stops, the node's proxy becomes port 0, where nothing
can listen, until Tor runs again. Checked with a fake Tor printing
misleading lines: only Tor's own first line is believed.

## N1, N2. Seats and addresses of an entry point

The round-1 fix of eviction was bypassed in round 2: occupants spread over
twelve address groups, one young seat each, redialed every minute.
**Fix.** Protection is shared out per address group; when every seat is
young, the most crowded group gives up one; a group that arrived three times
in ten minutes loses the newcomer's first-minute grace (an honest newcomer
arrives once). Tor arrivals are not a group and keep it. The address book:
a caller writes at most 128 new addresses per connection, an address group
512 an hour, a peer we dialed one reply's worth; onion names were left out
in round 1 and now share the same bounds. **Residual:** one address group
patient for an hour can still replace the entries no one has proven yet, and
every Tor caller shares one budget.

## N3. Blocks of a deep reorganization

A block refused at first for its context, then made active by a heavier
branch, was never written to disk; a restart put the node back on the
abandoned chain. The first fix wrote every such block at once, and a
restart then adopted a branch the running node had refused. **Fix.** Every
block of the branch a reorganization connects is written, and only those.
Both scenarios run again on real nodes.

## E1. The public explorer behind Caddy

The 0.5.8 guide capped Caddy's connections to the node at 48: one HTTP/2
connection opening 48 requests and never reading held all of them.
Reproduced against Caddy 2.10.2. **Fix.** No cap; Caddy buffers each answer
(`response_buffers 4MB`) and drops one not delivered within 30 seconds; a
systemd drop-in caps Caddy's memory, so a flood of non-readers restarts
Caddy, not the server. **Residual:** that flood can still interrupt the
explorer for a few seconds at a time; the node is not touched.

## D1. Tor by default

Three ways round the new default were found before release: a wallet made
reachable by default became reachable **in the clear** once Tor was turned
off; any program listening on port 9050 counted as a Tor; a `settings.txt`
saved with a byte-order mark, or not in UTF-8, was read as empty and
rewritten. **Fix.** The default is `reachable=onion`: reachable through Tor
only, never in the clear. Only a Tor the wallet starts itself counts. A
byte-order mark is read through, and a file that cannot be read is never
written.

## T2, W2, W3, C2, P1

The quick Tor restart is no longer armed by a short wake nor fired while Tor
is starting, and an unreachable onion is restarted at 30 minutes, then 1, 2
and 4 hours. "The words match" is taken only for the words, owner and
language shown; "they differ" is always taken. Choosing another panel stops
the call followed on screen. A splice is held and sent again after a restart
only while it can still confirm. A policy's preimages are no longer hashed
before the peer's budget is counted.

---

## Open

- **The Tor files inside an archive** are covered by the archive's
  signature, but the verifier does not compare them with the Tor Project's
  own release.
- **The node's RPC port** can be held by another account while the node is
  down; the monitor then reads that program's answers.
- **systemd hardening** of the service files can go further.
- **After the last issuing block**, an empty block has no valid coinbase:
  for the review of the chain's rules before mainnet, with A1 and A2 of the
  seventh campaign.
- **Low:** a fast sync accepts extra headers it does not check; compact
  blocks name transactions by txid; the address-index log is not synced to
  disk at each write (it repairs itself); a name tells where its owner can be
  reached (TOR.md, section 6).

## Sound

Transactions, signatures and the mempool (read in full, decoding fuzzed);
storage, restarts and names; peer address groups in IPv6; the forwarded
address; the release workflow's artifacts and its publication; the signature
check of the bundled Tor; the channel's backup question on the page; no
automatic broadcast of a commitment left in the channel code.
