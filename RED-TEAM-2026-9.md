# Ninth Q21 campaign — eight reviewers on the published 0.5.9 (0.5.10)

*0.5.9 exactly as published, attacked by eight reviewers, two for each way
of thinking: the architects (invariants, trust boundaries, shared
resources), the innovators (new paths through the features), the
persevering (every branch read in full, every restart and kill), and the
technicians (the release, Tor, the servers, the local machine). They worked
as a team on one board, each finding reproduced by its finder and verified
by another reviewer or by compiling the proof against the real code. The
fixes, in 0.5.10, were then attacked again by four reviewers, one per area,
in three more rounds.
Rules: nothing that creates money, takes control of anything, or slows the
real network — every attack ran in a local lab.*

*As in the previous campaigns, a finding is CONFIRMED only when it was run
against the real code or the real binary; every confirmed attack in the node
became a test, checked to fail without its fix.*

---

## On one page

| # | Severity | Topic | Status |
|---|---|---|---|
| S1 | 🔴 HIGH | Six visitor addresses, each within its budget, made a public explorer exceed its memory and be stopped, again and again | Fixed; bounded by size too in round 2 |
| S2 | 🔴 HIGH | A power cut during a payment could leave a channel neither loaded nor watched | Fixed; bounded in round 2 |
| S3 | 🔴 HIGH | On Linux, another account's program listening on every address passed for this account's Tor | Fixed; two bypasses in rounds 2 and 3, closed |
| S4 | 🔴 HIGH | Two onion names alike in 28 bits took each other's place inside the node | Fixed |
| M1 | 🟠 MEDIUM | A channel whose funding a reorganization took away kept paying, backed by nothing | Fixed; four gaps in round 2, closed; one residual below |
| M2 | 🟠 MEDIUM | A peer asking for 65,535 confirmations blocked every new opening for three months | Fixed |
| M3 | 🟠 MEDIUM | A wallet tab left open after the wallet stopped showed whatever answered next on its port | Fixed |
| M4 | 🟠 MEDIUM | The share of the onion book one source may hold was reset at each restart | Fixed |
| M5 | 🟠 MEDIUM | An IPv4 address was "proven" by any TCP connection, and forgot it at each restart | Fixed |
| L1 | 🟡 LOW | One peer's announced height was the network's | Fixed; two bypasses in rounds 2 and 3, closed |
| L2 | 🟡 LOW | The explorer showed a block off the main chain as confirmed | Fixed |
| L3 | 🟡 LOW | Five addresses emptied the explorer's shared search budget | Fixed |
| L4 | 🟡 LOW | Two connections calling in raised the "clock late" warning | Fixed |
| L5 | 🟡 LOW | The public peer list described every seat | Fixed |
| L6 | 🟡 LOW | A reach announcement outlived its owner's name after a reorganization | Fixed |
| L7 | 🟡 LOW | A fast sync wrote headers past the adopted tip | Fixed |
| L8 | hardening | The verifier did not compare a zip entry's local sizes, nor refuse non-ASCII names; the server guides checked the signed comment by eye only | Fixed |

**No money creation, no signature forgery, no chain split, no remote
takeover was found.** The release chain (archives, signature, verification)
held against twenty-two new crafted archives. The rules of the chain are
unchanged since 0.5.6.

---

## S1. The public explorer and its memory

A visitor can ask for a large block over and over, each request within its
call budget: every call cost the same, whatever the size of its answer, and
nothing bounded how many large answers the node built at once. Six addresses
were enough to take the France node past its memory limit; systemd stopped
it, restarted it ten seconds later, and the attacker started again.

**Fix.** A public node builds at most four answers at once, all visitors
together; a request waits up to ten seconds for its turn, then reads "too
many requests". A large answer is charged to its visitor's budget by its
size, one call per 64 KiB. The local wallet and RPC are not concerned.

## S2. A channel after a power cut

The channel journal is appended to at each payment. A power cut at the wrong
moment can leave the end of the file filled with zeros, which the reader
took for a corruption: the channel was no longer loaded nor watched, and a
revoked state of the other side would have gone unpunished.

**Fix.** Zeros to the end of the file are read as an unfinished last write,
as the block store already did. A checksum that fails anywhere else is still
a corruption.

## S3, M3. The local computer

On Linux, the check that a Tor on 9050 or 9150 belongs to this account or
to the system only looked at listeners on `127.0.0.1`: another account
listening on every address passed. It now looks at every listener of the
port, IPv4 and IPv6, any address.

A wallet tab left open after the wallet stopped kept calling its port. A
program of another account listening there next was shown in the tab as the
wallet: its receiving address, and the backup code if the user checked it.
Every answer of the wallet to an authorized request now names the run of the
program; the page keeps the first and stops for good at an answer from
another run or from none, or after two calls in a row that reach nothing.
It never sends a failed call again. Every answer also carries
`Cross-Origin-Opener-Policy: same-origin`: a local page on another port could
open the wallet and later swap the tab for its own.

## S4, M4, M5. The address and onion books

Onion names were filed inside the node under a 28-bit stand-in address: a
name alike in those bits, made in minutes, took the place of an entry point's
name. They are now filed under 64 bits, in `100::/64`, and every name is a
source of its own. `onions.dat` keeps who wrote each name (a fifth field):
a restart used to give every name back to the node itself, and one source
regained its eighth of the book at each one. An IPv4 address is proven by a
completed Q21 handshake, no longer by a TCP connection any listener gives,
and what each address earned is kept across restarts.

## M1, M2. Channels and the chain

A reorganization of six blocks or more can take a channel's funding off the
chain. The channel kept accepting payments that nothing backed any more. An
open channel whose funding is no longer an unspent output of the active
chain, with no spend seen, now signs nothing until it confirms again, from
the restart on as well; its funder holds the coins and announces the funding
again.

A peer could ask for up to 65,535 confirmations at an opening: the channel
never opened, never expired, and held a place among the openings a node
accepts. The depth asked for is now bounded by the longest delay.

## L1–L8

The network height counts a peer's announced height only while it backs it:
a peer that leaves our request for headers unanswered past two minutes
counts for our own height, and an answer that ends its chain ends its claim.
`getblock` says whether a block is on the main chain, and the explorer shows
no confirmation for one a reorganization left aside, under a warning. With
an address index up to date, an unknown transaction or an identifier's
beginning no longer spends the search budget all visitors share, and that
budget is twenty visitors' worth. A late-clock sign comes only from a peer
this node dialed, once per address group. A public `getpeers` gives counts
only. A reach announcement is served only while its key owns a name. A fast
sync writes only the headers of the authenticated path, and the bodies up
to its tip. `tools/verify-release.sh` checks a zip entry's local sizes and
refuses names that are not printable ASCII; the server guides check the
signed comment with a command.

## And one change asked by the user

A closed channel is closed: once its close is confirmed, it no longer counts
toward the eight channels a contact may have with you. It stays watched for
about a day, at most 32 per contact.

---

## Round 2

Four reviewers, one per area, attacked the fixes on the release build; a
third and a fourth round checked the fixes of the round before. What they found, all fixed in 0.5.10:

- **Tor on this computer (HIGH).** With no Tor of its own, a node waited on
  127.0.0.1:9050, whoever listened there; a system Tor's port could change
  hands while it restarted; and a program of another account that closed its
  listening socket right after accepting was no listener when the node
  looked. Every connection through a local proxy now checks, on Linux, the
  account of the socket that accepted it.
- **Channels.** The funder's funding transaction was dropped at the first
  compaction of the journal, so a funding a reorganization took away was
  neither held nor announced again; it is kept. A funding back on the chain
  held the channel only until one block deep; it holds it until the agreed
  depth. The peer's payment left unsigned meanwhile kept both ends "in
  flight" until a reconnection; it is handled once the funding is back (a
  first fix by reestablish was taken for a replay, and penalized the peer:
  replaced). No close is made while the funding is off the chain, and a
  close alone not yet in a block is announced again at each block. Zeros
  longer than an append can leave, or a journal of zeros only, refuse the
  journal instead of emptying it, and every cut is said on the console.
- **Public explorer (MEDIUM).** Four answers built at a time bounded how
  many, not how large: an answer is now at most 4 MB (four million bytes,
  not 4 MiB), what the documented Caddy reads whole at once, and the error
  replacing a larger one has a fixed size (a first version echoed the
  visitor's id, six times larger once encoded).
- **Network height (LOW).** One orphan header per request, then the same old
  full batch sent back to every request, then one invented header after our
  tip with no body behind it, kept a claimed height counted; an answer that
  does not connect, or brings nothing new, now backs nothing, and a peer that
  delivers no body by the deadline counts for our own height. A
  peer with nothing new, which sends no answer, was never asked for headers
  again, and its later reorganization was followed only at the next restart;
  it is asked again once its request has waited two minutes, and at once when
  one of its blocks waits for a parent.
- **The wallet page** ended itself when the refresh's three calls failed
  together once; it now ends after four seconds without an answer.
- **The release verifier** refuses any zip entry with a data descriptor,
  flagged in the central directory or in the local header.
- **Hardening:** a peer that called in from `100::/64` is no onion source of
  its own; source keys in `onions.dat` use a fixed-key hash, the same for
  every build.

Held in rounds 2 and 3: the run id and the opener policy of the wallet page,
the onion stand-ins, the onion sources across restarts, an IPv4 address
proven by a handshake, the clock warning, reach announcements after a
reorganization, the fast-sync adoption, `getblock`'s `active`, the public
`getpeers`, the search budget with an index, the funding depth at opening,
and closed channels out of the count.

---

## Open

- **A finished splice undone by a deep reorganization** (MEDIUM, found in
  round 2): once a splice is buried and finished, the old funding is no
  longer watched. A reorganization deeper than the splice's burial that
  leaves the splice out of every pool brings the old funding back unspent,
  and a revoked state on it is not punished. It takes such a reorganization
  and a dishonest peer; the channel at least pays nothing meanwhile (its new
  funding is gone). Fix planned: watch the old funding until the splice is
  buried past the deepest reorganization, and keep the splice to announce it
  again.
- **A channel whose funding can never come back** (LOW): a funder that
  spends the funding's coins elsewhere after a deep reorganization leaves the
  other side with a channel held for good, counted among its eight.
- **Proofs saved by 0.5.9**: an IPv4 address marked proven by 0.5.9 (by a
  bare connection) is taken as proven once, at the first start of 0.5.10.
- **Two onion services of one Tor**, both dialed by the node, count as two
  signs of a late clock.
- Every item of the "Open" section of RED-TEAM-2026-8.md still stands, but
  the fast sync's extra headers (L7).
- **On macOS and Windows**, a local proxy is still trusted by its port
  alone: on a computer shared with other accounts, prefer the bundled
  Tor (TOR.md).
- **The network height** is still what peers announce, now only while they
  back it with headers; an eclipsed node sees what its adversary shows it.
- **A search by amount** always spends the shared search budget: there is no
  index by amount.

## Sound

The release chain (twenty-two new crafted archives refused); reorganizations
and restarts (the campaign-8 fix holds); the address index; the fast-sync
snapshot; names; message decoding and rate limits; seat eviction; the wallet
page against other sites, the launch token, defaults and look-alike names;
cooperative closes, the "older copy" claim and the verification words;
forced kills during a thousand payments and during splices; going from
0.5.9 to 0.5.8 and back.
