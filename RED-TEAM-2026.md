# Q21 attack simulation — severity report

*Phase 8b, adversarial campaign. A team of six analysts read the code thinking
like attackers, each on one surface: consensus, transaction and block
validation, the peer-to-peer network, the wallet and keys, the API/explorer,
and proof of work. The major flaw was **written as attack code and thrown at
the real program** — not just described. It is fixed, and the fix is proven by
the same test that demonstrated the flaw.*

*Constraint held throughout: a block is still solved in two minutes; nothing
in these fixes slows the chain down or moves its control elsewhere.*

---

## On one page, for those short on time

We found **one critical flaw, real and proven**: under perfectly ordinary
conditions, the chain could **create money out of nothing** and make nodes
diverge from one another. It is **fixed**, and the attack that demonstrated it
now fails against the fixed code.

The rest — eight hardening points — ranges from "important to do before
launch" to "hygiene detail". None allows taking control of the chain, stealing
funds remotely, or breaking into the wallet. The bulk of the code proved
**remarkably well defended**: most of the classic attacks we went looking for
were already closed, with a non-regression test locking them in.

This is the result you hope for from a pre-genesis audit: the serious defect
comes out now, gets fixed without breaking the chain, and costs nothing —
because block 1 does not exist yet.

| # | Severity | Flaw | Status |
|---|---|---|---|
| 1 | 🔴 **CRITICAL** | Money creation during a reorg | ✅ **Fixed and proven** |
| 2 | 🟠 HIGH | Blocking of inbound connections (denial of service) | ✅ Fixed |
| 3 | 🟡 MEDIUM | The difficulty bound is not checked in the proof-of-work core | ✅ Fixed + test |
| 4 | 🟡 MEDIUM | Address book amplification and leak before the handshake | ✅ Fixed |
| 5 | 🟡 MEDIUM | The same message replayed exhausts the node's CPU | ✅ Fixed |
| 6 | 🟡 MEDIUM | Public explorer: search quotas can be bypassed | ✅ Fixed |
| 7 | 🟡 MEDIUM | Wallet substitution by writing to the data directory | ◑ Already bounded by the OS; out-of-band residue (see below) |
| 8 | 🟢 LOW | Five hygiene points | ✅ Fixed |

*All fixes were validated: full test suite green (21 binaries), clippy with no
warnings, and, for both the critical flaw and the difficulty bound, an attack
test that now fails against the fixed code. No fix touches the two-minute
pace.*

---

## 1. 🔴 CRITICAL — Money created out of nothing during a reorg

**This is the only flaw in this report that could have destroyed the project.
It is fixed.**

### What it is, in plain terms

Picture a shared ledger where everyone checks everything. Sometimes, two
miners find a block at almost the same time, the network hesitates for a
moment, then settles on the chain with the most work: this is a **reorg**, a
normal and frequent event in any proof of work. The losing block is *undone* —
its entries are reversed, and the ledger goes back to its previous state.

Now, Q21 allows a payment within a block to spend the change from an earlier
payment in the same block. This is normal and common: you pay someone, they
give you change, and you spend that change right away. The code calls this
"parent-before-child chaining", and it allows it on purpose.

The defect sat at the intersection of the two. When such a block was
**undone**, the routine that puts the ledger back in order got it wrong: the
coin born **and** spent inside the block was first removed, then **put back**
by mistake. It survived the undo — a phantom coin, spendable, matching no
payment on the real chain. Money created out of nothing.

### The proof, in numbers

We did not describe the attack, we **executed** it against the real code.
Starting point: a single coin of 10,000. We build the booby-trapped block and
undo it the way a reorg would. Measured result:

```
value before : 10000
value after  : 19000      ← 9,000 created out of nothing
phantom Y present after undo: true
identical commitment: false
```

Worse: the commitment of the corrupted state remained **consistent with
itself** — the node's internal check saw nothing abnormal. A node that went
through the reorg and a node that synced from scratch from the winning chain
ended up with **two different ledgers**, both believing themselves correct:
the network splits silently, and the inflation is invisible.

### Why it was serious enough to stop everything

Three combined reasons. Money creation ruins the fundamental promise of a cap
at 21,000,001. Divergence between nodes breaks consensus — the network stops
being a single network. And above all, **it did not require an attacker**: a
reorg is normal, spending your change within a block is too; the defect would
therefore trigger on its own, on ordinary activity, sooner or later.

### The fix, and why it does not slow the chain

A coin born and spent in the same block did not exist before that block;
after the undo, it must therefore not exist. The fix says exactly that: during
the undo, a spent coin is restored **only if the block did not also create
it**. Present in both lists, it nets out: removed, never put back.

This is an **undo accounting** fix, not a pace fix: it touches neither the
proof of work, nor the difficulty, nor block validation. A block is still
solved in two minutes, exactly as before. The attack test is now kept
permanently in the test suite (`tests/attack_reorg_inflation.rs`): if anyone
ever reintroduces the defect, it will catch it.

**Status: fixed, non-regression checked on the whole suite.**

---

## 2. 🟠 HIGH — An attacker can block inbound connections

### In plain terms

To enter the network, a new node knocks on the door of a "bootstrap node"
(see `JOIN.md`). A bootstrap node accepts a limited number of inbound
connections. The defect: the code never requires a connection to **complete
its introduction** (the "handshake") to keep its slot. An attacker opens
connections, sends just a small "ping" from time to time to look alive,
without ever introducing itself — and occupies all the inbound slots
indefinitely.

### The impact, measured at its true size

This is **not** a takeover and **not** theft. It is a targeted denial of
service: with a few spread-out addresses, an attacker fills the 24 inbound
slots of a bootstrap node and prevents newcomers from entering *through it*.
Nodes already connected carry on, and the outbound connections protected
against isolation still work. It is a degradation of reachability, not a
network halt. The "high" severity comes from the fact that a young network,
with few bootstrap nodes, is sensitive to it.

### How to fix it

Set a **handshake deadline**: a connection that has not introduced itself
within a short delay (ten to thirty seconds) is closed, and a "ping" received
before the introduction must not refresh the liveness counter. It is a handful
of lines in connection management, with no effect on the block pace.

---

## 3. 🟡 MEDIUM — The difficulty bound is not checked where it should be

### In plain terms

Proof of work imposes a **minimum difficulty**: without it, one could build a
valid block with no effort, and mine far faster than the intended two-minute
pace. Today, this bound is indeed enforced — but **outside** the core of the
proof of work, in the code that attaches blocks to the chain. The function
that judges "is this work sufficient?" itself accepts any difficulty it is
given.

### The impact

**None today**: the only two places that call this function set the bound just
before, and the genesis hard-codes it. The risk is **latent**: the day some new
code calls this function and forgets to set the bound — for example a future
validator that checks headers before bodies — it would reintroduce exactly the
"infinitely many valid headers without mining" defect that phase 8 had already
fixed. It is the kind of debt that blows up months later, far from where it
was incurred.

### How to fix it

Move the invariant **into** the work verification function: have it refuse a
target easier than the minimum difficulty itself, instead of trusting its
callers. The rule then lives with the computation it protects, and no future
caller can forget it. This fix *strengthens* the two-minute guarantee; it does
not touch it.

---

## 4. 🟡 MEDIUM — The address book leaks and amplifies before the handshake

### In plain terms

A node keeps an address book of other nodes. The command that requests this
book (`getaddr`) is served **without requiring the introduction**, and without
a rate limit. A small 24-byte request triggers a reply of up to 16,000 bytes —
an amplification of about 600 times — built while the node holds its main
lock. And anyone, without introducing themselves, can thereby **harvest the
whole address book**.

### The impact

Two moderate nuisances: an amplification and load lever (the main lock is also
the one used to validate blocks), and network reconnaissance handed to an
anonymous scanner. It is not a takeover; it does, however, contradict the
code's stated principle — "nothing is read before the handshake".

### How to fix it

Require a completed handshake before serving `getaddr`, as is already the case
for the other commands, and apply the same token bucket (rate limit) as the
rest. The code already has this mechanism; it only needs to be extended to
this command.

---

## 5. 🟡 MEDIUM — A replayed message exhausts the CPU

### In plain terms

When a node receives a transaction, it computes its identifier (a hash of the
whole transaction) before checking whether it already knows it. The rate
guard only applies to **new** transactions. By replaying the same large,
already-known transaction in a loop, an attacker forces the node to recompute
that expensive hash every time — up to twice — without ever hitting the rate
limit, and all of it under the main lock.

### The impact

A CPU-exhaustion denial of service: the node becomes serialized under
sustained replay. No theft, no takeover — a performance degradation.

### How to fix it

Apply the rate limit **before** the expensive computation, or keep a small
memory of recently seen hashes to reject a replay without recomputing it. The
cost of *deciding* that a transaction is already known must also be capped,
not just the cost of processing new ones.

---

## 6. 🟡 MEDIUM — Public explorer: search quotas can be bypassed

*Only concerns the server if the public explorer is enabled — which is the
case on your public server.*

### In plain terms

The public explorer runs behind a front web server. To share searches fairly
among visitors, the node counts them per IP address. But it **trusts** a
header (`X-Forwarded-For`) that the front server is supposed to fill in
honestly. If the front server is configured to *append* to this header instead
of *replacing* it — a common default setting — the attacker controls its
content and makes up a different IP for each request, bypassing the
per-visitor quota.

### The impact

A denial of service on the explorer's **search**: the attacker exhausts the
shared global quota and deprives real visitors. **Block validation remains
protected** by a separate global ceiling — it is a nuisance for the explorer,
not a chain freeze.

### How to fix it

Do not blindly trust the first link of the header: make the number of trusted
intermediaries explicit (take the *last* entry, or a number set by the
operator). On the configuration side, make sure the front server **replaces**
the header. Two complementary steps.

---

## 7. 🟡 MEDIUM — Wallet substitution by writing to the data directory

### In plain terms

The wallet protects itself against substitution: two small control files (an
"anchor" and a "serial number") prevent your wallet from being replaced by
another one, or from being rolled back to an old backup (which would cause
one-time keys to be signed with again — dangerous). But these two files are
in **plain text** and are not bound to your passphrase. Someone who can
**write to your data directory** can rewrite them consistently and get their
own wallet adopted.

### The impact

Real but **bounded**: one must already be able to write to your directory —
that is, already be inside your machine, under your account. Someone in that
position can read your `wallet.dat` anyway. The code explicitly acknowledges
this as "the same limit, already accepted, as the anti-replay by serial
number". This is not a remote flaw.

### How to fix it

Bind the anchor to the passphrase (authenticate it with a hash derived from
the sealed seed), so that an attacker without the passphrase cannot forge a
valid anchor. A hardening, not an emergency.

---

## 8. 🟢 LOW — Five hygiene points

None is remotely exploitable; these are corners to clean up.

**a. Possible panic on the fallback path of a reorg** (`chain.rs`). A reorg
that fails halfway restores the original chain with an `expect` that *crashes
the node* instead of returning a clean error. We could not construct the input
that triggers it (the reconnection path is deterministic and was valid
before), so this is defense in depth — but a crash is never the right answer
in a consensus routine. *Fix: return an error instead of panicking.*

**b. "SphincsPlus" outputs that are valid but unspendable forever.** This
signature scheme is accepted when creating an output but not available for
spending: a coin locked to it is **burned** for good. Nobody gains from it (it
is the recipient who chooses), but it is a trap. *Fix: refuse this scheme at
creation as long as it is not available for spending.*

**c. The proof-of-work cache mixing can cancel itself out.** In a handful of
cells out of millions, an operation neutralizes itself and produces a constant
value. A minor loss of entropy, no exploitable mining shortcut. *Fix:
guarantee that the two mixed terms differ.*

**d. No minimum passphrase strength is enforced.** A one-character passphrase
is sealed with the full strength of the encryption — but can be guessed in an
instant. *Fix: enforce a floor, or at least refuse to seal below a
threshold.* (An empty passphrase, for its part, is handled correctly.)

**e. Duplicate `Transfer-Encoding` / `Content-Length` HTTP headers not
rejected.** Harmless today (each connection closes after a single request, so
no "desync"), but would become exploitable if connection reuse were ever
added. *Fix: reject these ambiguous headers, for consistency with the
rejection of a duplicate `Host` already in place.*

---

## What held — and what you should know

An audit that listed only the flaws would give a false picture. A large share
of the classic attacks was **already closed**, checked in the code:

- **The wallet and keys.** No seed leak, no one-time key reuse found — the two
  crown jewels we searched hardest for. The seed is encrypted then
  authenticated, wiped from memory after use, never logged. Reserve-before-sign
  is watertight.
- **Inflation through transactions.** Value conservation, absolute cap,
  additions protected against overflow, uncle reward removed: everything is
  locked down. (Flaw no. 1 slipped *past* these defenses, through undo
  accounting — not through validation.)
- **Difficulty and time.** The "time-warp" attack (falsifying timestamps to
  mine faster) is neutralized: time is treated as signed and asymmetric, and
  any manipulation *increases* the difficulty.
- **Decoding network messages.** No memory bomb, no decoder crash found — the
  lengths announced by the attacker are bounded by what the frame actually
  contains.
- **The 51% attack.** It has no software fix: it consists of owning more than
  half of the computing power. The only defense is the number of independent
  miners — that is, decentralization, which `JOIN.md` discusses. It is not a
  flaw in the code; it is an economic property of the network.

---

## Status after the fixes

All eight points are handled. The critical flaw and the six service or hygiene
flaws (2 to 6, 8) are **fixed**, each with its justification in a comment in
the code and, for the two most serious, an attack test that now fails against
the fixed code. The whole test suite stays green and clippy is silent.

Point 7 deserves an honest word, because it is not "fixed" and cannot be fixed
in band. Wallet substitution assumes an attacker who **writes to the data
directory**. The control files (the anchor, the wallet) are already written
with **owner-only** access: *another* account on the machine therefore cannot
perform the substitution. The residue is code running **under the user's own
account** — malware already inside. Against it, no wallet lock holds: it reads
the seed from the process memory, records the passphrase keystrokes, replaces
the binary. Binding the anchor to the passphrase would change nothing — at
check time, the verifier holds the legitimate seed no more than the attacker
does, so the guarantee would go in circles. Claiming to have closed it would
be security theater. The real countermeasure is at the system level: keep the
machine clean, and the directory out of reach of other accounts — which is
already the case by default.

## What remains open, and is not a bug

The warning the code itself carries, which must be repeated: the
proof-of-work primitives **have received no external cryptanalysis**. This
campaign checked the *plumbing* — that the pipes are properly connected, that
the flaws found are closed, that the most serious attack now fails for good.
It does not replace a cryptographer's review of the mixing function itself. It
is the prerequisite that the white paper rightly marks as open — and the only
thing, from now on, standing between this code and a calm genesis.
