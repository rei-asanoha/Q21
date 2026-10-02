# The Q21 explorer

See the chain — blocks, transactions, addresses — in a browser, served by your
own node.

## In one command

```bash
./q21 explorer
```

The browser opens. A single search field, which accepts four things:

| What you paste | What you get |
|---|---|
| `276` | The block at that height |
| `5aabc886d907…` (64 characters) | The block, or the transaction, with that identifier |
| `tq211qssljt322rlk…` | The address: its balance, and all its movements |

The wallet already serves this explorer, at the same place and on the same
port: link at the bottom of the page, or `http://127.0.0.1:<port>/`. The
command above is for the opposite case — looking at the chain **without**
opening a wallet. The methods that move funds are then not disabled by a
setting: they are absent.

---

## Why it is not hosted elsewhere

To look at a chain, almost everyone opens a third party's website. People thus
trust a server to tell them what a system built to trust no one contains — and
that server can be wrong, lie, disappear, or be coerced.

This page is served by your node, on the loopback, and only displays what your
machine has validated itself. It loads **no external resources**: no font, no
stylesheet, no remote script. An explorer page that calls a CDN announces to it
everything you look at.

It also displays, plainly, what the protocol does **not** protect. An explorer
that only shows what reassures lies by omission.

---

## The address index

"Show me all the transactions of this address" has no cheap answer in a
blockchain. Nothing in the structure links an address to its transactions: you
have to go through all of them.

Without an index, the node therefore scans backward and stops after 2,000
blocks. The answer is not wrong — it is incomplete, **and it says so**:

> **Bounded history.** Search went back to block 12400 of 14400. The balance
> shown stays exact: it comes from the set of unspent outputs, not from this
> list.

`q21 explorer` enables the index by default; `q21 node` and `q21 wallet` only
enable it if asked, with `--address-index`. An index is paid for twice, in disk
space and in writes at every block, and a node that validates the chain has no
need for it: it only searches its own addresses, and it knows which ones.
Bitcoin Core made the same decision with `txindex`, for the same reason.

### What the index makes possible, and what it costs

|  | Without index | With index |
|---|---|---|
| Address search | Last 2,000 blocks | The whole chain |
| Amounts **sent** by an address | Not resolved | Resolved |
| Search by transaction identifier | Last 2,000 blocks | Immediate |
| Balance of an address | Exact | Exact |
| Disk | nothing | a log that grows with the chain |
| First start | nothing | a full scan |

The **balance** depends on no index, and that is deliberate: it comes from the
set of unspent outputs that the node keeps up to date anyway. It stays exact
even when the displayed history is not.

### The hard half

Indexing what an address **receives** is immediate: an output carries the hash
of the key allowed to spend it.

What it **sends** is another matter. A transaction input only designates the
output it consumes — not its amount, not its owner. The witness is not enough:
the key hash depends on the signature scheme, and the scheme is written on the
output, not on the input.

The index therefore keeps a table of **unspent** outputs — the same keys as
the UTXO set, whose size depends on the economy and not on the length of the
chain. An output enters it when it is created, leaves it when it is spent, and
on the way answers the question "whose was it".

Consequence: **the index matches the chain tip exactly, or else it is rebuilt
from scratch.** Nothing in between. An index a few blocks behind would have
lost the outputs created before that gap and spent during it; the
corresponding sends would be attributed to no one, and an address's screen
would show its receipts without its sends. A wrong index cannot be seen — a
rebuilt index is paid for once.

---

## What the index guarantees despite an interruption

The log is written sequentially, one record per block, **each carrying its own
checksum**. A write cut in half — out of space, abrupt shutdown — leaves an
unreadable last record, which is ignored.

The index then restarts a few blocks back, notices that it no longer matches
the tip, and rebuilds itself. This is not vital data: the index is derived
entirely from the chain, which is the only source.

Four tests pin this behavior down in `src/index.rs`: truncated log, modified
byte, heights that jump, reorg.

---

## The token, and the fragment it shares with routing

The node requires a token on every RPC method. The launcher puts in the
**fragment** of the address — what follows the `#`, which the browser never
sends to the server — a one-time launch token; the page immediately erases it
from the address bar, exchanges it for the session token, and then sends the
latter as `Authorization: Bearer`. The link is therefore only good once —
that is deliberate, the address goes through the browser's command line,
readable by other accounts. A closed tab, on the other hand, can be reopened
as long as the program is running: the session token is stored in the
browser, partitioned by port, and dies with the process that drew it. Without
a launcher (`q21 node --rpc-token`), the page asks for the token in a field.

That same fragment is used for routing between the four views. The two never
get mixed up: **a route always starts with a slash, a token never does.**

Pleasant consequences that come for free: the browser's "back" button works,
every page has an address that can be bookmarked, and switching views requires
no request to the server — the page remains a single file, served as is.

---

## A defect found by the first user

A transaction's **Status** tile displayed this, literally, on screen:

```
<span class="badge">confirmed</span>
```

The markup had been passed to the display function without being marked as
such. That function escapes by default — **which is the right direction**, the
one that protects against injection — and so it did exactly what it was asked.

No test could catch it: the existing ones looked for the opposite defect,
markup inserted *without* escaping. You had to look the other way.

The fix is not to add the marking at that particular spot, but to provide a
function — `badge()` — that builds the label and takes care of the marking. A
test now goes through every call in both pages, balancing the parentheses, and
rejects any argument carrying an angle bracket followed by a letter without
going through `raw()`. It was checked by reintroducing the defect.

---

## What the explorer does not do

- **A transaction's fees are not displayed.** That would require resolving
  every input to know its value. The page would rather say nothing than
  display a figure it has not checked.
- **No charts.** Emission, difficulty, block size: the figures are there, the
  graphs are not.
- **It is designed for the loopback.** No rate limiting, no cache: exposing it
  publicly would require both.
- **It does not paginate.** An address displays its 100 most recent
  movements, and announces the total.
