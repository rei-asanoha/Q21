# Intrusion audit: the public explorer

Carried out before anything went online, against a real node in public mode —
a chain of 1,224 blocks, address index enabled, loopback port, declared name
`explorer.example.org`.

The question asked was single and non-negotiable: **can a visitor do anything
other than read?**

The answer is no. It was not at the start of this audit.

---

## What was found, and fixed

Five findings. None allowed funds to be moved — the architecture already took
care of that — but four opened a door that had no reason to exist, and one
made the service trivially unusable.

### 1 · The wallet page was served publicly — fixed

`https://explorer.example.org/wallet` returned **200** and displayed the full
Q21 wallet interface.

It could not move anything: the published node has no wallet, and all the
corresponding methods are refused. But it is the exact set for a phishing
attack, **staged by us, on the project's official domain**. A visitor sees an
authentic interface there and gets into the habit of typing things into a
website — precisely what a Q21 holder must never learn to do.

A surface that serves no purpose gets removed: these paths now return **404**
in public mode, and the front web server blocks them too.

### 2 · Beyond 64 headers, the rest became the body — fixed

The parser stopped at the limit **without saying anything**, and reading the
body resumed where it had left off: the excess headers silently became the
start of the body.

No leak followed — connections close after each response — but a request
whose splitting depends on the sender is the definition of *request
smuggling*, and this tolerance would become a flaw the day connection reuse
was added. Exceeding the limit is now a refusal, `400`.

### 3 · A duplicate `Host` got through depending on the order — fixed

`Host: evil.example` followed by `Host: explorer.example.org` was **accepted**:
the table keeps the last value, whereas an intermediary reads the first. Two
machines that do not read the same value for the same field is exactly what
request smuggling exploits.

No browser sends two, and the standard forbids it. The refusal is now
explicit, `400`, **whatever the order**.

### 4 · A request without `Host` was served — fixed

A published service answers only under the name it has been given. A missing
`Host` header now returns `403` in public mode. Locally, the tolerance
remains: there the guard protects against a browser, and a browser always
sends this header.

### 5 · Slowloris made the service unavailable — fixed by the architecture

Two hundred connections opened and **never completed** saturated the server's
sixty-four threads. During the attack, every other visitor received `503`.
Reproduced in two lines of Python.

A one-thread-per-connection server cannot win against this attack on its own:
the countermeasure belongs to the front web server, designed to hold thousands
of slow connections, and which only opens a connection to the node once the
request is complete.

The fix is therefore twofold, and structural:

- **The node refuses to start in public mode anywhere other than on the
  loopback.** This is no longer a recommendation in a document: it is a
  refusal by the program.
- **The front web server enforces `read_header 5s`**, which cuts a silent
  connection before it costs anything.

---

## What held, and did not need fixing

### Methods that would modify something

Eleven methods tried, eleven refusals — including `stop`, which would shut the
server down:

```
stop, sendtoaddress, getnewaddress, setmining, setaddresslabel,
getbalance, listtransactions, preparesend, getwalletinfo,
listaddresses, estimatefee
    -> "wallet methods disabled. They can move funds and must be requested explicitly at startup."
```

And the safeguard is upstream: **the binary refuses to start in public mode if
a wallet is served**, with a message that says how to do it differently.

### DNS rebinding

Seven hostile `Host` headers, seven refusals — including
`explorer.example.org.evil.example`, the kind of substring that fools a lazy
comparison.

Five third-party origins, five refusals — including `null`,
`https://evil.example/#explorer.example.org`, and the **plain-HTTP** origin of
the legitimate name.

### Paths

Directory traversal (`/../../etc/passwd`, encoded or not), `/.git/config`,
`/wallet.dat`: **404**, no leak. Seven unexpected HTTP verbs: **404**.

### The JSON parser

Nesting of 100,000 levels, an object of 50,000 braces, a 4,000-digit number, a
500,000-character identifier, broken Unicode, `NaN`, duplicate keys: each case
answers in under a hundredth of a second, with no notable resource use, and
the node stays alive.

**Duplicate keys** are rejected as an unreadable document — the right
behavior: `{"method":"getinfo","method":"stop"}` should not have to choose.

### Batch amplification

Bounded by a previous audit, and checked again: 101 calls in a batch are
refused, 5,000 too, and the cumulative size of the responses is capped.

### Computation cost

On a 1,224-block chain, with the index:

| Method | Median time |
|---|---:|
| `getinfo` | 0.3 ms |
| `getblock` | 0.2 ms |
| `gettransaction` (unknown) | 3.3 ms |
| `search` | 0.2 ms |
| `getsecurity` | 0.1 ms |

The most expensive — looking up a transaction that does not exist — costs
3 ms for 143 bytes sent. The amplification exists but remains modest; it will
be reassessed once the chain has grown, because this cost increases with the
height.

### Size bounds

2 MiB body: refused. Lying `Content-Length` in both directions: refused or
without effect. 20 KiB request line: refused. 20 KiB header: refused.
Carriage-return injection in a header value: without effect, no forged header
in the response.

### Response headers

Already in place, and checked: `Content-Security-Policy: default-src 'none'`,
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`.

### Trust in the front server

`X-Forwarded-Host: explorer.example.org` with `Host: evil.example` is
**refused**. The node trusts no rewritten header — which is the right rule
when the front server is the only one able to set them.

---

## What remains, and is accepted

**Saturation by volume.** Anyone can request blocks in a loop. On a test
network, that is acceptable and even instructive: it is a measurement we want.
The front web server can rate-limit per address if this becomes a nuisance;
it is not enabled today, for lack of knowing at what threshold.

**Cost that grows with the chain.** `gettransaction` on an unknown identifier
scans a window of blocks. At 1,224 blocks it costs 3 ms; at a million, an index
or a bound will be needed. This is noted as debt, not as a flaw.

**What the explorer reveals is what it must reveal**: height, blocks,
transactions, difficulty, emission. An explorer that hid the chain would make
no sense. The number of peers is returned **without their addresses** — which
was checked, and is the right compromise.

---

## The tests that guard these fixes

New tests, in `src/http.rs`, that fail if one of the doors reopens:

- the declared name is accepted, another is not, including one that contains
  it;
- the declared origin is accepted, a third-party or plain-HTTP origin is not;
- `Content-Type` is still required in public mode;
- a duplicate `Host` is refused in both orders;
- a request without `Host` is refused in public mode;
- public mode refuses to listen outside the loopback;
- too many headers is a refusal, not a reinterpretation.

They run on every release.

---

## Second pass: attack simulations, in more depth

Taken up again afterwards, with just one more question: **if a text chosen by
a stranger ever reached the page, would it stay inert?** And a second surface,
never tested until then: **the public peer-to-peer port**.

### What the chain can inject — nothing, today

The only field of a block that a stranger fills in as they please is the
message of the reward transaction. We checked, raw response in hand, that **no
explorer method exposes it**: neither `getblock` nor `gettransaction` returns
it. Everything the page displays is hexadecimal, a number or a bech32 address
— three alphabets without a single active character.

Every value that does cross the page goes through a single escaping function,
and error messages are set via `textContent`, never as HTML. Each page carries
**only one** script, the one we wrote, and **no** inline handler.

### Hardening anyway: a nonce per response

A door closed today can reopen the day a field is added without thinking about
it. The content security policy said `script-src 'unsafe-inline'` — so it
allowed any inline script, including a script slipped into the page. It now
carries a **nonce drawn at random for each response**, written on the
`<script>` tag and in the header. The browser executes only that script; an
injected script does not have the nonce, and stays dead. Two pages served back
to back do not have the same nonce: it cannot be guessed. Without secure
randomness, the page goes out with a policy that forbids **any** script — the
right failure.

Five new tests guard this point: the nonce differs from one response to the
next, the tag carries the one from the header, a JSON response allows no
script, and `'unsafe-inline'` does not come back into the policy.

### The peer-to-peer port, tested for the first time

It is the first thing a byte from a stranger touches, and it is public.
**1,930 malformed frames** were sent to it: purely random bytes, the right
magic with an unknown command, known commands with absurd payloads, headers
announcing four billion elements, frames truncated then cut off abruptly,
wrong checksums, nonzero padding, byte-by-byte sending then abandonment.

The node **absorbed everything without a single panic**, memory stable at
4.5 MiB, and it was still answering normally at the end. That is the promise
written at the top of the protocol file — *no allocation before checking, no
panic* — kept under test.

### The three batteries, replayed against the new version

The batteries from the first pass — path traversal, DNS rebinding, methods
that would modify something, size bounds, JSON parser, batch amplification,
cost per request, Slowloris — were **replayed identically** against the nonce
version. Same verdict: every door holds. The only residue remains the same,
and it is accepted: two hundred silent connections saturate a
one-thread-per-connection server. The countermeasure is not in the node — it
is in the front web server, and in the node's refusal to expose itself
anywhere other than on the loopback. Both are in place.

**Verdict of the second pass: nothing new to fix in substance, one notch of
hardening added out of caution.** The vault holds.
