# Mining Q21, explained simply

This document is for someone who has never mined and does not want to learn
computing to get started. No prior knowledge is assumed. The figures it
contains were **measured**, except those marked as estimates — and they are
marked.

---

## 1 · What is mining?

Every two minutes, someone in the network writes a new page of Q21's big
ledger. This page is called a **block**: it contains the transfers people
have made to each other since the previous page.

The question is: **who gets to write the page?**

If anyone could, anyone could lie. So a contest is organized. Everyone who
wants to write the page searches at the same time for the answer to a puzzle.
The first to find it writes the page — and receives brand-new Q21 as a
reward.

**Mining is taking part in this contest.** Nothing more. Your computer
searches, over and over, for the answer to the current puzzle.

Two things follow from this, and they matter:

- **You do not win every time.** You win sometimes. The faster your machine
  searches, the more often you win — but it is chance, like a lottery where
  you keep buying tickets.
- **The winner cannot cheat.** Writing a false page is pointless: all the
  other machines check it and reject it. Winning the contest gives the right
  to write a **true** page, not just any page.

---

## 2 · Why Q21 does not do what Bitcoin does

This is the heart of the project, so let us take our time.

### Bitcoin's puzzle is pure computation

With Bitcoin, the puzzle is a giant mental arithmetic exercise: trying
numbers, one by one, until a good one is found. Nothing to remember, nothing
to go and fetch. Just compute, very fast.

The problem is that **a machine can be built to do nothing but that**. It is
called an ASIC: a chip that can do only one computation, but does it about
**a hundred million times faster** than a normal computer.

The result is well known: in 2009 people mined Bitcoin on their laptops; in
2026 it takes an air-conditioned warehouse, thousands of specialized machines
and an industrial electricity contract. The individual has been pushed out.
Not by a decision, by the physics of the contest.

### Q21's puzzle is a hunt through a dictionary

Q21 changes the nature of the puzzle.

> **Imagine a two-gigabyte dictionary** — about 67 million pages. To try your
> luck once, computing is not enough: you have to **fetch pages at random
> from this dictionary**, several times in a row, and each page tells you
> which one to look up next.

The computation itself is fast. What takes time is **fetching the pages**.
And there, something changes completely:

- A specialized chip cannot fetch a page any faster. Fetching data from
  memory takes the same time for everyone. It is a physical limit, not a
  question of how fine the chip's process is.
- To be fast, the chip would have to **carry the entire dictionary**. Two
  gigabytes of fast memory on a chip is very expensive — and at that point,
  the manufacturer has essentially built… a normal computer.

This is what is called a **"memory-hard"** proof of work. Ethereum used the
same principle for seven years, and it worked: people mined it on ordinary
graphics cards right up to the end.

### And the dictionary grows

A last defense, and it is automatic: **about every 71 days, the dictionary
grows by 5%.** It starts at 2 gigabytes and rises to 4, reached around the
third year.

A specialized machine is designed around a fixed amount of memory. When the
dictionary exceeds that amount, the machine becomes bad — on its own,
without anyone deciding anything.

> Monero, another currency, had to put itself through four emergency rule
> changes between 2018 and 2019 to drive out the specialized machines that
> were arriving. Here, it is planned from the start and happens without
> intervention.

### The two-level trick

A clever miner might say: "I won't keep the dictionary, I'll recompute each
page when I need it — I'll save 2 gigabytes".

Q21 makes that a losing calculation. The dictionary is made from a **small
64-megabyte notebook**, and rebuilding **a single page** of the dictionary
requires looking up the notebook **256 times**.

So whoever wants to save memory multiplies their work by 256. They save
nothing: they pay differently, and more.

---

## 3 · What you need, concretely

### The software

**The same as the wallet.** There is no separate mining software to
download, no configuration to write, no "pool" to sign up with. The Q21
wallet mines.

*(The **Mine** tab of the wallet page turns it on and off without restarting
anything, and shows the rate, the blocks found and the memory actually in
use. The `--mine` option at launch remains available for a machine without a
screen.)*

### The machine

> **The figures in this section are those of the main chain**, the only one
> for which the size of the table matters: it is sized so that a specialized
> machine has no advantage over an ordinary computer.
>
> On the **testnet** — the only network open today — the table starts at
> 32 MiB and caps at 128 MiB. Any machine can mine there, including an old
> Raspberry Pi. A testnet is there to put the protocol to the test, not to
> defend a currency; imposing the requirements of the main chain on it would
> only keep participants away.

| What you need | Detail |
|---|---|
| **Any PC or Mac** | Desktop or laptop, Windows, macOS or Linux |
| **At least 4 GB of RAM** | 8 GB is comfortable. The dictionary is what eats it |
| **No graphics card** | It is useless here. Memory does the work |
| **An ordinary internet connection** | The traffic is modest |

That is all. No hardware to buy, no dedicated machine. The computer you are
reading this page on is probably fine.

> ⚠️ **Plan memory for the future.** The dictionary grows by 5% every 71 days
> and **caps at 4 GB**, reached around the third year. A machine with 8 GB of
> RAM is therefore enough forever. A machine that does not mine, on the other
> hand, will only ever need the small notebook — 64 MB today, 128 MB at most.
>
> | When | Dictionary size |
> |---|---|
> | at launch | 2.0 GB |
> | after 1 year | 2.6 GB |
> | after 2 years | 3.3 GB |
> | from 3 years on | 4.0 GB — and never more |

### Can my machine mine? Case by case

| The machine | Does it mine? | Why |
|---|---|---|
| **Desktop PC, Windows 10 or 11** | ✅ yes | The normal case. The more cores, the better |
| **Windows laptop** | ✅ yes | See the caveat on laptops below |
| **Apple Silicon Mac (M1 and later)** | ✅ yes | Very fast unified memory: good hardware for this |
| **Intel Mac** | ✅ yes | A binary is built for it |
| **PC running Linux** | ✅ yes | Binary `q21-linux-x86_64` |
| **Raspberry Pi 5, 16 GB** | ⚠️ yes, but slowly | See below |
| **Raspberry Pi 5, 8 GB** | ⚠️ yes, but slowly | 4 GB of table, 4 GB for the rest: it fits, forever |
| **Raspberry Pi 5, 4 GB or less** | ❌ no | The table alone fills all the memory |
| **Raspberry Pi 4 or earlier** | ❌ no | 8 GB at most, and far too slow memory |
| **Windows XP, Vista, 7, 8** | ❌ no | Two reasons, both final — see below |
| **A phone** | ❌ no | Neither the memory, nor the cooling, nor the system's permission |

### Windows XP: no, and it is not a matter of goodwill

Two independent reasons, each of which would be enough.

**The language.** Q21 is written in Rust, and Rust requires **Windows 10 at
minimum** for its official Windows targets. Windows 7 and 8 lost support in
2024; XP lost it much longer ago. There is therefore no simple way to produce
a `q21.exe` that would start on XP.

**Memory.** XP is, in practice, a 32-bit system: a program there has only
2 GB of address space, sometimes 3. Q21's table needs **2 GB on its own**,
and will go up to 4. Even rewriting everything, it does not fit. It is not a
problem of system version, it is a problem of arithmetic.

A machine from the XP era can, on the other hand, perfectly well take a
recent 64-bit Linux — and then, if it has enough memory, it mines.

### The Raspberry Pi: yes, and it is interesting

Since this version, a **`q21-linux-arm64`** binary is built with every
release, on a real ARM machine. A 16 GB Raspberry Pi 5 can therefore mine
without compiling anything.

But let us be precise about what to expect:

- **Its memory is slow.** The Pi 5 uses LPDDR4X on a narrow bus — a few
  gigabytes per second, where a recent desktop PC does ten times more. And
  that is exactly the resource the puzzle consumes. A Pi will therefore mine,
  but **several times slower** than an ordinary PC.
- **8 GB is enough, forever.** The table caps at 4 GiB from the third year,
  which leaves as much for the system and everything else.
- **Its SD card is not infinite.** Start it with **`--prune`**: the disk then
  keeps only the last eight days of blocks, and the rest is summarized in a
  snapshot. The node still verifies everything; it simply does not keep what
  it will never read again. An explorer, on the other hand, must keep
  everything — that is the server's role, not the Pi's.
- **On the other hand, for running a node that does not mine, a Pi is
  perfect**, and will stay so: a verifier only ever needs the small notebook,
  128 MB at most, forever.

This is in fact the best use of a Pi in this network: a permanent, silent
verification point, at three watts.

### The laptop: yes, with a caveat

A laptop mines very well. Three things to know:

- **It will heat up and spin its fans.** It is noisy, and it wears the
  machine faster than quiet office work.
- **It will throttle.** A laptop lowers its frequency when it heats up. The
  rate shown after ten minutes is the real one, not the one from the first
  minute.
- **Closing the lid puts the machine to sleep**, and mining stops. That is
  normal. *(This action had also revealed a real defect in the protocol, now
  fixed — see `NETWORK.md`.)*

### The first startup is slow, and that is normal

On the very first launch, the program **builds the dictionary**. This takes
several minutes, during which it seems to do nothing.

Measured on a modest machine with **2 cores**:

| Step | Time |
|---|---|
| Build the small notebook (64 MB) | **12 seconds** |
| Build the dictionary (2 GB) | **9 minutes 43** |

On a recent desktop computer with 8 cores, count rather on **two to three
minutes**. And it is only redone **once every 71 days**, when the dictionary
changes.

---

## 4 · How much does it earn?

### What is distributed

The network creates **13.82 Q21 per block** at the start, and a block comes
every two minutes. That is about **9,955 Q21 per day**, for the whole world.

This reward decreases continuously: it is multiplied by 0.9971555 about every
6 days. No sudden halving as with Bitcoin — a smooth decay, every six days,
up to the limit of **21,000,001** units.

### What you receive

**Your share is your machine's power divided by the power of the whole
network.** Nothing else.

If ten people mine with comparable machines, each receives about a tenth. If
a thousand people join in, each receives a thousandth — the total reward
itself does not change.

That is the only honest thing that can be said today, because **nobody knows
how many people will mine**. Any promise of a figure for returns would be an
invention.

### The difficulty adjusts

If many machines arrive, the puzzle automatically becomes harder, so that
blocks keep coming every two minutes. If machines leave, it becomes easier
again.

Consequence: **you cannot speed up the network by buying hardware.** You can
only increase *your own share* of the pie.

---

## 5 · How to increase your power

In order of real effectiveness:

| What helps | Why |
|---|---|
| **More processor cores** | The program uses them all. Twice as many cores ≈ twice as many attempts |
| **Faster memory** | The puzzle spends its time reading memory. That is the real bottleneck |
| **A second machine** | An old laptop lying around counts as much as half of a new one |
| **Running longer** | Mining 24 h earns 24 times more than mining 1 h |

### Memory: how much, and how fast?

This is the question that always comes up, so let us answer in order.

**How much memory do you need?** It is not a fixed figure: the dictionary
grows by 5% every 71 days, up to a cap of 4 GiB.

| When | The dictionary weighs | RAM to have |
|---|---:|---|
| Today | 2.0 GiB | 4 GB fits, 8 GB is comfortable |
| From 3 years on | 4.0 GiB (cap) | **8 GB, permanently** |

In other words: **if you buy a machine to mine for the long haul, take 8 GB
and forget about it.** The 4 GiB cap is reached around the third year and
never moves again; 8 GB of RAM therefore covers the whole life of the
network, dictionary plus system.

**Do you need many memory sticks?** No — you need **two**, and it matters
more than you might think.

Desktop processors read memory through two channels in parallel. With a
single stick, only one channel works and half the bandwidth is lost. With
two identical sticks, both channels work.

> **Two 8 GB sticks are better than a single 16 GB one**, for the same amount
> and at a comparable price. It is the most cost-effective advice on this
> page.

Beyond two, you gain almost nothing: consumer machines have only two
channels, and filling all four slots often forces the memory to run *slower*.
Two sticks is the right count.

**Does speed matter?** Yes, and it is probably the most important variable
after the number of cores.

Q21's whole design rests on the fact that the puzzle **waits for memory**
rather than computing. Fast DDR5 should therefore beat slow DDR4, with the
same processor. Two technical details, for those who want them: **latency**
weighs the most (the time to fetch *one* piece of data at random), ahead of
**bandwidth** (the total amount per second).

> ⚠️ **This is a prediction, not a measurement.** The exact effect of memory
> speed on Q21's mining rate has never been measured: it would take the same
> machine with two different sets of sticks, which the current test machine
> does not allow. What is measured is the rate per core (84,053 attempts/s);
> what is deduced from the design is that memory is in charge.
>
> If you have two sets of sticks at hand, running
> `cargo run --release --example mining_bench` with one and then the other
> would produce the first real figure on the question. That would be a useful
> contribution.

And what **does not help**, contrary to intuition:

- **A graphics card.** It is designed to compute a lot in parallel, not to
  fetch pages at random from a large dictionary.
- **A very fast SSD.** The dictionary lives in RAM, not on the disk.
- **Buying a specialized mining machine.** None exists for Q21, and the whole
  design aims for none ever to exist.

### What it gives, measured

On the 2-core test machine:

```
  84,053 attempts per second per core
 191,715 attempts per second on the 2 cores
```

A desktop computer with 8 cores would therefore do around **700,000 attempts
per second** — four times more, for a machine costing a few hundred euros,
not a few tens of thousands.

*(These measurements come from `cargo run --release --example mining_bench`,
which anyone can run again on their own machine.)*

---

## 6 · What it costs in electricity

Mining means running your processor flat out, continuously. The expense is
therefore electricity — and nothing else, since there is no hardware to buy.

**Estimates** — not measurements, because power draw depends on your
machine:

| Machine | Power under load | Per month, 24/7 | Monthly cost (€0.25/kWh) |
|---|---|---|---|
| Ordinary laptop | ~35 W | ~25 kWh | **~€6** |
| Desktop PC | ~100 W | ~72 kWh | **~€18** |
| Large desktop PC | ~200 W | ~144 kWh | **~€36** |

For comparison, a current Bitcoin mining machine draws about **3,500 W** —
thirty-five times the desktop PC above, on its own. And it takes thousands of
them to carry any weight.

A few honest remarks:

- **Mining produces heat.** In winter, that heat replaces a little heating.
  In summer, it adds to the heat of the room.
- **The fan will run.** A laptop that mines is a noisy laptop.
- **Nothing forces you to mine continuously.** Mining during the day and
  stopping at night works perfectly; you simply win half as often.

---

## 7 · What to know before starting

### No Q21 has any value, and none ever will

The current network is a **testnet**. It can be reset at any time. What is
mined on it is neither a currency, nor an investment, nor an asset.

Anyone who offers to buy, sell or exchange Q21 today is deceiving you.

### The proof of work has not been reviewed by outside experts

This is the most important point of this document, and it is uncomfortable.

Everything explained in section 2 — the resistance to specialized machines —
rests on measurements made **by the author of the program, on their own
machine**, against their own implementation. Nobody whose job it is has yet
tried to break it.

Designing a proof of work is an exercise in which it is easy to be wrong, and
this project has already been wrong once: a first version showed reassuring
results… because it was measured on a dictionary too small to reveal the
flaw. Once corrected, the measurement revealed that doing entirely without
memory cost only 2.86 times more — far too little. It is the two-level
construction described above that raised this cost to 47.8 times.

**So: Q21's ASIC resistance is a supported hypothesis, not an established
fact.** Opening the public testnet is also an invitation to come and break
it.

### Mining puts your funds at no risk

The program that mines is the same one that holds your wallet, on your
machine, and your keys never leave it. Mining exposes nothing more than
running the wallet.

On the other hand, **your antivirus may complain**. Many antivirus programs
flag any mining software as suspicious, on principle, without distinguishing
the one you started on purpose from one an intruder installed without your
knowledge. It is not the sign of a problem — it is the sign of an antivirus
doing its job with a crude rule.

---

## 8 · Summary in ten lines

1. Mining is having your computer search for the answer to a puzzle.
2. The winner writes the next page of the ledger and receives new Q21.
3. With Bitcoin, the puzzle is pure computation — specialized machines took
   everything.
4. With Q21, it forces a search through a 2 GB dictionary in memory.
5. Fetching data from memory takes the same time for everyone: that is what
   protects the individual.
6. The dictionary grows by 5% every 71 days, which makes dedicated hardware
   obsolete on its own.
7. You need: an ordinary PC or Mac, 4 GB of memory, the Q21 wallet.
8. The first startup takes a few minutes — it builds the dictionary.
9. The cost is electricity: between €6 and €36 per month depending on the
   machine.
10. None of this has any value today, and the ASIC resistance still has to be
    checked by others.

---

*For the technical details: [WHITEPAPER.md](WHITEPAPER.md) section 5, and
`src/memhard.rs`, which itself carries the warning of section 7.*
