# Join Q21 in ten minutes

This guide is written for someone who has never opened a terminal. It assumes
no prior knowledge, and it really does take ten minutes if you follow the steps
in order.

There are two ways to join the network, and the first is all that almost
everyone needs.

**Taking part** — having a wallet, and mining if you want to. Your computer
downloads the chain, checks it itself block by block, and trusts no one. That
already makes it a full node. Since version 0.2, the wallet goes a step further
without asking you anything: it also accepts connections from others and asks
your home router to open access to it, so that the network does not depend on
a single machine. Most routers do this on their own; if yours refuses, nothing
changes for you, and your wallet simply remains a client that connects out to
the network. You can see and change this setting in the wallet's Network tab.
See Part 1.

**Being an entry point** — a *bootstrap node*. A newcomer knows no one; they
need a first address to knock on. An entry point is a node that can be reached
from the outside, stays on all the time, and has a well-known address. The
network only needs a handful of entry points, run by different people, so that
it depends on no one — not even the person who wrote the program. Part 2 is
for those who want to help with that.

---

## Part 1 — Taking part

### 1. Download the right file

On the project's releases page, each release offers one archive per type of
computer:

| Your computer | File |
|---|---|
| Windows | `q21-windows-x86_64.zip` |
| Mac with Apple Silicon (M1 and later) | `q21-macos-arm64.tar.gz` |
| Intel Mac | `q21-macos-x86_64.tar.gz` |
| Linux, regular PC | `q21-linux-x86_64.tar.gz` |
| Raspberry Pi 5, ARM Linux | `q21-linux-arm64.tar.gz` |

Also download the small `SHA256SUMS` file that comes with them.

### 2. Check what you downloaded

Software that holds keys should never be installed without checking it first.
Open a command window in your downloads folder — PowerShell on Windows,
Terminal on Mac and Linux — and type the line for your computer:

```
Windows      Get-FileHash q21-windows-x86_64.zip
Mac          shasum -a 256 q21-macos-arm64.tar.gz
Linux        sha256sum q21-linux-x86_64.tar.gz
```

The string of letters and numbers it displays must be **identical** to the one
listed for that file in `SHA256SUMS`. If it differs, stop here: the file is not
the one that was published.

`SIGNING.md` explains how to also check that `SHA256SUMS` itself really was
signed by the project. It is an extra level of confidence, and it is worth
going through once.

### 3. Unzip — and know where the program will knock

Unzip the archive wherever you like — on the Desktop, in Documents. You get a
folder containing the program (`q21.exe` on Windows, `q21` everywhere else), a
launcher you double-click, a few documents, and a `q21-data` subfolder.

**There is nothing for you to do here.** This step is for reading, not doing:
the entry point is already set up, and you can skip ahead to step 4. It is here
because one day you may want to change it, and it is better to know how before
you need to.

Here is what is at stake. **The program does not contain any server address**,
and that is deliberate: an address built into distributed software would become
a permanent dependency on whoever controls it, and a protocol meant to outlive
its author should not be born with its author's address inside it. So the
address is supplied **alongside** the program, in an ordinary file that you can
read and edit. There are two such files, and that is deliberate too:
`bootstrap.txt`, placed next to the program — the one the release puts there —
and `q21-data/bootstrap.txt`, your own, which takes priority if you create it.
Open them; they explain themselves.

Why two? Because a file stored in a subfolder can get lost when an archive is
packaged, depending on the tool and the platform — this has happened, and
Windows users of one release were left without an entry point while Mac and
Linux worked fine. A file sitting at the top level survives every tool. So
losing one of them no longer leaves anyone in the dark.

The difference is not a mere formality. An address inside the program can only
be changed by redistributing the program — and so only by whoever signs it. An
address in a text file belongs to you the moment you have it: add lines,
replace them all, empty the file. The protocol does not depend on any of these
addresses; they are only used to knock on a first door. What your computer
believes after that will come from the proof of work and from the genesis block
that it computes itself.

One address per line, `host` or `host:port`. Blank lines and lines starting
with `#` are ignored. When other entry points exist, their addresses get added
here; `NETWORK.md` keeps the list up to date.

**If the file is missing** — you deleted it, or the archive was only partly
copied — the wallet will tell you so plainly when it starts, and will remind you
what to write in it. To recreate it by hand, a single line is enough, run from
the program's folder:

```
Windows      mkdir q21-data ; Set-Content q21-data\bootstrap.txt "bootstrap.q21.dev:21121"
Mac, Linux   mkdir -p q21-data && echo bootstrap.q21.dev:21121 > q21-data/bootstrap.txt
```

On Windows, Notepad sometimes adds `.txt` a second time without telling you,
which gives you `bootstrap.txt.txt` — a file the program cannot see. When you
save, choose "Save as type: All files" and type the full name. On Mac, TextEdit
must be switched to "Format → Make Plain Text" before saving, or it will produce
a rich-text document. The command line above avoids both pitfalls.

### 4. Launch

- **Windows**: double-click `Q21 Wallet.bat`.
- **Mac**: double-click `Q21 Wallet.command`.
- **Linux and Raspberry Pi**: in the Terminal, from inside the folder,
  `./q21 wallet`.

A black window opens and stays open — that is the node, so leave it alone.
Then your browser opens on a page that walks you through the rest: create a
wallet, or restore yours from its backup code. There is nothing to type in the
black window.

**Copy the backup code onto paper.** It is the only way to recover your funds
if this disk is lost — and it is all you need: on a brand-new computer, that
code alone restores your entire wallet.

Two warnings are normal the first time you launch, and both say the same thing:
no commercial certificate was bought for this program. That is true, and the
check in step 2 takes its place.

**Windows** shows a SmartScreen screen: click "More info", then "Run anyway".

**Mac** refuses to open the launcher — "from an unidentified developer" — or
offers to move it to the Trash. Don't. Open **System Settings → Privacy &
Security** and scroll all the way down: a line there says that
`Q21 Wallet.command` was blocked, with an **"Open Anyway"** button. Click it,
confirm, and you're done: the launcher itself removes the quarantine flag from
the rest of the folder, and you will never be asked again, either for the
launcher or for `q21`. On a Mac older than macOS 15, right-clicking the
launcher and choosing "Open" is enough.

If you would rather not go through System Settings at all, the Terminal does the
same thing in one line, from the unzipped folder: `xattr -dr com.apple.quarantine .`
A program signed and notarized by Apple would avoid this detour; that would
require an identity verified by Apple, and this project has chosen not to have
one.

### 5. Know that you're in

The wallet page tells you, at the top. While your node is talking to no one,
it reads **Offline** · no computer reachable. While it catches up with the
chain, **Syncing**, with the number of blocks left. Once it has caught up,
**Connected**, for example:

```
Connected · 4 peer(s) · block 1240
```

`4 peer(s)` means your node is talking to four others. As soon as it has at
least one, the page leaves **Offline**: you are on the network, and the height
climbs until it catches up with the chain. The first sync takes anywhere from
a few minutes to an hour, depending on how old the chain is. The **Network**
tab shows the count at any time, under "Computers connected to yours".

If the page stays on **Offline**, reread step 3: in almost every case, the
`bootstrap.txt` file is not in the right place, or has a different name.

The page's **Info** tab shows the version of the program you are running, and
`q21 version` gives the same answer from a command window. That is the first
thing to share if you ask for help anywhere.

### 6. Mine, if you want to

Mining means lending your computer's memory to the network, and getting paid
for every block you find. The graphics card is of no use: memory does the work,
and `MINING.md` explains why.

**On the test network — the only one that exists today — any ordinary computer
will do.** There, the miner's table starts at **32 MiB** and tops out at
**128 MiB**: an old laptop or a Raspberry Pi 4 is fine. The figures you will
read elsewhere in the project — a 2 GiB table, 8 GB of RAM — are for the
**main chain**, sized so that specialized hardware has no advantage over yours.
The test network exists to put the protocol through its paces, not to defend a
currency: it has no reason to ask for that much, and requiring a powerful
computer to take part would shut out precisely the people it needs.

Add `--mine` when launching:

- **Windows**: open `Q21 Wallet.bat` in Notepad (right-click → Edit), and
  replace the line `q21.exe wallet` with `q21.exe wallet --mine`.
- **Mac**: same thing in `Q21 Wallet.command`, using TextEdit: replace the
  line `./q21 wallet` with `./q21 wallet --mine`.
- **Linux and Raspberry Pi**: `./q21 wallet --mine`.

The first time you launch in mining mode, the program builds its table in
memory — a few seconds on the test network, and only once per 71-day period.
After that, it mines as long as the window is open, using all cores;
`--threads 2` limits how many it uses if you want to keep the computer
responsive.

The wallet's **Mine** tab shows the memory actually in use. That value is the
one to go by, not this guide: it is calculated by your own computer.

---

## Part 2 — Being an entry point

### What it takes

Three things, and none of them is technical in the way you might fear.

A **computer that stays on**: a computer you never switch off, a Raspberry Pi in
a closet, or a small server rented for a few euros a month. An entry point that
shuts down at night is not an entry point.

An **open door**: the test network talks on port `21121`. That port needs to
reach your computer from the internet. Behind a home router, this is called
*port forwarding*; on a rented server, the port is usually open from the start
or can be opened with one click.

A **known address**: you need to tell the project, so newcomers know where to
knock.

On the test network, memory is not an obstacle: a node that only verifies fits
in a **1 MiB** table, and a node that mines in **32 MiB**. A Raspberry Pi, even
an old one, can handle either. These figures grow by 5% every 71 days and top
out at 128 MiB.

On the main chain, once it exists, it will be 64 MiB to verify and 2 GiB to
mine — see `MINING.md`.

### 1. Listen

Take the launch command from Part 1 and add `--listen 21121`:

```
Windows      .\q21.exe wallet --listen 21121
Mac          ./q21 wallet --listen 21121
Linux, Pi    ./q21 wallet --listen 21121
```

Add `--mine` as well if you are also mining. On a computer without a screen — a
server, a Pi — it is better to run the node on its own, without the wallet or a
browser: `./q21 node --network testnet --listen 21121`. `SERVER.md` shows how
to make it start automatically with the computer and restart itself if it
crashes.

### 2. Open the door on your router

Every router has its own admin page, usually at `192.168.1.1` or
`192.168.1.254` in a browser, with the password printed on a label underneath
the router. Look for "Port forwarding", "NAT", or "Port redirection", and add a
rule:

- protocol **TCP**
- external port **21121**
- to your computer's local address, port **21121**

You can find your computer's local address with `ipconfig` (Windows) or
`ip a` (Linux); it looks like `192.168.1.x`. It is wise to make it fixed in the
router ("static lease" or "DHCP reservation"), otherwise it may change and the
rule will no longer lead anywhere.

Some internet providers no longer give each subscriber a public address (this
is called *CGNAT*): in that case, no port forwarding will work, and a small
rented server is the only option. `SERVER.md` describes one, from start to
finish.

### 3. Check from the outside

Don't take the router's word for it. On a port-checking website —
`yougetsignal.com/tools/open-ports`, for example — enter your public address
(the one the site itself displays) and port `21121`. It should say **open**.
Until it does, no one can get in.

### 4. Tell the project

Open an *Issue* on the repository, `github.com/rei-asanoha/Q21/issues`, with a
title such as `New entry point: 203.0.113.7:21121` — using a domain name
instead of the address if you have one, since it lasts longer. It will be added
to the list in `NETWORK.md`, and to the one that the name `bootstrap.q21.dev`
returns.

This is the step that makes the difference between a network that depends on
one person and a network that depends on no one. Five entry points, run by five
people, with five hosting providers, and the original server can shut down
without anyone noticing: those who are already in have their address book,
saved on their own disk, and no longer need to ask anyone; newcomers knock on
the others' doors.

---

## If something goes wrong

**Start here**, whatever the problem. In a command window, from the program's
folder — and **without closing the wallet**, which is the whole point:

```
Windows      .\q21.exe diagnostic
Mac, Linux   ./q21 diagnostic
```

It retraces the whole path in order — the bootstrap file, the name lookup,
opening the port, the handshake — and names the step that fails. From the home
page, a network problem always looks the same; this command, on the other hand,
tells a missing file apart from a firewall, and a firewall apart from an entry
point that is down. If you ask for help anywhere, attach its complete output.

**"No bootstrap address: this node is not looking for anyone"**, on the page —
sometimes also **"no bootstrap: this node will not look for anyone"**, in the
black window. Both mean the same thing: the `bootstrap.txt` file is not in `q21-data`, or has
a different name. It ships with the program; if it has disappeared, step 3
gives the line that recreates it.

**Offline that doesn't change, without that message** — so the node does
have an address and is really knocking, but no one answers. This is a different
problem: either the entry point is temporarily down, or your network blocks
outgoing connections to port `21121` — rare at home, common at work. To find
out which from your own computer: `Test-NetConnection bootstrap.q21.dev -Port 21121`
on Windows, `nc -vz bootstrap.q21.dev 21121` on Mac or Linux.

**Windows asks "Terminate batch job (Y/N)?"** — you pressed Ctrl-C in the
black window. The wallet has already shut down cleanly; answer whatever you
like. To close it, it is better to use the page's "Close the wallet" button.

**The port shows as closed from the outside even though the rule exists** — the
local address has changed, or the computer's own firewall is blocking it: on
Windows, the first time you launch, a window asks you to allow `q21.exe` on
private *and* public networks; check both.

## Going further

- `WALLET.md` — what the wallet protects, and how to back it up
- `MINING.md` — what your computer mines, and why an ordinary computer is
  enough
- `NETWORK.md` — the test network's entry points, and how to run one
- `SERVER.md` — a node on a rented server that restarts on its own
- `SIGNING.md` — checking that a release really comes from the project
