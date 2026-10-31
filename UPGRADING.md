# Updating your wallet

Five minutes. No commands.

---

## 1 · Pour the new content **into** the existing folder

> ### ⚠ Never delete the `Q21` folder itself
>
> It contains a **hidden** subfolder named `.git`. That `.git` **is** the
> repository: it is what knows the history and the link to GitHub. This
> archive does not contain one — on purpose, because a second `.git` would
> cause the "unrelated histories" error.
>
> Deleting the folder to put the archive's folder in its place therefore
> destroys the repository, and GitHub Desktop displays **"Can't find Q21"**.
>
> You **pour** the new content into it. You do not replace the container.

You downloaded `q21-repo.zip`. Unzip it: you get a `q21` folder.

1. In GitHub Desktop: **Repository** menu → **Show in Explorer**
   → File Explorer opens on your repository folder
2. Open the `q21` folder that came from the archive, in **another** window
3. Inside it: `Ctrl` + `A` (select all), then `Ctrl` + `C`
4. Go back to the repository window: `Ctrl` + `V`
5. Windows asks what to do → **Replace the files in the destination**

Go back to GitHub Desktop: it shows the modified files in the *Changes* tab.

> **If GitHub Desktop already displays "Can't find Q21"** — the folder has been
> deleted. Click **Clone Again**: GitHub Desktop downloads the repository again
> from your account, with its `.git`. Then pick up again at step 2 above.
>
> If a `Q21` folder still exists at that location without being a repository,
> rename it to `Q21-old` before clicking **Clone Again**, then delete it once
> the operation is finished.

---

## 2 · Push to GitHub

At the bottom left, in the **Summary** field, write:

```
Explorer: search, blocks, transactions, addresses
```

Click **Commit to main**, then **Push origin** at the top.

---

## 3 · Run the build again

On `github.com/rei-asanoha/Q21`:

**Actions** → **Release** (left column) → **Run workflow** ▾ → green **Run workflow** button

Ten to twenty minutes. Then download, at the bottom of the page,
`q21-windows-x86_64.zip` **and** `SHA256SUMS-signed`, and check the signature
before installing — the steps are in [SIGNING.md](SIGNING.md), section 4. A
red run, or a trusted comment that does not say `Q21 main <commit hash>`, is a
file you do not install.

---

# Upgrading from 0.5.3 to 0.5.4

0.5.4 schedules one new rule of the chain on the testnet: from **block
7,600**, a block's timestamp must be strictly later than its parent's. It is
a stricter rule (a soft fork): an older node keeps following the chain, but
a miner still on an older release may produce blocks every 0.5.4 node
refuses. **Every node that mines must run 0.5.4 before block 7,600**; run it
everywhere, servers included.

The rest of the testnet schedule is unchanged: payment channels open since
block 4,980, names since block 5,200.

## What changes

| | 0.5.3 | 0.5.4 |
|---|---|---|
| Block timestamps | After the median of the eleven blocks before: a minority miner could date its blocks back and slow the chain (a third of the hashrate: more than eighteen minutes per block) | From block 7,600, also strictly after the parent's: the same miner keeps the chain within about a tenth of two minutes. The node's own blocks follow the rule even when its clock lags behind the tip |
| A new node | A peer alone with a new node for its first hour could bind it to a chain of its own | The release carries anchors, blocks of the real chain: no chain without them can pass their heights, and finality never binds below the last one |
| `getinfo` | — | `block_time_rule`: the activation height, whether the next block is under the rule, and the last anchored height |
| Peers | — | A block refused only by the new rule costs the peer that relayed it nothing: it may still run 0.5.3 |
| Private channel | The opening explained twice; an unreachable other side read "peer is not connected" next to a Pay button | Explained once; an unreachable other side is said plainly, with a **Connect again** button and no Pay button until it is back |

## Who should upgrade, and when

Everyone, before block 7,600: entry points, explorers, servers, wallets.
Mining nodes first. A node that never mines and stays on 0.5.3 keeps
following the chain, but should upgrade too.

## How to check a node

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{}}' \
  http://127.0.0.1:21080/rpc | grep -o '"block_time_rule":{[^}]*}'
```

A 0.5.4 node answers with `"activation_height":7600`; a 0.5.3 node prints
nothing.

## The data folder

Nothing changes in it. Going back to 0.5.3 is possible before block 7,600;
after it, a 0.5.3 node that mines may build blocks the others refuse.

---

# Upgrading from 0.5.1 or 0.5.2 to 0.5.3

0.5.3 changes no rule of the chain and no message of the protocol: a 0.5.3
node agrees with 0.5.1 and 0.5.2 nodes on every block, and keeps its payment
channels with them. It reworks the wallet's channel tab and makes the funds in
a channel, and every fee, safer.

The testnet schedule is unchanged: payment channels open since block 4,980,
names since block 5,200.

## What changes

| | 0.5.2 | 0.5.3 |
|---|---|---|
| The channel tab | Called **Links**: contact cards, then forms and tables below | Called **Private channel**. Your names on top (up to three, an empty place offers to take one), the three steps, then your contacts on the left and, on the right, the channel with the one you choose: what you can send, what they can send you, what is in the channel, Pay, the payments made in it, Close |
| Archives | The links closed since the wallet was opened, gone at the next start | Every closed channel, kept for good: when it closed, with whom, what you put in, what you paid or received, what came back. Folded behind an arrow, sorted by month and year |
| A data folder restored from an older copy | A channel in it could broadcast a state it had already revoked, and lose the whole channel to the other side | The older copy is recognized when the two sides reconnect. It refuses to pay or to close, and says why; the other side, which holds the latest state, closes the channel once a second connection confirms it, and the restored side gets its latest balance back |
| Close without the other side | The lowest fee: in a busy network the close could wait for days, and it cannot be bumped | The highest fee tier, so that it gets through, shown in the confirmation before you decide |
| The other side's delay | An acceptor took any delay the funder proposed within the network's range | An acceptor takes no less than its own default: the delay is how long it may stay offline and still answer an old state |
| Fees | Estimated from the median of the waiting transactions, which a few large ones could inflate | Estimated from what the next block takes, and capped. Registering a name, gathering small coins and bringing back what sits on your identity address show their fee first; the fee you confirm is the most the node may take, change too small to keep included |
| The backup code | Shown as one long line; the check asked for the whole code | Shown in numbered groups of four; the check asks for three groups. **Info → Check my backup** says whether the code on your sheet restores this wallet, and where a single slip is |
| A wallet restored from its backup code alone | Funds a channel close paid to the channel's key stayed there | Claimed back to the balance automatically |
| A late clock | Blocks refused in silence | A banner says this computer's clock seems late, with the gap observed |

## Who should upgrade, and when

Anyone with a wallet, and both sides of a channel: the protection against an
older copy works best when both run 0.5.3. A node that only runs as a server
(entry point, explorer) gains little and can stay on 0.5.1 or 0.5.2.

## The data folder

0.5.3 writes a few small files beside each channel's journal in the
`channels` folder: the date and height it closed at, how it ended, its
payments, and the identity of the person it is with. They are only read for
the page; the channel's funds never depend on them. A channel accepted under
0.5.3 uses a key from a new range, so that a wallet restored from its backup
code finds it again. Going back to 0.5.2 is possible, but close the channels
opened toward you under 0.5.3 first.

---

# Upgrading from 0.5.1 to 0.5.2

0.5.2 changes the wallet page only: no rule of the chain, no message of the
protocol, nothing in the data folder. A 0.5.1 node and a 0.5.2 node agree on
every block and talk to each other as before.

The testnet schedule is unchanged: payment channels open since block 4,980,
names since block 5,200.

## What changes

| | 0.5.1 | 0.5.2 |
|---|---|---|
| The Channels tab | Called Channels; forms side by side, with the contacts as a table | Called **Links**, in three steps: find someone by their name, check together with words read aloud, pay. Each contact is a card with its one next step: connect, check with words, create a quick link, pay |
| Finding someone | A name typed in the "add a contact" form, without seeing first who it belongs to | A search box: the name is looked up on the chain first, then added in one click. Your own names are shown with a copy button, to give them to others |
| Closed links | Stayed in the list with the open ones | Move to a folded **Archives** section once their funds are back. A link whose penalty is not yet confirmed stays in the list until it is |
| Verification words | A second verification on the same connection showed nothing; the words were at the top of a page often scrolled away | Every verification shows, the second one too. The words sit in a panel that stays in view, on every tab; "Later" puts it aside without concluding anything |
| Activity: change | On a payment, the change coming back read as money received (`+ 9.62` after a name registration) | The change is grey, labelled "change back", under Received. Sent is what really left the wallet, fees included |
| Activity: reference | The hash broken over a dozen lines | Its beginning and end on one line; the whole hash in the tooltip and in the copy button |

## Who should upgrade, and when

Anyone who uses the wallet page, whenever convenient. A node that only runs
as a server (entry point, explorer) gains nothing and can stay on 0.5.1.

---

# Upgrading from 0.5.0 to 0.5.1

0.5.1 changes no rule of the chain and no message of the protocol: a 0.5.0
node and a 0.5.1 node agree on every block and talk to each other as before.
It hardens what a stranger could do to a node, how a new node finds the real
chain, and how a release reaches you.

The testnet schedule is unchanged: payment channels open since block 4,980,
names since block 5,200.

## What changes

| | 0.5.0 | 0.5.1 |
|---|---|---|
| Ping | Answered at once, always, even before the handshake, past the reply queue's cap: one connection sending pings and reading slowly took a node's memory from a few megabytes to gigabytes | Answered only after the handshake, eight at once then one per second, as an ordinary reply |
| Inbound slots | Full meant full: whoever held the 24 inbound slots kept them, and newcomers were refused | A full node lets its most recent inbound peer go to make room. The four peers that most recently brought a block or a transaction the node kept, and the eight connected longest, are never chosen. Connections through Tor, which all arrive from `127.0.0.1`, hold at most 12 of the 24 slots |
| A new node's first hour | Rolling finality (720 blocks) bound a node from its first block: a first peer handing it a cheap chain of its own could lock it there for good | A new node follows the chain with the most work until its tip has been recent for an hour; then finality binds it for good, recorded in `finality.dat`. While it catches up, a block forking that deep is taken only from a peer it dialed itself, a limited number from each. See NETWORK.md, "A new node's first hour" |
| Penalties | A block refused for the node's own state — its finality, its undo window, its clock, its pruned history — cost the sender half its score: honest peers were banned | Such refusals cost nothing |
| Serving blocks | Each request bounded, not their rate | Every peer has a budget across requests: 32 MiB at once, then 4 MiB per second. A request beyond it waits, it is not dropped |
| Public explorer | `getpeers` listed every peer's address | With `--rpc-public`, `getpeers` gives `null` for the address and the channel identities |
| Counters | — | `getinfo` → `network_stats` gives `inbound_evicted`, `getdata_throttled` and `deep_forks_ignored` |
| Releases | Signed by a key kept in GitHub | Signed offline; a release is created as a draft and made public only once `tools/verify-release.sh` has checked it: signature, every archive, the program inside each, every other file against the tagged commit, and the independent attestations required (`attestations/threshold`). You can run the same script at home. See SIGNING.md |
| Service files | No memory or task ceiling | The examples in SERVER.md, NETWORK.md and HARDENING.md set `MemoryHigh=1536M`, `MemoryMax=2G`, `TasksMax=512`, `LimitNOFILE=4096` |

## Who should upgrade, and when

Everyone, in any order: entry points and public explorers first, since they
are the ones strangers reach. Nothing breaks while some nodes still run
0.5.0.

## The data folder

0.5.1 writes one small file, `finality.dat`, with one word: `bound` or
`catching-up`. A data folder that already followed the chain — more than 720
blocks — is `bound` at the first start of 0.5.1, so an existing node keeps
its finality exactly as before. A new folder starts `catching-up` and becomes
`bound` after its first hour at a recent tip. Going back to 0.5.0 ignores the
file.

## For operators: the service file

On a server started by systemd, add the ceilings to the existing service
without editing it:

```bash
sudo mkdir -p /etc/systemd/system/q21.service.d
sudo tee /etc/systemd/system/q21.service.d/limits.conf > /dev/null <<'EOF'
[Service]
MemoryHigh=1536M
MemoryMax=2G
TasksMax=512
LimitNOFILE=4096
EOF
sudo systemctl daemon-reload
systemctl show q21 -p MemoryMax -p TasksMax
```

→ `MemoryMax=2147483648` and `TasksMax=512`. They apply at the next restart
of the service. See SERVER.md, "Memory and thread ceilings".

# Upgrading from 0.4.12 to 0.5.0

0.5.0 gives wallets names, a contact book and a way to know who is on the
other end of a channel. Names are a rule of the chain: on testnet they open
at **block 5,200**. Payment channels stay as they are, open since
block 4,980.

## What changes

| | 0.4.12 | 0.5.0 |
|---|---|---|
| Names | — | A wallet registers up to three names, 3 to 30 characters from `a`–`z`, `0`–`9` and `-`. Each costs 0.5 Q21, **destroyed**: the price sits in an output no key can ever spend, and no miner collects it. A name belongs for good to the identity key derived from the recovery phrase: restoring the phrase restores the name. It does not expire and cannot be transferred |
| Look-alikes | — | Refused by the chain, not by a warning: two names cannot share a skeleton, where hyphens are dropped, `0`, `1`, `2`, `4`, `5`, `6`, `8`, `9` and `i` read as `o`, `l`, `z`, `a`, `s`, `b`, `b`, `g` and `l`, and `rn`, `vv`, `cl` read as `m`, `w`, `d`. `de1bu` cannot stand next to `delbu` |
| Protocol | 5 | 6. Name transactions and reach announcements go to protocol 6 peers only. A 0.4.12 peer keeps its link and everything else until the first block that carries a name |
| Contacts | — | A local book in the wallet file, sealed with it: a name of your own for each person, pinned to the identity their channel session proves |
| Verification | — | Two people read four words aloud — six for a large amount or a stranger — from the BIP 39 lists (English, French or Japanese). The words match only if no one stands between the two wallets. Opening or paying a channel toward a peer that is not a verified contact asks for a tick first. Both ends need 0.5.0 |
| Reach | — | A wallet that owns a name signs where it can be reached — its onion service — and its peers relay it, so a contact is found by name. Each peer has its own budget, and an owner is relayed at most once per ten minutes |
| Channel close | "closing" for 721 blocks | "closed · funds returned" once the closing transaction is as deep as a funding (6 confirmations on testnet). The node keeps watching it to 721 blocks, out of sight |
| Identity address | — | Not an address to pay. What sits there by mistake is spent by the next registration first, or brought back to the balance from the Channels tab (`identitysweep`) |
| RPC | — | New: `namecheck`, `namelookup`, `nameregister`, `namelist`, `channelidentity`, `contactlist`, `contactadd`, `contactremove`, `contactconnect`, `contactverify`, `verifications`, `contactconfirm`, `identitysweep`. `getpeers` gives `channel_owner`; `channellist` gives `close_txid`, `close_height` and `funding_depth`; `getsupply` gives `burned_by_names`, `spendable` and `names`; `listtransactions` marks registrations with `"purpose": "name"` |

## Who must upgrade, and when

**Every testnet node, before block 5,200** — entry points, miners, wallets,
explorers. A 0.4.12 node and a 0.5.0 node agree on every block that carries
no name, below block 5,200 and above it. They part at the first block that
carries one: a 0.4.12 node cannot read a name output, refuses that block and
stops there. Its log names no culprit: it simply ends up with no peer, and
reports itself not synced. Nothing on disk is damaged: installed over the
same folder, 0.5.0 resumes from that height.

Miners first, then everyone else, and no name registered before every node
runs 0.5.0. Mainnet schedules no name.

## The wallet file

0.5.0 adds two lines to the wallet file: `contacts=` and `name_txs=`. A
0.4.12 wallet opened by 0.5.0 starts with an empty book. Going back to 0.4.12
keeps the keys, the addresses, the balance and the names, which live on the
chain; it drops both lines when it saves the file. Back on 0.5.0, the contact
book is then empty, and the history reads the earlier payments of a name's
price as payments to the identity address.

---

# Upgrading from 0.4.11 to 0.4.12

0.4.12 changes one thing: payment channels open on testnet at **block 4,980**
instead of block 16,000. Same protocol (5), same chain, same data directory,
same wallet file. `channelstatus` (or `getinfo`, under `policy_activation`)
gives the activation height and how many blocks remain.

## Who needs it

**Every testnet node, before the first channel opens** — entry points,
miners, wallets, explorers. A 0.4.11 node and a 0.4.12 node agree on every
block that carries no policy, below block 4,980 and above it. They part at
the first block that carries one, that is at the first channel funding: a
0.4.11 node still waits for block 16,000, refuses that block, and stops
there, as a 0.4.10 node would. Nothing on disk is damaged: installed over the
same folder, 0.4.12 resumes from that height.

Upgrade every node before block 4,980, and open no channel before every node
runs 0.4.12. Miners first: a block that carries a policy is only built by a
0.4.12 miner, and only 0.4.12 nodes build on it.

---

# Upgrading from 0.4.10 to 0.4.11

> 0.4.12 moved the testnet activation to block 4,980. Wherever this section
> says 16,000, read 4,980. A 0.4.10 node can go straight to 0.4.12.

`channelstatus` (or `getinfo`, under `policy_activation`) gives the
activation height and how many blocks remain.

0.4.11 brings payment channels to **testnet**. Four things come together:

- the pay-to-policy outputs channels are built from become valid on testnet
  at a height announced in advance, **block 16,000**: a
  **hard fork**, after which a 0.4.10 node no longer follows testnet;
- channel peers talk through an **encrypted, authenticated transport**
  (ML-KEM-1024 and ML-DSA-87), not in clear;
- the wallet gets a **Channels** tab;
- channels on testnet use **terms fit for a public network**: days, not
  minutes, to answer a cheat.

Same chain until block 16,000, same data directory, same wallet file.
Mainnet does not exist yet, and nothing in this release would open
policies or channels there. Regtest keeps the rule it had in 0.4.10, open
from its first block, and its short channel terms.

## What changes

| | 0.4.10 | 0.4.11 |
|---|---|---|
| A testnet block carrying a policy output, or spending one | Malformed: refused, and the peer that sent it cut | Below block 16,000, the same. From block 16,000 on, valid when its policies are satisfied |
| A testnet payment creating or spending a policy output | Malformed | Refused by the pool until the next block is 16,000; from then on, accepted like any other |
| Payment channels on testnet | None: no channel message sent or accepted | The channel manager runs on a node started with `--rpc-wallet` (the wallet included) from its start. `channellist` and `channelinfo` answer at once; `channelopen`, `channelpay` and `channelclose` refuse, saying how many blocks remain, until the tip reaches 16,000, so that every funding confirms at block 16,000 or later. No channel message, session handshake included, leaves before then |
| How channel peers talk | Frames in clear over the P2P link, the peer named by an id it declared itself | Every frame inside a session: each side proves its ML-DSA-87 node identity over a transcript holding both ends' fresh ML-KEM-1024 keys, then records are encrypted and authenticated, with forward secrecy and rekeying. A party relaying the connection can delay or drop frames, nothing else. `channelopen` names a peer by address or by the node id its session authenticated; `getpeers` shows each peer's `channel_session` |
| Versions announced | Protocol 4; channel capability `+chan` | Protocol 5, meaning "follows the activation", and channel capability `+chanv3`, channel protocol 3 (session frames). The capability is announced alone, with no id, and only once channels are open: on testnet from the activation height on. A 0.4.10 node keeps a 0.4.11 peer and the reverse. On testnet every protocol-5 link may carry channel frames once the tip reaches the activation height, the links opened before it included, which keep their connection: a node without channels ignores the frames, and the dialer stops asking it after a few. A 0.4.10 channel node (`+chan`) is not one: its frames are refused without blame |
| Channel terms | 12-block to-self delay, 2 confirmations, everywhere | Per network. Testnet: 1,440 blocks (about two days) proposed, 720 to 2,016 accepted from a peer, 6 confirmations before a channel opens. Regtest keeps 12 blocks (6 to 2,016 accepted) and 2 confirmations. `getinfo` reports them under `channel_terms` |
| The wallet | — | A Channels tab: until channels are active it says at which block, in how many blocks and about how long; then it lists channels with the balances in plain words, opens one with a connected peer that runs channels, pays, and closes, cooperatively or without the peer. Each step is confirmed with what moves, the fees and the delay of a forced close |
| A peer still on 0.4.10 | — | Is never offered a policy transaction, which it would read as malformed. From two days (1,440 blocks) before the activation, each such peer is named in the log once per connection, and counted in `getinfo` (`policy_activation.peers_predating_activation`); `getpeers` shows every peer's `protocol_version` and `follows_activation` |
| A policy transaction from a 0.4.11 peer that is a few blocks ahead | — | Refused without any penalty, and the link stays |
| Where the activation stands | — | `channelstatus`: `network`, `activation_height`, `tip`, `active`, `blocks_remaining`, `eta_seconds` |

## Who must upgrade, and when

**Every testnet node, before block 16,000** — entry points, miners, wallets,
explorers. At two-minute blocks, 16,000 is about two weeks after the release.
The order does not matter before the activation: until block 16,000 a 0.4.10
node and a 0.4.11 node agree on every block, relay each other's payments, and
stay connected.

Miners first among them: a block of 16,000 or above that carries a policy is
only built by a 0.4.11 miner, and only 0.4.11 nodes build on it.

## What happens to a node left on 0.4.10

Nothing, until the first block at or above 16,000 that carries a policy
output — in practice the first channel funding. Then:

1. It refuses that block as malformed and disconnects the peer that sent it;
   every upgraded peer sends it the same block, so it disconnects them all,
   one after the other. It stays at the height before that block, its peer
   count falls to zero, and its log shows nothing but reconnections. The
   pages and the wallet show a height that no longer moves.
2. If it mines, it mines on that old tip, a branch of its own. Its blocks
   are valid for upgraded nodes too, but stay on a side branch as long as the
   upgraded miners have more work. That is why miners upgrade first: should
   the miners left on 0.4.10 hold most of the work, their branch would win,
   and upgraded nodes would follow it, putting the policy transactions back
   in their pools until an upgraded miner confirms them again. Payments sent
   from a 0.4.10 wallet after the activation reach only the other 0.4.10
   nodes.
3. Nothing on disk is lost or damaged. Installed over the same folder, 0.4.11
   resumes from the height where 0.4.10 stopped and catches up within
   seconds to minutes; nothing is re-downloaded from the start and the
   wallet is untouched.

Upgrade before block 16,000 and none of this happens.

## Channels opened on regtest with 0.4.10

They spoke the clear protocol, which 0.4.11 no longer speaks: a 0.4.10 and
a 0.4.11 regtest node do not hold a channel together. Close such channels
cooperatively before upgrading either end.

---

# Upgrading from 0.4.9 to 0.4.10

0.4.10 is a drop-in replacement: same protocol (4), same chain, same data
directory, same wallet file. A 0.4.9 node and a 0.4.10 node talk to each
other, and nothing a 0.4.10 node accepts on testnet is refused by a 0.4.9
node, or the reverse: the blocks a 0.4.10 miner builds are accepted by 0.4.9.
It fixes five faults of the transaction pool, the miner and block relay that
were already present in 0.4.9, found under load with a full pool, crashes and
chain splits. It also carries payment channels, complete and tested but
**active on regtest only**.

## What changes

| | 0.4.9 | 0.4.10 |
|---|---|---|
| Payments of blocks abandoned in a reorganization, when the pool is full | Refused by the full pool: confirmed payments could disappear | Taken back even into a full pool, ahead of newcomers |
| A miner's coinbase when a block holds a payment and the payment that spends it | The fee of the second payment was left out: the miner lost it | Counted. The block is the same one 0.4.9 accepts |
| The miner's own block refused | Silently thrown away, and the same block built again, forever | Logged; the offending transaction is dropped from the pool; an identical template is not hashed again; the miner waits when the chain's clock runs ahead |
| A newcomer seated in a full pool | Could push out the very payments it builds on | Its ancestors are never pushed out to seat it |
| A transaction a full pool refused | Downloaded again from every peer at every block | Remembered across blocks |
| A peer slow to deliver a block body on a busy link | Banned: honest peers were cut and chain splits did not heal | Not banned; a block whose parent we lack makes us ask for the headers |
| A payment sent in the half-second after `stop` | Answered "accepted", then lost at restart: the pool had already been written | Refused with "the node is shutting down"; sends already under way finish and are saved first |
| The constant-time helpers under ML-DSA (`ctutils`) | 0.4.2, affected by RUSTSEC-2026-0385: some masks could compile to a branch on secret data | 0.4.5, the corrected release |
| A node paused and resumed (a debugger, a laptop lid, `SIGSTOP`) | Every link dropped on resume | Links kept |
| Payment channels | — | Complete channels on regtest: `channelopen`, `channelpay`, `channelclose`, `channellist`, `channelinfo`; payments in a few milliseconds; penalties for a revoked state; recovery after a crash, a lost link, a reorganization or a revoked state confirmed while the node was off. **On testnet and mainnet nothing changes**: no channel message is sent or accepted, and a policy output is treated exactly as 0.4.9 treats it |

## Who needs it

Everyone, the entry points first. The order does not matter for safety: a
0.4.9 node and a 0.4.10 node agree on every block. Turning channels on for
testnet is a separate, later decision: it changes the consensus rules, so it
needs every node on 0.4.10 or later first.

---

# Upgrading from 0.4.8 to 0.4.9

0.4.9 is a drop-in replacement: same protocol (4), same chain, same data
directory, same wallet file. A 0.4.8 node and a 0.4.9 node talk to each
other. It comes out of the two-hour endurance test of 18 October 2026: three
agents at three payments a second each, about 23,000 payments accepted.
Nothing was lost to the chain itself, but the entry points froze for minutes
at a time, the wallets showed "no response" all at once, and about 4 % of
the accepted payments never reached a block. A second round of local testing,
on 19 October, with ten nodes, congested-Tor wallets, payments to many
recipients at once, crashes and freezes, found two more faults, fixed here: a
node that fell behind only ever recovered the top of a peer's pool, and a
payment larger than what a wallet would be left with was wrongly told to wait
for a block.

## What changes

| | 0.4.8 | 0.4.9 |
|---|---|---|
| A peer that stops reading (a stalled Tor circuit, a laptop that slept) | Every broadcast wrote to each peer in turn and waited up to 30 seconds on that one; dropping it waited too, while holding the node's lock. A few such peers froze a node for minutes: no block relayed, no wallet answering | Each peer has its own send queue and writer: nobody waits for anybody. A peer that does not read is dropped by its own timeout; one that reads slowly is served at its pace, on Windows too, where a block sent in one piece used to be cut below 140 KB/s |
| A reorganization on a node with the address index (the entry points, every wallet) | The index erased itself and reindexed the whole chain while holding the node's lock: more than ten minutes frozen on the entry points | The index goes back to the fork only, a few blocks at a time, outside the node's lock |
| A full pool (64 MiB) | A payment paying one unit more pushed out another, and every payment built on it went too: about a thousand accepted payments vanished in the test | A newcomer must pay clearly more than what it pushes out. Payments nothing depends on go first; a chain goes out as a whole only when the newcomer pays clearly more than the chain does on average. The node's own wallet payments are never pushed out of its own pool, even through a reorganization. A newcomer that cannot get in is refused before its signature is checked |
| A payment that arrives before the one it builds on | Refused, and heard of again only at the next offer of a peer's pool: up to ten minutes | Waits for it, and goes in the moment it arrives |
| A payment a miner missed | Offered again after ten minutes | After two minutes, one block. A payment refused for a full pool is not downloaded again before the next block |
| A node behind by a full pool (a fresh wallet, a node back from a bad link) | The periodic offer re-sent only the top of the pool, which the node already held: it received about a hundred and forty transactions and then nothing, and a miner mined near-empty blocks while its peers held thousands | The offer covers the whole pool; a node catches up a backlog of two thousand transactions in about three minutes, and the miner's blocks stay full |
| A requested transaction larger than the per-peer budget (a consolidation of a hundred coins) | Dropped and re-requested at the next offer: it crossed the network one transaction per offer | Served whatever its size, since we asked for it; the budget still bounds what a peer pushes unasked |
| Paying more than what the wallet will be left with once its pending sends are mined | Told to "wait for a block", which changed nothing | Told there are not enough funds — and, when the funds are only scattered across many small coins, offered a button to gather them |
| A reorganization deeper than six blocks | The payments of the older abandoned blocks were not put back in the queue | Put back up to twelve blocks deep |
| A relay passing on many payments | Eight signature checks a second granted to each peer, and what it sent beyond counted as misconduct | Sixteen; a peer is only asked for what that allows, and what it was asked for is never misconduct |
| A tip that stops moving | Nothing done until the next block arrived | After ten minutes, the peers are asked what follows it |
| The machine "woke up from sleep" | Every link cut, onion ones included, even on a false alarm | Every peer is pinged; only those that do not answer within twenty seconds are dropped |
| A wallet through Tor | Reached the entry points both by onion and through Tor exits | Onion first; the exits only with fewer than two onion links |
| The wallet's log | Silent between two events | A status line every five minutes: height, peers, pool, Tor |
| The monitor (`tools/monitor.sh`) | Restarted a running node after one run without an answer | After three runs in a row: a busy node is not a dead node |
| Address and history lookups | Copied the whole mempool under the node's lock | Read it in place |
| The macOS launchers | Removed the quarantine from the whole folder, including any other download sitting next to it | Only from the files of the archive, by name |
| The console launchers | `Q21 Wallet - console.bat` and `Q21 Wallet - Terminal.command` next to the application | In the `Troubleshooting` folder, so that they are not opened instead of it |

## Who needs it

Everyone, the entry points first: they are the ones that froze. Then every
wallet.

On a server, replace the binary and restart the service, then copy the new
`tools/monitor.sh` over the old one. Its state file gains a companion,
`state.silent`, in the same directory: nothing to configure. The number of
silent runs before a restart is `Q21_SILENT_RUNS` (3 by default).

Unzipped over an older folder, the archive leaves the old console
launchers in place, next to the application: they still work. The new ones
are in `Troubleshooting`, and the old ones can be deleted.

---

# Upgrading from 0.4.7 to 0.4.8

0.4.8 is a drop-in replacement: same protocol (4), same chain, same data
directory, same wallet file. It comes out of the testnet load test of
15 October 2026 (0 payments lost out of 600 followed) and of the first Tor
test on a Raspberry Pi, on 17 October.

## What changes

| | 0.4.7 | 0.4.8 |
|---|---|---|
| Tor in the wallet | Tor Browser had to be installed, opened, and kept open | **Tor comes in the archive** (Windows, macOS, Linux x86_64). The switch in the Network tab is enough: the wallet starts Tor, shows its progress, starts it again if it stops, and stops it when it closes |
| A reachable wallet behind Tor | An onion service set up by hand in Tor's configuration | **A hidden node by itself**: the bundled Tor creates its onion address, the wallet announces it. The address is kept in `q21-data/tor/onion/` |
| Onion addresses learned from the network | Forgotten at every restart, and after five failed attempts | Written to `onions.dat`; forgotten only when one keeps failing **and** has not been seen for three days |
| The entry points | Reachable through Tor exit relays only | Also onion services, named in `bootstrap.txt`: a node through Tor still finds the network when their usual addresses are blocked or down |
| Several dials through Tor | One after the other: a server that was down held up the rest for a minute each | All at once |
| New addresses on the network | Learned only when connecting to a peer | Also asked again every ten minutes |
| A server named twice in `bootstrap.txt` (name and address), through Tor | Counted as two peers | Recognized as one |
| A body of the chain that never reached the disk | Cut the chain in two at the next restart; an old side branch could pass for the best chain, and the node fell back hundreds of blocks | Written again from memory every five minutes; at restart, a hole sends the node back to the genesis to resync, never onto an old branch |
| Paying when the large coins are all held by pending payments | A dozen confirmed crumbs: a transaction ten times heavier | One pending coin that covers the payment, when there is one |
| An onion address in `bootstrap.txt` without Tor | A line per address at every start | Skipped quietly, never handed to the system resolver |
| Opening the wallet (Windows, macOS) | `Q21 Wallet.bat` / `Q21 Wallet.command`: a PowerShell or Terminal window next to the browser | `Q21 Wallet.exe` / `Q21 Wallet.app`: **no window**, only the page. Launched again, the wallet opens its page again; an error at startup shows in a dialog box, and in `q21-data/wallet.log`. The scripts stay as `Q21 Wallet - console.bat` and `Q21 Wallet - Terminal.command` |

## Who needs it

Everyone. The wallets first, this time: they are the ones that gain Tor. The
entry points then, for the onion addresses and the fixes; on a server, the
onion service itself is two lines of Tor configuration (TOR.md, section 4).

Unzipped over an older folder, the archive leaves the old `Q21 Wallet.bat`
or `Q21 Wallet.command` in place: they still work, with their window. The
launcher without a window is `Q21 Wallet.exe` on Windows and `Q21 Wallet.app`
on macOS; the old files can be deleted.

A 0.4.7 node and a 0.4.8 node talk to each other: the protocol does not
change. Given the 0.4.8 `bootstrap.txt`, a 0.4.7 node on Tor uses its
`.onion` lines; one that is not on Tor skips them at startup, but its
maintenance loop asks the system resolver about them, which fails (an onion
name has no DNS record) and tells the resolver which names were asked. They
are public names; updating ends it.

---

# Upgrading from 0.4.5 to 0.4.7

0.4.7 is a drop-in replacement: same chain, same data directory, same wallet
file (still `Q21SEAL4`), so going back to 0.4.5 stays possible. It comes out
of a second load test of the testnet, on 14 October 2026: two wallets, about
6,400 payments, blocks full at 227 payments. Every payment was accepted, but
a part of those built on top of pending ones never reached a block. There is
no 0.4.6: the fix ships in 0.4.7, together with Tor.

## What changes

| | 0.4.5 | 0.4.7 |
|---|---|---|
| A block confirms a payment that others depend on | The node also dropped every pending payment built on it: accepted, never confirmed. In a replay of the test, 111 and 231 payments out of 1,080 were lost | They stay in the queue and go into the next blocks. Same replay: 0 lost |
| A block replaced by a longer chain (reorganization) | Its payments were forgotten | They go back into the queue (six blocks deep at most) |
| Which coins pay | The oldest first: a wallet with hundreds of small coins could not pay 50 Q21 ("insufficient funds") | The largest first. When even they need more coins than a transaction can carry (about 240), the message says so |
| Many small coins | Nothing to gather them | `consolidate` (RPC) gathers the smallest ones, 100 by default, into a single coin paid to yourself |
| Private addresses (`192.168.…`, `10.…`) heard from a peer | Kept and passed on to the whole testnet | Refused, and never passed on |
| Mining while reachable without Tor | Nothing said | A warning at startup and in the wallet: the blocks found first appear coming from this IP address |
| Tor | — | `--tor`, `--proxy`, `--onion`, and a switch in the Network tab. See [TOR.md](TOR.md) |
| Protocol | 3 | 4: one new message, `onionaddr`, sent only to peers of version 4 |

## Who needs it

Everyone, in this order:

1. the entry points (servers): they keep the pending payments that depend on
   a confirmed one, and pass on onion addresses;
2. the wallets. No backup is needed this time: the wallet file does not
   change. Copying `q21-data` aside before any update remains a good habit.

A 0.4.5 node and a 0.4.7 node talk to each other: a version 3 peer is never
sent the new message.

---

# Upgrading from 0.4.4 to 0.4.5

0.4.5 is a drop-in replacement for the node: same protocol (3), same chain,
same data directory. It comes out of a load test of the testnet on
11 October 2026: two wallets, about 1,800 payments in two hours, over the
France and Singapore entry points. No payment was lost, but the test showed
the weak points below.

## What changes

| | 0.4.4 | 0.4.5 |
|---|---|---|
| A node asked to mine before it has caught up | Mines a chain of its own from where it stands; every peer refuses its blocks | Waits for a first peer (five minutes at most) and for the height its peers announce; the console says `mining paused` and `mining resumed` |
| Monitoring while nobody mines | `monitor.sh` restarts a healthy node every hour | Peers connected and none knows a longer chain: the network is idle, the node is left running, the log says so about once an hour |
| Cost of a payment in the wallet | Two Argon2id derivations (the wallet is written twice): about 0.7 s on a PC, several seconds on a small board | One derivation per session, then a fresh nonce for each write: about 25 ms |
| Every confirmed coin already used by pending payments | Wait for the next block | The wallet spends the change of its own pending payments, up to a chain of 25 unconfirmed transactions |
| A pending payment that pays more than the one it depends on | Left out of the next block, which cost one block per link | Goes into the block right after its parent |
| Closing the Terminal window of a node (macOS, Linux) | The node is killed on the spot; pending transactions are lost | Clean shutdown: pending transactions are written to `mempool.dat`. A node started with `nohup` still ignores the window |
| Closing the PowerShell window of a node (Windows) | A mining node could take tens of seconds to notice, and Windows gives a few: the pending transactions were lost | A mining round lasts about a second, and the pending transactions are written first |
| A peer that connects after a payment was sent, or missed it | Never hears of it | Pending transactions are offered to each new peer, and to every peer every ten minutes |
| `sendtoaddress` and `sendmany` without a `fee` | 1,000 units whatever the size: a payment that needs 14 coins or more was refused | Computed on the real transaction at the rate of the pending ones, never below 1,000 units; the answer gives the `fee` paid |
| `sendmany` | Could take coins already used by a pending payment (refused as a double spend), and wrote the wallet under the node's lock | Same path as `sendtoaddress` |

## ⚠ Wallets: back up the data folder first

The first time 0.4.5 writes a wallet, it converts the file to a new sealed
format (`Q21SEAL4`), the one that makes a payment cheap. **0.4.4 and earlier
cannot open it.** Before installing 0.4.5, copy the `q21-data` folder aside,
for example as `q21-data-backup-0.4.4`.

Opened by 0.4.4, a converted wallet is refused with a message saying the
directory "was protected by a passphrase; this file is not". In this case the
message is wrong about the cause: **delete nothing**. Put back the copy you
made, or go on with 0.4.5. Your backup code restores the wallet with any
version.

## Who needs it

Everyone, in this order:

1. the entry points (servers), so that they offer pending transactions to
   the wallets that connect, and so that `monitor.sh` stops restarting them
   when the network is idle — copy the new `tools/monitor.sh` to
   `/opt/q21/monitor.sh`;
2. the wallets, after backing up `q21-data`.

A 0.4.4 node and a 0.4.5 node talk to each other: nothing in the protocol
changes.

---

# Upgrading from 0.4.3 to 0.4.4

0.4.4 is a drop-in replacement: same protocol (3), same chain, same data
directory. It changes only the wallet.

## What changes

| | 0.4.3 | 0.4.4 |
|---|---|---|
| Several payments before the next block | The second one was refused ("a transaction already pending spends the same funds"), even with many coins: one payment per block, about one every two minutes | Each payment takes coins that the pending ones do not spend: as many payments as the wallet has coins |
| Every coin already used by pending payments | "insufficient funds", for money the wallet does have | Says the coins are waiting for a block, and to send again after it |

## Who needs it

The wallets. A node without a wallet (a server, a node on a small board)
behaves exactly as with 0.4.3: updating it is optional.

---

# Upgrading from 0.4.2 to 0.4.3

0.4.3 is a drop-in replacement: same protocol (3), same chain, same data
directory. It comes out of an adversarial review of 0.4.2, which found no way
to break the chain, and closes the operational weak points it did find.

## What changes

| | 0.4.2 | 0.4.3 |
|---|---|---|
| Public explorer whose reverse proxy crashed | Nobody is told, the explorer stays down | `tools/monitor.sh` checks the page from outside (`Q21_PUBLIC_URL`), restarts the proxy and notifies |
| Caddy after a crash | Stays stopped | PUBLIC-EXPLORER.md makes it restart on its own (`Restart=on-failure`) and shows how to keep it up to date |
| Signing on a scheme the program cannot use | The node panics | The spend is refused, nothing is signed |
| Activity notes ("Full history…") | In English for every reader | Translated, and the note says whether the index was used |
| Monitoring of a node without a public explorer | Refused by the node (the RPC admitted only the node's own account), then restarted it every ten minutes | The administrator is admitted; `monitor.sh` never restarts a node that refuses it |
| Entry points shipped in `bootstrap.txt` | One machine (France) | Two machines, on two continents (France and Singapore) |

## Updating a server that publishes the explorer

The node and its service do not change: replace the program as for 0.4.2.

Then, once, make Caddy restart after a crash, and give the monitoring the
explorer's address. The steps are in PUBLIC-EXPLORER.md (section 4.1) and
SERVER.md ("Getting notified without watching"): a `restart.conf` file next
to Caddy's service, a `Q21_PUBLIC_URL=` line in `/etc/q21/monitor.env`, and
the new `monitor.sh` copied to `/opt/q21/monitor.sh`.

## Updating a wallet

Unpack the new archive over the old one, as for 0.4.2. It also replaces
`q21-data/bootstrap.txt` with the new list of entry points: if you had added
your own lines to that file, copy them aside before, and add them back after.

---

# Upgrading from 0.4.1 to 0.4.2

0.4.2 is a drop-in replacement: same protocol (3), same chain, same data
directory. It fixes the search of the explorer opened from the wallet, and the
Activity tab of a wallet that mines.

## What was wrong

| Symptom in 0.4.1 | Cause | 0.4.2 |
|---|---|---|
| Opened from the wallet, the explorer asks for an "access token" and every search stays on "Searching…" | The wallet's link handed the explorer a token it could not use | The explorer uses the wallet's session, which is served by the same node |
| A transaction older than about three days is "not found" | The wallet's node had no address index: 2,000 blocks at most | The wallet builds the index |
| An address page never shows what the address sent | Same cause | Same fix |
| An address copied by hand, `0,5`, `0.5 Q21` or `1 000,5` are refused | The search required the exact form the node prints | Spaces, line breaks, a decimal comma and the unit are accepted |
| An identifier copied from a list (`f470f6d8d1652b74…`) is refused | Lists show 16 characters | 8 characters or more are completed, if only one identifier matches |
| A payment just sent is not on the recipient's address page | The mempool was ignored | Pending movements are shown, marked "pending" |
| "Sent" shows nothing in the Activity of a wallet that mines | The page filtered the last 100 rows, all mining rewards | The node filters before the limit, over the whole history |
| Activity stops at the 100 most recent rows | No way to ask for more | **Show older movements**, a hundred at a time, up to 2,000 |
| A synchronization stalls on blocks that carry transactions: one block per connection, and the peer is penalized | A requested block arriving before its parent was dropped | It waits for its parent, then connects |
| A wallet restored from its backup code can miss addresses whose coins were all spent | Discovery only counted addresses still holding a coin | With the index, an address counts as used if it ever appeared in the chain |

## The address index, now built by the wallet

On the first start of 0.4.2, the wallet reads the whole chain once to build
the index. This takes a few seconds and writes an `index.dat` file in the data
folder. Then each new block updates it.

Nothing to do. To keep the old behavior, start the wallet with `--no-index`.
A wallet started with `--prune` never builds it.

## Restoring from the backup code

A wallet restored on a new machine finds its addresses again while the chain
arrives. Since 0.4.2 it also recognizes the addresses it emptied, through the
address index: the balance and the whole history come back, sends included.

## The Receive tab

The address to give is now shown at the top of the Receive tab, whole, with a
**Copy the address** button and a link to see it in the explorer. Every
address of the wallet stays valid: the new display changes no address.

## Updating a server

The public explorer already runs with `--address-index`: only the search
tolerance and the pending movements change there. The steps are the same as
for 0.4.1, below.

---

# Upgrading from 0.4.0 to 0.4.1

0.4.1 is a drop-in replacement: same protocol (3), same chain, same data
directory. A 0.4.0 node and a 0.4.1 node talk to each other, and nothing is
converted. Replace the program, restart, and read the four changes below.

## Your wallet is a client unless you say otherwise

Up to 0.4.0, a wallet was **reachable by default**: it listened for incoming
connections, asked your router to open a port, and announced your public IP
address to its peers, which passed it on to every node of the network. An
address once announced cannot be called back.

Since 0.4.1, a wallet is reachable **only** if `settings.txt` says
`reachable=yes`, which is what the Network tab writes when you turn the
setting on. Concretely:

| Before the update | After |
|---|---|
| you never touched the setting | **client** (it was reachable) |
| you turned it off (`reachable=no`) | client |
| you turned it on (`reachable=yes`) | reachable, as you chose |

If you want your wallet to stay reachable, turn the setting on again in the
Network tab and restart the wallet. The tab no longer shows your public
address: only whether your router opened the port.

## Servers: the monitoring now keeps its measurement

The monitoring unit published up to 0.4.0 let systemd delete its state file
after every run, so every run took its first measurement again and a stuck
node was never noticed. If you installed it, add one line to the unit:

```bash
sudo sed -i 's/^RuntimeDirectory=q21-monitor$/RuntimeDirectory=q21-monitor\nRuntimeDirectoryPreserve=yes/' /etc/systemd/system/q21-monitor.service
sudo systemctl daemon-reload && sudo systemctl start q21-monitor.service
sudo cat /run/q21-monitor/state
```

The last command prints the height and the time it was recorded. Ten minutes
later, the height must have grown. `tools/monitor.sh` itself did not change,
only its comments: an installed copy can stay.

## A 0.3.x bootstrap file next to the program is read again

The 0.4.0 migration renamed the bootstrap file of the data directory, not the
one that 0.3.x archives put **next to the program**. A server upgraded by
replacing its binary only, with that old file still beside it, started with no
address to contact. 0.4.1 reads it again when no `bootstrap.txt` stands next
to the program, and says so at startup:

```
  bootstrap: reading the 0.3.x file /opt/q21/amorces.txt. Rename it to bootstrap.txt next to the program.
```

Rename it, or replace it with the `bootstrap.txt` of the archive, which names
the current entry points.

## The release page lists only what you need

The archives, `SHA256SUMS` and `SHA256SUMS.minisig`. The separate `.sha256`
files are gone: their content is in `SHA256SUMS`, which is the signed one.

## Updating a server

The service and its options do not change. Download, check the signature as
in [SIGNING.md](SIGNING.md), then:

```bash
sudo systemctl stop q21
sudo install -o root -g root -m 0755 q21 /opt/q21/q21
sudo systemctl start q21
sudo /opt/q21/q21 version
```

---

# Upgrading from 0.3.x to 0.4.0

Version 0.4.0 moves the program to English: file names, options, commands
and messages. It also **restarts the public testnet from a new genesis
block**. Your seed, your passphrase, your backup code and your addresses do
not change; your testnet coins do not carry over, since they belong to the
old chain. Here is what happens, and the one thing you have to do by hand if
you run a node as a service.

## The testnet starts again

The genesis message changed in 0.4.0, so the testnet has a new genesis block:

```
testnet  e310676c854f693693008d7270b583092c065051f73dc33b245676d804d77227
```

`q21 genesis testnet` prints it. On first start, 0.4.0 finds the blocks of the
old chain in your data directory, puts them aside in `old-chain-<id>/` — nothing
is deleted — and starts the new chain at height 0. Your wallet is the same
wallet: the same seed, the same addresses, on a new chain. Testnet coins have
no value; mine again to get some.

## Your data directory is upgraded on first start

Close the 0.3.x program first. Then start 0.4.0 on the same data directory —
`q21-data` next to the program, or the folder you give with `--datadir`. The
folder keeps its name; only the files inside are renamed, once, before
anything else reads them:

| 0.3.x | 0.4.0 |
|---|---|
| `reglages.txt`, `joignable=oui` / `joignable=non` | `settings.txt`, `reachable=yes` / `reachable=no` |
| `wallet.ancre` | `wallet.anchor` |
| `amorces.txt` | `bootstrap.txt` |
| `entetes.dat` | `headers.dat` |
| `ancienne-chaine-<id>/` | `old-chain-<id>/` |
| `.verrou` | `.lock` |
| keys of `adoption.txt` | English keys |

`wallet.dat`, `blocks.dat`, `state.dat` and the other files keep their names.
Each action is printed at startup, for example:

```
  data directory upgraded: reglages.txt -> settings.txt (reachable=no)
  data directory upgraded: amorces.txt -> bootstrap.txt
```

If a 0.3.x program is still running on the same directory, 0.4.0 refuses to
start instead of renaming files under its feet:

```
error: an older q21 (0.3.x) is still running on <directory>. Close it, then start this version again.
```

If both `amorces.txt` and `bootstrap.txt` exist — a new archive unpacked over
the old folder — the addresses you had added yourself are appended to
`bootstrap.txt`, under a `# Carried over from amorces.txt` line.

## Your wallet file is converted the first time you open it

`wallet.dat` is sealed by your passphrase, so it cannot be converted before
you type it. The first time 0.4.0 opens your wallet, it rewrites it in the
0.4 format and says so:

```
  Wallet converted to the 0.4 file format.
```

| 0.3.x | 0.4.0 |
|---|---|
| sealed format `Q21SCEL2` | `Q21SEAL3` (same Argon2id protection) |
| keys `serie=`, `verifie_jusqu_a=`, `consommes=`, `reserves=`, `etiquettes=`, `demandees=` | `serial=`, `verified_up_to=`, `consumed=`, `reserved=`, `labels=`, `requested=` |
| seed fingerprint in `wallet.anchor` | recomputed under the new label |
| `addresses.dat` cache | re-authenticated under the new key |

Your seed, your addresses, your address book and the list of one-time keys
already used are carried over unchanged. **Do not go back to 0.3.x
afterwards**: it cannot read the converted file, and it could not join the
new testnet anyway.

## "Not reachable" stays not reachable

If you had told your wallet not to accept incoming connections (`joignable=non`
in `reglages.txt`), 0.4.0 keeps that choice: it becomes `reachable=no` in
`settings.txt`. Any old value other than `oui` becomes `no`, the more private
choice, and when both files exist, a `no` in either one wins. If the setting
cannot be written, the program stops rather than start with the default — which
would open your router port and publish your address.

## Update your systemd units

0.4.0 keeps no alias for the old names: an old option is now an error, and a service
started with one fails at every restart (`error: unknown option: --reseau`).
Edit `ExecStart=` in your units:

| 0.3.x | 0.4.0 |
|---|---|
| `--reseau` | `--network` |
| `--amorce` | `--bootstrap` |
| `--sans-amorces` | `--no-bootstrap` |
| `--elaguer` | `--prune` |
| `--index-adresses` | `--address-index` |
| `--ouvrir-box` | `--upnp` |
| `--silencieux` | `--quiet` |
| `--fils` | `--threads` |
| `--pairs` | `--peers` |
| `--rpc-token-fichier` | `--rpc-token-file` |
| `--phrase-fichier` | `--passphrase-file` |
| `--code-fichier` | `--backup-code-file` |

The commands follow suit: `genese` → `genesis`, `explorateur` → `explorer`,
`instantane` → `snapshot`, `revalider` → `revalidate`, `securite` →
`security`, and `portefeuille` is gone (use `wallet`). For example, the entry
point's line becomes:

```ini
ExecStart=/opt/q21/q21 --datadir /opt/q21/data node --network testnet --listen 21121 --no-bootstrap
```

Keep your existing `--datadir` and `ReadWritePaths=` as they are: the folder is
upgraded in place, it does not need to move. Then:

```bash
sudo systemctl daemon-reload && sudo systemctl restart q21
```

If you use the monitoring script, it is now `tools/monitor.sh` (formerly
`outils/surveiller.sh`); [SERVER.md](SERVER.md) gives the new unit files.

## 0.3.x and 0.4.0 nodes do not talk to each other

0.4.0 speaks protocol version 3. A 0.3.x node (protocol version 2) is
disconnected at the handshake, without penalty. Upgrade every node you run —
the entry point included — and tell the people who join through yours: a
0.3.x wallet will find no peers on a 0.4.0 network.

## Snapshots exported by 0.3.x must be exported again

The labels of the state commitment changed, so every state commitment
published by 0.3.x changes too. A snapshot exported by 0.3.x
(`instantane exporter` or `instantane exporter-amorce`) no longer loads in
0.4.0: export it again from a 0.4.0 node with `q21 snapshot export` or
`q21 snapshot export-sync`, and publish the new commitment. Your own
`state.dat` is carried over: it is relabeled after a full check, or rebuilt
from the blocks if it cannot be. A node that started from a 0.3.x snapshot
keeps its trusted commitment, and `q21 revalidate` still checks it.

---

# What changes for you

## The explorer: phase 3

A single search field, at the top of the page. Paste anything into it:

| What you paste | What you get |
|---|---|
| `276` | The block at that height |
| A 64-character identifier | The block, or the transaction |
| A `tq211q…` address | Its balance and all its movements |

Four pages linked to one another: from a block you click on a transaction,
from that transaction you click on an address, and the browser's "back" button
takes you back.

**You have nothing more to launch.** Your wallet already serves the explorer,
at the same place and on the same port: the link is at the bottom of the page.

And if you want to look at the chain *without* opening a wallet:

```
q21 explorer
```

No method capable of moving funds is served then — not disabled by a setting,
absent.

## Address search, and its honesty

Finding all the transactions of an address is expensive: nothing in a
blockchain links an address to its transactions. You have to go through all of
them.

`q21 explorer` therefore builds an **index** at startup, and the search is
then complete. Since 0.4.2 your wallet does too (see the 0.4.1 to 0.4.2
section); `--no-index` turns it off.

In both cases **the page always says which of the two paths was used**:

> **Bounded history.** Search went back to block 12400 of 14400. The balance
> shown stays exact: it comes from the set of unspent outputs, not from this
> list.

The balance itself depends on no index: it comes from the unspent outputs that
your node keeps up to date anyway. It is exact in every case.

## Two Q21 programs can no longer damage the same folder

This is the most important fix in this version, and it comes from a
reproduction: your wallet could become **impossible to open**.

The case is ordinary. The wallet is running in its window; you open a second
window and run `q21 mine` to confirm a transaction. Two programs then write the
same wallet file. They trip over each other, and at the next start you read
this:

```
error: this wallet carries serial number 6, whereas this
             directory has already seen a more recent one (7).
             This is the signature of a restore from an old backup.
```

An alarming message, an intact wallet: it is a **counter** that diverged, not
your funds. But you had no way of knowing that.

Now, the second program is politely refused:

```
error: another q21 is already using this data directory.

  Directory: q21-data

  Two programs that write the same wallet and the same block file
  damage both. Close the other window — the "Close the wallet"
  button on the Info tab, or the window's close button — then start
  this one again.
```

> **If you run into the serial-number message on your current installation**:
> delete the `wallet.seq` file in the `q21-data` folder. Your Q21 and your
> seed are intact. Checked: the wallet reopens with its whole balance.

## Your wallet file can no longer be cut in half

It used to be erased and then rewritten. An interruption between the two — a
dead battery, an abrupt shutdown — left an empty file, in other words a lost
seed. Now it is written next to the old one, then renamed in one go: either
the old version or the new one, never a mix.

## You no longer need Ctrl-C

In the wallet, **Info** tab, at the very bottom: a **"Close the wallet"**
button.

A first click asks for confirmation, a second one closes. The node writes its
pending transactions, its state and your wallet, then stops. The black window
closes on its own.

**Closing the black window** with its close button works too: it is
intercepted the same way.

## The "Terminate batch job (Y/N)?" message

This is what got you stuck, and **it was not a malfunction**.

This message does not come from Q21. It comes from Windows: when you press
`Ctrl` + `C` while a `.bat` file is running, the command interpreter asks
*its own* question before handing control back. No line of the file can
prevent it — it comes before the script has any say.

At that point, **everything is already saved**. The proof is just above it, on
the screen:

```
  Shutdown requested. Writing...
Stopped. Final height: ...
```

These two lines mean that Q21 intercepted your `Ctrl` + `C`, wrote what it had
to write, and stopped cleanly. The Windows question comes **after**.

**Answer `Y`.** You lose nothing.

And now you no longer have to: the button exists.

## The passphrase is asked for first

Before, the screen displayed the address, "leave this window open", then
suddenly a bare line:

```
Wallet passphrase:
```

With nothing to announce it, after telling you that everything was running.
That was the wrong order. Now the window says it right away:

```
Q21 Wallet

  This wallet is protected by a passphrase.
```

and the passphrase is typed into the page that the browser opens, before
anything else. The wallet's address is only displayed **after** — when the
wallet is really open. A wrong passphrase fails right away, on that page,
instead of opening the wallet on a page that would be of no use.

## The window says how to stop it

The three ways, written out in black and white at startup:

```
  To stop, either:
    - the "Close the wallet" button, Info tab;
    - close this window;
    - Ctrl-C here. Windows then asks "Terminate batch job
      (Y/N)?": answer Y. This is not an error,
      everything is already saved when this question appears.
```

---

# The command that will save you round trips

```
q21 wallet --mine
```

The wallet **and** mining at the same time. Your transactions confirm on their
own within a few seconds, without stopping anything.

If you go through the double-click file, mining is not enabled — that is on
purpose, it would keep your processor busy all the time.

---

# What is still imperfect

- No QR code for receiving addresses
- The history goes back 5,000 blocks, no further — the page says so when it
  stops there
- The files are still not code-signed: Windows and macOS will display their
  warning, and they are right to do so
