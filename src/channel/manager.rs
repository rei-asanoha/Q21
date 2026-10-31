//! The node's channel manager: it owns the running [`Machine`]s, routes
//! inbound messages to the right channel, drives the protocol, and persists
//! through each channel's journal.
//!
//! # Framing
//!
//! A channel travels over the network as an opaque payload (see
//! [`crate::wire::Message::Channel`]), sealed in the authenticated session
//! between the two nodes ([`crate::channel::transport`], carried by
//! [`crate::channel::link`]). This module sees only what a session opened: a
//! 32-byte channel id, a one-byte kind, then a body. Two kinds are control
//! frames the manager handles itself — `Hello` and `HelloBack`, which
//! exchange the two parties' per-channel public keys before the funding policy
//! (and thus the channel id) can exist — and one kind carries an engine
//! [`crate::channel::messages::Message`] verbatim. Routing is by channel id,
//! except the two control frames, which are routed by peer (one open in flight
//! per peer).
//!
//! # Peers
//!
//! A peer is a connection with an established session, registered by
//! [`ChannelManager::on_session`] with the node id the session authenticated.
//! A channel is bound to that node id, journaled beside it, and to nothing
//! else: a frame for a channel is acted on only from a session authenticated
//! as the channel's counterparty, and a new session from it resynchronizes
//! every channel held with it, with a reestablish whose proof covers the
//! session's binding value.
//!
//! # Locking
//!
//! The manager holds its own mutex and never the node's chain lock. Signing and
//! verification happen under the manager mutex only. Anything that touches the
//! chain — building and broadcasting the funding transaction, broadcasting a
//! cooperative close or a penalty — is delegated to hooks the node installs,
//! which take the chain lock themselves, after the cryptography is done.

use crate::address::Network;
use crate::channel::keys::{ChannelKey, NodeIdentity, Signer, CHANNEL_SCHEME};
use crate::channel::machine::{channel_id, ChannelError, Machine, Phase, SyncVerdict};
use crate::channel::messages::Message as ChMsg;
use crate::channel::txbuild;
use crate::channel::verify;
use crate::channel::watcher::{OutputRef, Watch};
use crate::hash::Hash256;
use crate::ser::{Reader, Writer};
use crate::sig;
use crate::tx::{OutPoint, Transaction, TxOut};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const KIND_ENGINE: u8 = 0;
const KIND_HELLO: u8 = 1;
const KIND_HELLO_BACK: u8 = 2;
/// A contact verification message ([`crate::channel::verify`]). Sent only to
/// peers of protocol 6 or later: an older one counts an unknown kind against
/// the sender.
const KIND_VERIFY: u8 = 3;
/// How long a verification may wait for the other wallet before it is
/// dropped: the other holder declared a mismatch, closed its wallet, or never
/// answered. The words of a ready verification do not expire: the holder
/// reads them when the other person is on the phone.
pub const VERIFY_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Records whether the verification on `peer` now waits for the other
/// wallet, and drops those that waited too long.
fn track_waiting(inner: &mut Inner, peer: u64, now: std::time::Instant) {
    let waiting = matches!(
        inner.verifications.get(&peer),
        Some((
            verify::State::Committed { .. } | verify::State::Answered { .. },
            _
        ))
    );
    if waiting {
        inner.verify_waiting.entry(peer).or_insert(now);
    } else {
        inner.verify_waiting.remove(&peer);
    }
}

/// Drops the verifications that have waited longer than
/// [`VERIFY_WAIT_TIMEOUT`] for the other wallet.
fn expire_waiting(inner: &mut Inner, now: std::time::Instant) {
    expire_waiting_in(&mut inner.verifications, &mut inner.verify_waiting, now);
}

type Verifications = HashMap<u64, (verify::State, Option<std::time::Instant>)>;

fn expire_waiting_in(
    verifications: &mut Verifications,
    waiting: &mut HashMap<u64, std::time::Instant>,
    now: std::time::Instant,
) {
    let stale: Vec<u64> = waiting
        .iter()
        .filter(|(_, at)| now.saturating_duration_since(**at) >= VERIFY_WAIT_TIMEOUT)
        .map(|(p, _)| *p)
        .collect();
    for p in stale {
        waiting.remove(&p);
        if matches!(
            verifications.get(&p),
            Some((
                verify::State::Committed { .. } | verify::State::Answered { .. },
                _
            ))
        ) {
            verifications.remove(&p);
        }
    }
}

/// Fee reserved for a cooperative close, a penalty, or a sweep, in units. The
/// sweep builders cap it so a swept output never falls below the dust floor
/// (see [`crate::channel::txbuild::capped_fee`]).
pub const CLOSE_FEE: u64 = crate::channel::txbuild::SWEEP_FEE;

/// Builds and signs the funding transaction paying the given output, and
/// returns it — not broadcast: the manager broadcasts it only once the
/// acceptor has signed our first commitment. Takes the chain and wallet locks
/// itself.
pub type FundFn = dyn Fn(Hash256, TxOut) -> Result<Transaction, String> + Send + Sync;
/// Broadcasts a transaction (cooperative close, penalty, sweep) through the
/// normal mempool and relay.
pub type BroadcastFn = dyn Fn(&Transaction) -> Result<(), String> + Send + Sync;
/// Yields a fresh wallet address to receive swept or claimed funds.
pub type SweepAddrFn = dyn Fn() -> Hash256 + Send + Sync;
/// Holds back (`true`) or releases (`false`) the wallet coins a funding
/// transaction spends, so no other spend selects them while the funding is
/// signed but not yet confirmed. Idempotent; takes the wallet lock itself.
pub type ReserveFn = dyn Fn(&Transaction, bool) + Send + Sync;

/// How far back a startup rescan looks for a channel whose journal holds no
/// funding height (one opened before it was journaled).
pub const MAX_RESCAN_BLOCKS: u64 = 20_000;

/// The chain oracle the block hook and the startup rescan receive: for an
/// unspent outpoint, its confirmation depth (`1` in the tip) and the output
/// itself; `None` once it is spent or absent.
pub type DepthOf<'a> = dyn Fn(&OutPoint) -> Option<(u64, TxOut)> + 'a;

/// What the node must do for the manager when the chain is involved.
pub struct Hooks {
    pub fund: Box<FundFn>,
    pub broadcast: Box<BroadcastFn>,
    pub sweep_address: Box<SweepAddrFn>,
    /// See [`ReserveFn`]: from the funding's signature at Accept until it
    /// confirms, or until the channel is given up.
    pub reserve: Box<ReserveFn>,
    /// Yields a fresh wallet address to receive this party's cooperative-close
    /// payout — a real wallet address the wallet scans and can spend, never a
    /// channel key.
    pub payout_address: Box<SweepAddrFn>,
}

/// What handling one inbound frame produces.
#[derive(Default)]
pub struct Reaction {
    /// Opaque payloads to send back to the peer (already framed).
    pub frames: Vec<Vec<u8>>,
    /// Misconduct points for a malformed or out-of-place frame.
    pub penalize: u32,
}

/// A one-line summary of a channel, for the RPC.
#[derive(Clone, Debug)]
pub struct ChannelSummary {
    pub channel_id: Hash256,
    pub peer: u64,
    pub phase: Phase,
    pub capacity: u64,
    /// Ours irrevocably: what the counterparty can no longer take back by
    /// broadcasting a state it has not revoked (see
    /// [`Machine::irrevocable_balance`]).
    pub local_balance: u64,
    /// Paid to us in the latest state, not yet irrevocable: the payer has
    /// not revoked the state before it. `local_balance + pending_incoming +
    /// remote_balance` is the capacity.
    pub pending_incoming: u64,
    /// The counterparty's balance in the latest state.
    pub remote_balance: u64,
    pub state_number: u64,
    pub funding: Option<OutPoint>,
    /// An update is still settling: proposed, acknowledged, or a revocation
    /// still owed either way.
    pub in_flight: bool,
    /// The last transaction that ends the channel, once confirmed, and the
    /// height it confirmed at: the funds it pays are back in the wallets as
    /// soon as it is [`Self::funding_depth`] deep, long before the channel is
    /// marked closed at the settle depth ([`settle_depth`]).
    pub close_txid: Option<Hash256>,
    pub close_height: Option<u64>,
    /// The confirmations a funding waits for, also the depth a close is
    /// shown done at.
    pub funding_depth: u16,
    /// The to-self delay of a forced close, in blocks: how long the side
    /// that closes alone waits for its own funds, and how long the other side
    /// has to come back online and punish a revoked state.
    pub delay: u16,
    /// Whether we funded the channel: the capacity came from our wallet.
    pub we_funded: bool,
    /// The fee a close without the peer pays ([`FORCE_CLOSE_TIER`]), from the
    /// funder's side.
    pub force_close_fee: u64,
    /// Whether the peer's reestablish was answered on the current
    /// connection: until it is, no payment or close can start.
    pub synced: bool,
    /// When the transaction that ends the channel was first seen confirmed,
    /// in seconds since 1970, alongside [`Self::close_height`].
    pub close_time: Option<u64>,
    /// After our own commitment confirmed: the height from which our side,
    /// held by the delay, can be swept back to the wallet.
    pub release_height: Option<u64>,
    /// The node id the channel is bound to, as its session authenticated it.
    pub peer_identity: String,
    /// The identity address (hex) the peer's session proved, as a contact
    /// pins it: empty until a session with the peer has been seen.
    pub peer_owner: String,
    /// Our copy of the channel is older than the peer's: it can no longer be
    /// operated, the peer is to close it (see [`SyncVerdict::WeAreBehind`]).
    pub behind: bool,
    /// The peer's last reestablish showed an older copy of the channel than
    /// ours, once: closed with our latest state if the next session shows the
    /// same (see [`SyncVerdict::PeerIsBehind`]); the holder may close it now.
    pub peer_behind: bool,
}

/// How a channel ended, as its last phase before it was marked closed tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosedHow {
    /// Both sides signed the final balances.
    Cooperative,
    /// A commitment was broadcast, by either side, and settled after its delay.
    Forced,
    /// A revoked commitment was broadcast and punished.
    Penalty,
    /// Closed before this was recorded (a journal from 0.5.2 or earlier).
    Unknown,
}

impl ClosedHow {
    pub fn as_str(self) -> &'static str {
        match self {
            ClosedHow::Cooperative => "cooperative",
            ClosedHow::Forced => "forced",
            ClosedHow::Penalty => "penalty",
            ClosedHow::Unknown => "unknown",
        }
    }

    fn parse(s: &str) -> ClosedHow {
        match s {
            "cooperative" => ClosedHow::Cooperative,
            "forced" => ClosedHow::Forced,
            "penalty" => ClosedHow::Penalty,
            _ => ClosedHow::Unknown,
        }
    }
}

/// A closed channel, for the archives: what was put in, what came back, when.
#[derive(Clone, Debug)]
pub struct ArchivedChannel {
    pub channel_id: Hash256,
    pub peer_identity: String,
    /// The peer's identity address (hex), when it was recorded.
    pub peer_owner: String,
    pub capacity: u64,
    pub we_funded: bool,
    /// Our balance in the last state, before any on-chain fee.
    pub final_local: u64,
    /// The counterparty's balance in the last state.
    pub final_remote: u64,
    /// When the channel was closed, in seconds since 1970: when the
    /// transaction that ended it was seen confirmed; for a channel closed
    /// before this was recorded, when its journal was last written.
    pub closed_time: u64,
    /// The height that transaction confirmed at, when recorded.
    pub closed_height: Option<u64>,
    pub how: ClosedHow,
    /// Payments made in the channel, from its history.
    pub payments: usize,
}

/// One payment in a channel's history: the state it settled in, when, and
/// how much our balance moved (negative: we paid; positive: we were paid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub state: u64,
    pub time: u64,
    pub delta: i128,
}

/// The time now, in seconds since 1970; 0 on a clock set before it.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses a channel history: lines `state time balance`, in the order they
/// were appended. A state appears once (the first line wins: a payment is
/// dated when it settled), states are taken in order, and each entry is the
/// move of our balance from the state before. `initial` is our balance in
/// the first commitment. A malformed line is skipped: the history is a
/// courtesy, never what the channel's funds depend on.
pub fn parse_history(text: &str, initial: u64) -> Vec<HistoryEntry> {
    let mut by_state: std::collections::BTreeMap<u64, (u64, u64)> = Default::default();
    for line in text.lines() {
        let mut it = line.split_ascii_whitespace();
        let (Some(a), Some(b), Some(c), None) = (it.next(), it.next(), it.next(), it.next()) else {
            continue;
        };
        let (Ok(state), Ok(time), Ok(balance)) =
            (a.parse::<u64>(), b.parse::<u64>(), c.parse::<u64>())
        else {
            continue;
        };
        by_state.entry(state).or_insert((time, balance));
    }
    let mut out = Vec::new();
    let mut previous = initial;
    for (state, (time, balance)) in by_state {
        let delta = i128::from(balance) - i128::from(previous);
        previous = balance;
        if delta != 0 {
            out.push(HistoryEntry { state, time, delta });
        }
    }
    out
}

struct Chan {
    machine: Machine,
    /// The live network connection id of the peer. Transient: it changes on
    /// every reconnect and is re-bound at the reestablish of the next session
    /// authenticated as `peer_identity`.
    peer: u64,
    /// The counterparty's node id (hex), as its session authenticated it,
    /// persisted beside the journal: what the channel is bound to. A journal
    /// written before the transport holds a legacy id there instead (see
    /// [`is_node_id`]), replaced at the first reestablish that proves the
    /// channel's funding key over an authenticated session.
    peer_identity: String,
    /// The identity address the peer's session proved, persisted beside the
    /// journal once seen: it names the contact the channel is with, also
    /// while the peer is offline and once the channel is archived. Display
    /// only: nothing the channel accepts depends on it.
    peer_owner: Option<Hash256>,
    /// A reestablish that showed the peer's copy older than ours: its
    /// counters, ours then, and the session it came over. A second session
    /// showing the same, with nothing moved in between, closes the channel.
    peer_behind: Option<([u64; 4], [u64; 4], [u8; 32])>,
    /// The height the transaction that ends the channel confirmed at, and
    /// when this node first saw it there: the date the archives give the
    /// close. Persisted beside the journal.
    closing: Option<(u64, u64)>,
    capacity: u64,
    /// Whether the peer's reestablish has been received and answered on the
    /// current connection. Until it has, a message one side lost may still be
    /// owed, and a new update or close stacked on top of it would be refused
    /// by the peer; so neither starts before. A channel opened on the current
    /// connection starts synchronized.
    synced: bool,
    /// What the channel is waiting for on chain, once a commitment has been
    /// broadcast. `None` while the channel is still off-chain or settled.
    close: Option<CloseTracker>,
    /// The confirmed spend of the funding output the channel last reacted to.
    /// A funding output is spent once per chain: a different spend means the
    /// first left the chain in a reorganization, and the new one is
    /// classified afresh — a revoked commitment that replaced the latest one
    /// is still punished.
    spend: Option<Hash256>,
    /// Whether the coins of our funding transaction are held back in the
    /// wallet (see [`ReserveFn`]).
    reserved: bool,
    /// A transaction other than our funding seen confirmed spending one of
    /// its coins, with its height: once that is buried, the funding can never
    /// confirm and the channel is given up.
    conflict: Option<(Hash256, u64)>,
    /// The last state written to the channel's history (see
    /// [`ChannelManager::note_history`]).
    logged: Option<u64>,
    /// Our copy of the channel is older than the peer's (see
    /// [`SyncVerdict::WeAreBehind`]): nothing may be signed or broadcast on
    /// it. Persisted beside the journal, so a restart keeps it.
    behind: bool,
}

/// What a closing channel is waiting for on chain, so the block hook can finish
/// the close without any further message from the peer.
enum CloseTracker {
    /// Our own commitment is confirmed; its `to_local` output can be swept only
    /// after `delay` blocks have passed since `commit_height`.
    DelayedSweep {
        to_local: OutputRef,
        state: u64,
        delay: u16,
        commit_height: u64,
    },
    /// A finalizing transaction (claim, or delayed sweep) has been broadcast;
    /// the channel is settled once the output it spends is spent on chain — by
    /// this transaction, or by an earlier version of it broadcast before a
    /// restart. Kept whole, to be broadcast again after a restart.
    Finalizing { spends: OutPoint, tx: Transaction },
    /// A penalty has been broadcast at [`txbuild::penalty_fee`], with the
    /// claim of our own `to_remote` in the revoked commitment when it has
    /// one. While either stays unconfirmed it is announced again at every
    /// block, for the nodes that dropped it or never had it. Settled once
    /// the revoked output is spent — by the penalty, by a version built
    /// before a restart, or, too late, by the cheater — and our `to_remote`
    /// is spent too: `swept` and `claimed` name the spends seen.
    Penalty {
        watch: Box<Watch>,
        current: Transaction,
        claim: Option<Transaction>,
        swept: Option<Hash256>,
        claimed: Option<Hash256>,
    },
    /// The transactions `by` that end the channel confirmed, the last at
    /// `height`. The channel is marked closed — and no longer reloaded — only
    /// once that is buried to the settle depth; until then a reorganization
    /// that takes any of them off the chain brings back what was awaited.
    Settling {
        by: Vec<Hash256>,
        height: u64,
        prior: Option<Box<CloseTracker>>,
    },
}

/// Channels we accepted that are not yet funded on chain, across all peers.
/// Each holds a journal and is reloaded at every start until it opens or
/// expires. Counted apart from the ones we open, which they never block.
pub const MAX_UNFUNDED_CHANNELS: usize = 32;
/// Channels we accepted from one peer — by connection or announced identity —
/// that are not yet funded on chain.
pub const MAX_UNFUNDED_PER_PEER: usize = 4;
/// Channels we open whose funding is not on chain yet.
pub const MAX_UNFUNDED_OUTBOUND: usize = 32;
/// How long a channel may wait for its funding before it is forgotten, its
/// journal deleted — only when nothing is at stake: our side accepted it and
/// put nothing in, or we fund it and never broadcast the funding.
pub const UNFUNDED_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
/// How long a channel we accepted may wait for the funder's Funding message:
/// an honest funder sends it within a round trip of our Accept.
pub const INBOUND_FUNDING_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Opens in progress from one announced identity, whatever its connections.
pub const MAX_PENDING_PER_IDENTITY: usize = 2;

/// Key indices from this one up are derived for the channels we accept (see
/// [`ChannelManager::acceptor_index`]); below it they count the channels we
/// open.
const ACCEPTOR_INDEX_BASE: u32 = 0x8000_0000;

/// Key indices from this one up to [`ACCEPTOR_INDEX_BASE`] are counted for
/// the channels we accept, from 0.5.3 on: counted, so that a wallet restored
/// from its backup code can derive them again and find what a peer's close
/// paid to them. Below it they count the channels we open; from
/// [`ACCEPTOR_INDEX_BASE`] up, the indices derived from the funder's key that
/// 0.5.2 and earlier gave the channels they accepted.
pub const ACCEPTOR_COUNTER_BASE: u32 = 0x4000_0000;

/// Indices of each kind derived beyond the last one used when looking for
/// funds a close paid to a channel key: a wallet restored from its backup
/// code knows none of its channels.
pub const KEY_SCAN_WINDOW: u32 = 200;

/// How long a claim of a key output is remembered, in blocks: past it, an
/// output still there is claimed again, and the memory of claims stays
/// bounded.
const CLAIM_MEMORY_BLOCKS: u64 = 1_000;

/// Why a channel whose copy is older than the peer's refuses everything.
const BEHIND: &str =
    "this copy of the channel is older than your contact's (restored from a backup?): \
     it can no longer be operated from here. Ask your contact to close it: your side \
     comes back to your wallet";

/// The fee tier of every commitment we broadcast to close without the peer.
/// The highest one: there is neither replacement nor child-pays-for-parent,
/// so the version broadcast is the one that must get through a congested
/// pool; the medium tier left funds frozen for as long as a congestion
/// lasted. The funder's balance always covers it (the state machine refuses
/// any state where it would not), and at the relay floor it costs a few
/// thousand units.
pub const FORCE_CLOSE_TIER: crate::channel::txbuild::FeeTier =
    crate::channel::txbuild::FeeTier::High;

/// Channels one peer may hold with this node at once, settled ones aside.
pub const MAX_CHANNELS_PER_PEER: usize = 8;
/// Channel opens waiting for the peer's next message, across all peers, on
/// each side of the handshake.
pub const MAX_PENDING_OPENS: usize = 16;
/// How long an open may wait for the peer's next message before it is
/// forgotten: an honest handshake answers within seconds, and a peer that
/// sent a `Hello` and vanished must not hold a slot forever.
pub const PENDING_OPEN_TTL: std::time::Duration = std::time::Duration::from_secs(120);

struct PendingFunder {
    since: std::time::Instant,
    index: u32,
    capacity: u64,
    delay: u16,
    depth: u16,
    our_payout: Hash256,
    peer_identity: String,
}

struct PendingAcceptor {
    since: std::time::Instant,
    index: u32,
    funder_pubkey: Vec<u8>,
    capacity: u64,
    delay: u16,
    depth: u16,
    funder_payout: Hash256,
    our_payout: Hash256,
    peer_identity: String,
}

/// A connection whose session is established: what it authenticated.
struct Link {
    /// The peer's node id, hex ([`is_node_id`]).
    identity: String,
    /// The peer's legacy node id, hex, as it signed it in the handshake.
    legacy: String,
    /// The session's binding value: the nonce its reestablish proofs sign.
    binding: [u8; 32],
    /// The hash of the key the session proved, as an ML-DSA-87 address: what
    /// owns the peer's names, and what a contact pins. Set right after the
    /// session is recorded ([`ChannelManager::set_session_owner`]).
    owner: Option<Hash256>,
}

/// Sessions established at once. A connection holds at most one, and the
/// link layer bounds connections; this only caps the map.
const MAX_LINKS: usize = 1024;

struct Inner {
    channels: HashMap<Hash256, Chan>,
    /// Connections with an established session, by connection id.
    links: HashMap<u64, Link>,
    pending_funder: HashMap<u64, PendingFunder>,
    pending_acceptor: HashMap<u64, PendingAcceptor>,
    next_index: u32,
    /// See [`PENDING_OPEN_TTL`]; shortened by tests.
    pending_ttl: std::time::Duration,
    /// See [`UNFUNDED_TTL`]; shortened by tests.
    unfunded_ttl: std::time::Duration,
    /// See [`INBOUND_FUNDING_TTL`]; shortened by tests.
    inbound_funding_ttl: std::time::Duration,
    /// A wallet payout address offered in a Hello or HelloBack and not yet
    /// used by a channel: offered again until one is, so opens that never
    /// complete do not grow the wallet by an address each.
    spare_payout: Option<Hash256>,
    /// Contact verifications, by connection: where each stands, and when its
    /// last commitment arrived.
    verifications: Verifications,
    /// Since when each verification has been waiting for the other wallet
    /// (committed or answered, words not drawn yet). See
    /// [`VERIFY_WAIT_TIMEOUT`].
    verify_waiting: HashMap<u64, std::time::Instant>,
    /// Channels found closed in their journals at start: no longer operated,
    /// still shown, so a restart does not erase what the holder did.
    archived: Vec<ArchivedChannel>,
    /// The next counted acceptor index, past [`ACCEPTOR_COUNTER_BASE`].
    next_acceptor: u32,
    /// Acceptor indices offered in a HelloBack whose open never came:
    /// offered again first, so Hellos that lead nowhere spend no index.
    free_acceptor: Vec<u32>,
    /// The channel keys looked at for funds a close paid them, by the hash
    /// an output names: derived once (see [`ChannelManager::recover_key_outputs`]).
    key_hashes: Option<(u32, u32, HashMap<Hash256, u32>)>,
    /// Outputs paying a channel key already claimed, with the height of the
    /// claim: claimed again only if still unspent a few blocks later.
    claimed: HashMap<OutPoint, u64>,
}

impl Inner {
    /// Forgets the opens that waited too long for the peer.
    fn expire_pending(&mut self) {
        let ttl = self.pending_ttl;
        self.pending_funder.retain(|_, p| p.since.elapsed() < ttl);
        let mut freed = Vec::new();
        self.pending_acceptor.retain(|_, p| {
            let keep = p.since.elapsed() < ttl;
            if !keep {
                freed.push(p.index);
            }
            keep
        });
        self.free_counted(freed);
    }

    /// Gives counted acceptor indices back, for the next Hello.
    fn free_counted(&mut self, indices: Vec<u32>) {
        for i in indices {
            if (ACCEPTOR_COUNTER_BASE..ACCEPTOR_INDEX_BASE).contains(&i)
                && !self.free_acceptor.contains(&i)
            {
                self.free_acceptor.push(i);
            }
        }
    }

    /// Channels whose funding is not on chain yet: those we accepted
    /// (`inbound`), or those we open.
    fn unfunded(&self, inbound: bool) -> usize {
        self.unfunded_iter(inbound).count()
    }

    fn unfunded_iter_mut(&mut self, inbound: bool) -> impl Iterator<Item = &mut Chan> {
        let side = if inbound {
            crate::channel::txbuild::ACCEPTOR
        } else {
            crate::channel::txbuild::FUNDER
        };
        self.channels.values_mut().filter(move |c| {
            matches!(c.machine.phase(), Phase::Opening | Phase::Funded)
                && c.machine.our_index() == side
        })
    }

    fn unfunded_iter(&self, inbound: bool) -> impl Iterator<Item = &Chan> {
        let side = if inbound {
            crate::channel::txbuild::ACCEPTOR
        } else {
            crate::channel::txbuild::FUNDER
        };
        self.channels.values().filter(move |c| {
            matches!(c.machine.phase(), Phase::Opening | Phase::Funded)
                && c.machine.our_index() == side
        })
    }

    /// Unfunded channels we accepted from a peer, by connection or identity.
    fn unfunded_inbound_with(&self, peer: u64, identity: &str) -> usize {
        self.unfunded_iter(true)
            .filter(|c| c.peer == peer || (!identity.is_empty() && c.peer_identity == identity))
            .count()
    }

    /// Room for one more channel accepted from this peer.
    fn inbound_room(&self, peer: u64, identity: &str) -> bool {
        self.unfunded(true) < MAX_UNFUNDED_CHANNELS
            && self.unfunded_inbound_with(peer, identity) < MAX_UNFUNDED_PER_PEER
    }

    /// Channels held with a peer, known by its connection id or its durable
    /// identity, settled ones aside.
    fn channels_with(&self, peer: u64, identity: &str) -> usize {
        self.channels
            .values()
            .filter(|c| c.machine.phase() != Phase::Closed)
            .filter(|c| c.peer == peer || (!identity.is_empty() && c.peer_identity == identity))
            .count()
    }
}

/// Seals a frame into a peer's session and queues it (see
/// [`ChannelManager::send`]); installed by the link layer.
pub type SendFn = dyn Fn(u64, Vec<u8>) -> bool + Send + Sync;

pub struct ChannelManager {
    network: Network,
    base_fee_rate: u64,
    wallet_seed: [u8; 32],
    /// The static identity the transport authenticates this node by.
    identity: NodeIdentity,
    /// Where [`ChannelManager::send`] goes: the link layer's sealing send.
    outbound: std::sync::RwLock<Option<Box<SendFn>>>,
    journal_dir: PathBuf,
    default_delay: u16,
    default_depth: u16,
    hooks: Hooks,
    inner: Mutex<Inner>,
    /// Set while [`ChannelManager::rescan`] replays past blocks: reactions are
    /// computed but nothing is broadcast until the replay reaches the tip.
    replaying: AtomicBool,
    /// Transactions decided while the channel lock was held, broadcast once
    /// it is released (the broadcast hook takes the chain lock).
    to_broadcast: Mutex<Vec<(Transaction, &'static str)>>,
}

fn write_frame(cid: Hash256, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(33 + body.len());
    w.bytes(cid.as_bytes());
    w.u8(kind);
    w.bytes(body);
    w.finish()
}

impl ChannelManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        base_fee_rate: u64,
        wallet_seed: [u8; 32],
        journal_dir: PathBuf,
        default_delay: u16,
        default_depth: u16,
        hooks: Hooks,
    ) -> ChannelManager {
        let mgr = ChannelManager {
            network,
            base_fee_rate,
            identity: NodeIdentity::derive(&wallet_seed),
            outbound: std::sync::RwLock::new(None),
            wallet_seed,
            journal_dir,
            default_delay,
            default_depth,
            hooks,
            replaying: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                channels: HashMap::new(),
                links: HashMap::new(),
                pending_funder: HashMap::new(),
                pending_acceptor: HashMap::new(),
                next_index: 0,
                pending_ttl: PENDING_OPEN_TTL,
                spare_payout: None,
                unfunded_ttl: UNFUNDED_TTL,
                inbound_funding_ttl: INBOUND_FUNDING_TTL,
                verifications: HashMap::new(),
                verify_waiting: HashMap::new(),
                archived: Vec::new(),
                next_acceptor: 0,
                free_acceptor: Vec::new(),
                key_hashes: None,
                claimed: HashMap::new(),
            }),
            to_broadcast: Mutex::new(Vec::new()),
        };
        // Reload every channel persisted under `journal_dir`, so a restart —
        // clean or after a crash — finds its channels again, with the watcher
        // armed, instead of an empty map over funds it can no longer manage.
        mgr.reload();
        mgr
    }

    /// Enumerates the journal directory and replays each channel back into the
    /// map. Each journal's signing key is the wallet key at some channel index;
    /// the index is not stored, so we recover it by deriving keys in order and
    /// matching the public key the opening record carries. On regtest a handful
    /// of indices are in play, so the search is short and runs once at startup.
    fn reload(&self) {
        let entries = match std::fs::read_dir(&self.journal_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        use crate::channel::journal::{Journal, Record};
        // (journal path, our funding pubkey, journaled key index) for every
        // intact channel journal.
        let mut found: Vec<(PathBuf, Vec<u8>, Option<u32>)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jrnl") {
                continue;
            }
            let (_journal, records) = match Journal::open(&path) {
                Ok(j) => j,
                Err(e) => {
                    // Left as it is: the channel is not managed until the
                    // journal is recovered, but nothing in it is destroyed.
                    eprintln!("ALERT: {e}; this channel is not loaded");
                    continue;
                }
            };
            let Some(Record::Opened {
                our_pubkey,
                key_index,
                ..
            }) = records.first()
            else {
                continue;
            };
            // In the opening record; in journals written before it was, in a
            // record of its own.
            let index = key_index.or_else(|| {
                records.iter().find_map(|r| match r {
                    Record::KeyIndex { index } => Some(*index),
                    _ => None,
                })
            });
            found.push((path, our_pubkey.clone(), index));
        }
        let mut g = self.inner.lock().unwrap();
        g.next_index = self.read_next_index();
        g.next_acceptor = self.read_next_acceptor();
        let mut legacy = Vec::new();
        for (path, pubkey, index) in found {
            // The journaled index, checked against the key it must give.
            match index.filter(|&i| self.signer(i).pubkey() == pubkey.as_slice()) {
                Some(i) => self.load_channel(&mut g, &path, i),
                None => legacy.push((path, pubkey)),
            }
        }
        if legacy.is_empty() {
            return;
        }
        // Journals written before the index was: find it by deriving keys in
        // order. The cap bounds the search.
        let cap = (legacy.len() as u32)
            .saturating_mul(64)
            .saturating_add(1024)
            .max(g.next_index.saturating_add(64));
        let mut index = 0u32;
        while !legacy.is_empty() && index < cap {
            let pk = self.signer(index).pubkey().to_vec();
            if let Some(pos) = legacy.iter().position(|(_, candidate)| *candidate == pk) {
                let (path, _) = legacy.remove(pos);
                self.load_channel(&mut g, &path, index);
            }
            index += 1;
        }
        // A journal no key of this wallet opens: its channel cannot be
        // operated, and its funds may need attention. Never silently.
        for (path, _) in legacy {
            eprintln!(
                "ALERT: channel journal {} matches no key of this wallet; the channel is not loaded",
                path.display()
            );
        }
    }

    /// Reopens one channel journal with the key at `index` and adds it, unless
    /// settled.
    fn load_channel(&self, g: &mut Inner, path: &std::path::Path, index: u32) {
        if index < ACCEPTOR_COUNTER_BASE {
            g.next_index = g.next_index.max(index + 1);
        } else if index < ACCEPTOR_INDEX_BASE {
            g.next_acceptor = g.next_acceptor.max(index - ACCEPTOR_COUNTER_BASE + 1);
        }
        match Machine::reopen(path, self.network, self.signer(index), self.base_fee_rate) {
            Ok(mut machine) => {
                let _ = machine.note_key_index(index);
                if matches!(machine.phase(), Phase::Closed) {
                    // Not operated any more; kept for the archives, unless it
                    // never reached the chain (an abandoned open moved no
                    // funds and is no history).
                    if self.reached_chain(&machine) {
                        let entry = self.archived_entry(&machine, path);
                        g.archived.push(entry);
                    }
                    return;
                }
                let cid = machine.channel_id();
                let capacity = machine.params().capacity.units();
                // The peer's connection is transient; its node id, persisted
                // in a sidecar, tells which session the channel is with.
                let peer_identity = self.read_peer_identity(cid);
                let behind = self.behind_path(cid).exists();
                let peer_owner = self.read_owner(cid);
                let closing = self.read_closing(cid);
                g.channels.insert(
                    cid,
                    Chan {
                        machine,
                        peer: u64::MAX,
                        peer_identity,
                        peer_owner,
                        peer_behind: None,
                        closing,
                        capacity,
                        synced: false,
                        close: None,
                        spend: None,
                        reserved: false,
                        conflict: None,
                        logged: None,
                        behind,
                    },
                );
            }
            Err(e) => eprintln!(
                "ALERT: channel journal {} could not be reopened: {e:?}",
                path.display()
            ),
        }
    }

    /// Shortens how long an open may wait for the peer (see
    /// [`PENDING_OPEN_TTL`]), for tests.
    #[doc(hidden)]
    pub fn set_pending_open_ttl(&self, ttl: std::time::Duration) {
        self.inner.lock().unwrap().pending_ttl = ttl;
    }

    /// Opens waiting for the peer: `(as funder, as acceptor)`.
    pub fn pending_opens(&self) -> (usize, usize) {
        let mut g = self.inner.lock().unwrap();
        g.expire_pending();
        (g.pending_funder.len(), g.pending_acceptor.len())
    }

    /// The network the channels live on.
    pub fn network(&self) -> Network {
        self.network
    }

    /// This node's channel identity, the key its transport sessions are
    /// authenticated with.
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// This node's full node id (64 hex): what a peer's session authenticates
    /// it as, and what the peer binds its channels with us to.
    pub fn node_id(&self) -> String {
        self.identity
            .id()
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The authenticated node id (hex) of the session on connection `peer`.
    pub fn peer_node_id(&self, peer: u64) -> Option<String> {
        let g = self.inner.lock().unwrap();
        g.links.get(&peer).map(|l| l.identity.clone())
    }

    /// Records the identity address the session on `peer` proved.
    pub fn set_session_owner(&self, peer: u64, owner: Hash256) {
        let mut g = self.inner.lock().unwrap();
        if let Some(l) = g.links.get_mut(&peer) {
            l.owner = Some(owner);
        }
        self.fill_owners(&mut g);
    }

    /// The identity address the session on connection `peer` proved: the
    /// hash of its key, as the owner of its names.
    pub fn peer_owner(&self, peer: u64) -> Option<Hash256> {
        let g = self.inner.lock().unwrap();
        g.links.get(&peer).and_then(|l| l.owner)
    }

    /// The binding value of the session on connection `peer`.
    pub fn session_binding(&self, peer: u64) -> Option<[u8; 32]> {
        let g = self.inner.lock().unwrap();
        g.links.get(&peer).map(|l| l.binding)
    }

    /// A connection whose session proved `owner`, if any (the lowest id).
    pub fn connection_of_owner(&self, owner: &Hash256) -> Option<u64> {
        let g = self.inner.lock().unwrap();
        g.links
            .iter()
            .filter(|(_, l)| l.owner.as_ref() == Some(owner))
            .map(|(id, _)| *id)
            .min()
    }

    /// This node's identity address: the hash of its identity key, as the
    /// owner of its names.
    pub fn own_owner(&self) -> Hash256 {
        crate::sig::pubkey_hash(CHANNEL_SCHEME, self.identity.pubkey())
    }

    // --- Contact verification ----------------------------------------------

    /// Starts verifying the peer on connection `peer` with `count` words.
    /// The caller checked that the peer speaks protocol 6.
    pub fn start_verification(&self, peer: u64, count: u8) -> Result<(), String> {
        if count != verify::WORDS_DEFAULT && count != verify::WORDS_STRONG {
            return Err("4 or 6 words".into());
        }
        let id = crate::rng::bytes::<{ verify::ID_LEN }>().map_err(|e| format!("{e:?}"))?;
        let nonce = crate::rng::bytes::<32>().map_err(|e| format!("{e:?}"))?;
        let frame = {
            let mut g = self.inner.lock().unwrap();
            expire_waiting(&mut g, std::time::Instant::now());
            if !g.links.get(&peer).is_some_and(|l| l.owner.is_some()) {
                return Err("no session with this peer".into());
            }
            if matches!(g.verifications.get(&peer), Some((verify::State::Failed, _))) {
                return Err(
                    "the words did not match on this connection: reconnect to verify again".into(),
                );
            }
            let (state, msg) = verify::start(count, id, nonce);
            g.verifications.insert(peer, (state, None));
            g.verify_waiting.remove(&peer);
            track_waiting(&mut g, peer, std::time::Instant::now());
            write_frame(Hash256::ZERO, KIND_VERIFY, &msg.encode())
        };
        if self.send(peer, frame) {
            Ok(())
        } else {
            Err("the peer is not connected".into())
        }
    }

    fn on_verify(&self, peer: u64, binding: [u8; 32], body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let msg = verify::VerifyMsg::decode(body).ok_or("bad verification message")?;
        let fresh = crate::rng::bytes::<32>().map_err(|e| format!("{e:?}"))?;
        let us = self.own_owner();
        let mut g = self.inner.lock().unwrap();
        let Some(them) = g.links.get(&peer).and_then(|l| l.owner) else {
            return Ok(Vec::new());
        };
        let now = std::time::Instant::now();
        let entry = g.verifications.get(&peer);
        // A commitment per second at most: each one asks the other holder to
        // read words, and a flood of them is an annoyance, not a protocol.
        if matches!(msg, verify::VerifyMsg::Commit { .. })
            && entry
                .and_then(|(_, at)| *at)
                .is_some_and(|at| now.duration_since(at) < std::time::Duration::from_secs(1))
        {
            return Err("verification requests too fast".into());
        }
        let parties = verify::Parties {
            binding,
            us,
            peer: them,
        };
        let is_commit = matches!(msg, verify::VerifyMsg::Commit { .. });
        let last = entry.and_then(|(_, at)| *at);
        match verify::receive(entry.map(|(s, _)| s), msg, &parties, fresh) {
            Ok((state, reply)) => {
                g.verifications
                    .insert(peer, (state, if is_commit { Some(now) } else { last }));
                if is_commit {
                    g.verify_waiting.remove(&peer);
                }
                track_waiting(&mut g, peer, now);
                Ok(reply
                    .map(|m| vec![write_frame(Hash256::ZERO, KIND_VERIFY, &m.encode())])
                    .unwrap_or_default())
            }
            // Out of order, or refused after a mismatch: dropped, not
            // charged. A crossing or a late message is not misconduct.
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Where the verification on connection `peer` stands.
    pub fn verification(&self, peer: u64) -> Option<verify::State> {
        let mut g = self.inner.lock().unwrap();
        expire_waiting(&mut g, std::time::Instant::now());
        g.verifications.get(&peer).map(|(s, _)| s.clone())
    }

    /// Every verification under way or ready, by connection, with the
    /// identity address its session proved.
    pub fn verifications(&self) -> Vec<(u64, Hash256, verify::State)> {
        let mut g = self.inner.lock().unwrap();
        expire_waiting(&mut g, std::time::Instant::now());
        let mut v: Vec<(u64, Hash256, verify::State)> = g
            .verifications
            .iter()
            .filter_map(|(p, (s, _))| {
                g.links
                    .get(p)
                    .and_then(|l| l.owner)
                    .map(|o| (*p, o, s.clone()))
            })
            .collect();
        v.sort_by_key(|(p, _, _)| *p);
        v
    }

    /// The holder read the words: `matched` or not. A match ends the
    /// verification; a mismatch refuses any other on this connection.
    pub fn conclude_verification(&self, peer: u64, matched: bool) {
        let mut g = self.inner.lock().unwrap();
        if matched {
            g.verifications.remove(&peer);
        } else {
            g.verifications.insert(peer, (verify::State::Failed, None));
        }
        g.verify_waiting.remove(&peer);
    }

    /// Installs where [`ChannelManager::send`] goes.
    pub fn set_outbound(&self, send: Box<SendFn>) {
        if let Ok(mut g) = self.outbound.write() {
            *g = Some(send);
        }
    }

    /// Sends a frame this manager produced to `peer`, sealed in its session.
    /// False when the peer holds no session, or nothing is installed.
    pub fn send(&self, peer: u64, frame: Vec<u8>) -> bool {
        match self.outbound.read() {
            Ok(g) => g.as_ref().is_some_and(|f| f(peer, frame)),
            Err(_) => false,
        }
    }

    /// The payout address to offer in a Hello or HelloBack: the spare one if
    /// any, else a fresh wallet address — drawn without the manager's lock
    /// held, since drawing one writes the wallet.
    fn spare_payout(&self) -> Hash256 {
        if let Some(p) = self.inner.lock().unwrap().spare_payout {
            return p;
        }
        let fresh = (self.hooks.payout_address)();
        *self.inner.lock().unwrap().spare_payout.get_or_insert(fresh)
    }

    /// The shortest to-self delay we accept from a funder: our own default
    /// delay, never below the network's floor.
    pub fn acceptor_min_delay(&self) -> u16 {
        let terms = crate::channel::terms(self.network);
        self.default_delay.max(terms.min_delay).min(terms.max_delay)
    }

    /// The key index of a channel we accept: counted from
    /// [`ACCEPTOR_COUNTER_BASE`], so that a wallet restored from its backup
    /// code derives it again (see [`Self::recover_key_outputs`]). An index
    /// offered to a Hello that led nowhere is offered again first, so Hellos
    /// that never become channels spend none. Until 0.5.2 the index derived
    /// from the funder's key, which nothing but the channel's journal could
    /// find again.
    fn acceptor_index(&self, g: &mut Inner) -> u32 {
        if let Some(i) = g.free_acceptor.pop() {
            return i;
        }
        let i = ACCEPTOR_COUNTER_BASE + g.next_acceptor;
        g.next_acceptor += 1;
        let _ = crate::channel::journal::atomic_write(
            &self.journal_dir.join("next_acceptor_index"),
            &g.next_acceptor.to_le_bytes(),
        );
        i
    }

    fn read_next_acceptor(&self) -> u32 {
        std::fs::read(self.journal_dir.join("next_acceptor_index"))
            .ok()
            .and_then(|b| {
                b.get(..4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            })
            .unwrap_or(0)
    }

    fn next_index_path(&self) -> PathBuf {
        self.journal_dir.join("next_index")
    }

    fn write_next_index(&self, next: u32) {
        let _ = crate::channel::journal::atomic_write(&self.next_index_path(), &next.to_le_bytes());
    }

    fn read_next_index(&self) -> u32 {
        std::fs::read(self.next_index_path())
            .ok()
            .and_then(|b| {
                b.get(..4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            })
            .unwrap_or(0)
    }

    fn signer(&self, index: u32) -> Box<dyn Signer> {
        Box::new(ChannelKey::derive(&self.wallet_seed, index))
    }

    /// The sidecar file holding the node id a channel is bound to, beside its
    /// journal. Kept out of the journal so the engine's crash-safe record
    /// format is untouched. It decides which session the channel listens to,
    /// not what the channel accepts: every frame that moves it is signed by
    /// the counterparty's funding key.
    fn peer_identity_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.peer", cid.to_hex()))
    }

    fn write_peer_identity(&self, cid: Hash256, identity: &str) {
        let _ = crate::channel::journal::atomic_write(
            &self.peer_identity_path(cid),
            identity.as_bytes(),
        );
    }

    /// The sidecar holding the identity address of a channel's peer, in hex.
    fn owner_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.owner", cid.to_hex()))
    }

    fn write_owner(&self, cid: Hash256, owner: &Hash256) {
        let _ =
            crate::channel::journal::atomic_write(&self.owner_path(cid), owner.to_hex().as_bytes());
    }

    fn read_owner(&self, cid: Hash256) -> Option<Hash256> {
        let text = std::fs::read_to_string(self.owner_path(cid)).ok()?;
        Hash256::from_hex(text.trim())
    }

    /// Gives the channels whose peer's identity address is not known yet the
    /// one a session with the same node id has proved, and keeps it.
    fn fill_owners(&self, g: &mut Inner) {
        let Inner {
            channels, links, ..
        } = g;
        for c in channels.values_mut().filter(|c| c.peer_owner.is_none()) {
            let found = links
                .values()
                .find(|l| !c.peer_identity.is_empty() && l.identity == c.peer_identity)
                .and_then(|l| l.owner);
            if let Some(o) = found {
                self.write_owner(c.machine.channel_id(), &o);
                c.peer_owner = Some(o);
            }
        }
    }

    /// The sidecar marking a channel whose copy is older than the peer's.
    fn behind_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.behind", cid.to_hex()))
    }

    fn write_behind(&self, cid: Hash256) {
        let _ = crate::channel::journal::atomic_write(&self.behind_path(cid), b"behind\n");
    }

    /// The sidecar recording how and when a channel ended: `height time how`.
    fn end_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.end", cid.to_hex()))
    }

    /// The sidecar listing the channel's settled states, one line each:
    /// `state time our_balance`. Kept out of the journal, whose records the
    /// channel's safety depends on; this one only tells the holder what
    /// happened.
    fn history_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.history", cid.to_hex()))
    }

    /// Records how a channel ended, once its last transaction confirmed at
    /// `height`, dated when that confirmation was first seen. Best effort:
    /// the archives fall back on the journal's date.
    fn write_end(&self, cid: Hash256, height: u64, how: ClosedHow) {
        let time = self
            .read_closing(cid)
            .filter(|(h, _)| *h == height)
            .map_or_else(unix_now, |(_, t)| t);
        let line = format!("{height} {time} {}\n", how.as_str());
        let _ = crate::channel::journal::atomic_write(&self.end_path(cid), line.as_bytes());
    }

    /// The sidecar dating the confirmation of the transaction that ends a
    /// channel: `height time`.
    fn closing_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.closing", cid.to_hex()))
    }

    fn read_closing(&self, cid: Hash256) -> Option<(u64, u64)> {
        let text = std::fs::read_to_string(self.closing_path(cid)).ok()?;
        let mut it = text.split_ascii_whitespace();
        let height = it.next()?.parse().ok()?;
        let time = it.next()?.parse().ok()?;
        Some((height, time))
    }

    /// Dates the confirmation of the transaction that ends a channel, the
    /// first time it is seen at its height (again after a reorganization
    /// moved it).
    fn note_closing(&self, chan: &mut Chan) {
        let Some(CloseTracker::Settling { height, .. }) = &chan.close else {
            return;
        };
        let height = *height;
        if chan.closing.is_some_and(|(h, _)| h == height) {
            return;
        }
        let seen = (height, unix_now());
        let _ = crate::channel::journal::atomic_write(
            &self.closing_path(chan.machine.channel_id()),
            format!("{} {}\n", seen.0, seen.1).as_bytes(),
        );
        chan.closing = Some(seen);
    }

    /// Appends the channel's latest state to its history once it has
    /// settled: no update in flight, and a state not written yet.
    fn note_history(&self, chan: &mut Chan) {
        if chan.machine.update_in_flight() {
            return;
        }
        let Some(state) = chan.machine.local_commit_number() else {
            return;
        };
        if chan.logged.is_some_and(|l| l >= state) {
            return;
        }
        let us = chan.machine.our_index();
        let balance = chan.machine.latest_balances()[us];
        let line = format!("{state} {} {balance}\n", unix_now());
        let path = self.history_path(chan.machine.channel_id());
        use std::io::Write;
        let ok = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .is_ok();
        if ok {
            chan.logged = Some(state);
        }
    }

    /// Our balance when the channel opened: the whole capacity for the
    /// funder, nothing for the acceptor.
    fn initial_balance(machine: &Machine) -> u64 {
        if machine.our_index() == crate::channel::txbuild::FUNDER {
            machine.params().capacity.units()
        } else {
            0
        }
    }

    /// The payments made in a channel, oldest first.
    pub fn history(&self, cid: Hash256) -> Vec<HistoryEntry> {
        let initial = {
            let g = self.inner.lock().unwrap();
            match g.channels.get(&cid) {
                Some(c) => Self::initial_balance(&c.machine),
                None => match g.archived.iter().find(|a| a.channel_id == cid) {
                    Some(a) if a.we_funded => a.capacity,
                    Some(_) => 0,
                    None => return Vec::new(),
                },
            }
        };
        let text = std::fs::read_to_string(self.history_path(cid)).unwrap_or_default();
        parse_history(&text, initial)
    }

    /// The archive entry of a closed channel reopened from `path`.
    fn archived_entry(&self, machine: &Machine, path: &std::path::Path) -> ArchivedChannel {
        let cid = machine.channel_id();
        let us = machine.our_index();
        let bal = machine.latest_balances();
        let end = std::fs::read_to_string(self.end_path(cid)).ok();
        let mut fields = end.as_deref().unwrap_or("").split_ascii_whitespace();
        let height = fields.next().and_then(|v| v.parse::<u64>().ok());
        let time = fields.next().and_then(|v| v.parse::<u64>().ok());
        let how = fields
            .next()
            .map(ClosedHow::parse)
            .unwrap_or(ClosedHow::Unknown);
        let time = time.unwrap_or_else(|| {
            std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
        let history = std::fs::read_to_string(self.history_path(cid)).unwrap_or_default();
        ArchivedChannel {
            channel_id: cid,
            peer_identity: self.read_peer_identity(cid),
            peer_owner: self.read_owner(cid).map(|o| o.to_hex()).unwrap_or_default(),
            capacity: machine.params().capacity.units(),
            we_funded: us == crate::channel::txbuild::FUNDER,
            final_local: bal[us],
            final_remote: bal[1 - us],
            closed_time: time,
            closed_height: height,
            how,
            payments: parse_history(&history, Self::initial_balance(machine)).len(),
        }
    }

    /// Whether a closed channel ever held funds on chain: its funding was seen
    /// confirmed, or its end was recorded. An open given up before its
    /// funding confirmed moved nothing, and has no place in the archives.
    fn reached_chain(&self, machine: &Machine) -> bool {
        machine.funding_height().is_some() || self.end_path(machine.channel_id()).exists()
    }

    /// Every closed channel: those found closed at start, and those closed
    /// since, most recent first.
    pub fn archived(&self) -> Vec<ArchivedChannel> {
        let g = self.inner.lock().unwrap();
        let mut out = g.archived.clone();
        for c in g.channels.values() {
            if c.machine.phase() == Phase::Closed && self.reached_chain(&c.machine) {
                out.push(
                    self.archived_entry(&c.machine, &self.journal_path(c.machine.channel_id())),
                );
            }
        }
        out.sort_by_key(|a| std::cmp::Reverse(a.closed_time));
        out
    }

    fn read_peer_identity(&self, cid: Hash256) -> String {
        std::fs::read(self.peer_identity_path(cid))
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default()
    }

    fn journal_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.jrnl", cid.to_hex()))
    }

    // --- Operations the node/RPC initiate --------------------------------

    /// Opens a channel to `peer` as funder, returning the control frame to
    /// send. The funding policy — and thus the channel id — cannot exist until
    /// the acceptor's key is known, so this first exchanges keys. The channel
    /// is with the node id `peer`'s session authenticated, whoever that is.
    pub fn open(
        &self,
        peer: u64,
        capacity: u64,
        delay: Option<u16>,
        depth: Option<u16>,
    ) -> Result<Vec<u8>, String> {
        let identity = self
            .peer_node_id(peer)
            .ok_or("the peer holds no authenticated channel session")?;
        let peer_identity = identity.as_str();
        let our_payout = self.spare_payout();
        let mut g = self.inner.lock().unwrap();
        g.expire_pending();
        if g.pending_funder.len() >= MAX_PENDING_OPENS && !g.pending_funder.contains_key(&peer) {
            return Err("too many channel opens in progress".into());
        }
        if g.channels_with(peer, peer_identity) >= MAX_CHANNELS_PER_PEER {
            return Err("too many channels with this peer".into());
        }
        if g.unfunded(false) >= MAX_UNFUNDED_OUTBOUND {
            return Err("too many channels waiting for their funding".into());
        }
        let index = g.next_index;
        if index >= ACCEPTOR_INDEX_BASE {
            return Err("channel key indices exhausted".into());
        }
        g.next_index += 1;
        // The counter survives a restart: an index once offered to a peer is
        // never handed to another channel.
        self.write_next_index(g.next_index);
        let delay = delay.unwrap_or(self.default_delay);
        let depth = depth.unwrap_or(self.default_depth);
        let our_pubkey = self.signer(index).pubkey().to_vec();
        g.pending_funder.insert(
            peer,
            PendingFunder {
                since: std::time::Instant::now(),
                index,
                capacity,
                delay,
                depth,
                our_payout,
                peer_identity: peer_identity.to_string(),
            },
        );
        // Hello body: our funding pubkey, capacity, delay, depth, payout.
        let mut w = Writer::new();
        w.var_bytes(&our_pubkey);
        w.u64(capacity);
        w.bytes(&delay.to_le_bytes());
        w.bytes(&depth.to_le_bytes());
        w.bytes(our_payout.as_bytes());
        Ok(write_frame(Hash256::ZERO, KIND_HELLO, &w.finish()))
    }

    /// Makes a payment of `amount` to the peer on `cid`.
    pub fn pay(&self, cid: Hash256, amount: u64) -> Result<Vec<u8>, String> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        if chan.behind {
            return Err(BEHIND.into());
        }
        if chan.machine.phase() != Phase::Open {
            return Err("channel not open".into());
        }
        if !chan.synced {
            return Err("channel is not yet resynchronized with its peer".into());
        }
        // Derived from the persisted counters, so a proposal reloaded from the
        // journal after a crash still counts until the reestablish settles it.
        if chan.machine.update_in_flight() {
            return Err("a payment is already in flight".into());
        }
        let us = chan.machine.our_index();
        let mut bal = chan.machine.balances();
        if bal[us] < amount {
            return Err("insufficient channel balance".into());
        }
        bal[us] -= amount;
        bal[1 - us] += amount;
        let msg = chan.machine.propose(bal).map_err(err)?;
        Ok(write_frame(cid, KIND_ENGINE, &msg.encode()))
    }

    /// Proposes a cooperative close of `cid`, returning the `Close` frame to
    /// send. While a payment is still settling the close is agreed at once
    /// (no new payment starts) and its frame goes out when the payment
    /// completes, so this returns `None`. On a channel already closing
    /// cooperatively it returns the agreed `Close` again, so a close
    /// interrupted by a crash or a dropped link can be completed.
    pub fn close(&self, cid: Hash256) -> Result<Option<Vec<u8>>, String> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        if chan.behind {
            return Err(BEHIND.into());
        }
        if !chan.synced {
            return Err("channel is not yet resynchronized with its peer".into());
        }
        if chan.machine.update_in_flight() {
            chan.machine.agree_close(CLOSE_FEE, true).map_err(err)?;
            return Ok(None);
        }
        // Closing already on the peer's proposal: nothing of ours to send.
        if chan.machine.phase() == Phase::Closing && !chan.machine.closing_on_our_proposal() {
            return Ok(None);
        }
        let msg = chan.machine.propose_close(CLOSE_FEE).map_err(err)?;
        Ok(Some(write_frame(cid, KIND_ENGINE, &msg.encode())))
    }

    /// Signals that `cid`'s funding is buried to the agreed depth, returning
    /// the `ready` frame to send.
    pub fn funding_confirmed(&self, cid: Hash256) -> Result<Vec<u8>, String> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        let msg = chan.machine.funding_confirmed().map_err(err)?;
        Ok(write_frame(cid, KIND_ENGINE, &msg.encode()))
    }

    /// Called when the session on connection `peer` is established: `identity`
    /// is the node id it authenticated (hex), `legacy` the legacy node id it
    /// signed (hex), `binding` its binding value. Returns the reestablish of
    /// every channel held with that node id, to send on it: each proves our
    /// funding key over the binding, and the channel resynchronizes once the
    /// peer's own proof comes back on this session.
    ///
    /// A channel whose journal still names its peer by a legacy id is offered
    /// too when the session signed that id; it is bound to the session's node
    /// id only once the peer's reestablish proves the channel's funding key.
    pub fn on_session(
        &self,
        peer: u64,
        identity: &str,
        legacy: &str,
        binding: [u8; 32],
    ) -> Vec<Vec<u8>> {
        let mut g = self.inner.lock().unwrap();
        if g.links.len() >= MAX_LINKS && !g.links.contains_key(&peer) {
            return Vec::new();
        }
        g.links.insert(
            peer,
            Link {
                identity: identity.to_string(),
                legacy: legacy.to_string(),
                binding,
                owner: None,
            },
        );
        let mut out = Vec::new();
        for c in g.channels.values_mut() {
            if !bound_to(c, identity, legacy) {
                continue;
            }
            // A new session on the link the channel uses: whatever the last
            // one left unsent is owed again, so nothing new starts before the
            // reestablish. A second link leaves the current one alone.
            if c.peer == peer {
                c.synced = false;
            }
            let cid = c.machine.channel_id();
            out.push(write_frame(
                cid,
                KIND_ENGINE,
                &c.machine.reestablish_for(binding).encode(),
            ));
        }
        out
    }

    /// Called when the session on connection `peer` ends — the connection
    /// closed, or the session failed and a new one is to be negotiated.
    /// Nothing more is taken from it, and its channels wait for the next.
    pub fn on_session_closed(&self, peer: u64) {
        let mut g = self.inner.lock().unwrap();
        g.links.remove(&peer);
        g.verifications.remove(&peer);
        g.verify_waiting.remove(&peer);
        g.pending_funder.remove(&peer);
        g.pending_acceptor.remove(&peer);
        for c in g.channels.values_mut() {
            if c.peer == peer {
                c.synced = false;
            }
        }
    }

    /// Whether a channel not yet settled is held with the node `identity`
    /// (hex node id): its handshakes draw on a budget of their own (see
    /// [`crate::channel::link`]).
    pub fn holds_channel_with(&self, identity: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.channels
            .values()
            .any(|c| c.peer_identity == identity && c.machine.phase() != Phase::Closed)
    }

    /// Ends every session whose connection `keep` no longer holds, as
    /// [`ChannelManager::on_session_closed`] does: a connection may close
    /// while its handshake completes, before the link layer could say so.
    pub fn retain_sessions(&self, keep: &dyn Fn(u64) -> bool) {
        let gone: Vec<u64> = {
            let g = self.inner.lock().unwrap();
            g.links.keys().copied().filter(|p| !keep(*p)).collect()
        };
        for p in gone {
            self.on_session_closed(p);
        }
    }

    /// The connections with an established session, and the node id each
    /// authenticated.
    pub fn sessions(&self) -> Vec<(u64, String)> {
        let g = self.inner.lock().unwrap();
        let mut v: Vec<(u64, String)> = g
            .links
            .iter()
            .map(|(p, l)| (*p, l.identity.clone()))
            .collect();
        v.sort();
        v
    }

    // --- Inbound ----------------------------------------------------------

    /// Handles one frame a session opened on connection `peer`. A frame from
    /// a connection with no established session is ignored.
    pub fn deliver(&self, peer: u64, bytes: &[u8]) -> Reaction {
        let link = {
            let g = self.inner.lock().unwrap();
            g.links
                .get(&peer)
                .map(|l| (l.identity.clone(), l.legacy.clone(), l.binding))
        };
        let Some((identity, legacy, binding)) = link else {
            return Reaction::default();
        };
        let from = From {
            peer,
            identity: &identity,
            legacy: &legacy,
            binding,
        };
        let reaction = self.deliver_inner(&from, bytes);
        let decided = std::mem::take(&mut *self.to_broadcast.lock().unwrap());
        for (tx, what) in decided {
            self.broadcast_or_warn(&tx, what);
        }
        match reaction {
            Ok(frames) => Reaction {
                frames,
                penalize: 0,
            },
            Err(_) => Reaction {
                frames: Vec::new(),
                penalize: crate::net::MISCONDUCT_CHANNEL,
            },
        }
    }

    fn deliver_inner(&self, from: &From, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if bytes.len() < 33 {
            return Err("short frame".into());
        }
        let mut r = Reader::new(bytes);
        let cid = Hash256(r.array32().map_err(|_| "cid")?);
        let kind = r.u8().map_err(|_| "kind")?;
        let body = &bytes[33..];
        let (peer, peer_identity) = (from.peer, from.identity);
        match kind {
            KIND_HELLO => self.on_hello(peer, peer_identity, body),
            KIND_HELLO_BACK => self.on_hello_back(peer, peer_identity, body),
            KIND_VERIFY => self.on_verify(peer, from.binding, body),
            KIND_ENGINE => {
                let msg = ChMsg::decode(body).map_err(|_| "bad engine message")?;
                let out = self.on_engine(from, cid, msg);
                // A payment settles on a message from the peer: whatever this
                // one completed goes into the channel's history.
                if let Some(chan) = self.inner.lock().unwrap().channels.get_mut(&cid) {
                    self.note_history(chan);
                }
                out
            }
            _ => Err("unknown frame kind".into()),
        }
    }

    fn on_hello(
        &self,
        peer: u64,
        peer_identity: &str,
        body: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut r = Reader::new(body);
        let funder_pubkey = r.var_bytes().map_err(|_| "pubkey")?.to_vec();
        if funder_pubkey.len() != CHANNEL_SCHEME.pubkey_len() {
            return Err("pubkey length".into());
        }
        let capacity = r.u64().map_err(|_| "capacity")?;
        let delay = u16::from_le_bytes([r.u8().map_err(|_| "d")?, r.u8().map_err(|_| "d")?]);
        let depth = u16::from_le_bytes([r.u8().map_err(|_| "d")?, r.u8().map_err(|_| "d")?]);
        let funder_payout = Hash256(r.array32().map_err(|_| "payout")?);
        // The funder chooses the to-self delay, and the delay is how long we
        // may stay offline before a revoked state of theirs can no longer be
        // punished. We accept no less than what we would ask ourselves: the
        // network's floor (720 blocks on testnet, about a day) left whoever
        // accepted a channel a single day offline, and nothing told them.
        if delay < self.acceptor_min_delay() {
            return Ok(Vec::new());
        }
        // Bounded: opens in progress across all peers and per announced
        // identity (one per connection, by construction), and channels per
        // peer. Beyond any of them the Hello is not answered — the funder's
        // open lapses. Nothing persistent is spent on a Hello: the key index
        // derives from the funder's key, and the payout address offered is the
        // spare one, until a channel actually uses it.
        let admitted = |g: &mut Inner| {
            g.expire_pending();
            let full = g.pending_acceptor.len() >= MAX_PENDING_OPENS
                && !g.pending_acceptor.contains_key(&peer);
            let same_identity = !peer_identity.is_empty()
                && g.pending_acceptor
                    .iter()
                    .filter(|(p, a)| **p != peer && a.peer_identity == peer_identity)
                    .count()
                    >= MAX_PENDING_PER_IDENTITY;
            !full
                && !same_identity
                && g.channels_with(peer, peer_identity) < MAX_CHANNELS_PER_PEER
                && g.inbound_room(peer, peer_identity)
        };
        if !admitted(&mut self.inner.lock().unwrap()) {
            return Ok(Vec::new());
        }
        let our_payout = self.spare_payout();
        let mut g = self.inner.lock().unwrap();
        if !admitted(&mut g) {
            return Ok(Vec::new());
        }
        let index = self.acceptor_index(&mut g);
        let our_pubkey = self.signer(index).pubkey().to_vec();
        let replaced = g.pending_acceptor.insert(
            peer,
            PendingAcceptor {
                since: std::time::Instant::now(),
                index,
                funder_pubkey,
                capacity,
                delay,
                depth,
                funder_payout,
                our_payout,
                peer_identity: peer_identity.to_string(),
            },
        );
        if let Some(old) = replaced {
            g.free_counted(vec![old.index]);
        }
        // HelloBack body: our funding pubkey and our payout.
        let mut w = Writer::new();
        w.var_bytes(&our_pubkey);
        w.bytes(our_payout.as_bytes());
        Ok(vec![write_frame(
            Hash256::ZERO,
            KIND_HELLO_BACK,
            &w.finish(),
        )])
    }

    fn on_hello_back(
        &self,
        peer: u64,
        peer_identity: &str,
        body: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut r = Reader::new(body);
        let acceptor_pubkey = r.var_bytes().map_err(|_| "pubkey")?.to_vec();
        if acceptor_pubkey.len() != CHANNEL_SCHEME.pubkey_len() {
            return Err("pubkey length".into());
        }
        let acceptor_payout = Hash256(r.array32().map_err(|_| "payout")?);
        let mut g = self.inner.lock().unwrap();
        // Ours to the node id this connection's session authenticated; a
        // later session on it is another peer's until proven otherwise.
        if g.pending_funder
            .get(&peer)
            .is_some_and(|p| p.peer_identity != peer_identity)
        {
            return Ok(Vec::new());
        }
        let pending = g.pending_funder.remove(&peer).ok_or("no pending open")?;
        let signer = self.signer(pending.index);
        let funding = [
            signer.pubkey_hash(),
            sig::pubkey_hash(CHANNEL_SCHEME, &acceptor_pubkey),
        ];
        if g.spare_payout == Some(pending.our_payout) {
            g.spare_payout = None;
        }
        let cid = channel_id(&funding);
        let (machine, open) = Machine::new_funder(
            self.journal_path(cid),
            self.network,
            signer,
            acceptor_pubkey,
            pending.capacity,
            pending.delay,
            pending.depth,
            self.base_fee_rate,
            pending.our_payout,
            acceptor_payout,
        )
        .map_err(err)?;
        self.write_peer_identity(cid, &pending.peer_identity);
        let peer_owner = g.links.get(&peer).and_then(|l| l.owner);
        if let Some(o) = peer_owner {
            self.write_owner(cid, &o);
        }
        g.channels.insert(
            cid,
            Chan {
                machine,
                peer,
                peer_identity: pending.peer_identity,
                peer_owner,
                peer_behind: None,
                closing: None,
                capacity: pending.capacity,
                synced: true,
                close: None,
                spend: None,
                reserved: false,
                conflict: None,
                logged: None,
                behind: false,
            },
        );
        Ok(vec![write_frame(cid, KIND_ENGINE, &open.encode())])
    }

    fn on_engine(&self, from: &From, cid: Hash256, msg: ChMsg) -> Result<Vec<Vec<u8>>, String> {
        let (peer, peer_identity) = (from.peer, from.identity);
        // The acceptor's first engine message is the funder's Open: build the
        // channel from the pending acceptor state.
        if matches!(msg, ChMsg::Open { .. }) {
            return self.accept_open(peer, peer_identity, cid, msg);
        }
        let mut g = self.inner.lock().unwrap();
        // The sessions alive now, for a reestablish: one arriving over a
        // second session while the channel runs on another may be older than
        // the traffic that went over that one since it was sent.
        let live: Vec<u64> = if matches!(msg, ChMsg::Reestablish { .. }) {
            g.links.keys().copied().collect()
        } else {
            Vec::new()
        };
        let Some(chan) = g.channels.get_mut(&cid) else {
            // A peer that still tracks a channel we have settled and forgotten
            // (closed on our side, still closing on theirs) offers its
            // reestablish at every session. Penalising it dropped the link
            // at every reconnect; there is simply nothing to resynchronize.
            if matches!(msg, ChMsg::Reestablish { .. }) {
                return Ok(Vec::new());
            }
            return Err("unknown channel".into());
        };
        // Authentication. The session proved the sender's node id; a frame is
        // acted on only for a channel bound to that id. A frame for a channel
        // held with another node is ignored, not penalised: a node may hold
        // channels with several peers, and only learns which from the id.
        //
        // A reestablish is taken only over this session's own binding value,
        // which its proof signs with the channel's funding key: one captured
        // from an earlier session, or proven over another, is good for
        // nothing here. A channel journaled before the transport names its
        // peer by a legacy id; the session signed one, which proves nothing
        // alone, so such a channel takes only a reestablish, and is bound to
        // the session's node id once that proof verifies.
        match &msg {
            ChMsg::Reestablish { nonce, .. }
                if *nonce != from.binding || !bound_to(chan, peer_identity, from.legacy) =>
            {
                return Ok(Vec::new());
            }
            ChMsg::Reestablish { .. } => {}
            _ if chan.peer_identity != peer_identity => return Ok(Vec::new()),
            _ => {}
        }
        let mut out = Vec::new();
        match msg {
            ChMsg::Accept { .. } => {
                // A replayed Accept funds nothing again: the Funding already
                // built is sent again, if any.
                if chan.machine.accepted() {
                    if chan.machine.funding_outpoint().is_some() {
                        let m = chan.machine.funding_message().map_err(err)?;
                        out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
                    }
                    return Ok(out);
                }
                chan.machine.on_accept(&msg).map_err(err)?;
                // The funder builds and signs the funding transaction and tells
                // the acceptor its outpoint. It is broadcast only once the
                // acceptor's FundingSigned is in: broadcast earlier, the
                // capacity would sit in the 2-of-2 output with no commitment
                // the funder could enforce to get it back.
                let funding_output = chan.machine.funding_output();
                drop(g); // the fund hook takes the chain lock
                let tx = (self.hooks.fund)(cid, funding_output)?;
                // Its coins are held back at once: until it is broadcast, a
                // round trip from now, they are in no mempool, and any other
                // spend would choose them again.
                (self.hooks.reserve)(&tx, true);
                let built = (|| {
                    let index = tx
                        .outputs
                        .iter()
                        .position(|o| *o == funding_output)
                        .ok_or("the funding transaction does not pay the channel")?;
                    let outpoint = OutPoint {
                        txid: tx.txid(),
                        index: index as u32,
                    };
                    let mut g = self.inner.lock().unwrap();
                    let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
                    let m = chan.machine.funding_built(outpoint, &tx).map_err(err)?;
                    chan.reserved = true;
                    Ok::<_, String>(m)
                })();
                match built {
                    Ok(m) => out.push(write_frame(cid, KIND_ENGINE, &m.encode())),
                    Err(e) => {
                        (self.hooks.reserve)(&tx, false);
                        return Err(e);
                    }
                }
            }
            ChMsg::Funding { .. } => {
                let m = chan.machine.on_funding(&msg).map_err(err)?;
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
            }
            ChMsg::FundingSigned { .. } => {
                chan.machine.on_funding_signed(&msg).map_err(err)?;
                // We hold the acceptor's signature over our commitment 0: the
                // capacity can always come back. Now the funding goes out.
                let tx = chan.machine.funding_tx().cloned();
                drop(g);
                if let Some(tx) = tx {
                    self.broadcast_or_warn(&tx, "funding");
                }
            }
            ChMsg::Ready { .. } => {
                fresh(chan.machine.on_ready(&msg))?;
            }
            ChMsg::Update { .. } => {
                // An ordinary update, one crossing our own proposal (both ends
                // paid at once: the two are merged into the next state), or a
                // crossed proposal resent at a reestablish.
                for m in chan.machine.on_peer_update(&msg).map_err(err)? {
                    out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
                }
            }
            ChMsg::Ack { .. } => {
                let m = chan.machine.on_ack(&msg).map_err(err)?;
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
                out.extend(pending_close(chan, cid));
            }
            ChMsg::Revoke { .. } => {
                chan.machine.on_revoke(&msg).map_err(err)?;
                // The peer's revocation of crossed proposals: the merge may be
                // ours to propose now.
                if let Some(m) = chan.machine.merge_if_ready().map_err(err)? {
                    out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
                }
                out.extend(pending_close(chan, cid));
            }
            ChMsg::Close { .. } => {
                // Signed by the counterparty's funding key: from a connection
                // that merely relays both sides, an unsigned or replayed Close
                // moves nothing.
                if chan.machine.update_in_flight() {
                    // The peer's Close crossed an update still settling here:
                    // agree now, and send our own Close once the update
                    // completes; the peer signs that one.
                    fresh(chan.machine.on_close_crossing(&msg))?;
                } else if let Some(m) = fresh(chan.machine.on_close(&msg))? {
                    out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
                }
            }
            ChMsg::CloseSigned { .. } => {
                let already = chan.machine.has_signed_close();
                let tx = chan.machine.on_close_signed(&msg).map_err(err)?;
                drop(g);
                // Both sides may complete the same close after a reconnect; a
                // copy already in the mempool is no fault of the peer's.
                if !already {
                    self.broadcast_or_warn(&tx, "cooperative close");
                }
            }
            ChMsg::Reestablish {
                local_commit_number,
                remote_commit_number,
                next_revocation_sent,
                next_revocation_recv,
                ..
            } => {
                let theirs = [
                    local_commit_number,
                    remote_commit_number,
                    next_revocation_sent,
                    next_revocation_recv,
                ];
                // The channel runs, in step, over another session still
                // alive: this reestablish may predate payments made over that
                // one since, and would show the peer behind when it is not.
                // It is checked, and nothing more: the channel stays where it
                // runs.
                let elsewhere = chan.synced && chan.peer != peer && live.contains(&chan.peer);
                let frames = chan.machine.on_reestablish(&msg).map_err(err)?;
                if elsewhere && chan.machine.sync() != SyncVerdict::InStep {
                    return Ok(out);
                }
                // The channel's funding key proved itself over this session:
                // the channel's traffic goes over it from now on. A channel
                // still named by a legacy id is bound to the node id.
                chan.peer = peer;
                if chan.peer_identity != peer_identity {
                    chan.peer_identity = peer_identity.to_string();
                    self.write_peer_identity(cid, peer_identity);
                }
                match chan.machine.sync() {
                    SyncVerdict::InStep => {
                        for f in frames {
                            out.push(write_frame(cid, KIND_ENGINE, &f.encode()));
                        }
                        chan.synced = true;
                        chan.peer_behind = None;
                    }
                    // Our copy is older: our latest commitment may be one we
                    // revoked. Never signed nor broadcast from now on; the
                    // peer holds the latest state and closes with it, which
                    // pays our side to our channel key, claimed as usual.
                    SyncVerdict::WeAreBehind => {
                        if !chan.behind {
                            chan.behind = true;
                            self.write_behind(cid);
                            eprintln!(
                                "ALERT: channel {}: this copy of the channel is older than \
                                 the peer's (a data folder restored from a backup?). Do not \
                                 close it from here: the peer closes it with the latest state, \
                                 and our side comes back to the wallet",
                                cid.to_hex()
                            );
                        }
                    }
                    // The peer's copy is older: its latest commitment may be
                    // revoked, and broadcasting it would lose it the whole
                    // channel. Once is not proof enough — a reestablish held
                    // up in transit looks the same — so the first time it is
                    // noted, and the holder can close; a second session that
                    // shows the same, with nothing moved on either side in
                    // between, closes the channel with the latest state: the
                    // peer's side comes back to it at once, ours after the
                    // delay.
                    SyncVerdict::PeerIsBehind => {
                        let ours = chan.machine.sync_counters();
                        let confirmed = chan
                            .peer_behind
                            .is_some_and(|(t, o, b)| t == theirs && o == ours && b != from.binding);
                        if !confirmed {
                            if chan
                                .peer_behind
                                .map_or(true, |(t, o, _)| t != theirs || o != ours)
                            {
                                eprintln!(
                                    "ALERT: channel {}: the peer seems to run an older copy of \
                                     the channel; closed with the latest state if its next \
                                     session shows the same",
                                    cid.to_hex()
                                );
                            }
                            chan.peer_behind = Some((theirs, ours, from.binding));
                        } else if chan.machine.phase() == Phase::Open
                            || chan.machine.phase() == Phase::Closing
                        {
                            chan.peer_behind = None;
                            match chan.machine.force_close(FORCE_CLOSE_TIER) {
                                Ok(tx) => {
                                    eprintln!(
                                        "ALERT: channel {}: the peer runs an older copy of the \
                                         channel; closed with the latest state so that it \
                                         gets its funds back",
                                        cid.to_hex()
                                    );
                                    self.to_broadcast.lock().unwrap().push((tx, "commitment"));
                                }
                                Err(e) => eprintln!(
                                    "ALERT: channel {}: the peer runs an older copy of the \
                                     channel, and the close failed: {e:?}",
                                    cid.to_hex()
                                ),
                            }
                        }
                    }
                }
            }
            ChMsg::Error { .. } | ChMsg::Open { .. } => {}
        }
        Ok(out)
    }

    fn accept_open(
        &self,
        peer: u64,
        peer_identity: &str,
        cid: Hash256,
        open: ChMsg,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut g = self.inner.lock().unwrap();
        if g.pending_acceptor
            .get(&peer)
            .is_some_and(|p| p.peer_identity != peer_identity)
        {
            return Ok(Vec::new());
        }
        let pending = g
            .pending_acceptor
            .remove(&peer)
            .ok_or("no pending accept")?;
        // Checked again: other channels may have taken the room since the
        // Hello. Not answered, as a Hello beyond the bounds is not.
        if !g.inbound_room(peer, &pending.peer_identity) {
            return Ok(Vec::new());
        }
        // The engine Open must match what the Hello promised: same funder key
        // and same terms, or the peer changed its mind mid-handshake.
        if let ChMsg::Open {
            capacity,
            delay,
            funding_depth,
            funder_pubkey,
            ..
        } = &open
        {
            if *funder_pubkey != pending.funder_pubkey
                || *capacity != pending.capacity
                || *delay != pending.delay
                || *funding_depth != pending.depth
            {
                return Err("open does not match hello".into());
            }
        }
        let signer = self.signer(pending.index);
        let (machine, accept) = Machine::accept(
            self.journal_path(cid),
            self.network,
            signer,
            self.base_fee_rate,
            &open,
            pending.our_payout,
            pending.funder_payout,
        )
        .map_err(err)?;
        if machine.channel_id() != cid {
            return Err("channel id mismatch".into());
        }
        if g.spare_payout == Some(pending.our_payout) {
            g.spare_payout = None;
        }
        self.write_peer_identity(cid, &pending.peer_identity);
        let peer_owner = g.links.get(&peer).and_then(|l| l.owner);
        if let Some(o) = peer_owner {
            self.write_owner(cid, &o);
        }
        g.channels.insert(
            cid,
            Chan {
                machine,
                peer,
                peer_identity: pending.peer_identity,
                peer_owner,
                peer_behind: None,
                closing: None,
                capacity: pending.capacity,
                synced: true,
                close: None,
                spend: None,
                reserved: false,
                conflict: None,
                logged: None,
                behind: false,
            },
        );
        Ok(vec![write_frame(cid, KIND_ENGINE, &accept.encode())])
    }

    // --- Watcher ----------------------------------------------------------

    /// Examines a transaction that spends a channel's funding output and acts on
    /// it: a revoked broadcast is punished, the counterparty's latest is
    /// claimed. Returns the penalty/claim transaction broadcast, if any. This is
    /// the direct-call path (the node drives the full lifecycle through
    /// [`ChannelManager::on_connected_block`], which also schedules the delayed
    /// sweep of our own commitment).
    pub fn on_funding_spend(&self, cid: Hash256, tx: &Transaction) -> Option<Transaction> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid)?;
        let funding = chan.machine.funding_outpoint()?;
        chan.spend = Some(tx.txid());
        let decision = classify_spend(chan, funding, tx);
        let sweep_to = (self.hooks.sweep_address)();
        match decision {
            Watch::RevokedByPeer { .. } => self.start_penalty(chan, decision, sweep_to),
            Watch::PeerLatest {
                to_remote: Some(to_remote),
                ..
            } => {
                let claim = chan
                    .machine
                    .build_to_remote_claim(&to_remote, sweep_to, CLOSE_FEE);
                let _ = chan.machine.mark_forcing();
                chan.close = Some(CloseTracker::Finalizing {
                    spends: to_remote.outpoint,
                    tx: claim.clone(),
                });
                self.broadcast_or_warn(&claim, "to_remote claim");
                Some(claim)
            }
            _ => None,
        }
    }

    /// Drives every on-chain reaction for one connected block, off the chain
    /// lock: it records commitments that spend a funding output, confirms a
    /// funding buried to its agreed depth, schedules the delayed sweep of our
    /// own commitment, and settles a channel once its finalizing transaction
    /// confirms. `height` is the new tip; `depth_of` returns the confirmation
    /// depth (`1` in the tip) of an unspent outpoint, or `None` once it is
    /// spent or absent. Returns the frames to send, each with its peer.
    pub fn on_connected_block(
        &self,
        txs: &[Transaction],
        height: u64,
        depth_of: &DepthOf,
    ) -> Vec<(u64, Vec<u8>)> {
        self.watch_fundings(txs, height);
        self.react_to_spends(txs, height);
        let frames = self.confirm_buried(height, depth_of);
        self.advance_closes(txs, height);
        self.expire_unfunded(height, depth_of);
        self.tend_fundings(depth_of);
        frames
    }

    /// Follows our own fundings not yet open in the block at `height`: the
    /// funding itself confirming (its height journaled, so a restart scans
    /// from there), or another transaction spending one of its coins — the
    /// only conflict there is: the funding spending them is no conflict.
    fn watch_fundings(&self, txs: &[Transaction], height: u64) {
        let mut g = self.inner.lock().unwrap();
        for c in g.unfunded_iter_mut(false) {
            let Some(funding) = c.machine.funding_tx() else {
                continue;
            };
            let txid = funding.txid();
            let coins: Vec<OutPoint> = funding.inputs.iter().map(|i| i.prev_out).collect();
            if txs.iter().any(|t| t.txid() == txid) {
                let _ = c.machine.note_funding_height(height);
                c.conflict = None;
            } else if let Some(t) = txs
                .iter()
                .find(|t| t.inputs.iter().any(|i| coins.contains(&i.prev_out)))
            {
                c.conflict = Some((t.txid(), height));
            }
        }
    }

    /// Each block: our funding, signed for by the acceptor and still in no
    /// block, is announced again — a pool may have dropped it — and the coins
    /// of a channel past its opening are released.
    fn tend_fundings(&self, depth_of: &DepthOf) {
        let mut again = Vec::new();
        let mut release = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            for c in g.channels.values_mut() {
                let Some(tx) = c.machine.funding_tx().cloned() else {
                    continue;
                };
                let opening = matches!(c.machine.phase(), Phase::Opening | Phase::Funded);
                if c.reserved && (!opening || c.spend.is_some()) {
                    c.reserved = false;
                    release.push(tx.clone());
                }
                // Unconfirmed and unconflicted: every coin it spends is still
                // unspent on chain.
                let pending = c.machine.phase() == Phase::Funded
                    && c.spend.is_none()
                    && c.machine
                        .funding_outpoint()
                        .is_some_and(|op| depth_of(&op).is_none())
                    && tx.inputs.iter().all(|i| depth_of(&i.prev_out).is_some());
                if pending {
                    again.push(tx);
                }
            }
        }
        for tx in release {
            (self.hooks.reserve)(&tx, false);
        }
        for tx in again {
            self.broadcast_or_warn(&tx, "funding");
        }
    }

    /// Shortens how long a channel may wait for its funding (see
    /// [`UNFUNDED_TTL`]), for tests.
    #[doc(hidden)]
    pub fn set_unfunded_ttl(&self, ttl: std::time::Duration) {
        let mut g = self.inner.lock().unwrap();
        g.unfunded_ttl = ttl;
        g.inbound_funding_ttl = g.inbound_funding_ttl.min(ttl);
    }

    /// Forgets the channels that waited longer than [`UNFUNDED_TTL`] for a
    /// funding that is not on chain, deleting their journals — only those
    /// where nothing of ours is at stake: a channel we accepted (the funder
    /// alone puts funds in, and keeps our signature over its first commitment
    /// to recover them), or one we fund whose funding was never broadcast
    /// (we never received the acceptor's signature). A channel we funded and
    /// broadcast is kept: should its funding confirm late, our commitment is
    /// how the capacity comes back.
    ///
    /// A channel we accepted whose Funding never came waits only
    /// [`INBOUND_FUNDING_TTL`].
    fn expire_unfunded(&self, height: u64, depth_of: &DepthOf) {
        let mut g = self.inner.lock().unwrap();
        let (long, short) = (g.unfunded_ttl, g.inbound_funding_ttl);
        let ttl_of = |c: &Chan| {
            if c.machine.our_index() == crate::channel::txbuild::ACCEPTOR
                && c.machine.funding_outpoint().is_none()
            {
                short
            } else {
                long
            }
        };
        let stale: Vec<(Hash256, std::time::Duration)> = g
            .channels
            .values()
            .filter(|c| matches!(c.machine.phase(), Phase::Opening | Phase::Funded))
            .filter(|c| {
                c.machine.our_index() == crate::channel::txbuild::ACCEPTOR
                    || c.machine.local_commit_number().is_none()
            })
            .filter(|c| {
                c.machine
                    .funding_outpoint()
                    .map_or(true, |op| depth_of(&op).is_none())
            })
            .filter(|c| {
                let path = self.journal_path(c.machine.channel_id());
                std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age >= ttl_of(c))
            })
            .map(|c| (c.machine.channel_id(), ttl_of(c)))
            .collect();
        let mut release = Vec::new();
        for (cid, ttl) in stale {
            release.extend(self.forget(&mut g, cid));
            eprintln!(
                "channel {}: never funded; forgotten after waiting {}s",
                cid.to_hex(),
                ttl.as_secs()
            );
        }
        // Our funding, unconfirmed, one of whose coins another transaction
        // spent on chain: it can never confirm. Given up once that spend is
        // buried — the coins released, the channel marked abandoned, its
        // journal kept: were the funding on chain after all, its key and
        // commitments are still there to recover the capacity.
        let network = self.network;
        for c in g.unfunded_iter_mut(false) {
            let Some((_, at)) = c.conflict else {
                continue;
            };
            let funded = c
                .machine
                .funding_outpoint()
                .is_some_and(|op| depth_of(&op).is_some());
            let buried = height.saturating_add(1).saturating_sub(at)
                >= settle_depth(network, c.machine.funding_depth());
            if c.spend.is_some() || funded || c.machine.funding_height().is_some() || !buried {
                continue;
            }
            if c.machine.mark_abandoned().is_ok() {
                if c.reserved {
                    c.reserved = false;
                    release.extend(c.machine.funding_tx().cloned());
                }
                eprintln!(
                    "channel {}: a coin its funding spends was spent by another \
                     transaction; the funding can never confirm, channel abandoned",
                    c.machine.channel_id().to_hex()
                );
            }
        }
        drop(g);
        for tx in release {
            (self.hooks.reserve)(&tx, false);
        }
    }

    /// Drops a channel with nothing at stake, its journal and sidecar too.
    /// Returns its funding transaction if its coins were held back: the
    /// caller releases them (see [`ReserveFn`]) once the lock is dropped.
    fn forget(&self, g: &mut Inner, cid: Hash256) -> Option<Transaction> {
        let chan = g.channels.remove(&cid)?;
        let _ = std::fs::remove_file(self.journal_path(cid));
        let _ = std::fs::remove_file(self.peer_identity_path(cid));
        chan.reserved
            .then(|| chan.machine.funding_tx().cloned())
            .flatten()
    }

    /// Catches up, at startup, with what happened on chain while the node was
    /// down or before a crash: the close and penalty tracking lives in memory.
    ///
    /// For every reloaded channel whose funding output is spent at the tip,
    /// the blocks from the funding's confirmation height (journaled; without
    /// it, the last [`MAX_RESCAN_BLOCKS`]) up to the tip are replayed through
    /// the same reactions as live blocks: a revoked commitment is punished
    /// (and our own balance in it claimed), our
    /// own commitment's delayed sweep is scheduled, and a cooperative close, or
    /// a claim, sweep or penalty already confirmed, settles the channel once
    /// buried to the funding depth. Nothing is
    /// broadcast during the replay; at the tip, every transaction still
    /// awaited is broadcast once: a penalty, a claim or
    /// sweep, a cooperative close we hold signed, or our commitment if we were
    /// force-closing and it never confirmed. `txs_at` yields the transactions
    /// of the active chain's block at a height.
    pub fn rescan(
        &self,
        tip: u64,
        txs_at: &dyn Fn(u64) -> Option<Vec<Transaction>>,
        depth_of: &DepthOf,
    ) {
        let start = {
            let g = self.inner.lock().unwrap();
            g.channels
                .values()
                .filter(|c| {
                    let Some(op) = c.machine.funding_outpoint() else {
                        return false;
                    };
                    // Spent, or never seen confirmed: only a funding known to
                    // have confirmed is looked for — or our own funding one
                    // of whose coins is spent on chain: by the funding itself,
                    // confirmed (and maybe spent) while we were down, or by a
                    // conflict. Either is in the blocks scanned.
                    let coin_spent = c.machine.funding_tx().is_some_and(|tx| {
                        tx.inputs.iter().any(|i| depth_of(&i.prev_out).is_none())
                    });
                    depth_of(&op).is_none()
                        && (c.machine.funding_height().is_some()
                            || !matches!(c.machine.phase(), Phase::Opening | Phase::Funded)
                            || coin_spent)
                })
                .map(|c| {
                    c.machine
                        .funding_height()
                        .unwrap_or_else(|| tip.saturating_sub(MAX_RESCAN_BLOCKS))
                })
                .min()
        };
        if let Some(start) = start {
            self.replaying.store(true, Ordering::SeqCst);
            for h in start..=tip {
                if let Some(txs) = txs_at(h) {
                    self.watch_fundings(&txs, h);
                    self.react_to_spends(&txs, h);
                    self.advance_closes(&txs, h);
                }
            }
            self.replaying.store(false, Ordering::SeqCst);
        }
        self.resume_after_restart(depth_of);
    }

    /// Broadcasts, once, every transaction a channel still waits on (see
    /// [`ChannelManager::rescan`]).
    fn resume_after_restart(&self, depth_of: &DepthOf) {
        let mut pending: Vec<(Transaction, &'static str)> = Vec::new();
        let mut hold = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            for c in g.channels.values_mut() {
                // Our funding, signed and not yet on chain: its coins are held
                // back again (the wallet keeps that in memory only).
                if matches!(c.machine.phase(), Phase::Opening | Phase::Funded)
                    && c.machine
                        .funding_outpoint()
                        .is_some_and(|op| depth_of(&op).is_none())
                {
                    if let Some(tx) = c.machine.funding_tx() {
                        hold.push(tx.clone());
                        c.reserved = true;
                    }
                }
                // Our funding, signed for by the acceptor, not yet on chain: a
                // crash may have come before its broadcast, or lost it.
                if c.machine.phase() == Phase::Funded {
                    let unconfirmed = c
                        .machine
                        .funding_outpoint()
                        .is_some_and(|op| depth_of(&op).is_none());
                    if let (true, Some(tx)) = (unconfirmed, c.machine.funding_tx()) {
                        pending.push((tx.clone(), "funding"));
                    }
                }
                match &c.close {
                    Some(CloseTracker::Penalty {
                        current,
                        claim,
                        swept,
                        claimed,
                        ..
                    }) => {
                        if swept.is_none() {
                            pending.push((current.clone(), "penalty"));
                        }
                        if let (Some(claim), None) = (claim, claimed) {
                            pending.push((claim.clone(), "to_remote claim"));
                        }
                    }
                    Some(CloseTracker::Finalizing { tx, .. }) => {
                        pending.push((tx.clone(), "claim or sweep"));
                    }
                    Some(CloseTracker::DelayedSweep { .. } | CloseTracker::Settling { .. }) => {}
                    None => {
                        let unspent = c
                            .machine
                            .funding_outpoint()
                            .is_some_and(|op| depth_of(&op).is_some());
                        if !unspent {
                            continue;
                        }
                        match c.machine.phase() {
                            Phase::Funded => {}
                            Phase::Closing => {
                                if let Some(tx) = c.machine.signed_cooperative_close() {
                                    pending.push((tx, "cooperative close"));
                                }
                            }
                            // Never from an older copy: its latest commitment
                            // may be revoked.
                            Phase::Forcing if !c.behind => {
                                let latest = c.machine.local_commit_number().and_then(|n| {
                                    c.machine.signed_commitment_at(n, FORCE_CLOSE_TIER).ok()
                                });
                                if let Some(tx) = latest {
                                    pending.push((tx, "commitment"));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        for tx in hold {
            (self.hooks.reserve)(&tx, true);
        }
        for (tx, what) in pending {
            self.broadcast_or_warn(&tx, what);
        }
    }

    /// Forgets, for every channel, a funding spend that a reorganization took
    /// off the chain, with whatever the channel was waiting for after it. The
    /// spend that replaces it, if any, is classified afresh when its block is
    /// connected; if the same one comes back, it is re-armed from its new
    /// height.
    pub fn on_disconnected_block(&self, txs: &[Transaction]) {
        let gone: Vec<Hash256> = txs.iter().map(|t| t.txid()).collect();
        self.on_disconnected_txids(&gone);
    }

    /// [`ChannelManager::on_disconnected_block`], from the transaction ids.
    pub fn on_disconnected_txids(&self, txids: &[Hash256]) {
        let gone: std::collections::HashSet<Hash256> = txids.iter().copied().collect();
        let mut g = self.inner.lock().unwrap();
        for chan in g.channels.values_mut() {
            // The transaction that was settling the channel left the chain:
            // wait again for what it ended.
            if matches!(&chan.close, Some(CloseTracker::Settling { by, .. })
                if by.iter().any(|b| gone.contains(b)))
            {
                if let Some(CloseTracker::Settling { prior, .. }) = chan.close.take() {
                    chan.close = prior.map(|p| *p);
                }
            }
            // A penalty or claim seen confirmed that left the chain: awaited
            // again, and announced again at the next block.
            if let Some(CloseTracker::Penalty { swept, claimed, .. }) = &mut chan.close {
                if swept.is_some_and(|t| gone.contains(&t)) {
                    *swept = None;
                }
                if claimed.is_some_and(|t| gone.contains(&t)) {
                    *claimed = None;
                }
            }
            if chan.spend.is_some_and(|s| gone.contains(&s)) {
                chan.spend = None;
                chan.close = None;
            }
            if chan.conflict.is_some_and(|(t, _)| gone.contains(&t)) {
                chan.conflict = None;
            }
        }
    }

    /// Reacts to any funding-output spend in `txs`, recording the commitment and
    /// starting the right close path for each channel it concerns.
    fn react_to_spends(&self, txs: &[Transaction], height: u64) {
        let watched = self.watched_funding();
        if watched.is_empty() {
            return;
        }
        for tx in txs {
            for inp in &tx.inputs {
                if let Some((cid, _)) = watched.iter().find(|(_, o)| *o == inp.prev_out) {
                    self.react_to_spend(*cid, tx, height);
                }
            }
        }
    }

    fn react_to_spend(&self, cid: Hash256, tx: &Transaction, height: u64) {
        let mut g = self.inner.lock().unwrap();
        let Some(chan) = g.channels.get_mut(&cid) else {
            return;
        };
        let Some(funding) = chan.machine.funding_outpoint() else {
            return;
        };
        let txid = tx.txid();
        if chan.spend == Some(txid) {
            // The same spend again: a reorganization put it in a later block.
            // The clocks that count from its confirmation restart there.
            if let Some(CloseTracker::DelayedSweep { commit_height, .. }) = &mut chan.close {
                *commit_height = height;
            }
            return;
        }
        if chan.spend.is_some() {
            // A different spend of the funding output: the one we reacted to
            // left the chain. Whatever we were waiting for went with it.
            eprintln!(
                "channel {}: the funding output is now spent by {}; reclassifying",
                cid.to_hex(),
                txid.to_hex()
            );
            chan.close = None;
        }
        chan.spend = Some(txid);
        // The cooperative close we agreed to, broadcast by the peer: settled.
        if chan.machine.is_cooperative_close(tx) {
            settle(chan, txid, height);
            return;
        }
        let decision = classify_spend(chan, funding, tx);
        let sweep_to = (self.hooks.sweep_address)();
        match decision {
            Watch::RevokedByPeer { .. } => {
                let _ = self.start_penalty(chan, decision, sweep_to);
            }
            Watch::PeerLatest { to_remote, .. } => {
                let _ = chan.machine.mark_forcing();
                match to_remote {
                    Some(to_remote) => {
                        let claim = chan
                            .machine
                            .build_to_remote_claim(&to_remote, sweep_to, CLOSE_FEE);
                        chan.close = Some(CloseTracker::Finalizing {
                            spends: to_remote.outpoint,
                            tx: claim.clone(),
                        });
                        self.broadcast_or_warn(&claim, "to_remote claim");
                    }
                    // Our funds were trimmed to dust: nothing to claim, settled.
                    None => settle(chan, txid, height),
                }
            }
            Watch::OurCommitment {
                state,
                to_local,
                delay,
            } => {
                let _ = chan.machine.mark_forcing();
                match to_local {
                    Some(to_local) => {
                        chan.close = Some(CloseTracker::DelayedSweep {
                            to_local,
                            state,
                            delay,
                            commit_height: height,
                        });
                    }
                    // Our own output was trimmed to dust: nothing to sweep.
                    None => settle(chan, txid, height),
                }
            }
            Watch::NotOurChannel | Watch::Unrecognized => {}
        }
    }

    /// Confirms the funding of every channel buried to its agreed depth, moving
    /// it to open and returning the `ready` frame to send its peer.
    fn confirm_buried(&self, height: u64, depth_of: &DepthOf) -> Vec<(u64, Vec<u8>)> {
        let mut g = self.inner.lock().unwrap();
        // Where each funding confirmed, journaled once: a restarted node scans
        // from there for a spend it missed while down. Recorded for any channel
        // whose funding is on chain, so one opened before this was journaled
        // gets it at the next block.
        let mut confirmed = Vec::new();
        for c in g.channels.values_mut() {
            if let Some((depth, _)) = c.machine.funding_outpoint().and_then(|op| depth_of(&op)) {
                let at = height.saturating_add(1).saturating_sub(depth);
                if c.machine.funding_height() != Some(at) {
                    let _ = c.machine.note_funding_height(at);
                }
                // Our funding is on chain: its coins are spent, nothing left
                // to hold back.
                if c.reserved {
                    c.reserved = false;
                    confirmed.extend(c.machine.funding_tx().cloned());
                }
            }
        }
        // The outpoint the funder named must be the channel's funding output:
        // the 2-of-2 policy, for the whole capacity. An outpoint names one
        // output forever, so any other is final: a channel we accepted on it
        // is forgotten at once — the funder alone would have put funds in,
        // and nothing on chain backs it. Left waiting, any existing coin
        // named by a stranger held one of the bounded unfunded slots for good.
        let named_elsewhere: Vec<Hash256> = g
            .unfunded_iter(true)
            .filter(|c| {
                c.machine
                    .funding_outpoint()
                    .and_then(|op| depth_of(&op))
                    .is_some_and(|(_, output)| output != c.machine.funding_output())
            })
            .map(|c| c.machine.channel_id())
            .collect();
        for cid in named_elsewhere {
            eprintln!(
                "channel {}: the announced funding output is not the channel's 2-of-2 \
                 output for its capacity; forgotten",
                cid.to_hex()
            );
            let _ = self.forget(&mut g, cid);
        }
        let ready: Vec<(Hash256, u64)> = g
            .channels
            .values()
            // A channel waiting on its funding: the funder sits in `Funded`, the
            // acceptor in `Opening` with its first commitment already signed.
            // Either way the funding outpoint and commitment zero are known.
            .filter(|c| {
                matches!(c.machine.phase(), Phase::Funded | Phase::Opening)
                    && c.machine.local_commit_number().is_some()
            })
            .filter_map(|c| {
                let op = c.machine.funding_outpoint()?;
                let (depth, output) = depth_of(&op)?;
                // Ours, as funder, cannot differ; never open on another one.
                if output != c.machine.funding_output() {
                    if depth == 1 {
                        eprintln!(
                            "ALERT: channel {}: the announced funding output is not the \
                             channel's 2-of-2 output for its capacity; not opening",
                            c.machine.channel_id().to_hex()
                        );
                    }
                    return None;
                }
                (depth >= u64::from(c.machine.funding_depth()))
                    .then_some((c.machine.channel_id(), c.peer))
            })
            .collect();
        let mut frames = Vec::new();
        for (cid, peer) in ready {
            if let Some(chan) = g.channels.get_mut(&cid) {
                if let Ok(msg) = chan.machine.funding_confirmed() {
                    frames.push((peer, write_frame(cid, KIND_ENGINE, &msg.encode())));
                }
            }
        }
        drop(g);
        for tx in confirmed {
            (self.hooks.reserve)(&tx, false);
        }
        frames
    }

    /// Advances every channel settling on chain: broadcasts the delayed sweep of
    /// our own commitment once its `Older(D)` has matured, and moves a channel to
    /// `closed` (or `penalised` then `closed`) when its finalizing transaction
    /// confirms in this block.
    fn advance_closes(&self, txs: &[Transaction], height: u64) {
        let mut g = self.inner.lock().unwrap();
        let cids: Vec<Hash256> = g.channels.keys().copied().collect();
        for cid in cids {
            let Some(chan) = g.channels.get_mut(&cid) else {
                continue;
            };
            match &chan.close {
                Some(CloseTracker::DelayedSweep {
                    to_local,
                    state,
                    delay,
                    commit_height,
                }) => {
                    // Our to_local spent before we swept it: only the
                    // revocation branch can do that, so the commitment was a
                    // revoked one — a journal restored from an old copy. Waiting
                    // for a sweep that can never confirm would hold the channel
                    // forever.
                    let outpoint = to_local.outpoint;
                    if let Some(by) = spender(txs, outpoint) {
                        eprintln!(
                            "ALERT: channel {}: our to_local was taken by a penalty; the \
                             broadcast commitment had been revoked",
                            cid.to_hex()
                        );
                        settle(chan, by, height);
                        self.note_closing(chan);
                        if let Some((at, how)) = finish_settling(chan, height, self.network) {
                            self.write_end(cid, at, how);
                        }
                        continue;
                    }
                    // `Older(D)` is satisfied once the chain is `D` blocks past
                    // the commitment: height >= commit_height + D.
                    if height >= commit_height.saturating_add(u64::from(*delay)) {
                        // A fresh wallet address only when a sweep is built,
                        // not one per channel at every block.
                        let sweep_to = (self.hooks.sweep_address)();
                        let watch = Watch::OurCommitment {
                            state: *state,
                            to_local: Some(*to_local),
                            delay: *delay,
                        };
                        if let Ok(sweep) =
                            chan.machine.build_local_sweep(&watch, sweep_to, CLOSE_FEE)
                        {
                            chan.close = Some(CloseTracker::Finalizing {
                                spends: to_local.outpoint,
                                tx: sweep.clone(),
                            });
                            self.broadcast_or_warn(&sweep, "delayed sweep");
                        }
                    }
                }
                Some(CloseTracker::Finalizing { spends, .. }) => {
                    if let Some(by) = spender(txs, *spends) {
                        settle(chan, by, height);
                    }
                }
                Some(CloseTracker::Penalty { .. }) => self.advance_penalty(chan, txs, height),
                Some(CloseTracker::Settling { .. }) | None => {}
            }
            self.note_closing(chan);
            if let Some((at, how)) = finish_settling(chan, height, self.network) {
                self.write_end(cid, at, how);
            }
        }
    }

    /// Builds and broadcasts the penalty against a revoked commitment, at
    /// [`txbuild::penalty_fee`], and the claim of our own `to_remote` there,
    /// and keeps both to announce again until they settle.
    fn start_penalty(
        &self,
        chan: &mut Chan,
        watch: Watch,
        sweep_to: Hash256,
    ) -> Option<Transaction> {
        // The weight does not depend on the fee: build once to weigh it.
        let draft = chan
            .machine
            .build_penalty(&watch, sweep_to, CLOSE_FEE)
            .ok()?;
        let penalty = chan
            .machine
            .build_penalty(&watch, sweep_to, txbuild::penalty_fee(&draft))
            .ok()?;
        // Our own balance in the revoked state pays our channel key, as in
        // any commitment: claimed to the wallet like the peer's latest.
        let claim = match &watch {
            Watch::RevokedByPeer {
                to_remote: Some(to_remote),
                ..
            } => Some(
                chan.machine
                    .build_to_remote_claim(to_remote, sweep_to, CLOSE_FEE),
            ),
            _ => None,
        };
        let _ = chan.machine.mark_penalised();
        chan.close = Some(CloseTracker::Penalty {
            watch: Box::new(watch),
            current: penalty.clone(),
            claim: claim.clone(),
            swept: None,
            claimed: None,
        });
        self.broadcast_or_warn(&penalty, "penalty");
        if let Some(claim) = &claim {
            self.broadcast_or_warn(claim, "to_remote claim");
        }
        Some(penalty)
    }

    /// One block for a channel whose penalty is out: note the revoked output
    /// and our `to_remote` spent, settle once both are, and announce again
    /// whichever is still awaited. Past the cheater's delay the penalty stays
    /// valid until the cheater sweeps, so it is still worth announcing.
    fn advance_penalty(&self, chan: &mut Chan, txs: &[Transaction], height: u64) {
        let in_commitment_block = txs.iter().any(|t| Some(t.txid()) == chan.spend);
        let Some(CloseTracker::Penalty {
            watch,
            current,
            claim,
            swept,
            claimed,
        }) = &mut chan.close
        else {
            return;
        };
        let Watch::RevokedByPeer {
            to_local,
            revocation_secret,
            to_remote,
            ..
        } = watch.as_ref()
        else {
            return;
        };
        let revoked = to_local.outpoint;
        if let Some((tx, input)) = txs.iter().find_map(|t| {
            t.inputs
                .iter()
                .find(|i| i.prev_out == revoked)
                .map(|i| (t, i))
        }) {
            // Any penalty, whichever sweep address it pays (one built before
            // a restart pays another), reveals the revocation secret; the
            // cheater's delayed sweep does not.
            let ours = input
                .witness
                .signature
                .windows(revocation_secret.len())
                .any(|w| w == revocation_secret.as_slice());
            if !ours {
                eprintln!("ALERT: a revoked channel output was swept before the penalty confirmed");
            }
            *swept = Some(tx.txid());
        }
        if let Some(op) = to_remote.map(|r| r.outpoint) {
            if let Some(by) = spender(txs, op) {
                *claimed = Some(by);
            }
        }
        let done_claim = to_remote.is_none() || claimed.is_some();
        if let (Some(s), true) = (*swept, done_claim) {
            let by: Vec<Hash256> = std::iter::once(s).chain(*claimed).collect();
            let _ = chan.machine.mark_penalised();
            settle_all(chan, by, height);
            return;
        }
        // In the block holding the revoked commitment they have just gone out.
        if in_commitment_block {
            return;
        }
        let mut again = Vec::new();
        if swept.is_none() {
            again.push((current.clone(), "penalty"));
        }
        if let (Some(c), None) = (claim.as_ref(), *claimed) {
            again.push((c.clone(), "to_remote claim"));
        }
        for (tx, what) in again {
            self.broadcast_or_warn(&tx, what);
        }
    }

    /// Claims what a close paid to one of our channel keys, for a channel
    /// this node no longer operates — above all after a wallet was restored
    /// from its backup code, which knows no channel: when the peer closes
    /// alone, our side of its commitment pays our channel key, and nothing
    /// else would ever spend it. `find` lists the unspent outputs paying a
    /// key hash. The claims pay a fresh wallet address and are broadcast.
    ///
    /// Every key output paying a channel key is ours to take at once: the
    /// `to_remote` of a commitment carries no delay, and a funding is a
    /// two-key policy, never a key output. A live channel claims the one its
    /// own close pays, and that one is skipped. Returns how many claims went
    /// out.
    pub fn recover_key_outputs(
        &self,
        height: u64,
        find: &dyn Fn(&Hash256) -> Vec<(OutPoint, TxOut)>,
    ) -> usize {
        let mut claims = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            let funder_upto = g.next_index.saturating_add(KEY_SCAN_WINDOW);
            let acceptor_upto = g.next_acceptor.saturating_add(KEY_SCAN_WINDOW);
            // Derived once, then extended as channels use further indices.
            let (f0, a0, mut map) = g.key_hashes.take().unwrap_or((0, 0, HashMap::new()));
            let indices = (f0..funder_upto)
                .chain((a0..acceptor_upto).map(|i| ACCEPTOR_COUNTER_BASE.saturating_add(i)));
            for i in indices {
                map.insert(self.signer(i).pubkey_hash(), i);
            }
            g.key_hashes = Some((funder_upto.max(f0), acceptor_upto.max(a0), map));
            // A live channel claims its own `to_remote` from the close it
            // follows; any other output paying one of its keys — left by an
            // earlier channel on the same index, before a restore reset the
            // counters — is recovered here.
            let live: std::collections::HashSet<Hash256> = g
                .channels
                .values()
                .filter(|c| c.machine.phase() != Phase::Closed)
                .filter_map(|c| c.spend)
                .collect();
            g.claimed
                .retain(|_, at| height < at.saturating_add(CLAIM_MEMORY_BLOCKS));
            let hashes: Vec<(Hash256, u32)> = g
                .key_hashes
                .as_ref()
                .map(|(_, _, m)| m.iter().map(|(h, i)| (*h, *i)).collect())
                .unwrap_or_default();
            for (hash, index) in hashes {
                for (op, out) in find(&hash) {
                    if out.scheme != CHANNEL_SCHEME
                        || out.pubkey_hash != hash
                        || live.contains(&op.txid)
                    {
                        continue;
                    }
                    // Claimed already, and not yet long enough ago to try again.
                    if g.claimed
                        .get(&op)
                        .is_some_and(|at| height < at.saturating_add(6))
                    {
                        continue;
                    }
                    let value = out.value.units();
                    let fee = crate::channel::txbuild::capped_fee(
                        value,
                        crate::channel::txbuild::SWEEP_FEE,
                    );
                    if value.saturating_sub(fee) < crate::consensus::MIN_OUTPUT_VALUE {
                        continue;
                    }
                    g.claimed.insert(op, height);
                    claims.push((op, out, index, fee));
                }
            }
        }
        let n = claims.len();
        for (op, out, index, fee) in claims {
            let sweep_to = (self.hooks.sweep_address)();
            let signer = self.signer(index);
            let tx = crate::channel::txbuild::to_remote_claim_tx(
                op,
                &out,
                sweep_to,
                fee,
                self.network,
                signer.as_ref(),
            );
            eprintln!(
                "channel key {index}: claiming {} paid to it by a close, back to the wallet",
                out.value
            );
            self.broadcast_or_warn(&tx, "claim of a channel key output");
        }
        n
    }

    /// The funding outpoints this manager is watching, with their channel ids.
    pub fn watched_funding(&self) -> Vec<(Hash256, OutPoint)> {
        let g = self.inner.lock().unwrap();
        g.channels
            .values()
            .filter_map(|c| {
                c.machine
                    .funding_outpoint()
                    .map(|o| (c.machine.channel_id(), o))
            })
            .collect()
    }

    // --- RPC views --------------------------------------------------------

    pub fn list(&self) -> Vec<ChannelSummary> {
        let mut g = self.inner.lock().unwrap();
        self.fill_owners(&mut g);
        g.channels.values().map(summary).collect()
    }

    pub fn info(&self, cid: Hash256) -> Option<ChannelSummary> {
        let g = self.inner.lock().unwrap();
        g.channels.get(&cid).map(summary)
    }

    /// The funding output a channel expects on chain: the 2-of-2 policy for
    /// its whole capacity.
    pub fn funding_output_of(&self, cid: Hash256) -> Option<TxOut> {
        let g = self.inner.lock().unwrap();
        g.channels.get(&cid).map(|c| c.machine.funding_output())
    }

    /// The peer a channel is with.
    pub fn peer_of(&self, cid: Hash256) -> Option<u64> {
        let g = self.inner.lock().unwrap();
        g.channels.get(&cid).map(|c| c.peer)
    }

    /// Force-closes a channel by broadcasting our latest commitment. Returns
    /// the transaction broadcast.
    pub fn force_close(&self, cid: Hash256) -> Result<Transaction, String> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        // An older copy's latest commitment may be revoked: broadcasting it
        // would lose the whole channel to a penalty.
        if chan.behind {
            return Err(BEHIND.into());
        }
        let tx = chan.machine.force_close(FORCE_CLOSE_TIER).map_err(err)?;
        drop(g);
        (self.hooks.broadcast)(&tx)?;
        Ok(tx)
    }

    /// A fully-signed commitment at state `n`, for exercising the watcher with
    /// a (possibly revoked) broadcast. An audit hook, never a production path.
    #[cfg(feature = "audit")]
    pub fn signed_commitment(&self, cid: Hash256, n: u64) -> Option<Transaction> {
        let g = self.inner.lock().unwrap();
        g.channels.get(&cid).and_then(|c| {
            c.machine
                .signed_commitment_at(n, crate::channel::txbuild::FeeTier::Low)
                .ok()
        })
    }

    /// The channel id of the (single) channel with `peer`, if any — used by the
    /// RPC to let an agent name a peer instead of a channel id when
    /// unambiguous.
    pub fn channel_with_peer(&self, peer: u64) -> Option<Hash256> {
        let g = self.inner.lock().unwrap();
        let mut found = None;
        for c in g.channels.values() {
            if c.peer == peer {
                if found.is_some() {
                    return None; // ambiguous
                }
                found = Some(c.machine.channel_id());
            }
        }
        found
    }
}

/// The `Close` of a cooperative close agreed while an update was still in
/// flight, once that update has settled: the close could not be signed over
/// balances the two sides did not yet share, so it follows the update.
fn pending_close(chan: &mut Chan, cid: Hash256) -> Option<Vec<u8>> {
    let msg = chan.machine.close_after_update().ok()??;
    Some(write_frame(cid, KIND_ENGINE, &msg.encode()))
}

/// The channel seed derives every channel key and revocation root this node
/// holds: it does not outlive the manager.
impl Drop for ChannelManager {
    fn drop(&mut self) {
        crate::kdf::wipe(&mut self.wallet_seed);
    }
}

/// Classifies a funding-output spend for `chan`, robust to the single-output
/// commitment shape (see [`Machine::identify_spend`]).
fn classify_spend(chan: &Chan, _funding: OutPoint, tx: &Transaction) -> Watch {
    chan.machine.identify_spend(tx)
}

impl ChannelManager {
    /// Broadcasts an on-chain protection transaction (penalty, claim, sweep),
    /// warning loudly on failure. A swallowed error here can mean lost funds —
    /// a penalty that never confirms lets a cheater's delayed sweep win — so it
    /// must never pass silently.
    fn broadcast_or_warn(&self, tx: &Transaction, what: &str) {
        // Replaying blocks the node already holds at startup: what would have
        // gone out then is broadcast once, at the tip, by `rescan`.
        if self.replaying.load(Ordering::SeqCst) {
            return;
        }
        if let Err(e) = (self.hooks.broadcast)(tx) {
            eprintln!("ALERT: channel {what} transaction could not be broadcast: {e}");
        }
    }
}

/// The transaction in `txs` spending `op`, if any.
fn spender(txs: &[Transaction], op: OutPoint) -> Option<Hash256> {
    txs.iter()
        .find(|t| t.inputs.iter().any(|i| i.prev_out == op))
        .map(|t| t.txid())
}

/// The channel's last transaction, `by`, confirmed at `height`: wait for it
/// to be buried before marking the channel closed, keeping what was awaited
/// in case a reorganization takes it away.
fn settle(chan: &mut Chan, by: Hash256, height: u64) {
    settle_all(chan, vec![by], height);
}

/// [`settle`], for a channel ended by several transactions.
fn settle_all(chan: &mut Chan, by: Vec<Hash256>, height: u64) {
    let prior = chan.close.take().map(Box::new);
    chan.close = Some(CloseTracker::Settling { by, height, prior });
}

/// How deep the transaction that ends a channel must be buried before the
/// channel is marked closed and no longer watched or reloaded. On regtest,
/// the funding depth, as a funding is buried to open the channel; elsewhere,
/// past the deepest reorganization a node accepts
/// ([`crate::consensus::MAX_REORG_DEPTH`]), so a closed channel is never
/// forgotten while a reorganization could still take its close away.
pub fn settle_depth(network: Network, funding_depth: u16) -> u64 {
    let funding = u64::from(funding_depth.max(1));
    match network {
        Network::Regtest => funding,
        _ => funding.max(crate::consensus::MAX_REORG_DEPTH + 1),
    }
}

/// Marks a settling channel closed once its last transaction is buried to
/// [`settle_depth`] at chain height `height`.
///
/// Returns the height the channel's last transaction confirmed at and how
/// the channel ended, when it is marked closed now.
fn finish_settling(chan: &mut Chan, height: u64, network: Network) -> Option<(u64, ClosedHow)> {
    if let Some(CloseTracker::Settling { height: at, .. }) = &chan.close {
        let at = *at;
        let depth = height.saturating_add(1).saturating_sub(at);
        if depth >= settle_depth(network, chan.machine.funding_depth()) {
            let how = match chan.machine.phase() {
                Phase::Closing => ClosedHow::Cooperative,
                Phase::Penalised => ClosedHow::Penalty,
                Phase::Forcing => ClosedHow::Forced,
                _ => ClosedHow::Unknown,
            };
            let _ = chan.machine.mark_closed();
            chan.close = None;
            return Some((at, how));
        }
    }
    None
}

fn summary(c: &Chan) -> ChannelSummary {
    let bal = c.machine.latest_balances();
    let us = c.machine.our_index();
    let sure = c.machine.irrevocable_balance().min(bal[us]);
    ChannelSummary {
        channel_id: c.machine.channel_id(),
        peer: c.peer,
        phase: c.machine.phase(),
        capacity: c.capacity,
        local_balance: sure,
        pending_incoming: bal[us] - sure,
        remote_balance: bal[1 - us],
        state_number: c.machine.local_commit_number().unwrap_or(0),
        funding: c.machine.funding_outpoint(),
        in_flight: c.machine.update_in_flight(),
        close_txid: match &c.close {
            Some(CloseTracker::Settling { by, .. }) => by.last().copied(),
            _ => None,
        },
        close_height: match &c.close {
            Some(CloseTracker::Settling { height, .. }) => Some(*height),
            _ => None,
        },
        funding_depth: c.machine.funding_depth(),
        delay: c.machine.params().delay,
        we_funded: us == crate::channel::txbuild::FUNDER,
        force_close_fee: c.machine.commit_fee(FORCE_CLOSE_TIER),
        synced: c.synced,
        release_height: match &c.close {
            Some(CloseTracker::DelayedSweep {
                commit_height,
                delay,
                ..
            }) => Some(commit_height.saturating_add(u64::from(*delay))),
            _ => None,
        },
        close_time: match (&c.close, c.closing) {
            (Some(CloseTracker::Settling { height, .. }), Some((h, t))) if *height == h => Some(t),
            _ => None,
        },
        peer_identity: c.peer_identity.clone(),
        peer_owner: c.peer_owner.map(|o| o.to_hex()).unwrap_or_default(),
        behind: c.behind,
        peer_behind: c.peer_behind.is_some(),
    }
}

fn err(e: ChannelError) -> String {
    format!("{e:?}")
}

/// A signed control message's outcome: a stale one (a replay, or one
/// overtaken on another connection) is ignored rather than misconduct.
fn fresh<T>(r: Result<T, ChannelError>) -> Result<Option<T>, String> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(ChannelError::Stale) => Ok(None),
        Err(e) => Err(err(e)),
    }
}

/// Where an inbound frame comes from: a connection, and what its session
/// authenticated.
struct From<'a> {
    peer: u64,
    identity: &'a str,
    legacy: &'a str,
    binding: [u8; 32],
}

/// Whether `s` is a node id, as a session authenticates it: 64 lowercase hex
/// characters. A channel journaled before the transport names its peer
/// otherwise — by the 32 hex characters of a legacy id, or an address.
pub fn is_node_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether a channel is held with the peer of a session that authenticated
/// `identity` and signed `legacy`: by node id, or — for a channel journaled
/// before the transport, until its first reestablish — by legacy id.
fn bound_to(chan: &Chan, identity: &str, legacy: &str) -> bool {
    chan.peer_identity == identity
        || (!is_node_id(&chan.peer_identity) && !legacy.is_empty() && chan.peer_identity == legacy)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verification left waiting by the other wallet — it declared a
    /// mismatch, closed, or never answered — is dropped after
    /// [`VERIFY_WAIT_TIMEOUT`], so that the screen stops showing it and a new
    /// one can start; words already drawn, and a failure, are kept.
    #[test]
    fn a_verification_waiting_for_nothing_expires() {
        let t0 = std::time::Instant::now();
        let mut v: Verifications = HashMap::new();
        let mut w: HashMap<u64, std::time::Instant> = HashMap::new();
        let (waiting, _) = verify::start(verify::WORDS_STRONG, [1; verify::ID_LEN], [2; 32]);
        v.insert(1, (waiting.clone(), None));
        w.insert(1, t0);
        v.insert(2, (verify::State::Failed, None));
        w.insert(2, t0);
        v.insert(3, (waiting, None));
        w.insert(3, t0 + VERIFY_WAIT_TIMEOUT / 2);
        expire_waiting_in(&mut v, &mut w, t0 + VERIFY_WAIT_TIMEOUT / 2);
        assert_eq!(v.len(), 3, "nothing before its time");
        expire_waiting_in(&mut v, &mut w, t0 + VERIFY_WAIT_TIMEOUT);
        assert!(!v.contains_key(&1), "the one waiting too long is dropped");
        assert!(
            matches!(v.get(&2), Some((verify::State::Failed, _))),
            "a failure stays"
        );
        assert!(v.contains_key(&3), "a later one waits on");
        assert!(!w.contains_key(&1) && !w.contains_key(&2));
    }

    /// The channel seed a manager holds is wiped when it is dropped.
    #[test]
    fn the_channel_seed_is_wiped_on_drop() {
        let dir = std::env::temp_dir().join(format!("q21-mgr-wipe-{}", std::process::id()));
        let hooks = Hooks {
            fund: Box::new(|_, _| Err("no".into())),
            broadcast: Box::new(|_| Ok(())),
            sweep_address: Box::new(|| Hash256::ZERO),
            payout_address: Box::new(|| Hash256::ZERO),
            reserve: Box::new(|_, _| {}),
        };
        let mgr = ChannelManager::new(Network::Regtest, 10, [0x77u8; 32], dir, 12, 2, hooks);
        let mut slot = std::mem::ManuallyDrop::new(mgr);
        let p: *const [u8; 32] = &slot.wallet_seed;
        assert_eq!(unsafe { *p }, [0x77u8; 32]);
        // Safe: dropped once, here; the bytes read stay in `slot`'s storage.
        let after = unsafe {
            std::mem::ManuallyDrop::drop(&mut slot);
            std::ptr::read_volatile(p)
        };
        assert_eq!(after, [0u8; 32]);
    }
}
