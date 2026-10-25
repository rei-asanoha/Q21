//! The node's channel manager: it owns the running [`Machine`]s, routes
//! inbound messages to the right channel, drives the protocol, and persists
//! through each channel's journal.
//!
//! # Framing
//!
//! A channel travels over the network as an opaque payload (see
//! [`crate::wire::Message::Channel`]). This module gives that payload its
//! structure: a 32-byte channel id, a one-byte kind, then a body. Two kinds are
//! control frames the manager handles itself — `Hello` and `HelloBack`, which
//! exchange the two parties' per-channel public keys before the funding policy
//! (and thus the channel id) can exist — and one kind carries an engine
//! [`crate::channel::messages::Message`] verbatim. Routing is by channel id,
//! except the two control frames, which are routed by peer (one open in flight
//! per peer).
//!
//! # Locking
//!
//! The manager holds its own mutex and never the node's chain lock. Signing and
//! verification happen under the manager mutex only. Anything that touches the
//! chain — building and broadcasting the funding transaction, broadcasting a
//! cooperative close or a penalty — is delegated to hooks the node installs,
//! which take the chain lock themselves, after the cryptography is done.

use crate::address::Network;
use crate::channel::keys::{ChannelKey, Signer, CHANNEL_SCHEME};
use crate::channel::machine::{channel_id, ChannelError, Machine, Phase};
use crate::channel::messages::Message as ChMsg;
use crate::channel::txbuild;
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
    pub local_balance: u64,
    pub remote_balance: u64,
    pub state_number: u64,
    pub funding: Option<OutPoint>,
}

/// Authenticated connections remembered per channel, and challenges awaiting
/// an answer: a handful, enough for two links per peer and a reconnect.
const MAX_AUTHED: usize = 4;
const MAX_CHALLENGES: usize = 8;

impl Chan {
    /// A fresh challenge for connection `conn`: the frame to send it.
    fn challenge(&mut self, conn: u64) -> Option<Vec<u8>> {
        let nonce = crate::rng::bytes::<32>().ok()?;
        let cid = self.machine.channel_id();
        self.challenges.retain(|(c, _)| *c != conn);
        if self.challenges.len() >= MAX_CHALLENGES {
            self.challenges.remove(0);
        }
        self.challenges.push((conn, nonce));
        Some(write_frame(
            cid,
            KIND_ENGINE,
            &ChMsg::Challenge {
                channel_id: cid,
                nonce,
            }
            .encode(),
        ))
    }
}

struct Chan {
    machine: Machine,
    /// The live network connection id of the peer. Transient: it changes on
    /// every reconnect and is re-bound from `peer_identity` at handshake time.
    peer: u64,
    /// A durable identifier of the counterparty (its address), persisted so a
    /// restart or reconnect can map the new connection id back to this channel.
    peer_identity: String,
    capacity: u64,
    /// Connections on which the counterparty proved itself: the one that ran
    /// the opening handshake, and each that answered our challenge with a
    /// reestablish signed by its funding key. Only frames from these are acted
    /// on. Most recent last.
    authed: Vec<u64>,
    /// Challenges we issued and not yet seen answered, per connection.
    challenges: Vec<(u64, [u8; 32])>,
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
    /// A penalty has been broadcast at [`txbuild::penalty_fee`]. While it stays
    /// unconfirmed and the cheater's delay runs, it is announced again at
    /// every block, for the nodes that dropped it or never had it. Settled
    /// once the revoked output is spent: by it, by a version built before a
    /// restart, or — too late — by the cheater.
    Penalty { watch: Watch, current: Transaction },
    /// The transaction `by` that ends the channel confirmed at `height`. The
    /// channel is marked closed — and no longer reloaded — only once that is
    /// buried to the funding depth; until then a reorganization that takes
    /// `by` off the chain brings back what was awaited before it.
    Settling {
        by: Hash256,
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

struct Inner {
    channels: HashMap<Hash256, Chan>,
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
}

impl Inner {
    /// Forgets the opens that waited too long for the peer.
    fn expire_pending(&mut self) {
        let ttl = self.pending_ttl;
        self.pending_funder.retain(|_, p| p.since.elapsed() < ttl);
        self.pending_acceptor.retain(|_, p| p.since.elapsed() < ttl);
    }

    /// Channels whose funding is not on chain yet: those we accepted
    /// (`inbound`), or those we open.
    fn unfunded(&self, inbound: bool) -> usize {
        self.unfunded_iter(inbound).count()
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

pub struct ChannelManager {
    network: Network,
    base_fee_rate: u64,
    wallet_seed: [u8; 32],
    journal_dir: PathBuf,
    default_delay: u16,
    default_depth: u16,
    hooks: Hooks,
    inner: Mutex<Inner>,
    /// Set while [`ChannelManager::rescan`] replays past blocks: reactions are
    /// computed but nothing is broadcast until the replay reaches the tip.
    replaying: AtomicBool,
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
            wallet_seed,
            journal_dir,
            default_delay,
            default_depth,
            hooks,
            replaying: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                channels: HashMap::new(),
                pending_funder: HashMap::new(),
                pending_acceptor: HashMap::new(),
                next_index: 0,
                pending_ttl: PENDING_OPEN_TTL,
                spare_payout: None,
                unfunded_ttl: UNFUNDED_TTL,
                inbound_funding_ttl: INBOUND_FUNDING_TTL,
            }),
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
        if index < ACCEPTOR_INDEX_BASE {
            g.next_index = g.next_index.max(index + 1);
        }
        match Machine::reopen(path, self.network, self.signer(index), self.base_fee_rate) {
            Ok(mut machine) => {
                let _ = machine.note_key_index(index);
                if matches!(machine.phase(), Phase::Closed) {
                    return;
                }
                let cid = machine.channel_id();
                let capacity = machine.params().capacity.units();
                // The peer's network id is transient; its durable identity,
                // persisted in a sidecar, tells a reconnect whom to challenge.
                let peer_identity = self.read_peer_identity(cid);
                g.channels.insert(
                    cid,
                    Chan {
                        machine,
                        peer: u64::MAX,
                        peer_identity,
                        capacity,
                        authed: Vec::new(),
                        challenges: Vec::new(),
                        synced: false,
                        close: None,
                        spend: None,
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

    /// This node's stable channel identity: the first 16 bytes of a tagged hash
    /// of the wallet seed, as lowercase hex. It is advertised in the handshake
    /// and persisted per channel, so a channel re-binds to its peer across a
    /// reconnect no matter which ephemeral port the peer dials from. It reveals
    /// nothing about the wallet: it is a one-way hash under a dedicated tag.
    pub fn node_id_hex(&self) -> String {
        let h = crate::hash::tagged_hash_parts("Q21/channel/node-id", &[&self.wallet_seed]).0;
        h[..crate::wire::CHANNEL_NODE_ID_HEX / 2]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
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

    /// The key index of a channel we accept from a funder whose channel key
    /// is `funder_pubkey`: derived, not counted, so a Hello that never leads
    /// to a channel spends nothing. Keyed by our seed, so a funder cannot aim
    /// at the index of another channel; the same funder key twice gives the
    /// same channel id, which the journal refuses.
    fn acceptor_index(&self, funder_pubkey: &[u8]) -> u32 {
        let h = crate::hash::tagged_hash_parts(
            "Q21/channel/acceptor-index",
            &[&self.wallet_seed, funder_pubkey],
        );
        let v = u32::from_le_bytes(h.0[..4].try_into().expect("four bytes"));
        ACCEPTOR_INDEX_BASE | v
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

    /// The sidecar file holding a channel's durable peer identity, beside its
    /// journal. Kept out of the journal so the engine's crash-safe record
    /// format is untouched; it carries no money-safety invariant.
    fn peer_identity_path(&self, cid: Hash256) -> PathBuf {
        self.journal_dir.join(format!("{}.peer", cid.to_hex()))
    }

    fn write_peer_identity(&self, cid: Hash256, identity: &str) {
        let _ = crate::channel::journal::atomic_write(
            &self.peer_identity_path(cid),
            identity.as_bytes(),
        );
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
    /// the acceptor's key is known, so this first exchanges keys.
    pub fn open(
        &self,
        peer: u64,
        peer_identity: &str,
        capacity: u64,
        delay: Option<u16>,
        depth: Option<u16>,
    ) -> Result<Vec<u8>, String> {
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

    /// Called when a channel-capable peer completes the handshake, with the
    /// peer's live connection id and the identity it announced. Every channel
    /// held with that identity — a hint only: anyone can announce it — or
    /// bound to that connection id is challenged on the new connection: the
    /// peer must answer with a reestablish signed by the channel's funding key
    /// over our fresh nonce before anything it sends there is acted on.
    pub fn on_peer_connected(&self, peer: u64, peer_identity: &str) -> Vec<Vec<u8>> {
        let mut g = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for c in g.channels.values_mut() {
            let same_link = c.peer == peer;
            let same_identity = !peer_identity.is_empty() && c.peer_identity == peer_identity;
            if same_link || same_identity {
                // A new connection under this id proves nothing yet; one that
                // merely claims the identity leaves the current link alone.
                c.authed.retain(|x| *x != peer);
                if same_link {
                    c.synced = false;
                }
                out.extend(c.challenge(peer));
            }
        }
        out
    }

    /// The challenges for every channel bound to `peer`, to send on
    /// reconnection: the channel resynchronizes once the peer answers.
    pub fn reestablish(&self, peer: u64) -> Vec<Vec<u8>> {
        let mut g = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for c in g.channels.values_mut() {
            if c.peer == peer {
                c.authed.retain(|x| *x != peer);
                c.synced = false;
                out.extend(c.challenge(peer));
            }
        }
        out
    }

    // --- Inbound ----------------------------------------------------------

    /// Handles one inbound frame from `peer`, whose durable identity (for
    /// re-binding on a later reconnect) is `peer_identity`.
    pub fn deliver(&self, peer: u64, peer_identity: &str, bytes: &[u8]) -> Reaction {
        match self.deliver_inner(peer, peer_identity, bytes) {
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

    fn deliver_inner(
        &self,
        peer: u64,
        peer_identity: &str,
        bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        if bytes.len() < 33 {
            return Err("short frame".into());
        }
        let mut r = Reader::new(bytes);
        let cid = Hash256(r.array32().map_err(|_| "cid")?);
        let kind = r.u8().map_err(|_| "kind")?;
        let body = &bytes[33..];
        match kind {
            KIND_HELLO => self.on_hello(peer, peer_identity, body),
            KIND_HELLO_BACK => self.on_hello_back(peer, peer_identity, body),
            KIND_ENGINE => {
                let msg = ChMsg::decode(body).map_err(|_| "bad engine message")?;
                self.on_engine(peer, peer_identity, cid, msg)
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
        let index = self.acceptor_index(&funder_pubkey);
        let our_pubkey = self.signer(index).pubkey().to_vec();
        g.pending_acceptor.insert(
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
        _peer_identity: &str,
        body: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut r = Reader::new(body);
        let acceptor_pubkey = r.var_bytes().map_err(|_| "pubkey")?.to_vec();
        if acceptor_pubkey.len() != CHANNEL_SCHEME.pubkey_len() {
            return Err("pubkey length".into());
        }
        let acceptor_payout = Hash256(r.array32().map_err(|_| "payout")?);
        let mut g = self.inner.lock().unwrap();
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
        g.channels.insert(
            cid,
            Chan {
                machine,
                peer,
                peer_identity: pending.peer_identity,
                capacity: pending.capacity,
                authed: vec![peer],
                challenges: Vec::new(),
                synced: true,
                close: None,
                spend: None,
            },
        );
        Ok(vec![write_frame(cid, KIND_ENGINE, &open.encode())])
    }

    fn on_engine(
        &self,
        peer: u64,
        peer_identity: &str,
        cid: Hash256,
        msg: ChMsg,
    ) -> Result<Vec<Vec<u8>>, String> {
        // The acceptor's first engine message is the funder's Open: build the
        // channel from the pending acceptor state.
        if matches!(msg, ChMsg::Open { .. }) {
            return self.accept_open(peer, peer_identity, cid, msg);
        }
        let mut g = self.inner.lock().unwrap();
        let Some(chan) = g.channels.get_mut(&cid) else {
            // A peer that still tracks a channel we have settled and forgotten
            // (closed on our side, still closing on theirs) offers its
            // reestablish at every connection. Penalising it dropped the link
            // at every reconnect; there is simply nothing to resynchronize.
            if matches!(msg, ChMsg::Reestablish { .. } | ChMsg::Challenge { .. }) {
                return Ok(Vec::new());
            }
            return Err("unknown channel".into());
        };
        // Authentication. A challenge is answered on any connection: the
        // answer proves our key over the asker's own nonce, good for nothing
        // else. A reestablish is taken only as the answer to a challenge we
        // issued on that very connection, and its proof must verify: then the
        // connection speaks for the counterparty. Every other frame is acted
        // on only from an authenticated connection; from any other it is
        // ignored, not penalised — an honest frame can trail a reconnect.
        // A self-declared identity, or a reestablish captured earlier and
        // replayed (after our restart, or on another connection), proves
        // nothing.
        match &msg {
            ChMsg::Challenge { nonce, .. } => {
                // Our own challenge first, if this connection has not been
                // asked yet: the peer then answers it before it handles our
                // reestablish, so what it resends after that reaches us on a
                // connection we already trust.
                let mut out = Vec::new();
                let challenged = chan.challenges.iter().any(|(c, _)| *c == peer);
                if !chan.authed.contains(&peer) && !challenged {
                    out.extend(chan.challenge(peer));
                }
                out.push(write_frame(
                    cid,
                    KIND_ENGINE,
                    &chan.machine.reestablish_for(*nonce).encode(),
                ));
                return Ok(out);
            }
            ChMsg::Reestablish { nonce, .. } => {
                let Some(at) = chan
                    .challenges
                    .iter()
                    .position(|(c, n)| *c == peer && n == nonce)
                else {
                    return Ok(Vec::new());
                };
                chan.challenges.remove(at);
            }
            _ if !chan.authed.contains(&peer) => return Ok(Vec::new()),
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
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
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
            ChMsg::Ready => {
                chan.machine.on_ready(&msg).map_err(err)?;
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
            ChMsg::Close { fee } => {
                if chan.machine.update_in_flight() {
                    // The peer's Close crossed an update still settling here:
                    // agree now, and send our own Close once the update
                    // completes; the peer signs that one.
                    chan.machine.agree_close(fee, false).map_err(err)?;
                } else {
                    let m = chan.machine.on_close(&msg).map_err(err)?;
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
            ChMsg::Reestablish { .. } => {
                let frames = chan.machine.on_reestablish(&msg).map_err(err)?;
                // The proof verified over our challenge on this connection: it
                // speaks for the channel's counterparty. Bind to it, and
                // remember the identity it announced, so a later reconnect
                // knows whom to challenge.
                chan.authed.retain(|c| *c != peer);
                if chan.authed.len() >= MAX_AUTHED {
                    chan.authed.remove(0);
                }
                chan.authed.push(peer);
                chan.peer = peer;
                if !peer_identity.is_empty() && chan.peer_identity != peer_identity {
                    chan.peer_identity = peer_identity.to_string();
                    self.write_peer_identity(cid, peer_identity);
                }
                for f in frames {
                    out.push(write_frame(cid, KIND_ENGINE, &f.encode()));
                }
                chan.synced = true;
            }
            ChMsg::Challenge { .. } => {}
            ChMsg::Error { .. } | ChMsg::Open { .. } => {}
        }
        Ok(out)
    }

    fn accept_open(
        &self,
        peer: u64,
        _peer_identity: &str,
        cid: Hash256,
        open: ChMsg,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut g = self.inner.lock().unwrap();
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
        g.channels.insert(
            cid,
            Chan {
                machine,
                peer,
                peer_identity: pending.peer_identity,
                capacity: pending.capacity,
                authed: vec![peer],
                challenges: Vec::new(),
                synced: true,
                close: None,
                spend: None,
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
        self.react_to_spends(txs, height);
        let frames = self.confirm_buried(height, depth_of);
        self.advance_closes(txs, height);
        self.expire_unfunded(depth_of);
        frames
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
    fn expire_unfunded(&self, depth_of: &DepthOf) {
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
        for (cid, ttl) in stale {
            self.forget(&mut g, cid);
            eprintln!(
                "channel {}: never funded; forgotten after waiting {}s",
                cid.to_hex(),
                ttl.as_secs()
            );
        }
    }

    /// Drops a channel with nothing at stake, its journal and sidecar too.
    fn forget(&self, g: &mut Inner, cid: Hash256) {
        g.channels.remove(&cid);
        let _ = std::fs::remove_file(self.journal_path(cid));
        let _ = std::fs::remove_file(self.peer_identity_path(cid));
    }

    /// Catches up, at startup, with what happened on chain while the node was
    /// down or before a crash: the close and penalty tracking lives in memory.
    ///
    /// For every reloaded channel whose funding output is spent at the tip,
    /// the blocks from the funding's confirmation height (journaled; without
    /// it, the last [`MAX_RESCAN_BLOCKS`]) up to the tip are replayed through
    /// the same reactions as live blocks: a revoked commitment is punished, our
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
                    // have confirmed is looked for.
                    depth_of(&op).is_none()
                        && (c.machine.funding_height().is_some()
                            || !matches!(c.machine.phase(), Phase::Opening | Phase::Funded))
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
        {
            let g = self.inner.lock().unwrap();
            for c in g.channels.values() {
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
                    Some(CloseTracker::Penalty { current, .. }) => {
                        pending.push((current.clone(), "penalty"));
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
                            Phase::Forcing => {
                                let latest = c.machine.local_commit_number().and_then(|n| {
                                    c.machine
                                        .signed_commitment_at(
                                            n,
                                            crate::channel::txbuild::FeeTier::Medium,
                                        )
                                        .ok()
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
            if matches!(&chan.close, Some(CloseTracker::Settling { by, .. }) if gone.contains(by)) {
                if let Some(CloseTracker::Settling { prior, .. }) = chan.close.take() {
                    chan.close = prior.map(|p| *p);
                }
            }
            if chan.spend.is_some_and(|s| gone.contains(&s)) {
                chan.spend = None;
                chan.close = None;
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
        for c in g.channels.values_mut() {
            if let Some((depth, _)) = c.machine.funding_outpoint().and_then(|op| depth_of(&op)) {
                let at = height.saturating_add(1).saturating_sub(depth);
                if c.machine.funding_height() != Some(at) {
                    let _ = c.machine.note_funding_height(at);
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
            self.forget(&mut g, cid);
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
                        finish_settling(chan, height, self.network);
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
            finish_settling(chan, height, self.network);
        }
    }

    /// Builds and broadcasts the penalty against a revoked commitment, at
    /// [`txbuild::penalty_fee`], and keeps it to announce again until it settles.
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
        let _ = chan.machine.mark_penalised();
        chan.close = Some(CloseTracker::Penalty {
            watch,
            current: penalty.clone(),
        });
        self.broadcast_or_warn(&penalty, "penalty");
        Some(penalty)
    }

    /// One block for a channel whose penalty is out: settle it once the
    /// revoked output is spent, or else announce the penalty again. Past the
    /// cheater's delay it stays valid until the cheater sweeps, so it is
    /// still worth announcing.
    fn advance_penalty(&self, chan: &mut Chan, txs: &[Transaction], height: u64) {
        let Some(CloseTracker::Penalty { watch, current }) = &chan.close else {
            return;
        };
        let Watch::RevokedByPeer {
            to_local,
            revocation_secret,
            ..
        } = watch
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
            let _ = chan.machine.mark_penalised();
            settle(chan, tx.txid(), height);
            return;
        }
        // In the block holding the revoked commitment it has just gone out.
        if txs.iter().any(|t| Some(t.txid()) == chan.spend) {
            return;
        }
        let tx = current.clone();
        self.broadcast_or_warn(&tx, "penalty");
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
        let g = self.inner.lock().unwrap();
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
        let tx = chan
            .machine
            .force_close(crate::channel::txbuild::FeeTier::Medium)
            .map_err(err)?;
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
fn finish_settling(chan: &mut Chan, height: u64, network: Network) {
    if let Some(CloseTracker::Settling { height: at, .. }) = &chan.close {
        let depth = height.saturating_add(1).saturating_sub(*at);
        if depth >= settle_depth(network, chan.machine.funding_depth()) {
            let _ = chan.machine.mark_closed();
            chan.close = None;
        }
    }
}

fn summary(c: &Chan) -> ChannelSummary {
    let bal = c.machine.balances();
    let us = c.machine.our_index();
    ChannelSummary {
        channel_id: c.machine.channel_id(),
        peer: c.peer,
        phase: c.machine.phase(),
        capacity: c.capacity,
        local_balance: bal[us],
        remote_balance: bal[1 - us],
        state_number: c.machine.local_commit_number().unwrap_or(0),
        funding: c.machine.funding_outpoint(),
    }
}

fn err(e: ChannelError) -> String {
    format!("{e:?}")
}

/// Adapter so the node's [`crate::net::ChannelSink`] can drive the manager.
impl crate::net::ChannelSink for ChannelManager {
    fn deliver(&self, peer: u64, peer_identity: &str, bytes: &[u8]) -> crate::net::ChannelOutcome {
        let r = ChannelManager::deliver(self, peer, peer_identity, bytes);
        crate::net::ChannelOutcome {
            replies: r.frames,
            penalize: r.penalize,
        }
    }

    fn node_identity(&self) -> Option<String> {
        Some(self.node_id_hex())
    }

    fn on_connected_block(
        &self,
        txs: &[Transaction],
        height: u64,
        depth_of: &DepthOf,
    ) -> Vec<(u64, Vec<u8>)> {
        ChannelManager::on_connected_block(self, txs, height, depth_of)
    }

    fn on_peer_connected(&self, peer: u64, peer_identity: &str) -> Vec<Vec<u8>> {
        ChannelManager::on_peer_connected(self, peer, peer_identity)
    }

    fn on_disconnected_txids(&self, txids: &[Hash256]) {
        ChannelManager::on_disconnected_txids(self, txids)
    }

    fn rescan(
        &self,
        tip: u64,
        txs_at: &dyn Fn(u64) -> Option<Vec<Transaction>>,
        depth_of: &DepthOf,
    ) {
        ChannelManager::rescan(self, tip, txs_at, depth_of)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The channel seed a manager holds is wiped when it is dropped.
    #[test]
    fn the_channel_seed_is_wiped_on_drop() {
        let dir = std::env::temp_dir().join(format!("q21-mgr-wipe-{}", std::process::id()));
        let hooks = Hooks {
            fund: Box::new(|_, _| Err("no".into())),
            broadcast: Box::new(|_| Ok(())),
            sweep_address: Box::new(|| Hash256::ZERO),
            payout_address: Box::new(|| Hash256::ZERO),
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
