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
use crate::channel::keys::{funding_key_seed, ChannelKey, Signer, CHANNEL_SCHEME};
use crate::channel::machine::{channel_id, ChannelError, Machine, Phase};
use crate::channel::messages::Message as ChMsg;
use crate::channel::watcher::{classify, OutputRef, Watch, WatchContext};
use crate::hash::Hash256;
use crate::ser::{Reader, Writer};
use crate::sig;
use crate::tx::{OutPoint, Transaction, TxOut};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

const KIND_ENGINE: u8 = 0;
const KIND_HELLO: u8 = 1;
const KIND_HELLO_BACK: u8 = 2;

/// Fee reserved for a cooperative close, a penalty, or a sweep, in units.
pub const CLOSE_FEE: u64 = 20_000;

/// Builds, signs, reserves and broadcasts the funding transaction paying the
/// given output; returns its outpoint. Takes the chain and wallet locks itself.
pub type FundFn = dyn Fn(Hash256, TxOut) -> Result<OutPoint, String> + Send + Sync;
/// Broadcasts a transaction (cooperative close, penalty, sweep) through the
/// normal mempool and relay.
pub type BroadcastFn = dyn Fn(&Transaction) -> Result<(), String> + Send + Sync;
/// Yields a fresh wallet address to receive swept or claimed funds.
pub type SweepAddrFn = dyn Fn() -> Hash256 + Send + Sync;

/// What the node must do for the manager when the chain is involved.
pub struct Hooks {
    pub fund: Box<FundFn>,
    pub broadcast: Box<BroadcastFn>,
    pub sweep_address: Box<SweepAddrFn>,
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

struct Chan {
    machine: Machine,
    peer: u64,
    capacity: u64,
    /// True while an update we proposed is still in flight.
    in_flight: bool,
    /// What the channel is waiting for on chain, once a commitment has been
    /// broadcast. `None` while the channel is still off-chain or settled.
    close: Option<CloseTracker>,
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
    /// A finalizing transaction (penalty, claim, or delayed sweep) has been
    /// broadcast; the channel is settled once it confirms.
    Finalizing { txid: Hash256, penalty: bool },
}

struct PendingFunder {
    index: u32,
    capacity: u64,
    delay: u16,
    depth: u16,
}

struct PendingAcceptor {
    index: u32,
    funder_pubkey: Vec<u8>,
    capacity: u64,
    delay: u16,
    depth: u16,
}

struct Inner {
    channels: HashMap<Hash256, Chan>,
    pending_funder: HashMap<u64, PendingFunder>,
    pending_acceptor: HashMap<u64, PendingAcceptor>,
    next_index: u32,
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
            inner: Mutex::new(Inner {
                channels: HashMap::new(),
                pending_funder: HashMap::new(),
                pending_acceptor: HashMap::new(),
                next_index: 0,
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
        // (journal path, our funding pubkey) for every intact channel journal.
        let mut pending: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jrnl") {
                continue;
            }
            let Ok((_journal, records)) = crate::channel::journal::Journal::open(&path) else {
                continue;
            };
            if let Some(crate::channel::journal::Record::Opened { our_pubkey, .. }) =
                records.first()
            {
                pending.push((path, our_pubkey.clone()));
            }
        }
        if pending.is_empty() {
            return;
        }
        // Match each journal to its channel index by deriving keys in order.
        // The cap bounds the search should a foreign journal ever appear.
        let cap = (pending.len() as u32)
            .saturating_mul(64)
            .saturating_add(1024);
        let mut remaining = pending.len();
        let mut g = self.inner.lock().unwrap();
        let mut index = 0u32;
        while remaining > 0 && index < cap {
            let pk = self.signer(index).pubkey().to_vec();
            if let Some(pos) = pending
                .iter()
                .position(|(_, candidate)| !candidate.is_empty() && *candidate == pk)
            {
                let path = pending[pos].0.clone();
                if let Ok(machine) =
                    Machine::reopen(&path, self.network, self.signer(index), self.base_fee_rate)
                {
                    if !matches!(machine.phase(), Phase::Closed) {
                        let cid = machine.channel_id();
                        let capacity = machine.params().capacity.units();
                        g.channels.insert(
                            cid,
                            Chan {
                                machine,
                                // The peer's network id is transient and not
                                // persisted; it is re-bound when the peer
                                // reconnects and a frame arrives for the channel.
                                peer: u64::MAX,
                                capacity,
                                in_flight: false,
                                close: None,
                            },
                        );
                    }
                }
                g.next_index = g.next_index.max(index + 1);
                pending[pos].1.clear();
                remaining -= 1;
            }
            index += 1;
        }
    }

    fn signer(&self, index: u32) -> Box<dyn Signer> {
        Box::new(ChannelKey::from_seed(&funding_key_seed(
            &self.wallet_seed,
            index,
        )))
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
        capacity: u64,
        delay: Option<u16>,
        depth: Option<u16>,
    ) -> Result<Vec<u8>, String> {
        let mut g = self.inner.lock().unwrap();
        let index = g.next_index;
        g.next_index += 1;
        let delay = delay.unwrap_or(self.default_delay);
        let depth = depth.unwrap_or(self.default_depth);
        let our_pubkey = self.signer(index).pubkey().to_vec();
        g.pending_funder.insert(
            peer,
            PendingFunder {
                index,
                capacity,
                delay,
                depth,
            },
        );
        // Hello body: our funding pubkey, capacity, delay, depth.
        let mut w = Writer::new();
        w.var_bytes(&our_pubkey);
        w.u64(capacity);
        w.bytes(&delay.to_le_bytes());
        w.bytes(&depth.to_le_bytes());
        Ok(write_frame(Hash256::ZERO, KIND_HELLO, &w.finish()))
    }

    /// Makes a payment of `amount` to the peer on `cid`.
    pub fn pay(&self, cid: Hash256, amount: u64) -> Result<Vec<u8>, String> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        if chan.machine.phase() != Phase::Open {
            return Err("channel not open".into());
        }
        if chan.in_flight {
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
        chan.in_flight = true;
        Ok(write_frame(cid, KIND_ENGINE, &msg.encode()))
    }

    /// Proposes a cooperative close of `cid`.
    pub fn close(&self, cid: Hash256) -> Result<Vec<u8>, String> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        let msg = chan.machine.propose_close(CLOSE_FEE).map_err(err)?;
        Ok(write_frame(cid, KIND_ENGINE, &msg.encode()))
    }

    /// Signals that `cid`'s funding is buried to the agreed depth, returning
    /// the `ready` frame to send.
    pub fn funding_confirmed(&self, cid: Hash256) -> Result<Vec<u8>, String> {
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        let msg = chan.machine.funding_confirmed().map_err(err)?;
        Ok(write_frame(cid, KIND_ENGINE, &msg.encode()))
    }

    /// Called when a channel-capable peer completes the handshake: the frames to
    /// send it to resync every channel we hold with it. The node routes these;
    /// the engine resends exactly the one in-flight message, if any.
    pub fn on_peer_connected(&self, peer: u64) -> Vec<Vec<u8>> {
        self.reestablish(peer)
    }

    /// The reestablish frames for every channel with `peer`, to send on
    /// reconnection.
    pub fn reestablish(&self, peer: u64) -> Vec<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        g.channels
            .values()
            .filter(|c| c.peer == peer)
            .filter_map(|c| {
                c.machine
                    .reestablish()
                    .ok()
                    .map(|m| write_frame(c.machine.channel_id(), KIND_ENGINE, &m.encode()))
            })
            .collect()
    }

    // --- Inbound ----------------------------------------------------------

    /// Handles one inbound frame from `peer`.
    pub fn deliver(&self, peer: u64, bytes: &[u8]) -> Reaction {
        match self.deliver_inner(peer, bytes) {
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

    fn deliver_inner(&self, peer: u64, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if bytes.len() < 33 {
            return Err("short frame".into());
        }
        let mut r = Reader::new(bytes);
        let cid = Hash256(r.array32().map_err(|_| "cid")?);
        let kind = r.u8().map_err(|_| "kind")?;
        let body = &bytes[33..];
        match kind {
            KIND_HELLO => self.on_hello(peer, body),
            KIND_HELLO_BACK => self.on_hello_back(peer, body),
            KIND_ENGINE => {
                let msg = ChMsg::decode(body).map_err(|_| "bad engine message")?;
                self.on_engine(peer, cid, msg)
            }
            _ => Err("unknown frame kind".into()),
        }
    }

    fn on_hello(&self, peer: u64, body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let mut r = Reader::new(body);
        let funder_pubkey = r.var_bytes().map_err(|_| "pubkey")?.to_vec();
        if funder_pubkey.len() != CHANNEL_SCHEME.pubkey_len() {
            return Err("pubkey length".into());
        }
        let capacity = r.u64().map_err(|_| "capacity")?;
        let delay = u16::from_le_bytes([r.u8().map_err(|_| "d")?, r.u8().map_err(|_| "d")?]);
        let depth = u16::from_le_bytes([r.u8().map_err(|_| "d")?, r.u8().map_err(|_| "d")?]);
        let mut g = self.inner.lock().unwrap();
        let index = g.next_index;
        g.next_index += 1;
        let our_pubkey = self.signer(index).pubkey().to_vec();
        g.pending_acceptor.insert(
            peer,
            PendingAcceptor {
                index,
                funder_pubkey,
                capacity,
                delay,
                depth,
            },
        );
        let mut w = Writer::new();
        w.var_bytes(&our_pubkey);
        Ok(vec![write_frame(
            Hash256::ZERO,
            KIND_HELLO_BACK,
            &w.finish(),
        )])
    }

    fn on_hello_back(&self, peer: u64, body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let mut r = Reader::new(body);
        let acceptor_pubkey = r.var_bytes().map_err(|_| "pubkey")?.to_vec();
        if acceptor_pubkey.len() != CHANNEL_SCHEME.pubkey_len() {
            return Err("pubkey length".into());
        }
        let mut g = self.inner.lock().unwrap();
        let pending = g.pending_funder.remove(&peer).ok_or("no pending open")?;
        let signer = self.signer(pending.index);
        let funding = [
            signer.pubkey_hash(),
            sig::pubkey_hash(CHANNEL_SCHEME, &acceptor_pubkey),
        ];
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
        )
        .map_err(err)?;
        g.channels.insert(
            cid,
            Chan {
                machine,
                peer,
                capacity: pending.capacity,
                in_flight: false,
                close: None,
            },
        );
        Ok(vec![write_frame(cid, KIND_ENGINE, &open.encode())])
    }

    fn on_engine(&self, peer: u64, cid: Hash256, msg: ChMsg) -> Result<Vec<Vec<u8>>, String> {
        // The acceptor's first engine message is the funder's Open: build the
        // channel from the pending acceptor state.
        if matches!(msg, ChMsg::Open { .. }) {
            return self.accept_open(peer, cid, msg);
        }
        let mut g = self.inner.lock().unwrap();
        let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
        // A frame for this channel came from `peer`: that is the live network
        // id to reach the counterparty on, which a reconnect may have changed.
        chan.peer = peer;
        let mut out = Vec::new();
        match msg {
            ChMsg::Accept { .. } => {
                chan.machine.on_accept(&msg).map_err(err)?;
                // Funder builds and broadcasts the funding transaction, then
                // tells the acceptor the outpoint.
                let funding_output = chan.machine.funding_output();
                drop(g); // the fund hook takes the chain lock
                let outpoint = (self.hooks.fund)(cid, funding_output)?;
                let mut g = self.inner.lock().unwrap();
                let chan = g.channels.get_mut(&cid).ok_or("unknown channel")?;
                let m = chan.machine.funding_created(outpoint).map_err(err)?;
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
            }
            ChMsg::Funding { .. } => {
                let m = chan.machine.on_funding(&msg).map_err(err)?;
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
            }
            ChMsg::FundingSigned { .. } => {
                chan.machine.on_funding_signed(&msg).map_err(err)?;
            }
            ChMsg::Ready => {
                chan.machine.on_ready(&msg).map_err(err)?;
            }
            ChMsg::Update { .. } => {
                let m = chan.machine.on_update(&msg).map_err(err)?;
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
            }
            ChMsg::Ack { .. } => {
                let m = chan.machine.on_ack(&msg).map_err(err)?;
                chan.in_flight = false;
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
            }
            ChMsg::Revoke { .. } => {
                chan.machine.on_revoke(&msg).map_err(err)?;
            }
            ChMsg::Close { .. } => {
                let m = chan.machine.on_close(&msg).map_err(err)?;
                out.push(write_frame(cid, KIND_ENGINE, &m.encode()));
            }
            ChMsg::CloseSigned { .. } => {
                let tx = chan.machine.on_close_signed(&msg).map_err(err)?;
                drop(g);
                (self.hooks.broadcast)(&tx)?;
            }
            ChMsg::Reestablish { .. } => {
                let frames = chan.machine.on_reestablish(&msg).map_err(err)?;
                for f in frames {
                    out.push(write_frame(cid, KIND_ENGINE, &f.encode()));
                }
            }
            ChMsg::Error { .. } | ChMsg::Open { .. } => {}
        }
        Ok(out)
    }

    fn accept_open(&self, peer: u64, cid: Hash256, open: ChMsg) -> Result<Vec<Vec<u8>>, String> {
        let mut g = self.inner.lock().unwrap();
        let pending = g
            .pending_acceptor
            .remove(&peer)
            .ok_or("no pending accept")?;
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
        )
        .map_err(err)?;
        if machine.channel_id() != cid {
            return Err("channel id mismatch".into());
        }
        g.channels.insert(
            cid,
            Chan {
                machine,
                peer,
                capacity: pending.capacity,
                in_flight: false,
                close: None,
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
        let decision = classify_spend(chan, funding, tx);
        let sweep_to = (self.hooks.sweep_address)();
        match decision {
            Watch::RevokedByPeer { .. } => {
                let penalty = chan
                    .machine
                    .build_penalty(&decision, sweep_to, CLOSE_FEE)
                    .ok()?;
                let _ = chan.machine.mark_penalised();
                chan.close = Some(CloseTracker::Finalizing {
                    txid: penalty.txid(),
                    penalty: true,
                });
                let _ = (self.hooks.broadcast)(&penalty);
                Some(penalty)
            }
            Watch::PeerLatest {
                to_remote: Some(to_remote),
                ..
            } => {
                let claim = chan
                    .machine
                    .build_to_remote_claim(&to_remote, sweep_to, CLOSE_FEE);
                let _ = chan.machine.mark_forcing();
                chan.close = Some(CloseTracker::Finalizing {
                    txid: claim.txid(),
                    penalty: false,
                });
                let _ = (self.hooks.broadcast)(&claim);
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
        depth_of: &dyn Fn(&OutPoint) -> Option<u64>,
    ) -> Vec<(u64, Vec<u8>)> {
        self.react_to_spends(txs, height);
        let frames = self.confirm_buried(depth_of);
        self.advance_closes(txs, height);
        frames
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
        // A channel already settling on chain ignores further spends.
        if chan.close.is_some() {
            return;
        }
        let Some(funding) = chan.machine.funding_outpoint() else {
            return;
        };
        let decision = classify_spend(chan, funding, tx);
        let sweep_to = (self.hooks.sweep_address)();
        match decision {
            Watch::RevokedByPeer { .. } => {
                if let Ok(penalty) = chan.machine.build_penalty(&decision, sweep_to, CLOSE_FEE) {
                    let _ = chan.machine.mark_penalised();
                    chan.close = Some(CloseTracker::Finalizing {
                        txid: penalty.txid(),
                        penalty: true,
                    });
                    let _ = (self.hooks.broadcast)(&penalty);
                }
            }
            Watch::PeerLatest { to_remote, .. } => {
                let _ = chan.machine.mark_forcing();
                match to_remote {
                    Some(to_remote) => {
                        let claim = chan
                            .machine
                            .build_to_remote_claim(&to_remote, sweep_to, CLOSE_FEE);
                        chan.close = Some(CloseTracker::Finalizing {
                            txid: claim.txid(),
                            penalty: false,
                        });
                        let _ = (self.hooks.broadcast)(&claim);
                    }
                    // Our funds were trimmed to dust: nothing to claim, settled.
                    None => {
                        let _ = chan.machine.mark_closed();
                    }
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
                    None => {
                        let _ = chan.machine.mark_closed();
                    }
                }
            }
            Watch::NotOurChannel | Watch::Unrecognized => {}
        }
    }

    /// Confirms the funding of every channel buried to its agreed depth, moving
    /// it to open and returning the `ready` frame to send its peer.
    fn confirm_buried(&self, depth_of: &dyn Fn(&OutPoint) -> Option<u64>) -> Vec<(u64, Vec<u8>)> {
        let mut g = self.inner.lock().unwrap();
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
                let depth = depth_of(&op)?;
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
            let sweep_to = (self.hooks.sweep_address)();
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
                    // `Older(D)` is satisfied once the chain is `D` blocks past
                    // the commitment: height >= commit_height + D.
                    if height >= commit_height.saturating_add(u64::from(*delay)) {
                        let watch = Watch::OurCommitment {
                            state: *state,
                            to_local: Some(*to_local),
                            delay: *delay,
                        };
                        if let Ok(sweep) =
                            chan.machine.build_local_sweep(&watch, sweep_to, CLOSE_FEE)
                        {
                            let txid = sweep.txid();
                            chan.close = Some(CloseTracker::Finalizing {
                                txid,
                                penalty: false,
                            });
                            let _ = (self.hooks.broadcast)(&sweep);
                        }
                    }
                }
                Some(CloseTracker::Finalizing { txid, penalty }) => {
                    let txid = *txid;
                    let penalty = *penalty;
                    if txs.iter().any(|t| t.txid() == txid) {
                        if penalty {
                            let _ = chan.machine.mark_penalised();
                        }
                        let _ = chan.machine.mark_closed();
                        chan.close = None;
                    }
                }
                None => {}
            }
        }
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

/// Classifies a funding-output spend for `chan`.
fn classify_spend(chan: &Chan, funding: OutPoint, tx: &Transaction) -> Watch {
    let ctx = WatchContext {
        params: chan.machine.params(),
        our_index: chan.machine.our_index(),
        store: chan.machine.revocation_store(),
        latest_state: chan.machine.local_commit_number().unwrap_or(0),
    };
    classify(&ctx, funding, tx)
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
    fn deliver(&self, peer: u64, bytes: &[u8]) -> crate::net::ChannelOutcome {
        let r = ChannelManager::deliver(self, peer, bytes);
        crate::net::ChannelOutcome {
            replies: r.frames,
            penalize: r.penalize,
        }
    }

    fn on_connected_block(
        &self,
        txs: &[Transaction],
        height: u64,
        depth_of: &dyn Fn(&OutPoint) -> Option<u64>,
    ) -> Vec<(u64, Vec<u8>)> {
        ChannelManager::on_connected_block(self, txs, height, depth_of)
    }

    fn on_peer_connected(&self, peer: u64) -> Vec<Vec<u8>> {
        ChannelManager::on_peer_connected(self, peer)
    }
}
