//! The channel state machine: explicit phases, an append-only journal, and the
//! invariants that make a crash survivable.
//!
//! # Phases
//!
//! ```text
//! OPENING ─ funding built & both first commitments signed ─▶ FUNDED
//! FUNDED  ─ funding buried to depth ───────────────────────▶ OPEN
//! OPEN    ─ cooperative close agreed ───────────────────────▶ CLOSING
//! OPEN    ─ a commitment is to be broadcast ────────────────▶ FORCING
//! OPEN    ─ a revoked commitment of the peer seen ──────────▶ PENALISED
//! {CLOSING, FORCING, PENALISED} ─ settled on chain ─────────▶ CLOSED
//! ```
//!
//! # The three safety invariants, and where they are enforced
//!
//! **INV1 — never reveal state `m`'s revocation secret before the signed state
//! `m+1` is persisted.** Revealing `secret(m)` abandons our commitment `m`; we
//! do it only once we hold a counterparty-signed commitment `m+1` we can
//! enforce instead. In code: every path that builds a [`Revocation`] first
//! asserts `local_commit_number >= m + 1`, and `local_commit_number` only
//! advances when a [`Record::LocalCommit`] has been `fsync`ed.
//!
//! **INV2 — never acknowledge a received update before its signature is
//! persisted.** [`Machine::on_update`] and [`Machine::on_ack`] append the
//! `LocalCommit` record (which carries the counterparty's signature over our
//! commitment) and wait for the `fsync` to return *before* building the Ack or
//! Revoke that acknowledges it. A crash after sending but before persisting is
//! impossible: the persist comes first.
//!
//! **INV3 — after a crash at any point, reestablish brings both sides to the
//! same latest state, with no loss and with neither side holding a commitment
//! the other has already revoked.** State is reconstructed from the journal
//! alone ([`Machine::reopen`]); [`Machine::on_reestablish`] compares the two
//! sides' persisted counters and resends exactly the one in-flight message
//! that did not land. The handlers are idempotent, so a resend that did land
//! changes nothing.
//!
//! # Crossed proposals
//!
//! When both sides propose the same state `n` at once, each has signed the
//! other's commitment `n` at its own proposal. Neither proposal may become
//! state `n`: the other side would keep a signature over a different, for it
//! better, commitment at the same index, enforceable until the index is
//! revoked. Instead both are merged into `n + 1` ([`Machine::on_crossed_update`]):
//! each side takes the peer's proposal as its commitment `n` and reveals the
//! secret of `n - 1`; the side holding the initiative then proposes `n + 1`
//! with both payments, and completing it reveals both secrets of `n`, which
//! revokes every commitment at that index whatever its balances.

use crate::address::Network;
use crate::channel::journal::{Balances, Journal, Record};
use crate::channel::keys::{Signer, CHANNEL_SCHEME};
use crate::channel::messages::{Message, Revocation, TierSigs};
use crate::channel::txbuild::{self, ChannelParams, Commitment, FeeTier, ACCEPTOR, FUNDER};
use crate::channel::watcher::{OutputRef, Watch};
use crate::hash::{tagged_hash_parts, Hash256};
use crate::sha256::sha256;
use crate::shachain;
use crate::tx::{OutPoint, Transaction, TxOut};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

/// The channel's lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Opening,
    Funded,
    Open,
    Closing,
    Forcing,
    Penalised,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// A journal write failed; the text is the OS error.
    Io(String),
    /// A counterparty signature did not verify.
    BadSignature,
    /// A revealed revocation secret did not match its announced point, or
    /// was inconsistent with the shachain.
    BadRevocation,
    /// A message arrived in a phase that does not expect it.
    Unexpected,
    /// A reestablish proof did not verify, or reused a nonce.
    BadReestablish,
    /// The balances of an update do not conserve the capacity, or underflow.
    BadBalances,
    /// A received update would move funds the wrong way — it lowers our own
    /// balance. A payment to us may only keep or raise our side; a proposer
    /// never drains the receiver.
    WrongDirection,
    /// An opening parameter (to-self delay, funding depth, or capacity) is out
    /// of the range this node will accept.
    BadParameters,
    /// We lack randomness for a nonce.
    NoRandomness,
    /// A guard caught an attempt to break a safety invariant. Should never
    /// fire; it means a caller sequenced the protocol wrongly.
    Invariant(&'static str),
}

impl From<std::io::Error> for ChannelError {
    fn from(e: std::io::Error) -> Self {
        ChannelError::Io(e.to_string())
    }
}

/// Derivation tag of the reestablish proof message.
const TAG_REESTABLISH: &str = "Q21/channel/reestablish-proof";

/// The channel identifier: a tagged hash of both funding keys, funder first,
/// so both sides compute the same value before any funding transaction exists.
pub fn channel_id(funding: &[Hash256; 2]) -> Hash256 {
    tagged_hash_parts(
        "Q21/channel/id",
        &[funding[0].as_bytes(), funding[1].as_bytes()],
    )
}

/// The root of our revocation shachain derives every revocation secret of the
/// channel, past and future: it does not outlive the machine.
impl Drop for Machine {
    fn drop(&mut self) {
        crate::kdf::wipe(&mut self.revocation_seed);
    }
}

/// `base` plus the payments of both proposals over it, or `None` on overflow.
fn merge(base: Balances, ours: Balances, theirs: Balances) -> Option<Balances> {
    let mut out = [0u64; 2];
    for i in 0..2 {
        out[i] = ours[i].checked_add(theirs[i])?.checked_sub(base[i])?;
    }
    Some(out)
}

/// Keeps only the `keep` highest states of a per-state map.
fn prune_to_latest<V>(map: &mut BTreeMap<u64, V>, keep: usize) {
    while map.len() > keep {
        let oldest = *map.keys().next().expect("non-empty");
        map.remove(&oldest);
    }
}

/// The message a reestablish proof signs: the channel, the sender's nonce, and
/// the sender's direction.
fn reestablish_message(channel_id: Hash256, nonce: [u8; 32], direction: u8) -> Hash256 {
    tagged_hash_parts(
        TAG_REESTABLISH,
        &[channel_id.as_bytes(), &nonce, &[direction]],
    )
}

/// One running channel.
pub struct Machine {
    params: ChannelParams,
    network: Network,
    /// Our own index: `FUNDER` or `ACCEPTOR`.
    our_index: usize,
    channel_id: Hash256,
    signer: Box<dyn Signer>,
    our_pubkey: Vec<u8>,
    their_pubkey: Vec<u8>,
    /// Each party's wallet payout address, `[funder, acceptor]`, used to build a
    /// cooperative close that pays spendable wallet outputs rather than channel
    /// keys no wallet scans.
    payout: [Hash256; 2],
    /// The root of our revocation shachain.
    revocation_seed: [u8; 32],
    funding_depth: u16,

    journal: Journal,
    phase: Phase,

    funding_outpoint: Option<OutPoint>,

    // --- Persisted counters, reconstructed on reopen. ---
    /// Highest state we hold a counterparty signature for (can enforce).
    local_commit_number: Option<u64>,
    /// Highest state we have signed the counterparty's commitment for.
    remote_commit_number: Option<u64>,
    /// Highest state we have revealed our revocation secret for.
    revocations_sent: Option<u64>,
    /// Highest state we hold the counterparty's revocation secret for.
    revocations_recv: Option<u64>,

    /// Our enforceable commitments, by state: balances and the counterparty's
    /// tier signatures. We keep the latest and the previous (the previous only
    /// to reason about reestablish; it is never broadcast once revoked).
    local_commits: BTreeMap<u64, (Balances, [Vec<u8>; 3])>,
    /// Balances we signed the counterparty's commitment at, by state.
    remote_balances: BTreeMap<u64, Balances>,
    /// Whether we initiated each recent state. The initiator persists its
    /// `RemoteCommit` before its `LocalCommit`, the responder the reverse, so
    /// replay recovers this from the order of the records. Reestablish needs it
    /// to resend the right message: a `Revoke` from the initiator, an `Ack`
    /// from the responder.
    initiated: BTreeMap<u64, bool>,
    /// The fee of the cooperative close we agreed to, once closing, so the
    /// `Close` can be sent again after a crash or a reconnect.
    close_fee: Option<u64>,
    /// Who pays the agreed close's fee: the party that proposed it.
    close_payer: Option<usize>,
    /// The funder's signed funding transaction, until the channel opens.
    funding_tx: Option<Transaction>,
    /// Whether we may have signed the cooperative close. Until we have, a
    /// payment to us that crossed our `Close` on the wire is still accepted;
    /// once we have, the peer holds a close over the old balances and no update
    /// may follow. Conservatively true for a channel reloaded while closing.
    close_signed: bool,
    /// The peer's signature over the cooperative close, once received.
    close_peer_sig: Option<Vec<u8>>,
    /// The height at which the funding confirmed, once known.
    funding_height: Option<u64>,

    /// The counterparty's announced revocation points, by state.
    their_points: BTreeMap<u64, Hash256>,
    /// The counterparty's revealed secrets, compact.
    store: shachain::Store,

    /// Base fee rate (per thousand weight units); the tiers multiply it.
    base_fee_rate: u64,

    /// Reestablish nonces already accepted from the peer, for freshness: the
    /// most recent [`MAX_SEEN_NONCES`], oldest first.
    seen_nonces: VecDeque<[u8; 32]>,
    /// A state the peer proposed and we have not received, as its last
    /// reestablish showed: it signed our commitment at that state. Its update
    /// was lost with the old link and comes again; until it lands, a proposal
    /// of ours would cross it. Not journaled: every reestablish sets it anew.
    peer_proposal: Option<u64>,
    /// A state both sides proposed at once (see "Crossed proposals" in the
    /// module documentation). Set until the merged state above it settles.
    crossed: Option<u64>,
}

/// Reestablish nonces remembered per channel. One is accepted per reconnection;
/// the window covers far more reconnections than a captured message could
/// usefully be replayed across, and bounds what a long-lived channel keeps.
pub const MAX_SEEN_NONCES: usize = 64;

/// Records a journal may hold before it is compacted into the few that
/// rebuild the same state. An update appends five or six, each commitment
/// record carrying three ML-DSA-87 signatures (about 14 KB).
pub const COMPACT_AFTER: usize = 64;

impl Machine {
    // --- Construction --------------------------------------------------------

    /// Opens the funder's side of a fresh channel and returns it with the
    /// [`Message::Open`] to send. The journal is created at `journal_path`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_funder(
        journal_path: impl AsRef<Path>,
        network: Network,
        signer: Box<dyn Signer>,
        their_pubkey: Vec<u8>,
        capacity: u64,
        delay: u16,
        funding_depth: u16,
        base_fee_rate: u64,
        our_payout: Hash256,
        their_payout: Hash256,
    ) -> Result<(Machine, Message), ChannelError> {
        let our_pubkey = signer.pubkey().to_vec();
        let funding = [
            signer.pubkey_hash(),
            crate::sig::pubkey_hash(CHANNEL_SCHEME, &their_pubkey),
        ];
        let params = ChannelParams {
            funding,
            capacity: crate::amount::Amount::from_units(capacity),
            delay,
        };
        // Funder is index 0, acceptor index 1.
        let payout = [our_payout, their_payout];
        let m = Machine::bootstrap(
            journal_path,
            network,
            FUNDER,
            signer,
            our_pubkey.clone(),
            their_pubkey,
            params,
            funding_depth,
            base_fee_rate,
            payout,
        )?;
        let open = Message::Open {
            capacity,
            delay,
            funding_depth,
            funder_pubkey: our_pubkey,
            first_hashes: vec![m.our_point(0), m.our_point(1)],
        };
        Ok((m, open))
    }

    /// Accepts an incoming [`Message::Open`] on the acceptor's side, returning
    /// the channel and the [`Message::Accept`] to send.
    pub fn accept(
        journal_path: impl AsRef<Path>,
        network: Network,
        signer: Box<dyn Signer>,
        base_fee_rate: u64,
        open: &Message,
        our_payout: Hash256,
        their_payout: Hash256,
    ) -> Result<(Machine, Message), ChannelError> {
        let Message::Open {
            capacity,
            delay,
            funding_depth,
            funder_pubkey,
            first_hashes,
        } = open
        else {
            return Err(ChannelError::Unexpected);
        };
        // H3: the funder chooses these; an acceptor must refuse an open that
        // would leave its funds unprotected or frozen. A too-short to-self delay
        // gives a revoked cheater's own sweep no head-start over our penalty; a
        // huge one freezes funds for years; depth 0 would treat an unconfirmed
        // funding as final; a dust capacity cannot carry two outputs and a fee.
        if *delay < crate::channel::MIN_DELAY_REGTEST
            || *delay > crate::channel::MAX_DELAY
            || *funding_depth < crate::channel::DEFAULT_FUNDING_DEPTH
            || *capacity < crate::channel::MIN_CAPACITY
            || *capacity > crate::channel::MAX_CAPACITY
        {
            return Err(ChannelError::BadParameters);
        }
        let our_pubkey = signer.pubkey().to_vec();
        let funding = [
            crate::sig::pubkey_hash(CHANNEL_SCHEME, funder_pubkey),
            signer.pubkey_hash(),
        ];
        let params = ChannelParams {
            funding,
            capacity: crate::amount::Amount::from_units(*capacity),
            delay: *delay,
        };
        // Acceptor is index 1; the funder's payout is index 0.
        let payout = [their_payout, our_payout];
        let mut m = Machine::bootstrap(
            journal_path,
            network,
            ACCEPTOR,
            signer,
            our_pubkey.clone(),
            funder_pubkey.clone(),
            params,
            *funding_depth,
            base_fee_rate,
            payout,
        )?;
        m.record_their_points(first_hashes)?;
        let accept = Message::Accept {
            acceptor_pubkey: our_pubkey,
            first_hashes: vec![m.our_point(0), m.our_point(1)],
        };
        Ok((m, accept))
    }

    #[allow(clippy::too_many_arguments)]
    fn bootstrap(
        journal_path: impl AsRef<Path>,
        network: Network,
        our_index: usize,
        signer: Box<dyn Signer>,
        our_pubkey: Vec<u8>,
        their_pubkey: Vec<u8>,
        params: ChannelParams,
        funding_depth: u16,
        base_fee_rate: u64,
        payout: [Hash256; 2],
    ) -> Result<Machine, ChannelError> {
        let cid = channel_id(&params.funding);
        let revocation_seed = signer.revocation_root(&cid);
        let (mut journal, existing) = Journal::open(journal_path)?;
        if !existing.is_empty() {
            return Err(ChannelError::Invariant("journal already in use"));
        }
        journal.append(&Record::Opened {
            channel_id: cid,
            our_index: our_index as u8,
            funding: params.funding,
            capacity: params.capacity.units(),
            delay: params.delay,
            funding_depth,
            our_pubkey: our_pubkey.clone(),
            their_pubkey: their_pubkey.clone(),
            payout,
        })?;
        Ok(Machine {
            params,
            network,
            our_index,
            channel_id: cid,
            signer,
            our_pubkey,
            their_pubkey,
            payout,
            revocation_seed,
            funding_depth,
            journal,
            phase: Phase::Opening,
            funding_outpoint: None,
            local_commit_number: None,
            remote_commit_number: None,
            revocations_sent: None,
            revocations_recv: None,
            local_commits: BTreeMap::new(),
            remote_balances: BTreeMap::new(),
            initiated: BTreeMap::new(),
            close_fee: None,
            close_payer: None,
            funding_tx: None,
            close_signed: false,
            close_peer_sig: None,
            funding_height: None,
            their_points: BTreeMap::new(),
            store: shachain::Store::new(),
            base_fee_rate,
            seen_nonces: VecDeque::new(),
            peer_proposal: None,
            crossed: None,
        })
    }

    // --- Revocation points ---------------------------------------------------

    fn our_secret(&self, n: u64) -> [u8; 32] {
        shachain::derive(&self.revocation_seed, shachain::MAX_INDEX - n)
    }

    fn our_point(&self, n: u64) -> Hash256 {
        // The secret of a state not yet revoked: no copy of it outlives this.
        let mut secret = self.our_secret(n);
        let point = Hash256(sha256(&secret));
        crate::kdf::wipe(&mut secret);
        point
    }

    fn record_their_points(&mut self, hashes: &[Hash256]) -> Result<(), ChannelError> {
        for (i, h) in hashes.iter().enumerate() {
            self.journal.append(&Record::TheirPoint {
                state: i as u64,
                point: *h,
            })?;
            self.their_points.insert(i as u64, *h);
        }
        Ok(())
    }

    // --- Fees ----------------------------------------------------------------

    fn commit_fee(&self, tier: FeeTier) -> u64 {
        txbuild::commitment_fee(&self.params, txbuild::tier_rate(self.base_fee_rate, tier))
    }

    // --- Commitment construction --------------------------------------------

    fn with_funding_input(&self, mut c: Commitment) -> Commitment {
        if let Some(op) = self.funding_outpoint {
            c.tx.inputs[0].prev_out = op;
        }
        c
    }

    /// The counterparty's commitment at state `n`, tier `tier`: they are the
    /// holder, so the revocation point is theirs.
    fn their_commitment(&self, n: u64, bal: Balances, tier: FeeTier) -> Option<Commitment> {
        let holder = 1 - self.our_index;
        let rev = *self.their_points.get(&n)?;
        Some(self.with_funding_input(self.params.commitment(
            holder,
            n,
            bal,
            self.commit_fee(tier),
            rev,
        )))
    }

    /// Our own commitment at state `n`, tier `tier`: we are the holder, so the
    /// revocation point is ours.
    fn our_commitment(&self, n: u64, bal: Balances, tier: FeeTier) -> Commitment {
        let rev = self.our_point(n);
        self.with_funding_input(self.params.commitment(
            self.our_index,
            n,
            bal,
            self.commit_fee(tier),
            rev,
        ))
    }

    /// Signs the counterparty's commitment at `n`, at every tier.
    fn sign_their_commitment(&self, n: u64, bal: Balances) -> Result<TierSigs, ChannelError> {
        let mut sigs: [Vec<u8>; 3] = Default::default();
        for tier in FeeTier::ALL {
            let c = self
                .their_commitment(n, bal, tier)
                .ok_or(ChannelError::Invariant("missing counterparty point"))?;
            let m = self
                .params
                .funding_sighash(&c.tx, self.network, self.our_index);
            sigs[tier as usize] = self.signer.sign(&m);
        }
        Ok(sigs)
    }

    /// Verifies the counterparty's signatures over our commitment at `n`, at
    /// every tier.
    fn verify_our_commitment(
        &self,
        n: u64,
        bal: Balances,
        sigs: &TierSigs,
    ) -> Result<(), ChannelError> {
        let their_leaf = (1 - self.our_index) as u8;
        let policy_bytes = self.params.funding_policy().encode();
        let spent = self.params.funding_output();
        for tier in FeeTier::ALL {
            let c = self.our_commitment(n, bal, tier);
            crate::policy::check_signature(
                &c.tx,
                0,
                self.network,
                &spent,
                &policy_bytes,
                their_leaf,
                &[],
                &self.their_pubkey,
                &sigs[tier as usize],
            )
            .map_err(|_| ChannelError::BadSignature)?;
        }
        Ok(())
    }

    // --- Balance checks ------------------------------------------------------

    fn check_balances(&self, bal: Balances) -> Result<(), ChannelError> {
        let sum = bal[0]
            .checked_add(bal[1])
            .ok_or(ChannelError::BadBalances)?;
        if sum != self.params.capacity.units() {
            return Err(ChannelError::BadBalances);
        }
        // The funder must still cover the highest-tier commitment fee.
        if bal[FUNDER] < self.commit_fee(FeeTier::High) {
            return Err(ChannelError::BadBalances);
        }
        Ok(())
    }

    // --- Opening handshake ---------------------------------------------------

    /// Funder: learns the acceptor's key from [`Message::Accept`]. The funding
    /// transaction is built outside the engine (by the wallet); call
    /// [`Machine::funding_created`] once its outpoint is known.
    pub fn on_accept(&mut self, accept: &Message) -> Result<(), ChannelError> {
        let Message::Accept {
            acceptor_pubkey,
            first_hashes,
        } = accept
        else {
            return Err(ChannelError::Unexpected);
        };
        if self.our_index != FUNDER || self.phase != Phase::Opening {
            return Err(ChannelError::Unexpected);
        }
        // Already accepted: a replayed Accept must not fund the channel a
        // second time (see [`Machine::accepted`]).
        if self.accepted() {
            return Err(ChannelError::Unexpected);
        }
        // The acceptor's key was already folded into the funding policy at
        // construction; re-check it matches what we accepted.
        if crate::sig::pubkey_hash(CHANNEL_SCHEME, acceptor_pubkey) != self.params.funding[ACCEPTOR]
        {
            return Err(ChannelError::Unexpected);
        }
        self.their_pubkey = acceptor_pubkey.clone();
        self.record_their_points(first_hashes)?;
        Ok(())
    }

    /// Funder: whether the acceptor's `Accept` has been taken. Explicit in the
    /// state: the acceptor's announced points are recorded at that moment.
    pub fn accepted(&self) -> bool {
        self.our_index == FUNDER && !self.their_points.is_empty()
    }

    /// Funder: records the signed funding transaction — not broadcast: that
    /// waits for the acceptor's signature over our first commitment
    /// ([`Machine::on_funding_signed`]) — and returns [`Message::Funding`].
    pub fn funding_built(
        &mut self,
        outpoint: OutPoint,
        tx: &Transaction,
    ) -> Result<Message, ChannelError> {
        if self.our_index != FUNDER || self.phase != Phase::Opening || !self.accepted() {
            return Err(ChannelError::Unexpected);
        }
        if tx.txid() != outpoint.txid
            || tx.outputs.get(outpoint.index as usize) != Some(&self.params.funding_output())
        {
            return Err(ChannelError::Invariant(
                "funding transaction does not fund the channel",
            ));
        }
        self.journal
            .append(&Record::FundingTx { tx: tx.encode() })?;
        self.funding_tx = Some(tx.clone());
        self.funding_created(outpoint)
    }

    /// The funder's signed funding transaction, kept until the channel opens.
    pub fn funding_tx(&self) -> Option<&Transaction> {
        self.funding_tx.as_ref()
    }

    /// Funder: the `Funding` message again, for an acceptor that asks twice.
    pub fn funding_message(&self) -> Result<Message, ChannelError> {
        let outpoint = self.funding()?;
        let bal = [self.params.capacity.units(), 0];
        Ok(Message::Funding {
            funding_txid: outpoint.txid,
            funding_index: outpoint.index,
            tier_sigs: self.sign_their_commitment(0, bal)?,
        })
    }

    /// Funder: records the funding outpoint and returns [`Message::Funding`]
    /// with our signatures of the acceptor's first commitment.
    pub fn funding_created(&mut self, outpoint: OutPoint) -> Result<Message, ChannelError> {
        if self.our_index != FUNDER || self.phase != Phase::Opening {
            return Err(ChannelError::Unexpected);
        }
        if self.funding_outpoint.is_some() {
            return Err(ChannelError::Unexpected);
        }
        self.set_funding(outpoint)?;
        let bal = [self.params.capacity.units(), 0];
        let tier_sigs = self.sign_their_commitment(0, bal)?;
        self.persist_remote_commit(0, bal)?;
        Ok(Message::Funding {
            funding_txid: outpoint.txid,
            funding_index: outpoint.index,
            tier_sigs,
        })
    }

    /// Acceptor: handles [`Message::Funding`], returning
    /// [`Message::FundingSigned`].
    pub fn on_funding(&mut self, funding: &Message) -> Result<Message, ChannelError> {
        let Message::Funding {
            funding_txid,
            funding_index,
            tier_sigs,
        } = funding
        else {
            return Err(ChannelError::Unexpected);
        };
        if self.our_index != ACCEPTOR || self.phase != Phase::Opening {
            return Err(ChannelError::Unexpected);
        }
        let outpoint = OutPoint {
            txid: *funding_txid,
            index: *funding_index,
        };
        // One funding per channel. The same Funding again (its answer was
        // lost) is answered again; another outpoint is refused rather than
        // overwriting the first.
        if let Some(known) = self.funding_outpoint {
            if known != outpoint || self.local_commit_number != Some(0) {
                return Err(ChannelError::Unexpected);
            }
            let bal = [self.params.capacity.units(), 0];
            self.verify_our_commitment(0, bal, tier_sigs)?;
            return Ok(Message::FundingSigned {
                tier_sigs: self.sign_their_commitment(0, bal)?,
            });
        }
        self.set_funding(outpoint)?;
        let bal = [self.params.capacity.units(), 0];
        // INV2: persist their signature over our commitment 0 before we
        // acknowledge by signing theirs.
        self.verify_our_commitment(0, bal, tier_sigs)?;
        self.persist_local_commit(0, bal, tier_sigs.clone(), /*we_initiated=*/ false)?;
        let our_sigs = self.sign_their_commitment(0, bal)?;
        self.persist_remote_commit(0, bal)?;
        Ok(Message::FundingSigned {
            tier_sigs: our_sigs,
        })
    }

    /// Funder: handles [`Message::FundingSigned`]. After this both sides hold a
    /// signed commitment 0; the funder may broadcast the funding transaction.
    pub fn on_funding_signed(&mut self, msg: &Message) -> Result<(), ChannelError> {
        let Message::FundingSigned { tier_sigs } = msg else {
            return Err(ChannelError::Unexpected);
        };
        if self.our_index != FUNDER || self.phase != Phase::Opening {
            return Err(ChannelError::Unexpected);
        }
        let bal = [self.params.capacity.units(), 0];
        self.verify_our_commitment(0, bal, tier_sigs)?;
        self.persist_local_commit(0, bal, tier_sigs.clone(), /*we_initiated=*/ true)?;
        self.phase = Phase::Funded;
        Ok(())
    }

    fn set_funding(&mut self, outpoint: OutPoint) -> Result<(), ChannelError> {
        self.funding_outpoint = Some(outpoint);
        self.journal.append(&Record::Funded {
            funding_txid: outpoint.txid,
            funding_index: outpoint.index,
        })?;
        Ok(())
    }

    /// Either side: the funding transaction is buried to the agreed depth.
    /// Returns [`Message::Ready`].
    pub fn funding_confirmed(&mut self) -> Result<Message, ChannelError> {
        if !matches!(self.phase, Phase::Funded | Phase::Opening) {
            return Err(ChannelError::Unexpected);
        }
        // The acceptor reaches FUNDED only via its own commitment 0; both have
        // LocalCommit(0) by now.
        self.journal.append(&Record::Ready)?;
        self.phase = Phase::Open;
        Ok(Message::Ready)
    }

    /// Either side: the peer signalled readiness.
    pub fn on_ready(&mut self, msg: &Message) -> Result<(), ChannelError> {
        if !matches!(msg, Message::Ready) {
            return Err(ChannelError::Unexpected);
        }
        Ok(())
    }

    // --- Payment update flow -------------------------------------------------

    /// Initiator: proposes moving to `balances` (the new `[funder, acceptor]`),
    /// returning the [`Message::Update`] to send. Persists our signature of the
    /// counterparty's new commitment before returning.
    pub fn propose(&mut self, balances: Balances) -> Result<Message, ChannelError> {
        if self.phase != Phase::Open {
            return Err(ChannelError::Unexpected);
        }
        self.check_balances(balances)?;
        let n = self.next_state();
        let tier_sigs = self.sign_their_commitment(n, balances)?;
        // Persist that we are committed to the counterparty's new state before
        // the signature leaves us.
        self.persist_remote_commit(n, balances)?;
        Ok(Message::Update {
            state: n,
            balances,
            tier_sigs,
        })
    }

    /// Responder: handles [`Message::Update`], returning [`Message::Ack`].
    pub fn on_update(&mut self, msg: &Message) -> Result<Message, ChannelError> {
        let Message::Update {
            state,
            balances,
            tier_sigs,
        } = msg
        else {
            return Err(ChannelError::Unexpected);
        };
        let n = *state;
        // State 0 is the funding commitment, never the subject of an update;
        // its predecessor `n - 1` does not exist.
        if n == 0 {
            return Err(ChannelError::Unexpected);
        }
        // Idempotent resend: we already processed this update. Answered even
        // once a cooperative close is agreed, so an update that was in flight
        // when the close began still completes.
        if matches!(self.phase, Phase::Open | Phase::Closing) && self.local_commit_number >= Some(n)
        {
            return self.resend_ack(n);
        }
        // A payment to us may still cross our own `Close`; it settles before
        // the close does. Never once we may have signed the close.
        let closing_open = self.phase == Phase::Closing && !self.close_signed;
        if self.phase != Phase::Open && !closing_open {
            return Err(ChannelError::Unexpected);
        }
        if n != self.next_state() {
            return Err(ChannelError::Unexpected);
        }
        self.check_balances(*balances)?;
        // C1: a received update is a payment the proposer makes TO us, so our
        // own balance may only stay the same or rise. A peer that lowers our
        // side is trying to drain us — reject it before we persist the drained
        // commitment or reveal any revocation secret. (We countersign and
        // reveal only after this guard; nothing is journaled above.)
        //
        // After crossed proposals at `n - 1`, the state above them is the merge
        // of both, and nothing else: the side holding the initiative proposes
        // it, the other accepts exactly that.
        let us = self.our_index;
        if self.crossed.is_some() && self.crossed == self.local_commit_number {
            if Some(*balances) != self.merged_balances() {
                return Err(ChannelError::BadBalances);
            }
        } else if balances[us] < self.current_balances()[us] {
            return Err(ChannelError::WrongDirection);
        }
        // INV2: persist the counterparty's signature over our commitment `n`
        // before acknowledging.
        self.verify_our_commitment(n, *balances, tier_sigs)?;
        self.persist_local_commit(
            n,
            *balances,
            tier_sigs.clone(),
            /*we_initiated=*/ false,
        )?;
        // Sign the counterparty's commitment `n` and persist that we did.
        let our_sigs = self.sign_their_commitment(n, *balances)?;
        self.persist_remote_commit(n, *balances)?;
        // INV1: reveal our secret for `n-1` only now that `n` is persisted.
        let revocation = self.make_revocation(n - 1)?;
        self.persist_revocation_sent(n - 1)?;
        Ok(Message::Ack {
            state: n,
            tier_sigs: our_sigs,
            revocation,
        })
    }

    /// Initiator: handles [`Message::Ack`], returning [`Message::Revoke`].
    pub fn on_ack(&mut self, msg: &Message) -> Result<Message, ChannelError> {
        let Message::Ack {
            state,
            tier_sigs,
            revocation,
        } = msg
        else {
            return Err(ChannelError::Unexpected);
        };
        // Our own proposal may complete after a cooperative close was agreed:
        // the Ack only settles the state we already committed to.
        if !matches!(self.phase, Phase::Open | Phase::Closing) {
            return Err(ChannelError::Unexpected);
        }
        let n = *state;
        // State 0 is the funding commitment, never the subject of an update;
        // its predecessor `n - 1` does not exist.
        if n == 0 {
            return Err(ChannelError::Unexpected);
        }
        // Idempotent resend path.
        if self.local_commit_number >= Some(n) && self.revocations_recv >= Some(n - 1) {
            return self.resend_revoke(n);
        }
        if self.remote_commit_number != Some(n) {
            return Err(ChannelError::Unexpected);
        }
        let balances = *self
            .remote_balances
            .get(&n)
            .ok_or(ChannelError::Invariant("missing remote balances"))?;
        // INV2: persist the counterparty's signature over our commitment `n`.
        self.verify_our_commitment(n, balances, tier_sigs)?;
        self.persist_local_commit(n, balances, tier_sigs.clone(), /*we_initiated=*/ true)?;
        // Store the counterparty's revocation of `n-1`.
        self.take_revocation(n - 1, revocation)?;
        // INV1: our commitment `n` is persisted, so reveal our secret `n-1`.
        let our_rev = self.make_revocation(n - 1)?;
        self.persist_revocation_sent(n - 1)?;
        self.compact_if_long()?;
        Ok(Message::Revoke {
            state: n,
            revocation: our_rev,
        })
    }

    /// Responder: handles [`Message::Revoke`], completing the update.
    pub fn on_revoke(&mut self, msg: &Message) -> Result<(), ChannelError> {
        let Message::Revoke { state, revocation } = msg else {
            return Err(ChannelError::Unexpected);
        };
        let n = *state;
        // State 0 is the funding commitment, never the subject of an update;
        // its predecessor `n - 1` does not exist.
        if n == 0 {
            return Err(ChannelError::Unexpected);
        }
        if self.revocations_recv >= Some(n - 1) {
            return Ok(()); // idempotent resend
        }
        self.take_revocation(n - 1, revocation)?;
        self.compact_if_long()?;
        Ok(())
    }

    fn next_state(&self) -> u64 {
        self.local_commit_number
            .map_or(0, |n| n + 1)
            .max(self.remote_commit_number.map_or(0, |n| n + 1))
    }

    fn make_revocation(&self, m: u64) -> Result<Revocation, ChannelError> {
        // INV1 guard.
        if self.local_commit_number < Some(m + 1) {
            return Err(ChannelError::Invariant(
                "would reveal a secret before the replacement state is persisted",
            ));
        }
        Ok(Revocation {
            secret: self.our_secret(m),
            next_hash: self.our_point(m + 2),
        })
    }

    fn take_revocation(&mut self, m: u64, rev: &Revocation) -> Result<(), ChannelError> {
        let announced = self
            .their_points
            .get(&m)
            .copied()
            .ok_or(ChannelError::BadRevocation)?;
        if Hash256(sha256(&rev.secret)) != announced {
            return Err(ChannelError::BadRevocation);
        }
        self.store
            .insert(rev.secret, shachain::MAX_INDEX - m)
            .map_err(|_| ChannelError::BadRevocation)?;
        // Persist the newly announced point before recording the revocation,
        // so a crash never loses a point a resend would need.
        self.journal.append(&Record::TheirPoint {
            state: m + 2,
            point: rev.next_hash,
        })?;
        self.their_points.remove(&m);
        self.their_points.insert(m + 2, rev.next_hash);
        self.persist_revocation_recv(m, rev.secret)?;
        Ok(())
    }

    // --- Persistence helpers (each fsyncs before returning) ------------------

    fn persist_local_commit(
        &mut self,
        n: u64,
        bal: Balances,
        their_sigs: [Vec<u8>; 3],
        we_initiated: bool,
    ) -> Result<(), ChannelError> {
        self.journal.append(&Record::LocalCommit {
            state: n,
            balances: bal,
            their_tier_sigs: their_sigs.clone(),
        })?;
        self.local_commit_number = Some(n);
        self.local_commits.insert(n, (bal, their_sigs));
        // Keep only the latest two enforceable commitments.
        while self.local_commits.len() > 2 {
            let oldest = *self.local_commits.keys().next().unwrap();
            self.local_commits.remove(&oldest);
        }
        self.note_initiator(n, we_initiated);
        Ok(())
    }

    /// Records who initiated state `n`, the first time it is seen.
    fn note_initiator(&mut self, n: u64, we_initiated: bool) {
        self.initiated.entry(n).or_insert(we_initiated);
        while self.initiated.len() > 3 {
            let oldest = *self.initiated.keys().next().unwrap();
            self.initiated.remove(&oldest);
        }
    }

    fn persist_remote_commit(&mut self, n: u64, bal: Balances) -> Result<(), ChannelError> {
        self.journal.append(&Record::RemoteCommit {
            state: n,
            balances: bal,
        })?;
        self.remote_commit_number = Some(n);
        self.remote_balances.insert(n, bal);
        prune_to_latest(&mut self.remote_balances, 2);
        // A RemoteCommit journaled before its LocalCommit marks the initiator.
        self.note_initiator(n, true);
        Ok(())
    }

    fn persist_revocation_sent(&mut self, m: u64) -> Result<(), ChannelError> {
        // A resend after a crash reveals the same secret again; journal the
        // fact only once, and never move the counter backwards.
        if self.revocations_sent >= Some(m) {
            return Ok(());
        }
        self.journal.append(&Record::RevocationSent { state: m })?;
        self.revocations_sent = Some(m);
        Ok(())
    }

    fn persist_revocation_recv(&mut self, m: u64, secret: [u8; 32]) -> Result<(), ChannelError> {
        self.journal
            .append(&Record::RevocationRecv { state: m, secret })?;
        self.revocations_recv = Some(m);
        Ok(())
    }

    // --- Compaction ------------------------------------------------------------

    /// The fewest records that replay to this machine's exact state: the
    /// opening, the funding, the commitments and signed balances still
    /// retained (each state's pair in the order that marks its initiator), the
    /// revocation counters with the counterparty's secrets in compact shachain
    /// form, the points announced and not yet revoked, and the phase.
    fn snapshot_records(&self) -> Vec<Record> {
        let mut out = vec![Record::Opened {
            channel_id: self.channel_id,
            our_index: self.our_index as u8,
            funding: self.params.funding,
            capacity: self.params.capacity.units(),
            delay: self.params.delay,
            funding_depth: self.funding_depth,
            our_pubkey: self.our_pubkey.clone(),
            their_pubkey: self.their_pubkey.clone(),
            payout: self.payout,
        }];
        if let Some(op) = self.funding_outpoint {
            out.push(Record::Funded {
                funding_txid: op.txid,
                funding_index: op.index,
            });
        }
        let mut states: Vec<u64> = self
            .local_commits
            .keys()
            .chain(self.remote_balances.keys())
            .copied()
            .collect();
        states.sort_unstable();
        states.dedup();
        for n in states {
            let local = self
                .local_commits
                .get(&n)
                .map(|(b, sigs)| Record::LocalCommit {
                    state: n,
                    balances: *b,
                    their_tier_sigs: sigs.clone(),
                });
            // Both sides sign the same balances for a state, so a signed
            // balance pruned from memory is the commitment's own: writing it
            // keeps the record order that tells who initiated the state.
            let remote = self
                .remote_balances
                .get(&n)
                .copied()
                .or_else(|| {
                    (self.remote_commit_number >= Some(n))
                        .then(|| self.local_commits.get(&n).map(|(b, _)| *b))
                        .flatten()
                })
                .map(|b| Record::RemoteCommit {
                    state: n,
                    balances: b,
                });
            let (first, second) = if self.initiated.get(&n) == Some(&true) {
                (remote, local)
            } else {
                (local, remote)
            };
            out.extend(first);
            out.extend(second);
        }
        if let Some(c) = self.crossed {
            if Some(c) >= self.local_commit_number {
                out.push(Record::Crossed { state: c });
            }
        }
        if let Some(m) = self.revocations_sent {
            out.push(Record::RevocationSent { state: m });
        }
        if let Some(m) = self.revocations_recv {
            out.push(Record::Revocations {
                state: m,
                entries: self.store.entries(),
            });
        }
        for (state, point) in &self.their_points {
            out.push(Record::TheirPoint {
                state: *state,
                point: *point,
            });
        }
        if !matches!(self.phase, Phase::Opening | Phase::Funded) {
            out.push(Record::Ready);
        }
        if let Some(height) = self.funding_height {
            out.push(Record::Confirmed { height });
        }
        if let (Some(tx), Phase::Opening | Phase::Funded) = (&self.funding_tx, self.phase) {
            out.push(Record::FundingTx { tx: tx.encode() });
        }
        if let Some(fee) = self.close_fee {
            out.push(Record::ClosingCoopBy {
                fee,
                payer: self.close_payer.unwrap_or(FUNDER) as u8,
            });
            if let Some(signature) = &self.close_peer_sig {
                out.push(Record::CloseSigned {
                    fee,
                    signature: signature.clone(),
                });
            }
        }
        match self.phase {
            Phase::Forcing => out.push(Record::Forcing),
            Phase::Penalised => out.push(Record::Penalised),
            Phase::Closed => out.push(Record::Closed),
            _ => {}
        }
        out
    }

    /// Rewrites the journal as [`Machine::snapshot_records`], atomically. The
    /// journal otherwise grows by an update's records, signatures included, for
    /// the life of the channel.
    pub fn compact(&mut self) -> Result<(), ChannelError> {
        let records = self.snapshot_records();
        self.journal.rewrite(&records)?;
        Ok(())
    }

    /// Compacts once the journal holds more than [`COMPACT_AFTER`] records.
    fn compact_if_long(&mut self) -> Result<(), ChannelError> {
        if self.journal.records() > COMPACT_AFTER {
            self.compact()?;
        }
        Ok(())
    }

    /// Records in the journal file.
    pub fn journal_records(&self) -> usize {
        self.journal.records()
    }

    /// Entries held in each per-state map and the reestablish nonce window,
    /// for the memory bounds: `(commitments, signed balances, initiators,
    /// announced points, nonces, shachain entries)`.
    pub fn retained(&self) -> [usize; 6] {
        [
            self.local_commits.len(),
            self.remote_balances.len(),
            self.initiated.len(),
            self.their_points.len(),
            self.seen_nonces.len(),
            self.store.len(),
        ]
    }

    /// Where the revocation root lives, so a test can check it is wiped on
    /// drop.
    #[cfg(all(test, feature = "mldsa"))]
    pub(crate) fn revocation_root_location(&self) -> *const [u8; 32] {
        &self.revocation_seed
    }

    /// Everything replay must rebuild, as text, so a test can compare a
    /// machine with its reopened journal.
    #[cfg(all(test, feature = "mldsa"))]
    pub(crate) fn digest(&self) -> String {
        // Who initiated a state matters only while that state is retained.
        let initiated: BTreeMap<u64, bool> = self
            .initiated
            .iter()
            .filter(|(n, _)| {
                self.local_commits.contains_key(n) || self.remote_balances.contains_key(n)
            })
            .map(|(n, b)| (*n, *b))
            .collect();
        let text = format!(
            "{:?} {:?} L{:?} R{:?} S{:?} V{:?} lc{:?} rb{:?} in{:?} tp{:?} st{:?} cf{:?} cs{} ps{:?} fh{:?} cr{:?}",
            self.phase,
            self.funding_outpoint,
            self.local_commit_number,
            self.remote_commit_number,
            self.revocations_sent,
            self.revocations_recv,
            self.local_commits,
            self.remote_balances,
            initiated,
            self.their_points,
            self.store.entries(),
            self.close_fee,
            self.close_signed,
            self.close_peer_sig,
            self.funding_height,
            self.crossed,
        );
        format!(
            "{:?} L{:?} R{:?} {}",
            self.phase,
            self.local_commit_number,
            self.remote_commit_number,
            Hash256(sha256(text.as_bytes())).to_hex()
        )
    }

    // --- Idempotent resends for reestablish ----------------------------------

    /// Our `Ack` of state `n`, as responder. A crash inside
    /// [`Machine::on_update`] can leave the counterparty's signature over our
    /// commitment `n` persisted but our own over theirs not yet: the
    /// acknowledgement is then completed here, each write `fsync`ed before the
    /// message is built, exactly as the first pass would have done.
    fn resend_ack(&mut self, n: u64) -> Result<Message, ChannelError> {
        let bal = match self.remote_balances.get(&n) {
            Some(b) => *b,
            None if self.local_commit_number == Some(n) && self.remote_commit_number < Some(n) => {
                let bal = self
                    .local_commits
                    .get(&n)
                    .map(|(b, _)| *b)
                    .ok_or(ChannelError::Invariant("missing local commitment"))?;
                self.persist_remote_commit(n, bal)?;
                // We answered this state; we did not initiate it.
                self.initiated.insert(n, false);
                bal
            }
            None => {
                return Err(ChannelError::Invariant(
                    "missing remote balances for resend",
                ))
            }
        };
        let tier_sigs = self.sign_their_commitment(n, bal)?;
        let revocation = self.make_revocation(n - 1)?;
        self.persist_revocation_sent(n - 1)?;
        Ok(Message::Ack {
            state: n,
            tier_sigs,
            revocation,
        })
    }

    fn resend_revoke(&mut self, n: u64) -> Result<Message, ChannelError> {
        let revocation = self.make_revocation(n - 1)?;
        self.persist_revocation_sent(n - 1)?;
        Ok(Message::Revoke {
            state: n,
            revocation,
        })
    }

    fn resend_update(&self, n: u64) -> Result<Message, ChannelError> {
        let bal = *self.remote_balances.get(&n).ok_or(ChannelError::Invariant(
            "missing remote balances for resend",
        ))?;
        let tier_sigs = self.sign_their_commitment(n, bal)?;
        Ok(Message::Update {
            state: n,
            balances: bal,
            tier_sigs,
        })
    }

    // --- Cooperative close ---------------------------------------------------

    /// Proposes a cooperative close at the current balance, returning
    /// [`Message::Close`]. The proposer pays the fee, from its own side.
    ///
    /// On a channel already closing cooperatively on our proposal, it returns
    /// the agreed `Close` again, unchanged: a close whose message was lost to a
    /// crash or a dropped link can be completed instead of stranding the
    /// channel.
    pub fn propose_close(&mut self, fee: u64) -> Result<Message, ChannelError> {
        if self.phase == Phase::Closing {
            return match (self.close_fee, self.close_payer) {
                (Some(agreed), Some(p)) if p == self.our_index => {
                    Ok(Message::Close { fee: agreed })
                }
                _ => Err(ChannelError::Unexpected),
            };
        }
        if self.phase != Phase::Open {
            return Err(ChannelError::Unexpected);
        }
        // Both sides must sign the same balances: never while an update is
        // still settling.
        if self.update_in_flight() {
            return Err(ChannelError::Unexpected);
        }
        self.check_close_fee(fee, self.our_index)?;
        self.journal_close(fee, self.our_index)?;
        Ok(Message::Close { fee })
    }

    /// Agrees to a cooperative close at `fee` while an update is still in
    /// flight — our own (`ours`) or the peer's — moving to
    /// [`Phase::Closing`] at once, so no new update starts. Once the update
    /// settles, our `Close` follows, or our signature of the peer's (see
    /// [`Machine::close_after_update`]). Idempotent.
    pub fn agree_close(&mut self, fee: u64, ours: bool) -> Result<(), ChannelError> {
        let payer = if ours {
            self.our_index
        } else {
            1 - self.our_index
        };
        match self.phase {
            Phase::Open => {
                self.check_close_fee(fee, payer)?;
                self.journal_close(fee, payer)
            }
            Phase::Closing => Ok(()),
            _ => Err(ChannelError::Unexpected),
        }
    }

    /// The message an agreed close owes once no update is in flight: our
    /// `Close` if we proposed it, our `CloseSigned` if the peer did.
    pub fn close_after_update(&mut self) -> Result<Option<Message>, ChannelError> {
        if self.phase != Phase::Closing || self.update_in_flight() {
            return Ok(None);
        }
        match (self.close_fee, self.close_payer) {
            (Some(fee), Some(p)) if p == self.our_index => Ok(Some(Message::Close { fee })),
            (Some(fee), Some(_)) => self.on_close(&Message::Close { fee }).map(Some),
            _ => Ok(None),
        }
    }

    /// A close fee `payer` may be charged: within [`txbuild::close_fee_bounds`]
    /// and within the payer's own balance. Bounded, because a fee is burned:
    /// unbounded, a peer proposing a close could make the other side pay away
    /// its whole balance.
    fn check_close_fee(&self, fee: u64, payer: usize) -> Result<(), ChannelError> {
        let (min, max) = txbuild::close_fee_bounds(&self.params);
        if fee < min || fee > max || fee > self.current_balances()[payer] {
            return Err(ChannelError::BadParameters);
        }
        Ok(())
    }

    fn journal_close(&mut self, fee: u64, payer: usize) -> Result<(), ChannelError> {
        self.journal.append(&Record::ClosingCoopBy {
            fee,
            payer: payer as u8,
        })?;
        self.phase = Phase::Closing;
        self.close_fee = Some(fee);
        self.close_payer = Some(payer);
        Ok(())
    }

    /// Handles a peer's [`Message::Close`], returning our [`Message::CloseSigned`].
    ///
    /// The close is the peer's proposal: its fee is charged to the peer alone,
    /// so our side is paid in full, and the fee must lie within the bounds we
    /// accept and within the peer's balance.
    pub fn on_close(&mut self, msg: &Message) -> Result<Message, ChannelError> {
        let Message::Close { fee } = msg else {
            return Err(ChannelError::Unexpected);
        };
        // A peer still waiting on a close we already completed asks again:
        // sign the same transaction again so it can settle too.
        if !matches!(self.phase, Phase::Open | Phase::Closing | Phase::Closed) {
            return Err(ChannelError::Unexpected);
        }
        if self.update_in_flight() {
            return Err(ChannelError::Unexpected);
        }
        let peer = 1 - self.our_index;
        self.check_close_fee(*fee, peer)?;
        if self.phase == Phase::Open {
            self.journal_close(*fee, peer)?;
        }
        let bal = self.current_balances();
        let close = self
            .params
            .cooperative_close(self.funding()?, bal, *fee, self.payout, peer);
        let m = self
            .params
            .funding_sighash(&close.tx, self.network, self.our_index);
        self.close_signed = true;
        Ok(Message::CloseSigned {
            fee: *fee,
            signature: self.signer.sign(&m),
        })
    }

    /// Verifies the peer's [`Message::CloseSigned`] and returns the fully
    /// signed cooperative close transaction, ready to broadcast.
    ///
    /// The channel stays [`Phase::Closing`] until the close confirms on chain;
    /// the peer's signature is journaled first, so the close can be rebuilt
    /// and broadcast again after a crash that lost it from the mempool (see
    /// [`Machine::signed_cooperative_close`]). Idempotent.
    pub fn on_close_signed(&mut self, msg: &Message) -> Result<Transaction, ChannelError> {
        let Message::CloseSigned { fee, signature } = msg else {
            return Err(ChannelError::Unexpected);
        };
        if !matches!(self.phase, Phase::Closing | Phase::Closed) {
            return Err(ChannelError::Unexpected);
        }
        // The peer's signature of OUR proposal: same fee, charged to us.
        if self.close_fee != Some(*fee) || self.close_payer != Some(self.our_index) {
            return Err(ChannelError::Unexpected);
        }
        let tx = self.assemble_close(*fee, signature)?;
        if self.close_peer_sig.is_none() {
            self.journal.append(&Record::CloseSigned {
                fee: *fee,
                signature: signature.clone(),
            })?;
            self.close_peer_sig = Some(signature.clone());
            self.close_fee = Some(*fee);
        }
        self.close_signed = true;
        Ok(tx)
    }

    /// The fully signed cooperative close, rebuilt from the peer's journaled
    /// signature, if we hold it.
    pub fn signed_cooperative_close(&self) -> Option<Transaction> {
        let sig = self.close_peer_sig.as_ref()?;
        self.assemble_close(self.close_fee?, sig).ok()
    }

    /// Whether the agreed cooperative close is our own proposal.
    pub fn closing_on_our_proposal(&self) -> bool {
        self.close_payer == Some(self.our_index)
    }

    /// Whether we hold the peer's signature over the cooperative close.
    pub fn has_signed_close(&self) -> bool {
        self.close_peer_sig.is_some()
    }

    /// Verifies the peer's signature over the cooperative close at `fee` and
    /// returns the close signed by both.
    fn assemble_close(&self, fee: u64, signature: &[u8]) -> Result<Transaction, ChannelError> {
        let bal = self.current_balances();
        let close =
            self.params
                .cooperative_close(self.funding()?, bal, fee, self.payout, self.our_index);
        let their_leaf = (1 - self.our_index) as u8;
        crate::policy::check_signature(
            &close.tx,
            0,
            self.network,
            &self.params.funding_output(),
            &self.params.funding_policy().encode(),
            their_leaf,
            &[],
            &self.their_pubkey,
            signature,
        )
        .map_err(|_| ChannelError::BadSignature)?;
        let mut tx = close.tx;
        let m = self
            .params
            .funding_sighash(&tx, self.network, self.our_index);
        let our_sig = self.signer.sign(&m);
        let mut sigs: [&[u8]; 2] = [&[], &[]];
        let mut pks: [&[u8]; 2] = [&[], &[]];
        sigs[self.our_index] = &our_sig;
        sigs[1 - self.our_index] = signature;
        pks[self.our_index] = &self.our_pubkey;
        pks[1 - self.our_index] = &self.their_pubkey;
        self.params.complete_funding_spend(&mut tx, sigs, pks);
        Ok(tx)
    }

    /// Records the height at which the funding confirmed, once (again after a
    /// reorganization moved it).
    pub fn note_funding_height(&mut self, height: u64) -> Result<(), ChannelError> {
        if self.funding_height != Some(height) {
            self.journal.append(&Record::Confirmed { height })?;
            self.funding_height = Some(height);
        }
        Ok(())
    }

    /// The height at which the funding confirmed, if recorded.
    pub fn funding_height(&self) -> Option<u64> {
        self.funding_height
    }

    // --- Reestablish ---------------------------------------------------------

    /// Reopens a channel from its journal after a crash or disconnect,
    /// reconstructing every counter from the records alone.
    #[allow(clippy::too_many_arguments)]
    pub fn reopen(
        journal_path: impl AsRef<Path>,
        network: Network,
        signer: Box<dyn Signer>,
        base_fee_rate: u64,
    ) -> Result<Machine, ChannelError> {
        let (journal, records) = Journal::open(journal_path)?;
        let opened = records
            .first()
            .cloned()
            .ok_or(ChannelError::Invariant("empty journal"))?;
        let Record::Opened {
            channel_id: cid,
            our_index,
            funding,
            capacity,
            delay,
            funding_depth,
            their_pubkey,
            payout,
            ..
        } = opened
        else {
            return Err(ChannelError::Invariant("first record is not Opened"));
        };
        let params = ChannelParams {
            funding,
            capacity: crate::amount::Amount::from_units(capacity),
            delay,
        };
        let revocation_seed = signer.revocation_root(&cid);
        let mut m = Machine {
            params,
            network,
            our_index: our_index as usize,
            channel_id: cid,
            our_pubkey: signer.pubkey().to_vec(),
            signer,
            their_pubkey,
            payout,
            revocation_seed,
            funding_depth,
            journal,
            phase: Phase::Opening,
            funding_outpoint: None,
            local_commit_number: None,
            remote_commit_number: None,
            revocations_sent: None,
            revocations_recv: None,
            local_commits: BTreeMap::new(),
            remote_balances: BTreeMap::new(),
            initiated: BTreeMap::new(),
            close_fee: None,
            close_payer: None,
            funding_tx: None,
            close_signed: false,
            close_peer_sig: None,
            funding_height: None,
            their_points: BTreeMap::new(),
            store: shachain::Store::new(),
            base_fee_rate,
            seen_nonces: VecDeque::new(),
            peer_proposal: None,
            crossed: None,
        };
        m.replay(&records);
        m.compact_if_long()?;
        Ok(m)
    }

    fn replay(&mut self, records: &[Record]) {
        for rec in records {
            match rec {
                Record::Opened { .. } => {}
                Record::Funded {
                    funding_txid,
                    funding_index,
                } => {
                    self.funding_outpoint = Some(OutPoint {
                        txid: *funding_txid,
                        index: *funding_index,
                    });
                }
                Record::LocalCommit {
                    state,
                    balances,
                    their_tier_sigs,
                } => {
                    self.local_commit_number = Some(*state);
                    self.local_commits
                        .insert(*state, (*balances, their_tier_sigs.clone()));
                    while self.local_commits.len() > 2 {
                        let oldest = *self.local_commits.keys().next().unwrap();
                        self.local_commits.remove(&oldest);
                    }
                    // LocalCommit first: we answered this state.
                    self.note_initiator(*state, false);
                }
                Record::RemoteCommit { state, balances } => {
                    self.remote_commit_number = Some(*state);
                    self.remote_balances.insert(*state, *balances);
                    prune_to_latest(&mut self.remote_balances, 2);
                    // RemoteCommit first: we proposed this state.
                    self.note_initiator(*state, true);
                }
                Record::RevocationSent { state } => self.revocations_sent = Some(*state),
                Record::RevocationRecv { state, secret } => {
                    self.revocations_recv = Some(*state);
                    let _ = self.store.insert(*secret, shachain::MAX_INDEX - *state);
                    self.their_points.remove(state);
                }
                Record::TheirPoint { state, point } => {
                    self.their_points.insert(*state, *point);
                }
                Record::Ready => self.phase = Phase::Open,
                Record::ClosingCoop { fee } => {
                    self.phase = Phase::Closing;
                    self.close_fee = Some(*fee);
                    self.close_payer = Some(FUNDER);
                }
                Record::ClosingCoopBy { fee, payer } => {
                    self.phase = Phase::Closing;
                    self.close_fee = Some(*fee);
                    self.close_payer = Some(usize::from(*payer).min(1));
                }
                Record::Forcing => self.phase = Phase::Forcing,
                Record::Penalised => self.phase = Phase::Penalised,
                Record::Closed => self.phase = Phase::Closed,
                Record::Confirmed { height } => self.funding_height = Some(*height),
                Record::FundingTx { tx } => {
                    self.funding_tx = Transaction::decode(tx).ok();
                }
                Record::Crossed { state } => self.crossed = Some(*state),
                Record::CloseSigned { fee, signature } => {
                    self.close_fee = Some(*fee);
                    self.close_payer = Some(self.our_index);
                    self.close_peer_sig = Some(signature.clone());
                    if self.phase != Phase::Closed {
                        self.phase = Phase::Closing;
                    }
                }
                Record::Revocations { state, entries } => {
                    self.revocations_recv = Some(*state);
                    if let Ok(store) = shachain::Store::restore(entries) {
                        self.store = store;
                    }
                }
            }
        }
        if self.phase == Phase::Opening && self.local_commit_number == Some(0) {
            self.phase = Phase::Funded;
        }
        self.close_signed = matches!(self.phase, Phase::Closing | Phase::Closed);
        // The counterparty's announced points were persisted as TheirPoint
        // records and are already back in `their_points`; the revoked ones were
        // removed above. Nothing more to rebuild.
    }

    /// Builds our [`Message::Reestablish`] on reconnection. It carries a fresh
    /// nonce and a proof of our funding key over `(channel_id, nonce,
    /// direction)`. From the peer's side the nonce is the peer's nonce, which
    /// is what its proof commits to; the peer rejects a nonce it has seen
    /// before, so a captured message cannot be replayed.
    pub fn reestablish(&self) -> Result<Message, ChannelError> {
        let nonce = crate::rng::bytes::<32>().map_err(|_| ChannelError::NoRandomness)?;
        Ok(self.reestablish_for(nonce))
    }

    /// Our [`Message::Reestablish`] answering the peer's challenge `nonce`:
    /// the proof of our funding key signs the peer's own fresh nonce, so the
    /// answer is good for that challenge — that connection — only.
    pub fn reestablish_for(&self, nonce: [u8; 32]) -> Message {
        let proof = self.signer.sign(&reestablish_message(
            self.channel_id,
            nonce,
            self.our_index as u8,
        ));
        Message::Reestablish {
            channel_id: self.channel_id,
            local_commit_number: self.local_commit_number.map_or(0, |n| n + 1),
            remote_commit_number: self.remote_commit_number.map_or(0, |n| n + 1),
            next_revocation_sent: self.revocations_sent.map_or(0, |m| m + 1),
            next_revocation_recv: self.revocations_recv.map_or(0, |m| m + 1),
            nonce,
            direction: self.our_index as u8,
            proof,
        }
    }

    /// Verifies a peer's [`Message::Reestablish`] and returns the messages we
    /// must resend to resynchronize. The peer runs the mirror of this; the two
    /// resend sets together restore both sides.
    pub fn on_reestablish(&mut self, msg: &Message) -> Result<Vec<Message>, ChannelError> {
        let Message::Reestablish {
            channel_id: cid,
            local_commit_number: their_next_local,
            remote_commit_number: their_next_remote,
            next_revocation_recv: their_next_recv,
            nonce,
            direction,
            proof,
            ..
        } = msg
        else {
            return Err(ChannelError::Unexpected);
        };
        if *cid != self.channel_id {
            return Err(ChannelError::BadReestablish);
        }
        if self.seen_nonces.contains(nonce) {
            return Err(ChannelError::BadReestablish);
        }
        // The peer proved its funding key over its own fresh nonce and its
        // direction; the freshness check above stops a replay. The nonce is
        // remembered only once the proof verifies, so a forged message cannot
        // fill the set.
        if usize::from(*direction) != 1 - self.our_index {
            return Err(ChannelError::BadReestablish);
        }
        let expected = reestablish_message(self.channel_id, *nonce, *direction);
        crate::sig::verify(CHANNEL_SCHEME, &self.their_pubkey, &expected, proof)
            .map_err(|_| ChannelError::BadReestablish)?;
        if self.seen_nonces.len() >= MAX_SEEN_NONCES {
            self.seen_nonces.pop_front();
        }
        self.seen_nonces.push_back(*nonce);
        // A channel settling on chain has nothing left to resynchronize.
        if matches!(
            self.phase,
            Phase::Forcing | Phase::Penalised | Phase::Closed
        ) {
            return Ok(Vec::new());
        }

        // --- Resync. The protocol is strictly sequential: at most one state
        // is in flight. Decide, from our persisted counters and the peer's,
        // what we owe it, in the order it must be processed.
        let their_local = their_next_local.checked_sub(1);
        let their_recv = their_next_recv.checked_sub(1);
        // The peer signed our commitment at a state we neither hold nor
        // proposed: its own update, lost with the old link, which it resends
        // on this reestablish. Proposing that state meanwhile crossed it, and
        // the channel deadlocked with both proposals in flight.
        let their_remote = their_next_remote.checked_sub(1);
        self.peer_proposal = their_remote
            .filter(|&r| self.local_commit_number < Some(r) && self.remote_commit_number < Some(r));
        let mut out = Vec::new();
        // The state whose Ack we have queued, so it is not sent twice.
        let mut acked: Option<u64> = None;

        if let Some(l) = self.local_commit_number {
            // A crash inside `on_update` after persisting the peer's signature
            // over our commitment `l`, before signing theirs: the Ack was never
            // built. Finish it now; it also carries our revocation of `l-1`.
            if l >= 1 && self.remote_commit_number < Some(l) {
                out.push(self.resend_ack(l)?);
                acked = Some(l);
            } else if l >= 1 && their_recv.map_or(true, |tr| tr < l - 1) {
                // We hold commitment `l`, so the secret of `l-1` is ours to
                // reveal (INV1), and the peer does not have it: the message
                // that carried it was lost, or a crash came between persisting
                // its receipt and journaling ours. The initiator of `l` reveals
                // it in a Revoke, the responder in an Ack.
                if self.initiated.get(&l) == Some(&true) {
                    out.push(self.resend_revoke(l)?);
                } else {
                    out.push(self.resend_ack(l)?);
                    acked = Some(l);
                }
            }
        }

        // We signed the peer's commitment at `r` but the peer has not persisted
        // it: resend our signature, as the Update we proposed or as the Ack we
        // answered with. After any revocation above, so the peer holds the
        // point it needs to sign our side of `r`.
        if let Some(r) = self.remote_commit_number {
            if r >= 1 && their_local.map_or(true, |tl| tl < r) && acked != Some(r) {
                if self.initiated.get(&r) == Some(&true) {
                    out.push(self.resend_update(r)?);
                } else {
                    out.push(self.resend_ack(r)?);
                }
            }
        }

        // Crossed proposals whose revocations are both in: the merge above
        // them, if ours to propose and not proposed yet.
        out.extend(self.merge_if_ready()?);

        // A cooperative close we agreed to is sent again: its Close may have
        // been lost, and the handlers are idempotent if it was not. Not while
        // an update still settles: both sides must sign the same balances, so
        // the Close then follows the update's completion.
        if self.phase == Phase::Closing && !self.update_in_flight() {
            // Only our own proposal: the peer resends its own, and a Close of
            // ours over the peer's proposal would charge us its fee.
            if let (Some(fee), Some(p)) = (self.close_fee, self.close_payer) {
                if p == self.our_index {
                    out.push(Message::Close { fee });
                }
            }
        }
        Ok(out)
    }

    /// Whether an update is still settling: we proposed a state the peer has not
    /// acknowledged, we hold a state we have not finished acknowledging, a
    /// revocation of the previous state is still owed in either direction, or
    /// the peer's reestablish showed a proposal of its own not received yet.
    /// While it is, no new update or close may start; a reestablish completes
    /// it.
    pub fn update_in_flight(&self) -> bool {
        let Some(l) = self.local_commit_number else {
            return false;
        };
        // The peer's own proposal, shown by its reestablish, is still on its
        // way to us.
        if self.peer_proposal.is_some_and(|p| l < p) {
            return true;
        }
        // Crossed proposals at `l`: in flight until their merge above settles.
        if self.crossed == Some(l) {
            return true;
        }
        if self.remote_commit_number != Some(l) {
            return true;
        }
        l >= 1 && (self.revocations_sent < Some(l - 1) || self.revocations_recv < Some(l - 1))
    }

    /// Whether `msg` is the peer's [`Message::Update`] for the very state we
    /// proposed and it has not acknowledged: both ends paid at the same
    /// moment. An honest race on the wire, not misconduct.
    pub fn crosses_our_proposal(&self, msg: &Message) -> bool {
        let Message::Update { state, .. } = msg else {
            return false;
        };
        matches!(self.phase, Phase::Open | Phase::Closing)
            && *state >= 1
            && self.remote_commit_number == Some(*state)
            && self.local_commit_number == Some(*state - 1)
            && self.initiated.get(state) == Some(&true)
    }

    /// Handles a peer's [`Message::Update`], whatever its relation to our own
    /// proposals: an ordinary update is acknowledged ([`Machine::on_update`]),
    /// one that crosses ours starts their merge ([`Machine::on_crossed_update`]),
    /// and a crossed proposal already taken is a resend with nothing to answer.
    pub fn on_peer_update(&mut self, msg: &Message) -> Result<Vec<Message>, ChannelError> {
        let Message::Update { state, .. } = msg else {
            return Err(ChannelError::Unexpected);
        };
        if self.crossed == Some(*state) && self.local_commit_number >= Some(*state) {
            return Ok(Vec::new());
        }
        if self.crosses_our_proposal(msg) {
            return self.on_crossed_update(msg);
        }
        Ok(vec![self.on_update(msg)?])
    }

    /// Both sides proposed state `n` at once: each signed the other's
    /// commitment `n` at its own proposal. Taking either proposal as state `n`
    /// would be unsafe: the other side keeps a signature over a different,
    /// for it better, commitment at the same index, enforceable until that
    /// index is revoked, so a payment both believe settled could be undone.
    ///
    /// So neither is taken. Each side journals the peer's proposal as its
    /// commitment `n` (it can enforce it: that is the peer's own payment to
    /// it), which lets it reveal the secret of `n - 1` now (INV1) and so
    /// announce the point of `n + 1`; it sends that revocation as a `Revoke`
    /// for `n`. Once both revocations are in, the side holding the initiative
    /// proposes `n + 1` at the merge of both proposals — both payments — and
    /// the ordinary update completes it, each side revealing the secret of
    /// `n`. That revokes every commitment either side holds at index `n`,
    /// whatever its balances, since a per-commitment point belongs to an
    /// index. Until then the channel is in flight, as for any update, and the
    /// most either side can enforce is the peer's own payment to it.
    pub fn on_crossed_update(&mut self, msg: &Message) -> Result<Vec<Message>, ChannelError> {
        let Message::Update {
            state,
            balances,
            tier_sigs,
        } = msg
        else {
            return Err(ChannelError::Unexpected);
        };
        if !self.crosses_our_proposal(msg) {
            return Err(ChannelError::Unexpected);
        }
        let n = *state;
        self.check_balances(*balances)?;
        // C1, against the last settled state: the peer's proposal is a payment
        // to us.
        let base = self.settled_balances(n - 1)?;
        let us = self.our_index;
        if balances[us] < base[us] {
            return Err(ChannelError::WrongDirection);
        }
        // The merge must be a valid state too.
        let ours = *self
            .remote_balances
            .get(&n)
            .ok_or(ChannelError::Invariant("missing our proposal"))?;
        merge(base, ours, *balances)
            .filter(|m| self.check_balances(*m).is_ok())
            .ok_or(ChannelError::BadBalances)?;
        self.verify_our_commitment(n, *balances, tier_sigs)?;
        if self.crossed != Some(n) {
            self.journal.append(&Record::Crossed { state: n })?;
            self.crossed = Some(n);
        }
        // INV2, then INV1: the peer's signature is persisted before we reveal
        // the secret of `n - 1`.
        self.persist_local_commit(n, *balances, tier_sigs.clone(), true)?;
        let revocation = self.make_revocation(n - 1)?;
        self.persist_revocation_sent(n - 1)?;
        let mut out = vec![Message::Revoke {
            state: n,
            revocation,
        }];
        out.extend(self.merge_if_ready()?);
        Ok(out)
    }

    /// The balances of a settled state `m`, as our commitment holds them.
    fn settled_balances(&self, m: u64) -> Result<Balances, ChannelError> {
        self.local_commits
            .get(&m)
            .map(|(b, _)| *b)
            .ok_or(ChannelError::Invariant("missing settled commitment"))
    }

    /// The merge of the two proposals crossed at the current state: the
    /// settled state below plus both payments.
    fn merged_balances(&self) -> Option<Balances> {
        let n = self.crossed?;
        let base = self.settled_balances(n.checked_sub(1)?).ok()?;
        let ours = *self.remote_balances.get(&n)?;
        let theirs = self.local_commits.get(&n)?.0;
        merge(base, ours, theirs)
    }

    /// After crossed proposals at `n`, once both sides have revealed the
    /// secret of `n - 1`, the side holding the initiative proposes their merge
    /// as `n + 1`. Returns that `Update`, or nothing if it is not yet time or
    /// not ours to send.
    pub fn merge_if_ready(&mut self) -> Result<Option<Message>, ChannelError> {
        let Some(n) = self.crossed else {
            return Ok(None);
        };
        let ready = self.local_commit_number == Some(n)
            && self.remote_commit_number == Some(n)
            && self.revocations_sent >= Some(n - 1)
            && self.revocations_recv >= Some(n - 1)
            && self.has_initiative()
            && matches!(self.phase, Phase::Open | Phase::Closing);
        if !ready {
            return Ok(None);
        }
        let merged = self
            .merged_balances()
            .ok_or(ChannelError::Invariant("crossed proposals do not merge"))?;
        self.check_balances(merged)?;
        let tier_sigs = self.sign_their_commitment(n + 1, merged)?;
        self.persist_remote_commit(n + 1, merged)?;
        Ok(Some(Message::Update {
            state: n + 1,
            balances: merged,
            tier_sigs,
        }))
    }

    /// Whether `tx` is a cooperative close of this channel: it spends the
    /// funding output and pays only the two parties' payout addresses, neither
    /// more than its current balance. A spend of the 2-of-2 funding output
    /// needs our signature, and we sign no other such shape, so this matches
    /// either party's proposal, whoever pays its fee.
    pub fn is_cooperative_close(&self, tx: &Transaction) -> bool {
        let Some(funding) = self.funding_outpoint else {
            return false;
        };
        if tx.inputs.len() != 1 || tx.inputs[0].prev_out != funding || tx.outputs.is_empty() {
            return false;
        }
        let bal = self.current_balances();
        tx.outputs.iter().all(|o| {
            o.scheme == CHANNEL_SCHEME
                && (0..2).any(|i| o.pubkey_hash == self.payout[i] && o.value.units() <= bal[i])
        })
    }

    // --- Force close and accessors ------------------------------------------

    /// Our latest enforceable commitment, fully signed at `tier`, ready to
    /// broadcast as a unilateral (force) close.
    pub fn force_close(&mut self, tier: FeeTier) -> Result<Transaction, ChannelError> {
        let n = self
            .local_commit_number
            .ok_or(ChannelError::Invariant("no commitment yet"))?;
        let (bal, their_sigs) = self
            .local_commits
            .get(&n)
            .cloned()
            .ok_or(ChannelError::Invariant("missing local commitment"))?;
        let c = self.our_commitment(n, bal, tier);
        let mut tx = c.tx;
        let m = self
            .params
            .funding_sighash(&tx, self.network, self.our_index);
        let our_sig = self.signer.sign(&m);
        let their_sig = &their_sigs[tier as usize];
        let mut sigs: [&[u8]; 2] = [&[], &[]];
        let mut pks: [&[u8]; 2] = [&[], &[]];
        sigs[self.our_index] = &our_sig;
        sigs[1 - self.our_index] = their_sig;
        pks[self.our_index] = &self.our_pubkey;
        pks[1 - self.our_index] = &self.their_pubkey;
        self.params.complete_funding_spend(&mut tx, sigs, pks);
        self.journal.append(&Record::Forcing)?;
        self.phase = Phase::Forcing;
        Ok(tx)
    }

    /// Records that a commitment is on chain and the channel is force-closing.
    /// Idempotent: a channel already in [`Phase::Forcing`] stays put. Used by
    /// the manager when it first sees a commitment spend the funding output.
    pub fn mark_forcing(&mut self) -> Result<(), ChannelError> {
        if self.phase != Phase::Forcing {
            self.journal.append(&Record::Forcing)?;
            self.phase = Phase::Forcing;
        }
        Ok(())
    }

    /// Records that we punished a revoked broadcast; moves to
    /// [`Phase::Penalised`].
    pub fn mark_penalised(&mut self) -> Result<(), ChannelError> {
        if self.phase != Phase::Penalised {
            self.journal.append(&Record::Penalised)?;
            self.phase = Phase::Penalised;
        }
        Ok(())
    }

    /// Records that the channel is settled on chain; moves to [`Phase::Closed`].
    pub fn mark_closed(&mut self) -> Result<(), ChannelError> {
        if self.phase != Phase::Closed {
            self.journal.append(&Record::Closed)?;
            self.phase = Phase::Closed;
        }
        Ok(())
    }

    /// Builds (and keeps private) a commitment at `n` for `tier` at the
    /// balances we signed it at, for use in tests of a revoked broadcast.
    pub fn signed_commitment_at(&self, n: u64, tier: FeeTier) -> Result<Transaction, ChannelError> {
        let (bal, their_sigs) = self
            .local_commits
            .get(&n)
            .cloned()
            .ok_or(ChannelError::Invariant("commitment not retained"))?;
        let c = self.our_commitment(n, bal, tier);
        let mut tx = c.tx;
        let m = self
            .params
            .funding_sighash(&tx, self.network, self.our_index);
        let our_sig = self.signer.sign(&m);
        let their_sig = &their_sigs[tier as usize];
        let mut sigs: [&[u8]; 2] = [&[], &[]];
        let mut pks: [&[u8]; 2] = [&[], &[]];
        sigs[self.our_index] = &our_sig;
        sigs[1 - self.our_index] = their_sig;
        pks[self.our_index] = &self.our_pubkey;
        pks[1 - self.our_index] = &self.their_pubkey;
        self.params.complete_funding_spend(&mut tx, sigs, pks);
        Ok(tx)
    }

    fn current_balances(&self) -> Balances {
        self.local_commit_number
            .and_then(|n| self.local_commits.get(&n))
            .map(|(b, _)| *b)
            .unwrap_or([self.params.capacity.units(), 0])
    }

    fn funding(&self) -> Result<OutPoint, ChannelError> {
        self.funding_outpoint
            .ok_or(ChannelError::Invariant("no funding outpoint"))
    }

    // --- Read-only accessors -------------------------------------------------

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn params(&self) -> &ChannelParams {
        &self.params
    }
    pub fn channel_id(&self) -> Hash256 {
        self.channel_id
    }
    pub fn our_index(&self) -> usize {
        self.our_index
    }
    /// Whether this side holds the initiative under the simultaneous-update
    /// tie-break: the party whose funding-pubkey hash is smaller proposes, and
    /// the other retries after its update lands.
    pub fn has_initiative(&self) -> bool {
        crate::channel::messages::initiative(&self.params.funding) == self.our_index
    }
    pub fn balances(&self) -> Balances {
        self.current_balances()
    }
    pub fn local_commit_number(&self) -> Option<u64> {
        self.local_commit_number
    }
    pub fn revocation_store(&self) -> &shachain::Store {
        &self.store
    }
    pub fn funding_output(&self) -> TxOut {
        self.params.funding_output()
    }
    pub fn funding_outpoint(&self) -> Option<OutPoint> {
        self.funding_outpoint
    }
    pub fn funding_depth(&self) -> u16 {
        self.funding_depth
    }
    pub fn their_pubkey(&self) -> &[u8] {
        &self.their_pubkey
    }
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }
}

/// Broadcast-time transaction builders driven by a [`Watch`] decision. These
/// hold a key, so they live on the machine rather than in the watcher.
impl Machine {
    /// Classifies a spend of the funding output robustly, including a commitment
    /// with a single `to_local` output and no `to_remote` — the shape that
    /// defeats the output-count heuristic and let a revoked single-output
    /// broadcast go unpunished.
    ///
    /// The `to_local` output pays a *policy*, whose lock hash is independent of
    /// its value, so we rebuild the policy for each hypothesis (the peer's
    /// revoked state, our own state, the peer's announced latest) and match it
    /// against the output. Only the trimmed-`to_local` shapes (the holder's own
    /// balance was dust, leaving a lone `to_remote`) fall through to the
    /// output-count heuristic [`crate::channel::watcher::classify`].
    pub fn identify_spend(&self, tx: &Transaction) -> Watch {
        let Some(funding) = self.funding_outpoint else {
            return Watch::NotOurChannel;
        };
        if tx.inputs.first().map(|i| i.prev_out) != Some(funding) {
            return Watch::NotOurChannel;
        }
        let n = self.params.state_of(tx);
        let txid = tx.txid();
        let our = self.our_index;
        let peer = 1 - our;
        let policy_out = tx
            .outputs
            .iter()
            .enumerate()
            .find(|(_, o)| o.scheme == crate::sig::SchemeId::Policy)
            .map(|(i, o)| (i as u32, *o));

        if let Some((idx, out)) = policy_out {
            let matches = |holder: usize, point: Hash256| {
                out.pubkey_hash == self.params.to_local_policy(holder, point).lock_hash()
            };
            let as_ref = OutputRef {
                outpoint: OutPoint { txid, index: idx },
                output: out,
            };
            // The peer's revoked commitment: we hold its secret for state `n`,
            // so the to_local point is the hash of that secret.
            if let Some(secret) = self.store.get(shachain::MAX_INDEX - n) {
                if matches(peer, Hash256(sha256(&secret))) {
                    return Watch::RevokedByPeer {
                        state: n,
                        to_local: as_ref,
                        revocation_secret: secret,
                    };
                }
            }
            // Our own commitment at state `n`.
            if matches(our, self.our_point(n)) {
                return Watch::OurCommitment {
                    state: n,
                    to_local: Some(as_ref),
                    delay: self.params.delay,
                };
            }
            // The peer's latest commitment (point announced, not revealed).
            if let Some(pt) = self.their_points.get(&n).copied() {
                if matches(peer, pt) {
                    let to_remote = self.find_our_output(tx, txid);
                    return Watch::PeerLatest {
                        state: n,
                        to_remote,
                    };
                }
            }
        }
        // No matchable to_local (trimmed to dust): the remaining shapes carry a
        // to_remote key output, which the output-count heuristic reads.
        let ctx = crate::channel::watcher::WatchContext {
            params: &self.params,
            our_index: our,
            store: &self.store,
            latest_state: self.local_commit_number.unwrap_or(0),
        };
        crate::channel::watcher::classify(&ctx, funding, tx)
    }

    /// A key output paying our own funding key (a `to_remote` that is ours).
    fn find_our_output(&self, tx: &Transaction, txid: Hash256) -> Option<OutputRef> {
        let ours = self.params.funding[self.our_index];
        tx.outputs.iter().enumerate().find_map(|(i, o)| {
            (o.scheme == CHANNEL_SCHEME && o.pubkey_hash == ours).then_some(OutputRef {
                outpoint: OutPoint {
                    txid,
                    index: i as u32,
                },
                output: *o,
            })
        })
    }

    /// Builds the signed penalty transaction that sweeps the counterparty's
    /// revoked `to_local` output to `sweep_to`, paying `fee`.
    pub fn build_penalty(
        &self,
        watch: &Watch,
        sweep_to: Hash256,
        fee: u64,
    ) -> Result<Transaction, ChannelError> {
        let Watch::RevokedByPeer {
            state,
            to_local,
            revocation_secret,
        } = watch
        else {
            return Err(ChannelError::Unexpected);
        };
        let _ = state;
        let holder = 1 - self.our_index;
        let point = Hash256(sha256(revocation_secret));
        let policy = self.params.to_local_policy(holder, point);
        Ok(txbuild::penalty_tx(
            to_local.outpoint,
            &to_local.output,
            &policy,
            *revocation_secret,
            sweep_to,
            fee,
            self.network,
            self.signer.as_ref(),
        ))
    }

    /// Builds the signed sweep of our own `to_local` output after the delay.
    pub fn build_local_sweep(
        &self,
        watch: &Watch,
        sweep_to: Hash256,
        fee: u64,
    ) -> Result<Transaction, ChannelError> {
        let Watch::OurCommitment {
            state,
            to_local: Some(to_local),
            ..
        } = watch
        else {
            return Err(ChannelError::Unexpected);
        };
        let policy = self
            .params
            .to_local_policy(self.our_index, self.our_point(*state));
        Ok(txbuild::local_sweep_tx(
            to_local.outpoint,
            &to_local.output,
            &policy,
            sweep_to,
            fee,
            self.network,
            self.signer.as_ref(),
        ))
    }

    /// Builds the signed claim of a `to_remote` output that is already ours.
    pub fn build_to_remote_claim(
        &self,
        to_remote: &crate::channel::watcher::OutputRef,
        sweep_to: Hash256,
        fee: u64,
    ) -> Transaction {
        txbuild::to_remote_claim_tx(
            to_remote.outpoint,
            &to_remote.output,
            sweep_to,
            fee,
            self.network,
            self.signer.as_ref(),
        )
    }
}
