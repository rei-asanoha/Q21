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

use crate::address::Network;
use crate::channel::journal::{Balances, Journal, Record};
use crate::channel::keys::{Signer, CHANNEL_SCHEME};
use crate::channel::messages::{Message, Revocation, TierSigs};
use crate::channel::txbuild::{self, ChannelParams, Commitment, FeeTier, ACCEPTOR, FUNDER};
use crate::channel::watcher::Watch;
use crate::hash::{tagged_hash_parts, Hash256};
use crate::sha256::sha256;
use crate::shachain;
use crate::tx::{OutPoint, Transaction, TxOut};
use std::collections::{BTreeMap, HashSet};
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
    /// Whether, for the current top state, we were the initiator. Set during
    /// replay from the order of the LocalCommit/RemoteCommit records, and
    /// during live operation as updates run.
    initiated_top: Option<bool>,

    /// The counterparty's announced revocation points, by state.
    their_points: BTreeMap<u64, Hash256>,
    /// The counterparty's revealed secrets, compact.
    store: shachain::Store,

    /// Base fee rate (per thousand weight units); the tiers multiply it.
    base_fee_rate: u64,

    /// Reestablish nonces already accepted from the peer, for freshness.
    seen_nonces: HashSet<[u8; 32]>,
}

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
    ) -> Result<Machine, ChannelError> {
        let cid = channel_id(&params.funding);
        let revocation_seed = sha256(
            &[
                b"Q21/channel/revocation-root".as_ref(),
                signer.pubkey(),
                cid.as_bytes(),
            ]
            .concat(),
        );
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
        })?;
        Ok(Machine {
            params,
            network,
            our_index,
            channel_id: cid,
            signer,
            our_pubkey,
            their_pubkey,
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
            initiated_top: None,
            their_points: BTreeMap::new(),
            store: shachain::Store::new(),
            base_fee_rate,
            seen_nonces: HashSet::new(),
        })
    }

    // --- Revocation points ---------------------------------------------------

    fn our_secret(&self, n: u64) -> [u8; 32] {
        shachain::derive(&self.revocation_seed, shachain::MAX_INDEX - n)
    }

    fn our_point(&self, n: u64) -> Hash256 {
        Hash256(sha256(&self.our_secret(n)))
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
        self.with_funding_input(
            self.params
                .commitment(self.our_index, n, bal, self.commit_fee(tier), rev),
        )
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
        let sum = bal[0].checked_add(bal[1]).ok_or(ChannelError::BadBalances)?;
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

    /// Funder: records the funding outpoint and returns [`Message::Funding`]
    /// with our signatures of the acceptor's first commitment.
    pub fn funding_created(&mut self, outpoint: OutPoint) -> Result<Message, ChannelError> {
        if self.our_index != FUNDER || self.phase != Phase::Opening {
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
        self.initiated_top = Some(true);
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
        if self.phase != Phase::Open {
            return Err(ChannelError::Unexpected);
        }
        let n = *state;
        // Idempotent resend: we already fully processed this update.
        if self.local_commit_number >= Some(n) {
            return self.resend_ack(n);
        }
        if n != self.next_state() {
            return Err(ChannelError::Unexpected);
        }
        self.check_balances(*balances)?;
        // INV2: persist the counterparty's signature over our commitment `n`
        // before acknowledging.
        self.verify_our_commitment(n, *balances, tier_sigs)?;
        self.persist_local_commit(n, *balances, tier_sigs.clone(), /*we_initiated=*/ false)?;
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
        if self.phase != Phase::Open {
            return Err(ChannelError::Unexpected);
        }
        let n = *state;
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
        if self.revocations_recv >= Some(n - 1) {
            return Ok(()); // idempotent resend
        }
        self.take_revocation(n - 1, revocation)?;
        Ok(())
    }

    fn next_state(&self) -> u64 {
        self.local_commit_number.map_or(0, |n| n + 1).max(
            self.remote_commit_number
                .map_or(0, |n| n + 1),
        )
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
        self.initiated_top = Some(we_initiated);
        Ok(())
    }

    fn persist_remote_commit(&mut self, n: u64, bal: Balances) -> Result<(), ChannelError> {
        self.journal
            .append(&Record::RemoteCommit { state: n, balances: bal })?;
        self.remote_commit_number = Some(n);
        self.remote_balances.insert(n, bal);
        Ok(())
    }

    fn persist_revocation_sent(&mut self, m: u64) -> Result<(), ChannelError> {
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

    // --- Idempotent resends for reestablish ----------------------------------

    fn resend_ack(&self, n: u64) -> Result<Message, ChannelError> {
        let bal = *self
            .remote_balances
            .get(&n)
            .ok_or(ChannelError::Invariant("missing remote balances for resend"))?;
        let tier_sigs = self.sign_their_commitment(n, bal)?;
        let revocation = self.make_revocation(n - 1)?;
        Ok(Message::Ack {
            state: n,
            tier_sigs,
            revocation,
        })
    }

    fn resend_revoke(&self, n: u64) -> Result<Message, ChannelError> {
        Ok(Message::Revoke {
            state: n,
            revocation: self.make_revocation(n - 1)?,
        })
    }

    fn resend_update(&self, n: u64) -> Result<Message, ChannelError> {
        let bal = *self
            .remote_balances
            .get(&n)
            .ok_or(ChannelError::Invariant("missing remote balances for resend"))?;
        let tier_sigs = self.sign_their_commitment(n, bal)?;
        Ok(Message::Update {
            state: n,
            balances: bal,
            tier_sigs,
        })
    }

    // --- Cooperative close ---------------------------------------------------

    /// Proposes a cooperative close at the current balance, returning
    /// [`Message::Close`].
    pub fn propose_close(&mut self, fee: u64) -> Result<Message, ChannelError> {
        if self.phase != Phase::Open {
            return Err(ChannelError::Unexpected);
        }
        self.journal.append(&Record::ClosingCoop { fee })?;
        self.phase = Phase::Closing;
        Ok(Message::Close { fee })
    }

    /// Handles a peer's [`Message::Close`], returning our [`Message::CloseSigned`].
    pub fn on_close(&mut self, msg: &Message) -> Result<Message, ChannelError> {
        let Message::Close { fee } = msg else {
            return Err(ChannelError::Unexpected);
        };
        if !matches!(self.phase, Phase::Open | Phase::Closing) {
            return Err(ChannelError::Unexpected);
        }
        if self.phase == Phase::Open {
            self.journal.append(&Record::ClosingCoop { fee: *fee })?;
            self.phase = Phase::Closing;
        }
        let bal = self.current_balances();
        let close = self.params.cooperative_close(self.funding()?, bal, *fee);
        let m = self
            .params
            .funding_sighash(&close.tx, self.network, self.our_index);
        Ok(Message::CloseSigned {
            fee: *fee,
            signature: self.signer.sign(&m),
        })
    }

    /// Verifies the peer's [`Message::CloseSigned`] and returns the fully
    /// signed cooperative close transaction, ready to broadcast.
    pub fn on_close_signed(&mut self, msg: &Message) -> Result<Transaction, ChannelError> {
        let Message::CloseSigned { fee, signature } = msg else {
            return Err(ChannelError::Unexpected);
        };
        let bal = self.current_balances();
        let close = self.params.cooperative_close(self.funding()?, bal, *fee);
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
        let (mut sigs_ours, mut sigs_theirs): (Vec<u8>, Vec<u8>) = (our_sig, signature.clone());
        let mut sigs: [&[u8]; 2] = [&[], &[]];
        let mut pks: [&[u8]; 2] = [&[], &[]];
        if self.our_index == FUNDER {
            sigs[FUNDER] = &sigs_ours;
            sigs[ACCEPTOR] = &sigs_theirs;
            pks[FUNDER] = &self.our_pubkey;
            pks[ACCEPTOR] = &self.their_pubkey;
        } else {
            sigs[ACCEPTOR] = &sigs_ours;
            sigs[FUNDER] = &sigs_theirs;
            pks[ACCEPTOR] = &self.our_pubkey;
            pks[FUNDER] = &self.their_pubkey;
        }
        self.params.complete_funding_spend(&mut tx, sigs, pks);
        let _ = (&mut sigs_ours, &mut sigs_theirs);
        self.journal.append(&Record::Closed)?;
        self.phase = Phase::Closed;
        Ok(tx)
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
        let revocation_seed = sha256(
            &[
                b"Q21/channel/revocation-root".as_ref(),
                signer.pubkey(),
                cid.as_bytes(),
            ]
            .concat(),
        );
        let mut m = Machine {
            params,
            network,
            our_index: our_index as usize,
            channel_id: cid,
            our_pubkey: signer.pubkey().to_vec(),
            signer,
            their_pubkey,
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
            initiated_top: None,
            their_points: BTreeMap::new(),
            store: shachain::Store::new(),
            base_fee_rate,
            seen_nonces: HashSet::new(),
        };
        m.replay(&records);
        Ok(m)
    }

    fn replay(&mut self, records: &[Record]) {
        let mut top_state: Option<u64> = None;
        let mut top_first_local: Option<bool> = None;
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
                    if Some(*state) > top_state {
                        top_state = Some(*state);
                        top_first_local = Some(true);
                    } else if top_state == Some(*state) && top_first_local.is_none() {
                        top_first_local = Some(true);
                    }
                }
                Record::RemoteCommit { state, balances } => {
                    self.remote_commit_number = Some(*state);
                    self.remote_balances.insert(*state, *balances);
                    if Some(*state) > top_state {
                        top_state = Some(*state);
                        top_first_local = Some(false);
                    } else if top_state == Some(*state) && top_first_local.is_none() {
                        top_first_local = Some(false);
                    }
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
                Record::ClosingCoop { .. } => self.phase = Phase::Closing,
                Record::Forcing => self.phase = Phase::Forcing,
                Record::Penalised => self.phase = Phase::Penalised,
                Record::Closed => self.phase = Phase::Closed,
            }
        }
        // top_first_local true => we journaled LocalCommit first => responder.
        // false => RemoteCommit first => initiator.
        self.initiated_top = top_first_local.map(|first_local| !first_local);
        if self.phase == Phase::Opening && self.local_commit_number == Some(0) {
            self.phase = Phase::Funded;
        }
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
        let proof = self
            .signer
            .sign(&reestablish_message(self.channel_id, nonce, self.our_index as u8));
        Ok(Message::Reestablish {
            channel_id: self.channel_id,
            local_commit_number: self.local_commit_number.map_or(0, |n| n + 1),
            remote_commit_number: self.remote_commit_number.map_or(0, |n| n + 1),
            next_revocation_sent: self.revocations_sent.map_or(0, |m| m + 1),
            next_revocation_recv: self.revocations_recv.map_or(0, |m| m + 1),
            nonce,
            direction: self.our_index as u8,
            proof,
        })
    }

    /// Verifies a peer's [`Message::Reestablish`] and returns the messages we
    /// must resend to resynchronize. The peer runs the mirror of this; the two
    /// resend sets together restore both sides.
    pub fn on_reestablish(&mut self, msg: &Message) -> Result<Vec<Message>, ChannelError> {
        let Message::Reestablish {
            channel_id: cid,
            local_commit_number: their_next_local,
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
        if !self.seen_nonces.insert(*nonce) {
            return Err(ChannelError::BadReestablish);
        }
        // The peer proved its funding key over its own fresh nonce and its
        // direction; the freshness check above stops a replay.
        if usize::from(*direction) != 1 - self.our_index {
            return Err(ChannelError::BadReestablish);
        }
        let expected = reestablish_message(self.channel_id, *nonce, *direction);
        crate::sig::verify(CHANNEL_SCHEME, &self.their_pubkey, &expected, proof)
            .map_err(|_| ChannelError::BadReestablish)?;

        // --- Resync. The protocol is strictly sequential: at most one state
        // is in flight. Decide, from the two sides' counters, which single
        // message we owe the peer.
        let mut out = Vec::new();
        // Their highest state they can enforce (local to them) is
        // their_next_local - 1; the highest they have signed for us equals our
        // local_commit's state when complete.
        let their_local = their_next_local.checked_sub(1);
        let their_recv = their_next_recv.checked_sub(1);

        // Case A: we signed the peer's commitment at `r` but they have not
        // persisted it (their enforceable top is below `r`): resend the
        // commitment signature as Update (if we initiated) or Ack (responder).
        if let Some(r) = self.remote_commit_number {
            if their_local.map_or(true, |tl| tl < r) {
                if self.initiated_top == Some(true) {
                    out.push(self.resend_update(r)?);
                } else {
                    out.push(self.resend_ack(r)?);
                }
                return Ok(out);
            }
        }

        // Case B: we owe a revocation the peer has not received. We have
        // revealed up to `revocations_sent`; if the peer's next_recv is below
        // or equal, resend that revocation.
        if let Some(s) = self.revocations_sent {
            if their_recv.map_or(true, |tr| tr < s) {
                // Resend as Ack (responder also owes its commitment sig, but
                // that was covered by Case A) or Revoke (initiator).
                if self.initiated_top == Some(true) {
                    out.push(self.resend_revoke(s + 1)?);
                } else {
                    out.push(self.resend_ack(s + 1)?);
                }
            }
        }
        Ok(out)
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

    /// Builds (and keeps private) a commitment at `n` for `tier` at the
    /// balances we signed it at, for use in tests of a revoked broadcast.
    pub fn signed_commitment_at(
        &self,
        n: u64,
        tier: FeeTier,
    ) -> Result<Transaction, ChannelError> {
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
        let policy = self.params.to_local_policy(self.our_index, self.our_point(*state));
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
