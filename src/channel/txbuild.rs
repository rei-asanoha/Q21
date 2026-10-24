//! Every transaction a channel produces, built from real policy outputs and
//! signed through the existing ML-DSA path.
//!
//! The shapes are those of `examples/channel_sim.rs`, pinned here so both
//! sides of a channel — and the watcher — compute byte-for-byte the same
//! transactions. Nothing in this file touches the chain: it builds and weighs,
//! and leaves broadcasting to a caller.

use crate::amount::Amount;
use crate::channel::keys::{Signer, CHANNEL_SCHEME};
use crate::consensus::{MIN_OUTPUT_VALUE, WITNESS_DISCOUNT};
use crate::hash::Hash256;
use crate::policy::{self, Policy, Satisfaction};
use crate::sha256::sha256;
use crate::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};

/// Index of the funder in every `[_; 2]` the channel carries.
pub const FUNDER: usize = 0;
/// Index of the acceptor.
pub const ACCEPTOR: usize = 1;

/// The three fee tiers every commitment state is signed at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FeeTier {
    Low = 0,
    Medium = 1,
    High = 2,
}

impl FeeTier {
    pub const ALL: [FeeTier; 3] = [FeeTier::Low, FeeTier::Medium, FeeTier::High];

    /// The multiplier this tier applies to the base rate: 1, 4, 16.
    pub const fn multiplier(self) -> u64 {
        match self {
            FeeTier::Low => 1,
            FeeTier::Medium => 4,
            FeeTier::High => 16,
        }
    }

    pub fn from_index(i: u8) -> Option<FeeTier> {
        match i {
            0 => Some(FeeTier::Low),
            1 => Some(FeeTier::Medium),
            2 => Some(FeeTier::High),
            _ => None,
        }
    }
}

/// Upper bound on a commitment fee rate, per thousand weight units. The ×16
/// tier multiplies a congested median, and without a cap a transient spike
/// would let the ladder eat an unbounded slice of the channel. Far above
/// [`crate::mempool::MIN_FEE_RATE`]; reaching it would already be an extreme
/// market.
pub const MAX_COMMIT_FEE_RATE: u64 = 10_000;

/// The fee reserved to sweep a `to_local`, penalty, or `to_remote` output. A
/// sweep's output is `value - fee`, but the fee is capped so that output never
/// falls below the dust floor (see [`capped_fee`]); otherwise a cheater could
/// pick a revoked balance that made the victim's penalty dust-invalid.
pub const SWEEP_FEE: u64 = 20_000;

/// A `to_local` output is created only when it clears the dust floor *plus* the
/// sweep fee, so any to_local that exists can always be swept to an output at or
/// above dust. A smaller holder balance is dropped into the miner fee — which
/// still denies a cheating counterparty, and costs an honest holder only a dust
/// amount on a tiny channel.
pub const TO_LOCAL_DUST: u64 = MIN_OUTPUT_VALUE + SWEEP_FEE;

/// The fee to charge a sweep of `value`, capped so the swept output stays at or
/// above the dust floor. With `TO_LOCAL_DUST` trimming, a created to_local pays
/// the full `SWEEP_FEE`; a smaller *revoked* output (shape chosen by a cheater)
/// pays less rather than producing a dust-invalid, unconfirmable sweep.
pub fn capped_fee(value: u64, fee: u64) -> u64 {
    fee.min(value.saturating_sub(MIN_OUTPUT_VALUE))
}

/// The fee rate of `tier`, from a base rate (itself at least the relay
/// minimum), multiplied and then capped.
pub fn tier_rate(base_rate: u64, tier: FeeTier) -> u64 {
    base_rate
        .max(crate::mempool::MIN_FEE_RATE)
        .saturating_mul(tier.multiplier())
        .min(MAX_COMMIT_FEE_RATE)
}

/// A plain key output to `hash` of `CHANNEL_SCHEME`.
pub fn key_output(hash: Hash256, value: u64) -> TxOut {
    TxOut {
        value: Amount::from_units(value),
        scheme: CHANNEL_SCHEME,
        pubkey_hash: hash,
    }
}

fn key_leaf(hash: Hash256) -> Policy {
    Policy::Key {
        scheme: CHANNEL_SCHEME,
        pubkey_hash: hash,
    }
}

fn one_input(op: OutPoint, outputs: Vec<TxOut>, lock_time: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: op,
            witness: Witness::default(),
            sequence: u32::MAX,
        }],
        outputs,
        lock_time,
    }
}

/// The static parameters of one channel: who the two parties are, how much the
/// funding holds, and the to-self delay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelParams {
    /// Pubkey hashes, `[FUNDER, ACCEPTOR]`; also their funding leaf positions.
    pub funding: [Hash256; 2],
    pub capacity: Amount,
    /// The `Older(D)` delay on a holder's own output.
    pub delay: u16,
}

/// A built commitment: the transaction, the `to_local` policy a holder (or a
/// watcher) rebuilds to spend it, and how many units dust trimming moved into
/// the fee.
pub struct Commitment {
    pub tx: Transaction,
    pub to_local: Policy,
    pub trimmed_units: u64,
    pub trimmed_outputs: u32,
}

impl ChannelParams {
    /// The 2-of-2 funding policy, `All[Key F, Key A]`.
    pub fn funding_policy(&self) -> Policy {
        Policy::All(vec![key_leaf(self.funding[0]), key_leaf(self.funding[1])])
    }

    /// The funding output, locked to the funding policy.
    pub fn funding_output(&self) -> TxOut {
        self.funding_policy().output(self.capacity)
    }

    /// The 48-bit mask that obscures the state number in a commitment's
    /// `lock_time`, derived from both funding keys as BOLT 3 does.
    pub fn obscurer(&self) -> u64 {
        let mut b = self.funding[0].0.to_vec();
        b.extend_from_slice(self.funding[1].as_bytes());
        let h = sha256(&b);
        u64::from_le_bytes(h[..8].try_into().unwrap()) & crate::shachain::MAX_INDEX
    }

    /// The state number carried, obscured, by a commitment's `lock_time`.
    pub fn state_of(&self, tx: &Transaction) -> u64 {
        tx.lock_time ^ self.obscurer()
    }

    /// The `to_local` policy of `holder`'s commitment at revocation point
    /// `rev` (the SHA-256 of the holder's secret for that state):
    /// `Any[ All[Key other, Preimage(rev)], All[Key holder, Older(D)] ]`.
    ///
    /// Branch 0 is the revocation path (the counterparty, with the secret);
    /// branch 1 is the delayed path (the holder, after `D` blocks).
    pub fn to_local_policy(&self, holder: usize, rev: Hash256) -> Policy {
        let other = 1 - holder;
        Policy::Any(vec![
            Policy::All(vec![key_leaf(self.funding[other]), Policy::Preimage(rev)]),
            Policy::All(vec![
                key_leaf(self.funding[holder]),
                Policy::Older(self.delay),
            ]),
        ])
    }

    /// Builds `holder`'s commitment for state `n` at balances `bal` (before
    /// the fee), paying commitment fee `fee` from the funder's side, with
    /// revocation point `rev`. Outputs below the dust floor are dropped and
    /// their value counted into the trim.
    ///
    /// `bal` is `[funder, acceptor]` and must already sum to the capacity.
    pub fn commitment(
        &self,
        holder: usize,
        n: u64,
        bal: [u64; 2],
        fee: u64,
        rev: Hash256,
    ) -> Commitment {
        let other = 1 - holder;
        let mut side = bal;
        // The funder pays the commitment fee, as in Lightning. A saturating
        // subtraction keeps a build from panicking on a pathological balance;
        // the state machine never lets the funder fall below the fee.
        side[FUNDER] = side[FUNDER].saturating_sub(fee);

        let to_local = self.to_local_policy(holder, rev);
        let mut outs = Vec::new();
        let mut trimmed_units = 0u64;
        let mut trimmed_outputs = 0u32;

        // The holder's own output is delayed/revocable and must later be swept,
        // so it is created only when it clears dust *and* the sweep fee; a
        // smaller balance goes to the miner fee (see [`TO_LOCAL_DUST`]).
        if side[holder] >= TO_LOCAL_DUST {
            outs.push(to_local.output(Amount::from_units(side[holder])));
        } else if side[holder] > 0 {
            trimmed_units += side[holder];
            trimmed_outputs += 1;
        }
        if side[other] >= MIN_OUTPUT_VALUE {
            outs.push(key_output(self.funding[other], side[other]));
        } else if side[other] > 0 {
            trimmed_units += side[other];
            trimmed_outputs += 1;
        }

        let lock_time = n ^ self.obscurer();
        let tx = one_input(self.funding_outpoint_placeholder(), outs, lock_time);
        Commitment {
            tx,
            to_local,
            trimmed_units,
            trimmed_outputs,
        }
    }

    // The funding outpoint is injected by the caller once the funding txid is
    // known; the builder leaves a placeholder so a commitment can be shaped
    // before funding is broadcast, then its input rewritten.
    fn funding_outpoint_placeholder(&self) -> OutPoint {
        OutPoint {
            txid: Hash256::ZERO,
            index: 0,
        }
    }

    /// The message the key at funding leaf `signer` signs over a spend of the
    /// funding output (a commitment or a cooperative close). The funding
    /// policy has no `Any`, so there are no choices.
    pub fn funding_sighash(
        &self,
        tx: &Transaction,
        network: crate::address::Network,
        signer: usize,
    ) -> Hash256 {
        policy::sighash(
            tx,
            0,
            network,
            &self.funding_output(),
            &self.funding_policy(),
            signer as u8,
            &[],
        )
    }

    /// Fills the witness of a funding spend with both signatures.
    pub fn complete_funding_spend(
        &self,
        tx: &mut Transaction,
        sigs: [&[u8]; 2],
        pubkeys: [&[u8]; 2],
    ) {
        let s = Satisfaction::All(
            (0..2)
                .map(|i| Satisfaction::Key {
                    pubkey: pubkeys[i].to_vec(),
                    signature: sigs[i].to_vec(),
                })
                .collect(),
        );
        tx.inputs[0].witness = policy::witness(&self.funding_policy(), &s);
    }

    /// A cooperative close paying each party its final balance, the side of
    /// `payer` (the party that proposed the close) less the close fee, dropping
    /// dust into the fee.
    ///
    /// Each output pays the party's **wallet** payout address (`payout[i]`),
    /// not its channel key: a channel key is not in any wallet's address space,
    /// so a close that paid it would leave the funds unspendable. Both sides
    /// build this transaction identically from the payout addresses they
    /// exchanged at open, so their signatures match.
    pub fn cooperative_close(
        &self,
        funding: OutPoint,
        bal: [u64; 2],
        fee: u64,
        payout: [Hash256; 2],
        payer: usize,
    ) -> Commitment {
        let mut side = bal;
        side[payer] = side[payer].saturating_sub(fee);
        let mut outs = Vec::new();
        let mut trimmed_units = 0u64;
        let mut trimmed_outputs = 0u32;
        for (i, &v) in side.iter().enumerate() {
            if v >= MIN_OUTPUT_VALUE {
                outs.push(key_output(payout[i], v));
            } else if v > 0 {
                trimmed_units += v;
                trimmed_outputs += 1;
            }
        }
        let tx = one_input(funding, outs, 0);
        Commitment {
            tx,
            // A close has no to_local; the funding policy is what it spends.
            to_local: self.funding_policy(),
            trimmed_units,
            trimmed_outputs,
        }
    }
}

/// The witness size of a spend is counted from both witness fields; a
/// commitment or close spends the funding output under the 2-of-2 policy. This
/// fills a *representative* witness of the right sizes so a fee can be
/// computed before the real signatures exist.
pub fn dummy_funding_witness(policy: &Policy) -> Witness {
    let key = Satisfaction::Key {
        pubkey: vec![0u8; CHANNEL_SCHEME.pubkey_len()],
        signature: vec![0u8; CHANNEL_SCHEME.sig_len()],
    };
    let s = Satisfaction::All(vec![key.clone(), key]);
    policy::witness(policy, &s)
}

/// The weight of a two-output commitment once fully witnessed: the figure the
/// commitment fee is computed from, so the fee does not depend on which side
/// happens to be dust.
pub fn standard_commitment_weight(params: &ChannelParams) -> u64 {
    // A representative two-output commitment: both balances above dust.
    let half = params.capacity.units() / 2;
    let c = params.commitment(
        FUNDER,
        0,
        [half, params.capacity.units() - half],
        0,
        Hash256::ZERO,
    );
    let mut tx = c.tx;
    tx.inputs[0].witness = dummy_funding_witness(&params.funding_policy());
    tx.weight(WITNESS_DISCOUNT)
}

/// The weight of a two-output cooperative close once fully witnessed.
pub fn standard_close_weight(params: &ChannelParams) -> u64 {
    let half = params.capacity.units() / 2;
    let c = params.cooperative_close(
        OutPoint {
            txid: Hash256::ZERO,
            index: 0,
        },
        [half, params.capacity.units() - half],
        0,
        [Hash256::ZERO, Hash256([1u8; 32])],
        FUNDER,
    );
    let mut tx = c.tx;
    tx.inputs[0].witness = dummy_funding_witness(&params.funding_policy());
    tx.weight(WITNESS_DISCOUNT)
}

/// The range of cooperative-close fees a party accepts, in units: from the
/// relay minimum rate to [`MAX_COMMIT_FEE_RATE`] over the close's weight, and
/// never less than the sweep fee at the top, which every node proposes.
pub fn close_fee_bounds(params: &ChannelParams) -> (u64, u64) {
    let w = standard_close_weight(params);
    let min = (crate::mempool::MIN_FEE_RATE.saturating_mul(w)).div_ceil(1000);
    let max = (MAX_COMMIT_FEE_RATE.saturating_mul(w) / 1000).max(SWEEP_FEE);
    (min, max)
}

/// The commitment fee, in units, at fee rate `rate` (per thousand weight
/// units), computed from the standard two-output commitment weight.
pub fn commitment_fee(params: &ChannelParams, rate: u64) -> u64 {
    rate.saturating_mul(standard_commitment_weight(params)) / 1000
}

/// A penalty transaction: the counterparty broadcast a revoked commitment, and
/// we sweep its `to_local` output through the revocation branch, which needs
/// our key and the revocation secret.
///
/// Built and signed at broadcast time: it needs only our own key.
#[allow(clippy::too_many_arguments)]
pub fn penalty_tx(
    to_local_outpoint: OutPoint,
    to_local_output: &TxOut,
    to_local_policy: &Policy,
    secret: [u8; 32],
    sweep_to: Hash256,
    fee: u64,
    network: crate::address::Network,
    signer: &dyn Signer,
) -> Transaction {
    let fee = capped_fee(to_local_output.value.units(), fee);
    let value = to_local_output.value.units().saturating_sub(fee);
    let mut tx = one_input(to_local_outpoint, vec![key_output(sweep_to, value)], 0);
    // Revocation path: choice 0 of the to_local `Any`, leaf 0 (the key),
    // the preimage at leaf 1.
    let m = policy::sighash(&tx, 0, network, to_local_output, to_local_policy, 0, &[0]);
    let s = Satisfaction::Any {
        index: 0,
        branch: Box::new(Satisfaction::All(vec![
            Satisfaction::Key {
                pubkey: signer.pubkey().to_vec(),
                signature: signer.sign(&m),
            },
            Satisfaction::Preimage(secret),
        ])),
    };
    tx.inputs[0].witness = policy::witness(to_local_policy, &s);
    tx
}

/// A local sweep: we broadcast our own commitment, and after the delay we take
/// our `to_local` output through the delayed branch, which needs only our key.
///
/// The spend carries the `Older(D)` branch; the chain enforces the age, so the
/// transaction is only valid once the commitment is `D` blocks deep.
pub fn local_sweep_tx(
    to_local_outpoint: OutPoint,
    to_local_output: &TxOut,
    to_local_policy: &Policy,
    sweep_to: Hash256,
    fee: u64,
    network: crate::address::Network,
    signer: &dyn Signer,
) -> Transaction {
    let fee = capped_fee(to_local_output.value.units(), fee);
    let value = to_local_output.value.units().saturating_sub(fee);
    let mut tx = one_input(to_local_outpoint, vec![key_output(sweep_to, value)], 0);
    // Delayed path: choice 1 of the `Any`, leaf is the holder's key (leaf 2
    // in the whole tree: other-key=0, preimage=1, holder-key=2).
    let holder_leaf = 2u8;
    let m = policy::sighash(
        &tx,
        0,
        network,
        to_local_output,
        to_local_policy,
        holder_leaf,
        &[1],
    );
    let s = Satisfaction::Any {
        index: 1,
        branch: Box::new(Satisfaction::All(vec![
            Satisfaction::Key {
                pubkey: signer.pubkey().to_vec(),
                signature: signer.sign(&m),
            },
            Satisfaction::Older,
        ])),
    };
    tx.inputs[0].witness = policy::witness(to_local_policy, &s);
    tx
}

/// A claim of a `to_remote` output: it is a plain key output to us, so we spend
/// it with an ordinary key witness.
pub fn to_remote_claim_tx(
    to_remote_outpoint: OutPoint,
    to_remote_output: &TxOut,
    sweep_to: Hash256,
    fee: u64,
    network: crate::address::Network,
    signer: &dyn Signer,
) -> Transaction {
    let fee = capped_fee(to_remote_output.value.units(), fee);
    let value = to_remote_output.value.units().saturating_sub(fee);
    let mut tx = one_input(to_remote_outpoint, vec![key_output(sweep_to, value)], 0);
    let m = tx.sighash(0, network, to_remote_output);
    tx.inputs[0].witness = Witness {
        pubkey: signer.pubkey().to_vec(),
        signature: signer.sign(&m),
    };
    tx
}

/// The weight of a single ML-DSA-87 key spend, the shape of a funding input
/// and of a `to_remote` claim: base of one input and one output, plus one key
/// witness.
pub fn key_spend_weight() -> u64 {
    let mut tx = one_input(
        OutPoint {
            txid: Hash256::ZERO,
            index: 0,
        },
        vec![key_output(Hash256::ZERO, MIN_OUTPUT_VALUE)],
        0,
    );
    tx.inputs[0].witness = Witness {
        pubkey: vec![0u8; CHANNEL_SCHEME.pubkey_len()],
        signature: vec![0u8; CHANNEL_SCHEME.sig_len()],
    };
    tx.weight(WITNESS_DISCOUNT)
}
