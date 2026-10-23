//! The watcher: pure logic that, given a spent funding outpoint and the
//! transaction that spent it, decides what the spend was and what to do.
//!
//! No chain I/O: a caller feeds it a transaction it saw on the chain, and it
//! returns a decision. It reads the state number from the commitment's
//! `lock_time` (deobscured with the funding keys) and uses the revocation store
//! to tell a revoked state from the latest one. It never signs: the penalty and
//! sweep transactions are built and signed at broadcast time, by the holder of
//! the key (see [`crate::channel::machine::Machine::build_penalty`] and
//! [`crate::channel::machine::Machine::build_local_sweep`]).

use crate::channel::txbuild::ChannelParams;
use crate::shachain;
use crate::sig::SchemeId;
use crate::tx::{OutPoint, Transaction, TxOut};

/// A located output of a broadcast commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputRef {
    pub outpoint: OutPoint,
    pub output: TxOut,
}

/// What the watcher concludes about a spend of the funding output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Watch {
    /// The counterparty broadcast a state it had revoked. Sweep its `to_local`
    /// output with the revocation secret before its delay elapses.
    RevokedByPeer {
        state: u64,
        to_local: OutputRef,
        revocation_secret: [u8; 32],
    },
    /// The counterparty broadcast its latest state. Our funds sit in the
    /// `to_remote` output, already ours to claim with our key.
    PeerLatest {
        state: u64,
        to_remote: Option<OutputRef>,
    },
    /// We broadcast our own commitment. Our `to_local` output is ours to sweep,
    /// but only after the to-self delay.
    OurCommitment {
        state: u64,
        to_local: Option<OutputRef>,
        delay: u16,
    },
    /// The spend is not of this channel's funding output.
    NotOurChannel,
    /// It spends the funding output but does not look like any commitment we
    /// know how to read.
    Unrecognized,
}

/// What the watcher needs to classify a spend, none of it from the chain.
pub struct WatchContext<'a> {
    pub params: &'a ChannelParams,
    /// Our own index, `FUNDER` or `ACCEPTOR`.
    pub our_index: usize,
    /// The counterparty's revealed revocation secrets.
    pub store: &'a shachain::Store,
    /// The highest commitment number we hold (our current state).
    pub latest_state: u64,
}

/// Finds a key output paying `hash`, with its index.
fn find_key_output(tx: &Transaction, hash: crate::hash::Hash256) -> Option<(u32, TxOut)> {
    tx.outputs.iter().enumerate().find_map(|(i, o)| {
        if o.scheme == SchemeId::MlDsa87 && o.pubkey_hash == hash {
            Some((i as u32, *o))
        } else {
            None
        }
    })
}

/// Finds the single policy output (the `to_local`), with its index.
fn find_policy_output(tx: &Transaction) -> Option<(u32, TxOut)> {
    tx.outputs
        .iter()
        .enumerate()
        .find_map(|(i, o)| (o.scheme == SchemeId::Policy).then_some((i as u32, *o)))
}

/// Classifies a transaction that may spend the funding output.
pub fn classify(ctx: &WatchContext, funding: OutPoint, tx: &Transaction) -> Watch {
    if tx.inputs.first().map(|i| i.prev_out) != Some(funding) {
        return Watch::NotOurChannel;
    }
    let n = ctx.params.state_of(tx);
    let our_hash = ctx.params.funding[ctx.our_index];
    let their_hash = ctx.params.funding[1 - ctx.our_index];

    // The to_remote output pays the non-holder. If it pays us, the
    // counterparty is the holder; if it pays them, we are.
    let txid = tx.txid();
    let to_remote_ours = find_key_output(tx, our_hash);
    let to_remote_theirs = find_key_output(tx, their_hash);
    let policy_out = find_policy_output(tx);

    let holder_is_peer = to_remote_ours.is_some();
    let holder_is_us = to_remote_theirs.is_some();

    if holder_is_peer && !holder_is_us {
        // The counterparty's commitment. Revoked iff we hold its secret.
        if let Some(secret) = ctx.store.get(shachain::MAX_INDEX - n) {
            if let Some((idx, out)) = policy_out {
                return Watch::RevokedByPeer {
                    state: n,
                    to_local: OutputRef {
                        outpoint: OutPoint { txid, index: idx },
                        output: out,
                    },
                    revocation_secret: secret,
                };
            }
            // Revoked but its to_local was trimmed to dust: nothing to sweep
            // there; our to_remote is still ours.
        }
        let to_remote = to_remote_ours.map(|(idx, out)| OutputRef {
            outpoint: OutPoint { txid, index: idx },
            output: out,
        });
        return Watch::PeerLatest {
            state: n,
            to_remote,
        };
    }

    if holder_is_us && !holder_is_peer {
        let to_local = policy_out.map(|(idx, out)| OutputRef {
            outpoint: OutPoint { txid, index: idx },
            output: out,
        });
        return Watch::OurCommitment {
            state: n,
            to_local,
            delay: ctx.params.delay,
        };
    }

    let _ = ctx.latest_state;
    Watch::Unrecognized
}
