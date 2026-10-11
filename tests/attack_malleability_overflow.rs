//! EXECUTED ATTACK: transaction malleability, and the 2010 value-overflow bug.
//!
//! Two documented real-world incidents, reproduced against Q21:
//!
//!   1. **Transaction malleability** — the class that drained Mt. Gox (2014):
//!      a third party rewrites the signature of a transaction in transit. If
//!      that changes its identity, it becomes a different, confusing
//!      transaction. SegWit answered it by keeping the witness out of the
//!      `txid`. We check that touching the witness changes nothing an honest
//!      party relies on, and that the tampered form cannot confirm.
//!
//!   2. **Value overflow (CVE-2010-5139)** — block 74,638, August 15 2010: a
//!      transaction with two ~92-billion-BTC outputs whose sum wrapped a
//!      64-bit integer, so it passed the "outputs <= inputs" check and minted
//!      184 billion BTC. We reproduce the exact shape and check that Q21
//!      refuses it, with a valid signature, before any conservation check.
//!
//! CONVENTION: the test PASSES (green) when the attack FAILS. A red test here
//! would be a real, exploitable vulnerability.

use q21_core::amount::Amount;
use q21_core::consensus::MAX_SUPPLY;
use q21_core::hash::Hash256;
use q21_core::lamport;
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxError, TxIn, TxOut, Witness};
use q21_core::utxo::{UtxoEntry, UtxoSet};
use q21_core::validate::{check_transaction, ValidationError};
use q21_core::Network;

use std::collections::HashSet;

const NETWORK: Network = Network::Regtest;
const SEED: [u8; 32] = [0x7c; 32];

fn key(i: u32) -> (lamport::SecretKey, Vec<u8>, Hash256) {
    let sk = lamport::SecretKey::from_seed(SEED, i);
    let pk = sk.public_key();
    let h = sig::pubkey_hash(SchemeId::LamportOts, &pk);
    (sk, pk, h)
}

/// One synthetic confirmed output of `value` units, locked by key `idx`.
fn one_utxo(idx: u32, value: u64) -> (UtxoSet, (OutPoint, u32, TxOut)) {
    let (_, _, h) = key(idx);
    let o = OutPoint {
        txid: Hash256([idx as u8; 32]),
        index: idx,
    };
    let out = TxOut {
        value: Amount::from_units(value),
        scheme: SchemeId::LamportOts,
        pubkey_hash: h,
    };
    let mut u = UtxoSet::new();
    u.insert(
        o,
        UtxoEntry {
            output: out,
            height: 1,
            is_coinbase: false,
        },
    );
    (u, (o, idx, out))
}

fn out(value: u64, lock: u8) -> TxOut {
    TxOut {
        value: Amount::from_units(value),
        scheme: SchemeId::LamportOts,
        pubkey_hash: Hash256([lock; 32]),
    }
}

/// A transaction spending `input`, signed for real over `outputs`.
fn signed(input: &(OutPoint, u32, TxOut), outputs: Vec<TxOut>) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: input.0,
            witness: Witness::default(),
            sequence: 0xffff_ffff,
        }],
        outputs,
        lock_time: 0,
    };
    let (sk, pk, _) = key(input.1);
    let m = tx.sighash(0, NETWORK, &input.2);
    tx.inputs[0].witness = Witness {
        pubkey: pk,
        signature: sk.sign(&m),
    };
    tx
}

// ===========================================================================
// 1. MALLEABILITY
// ===========================================================================

/// Rewriting the witness does not change the `txid`, and changes the `wtxid`.
///
/// This is the property SegWit introduced after malleability was used to
/// confuse exchanges: the identity a recipient waits for (`txid`) does not
/// depend on the malleable part (the signature).
#[test]
fn rewriting_the_witness_does_not_change_the_txid() {
    let (_u, input) = one_utxo(1, 500_000);
    let tx = signed(&input, vec![out(400_000, 0x22)]);

    let txid = tx.txid();
    let wtxid = tx.wtxid();

    // The attacker flips bytes of the signature and of the presented key.
    let mut mutated = tx.clone();
    for b in mutated.inputs[0].witness.signature.iter_mut().take(8) {
        *b ^= 0xff;
    }
    // Appending trailing bytes is the other classic malleation.
    mutated.inputs[0].witness.signature.push(0x00);

    assert_eq!(
        mutated.txid(),
        txid,
        "ATTACK SUCCEEDED: the witness changed the txid — malleability"
    );
    assert_ne!(
        mutated.wtxid(),
        wtxid,
        "the wtxid must register the change, so a block commitment can see it"
    );
    // And the Merkle leaf, which commits to both, does change: a block in
    // transit cannot have its signatures swapped unnoticed.
    assert_ne!(tx.merkle_leaf(), mutated.merkle_leaf());
}

/// The malleated form cannot confirm: its signature no longer verifies. So
/// malleability produces neither a new identity (above) nor a usable
/// transaction (here) — it produces nothing.
#[test]
fn a_malleated_transaction_cannot_confirm() {
    let (u, input) = one_utxo(2, 500_000);
    let honest = signed(&input, vec![out(400_000, 0x22)]);

    // The honest transaction verifies.
    let mut seen = HashSet::new();
    assert!(check_transaction(&honest, &u, NETWORK, 2, &mut seen).is_ok());

    // The malleated one does not.
    let mut mutated = honest.clone();
    mutated.inputs[0].witness.signature[0] ^= 0xff;
    let mut seen2 = HashSet::new();
    let r = check_transaction(&mutated, &u, NETWORK, 2, &mut seen2);
    assert!(
        matches!(r, Err(ValidationError::Signature(_))),
        "ATTACK SUCCEEDED: a malleated signature verified, got {r:?}"
    );
}

// ===========================================================================
// 2. VALUE OVERFLOW (CVE-2010-5139)
// ===========================================================================

/// The exact 2010 function: summing the outputs must fail on overflow, never
/// wrap. `total_output` is the one line whose absence minted 184 billion BTC.
#[test]
fn summing_outputs_fails_on_overflow_instead_of_wrapping() {
    // Many outputs, each within the cap, whose sum crosses 2^64.
    let per = MAX_SUPPLY; // the largest a single output may carry
    let n = (u64::MAX / per) as usize + 2; // enough to overflow the sum
    let outputs: Vec<TxOut> = (0..n).map(|_| out(per, 0x33)).collect();
    let tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: Hash256([9; 32]),
                index: 0,
            },
            witness: Witness::default(),
            sequence: 0,
        }],
        outputs,
        lock_time: 0,
    };
    assert!(
        matches!(tx.total_output(), Err(TxError::OutputSumOverflow)),
        "ATTACK SUCCEEDED: the output sum wrapped instead of failing"
    );
}

/// The full 2010 shape, with a VALID signature, run through the validator:
/// two enormous outputs. Q21 refuses it — and refuses it *before* the
/// conservation check, which is where the wrap used to slip through. The
/// money is never created.
#[test]
fn the_2010_overflow_transaction_is_refused_even_signed() {
    // The attacker really holds a coin and signs honestly over the two
    // monstrous outputs, exactly as in 2010.
    let (u, input) = one_utxo(3, 1_000_000);
    let huge = u64::MAX / 2 + 10; // two of them overflow u64
    let tx = signed(&input, vec![out(huge, 0x44), out(huge, 0x55)]);

    // The signature itself is valid: the attack is not a forgery.
    let m = tx.sighash(0, NETWORK, &input.2);
    let (_, pk, _) = key(3);
    assert!(
        sig::verify(
            SchemeId::LamportOts,
            &pk,
            &m,
            &tx.inputs[0].witness.signature
        )
        .is_ok(),
        "the test must exercise the overflow path, not a bad signature"
    );

    let mut seen = HashSet::new();
    let r = check_transaction(&tx, &u, NETWORK, 2, &mut seen);
    assert!(
        matches!(
            r,
            Err(ValidationError::Transaction(TxError::AmountAboveCap))
                | Err(ValidationError::Transaction(TxError::OutputSumOverflow))
        ),
        "ATTACK SUCCEEDED: the 2010 overflow transaction was accepted, got {r:?}"
    );
}

/// A single output above the whole supply is refused on its own: the per-output
/// cap is the first of the three layers (per output, the sum, the total).
#[test]
fn a_single_output_above_the_supply_is_refused() {
    let (u, input) = one_utxo(4, 1_000_000);
    let tx = signed(&input, vec![out(MAX_SUPPLY + 1, 0x66)]);
    let mut seen = HashSet::new();
    let r = check_transaction(&tx, &u, NETWORK, 2, &mut seen);
    assert!(
        matches!(
            r,
            Err(ValidationError::Transaction(TxError::AmountAboveCap))
        ),
        "ATTACK SUCCEEDED: an output above the supply was accepted, got {r:?}"
    );
}
