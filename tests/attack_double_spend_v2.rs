//! EXECUTED ATTACK: double spend, malleability and forgery (v2).
//!
//! Campaign of September 22, 2026. We do not read the code: we attack it.
//! Each test plays an adversary who holds a real wallet, builds or tampers
//! with a transaction, mines a block with a real proof of work (minimum
//! difficulty of the regtest network) and tries to get it accepted by a node.
//!
//! CONVENTION: the test PASSES (green) when the attack FAILS, that is, when
//! the node refuses the block, and for the RIGHT reason. A red test here
//! would be a real vulnerability, exploitable before launch.
//!
//! The six attacks covered:
//!   1. double spend of the same output within a single block;
//!   2. output tampered with (address, then amount) after signing;
//!   3. forged signature (one flipped byte);
//!   4. substitution of the presented public key;
//!   5. spending an immature coinbase;
//!   6. value not conserved: outputs > inputs, with a valid signature.

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::lamport::SecretKey;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow;
use q21_core::sig::{SchemeId, VerifyError};
use q21_core::tx::{Transaction, TxIn, TxOut, Witness};
use q21_core::validate::ValidationError;
use q21_core::wallet::Wallet;

const NETWORK: Network = Network::Regtest;
const ATTEMPTS: u64 = 50_000_000;

fn timestamp(height: u64) -> u64 {
    GENESIS_TIME + height * TARGET_BLOCK_SECS
}

/// Re-mines a block after altering it: without this, the alteration would
/// invalidate the Merkle root and hence the proof of work, and the block
/// would be refused for the wrong reason: a false positive that proves
/// nothing.
fn remine(b: &mut Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let table = PowTable::build(TableParams::for_network(NETWORK), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &table, ATTEMPTS).expect("re-mining");
}

/// Prepares a chain in which `w` holds mature funds.
fn chain_with_funds(w: &mut Wallet, blocks: u64) -> Chain {
    let _ = w.new_address();
    let g = genesis_block(NETWORK);
    let mut c = Chain::new(NETWORK, g);
    for i in 1..=blocks {
        let a = w.new_address();
        let t = timestamp(i);
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ATTEMPTS)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }
    c
}

// ---------------------------------------------------------------------------
// ATTACK 1: double spend of the same output within a single block.
//
// Alice signs ONE transfer to Bob, then slips it TWICE into the same block:
// both inputs point to the same confirmed output. The validator must catch
// the second occurrence.
// ---------------------------------------------------------------------------
#[test]
fn attack_double_spend_same_block_is_refused() {
    let mut alice = Wallet::from_seed([0xa1; 32], NETWORK);
    let mut c = chain_with_funds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb0; 32], NETWORK);
    let addr_bob = bob.new_address();

    let tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("building the transaction");

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = alice.new_address();
    let block = c
        .mine_block(
            miner.hash,
            SchemeId::LamportOts,
            &[tx.clone(), tx],
            t,
            ATTEMPTS,
        )
        .expect("mining the attack block");

    let r = c.connect(&block, t + 1);
    assert!(
        matches!(r, Err(ValidationError::DoubleSpend(_))),
        "ATTACK SUCCEEDED: double spend accepted, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 2a: tampered output: the address is redirected after signing.
//
// Alice signs a payment to Bob; the attacker replaces the output's key hash
// with their own. The sighash commits to the outputs: the signature is no
// longer worth anything.
// ---------------------------------------------------------------------------
#[test]
fn attack_redirected_output_address_is_refused() {
    let mut alice = Wallet::from_seed([0xa2; 32], NETWORK);
    let mut c = chain_with_funds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb2; 32], NETWORK);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("building");

    // The thief redirects the first output to their address.
    tx.outputs[0].pubkey_hash = Hash256([0x66; 32]);

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = alice.new_address();
    let mut block = c
        .mine_block(miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining");
    remine(&mut block);

    let r = c.connect(&block, t + 1);
    assert!(
        matches!(r, Err(ValidationError::Signature(_))),
        "ATTACK SUCCEEDED: redirected output accepted, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 2b: tampered output: the amount is inflated after signing.
// ---------------------------------------------------------------------------
#[test]
fn attack_inflated_output_amount_is_refused() {
    let mut alice = Wallet::from_seed([0xa3; 32], NETWORK);
    let mut c = chain_with_funds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb3; 32], NETWORK);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("building");

    // We multiply the payment by a thousand after the fact.
    let due = tx.outputs[0].value.units();
    tx.outputs[0].value = Amount::from_units(due * 1_000);

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = alice.new_address();
    let mut block = c
        .mine_block(miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining");
    remine(&mut block);

    let r = c.connect(&block, t + 1);
    assert!(
        matches!(r, Err(ValidationError::Signature(_))),
        "ATTACK SUCCEEDED: inflated amount accepted, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 3: forged signature: a single flipped byte.
// ---------------------------------------------------------------------------
#[test]
fn attack_forged_signature_is_refused() {
    let mut alice = Wallet::from_seed([0xa4; 32], NETWORK);
    let mut c = chain_with_funds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb4; 32], NETWORK);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("building");

    // One signature byte flipped: the revealed preimage no longer hashes back.
    tx.inputs[0].witness.signature[0] ^= 0x01;

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = alice.new_address();
    let block = c
        .mine_block(miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining");

    let r = c.connect(&block, t + 1);
    assert!(
        matches!(
            r,
            Err(ValidationError::Signature(VerifyError::InvalidSignature))
        ),
        "ATTACK SUCCEEDED: forged signature accepted, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 4: key substitution: another public key is presented.
//
// The presented key must hash to the key hash written in the lock.
// Substituting another one, however well formed, breaks that link.
// ---------------------------------------------------------------------------
#[test]
fn attack_key_substitution_is_refused() {
    let mut alice = Wallet::from_seed([0xa5; 32], NETWORK);
    let mut c = chain_with_funds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb5; 32], NETWORK);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("building");

    // A foreign public key, valid in itself but which does not open this lock.
    let foreign_key = SecretKey::from_seed([0x99; 32], 0).public_key();
    tx.inputs[0].witness.pubkey = foreign_key;

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = alice.new_address();
    let mut block = c
        .mine_block(miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining");
    remine(&mut block);

    let r = c.connect(&block, t + 1);
    assert!(
        matches!(r, Err(ValidationError::KeyDoesNotMatchLock)),
        "ATTACK SUCCEEDED: substituted key accepted, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 5: spending an immature coinbase.
//
// The wallet already refuses to build it; and if we force the validator's
// hand with a transaction signed by hand, it refuses too.
// ---------------------------------------------------------------------------
#[test]
fn attack_immature_coinbase_is_refused() {
    let seed = [0xa6; 32];
    let mut alice = Wallet::from_seed(seed, NETWORK);
    let mut c = chain_with_funds(&mut alice, 5);

    // 1) The wallet itself refuses: nothing is mature.
    let mut bob = Wallet::from_seed([0xb6; 32], NETWORK);
    let addr_bob = bob.new_address();
    let r = alice.create_transaction(
        &c.utxo,
        c.height(),
        &addr_bob,
        Amount::from_units(100_000),
        Amount::ZERO,
    );
    assert!(
        r.is_err(),
        "ATTACK SUCCEEDED: the wallet built on an immature coinbase"
    );

    // 2) We force the validator's hand: we target a coinbase directly.
    //    It belongs to one of Alice's addresses; we find the index that
    //    opens it to sign an authentic spend; only maturity must stop it.
    let target = c
        .utxo
        .iter()
        .map(|(o, _)| *o)
        .min()
        .expect("the UTXO set is not empty");
    let spent = c.utxo.get(&target).expect("targeted output").output;

    // Look for the derivation index whose key hash opens this lock.
    let index = (0..64u32)
        .find(|i| {
            q21_core::sig::pubkey_hash(
                SchemeId::LamportOts,
                &SecretKey::from_seed(seed, *i).public_key(),
            ) == spent.pubkey_hash
        })
        .expect("the coinbase address can be derived from Alice's wallet");
    let sk = SecretKey::from_seed(seed, index);

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: target,
            witness: Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(MIN_OUTPUT_VALUE),
            scheme: SchemeId::LamportOts,
            pubkey_hash: addr_bob.hash,
        }],
        lock_time: 0,
    };
    let msg = tx.sighash(0, NETWORK, &spent);
    tx.inputs[0].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = alice.new_address();
    let block = c
        .mine_block(miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining");
    let r = c.connect(&block, t + 1);
    assert!(
        matches!(r, Err(ValidationError::CoinbaseImmature { .. })),
        "ATTACK SUCCEEDED: immature coinbase spent, got {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 6: value not conserved, with an AUTHENTIC signature.
//
// The most honest case: we do not break the signature, we respect it. Alice
// forges by hand a transaction whose outputs are worth TWICE the input, then
// signs it correctly (the sighash commits to these inflated outputs, so the
// signature is valid). Only the value conservation rule can stop it, and it
// must.
// ---------------------------------------------------------------------------
#[test]
fn attack_value_not_conserved_with_valid_signature_is_refused() {
    let seed = [0xa7; 32];
    let mut alice = Wallet::from_seed(seed, NETWORK);
    let c = chain_with_funds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb7; 32], NETWORK);
    let addr_bob = bob.new_address();

    // A mature, spendable coin of Alice's, with its derivation index.
    let (target, spent, index) = alice
        .spendable(&c.utxo, c.height())
        .into_iter()
        .next()
        .expect("Alice has a spendable coin");
    let sk = SecretKey::from_seed(seed, index);

    // Outputs = 2 x input: money would appear if the node accepted it.
    let input_value = spent.value.units();
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: target,
            witness: Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(input_value * 2),
            scheme: SchemeId::LamportOts,
            pubkey_hash: addr_bob.hash,
        }],
        lock_time: 0,
    };
    // Authentic signature over the inflated transaction.
    let msg = tx.sighash(0, NETWORK, &spent);
    tx.inputs[0].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = timestamp(h);
    let miner = alice.new_address();
    let mut c = c;
    let block = c
        .mine_block(miner.hash, SchemeId::LamportOts, &[tx], t, ATTEMPTS)
        .expect("mining");

    let r = c.connect(&block, t + 1);
    assert!(
        matches!(r, Err(ValidationError::ValueNotConserved { .. })),
        "ATTACK SUCCEEDED: outputs > inputs accepted (inflation), got {r:?}"
    );
}
