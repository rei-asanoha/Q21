//! Real cost of verification, at both ML-DSA security levels.
//!
//! Verification is what **every node of the network** pays for every
//! signature of every transaction of every block. It is therefore
//! verification, and not signing, that decides whether a security level is
//! sustainable.
use q21_core::address::{Address, Network};
use q21_core::amount::Amount;
use q21_core::hash::Hash256;
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, TxOut};
use q21_core::utxo::{UtxoEntry, UtxoSet};
use q21_core::wallet::Wallet;

fn main() {
    if !SchemeId::MlDsa65.is_available() {
        eprintln!(
            "ML-DSA is not compiled into this binary.\n\
             Run again with: cargo run --release --features mldsa --example bench_sig"
        );
        return;
    }
    for (name, sch) in [
        ("ML-DSA-65 (NIST category 3)", SchemeId::MlDsa65),
        ("ML-DSA-87 (NIST category 5)", SchemeId::MlDsa87),
    ] {
        let mut w = Wallet::from_seed_scheme([3u8; 32], Network::Regtest, sch).unwrap();
        let a = w.new_address();
        let mut utxo = UtxoSet::new();
        utxo.insert(
            OutPoint {
                txid: Hash256([1u8; 32]),
                index: 0,
            },
            UtxoEntry {
                output: TxOut {
                    value: Amount::from_units(1_000_000),
                    scheme: sch,
                    pubkey_hash: a.hash,
                },
                height: 1,
                is_coinbase: false,
            },
        );
        let dest = Address::from_pubkey(Network::Regtest, sch, &[9u8; 32]);
        let tx = w
            .create_transaction(
                &utxo,
                10,
                &dest,
                Amount::from_units(1_000),
                Amount::from_units(100),
            )
            .expect("transaction");
        let input = &tx.inputs[0];
        let spent = utxo.get(&input.prev_out).expect("spent output").output;
        let m = tx.sighash(0, Network::Regtest, &spent);

        let n = 3_000;
        let t = std::time::Instant::now();
        let mut ok = 0usize;
        for _ in 0..n {
            if sig::verify(sch, &input.witness.pubkey, &m, &input.witness.signature).is_ok() {
                ok += 1;
            }
        }
        let d = t.elapsed();
        println!(
            "{name}\n  {ok}/{n} verified in {:?}\n  {:>9.0} verifications/s\n  public key {} B, signature {} B, transaction {} B\n",
            d,
            n as f64 / d.as_secs_f64(),
            input.witness.pubkey.len(),
            input.witness.signature.len(),
            tx.encode().len()
        );
    }
}
