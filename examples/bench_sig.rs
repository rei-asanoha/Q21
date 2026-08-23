//! Cout reel de la verification, aux deux niveaux de securite ML-DSA.
//!
//! La verification est ce que **chaque noeud du reseau** paie pour chaque
//! signature de chaque transaction de chaque bloc. C'est donc elle, et non la
//! signature, qui decide si un niveau de securite est tenable.
use q21_core::address::{Address, Network};
use q21_core::amount::Amount;
use q21_core::hash::Hash256;
use q21_core::sig::{self, SchemeId};
use q21_core::tx::{OutPoint, TxOut};
use q21_core::utxo::{UtxoEntry, UtxoSet};
use q21_core::wallet::Wallet;

fn main() {
    if !SchemeId::MlDsa65.disponible() {
        eprintln!(
            "ML-DSA n'est pas compile dans ce binaire.\n\
             Relancez avec : cargo run --release --features mldsa --example bench_sig"
        );
        return;
    }
    for (nom, sch) in [
        ("ML-DSA-65 (categorie NIST 3)", SchemeId::MlDsa65),
        ("ML-DSA-87 (categorie NIST 5)", SchemeId::MlDsa87),
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
        let entree = &tx.inputs[0];
        let m = tx.sighash(0);

        let n = 3_000;
        let t = std::time::Instant::now();
        let mut ok = 0usize;
        for _ in 0..n {
            if sig::verify(sch, &entree.witness.pubkey, &m, &entree.witness.signature).is_ok() {
                ok += 1;
            }
        }
        let d = t.elapsed();
        println!(
            "{nom}\n  {ok}/{n} verifiees en {:?}\n  {:>9.0} verifications/s\n  clef publique {} o, signature {} o, transaction {} o\n",
            d,
            n as f64 / d.as_secs_f64(),
            entree.witness.pubkey.len(),
            entree.witness.signature.len(),
            tx.encode().len()
        );
    }
}
