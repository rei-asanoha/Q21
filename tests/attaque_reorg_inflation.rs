//! ATTAQUE — inflation par annulation d'un bloc a depenses chainees intra-bloc.
//!
//! Simulation de red-team (phase 8b). On reproduit exactement ce qu'un mineur
//! adverse controle : un bloc ou une transaction depense une sortie creee par
//! une transaction precedente du MEME bloc (chainage parent-enfant, autorise et
//! teste par `regression_chainage`). Puis une reorganisation defait ce bloc.
//!
//! Hypothese d'attaque : `UtxoSet::undo` retire les creees puis reinsere les
//! consommees, sans dedoublonnage. La sortie intra-bloc figure dans les deux
//! listes ; retiree comme creee, elle est reinseree comme consommee, et
//! survit — un UTXO fantome, depensable, ne prolongeant aucune transaction de
//! la chaine active. Monnaie creee a partir de rien.

use q21_core::amount::Amount;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::utxo::{UndoRecord, UtxoSet};

fn sortie(v: u64, h: u8) -> TxOut {
    TxOut {
        value: Amount::from_units(v),
        scheme: SchemeId::LamportOts,
        pubkey_hash: Hash256([h; 32]),
    }
}

fn coinbase(v: u64, h: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase(vec![9, 9, 9])],
        outputs: vec![sortie(v, h)],
        lock_time: 0,
    }
}

fn depense(txid: Hash256, index: u32, v: u64, h: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint { txid, index },
            witness: Witness::default(),
            sequence: 0,
        }],
        outputs: vec![sortie(v, h)],
        lock_time: 0,
    }
}

#[test]
fn annuler_un_bloc_a_chainage_intra_bloc_ne_doit_pas_creer_de_monnaie() {
    let mut u = UtxoSet::new();

    // --- Etat de depart : une seule piece de 10 000 detenue par la victime.
    let w = coinbase(10_000, 1);
    let mut undo_pre = UndoRecord::default();
    u.apply_transaction(&w, 1, &mut undo_pre);

    let valeur_avant = u.total_value();
    let empreinte_avant = u.commitment();

    // --- Le bloc adverse : UN SEUL UndoRecord pour tout le bloc, comme le fait
    //     `Chain::connect`. Deux transactions chainees dans le meme bloc.
    let mut undo_bloc = UndoRecord::default();

    // tx1 : depense W (10 000) -> Y = 9 000 sur l'empreinte 2
    let tx1 = depense(w.txid(), 0, 9_000, 2);
    u.apply_transaction(&tx1, 2, &mut undo_bloc);
    let y = OutPoint {
        txid: tx1.txid(),
        index: 0,
    };

    // tx2 : depense Y (9 000) -> Z = 8 000 sur l'empreinte 3
    let tx2 = depense(tx1.txid(), 0, 8_000, 3);
    u.apply_transaction(&tx2, 2, &mut undo_bloc);

    // --- La reorganisation defait le bloc.
    u.undo(&undo_bloc);

    // --- Verdicts. Apres annulation, l'ensemble doit etre BIT POUR BIT celui
    //     d'avant le bloc : une seule piece de 10 000, aucune autre.
    let fantome_present = u.contains(&y);
    let valeur_apres = u.total_value();
    let empreinte_apres = u.commitment();

    println!("valeur avant  : {}", valeur_avant.units());
    println!("valeur apres  : {}", valeur_apres.units());
    println!("fantome Y present apres annulation : {fantome_present}");
    println!(
        "empreinte identique : {}",
        empreinte_avant == empreinte_apres
    );
    println!(
        "empreinte incrementale == recalculee : {}",
        u.commitment() == u.commitment_recalculee()
    );

    assert!(
        !fantome_present,
        "FANTOME : la sortie intra-bloc Y a survecu a l'annulation — UTXO depensable cree a partir de rien"
    );
    assert_eq!(
        valeur_apres.units(),
        valeur_avant.units(),
        "INFLATION : la valeur totale de l'ensemble a augmente apres annulation"
    );
    assert_eq!(
        empreinte_apres, empreinte_avant,
        "DIVERGENCE : l'empreinte d'etat differe de celle d'avant le bloc — un noeud fraichement synchronise calculera un autre engagement"
    );
}
