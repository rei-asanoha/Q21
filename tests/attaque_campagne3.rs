//! ATTAQUES (red-team, 3e campagne) — creation de monnaie et rejeu de signature.
//!
//! Trois attaques menees de bout en bout contre une vraie chaine, chacune
//! visant l'objectif le plus grave : faire exister une unite qui n'aurait pas
//! du l'etre, ou depenser ce qu'on ne detient pas.
//!
//! 1. Une coinbase qui reclame une unite de plus que sa subvention.
//! 2. Une coinbase qui reclame des frais que le bloc ne porte pas (« frais
//!    fantomes ») : le mineur empoche subvention + frais reels + 1.
//! 3. Le rejeu d'une signature d'une entree sur une autre entree de la meme
//!    transaction, verrouillees par la meme clef : sans liaison de l'indice
//!    dans le condensat signe, une seule signature ouvrirait les deux.
//!
//! Les trois doivent echouer. Ce fichier prouve qu'elles echouent.

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::{COINBASE_MATURITY, MIN_OUTPUT_VALUE, TARGET_BLOCK_SECS};
use q21_core::hash::Hash256;
use q21_core::lamport::SecretKey;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow;
use q21_core::sig::{pubkey_hash, SchemeId};
use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use q21_core::validate::ValidationError;
use q21_core::wallet::Wallet;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn horodatage(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

/// Re-mine un bloc apres qu'on l'a altere : sans quoi le validateur le
/// refuserait sur la racine de Merkle, et l'attaque passerait au vert sans rien
/// avoir prouve.
fn remine(b: &mut q21_core::block::Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let table = PowTable::build(TableParams::for_network(RESEAU), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &table, ESSAIS).expect("re-minage");
}

// ---------------------------------------------------------------------------
// 1. Une coinbase qui reclame une unite de trop
// ---------------------------------------------------------------------------

#[test]
fn une_coinbase_qui_reclame_une_unite_de_trop_est_refusee() {
    let mut w = Wallet::from_seed([0x31; 32], RESEAU);
    let a = w.new_address();
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    for i in 1..=3u64 {
        let t = horodatage(i);
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }

    let h = c.height() + 1;
    let t = horodatage(h);
    let mut bloc = c
        .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
        .expect("minage");

    // L'attaque : une unite indivisible de plus que la subvention autorisee.
    bloc.transactions[0].outputs[0].value =
        Amount::from_units(bloc.transactions[0].outputs[0].value.units() + 1);
    remine(&mut bloc);

    assert!(
        matches!(
            c.connect(&bloc, t + 1),
            Err(ValidationError::SubventionExcessive { .. })
        ),
        "une coinbase qui reclame plus que sa subvention doit etre refusee"
    );
}

// ---------------------------------------------------------------------------
// 2. Des frais fantomes
// ---------------------------------------------------------------------------

/// Un bloc porte une vraie transaction a frais `F`. La coinbase a donc droit a
/// `subvention + F`. L'attaque reclame `subvention + F + 1` : le mineur essaie
/// d'empocher un frais que personne n'a paye. La borne est exacte, a l'unite.
#[test]
fn une_coinbase_ne_peut_pas_reclamer_de_frais_fantomes() {
    let mut alice = Wallet::from_seed([0x32; 32], RESEAU);
    let _ = alice.new_address();
    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    for _ in 0..(COINBASE_MATURITY + 3) {
        let a = alice.new_address();
        let h = c.height() + 1;
        let t = horodatage(h);
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }

    // Une vraie depense, avec de vrais frais.
    let mut bob = Wallet::from_seed([0xb2; 32], RESEAU);
    let addr_bob = bob.new_address();
    let frais = Amount::from_units(7_000);
    let tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(50_000),
            frais,
        )
        .expect("construction de la depense");

    let h = c.height() + 1;
    let t = horodatage(h);
    let addr_mineur = alice.new_address();
    let mut bloc = c
        .mine_block(addr_mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage");

    // La coinbase a deja empoche les vrais frais. On en ajoute UN de plus :
    // un frais que le bloc ne porte pas.
    bloc.transactions[0].outputs[0].value =
        Amount::from_units(bloc.transactions[0].outputs[0].value.units() + 1);
    remine(&mut bloc);

    assert!(
        matches!(
            c.connect(&bloc, t + 1),
            Err(ValidationError::SubventionExcessive { .. })
        ),
        "les frais reclames ne peuvent pas depasser les frais reellement payes"
    );
}

// ---------------------------------------------------------------------------
// 3. Rejeu d'une signature d'une entree sur une autre
// ---------------------------------------------------------------------------

/// Deux sorties verrouillees par **la meme clef**. Une transaction les depense
/// toutes deux. La signature de l'entree 0 est-elle rejouable sur l'entree 1 ?
///
/// Elle ne doit pas l'etre : le condensat signe engage l'indice de l'entree
/// (`Transaction::sighash`). Sans cette liaison, une seule signature ouvrirait
/// autant d'entrees que la meme clef en verrouille — un vol de fonds propres,
/// certes, mais surtout la porte a des constructions ou une signature vaut pour
/// une entree qu'elle n'a jamais visee.
#[test]
fn une_signature_ne_se_rejoue_pas_d_une_entree_sur_l_autre() {
    // Une clef Lamport, deux coinbases qui lui sont versees : deux UTXO sous la
    // meme serrure. (Lamport a usage unique n'a de sens que cote confidentialite ;
    // le consensus l'autorise sur le reseau de regression, et c'est le seul
    // schema qui n'exige pas la feature `mldsa` pour signer dans une epreuve.)
    let sk = SecretKey::from_seed([0x33; 32], 0);
    let verrou = pubkey_hash(SchemeId::LamportOts, &sk.public_key());

    let mut c = Chain::new(RESEAU, genesis_block(RESEAU));
    for _ in 0..(COINBASE_MATURITY + 4) {
        let h = c.height() + 1;
        let t = horodatage(h);
        let b = c
            .mine_block(verrou, SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }

    // Deux sorties mures, verrouillees par `verrou`.
    let hauteur = c.height();
    let mut mures: Vec<(OutPoint, TxOut)> = c
        .utxo
        .iter()
        .filter(|(_, e)| {
            e.is_coinbase
                && hauteur >= e.height + COINBASE_MATURITY
                && e.output.pubkey_hash == verrou // pas la genese, verrouillee ailleurs
        })
        .map(|(o, e)| (*o, e.output))
        .collect();
    mures.sort_by_key(|(o, _)| *o);
    assert!(mures.len() >= 4, "il faut au moins quatre sorties mures");
    let (u0, out0) = mures[0];
    let (u1, out1) = mures[1];

    // Une transaction a deux entrees, chacune signee a son propre indice.
    let construire = |u0: OutPoint, u1: OutPoint| Transaction {
        version: 1,
        inputs: vec![
            TxIn {
                prev_out: u0,
                witness: Witness::default(),
                sequence: u32::MAX,
            },
            TxIn {
                prev_out: u1,
                witness: Witness::default(),
                sequence: u32::MAX,
            },
        ],
        outputs: vec![TxOut {
            value: Amount::from_units(MIN_OUTPUT_VALUE),
            scheme: SchemeId::LamportOts,
            pubkey_hash: Hash256([0x99; 32]),
        }],
        lock_time: 0,
    };

    // --- Le temoin : la depense honnete, chaque entree signee a son indice.
    let mut tx = construire(u0, u1);
    let msg0 = tx.sighash(0, RESEAU, &out0);
    let msg1 = tx.sighash(1, RESEAU, &out1);
    assert_ne!(
        msg0, msg1,
        "les deux entrees ne partagent pas leur condensat"
    );
    tx.inputs[0].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg0),
    };
    tx.inputs[1].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg1),
    };
    let h = c.height() + 1;
    let t = horodatage(h);
    let bloc = c
        .mine_block(verrou, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage du temoin");
    assert!(
        c.connect(&bloc, t + 1).is_ok(),
        "la depense honnete a deux entrees doit etre acceptee"
    );

    // --- L'attaque : deux AUTRES sorties, meme clef, mais on ne signe QUE
    // l'entree 0 et on recopie sa signature sur l'entree 1.
    let (u2, out2) = mures[2];
    let (u3, _out3) = mures[3];
    let mut attaque = construire(u2, u3);
    let msg2 = attaque.sighash(0, RESEAU, &out2);
    let temoin0 = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg2),
    };
    attaque.inputs[0].witness = temoin0.clone();
    // Le rejeu : la meme signature, la meme clef, sur l'entree 1.
    attaque.inputs[1].witness = temoin0;

    let h = c.height() + 1;
    let t = horodatage(h);
    let bloc = c
        .mine_block(verrou, SchemeId::LamportOts, &[attaque], t, ESSAIS)
        .expect("minage de l'attaque");
    let r = c.connect(&bloc, t + 1);
    assert!(
        r.is_err(),
        "une signature rejouee d'une entree sur l'autre ne doit JAMAIS etre acceptee (obtenu {r:?})"
    );
    assert!(
        matches!(r, Err(ValidationError::Signature(_))),
        "le rejeu doit etre refuse pour signature invalide, obtenu {r:?}"
    );
}
