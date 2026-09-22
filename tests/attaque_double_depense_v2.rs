//! ATTAQUE EXECUTEE — double-depense, malleabilite et falsification (v2).
//!
//! Campagne du 22 septembre 2026. On ne lit pas le code : on l'attaque. Chaque
//! test joue un adversaire qui tient un portefeuille reel, construit ou trafique
//! une transaction, mine un bloc avec une vraie preuve de travail (difficulte
//! minimale du reseau de regression) et tente de la faire accepter par un noeud.
//!
//! CONVENTION : le test REUSSIT (vert) quand l'attaque ECHOUE — c'est-a-dire
//! quand le noeud refuse le bloc, et pour la BONNE raison. Un test rouge ici
//! serait une faille reelle et exploitable avant lancement.
//!
//! Les six attaques couvertes :
//!   1. double-depense d'une meme sortie dans un seul bloc ;
//!   2. sortie trafiquee (adresse puis montant) apres signature ;
//!   3. signature falsifiee (un octet retourne) ;
//!   4. substitution de la clef publique presentee ;
//!   5. depense d'une coinbase immature ;
//!   6. valeur non conservee — sorties > entrees, signature pourtant valide.

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

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn horodatage(hauteur: u64) -> u64 {
    GENESIS_TIME + hauteur * TARGET_BLOCK_SECS
}

/// Re-mine un bloc apres l'avoir altere : sans cela, l'alteration invaliderait
/// la racine de Merkle donc la preuve de travail, et le bloc serait refuse pour
/// la mauvaise raison — un faux positif qui ne prouve rien.
fn remine(b: &mut Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let table = PowTable::build(TableParams::for_network(RESEAU), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &table, ESSAIS).expect("re-minage");
}

/// Prepare une chaine ou `w` detient des fonds mûrs.
fn chaine_avec_fonds(w: &mut Wallet, blocs: u64) -> Chain {
    let _ = w.new_address();
    let g = genesis_block(RESEAU);
    let mut c = Chain::new(RESEAU, g);
    for i in 1..=blocs {
        let a = w.new_address();
        let t = horodatage(i);
        let b = c
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
    }
    c
}

// ---------------------------------------------------------------------------
// ATTAQUE 1 — double-depense d'une meme sortie dans un seul bloc.
//
// Alice signe UN transfert vers Bob, puis le glisse DEUX fois dans le meme
// bloc : les deux entrees pointent la meme sortie confirmee. Le validateur doit
// mordre a la seconde occurrence.
// ---------------------------------------------------------------------------
#[test]
fn attaque_double_depense_meme_bloc_est_refusee() {
    let mut alice = Wallet::from_seed([0xa1; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb0; 32], RESEAU);
    let addr_bob = bob.new_address();

    let tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("construction de la transaction");

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = alice.new_address();
    let bloc = c
        .mine_block(
            mineur.hash,
            SchemeId::LamportOts,
            &[tx.clone(), tx],
            t,
            ESSAIS,
        )
        .expect("minage du bloc d'attaque");

    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(r, Err(ValidationError::DoubleDepense(_))),
        "ATTAQUE REUSSIE : double-depense acceptee, obtenu {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 2a — sortie trafiquee : on detourne l'adresse apres signature.
//
// Alice signe un paiement a Bob ; l'attaquant remplace l'empreinte de la sortie
// par la sienne. Le sighash engage les sorties : la signature ne vaut plus rien.
// ---------------------------------------------------------------------------
#[test]
fn attaque_adresse_de_sortie_detournee_est_refusee() {
    let mut alice = Wallet::from_seed([0xa2; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb2; 32], RESEAU);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("construction");

    // Le voleur redirige la premiere sortie vers son adresse.
    tx.outputs[0].pubkey_hash = Hash256([0x66; 32]);

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = alice.new_address();
    let mut bloc = c
        .mine_block(mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage");
    remine(&mut bloc);

    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(r, Err(ValidationError::Signature(_))),
        "ATTAQUE REUSSIE : sortie detournee acceptee, obtenu {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 2b — sortie trafiquee : on gonfle le montant apres signature.
// ---------------------------------------------------------------------------
#[test]
fn attaque_montant_de_sortie_gonfle_est_refuse() {
    let mut alice = Wallet::from_seed([0xa3; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb3; 32], RESEAU);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("construction");

    // On multiplie le paiement par mille apres coup.
    let du = tx.outputs[0].value.units();
    tx.outputs[0].value = Amount::from_units(du * 1_000);

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = alice.new_address();
    let mut bloc = c
        .mine_block(mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage");
    remine(&mut bloc);

    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(r, Err(ValidationError::Signature(_))),
        "ATTAQUE REUSSIE : montant gonfle accepte, obtenu {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 3 — signature falsifiee : un seul octet retourne.
// ---------------------------------------------------------------------------
#[test]
fn attaque_signature_falsifiee_est_refusee() {
    let mut alice = Wallet::from_seed([0xa4; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb4; 32], RESEAU);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("construction");

    // Un octet de signature retourne : la preimage revelee ne recondense plus.
    tx.inputs[0].witness.signature[0] ^= 0x01;

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = alice.new_address();
    let bloc = c
        .mine_block(mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage");

    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(
            r,
            Err(ValidationError::Signature(VerifyError::SignatureInvalide))
        ),
        "ATTAQUE REUSSIE : signature falsifiee acceptee, obtenu {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 4 — substitution de clef : on presente une autre clef publique.
//
// La clef presentee doit se condenser en l'empreinte inscrite dans le verrou.
// En substituer une autre — fut-elle parfaitement formee — casse ce lien.
// ---------------------------------------------------------------------------
#[test]
fn attaque_substitution_de_clef_est_refusee() {
    let mut alice = Wallet::from_seed([0xa5; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb5; 32], RESEAU);
    let addr_bob = bob.new_address();

    let mut tx = alice
        .create_transaction(
            &c.utxo,
            c.height(),
            &addr_bob,
            Amount::from_units(100_000),
            Amount::ZERO,
        )
        .expect("construction");

    // Une clef publique etrangere, valide en soi mais qui n'ouvre pas ce verrou.
    let clef_etrangere = SecretKey::from_seed([0x99; 32], 0).public_key();
    tx.inputs[0].witness.pubkey = clef_etrangere;

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = alice.new_address();
    let mut bloc = c
        .mine_block(mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage");
    remine(&mut bloc);

    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(r, Err(ValidationError::ClefNeCorrespondPasAuVerrou)),
        "ATTAQUE REUSSIE : clef substituee acceptee, obtenu {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 5 — depense d'une coinbase immature.
//
// Le portefeuille refuse deja de construire ; et si l'on force la main au
// validateur avec une transaction signee a la main, il refuse aussi.
// ---------------------------------------------------------------------------
#[test]
fn attaque_coinbase_immature_est_refusee() {
    let seed = [0xa6; 32];
    let mut alice = Wallet::from_seed(seed, RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, 5);

    // 1) Le portefeuille lui-meme refuse : rien n'est mûr.
    let mut bob = Wallet::from_seed([0xb6; 32], RESEAU);
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
        "ATTAQUE REUSSIE : le portefeuille a construit sur une coinbase immature"
    );

    // 2) On force la main au validateur : on vise une coinbase directement.
    //    Elle appartient a une adresse d'Alice ; on retrouve l'indice qui
    //    l'ouvre pour signer une depense authentique — seule la maturite doit
    //    l'arreter.
    let cible = c
        .utxo
        .iter()
        .map(|(o, _)| *o)
        .min()
        .expect("le jeu d'UTXO n'est pas vide");
    let depensee = c.utxo.get(&cible).expect("sortie visee").output;

    // Cherche l'indice de derivation dont l'empreinte ouvre ce verrou.
    let index = (0..64u32)
        .find(|i| {
            q21_core::sig::pubkey_hash(
                SchemeId::LamportOts,
                &SecretKey::from_seed(seed, *i).public_key(),
            ) == depensee.pubkey_hash
        })
        .expect("l'adresse de la coinbase est derivable du portefeuille d'Alice");
    let sk = SecretKey::from_seed(seed, index);

    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: cible,
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
    let msg = tx.sighash(0, RESEAU, &depensee);
    tx.inputs[0].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = alice.new_address();
    let bloc = c
        .mine_block(mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage");
    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(r, Err(ValidationError::CoinbaseImmature { .. })),
        "ATTAQUE REUSSIE : coinbase immature depensee, obtenu {r:?}"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 6 — valeur non conservee, avec une signature AUTHENTIQUE.
//
// Le cas le plus honnete : on ne casse pas la signature, on la respecte. Alice
// forge a la main une transaction dont les sorties valent DEUX FOIS l'entree,
// puis la signe correctement (le sighash engage ces sorties gonflees, donc la
// signature est valide). Seule la regle de conservation de la valeur peut
// l'arreter — et elle doit.
// ---------------------------------------------------------------------------
#[test]
fn attaque_valeur_non_conservee_signature_valide_est_refusee() {
    let seed = [0xa7; 32];
    let mut alice = Wallet::from_seed(seed, RESEAU);
    let c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 10);

    let mut bob = Wallet::from_seed([0xb7; 32], RESEAU);
    let addr_bob = bob.new_address();

    // Une piece mûre et depensable d'Alice, avec son indice de derivation.
    let (cible, depensee, index) = alice
        .spendable(&c.utxo, c.height())
        .into_iter()
        .next()
        .expect("Alice a une piece depensable");
    let sk = SecretKey::from_seed(seed, index);

    // Sorties = 2 x entree : de la monnaie apparaitrait si le noeud l'acceptait.
    let entree = depensee.value.units();
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: cible,
            witness: Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(entree * 2),
            scheme: SchemeId::LamportOts,
            pubkey_hash: addr_bob.hash,
        }],
        lock_time: 0,
    };
    // Signature authentique sur la transaction gonflee.
    let msg = tx.sighash(0, RESEAU, &depensee);
    tx.inputs[0].witness = Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = alice.new_address();
    let mut c = c;
    let bloc = c
        .mine_block(mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage");

    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(r, Err(ValidationError::ValeurNonConservee { .. })),
        "ATTAQUE REUSSIE : sorties > entrees acceptees (inflation), obtenu {r:?}"
    );
}
