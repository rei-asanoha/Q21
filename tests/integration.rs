//! Tests de bout en bout.
//!
//! Les tests unitaires verifient des pieces. Ceux-ci verifient que l'assemblage
//! tient : qu'on peut miner, transferer, et surtout qu'aucune sequence de blocs
//! acceptes ne peut fabriquer de la monnaie.
//!
//! Les scenarios tournent sur le reseau de regression, ou la difficulte reste
//! figee au minimum. La regle de consensus testee est identique.

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::emission;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::tx::{Transaction, TxOut};
use q21_core::validate::ValidationError;
use q21_core::wallet::Wallet;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn horodatage(hauteur: u64) -> u64 {
    GENESIS_TIME + hauteur * TARGET_BLOCK_SECS
}

/// Re-mine un bloc apres l'avoir altere.
///
/// Indispensable des lors qu'on teste une regle de valeur : modifier une
/// coinbase invalide la racine de Merkle, donc la preuve de travail. Sans
/// re-minage, le validateur refuserait le bloc pour la mauvaise raison et le
/// test passerait au vert sans rien prouver.
fn remine(b: &mut q21_core::block::Block) {
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

#[test]
fn scenario_complet_miner_puis_transferer() {
    let mut alice = Wallet::from_seed([0xa1; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 10);

    let solde_initial = alice.balance(&c.utxo, c.height());
    assert!(solde_initial.units() > 0, "Alice devrait detenir des fonds");

    let mut bob = Wallet::from_seed([0xb0; 32], RESEAU);
    let addr_bob = bob.new_address();

    let montant = Amount::from_units(50_000);
    let frais = Amount::from_units(1_000);
    let tx = alice
        .create_transaction(&c.utxo, c.height(), &addr_bob, montant, frais)
        .expect("construction de la transaction");

    let h = c.height() + 1;
    let t = horodatage(h);
    let addr_mineur = alice.new_address();
    let bloc = c
        .mine_block(addr_mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .expect("minage du bloc");

    let frais_percus = c
        .connect(&bloc, t + 1)
        .expect("le bloc devrait etre accepte");
    assert_eq!(frais_percus, frais);

    // Bob doit maintenant voir ses fonds.
    bob.rescan(1);
    assert_eq!(bob.balance(&c.utxo, c.height()), montant);
}

/// Le test qui compte le plus de tout le projet.
#[test]
fn aucune_sequence_de_blocs_ne_peut_fabriquer_de_la_monnaie() {
    let mut w = Wallet::from_seed([0x33; 32], RESEAU);
    let c = chaine_avec_fonds(&mut w, 300);

    // Ce que le protocole autorise a avoir emis a cette hauteur.
    let theorique = emission::total_supply_at(c.height()).units();

    assert_eq!(
        c.total_issued().units(),
        theorique,
        "l'emission constatee doit egaler l'emission theorique"
    );
    assert_eq!(
        c.utxo.total_value().units(),
        theorique,
        "sans depense, toute la monnaie emise doit etre dans les UTXO"
    );
    assert!(c.total_issued().units() <= MAX_SUPPLY);
}

#[test]
fn un_mineur_ne_peut_pas_s_octroyer_plus_que_son_du() {
    let mut w = Wallet::from_seed([0x44; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut w, 5);

    let h = c.height() + 1;
    let t = horodatage(h);
    let a = w.new_address();
    let mut bloc = c
        .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
        .unwrap();

    // Une seule unite de trop, la plus petite possible.
    let du = bloc.transactions[0].outputs[0].value.units();
    bloc.transactions[0].outputs[0].value = Amount::from_units(du + 1);
    remine(&mut bloc);

    assert!(matches!(
        c.connect(&bloc, t + 1),
        Err(ValidationError::SubventionExcessive { .. })
    ));
}

#[test]
fn une_double_depense_dans_le_meme_bloc_est_refusee() {
    let mut w = Wallet::from_seed([0x55; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);

    let mut dest = Wallet::from_seed([0x66; 32], RESEAU);
    let a = dest.new_address();
    let tx = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(1_000),
            Amount::ZERO,
        )
        .expect("construction");

    // Le meme transfert, deux fois dans le meme bloc.
    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = w.new_address();
    let bloc = c
        .mine_block(
            mineur.hash,
            SchemeId::LamportOts,
            &[tx.clone(), tx],
            t,
            ESSAIS,
        )
        .unwrap();

    assert!(matches!(
        c.connect(&bloc, t + 1),
        Err(ValidationError::DoubleDepense(_))
    ));
}

#[test]
fn une_signature_falsifiee_est_refusee() {
    let mut w = Wallet::from_seed([0x77; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);

    let mut dest = Wallet::from_seed([0x88; 32], RESEAU);
    let a = dest.new_address();
    let mut tx = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(1_000),
            Amount::ZERO,
        )
        .expect("construction");

    // Un seul octet de signature modifie.
    tx.inputs[0].witness.signature[0] ^= 0x01;

    let h = c.height() + 1;
    let t = horodatage(h);
    let mineur = w.new_address();
    let bloc = c
        .mine_block(mineur.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .unwrap();

    assert!(matches!(
        c.connect(&bloc, t + 1),
        Err(ValidationError::Signature(_))
    ));
}

#[test]
fn on_ne_peut_pas_depenser_la_sortie_d_autrui() {
    let mut alice = Wallet::from_seed([0x91; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut alice, COINBASE_MATURITY + 5);

    // Mallory construit une transaction qui consomme une sortie d'Alice, en
    // presentant sa propre clef.
    let mut mallory = Wallet::from_seed([0x92; 32], RESEAU);
    let cible = alice.spendable(&c.utxo, c.height())[0].0;

    let sk = q21_core::lamport::SecretKey::from_seed([0x92; 32], 0);
    let addr_mallory = mallory.new_address();
    let mut tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn {
            prev_out: cible,
            witness: q21_core::tx::Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(1_000),
            scheme: SchemeId::LamportOts,
            pubkey_hash: addr_mallory.hash,
        }],
        lock_time: 0,
    };
    let msg = tx.sighash(0);
    tx.inputs[0].witness = q21_core::tx::Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = horodatage(h);
    let bloc = c
        .mine_block(addr_mallory.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .unwrap();

    // La signature est parfaitement valide — mais pour la mauvaise clef.
    assert!(matches!(
        c.connect(&bloc, t + 1),
        Err(ValidationError::ClefNeCorrespondPasAuVerrou)
    ));
}

#[test]
fn une_coinbase_immature_ne_peut_pas_etre_depensee() {
    let mut w = Wallet::from_seed([0xaa; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut w, 5);

    // Rien n'est mûr : le portefeuille lui-meme refuse de construire.
    let mut dest = Wallet::from_seed([0xbb; 32], RESEAU);
    let a = dest.new_address();
    let r = w.create_transaction(
        &c.utxo,
        c.height(),
        &a,
        Amount::from_units(1_000),
        Amount::ZERO,
    );
    assert!(r.is_err(), "aucune sortie ne devrait etre depensable");

    // Et si l'on force la main au validateur, il refuse aussi.
    let cible = c
        .utxo
        .iter()
        .map(|(o, _)| *o)
        .min()
        .expect("le jeu d'UTXO n'est pas vide");
    let sk = q21_core::lamport::SecretKey::from_seed([0xaa; 32], 0);
    let mut tx = Transaction {
        version: 1,
        inputs: vec![q21_core::tx::TxIn {
            prev_out: cible,
            witness: q21_core::tx::Witness::default(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut {
            value: Amount::from_units(1),
            scheme: SchemeId::LamportOts,
            pubkey_hash: a.hash,
        }],
        lock_time: 0,
    };
    let msg = tx.sighash(0);
    tx.inputs[0].witness = q21_core::tx::Witness {
        pubkey: sk.public_key(),
        signature: sk.sign(&msg),
    };

    let h = c.height() + 1;
    let t = horodatage(h);
    let bloc = c
        .mine_block(a.hash, SchemeId::LamportOts, &[tx], t, ESSAIS)
        .unwrap();
    let r = c.connect(&bloc, t + 1);
    assert!(
        matches!(
            r,
            Err(ValidationError::CoinbaseImmature { .. })
                | Err(ValidationError::ClefNeCorrespondPasAuVerrou)
        ),
        "attendu immature ou mauvaise clef, obtenu {r:?}"
    );
}

#[test]
fn la_chaine_se_rejoue_a_l_identique() {
    let mut w = Wallet::from_seed([0xcc; 32], RESEAU);
    let _ = w.new_address();
    let g = genesis_block(RESEAU);

    let mut blocs = Vec::new();
    let mut c1 = Chain::new(RESEAU, g.clone());
    for i in 1..=20u64 {
        let a = w.new_address();
        let t = horodatage(i);
        let b = c1
            .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
            .unwrap();
        c1.connect(&b, t + 1).unwrap();
        blocs.push(b);
    }

    // Un second noeud rejoue les memes blocs et doit aboutir au meme etat.
    let mut c2 = Chain::new(RESEAU, g);
    for b in &blocs {
        c2.connect(b, b.header.time + 1).expect("rejeu refuse");
    }

    assert_eq!(c1.tip_id(), c2.tip_id());
    assert_eq!(c1.utxo.total_value(), c2.utxo.total_value());
    assert_eq!(c1.utxo.len(), c2.utxo.len());
    assert_eq!(c1.total_issued(), c2.total_issued());
}

#[test]
fn defaire_puis_refaire_redonne_le_meme_etat() {
    let mut w = Wallet::from_seed([0xdd; 32], RESEAU);
    let mut c = chaine_avec_fonds(&mut w, 30);

    let id_avant = c.tip_id();
    let masse_avant = c.utxo.total_value();
    let emis_avant = c.total_issued();

    let h = c.height() + 1;
    let t = horodatage(h);
    let a = w.new_address();
    let b = c
        .mine_block(a.hash, SchemeId::LamportOts, &[], t, ESSAIS)
        .unwrap();
    c.connect(&b, t + 1).unwrap();

    assert!(c.disconnect());
    assert_eq!(c.tip_id(), id_avant);
    assert_eq!(c.utxo.total_value(), masse_avant);

    // On rebranche exactement le meme bloc.
    c.connect(&b, t + 1).expect("reconnexion refusee");
    assert!(c.total_issued().units() > emis_avant.units());
}

#[test]
fn le_temoin_domine_la_taille_des_transactions() {
    // Traduction chiffree du probleme de dimensionnement de la section 7.
    let mut w = Wallet::from_seed([0xee; 32], RESEAU);
    let c = chaine_avec_fonds(&mut w, COINBASE_MATURITY + 5);
    let mut dest = Wallet::from_seed([0xef; 32], RESEAU);
    let a = dest.new_address();

    let tx = w
        .create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(1_000),
            Amount::ZERO,
        )
        .unwrap();

    let complet = tx.encode().len();
    let corps = tx.encode_without_witness().len();
    let temoin = complet - corps;

    assert!(
        temoin > corps * 50,
        "temoin {temoin} o contre corps {corps} o : le rapport attendu n'y est pas"
    );

    // Le witness discount doit reellement changer le poids facture.
    assert!(tx.weight(WITNESS_DISCOUNT) > tx.weight(1));
}

// ===========================================================================
// Reorganisations : ce qu'un attaquant majoritaire peut, et ne peut pas
// ===========================================================================

use q21_core::chain::{Accept, ChainError};

/// Construit une branche concurrente partant du meme bloc de genese.
///
/// Rend les blocs dans l'ordre, prets a etre soumis a la chaine principale.
fn branche_concurrente(
    genese: &q21_core::block::Block,
    n: u64,
    mineur: u8,
) -> Vec<q21_core::block::Block> {
    let mut c = Chain::new(RESEAU, genese.clone());
    let mut blocs = Vec::new();
    for i in 1..=n {
        // Horodatages decales : deux branches distinctes, donc deux blocs
        // differents a la meme hauteur.
        let t = horodatage(i) + mineur as u64;
        let b = c
            .mine_block(
                q21_core::hash::Hash256([mineur; 32]),
                SchemeId::LamportOts,
                &[],
                t,
                ESSAIS,
            )
            .expect("minage de la branche");
        c.connect(&b, t + 1).expect("connexion de la branche");
        blocs.push(b);
    }
    blocs
}

#[test]
fn une_branche_plus_travaillee_provoque_une_reorganisation() {
    let mut w = Wallet::from_seed([0x51; 32], RESEAU);
    let _ = w.new_address();
    let genese = genesis_block(RESEAU);
    let mut c = Chain::new(RESEAU, genese.clone());

    // Chaine honnete : trois blocs.
    for b in branche_concurrente(&genese, 3, 0x11) {
        c.submit(&b, b.header.time + 1).expect("branche honnete");
    }
    let tete_honnete = c.tip_id();
    assert_eq!(c.height(), 3);

    // Branche concurrente : cinq blocs, donc plus de travail cumule.
    let attaque = branche_concurrente(&genese, 5, 0x22);
    let mut resultats = Vec::new();
    for b in &attaque {
        resultats.push(c.submit(b, b.header.time + 100_000).expect("soumission"));
    }

    assert_ne!(c.tip_id(), tete_honnete, "la chaine aurait du basculer");
    assert_eq!(c.height(), 5);
    assert!(
        resultats
            .iter()
            .any(|r| matches!(r, Accept::Reorganise { .. })),
        "une reorganisation aurait du etre signalee : {resultats:?}"
    );
}

#[test]
fn une_branche_moins_travaillee_ne_bascule_pas() {
    let mut w = Wallet::from_seed([0x52; 32], RESEAU);
    let _ = w.new_address();
    let genese = genesis_block(RESEAU);
    let mut c = Chain::new(RESEAU, genese.clone());

    for b in branche_concurrente(&genese, 5, 0x11) {
        c.submit(&b, b.header.time + 1).expect("branche honnete");
    }
    let tete = c.tip_id();

    // Deux blocs seulement : moins de travail, donc aucune bascule.
    for b in branche_concurrente(&genese, 2, 0x22) {
        let r = c.submit(&b, b.header.time + 100_000).expect("soumission");
        assert_eq!(r, Accept::BrancheLaterale);
    }
    assert_eq!(c.tip_id(), tete, "la tete n'aurait pas du bouger");
    assert_eq!(c.height(), 5);
}

/// La demonstration honnete : un attaquant majoritaire **peut** annuler une
/// transaction recente. C'est la limite theorique du modele, pas un defaut de
/// l'implementation.
#[test]
fn un_attaquant_majoritaire_peut_annuler_une_transaction_recente() {
    let mut w = Wallet::from_seed([0x53; 32], RESEAU);
    let _ = w.new_address();
    let genese = genesis_block(RESEAU);
    let mut c = Chain::new(RESEAU, genese.clone());

    for b in branche_concurrente(&genese, 3, 0x11) {
        c.submit(&b, b.header.time + 1).expect("branche honnete");
    }
    let hauteur_avant = c.height();

    // L'attaquant produit une branche plus longue, qui ne contient pas les
    // blocs honnetes — donc aucune des transactions qu'ils portaient.
    for b in branche_concurrente(&genese, 6, 0x22) {
        let _ = c.submit(&b, b.header.time + 100_000);
    }

    assert!(c.height() > hauteur_avant);
    // L'histoire recente a bien ete reecrite. C'est ce que la finalite
    // glissante borne, sans pouvoir l'empecher en faible profondeur.
}

/// Et la contrepartie rassurante : meme en reorganisant, il ne cree pas un
/// centieme de Q21 de plus que son du.
#[test]
fn meme_en_reorganisant_l_attaquant_ne_cree_pas_de_monnaie() {
    let mut w = Wallet::from_seed([0x54; 32], RESEAU);
    let _ = w.new_address();
    let genese = genesis_block(RESEAU);
    let mut c = Chain::new(RESEAU, genese.clone());

    for b in branche_concurrente(&genese, 3, 0x11) {
        c.submit(&b, b.header.time + 1).expect("branche honnete");
    }
    for b in branche_concurrente(&genese, 7, 0x22) {
        let _ = c.submit(&b, b.header.time + 100_000);
    }

    let theorique = emission::total_supply_at(c.height()).units();
    assert_eq!(
        c.total_issued().units(),
        theorique,
        "une reorganisation ne doit jamais deregler l'emission"
    );
    assert_eq!(c.utxo.total_value().units(), theorique);
    assert!(c.total_issued().units() <= MAX_SUPPLY);
}

#[test]
fn une_reorganisation_plus_profonde_que_la_finalite_est_refusee() {
    let mut w = Wallet::from_seed([0x55; 32], RESEAU);
    let _ = w.new_address();
    let genese = genesis_block(RESEAU);
    let mut c = Chain::new(RESEAU, genese.clone());

    let profondeur = MAX_REORG_DEPTH + 5;
    for b in branche_concurrente(&genese, profondeur, 0x11) {
        c.submit(&b, b.header.time + 1).expect("branche honnete");
    }
    let tete = c.tip_id();
    let hauteur = c.height();

    // L'attaquant repart de la genese avec davantage de travail. La regle de
    // finalite glissante doit l'arreter, quel que soit son travail cumule.
    // Deux refus possibles, et ils disent deux choses differentes :
    //
    // - `FinaliteDepassee` : on a trouve l'ancetre commun, et la bascule
    //   demandee est trop profonde.
    // - `PointDeForkIntrouvable` : l'ancetre commun est si loin qu'on ne le
    //   cherche meme plus. C'est le cas ici, la fourche etant a la genese.
    //
    // Le second se nommait autrefois `FinaliteDepassee { profondeur: u64::MAX }`
    // — un aveu d'ignorance deguise en mesure, qui a deja coute un diagnostic.
    let attaque = branche_concurrente(&genese, profondeur + 10, 0x22);
    let mut refus = false;
    for b in &attaque {
        match c.submit(b, b.header.time + 100_000) {
            Err(ChainError::FinaliteDepassee { profondeur, .. }) => {
                assert!(
                    profondeur < u64::MAX,
                    "une profondeur annoncee doit etre une vraie profondeur"
                );
                refus = true;
                break;
            }
            Err(ChainError::PointDeForkIntrouvable { .. }) => {
                refus = true;
                break;
            }
            _ => continue,
        }
    }

    assert!(refus, "la finalite glissante aurait du refuser la bascule");
    assert_eq!(c.tip_id(), tete, "la tete ne doit pas avoir bouge");
    assert_eq!(c.height(), hauteur);
}
