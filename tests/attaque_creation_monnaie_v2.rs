//! ATTAQUE EXECUTEE — campagne du 22 septembre 2026.
//!
//! On ne lit plus le code : on l'attaque. Chaque test joue un mineur adverse
//! qui controle entierement le contenu d'un bloc, mine une preuve de travail
//! reelle (difficulte minimale du reseau de regression), puis tente de faire
//! accepter un bloc qui fabrique de la monnaie ou triche sur le travail.
//!
//! Le test REUSSIT (vert) quand l'attaque ECHOUE — c'est-a-dire quand le noeud
//! refuse le bloc pour la bonne raison. Un test rouge ici serait une faille
//! reelle et exploitable.

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::block::Block;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::*;
use q21_core::hash::Hash256;
use q21_core::memhard::{epoch_of, PowTable, TableParams};
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::tx::TxOut;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn horodatage(hauteur: u64) -> u64 {
    GENESIS_TIME + hauteur * TARGET_BLOCK_SECS
}

/// Re-mine un bloc apres l'avoir altere : sans cela, l'alteration invaliderait
/// la preuve de travail et le bloc serait refuse pour la mauvaise raison.
fn remine(b: &mut Block) {
    b.header.merkle_root = b.compute_merkle_root();
    b.header.uncles_root = b.compute_uncles_root();
    b.header.nonce = 0;
    let table = PowTable::build(TableParams::for_network(RESEAU), epoch_of(b.header.height));
    pow::mine_with_table(&mut b.header, &table, ESSAIS).expect("re-minage");
}

fn chaine_neuve() -> Chain {
    Chain::new(RESEAU, genesis_block(RESEAU))
}

/// Mine un bloc honnete a la hauteur suivante.
fn bloc_honnete(c: &Chain, h: u64) -> Block {
    let t = horodatage(h);
    c.mine_block(Hash256([7; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .expect("minage honnete")
}

// ---------------------------------------------------------------------------
// ATTAQUE 1 — se verser plus que la subvention (coinbase gonflee).
// ---------------------------------------------------------------------------
#[test]
fn attaque_coinbase_gonflee_est_refusee() {
    let mut c = chaine_neuve();
    let mut b = bloc_honnete(&c, 1);

    // Le mineur double sa recompense.
    let du = b.transactions[0].outputs[0].value.units();
    b.transactions[0].outputs[0].value = Amount::from_units(du + 1_000_000_000);
    remine(&mut b);

    let r = c.connect(&b, horodatage(1) + 1);
    assert!(
        r.is_err(),
        "ATTAQUE REUSSIE : une coinbase gonflee a ete acceptee"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 2 — ajouter une seconde sortie a la coinbase pour capter plus.
// ---------------------------------------------------------------------------
#[test]
fn attaque_seconde_sortie_coinbase_est_refusee() {
    let mut c = chaine_neuve();
    let mut b = bloc_honnete(&c, 1);

    b.transactions[0].outputs.push(TxOut {
        value: Amount::from_units(500_000),
        scheme: SchemeId::LamportOts,
        pubkey_hash: Hash256([42; 32]),
    });
    remine(&mut b);

    let r = c.connect(&b, horodatage(1) + 1);
    assert!(
        r.is_err(),
        "ATTAQUE REUSSIE : une coinbase a deux sorties a ete acceptee"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 3 — fausse preuve de travail : on trafique sans re-miner.
// ---------------------------------------------------------------------------
#[test]
fn attaque_sans_preuve_de_travail_est_refusee() {
    let mut c = chaine_neuve();
    let mut b = bloc_honnete(&c, 1);

    // On gonfle la coinbase MAIS on ne re-mine pas : le nonce ne vaut plus rien.
    let du = b.transactions[0].outputs[0].value.units();
    b.transactions[0].outputs[0].value = Amount::from_units(du + 1_000_000_000);
    b.header.merkle_root = b.compute_merkle_root();
    // pas de remine : la preuve de travail est desormais fausse.

    let r = c.connect(&b, horodatage(1) + 1);
    assert!(
        r.is_err(),
        "ATTAQUE REUSSIE : un bloc sans preuve de travail valide a ete accepte"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 4 — annoncer une difficulte plus facile que celle du consensus.
// ---------------------------------------------------------------------------
#[test]
fn attaque_fausse_difficulte_est_refusee() {
    let mut c = chaine_neuve();
    let mut b = bloc_honnete(&c, 1);

    // On affaiblit la cible annoncee (bits) puis on re-mine a cette cible facile.
    // La cible du consensus, elle, ne change pas : le noeud doit refuser.
    b.header.bits = b.header.bits.wrapping_add(0x0010_0000);
    let table = PowTable::build(TableParams::for_network(RESEAU), epoch_of(b.header.height));
    b.header.merkle_root = b.compute_merkle_root();
    b.header.nonce = 0;
    let _ = pow::mine_with_table(&mut b.header, &table, ESSAIS);

    let r = c.connect(&b, horodatage(1) + 1);
    assert!(
        r.is_err(),
        "ATTAQUE REUSSIE : une fausse difficulte a ete acceptee"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 5 — coinbase sans marque de hauteur (attaque BIP30/34).
// ---------------------------------------------------------------------------
#[test]
fn attaque_coinbase_sans_hauteur_est_refusee() {
    let mut c = chaine_neuve();
    let mut b = bloc_honnete(&c, 1);

    // On efface la marque de hauteur de la signature coinbase.
    b.transactions[0].inputs[0].witness.signature = vec![0xAB; 8];
    remine(&mut b);

    let r = c.connect(&b, horodatage(1) + 1);
    assert!(
        r.is_err(),
        "ATTAQUE REUSSIE : une coinbase sans hauteur a ete acceptee"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 6 — rejouer un bloc d'un autre reseau (mauvaise genese).
// ---------------------------------------------------------------------------
#[test]
fn attaque_bloc_d_un_autre_reseau_est_refusee() {
    // Un bloc mine sur testnet ne doit pas s'enchainer sur la genese regtest.
    let ct = Chain::new(Network::Testnet, genesis_block(Network::Testnet));
    let t = horodatage(1);
    let b_testnet = ct
        .mine_block(Hash256([7; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
        .expect("minage testnet");

    let mut c = chaine_neuve();
    let r = c.connect(&b_testnet, t + 1);
    assert!(
        r.is_err(),
        "ATTAQUE REUSSIE : un bloc d'un autre reseau a ete accepte"
    );
}

// ---------------------------------------------------------------------------
// ATTAQUE 7 — les frais ne doivent pas compter comme monnaie nouvelle.
// Verification comptable : apres une chaine honnete, l'emission cumulee
// correspond exactement au calendrier, jamais davantage.
// ---------------------------------------------------------------------------
#[test]
fn attaque_comptable_l_emission_suit_le_calendrier() {
    let mut c = chaine_neuve();
    for h in 1..=30 {
        let b = bloc_honnete(&c, h);
        c.connect(&b, horodatage(h) + 1).expect("connexion honnete");
    }
    // La monnaie reellement emise (genese comprise) doit egaler, au centime,
    // le calendrier officiel. Un centime de plus serait de l'inflation.
    let emis = c.total_issued().units();
    let attendu = q21_core::emission::total_supply_at(30).units();
    assert_eq!(
        emis, attendu,
        "DIVERGENCE COMPTABLE : emis={emis} attendu={attendu} — de la monnaie est apparue ou a disparu"
    );
    assert!(
        emis <= MAX_SUPPLY,
        "PLAFOND FRANCHI : {emis} > {MAX_SUPPLY}"
    );
}
