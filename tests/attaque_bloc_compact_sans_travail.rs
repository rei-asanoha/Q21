//! ATTAQUE (red-team 8b, 2e campagne, point 4) — faire fouiller le reservoir
//! d'un noeud avec des blocs compacts qui ne portent aucun travail.
//!
//! Un bloc compact n'apporte que l'en-tete et des identifiants courts ; le
//! corps, c'est le noeud qui le reconstruit en fouillant son reservoir, sous le
//! verrou global. Cette reconstruction se faisait AVANT qu'on ait regarde si
//! l'en-tete portait un travail reel. Un pair presente, au parent connu, dans
//! son budget d'annonces, faisait donc fouiller le reservoir pour des en-tetes
//! fabriques sans miner.
//!
//! Correction : l'en-tete est verifie seul — hauteur, finalite, difficulte,
//! horodatage, travail — avant qu'un seul identifiant ne soit compare (BIP 152).
//! Un en-tete faux ne coute plus rien d'autre que sa lecture, et vaut au pair
//! la sanction d'un bloc invalide. Un en-tete vrai passe exactement comme avant.

use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::compact::CompactBlock;
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::net::{magic_for, Node, BAN_THRESHOLD, MISCONDUCT_BAD_BLOCK};
use q21_core::pow::{PowEngine, Q21Pow};
use q21_core::sig::SchemeId;
use q21_core::wire::{Message, PROTOCOL_VERSION};
use q21_core::Network;

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::Duration;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn presenter(s: &mut TcpStream, magie: [u8; 4], nonce: u64) {
    s.write_all(
        &Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 0,
            nonce,
            user_agent: "epreuve".into(),
            start_height: 0,
        }
        .frame(magie),
    )
    .expect("version");
    s.write_all(&Message::VerAck.frame(magie)).expect("verack");
    std::thread::sleep(Duration::from_millis(300));
}

/// Attend qu'un compteur atteigne `cible`, deux secondes au plus.
fn attendre(lire: impl Fn() -> u64, cible: u64) -> u64 {
    let debut = std::time::Instant::now();
    loop {
        let v = lire();
        if v >= cible || debut.elapsed() > Duration::from_secs(2) {
            return v;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn un_bloc_compact_sans_travail_n_est_jamais_reconstruit() {
    let node = Node::new(RESEAU, Chain::new(RESEAU, genesis_block(RESEAU)));
    let addr = node.listen("127.0.0.1:0").expect("ecoute");
    let magie = magic_for(RESEAU);

    // Un vrai bloc, mine : tout y est juste — parent, hauteur, difficulte,
    // horodatage, travail.
    let t = GENESIS_TIME + TARGET_BLOCK_SECS;
    let vrai = node
        .with_chain(|c| c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS))
        .expect("minage");
    let pow = Q21Pow::new(RESEAU);
    assert!(
        pow.check(&vrai.header).is_ok(),
        "le bloc mine doit porter son travail"
    );

    // Le meme en-tete, au nonce change jusqu'a ce que le travail soit FAUX :
    // tout le reste (parent, hauteur, difficulte, horodatage) reste juste, pour
    // que seul le travail puisse le faire refuser.
    let mut forge = vrai.header;
    forge.nonce = forge.nonce.wrapping_add(1);
    while pow.check(&forge).is_ok() {
        forge.nonce = forge.nonce.wrapping_add(1);
    }
    let compact_forge = CompactBlock {
        header: forge,
        ..CompactBlock::from_block(&vrai, 7)
    };

    let mut s = TcpStream::connect(addr).expect("connexion");
    presenter(&mut s, magie, 0xc0ff_ee04);

    // --- L'attaque : un en-tete sans travail, dans le budget d'annonces.
    s.write_all(&Message::CmpctBlock(Box::new(compact_forge)).frame(magie))
        .expect("cmpctblock forge");
    let refuses = attendre(
        || node.stats.compacts_entete_refuse.load(Ordering::Relaxed),
        1,
    );
    let reconstruits = node.stats.compacts_reconstruits.load(Ordering::Relaxed);
    let invalides = node.stats.blocs_invalides.load(Ordering::Relaxed);
    eprintln!(
        "forge : {refuses} en-tete(s) refuse(s) avant reconstruction, \
         {reconstruits} reconstruction(s) entamee(s), {invalides} bloc(s) invalide(s)"
    );
    assert_eq!(
        refuses, 1,
        "l'en-tete sans travail doit etre refuse avant toute reconstruction"
    );
    assert_eq!(
        reconstruits, 0,
        "aucune reconstruction ne doit etre entamee pour un en-tete faux"
    );
    assert_eq!(invalides, 1, "un en-tete faux vaut un bloc invalide");
    assert_eq!(node.height(), 0, "rien ne doit avoir ete rattache");
    // Une seule faute ne coupe pas encore : la sanction est celle d'un bloc
    // invalide, et le seuil demande plus d'une faute.
    const _: () = assert!(MISCONDUCT_BAD_BLOCK < BAN_THRESHOLD);
    assert_eq!(node.peer_count(), 1, "une seule faute ne coupe pas encore");

    // --- Le vrai bloc, par le meme pair : rien n'a change pour lui.
    let compact_vrai = CompactBlock::from_block(&vrai, 7);
    s.write_all(&Message::CmpctBlock(Box::new(compact_vrai)).frame(magie))
        .expect("cmpctblock vrai");
    let reconstruits = attendre(
        || node.stats.compacts_reconstruits.load(Ordering::Relaxed),
        1,
    );
    let hauteur = attendre(|| node.height(), 1);
    eprintln!("vrai : {reconstruits} reconstruction(s), hauteur {hauteur}");
    assert_eq!(
        reconstruits, 1,
        "un en-tete au travail juste doit etre reconstruit"
    );
    assert_eq!(hauteur, 1, "le vrai bloc doit etre rattache");
    assert_eq!(
        node.stats.compacts_entete_refuse.load(Ordering::Relaxed),
        1,
        "le vrai bloc ne doit pas etre compte comme refuse"
    );

    // --- L'insistance coupe : une seconde faute franchit le seuil.
    let mut forge2 = forge;
    forge2.nonce = forge2.nonce.wrapping_add(1);
    forge2.time = t + 1;
    while pow.check(&forge2).is_ok() {
        forge2.nonce = forge2.nonce.wrapping_add(1);
    }
    // Sur la genese encore : la tete a avance, mais la genese reste un parent
    // connu a portee de finalite.
    let compact_forge2 = CompactBlock {
        header: forge2,
        ..CompactBlock::from_block(&vrai, 7)
    };
    s.write_all(&Message::CmpctBlock(Box::new(compact_forge2)).frame(magie))
        .expect("cmpctblock forge 2");
    let mut restants = node.peer_count();
    for _ in 0..40 {
        if restants == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        restants = node.peer_count();
    }
    assert_eq!(restants, 0, "deux en-tetes faux doivent couper le pair");
    assert_eq!(
        node.stats.compacts_reconstruits.load(Ordering::Relaxed),
        1,
        "toujours une seule reconstruction : celle du vrai bloc"
    );
    node.shutdown();
}
