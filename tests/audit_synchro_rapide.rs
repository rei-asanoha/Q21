//! Audit — synchronisation rapide par amorce, de pair a pair.
//!
//! On lance un vrai noeud qui ecoute, et un client qui telecharge son amorce
//! par le reseau, exactement comme un nouveau venu le ferait. On verifie que le
//! paquet arrive fidele, que l'empreinte est le seul juge de la confiance, et
//! qu'un pair qui n'annonce pas l'empreinte attendue est ecarte sans rien
//! adopter.

use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::net::{magic_for, Node};
use q21_core::sig::SchemeId;
use q21_core::store::{BlockArchive, BlockStore};
use q21_core::synchro_rapide;
use q21_core::Network;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn horodatage(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn rep(nom: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-audit-synchro-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn chaine_minee(dir: &Path, n: u64) -> (Chain, Arc<BlockArchive>) {
    let chemin = dir.join("blocks.dat");
    let g = genesis_block(RESEAU);
    BlockStore::new(&chemin).append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&chemin, RESEAU).unwrap();
    let archive = Arc::new(archive);

    let mut c = Chain::new(RESEAU, g);
    c.set_body_source(archive.clone());
    for i in 1..=n {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
        archive.append(&b).unwrap();
    }
    (c, archive)
}

/// Un pair sert une amorce, et le client la recoit fidele : octet pour octet, et
/// avec l'empreinte annoncee qui correspond a celle du paquet.
#[test]
fn un_pair_sert_une_amorce_fidele() {
    let dir = rep("fidele");
    let (chain, _archive) = chaine_minee(&dir, 20);

    // Ce que le serveur peut servir, calcule directement pour comparaison.
    let attendue = chain.construire_amorce().expect("amorce");
    let empreinte = attendue.empreinte_annoncee().unwrap();

    let node = Node::new(RESEAU, chain);
    let addr = node.listen("127.0.0.1:0").expect("ecoute");

    let recue = synchro_rapide::telecharger_amorce(
        addr,
        magic_for(RESEAU),
        0,
        empreinte,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .expect("telechargement");

    assert_eq!(
        recue, attendue,
        "l'amorce recue doit etre identique a la servie"
    );
    assert_eq!(recue.empreinte_annoncee(), Some(empreinte));
    assert!(!recue.entetes.is_empty());
    assert!(!recue.corps.is_empty());
}

/// L'empreinte est le seul juge : une valeur de confiance qui ne correspond pas
/// fait ecarter le pair, sans rien adopter.
#[test]
fn une_mauvaise_empreinte_fait_ecarter_le_pair() {
    let dir = rep("mauvaise");
    let (chain, _archive) = chaine_minee(&dir, 16);
    let node = Node::new(RESEAU, chain);
    let addr = node.listen("127.0.0.1:0").expect("ecoute");

    let fausse = Hash256([0x99; 32]);
    let r = synchro_rapide::telecharger_amorce(
        addr,
        magic_for(RESEAU),
        0,
        fausse,
        Duration::from_secs(5),
        Duration::from_secs(30),
    );
    assert!(
        r.is_err(),
        "une empreinte fausse doit faire echouer le telechargement"
    );
    let msg = r.err().unwrap();
    assert!(
        msg.contains("empreinte") || msg.contains("confiance"),
        "le refus doit nommer sa raison : {msg}"
    );
}

/// Le paquet recu par le reseau s'adopte : un noeud neuf en tire le meme etat
/// engage qu'un noeud complet. La boucle entiere, du fil a l'adoption.
#[test]
fn l_amorce_recue_par_le_reseau_s_adopte() {
    use q21_core::chain::AdoptionError;

    let dir = rep("adopte");
    let (chain, _archive) = chaine_minee(&dir, 20);
    let attendue = chain.construire_amorce().expect("amorce");
    let empreinte = attendue.empreinte_annoncee().unwrap();
    let tete = attendue.tete_annoncee().unwrap();

    let node = Node::new(RESEAU, chain);
    let addr = node.listen("127.0.0.1:0").expect("ecoute");

    let recue = synchro_rapide::telecharger_amorce(
        addr,
        magic_for(RESEAU),
        0,
        empreinte,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .expect("telechargement");

    // On adopte le paquet recu, ancre a l'empreinte et a la tete de confiance.
    let instantane = q21_core::state::Snapshot::from_portable_bytes(&recue.instantane, RESEAU)
        .expect("instantane");
    let r: Result<_, AdoptionError> =
        Chain::adopter_instantane(RESEAU, instantane, &recue.entetes, tete, empreinte);
    assert!(r.is_ok(), "l'amorce recue doit s'adopter : {:?}", r.err());
}
