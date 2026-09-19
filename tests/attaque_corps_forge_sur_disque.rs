//! ATTAQUE (red-team 8b, 2e campagne, point 5) — un corps forge sur le disque.
//!
//! Le fichier des blocs n'etait relu qu'en le decodant : des octets qui
//! forment un bloc etaient rendus comme **le** bloc demande, sans qu'on ait
//! confronte le corps a son en-tete. Deux voies y menaient :
//!
//! - l'adoption d'un instantane **par dossier** copiait `corps.dat` tel quel,
//!   la ou la voie reseau verifiait chaque corps avant d'ecrire un octet ;
//! - la relecture par l'archive (`BlockArchive::read`) rendait n'importe quel
//!   corps decodable, racine de Merkle fausse ou liste d'oncles inventee
//!   comprise.
//!
//! Un dossier fourni par un tiers pouvait donc figer un noeud sur une fausse
//! branche jusqu'a ce qu'on l'efface. Desormais : un corps relu doit porter
//! l'identifiant demande ET une forme juste, sinon il vaut « absent » ; et la
//! voie dossier verifie les corps comme la voie reseau.

use q21_core::block::BlockHeader;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::store::{BlockArchive, BlockStore, HeaderStore};
use q21_core::synchro_rapide::Amorce;
use q21_core::Network;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn q21() -> &'static str {
    env!("CARGO_BIN_EXE_q21")
}

fn rep(nom: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-attaque-corps-{nom}-{}", std::process::id()));
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
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
        archive.append(&b).unwrap();
    }
    (c, archive)
}

/// Un oncle invente : un en-tete quelconque, jamais mine.
fn oncle_invente(parent: &BlockHeader) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: parent.prev_block,
        merkle_root: Hash256([0x42; 32]),
        uncles_root: Hash256::ZERO,
        miner: Hash256([0x66; 32]),
        time: parent.time,
        bits: parent.bits,
        height: parent.height,
        nonce: 0xdead_beef,
    }
}

/// L'archive ne rend plus un corps dont la forme ne correspond pas a son
/// en-tete : il vaut « absent », et sera redemande au reseau.
#[test]
fn l_archive_refuse_un_corps_dont_la_forme_ne_correspond_pas_a_l_en_tete() {
    let dir = rep("archive");
    let (chain, _archive) = chaine_minee(&dir, 5);

    // Le fichier de l'attaquant : les memes blocs, sauf le 3e, dont le corps
    // porte un oncle que l'en-tete (inchange) n'engage pas.
    let chemin = dir.join("forge.dat");
    let bs = BlockStore::new(&chemin);
    let mut forge_id = None;
    for h in 0..=5u64 {
        let mut b = chain.block_at(h).expect("corps");
        if h == 3 {
            b.uncles.push(oncle_invente(&b.header));
            forge_id = Some(b.header.block_id());
            assert!(
                b.check_shape().is_err(),
                "le corps forge doit contredire son en-tete"
            );
        }
        bs.append(&b).unwrap();
    }
    let forge_id = forge_id.unwrap();

    let (archive, entetes, souci) = BlockArchive::open(&chemin, RESEAU).expect("ouverture");
    assert!(
        souci.is_none(),
        "le fichier forge se balaie sans incident : {souci:?}"
    );
    assert_eq!(entetes.len(), 6, "les six en-tetes sont indexes");

    // Les corps honnetes se relisent ; le corps forge vaut « absent ».
    for h in [0u64, 1, 2, 4, 5] {
        let id = chain.block_at(h).unwrap().header.block_id();
        assert!(
            archive.read(&id).is_some(),
            "le corps honnete {h} doit se relire"
        );
    }
    assert!(
        archive.read(&forge_id).is_none(),
        "un corps dont la forme contredit son en-tete ne doit jamais etre rendu"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Ecrit un dossier d'amorce comme `q21 instantane creer` le ferait, avec un
/// `corps.dat` laisse au choix de l'appelant.
fn dossier_amorce(dir: &Path, amorce: &Amorce, corps: &[q21_core::block::Block]) -> PathBuf {
    let d = dir.join("amorce");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("instantane.q21snap"), &amorce.instantane).unwrap();
    let hs = HeaderStore::new(d.join("entetes.q21hdr"));
    hs.append(&amorce.entetes).unwrap();
    let bs = BlockStore::new(d.join("corps.dat"));
    for b in corps {
        bs.append(b).unwrap();
    }
    d
}

fn adopter(
    datadir: &Path,
    dossier: &Path,
    tete: Hash256,
    empreinte: Hash256,
) -> std::process::Output {
    Command::new(q21())
        .arg("--datadir")
        .arg(datadir)
        .args(["instantane", "adopter"])
        .arg(dossier)
        .args(["--tete", &tete.to_hex(), "--empreinte", &empreinte.to_hex()])
        .stdin(Stdio::null())
        .output()
        .expect("lancement de q21")
}

/// L'adoption par dossier verifie les corps comme la voie reseau : un dossier
/// aux corps forges est refuse avant d'ecrire un octet, et un dossier honnete
/// s'adopte toujours.
#[test]
fn l_adoption_par_dossier_refuse_des_corps_forges() {
    let dir = rep("adopter");
    let (chain, _archive) = chaine_minee(&dir, 20);
    // L'amorce telle que `q21 instantane creer` la compose : l'instantane en
    // retrait de la tete, tous les en-tetes jusqu'a lui, la genese puis la
    // fenetre de corps autour de lui.
    let instantane = chain.snapshot_at_depth(5).expect("instantane");
    let hauteur = instantane.height;
    assert!(hauteur >= 10, "l'instantane doit etre loin de la genese");
    let entetes = chain.headers()[..=hauteur as usize].to_vec();
    let mut corps = vec![chain.block_at(0).unwrap()];
    for hh in (hauteur - 9)..=hauteur {
        corps.push(chain.block_at(hh).unwrap());
    }
    let amorce = Amorce {
        instantane: instantane.to_portable_bytes(),
        entetes,
        corps,
    };
    let empreinte = amorce.empreinte_annoncee().expect("empreinte");
    let tete = amorce.entetes.last().unwrap().block_id();

    // --- L'attaque : les vrais en-tetes, le vrai instantane, un corps forge.
    let mut forges = amorce.corps.clone();
    let cible = forges
        .iter_mut()
        .find(|b| b.header.height == hauteur)
        .expect("le corps de la tete est dans la fenetre");
    cible.uncles.push(oncle_invente(&cible.header));
    let dossier = dossier_amorce(&dir.join("hostile"), &amorce, &forges);
    let datadir = dir.join("noeud-hostile");
    let sortie = adopter(&datadir, &dossier, tete, empreinte);
    let stderr = String::from_utf8_lossy(&sortie.stderr);
    let stdout = String::from_utf8_lossy(&sortie.stdout);
    eprintln!(
        "hostile : statut {:?}\n{stdout}{stderr}",
        sortie.status.code()
    );
    assert!(
        !sortie.status.success(),
        "un dossier aux corps forges doit etre refuse"
    );
    assert!(
        format!("{stdout}{stderr}").contains("adoption refusee"),
        "le refus doit etre dit comme tel"
    );
    assert!(
        !datadir.join("blocks.dat").exists(),
        "rien ne doit avoir ete ecrit dans le dossier du noeud"
    );

    // --- Le temoin : le meme dossier, aux corps intacts, s'adopte.
    let dossier = dossier_amorce(&dir.join("honnete"), &amorce, &amorce.corps);
    let datadir = dir.join("noeud-honnete");
    let sortie = adopter(&datadir, &dossier, tete, empreinte);
    let stderr = String::from_utf8_lossy(&sortie.stderr);
    let stdout = String::from_utf8_lossy(&sortie.stdout);
    eprintln!(
        "honnete : statut {:?}\n{stdout}{stderr}",
        sortie.status.code()
    );
    assert!(
        sortie.status.success(),
        "un dossier honnete doit toujours s'adopter"
    );
    assert!(
        datadir.join("blocks.dat").exists(),
        "les corps honnetes doivent avoir ete poses"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
