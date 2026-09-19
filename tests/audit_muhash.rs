//! Audit — l'engagement MuHash sur le jeu d'UTXO.
//!
//! Ces epreuves verrouillent le primitif et son cablage de bout en bout : que
//! l'empreinte ne depende que de l'etat de la monnaie et pas du chemin par lequel
//! on y arrive, qu'un instantane la transporte fidelement, et surtout qu'un noeud
//! qui **adopte** un instantane atteigne exactement le meme etat engage qu'un
//! noeud qui a tout revalide. C'est cette derniere egalite qui autorise la
//! synchronisation rapide : sans elle, adopter un instantane serait un pari.

use q21_core::block::Block;
use q21_core::chain::{genesis_block, AdoptionError, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::sig::SchemeId;
use q21_core::state::{Snapshot, StateStore};
use q21_core::store::{BlockArchive, BlockStore};
use q21_core::Network;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const RESEAU: Network = Network::Regtest;
const ESSAIS: u64 = 50_000_000;

fn horodatage(h: u64) -> u64 {
    GENESIS_TIME + h * TARGET_BLOCK_SECS
}

fn rep(nom: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("q21-audit-muhash-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Mine `n` blocs, les ecrit dans une archive sur disque — comme le fait le
/// binaire — et rend la chaine, l'archive (source de corps pour un noeud repris)
/// et la suite des blocs, de la genese au dernier.
fn chaine_minee(dir: &Path, n: u64) -> (Chain, Arc<BlockArchive>, Vec<Block>) {
    let chemin = dir.join("blocks.dat");
    let g = genesis_block(RESEAU);
    let store = BlockStore::new(&chemin);
    store.append(&g).unwrap();
    let (archive, _, _) = BlockArchive::open(&chemin, RESEAU).unwrap();
    let archive = Arc::new(archive);

    let mut c = Chain::new(RESEAU, g.clone());
    c.set_body_source(archive.clone());
    let mut blocs = vec![g];
    for i in 1..=n {
        let t = horodatage(i);
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, ESSAIS)
            .expect("minage");
        c.connect(&b, t + 1).expect("connexion");
        archive.append(&b).unwrap();
        blocs.push(b);
    }
    (c, archive, blocs)
}

/// L'empreinte de la genese de regtest est un vecteur fige.
///
/// Ce test ne verifie pas une propriete, il **grave un nombre**. Toute la chaine
/// de calcul y passe : le format de la piece serialisee, l'expansion en 3072
/// bits, la reduction modulaire, le condensat final. Si l'un de ces maillons
/// change — un octet d'ordre dans la piece, un tag de domaine — ce nombre change,
/// et deux versions du logiciel cessent de s'accorder sur l'etat. Le figer, c'est
/// interdire ce glissement en silence.
#[test]
fn l_empreinte_de_la_genese_regtest_est_figee() {
    let c = Chain::new(RESEAU, genesis_block(RESEAU));
    assert_eq!(
        c.utxo_commitment().to_hex(),
        "273ba98d5d672994e3542c9c2e454fd0d4c9917488191d75c02161f45ffa8bba",
        "l'empreinte de la genese a change : le format de la piece ou le MuHash \
         a bouge, et deux versions ne s'accorderont plus sur l'etat"
    );
}

/// L'empreinte ne depend que de la suite de blocs, pas de la maniere de la
/// rejouer. Un noeud qui reconstruit sa chaine bloc par bloc retrouve
/// exactement l'empreinte d'un noeud qui l'a minee.
#[test]
fn l_empreinte_ne_depend_que_de_l_etat() {
    let (a, _ar, blocs) = chaine_minee(&rep("etat"), 12);

    let mut b = Chain::new(RESEAU, blocs[0].clone());
    for (i, bloc) in blocs.iter().enumerate().skip(1) {
        b.connect(bloc, horodatage(i as u64) + 1).expect("rejeu");
    }

    assert_eq!(a.height(), b.height());
    assert_eq!(
        a.utxo_commitment(),
        b.utxo_commitment(),
        "deux chaines au meme etat doivent porter la meme empreinte"
    );
}

/// L'instantane pris en retrait de la tete porte une empreinte fidele a son
/// propre jeu d'UTXO : elle se recalcule et correspond.
#[test]
fn l_instantane_transporte_une_empreinte_fidele() {
    let (c, _ar, _) = chaine_minee(&rep("fidele"), 16);
    let s = c.snapshot().expect("instantane");
    assert_eq!(
        s.muhash,
        s.utxo.commitment(),
        "l'empreinte inscrite doit correspondre au jeu qu'elle accompagne"
    );
}

/// Le cœur de la synchronisation rapide : un noeud qui **adopte** un instantane,
/// puis rejoue la courte fenetre qui le separe de la tete, atteint exactement le
/// meme etat engage qu'un noeud qui a tout revalide depuis la genese.
///
/// Sans cette egalite, adopter un instantane reviendrait a repartir d'un etat
/// dont on ne pourrait plus prouver qu'il est le bon. Avec elle, l'empreinte du
/// noeud repris se confronte a celle qu'annonce n'importe quel pair synchronise :
/// si elles s'accordent, le raccourci n'a rien coute a la verite.
#[test]
fn un_noeud_qui_adopte_l_instantane_atteint_le_meme_etat() {
    let (complet, archive, blocs) = chaine_minee(&rep("adopte"), 20);
    let s = complet.snapshot().expect("instantane");
    let hauteur_instantane = s.height;
    assert!(hauteur_instantane < complet.height(), "pris en retrait");

    let reprise = Chain::from_snapshot(RESEAU, s, &complet.headers())
        .unwrap_or_else(|e| panic!("reprise refusee : {e:?}"));
    let mut repris = reprise.chain;
    repris.set_body_source(archive.clone());
    // Rejoue la fenetre restante, bloc par bloc, comme le ferait un noeud au
    // demarrage.
    for id in &reprise.a_rejouer {
        let bloc = blocs
            .iter()
            .find(|b| b.header.block_id() == *id)
            .expect("le bloc a rejouer est connu");
        repris
            .connect(bloc, horodatage(bloc.header.height) + 1)
            .expect("rejeu de la fenetre");
    }

    assert_eq!(repris.height(), complet.height(), "meme tete atteinte");
    assert_eq!(
        repris.utxo_commitment(),
        complet.utxo_commitment(),
        "le noeud repris et le noeud complet doivent porter la MEME empreinte"
    );
}

/// Adoption ancree : avec la bonne tete et la bonne empreinte de confiance, un
/// noeud adopte l'instantane, rejoue la fenetre, et atteint le meme etat qu'un
/// noeud complet. C'est la passe B2 posee sur la B1 : l'assumeutxo de Q21.
#[test]
fn adopter_avec_les_bonnes_valeurs_atteint_le_meme_etat() {
    let (complet, archive, blocs) = chaine_minee(&rep("adopt-ok"), 20);
    let s = complet.snapshot().expect("instantane");
    let tete = s.tip;
    let empreinte = s.empreinte();

    let reprise = Chain::adopter_instantane(RESEAU, s, &complet.headers(), tete, empreinte)
        .unwrap_or_else(|e| panic!("adoption refusee : {e:?}"));
    let mut repris = reprise.chain;
    repris.set_body_source(archive.clone());
    for id in &reprise.a_rejouer {
        let bloc = blocs
            .iter()
            .find(|b| b.header.block_id() == *id)
            .expect("bloc a rejouer connu");
        repris
            .connect(bloc, horodatage(bloc.header.height) + 1)
            .expect("rejeu");
    }

    assert_eq!(repris.height(), complet.height());
    assert_eq!(repris.utxo_commitment(), complet.utxo_commitment());
}

/// Une empreinte de confiance qui ne correspond pas fait refuser l'adoption —
/// meme si le fichier est, en lui-meme, parfaitement coherent.
#[test]
fn adopter_avec_une_mauvaise_empreinte_est_refuse() {
    let (complet, _ar, _) = chaine_minee(&rep("adopt-emp"), 12);
    let s = complet.snapshot().expect("instantane");
    let tete = s.tip;
    let fausse = Hash256([0x99; 32]);
    assert!(matches!(
        Chain::adopter_instantane(RESEAU, s, &complet.headers(), tete, fausse),
        Err(AdoptionError::EmpreinteInattendue)
    ));
}

/// Une tete de confiance qui ne correspond pas fait refuser l'adoption.
#[test]
fn adopter_avec_une_mauvaise_tete_est_refuse() {
    let (complet, _ar, _) = chaine_minee(&rep("adopt-tete"), 12);
    let s = complet.snapshot().expect("instantane");
    let empreinte = s.empreinte();
    let fausse = Hash256([0x77; 32]);
    assert!(matches!(
        Chain::adopter_instantane(RESEAU, s, &complet.headers(), fausse, empreinte),
        Err(AdoptionError::TeteInattendue)
    ));
}

/// Des en-tetes qui ne menent pas a la tete de confiance — ici, aucun en-tete —
/// font refuser l'adoption : la tete n'est pas authentifiee.
#[test]
fn adopter_sans_entetes_authentifiants_est_refuse() {
    let (complet, _ar, _) = chaine_minee(&rep("adopt-hdr"), 12);
    let s = complet.snapshot().expect("instantane");
    let tete = s.tip;
    let empreinte = s.empreinte();
    assert!(matches!(
        Chain::adopter_instantane(RESEAU, s, &[], tete, empreinte),
        Err(AdoptionError::EntetesInauthentiques)
    ));
}

/// Un instantane sauvegarde puis relu conserve son empreinte, et le jeu relu la
/// reproduit. C'est la verification qu'un pair fera sur un fichier telecharge.
#[test]
fn un_instantane_relu_reste_verifiable() {
    let (c, _ar, _) = chaine_minee(&rep("relu"), 10);
    let s = c.snapshot().expect("instantane");

    let mut chemin = std::env::temp_dir();
    chemin.push(format!("q21-audit-muhash-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&chemin);
    let store = StateStore::new(&chemin);
    store.save(&s).expect("ecriture");

    let relu: Snapshot = store.load(RESEAU).expect("relecture");
    assert_eq!(relu.muhash, s.muhash, "l'empreinte survit au disque");
    assert_eq!(
        relu.utxo.commitment(),
        relu.muhash,
        "le jeu relu reproduit son empreinte"
    );
    let _ = std::fs::remove_file(&chemin);
}

/// Un instantane dont on a deplace la propriete d'une sortie — meme montant,
/// autre beneficiaire — porte une empreinte differente de celle de la chaine
/// honnete. Un pair qui compare a une valeur de confiance le voit donc, la ou le
/// seul controle d'emission le laissait passer.
#[test]
fn deplacer_une_sortie_ecarte_l_empreinte_de_la_valeur_honnete() {
    let (c, _ar, _) = chaine_minee(&rep("deplace"), 14);
    let honnete = c.utxo_commitment();

    let mut s = c.snapshot().expect("instantane");
    let honnete_a_cette_hauteur = s.utxo.commitment();

    // Le faussaire redirige une sortie vers lui.
    let cible = *s.utxo.iter().next().unwrap().0;
    let mut vole = *s.utxo.get(&cible).unwrap();
    vole.output.pubkey_hash = Hash256([0x99; 32]);
    s.utxo.remove(&cible);
    s.utxo.insert(cible, vole);

    let falsifiee = s.utxo.commitment();
    assert_ne!(
        falsifiee, honnete_a_cette_hauteur,
        "deplacer la propriete doit changer l'empreinte"
    );
    // Et elle ne peut pas non plus tomber par hasard sur l'empreinte de la tete.
    assert_ne!(falsifiee, honnete);
}
