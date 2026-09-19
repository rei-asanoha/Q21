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

/// Une chaine d'en-tetes **fabriquee**, sans le moindre travail, ne doit pas
/// etre adoptee — meme si tous les ancrages « correspondent ».
///
/// # L'attaque, telle qu'elle etait possible
///
/// L'adoption verifiait trois choses : l'empreinte egale la valeur de confiance,
/// la tete egale la tete de confiance, et les en-tetes menent structurellement
/// de cette tete a la vraie genese. Le raisonnement etait qu'un enchainement
/// jusqu'a la tete authentifie toute la chaine.
///
/// Il prouve que les ancetres sont authentiques *etant donne que la tete l'est*.
/// Or la tete ne vient que d'une chaine hexadecimale recopiee par l'operateur.
/// Qui la controle — explorateur usurpe, interception, miroir malveillant, faute
/// de frappe — fabrique une chaine d'en-tetes coherente **sans aucun calcul**,
/// se terminant sur sa propre tete, et fournit ses propres valeurs de confiance.
/// Les trois controles passaient. Le noeud adoptait un etat invente, pour un
/// cout d'attaque nul.
///
/// La preuve de travail est la seule chose verifiable sans faire confiance a
/// personne. On la reverifie donc, et l'attaque cesse d'etre gratuite.
#[test]
fn une_chaine_d_entetes_fabriquee_n_est_pas_adoptee() {
    use q21_core::block::BlockHeader;
    use q21_core::chain::AdoptionError;

    let dir = rep("fabriquee");
    let (chain, _archive) = chaine_minee(&dir, 30);
    // Recul d'un seul bloc : l'instantane est haut, donc la chaine que
    // l'attaquant doit fabriquer est longue. Avec un instantane « en retrait »
    // complet elle ne ferait qu'un en-tete, et un unique en-tete non mine passe
    // la cible tres permissive du reseau de regression une fois sur 256 — le
    // test ne prouverait alors rien.
    let instantane_honnete = chain.snapshot_at_depth(1).expect("instantane");
    assert!(
        instantane_honnete.height >= 25,
        "la chaine fabriquee doit etre assez longue pour que le controle morde"
    );

    // L'attaquant part de la vraie genese — sinon le controle de genese le
    // demasque immediatement — puis empile des en-tetes sans miner.
    let genese = genesis_block(RESEAU);
    let mut entetes: Vec<BlockHeader> = vec![genese.header];
    let mut prev = genese.header.block_id();
    for h in 1..=instantane_honnete.height {
        let e = BlockHeader {
            version: 1,
            prev_block: prev,
            merkle_root: Hash256([0x11; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([0x66; 32]),
            time: horodatage(h),
            bits: genese.header.bits,
            height: h,
            // Aucun minage : c'est tout l'interet de l'attaque.
            nonce: 0,
        };
        prev = e.block_id();
        entetes.push(e);
    }
    let tete_fabriquee = prev;

    // L'attaquant fournit ses propres ancrages, parfaitement coherents entre
    // eux : c'est exactement ce qu'un explorateur usurpe afficherait.
    let mut instantane = instantane_honnete;
    instantane.tip = tete_fabriquee;
    let empreinte = instantane.empreinte();

    let r = Chain::adopter_instantane(RESEAU, instantane, &entetes, tete_fabriquee, empreinte);

    assert!(
        matches!(
            r,
            Err(AdoptionError::TravailInvalide { .. })
                | Err(AdoptionError::DifficulteInvalide { .. })
        ),
        "une chaine d'en-tetes sans travail a ete adoptee : l'etat monetaire \
         d'un noeud neuf se fabrique alors gratuitement"
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

/// Un ancrage inscrit dans le binaire prime sur ce que l'operateur recopie.
///
/// C'est la derniere barriere du modele de confiance. La reverification du
/// travail rend deja l'attaque couteuse, mais un adversaire disposant d'une
/// grande puissance pourrait la payer. Un ancrage compile lui oppose une valeur
/// qui ne vient d'aucun reseau : elle vient du logiciel que l'utilisateur
/// execute deja, relu par quiconque lit le depot.
#[test]
fn un_ancrage_compile_prime_sur_la_valeur_de_l_operateur() {
    use q21_core::chain::AdoptionError;
    use q21_core::synchro_rapide::Ancrage;

    let dir = rep("ancrage");
    let (chain, _archive) = chaine_minee(&dir, 30);
    let instantane = chain.snapshot_at_depth(1).expect("instantane");

    // Le chemin honnete, tel que l'adoption le reconstruit.
    let chemin: Vec<q21_core::block::BlockHeader> = (0..=instantane.height)
        .map(|h| {
            let id = chain.active_at(h).expect("hauteur active");
            chain.header_of(&id).expect("en-tete")
        })
        .collect();

    // 1. Un ancrage conforme laisse passer.
    let vrai = Ancrage {
        hauteur: 10,
        tete: chain.active_at(10).expect("bloc 10"),
        empreinte: Hash256::ZERO, // ignoree : hauteur != celle de l'instantane
    };
    assert!(
        Chain::verifier_les_ancrages(&chemin, &instantane, &[vrai]).is_ok(),
        "une chaine conforme a l'ancrage doit etre acceptee"
    );

    // 2. Un ancrage qui designe un autre bloc a cette hauteur refuse tout, meme
    //    si la chaine porte un travail parfaitement valide.
    let empoisonne = Ancrage {
        hauteur: 10,
        tete: Hash256([0xab; 32]),
        empreinte: Hash256::ZERO,
    };
    assert!(
        matches!(
            Chain::verifier_les_ancrages(&chemin, &instantane, &[empoisonne]),
            Err(AdoptionError::AncrageContredit { hauteur: 10 })
        ),
        "une chaine qui contredit un ancrage doit etre refusee"
    );

    // 3. A la hauteur exacte de l'instantane, l'empreinte doit correspondre :
    //    l'operateur ne peut pas faire adopter un autre etat monetaire la ou le
    //    binaire connait l'empreinte.
    let mauvaise_empreinte = Ancrage {
        hauteur: instantane.height,
        tete: instantane.tip,
        empreinte: Hash256([0xcd; 32]),
    };
    assert!(
        matches!(
            Chain::verifier_les_ancrages(&chemin, &instantane, &[mauvaise_empreinte]),
            Err(AdoptionError::AncrageContredit { .. })
        ),
        "une empreinte contredisant l'ancrage doit etre refusee"
    );

    // 4. Un ancrage au-dela de ce qu'on adopte ne dit rien.
    let au_dela = Ancrage {
        hauteur: instantane.height + 1_000,
        tete: Hash256([0xef; 32]),
        empreinte: Hash256([0xef; 32]),
    };
    assert!(
        Chain::verifier_les_ancrages(&chemin, &instantane, &[au_dela]).is_ok(),
        "un ancrage plus haut que l'instantane ne doit rien interdire"
    );
}
