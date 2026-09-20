//! Epreuve — la genese publiee dans la documentation est celle que le code calcule.
//!
//! `RESEAU.md` demande a quiconque rejoint le reseau de comparer l'identifiant de
//! genese calcule sur sa machine a celui publie, et de refuser de continuer s'ils
//! different. C'est le seul acte de confiance de tout le processus.
//!
//! Le consensus a change plusieurs fois ; l'identifiant publie, lui, avait ete
//! recopie a la main. Le document donnait donc une valeur qui ne correspondait
//! plus a rien : celui qui appliquait consciencieusement le controle prescrit
//! concluait qu'il n'etait pas sur la bonne chaine — alors qu'il l'etait.
//!
//! Une valeur de reference recopiee a la main derive. Cette epreuve la rattache
//! au code : toute modification du consensus qui change la genese fait echouer la
//! construction tant que la documentation n'a pas suivi.

use q21_core::chain::genesis_block;
use q21_core::Network;
use std::path::{Path, PathBuf};

fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn lire(nom: &str) -> String {
    let chemin: PathBuf = racine().join(nom);
    std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("lecture de {} impossible : {e}", chemin.display()))
}

fn genese_testnet() -> String {
    genesis_block(Network::Testnet)
        .header
        .block_id()
        .to_string()
}

/// Un jeton hexadecimal, eventuellement suivi de points de suspension.
///
/// Les documents citent tantot l'empreinte complete, tantot un prefixe suivi de
/// `...` ou de `…`. On normalise les deux formes.
fn prefixe_hex(jeton: &str) -> Option<&str> {
    let jeton = jeton
        .trim_end_matches('…')
        .trim_end_matches("...")
        .trim_end_matches('`')
        .trim_start_matches('`');
    let hex = jeton.trim();
    if hex.len() >= 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

#[test]
fn reseau_md_publie_l_identifiant_de_genese_que_le_code_calcule() {
    let attendu = genese_testnet();
    let texte = lire("RESEAU.md");

    let ligne = texte
        .lines()
        .find(|l| l.trim_start().starts_with("identifiant"))
        .expect("RESEAU.md ne publie plus d'identifiant de genese");

    let publie = ligne
        .split_whitespace()
        .next_back()
        .expect("ligne `identifiant` vide dans RESEAU.md");

    assert_eq!(
        publie, attendu,
        "RESEAU.md publie une genese perimee.\n  publie : {publie}\n  calcule: {attendu}\n\
         Le consensus a change : mettre a jour RESEAU.md dans le meme commit."
    );
}

#[test]
fn aucun_document_ne_cite_une_genese_perimee() {
    let attendu = genese_testnet();

    // Les sorties d'exemple des guides d'installation citent un prefixe de la
    // genese. Un prefixe faux est aussi trompeur qu'une empreinte fausse : le
    // lecteur compare ce qu'il voit a ce qui est ecrit.
    let documents = [
        "RESEAU.md",
        "SERVEUR.md",
        "SERVEUR-WINDOWS.md",
        "REJOINDRE.md",
    ];

    for nom in documents {
        if !Path::new(&racine().join(nom)).exists() {
            continue;
        }
        let texte = lire(nom);
        for (numero, ligne) in texte.lines().enumerate() {
            let interessante = ligne.contains("genese ecrite") || ligne.contains("identifiant");
            if !interessante {
                continue;
            }
            for jeton in ligne.split_whitespace() {
                let Some(hex) = prefixe_hex(jeton) else {
                    continue;
                };
                assert!(
                    attendu.starts_with(hex),
                    "{nom}:{} cite une genese qui n'est pas celle du code.\n  \
                     cite   : {hex}\n  calcule: {attendu}",
                    numero + 1
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Les tailles de memoire annoncees aux participants
// ---------------------------------------------------------------------------
//
// REJOINDRE.md reclamait 8 Go de memoire vive pour miner, et annoncait une table
// de 2 Go : les chiffres de la chaine principale, dans le guide qui conduit au
// reseau d'essai. Celui-ci demande soixante-quatre fois moins. Un guide qui
// surestime ses exigences n'ecarte que des participants — et un reseau d'essai
// sans participants ne mesure rien.
//
// Ces tailles se calculent a partir des constantes de consensus. On les y
// rattache, comme la genese.

fn mio(elements: u32) -> u64 {
    (elements as u64) * (q21_core::consensus::POW_ELEMENT_SIZE as u64) / (1024 * 1024)
}

#[test]
fn rejoindre_md_annonce_les_tailles_memoire_du_reseau_d_essai() {
    use q21_core::memhard::{cache_size, table_size, TableParams};

    let p = TableParams::for_network(Network::Testnet);
    let table_depart = mio(table_size(p, 0));
    let table_plafond = mio(p.nmax);
    let cache_depart = mio(cache_size(p, 0)).max(1);

    let texte = lire("REJOINDRE.md");

    for (valeur, quoi) in [
        (table_depart, "la table du mineur a l'epoque 0"),
        (table_plafond, "le plafond de la table"),
        (cache_depart, "le cache d'un noeud qui verifie"),
    ] {
        let attendu = format!("{valeur} Mio");
        assert!(
            texte.contains(&attendu),
            "REJOINDRE.md n'annonce plus `{attendu}` pour {quoi}.\n\
             Les constantes de consensus ont change : mettre le guide a jour dans\n\
             le meme commit, sans quoi il decrit un reseau qui n'existe pas."
        );
    }

    // Le piege d'origine : les chiffres de la chaine principale presentes comme
    // ceux du reseau que le guide fait rejoindre.
    assert!(
        !texte.contains("Il faut **8 Go de mémoire vive**"),
        "REJOINDRE.md reclame a nouveau la memoire de la chaine principale pour \
         miner sur le reseau d'essai."
    );
}

// ---------------------------------------------------------------------------
// Le point d'entree livre avec le programme
// ---------------------------------------------------------------------------
//
// Le binaire ne contient l'adresse d'aucun serveur, et cela ne change pas : une
// adresse gravee dans un logiciel distribue serait une dependance permanente
// envers celui qui la tient. Mais le fichier qui la porte voyage desormais
// rempli dans l'archive. Sans cela, toute archive fraichement decompressee est
// aveugle, et son porteur lit « aucun ordinateur joignable » sans savoir que
// rien n'est casse.
//
// Deux derives deviennent alors possibles, et ces epreuves les ferment : livrer
// une adresse que le projet n'a pas publiee — donc que personne n'a verifiee —
// et cesser de livrer le fichier sans s'en apercevoir.

/// Les adresses livrees sont celles que le projet publie.
///
/// `RESEAU.md` pose la regle : « on n'ecrit ici que ce qui repond vraiment,
/// verifie depuis une machine exterieure ». Une adresse livree a des milliers
/// de machines doit au moins avoir passe cette porte-la.
#[test]
fn les_amorces_livrees_sont_celles_que_reseau_md_publie() {
    let fichier = lire("amorces-par-defaut.txt");
    let reseau_md = lire("RESEAU.md");

    let adresses: Vec<&str> = fichier
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    assert!(
        !adresses.is_empty(),
        "amorces-par-defaut.txt ne contient aucune adresse : l'archive repartirait \
         aveugle, et le premier lancement n'aboutirait nulle part."
    );

    for a in &adresses {
        assert!(
            reseau_md.contains(a),
            "amorces-par-defaut.txt livre `{a}`, que RESEAU.md ne publie pas.\n\
             Publier d'abord, livrer ensuite : on n'envoie pas a des inconnus une \
             adresse que le projet n'a pas verifiee."
        );
    }
}

/// La chaine de livraison depose bien ce fichier dans l'archive.
///
/// Le fichier peut etre parfait dans le depot et n'arriver nulle part. C'est
/// l'etape d'assemblage qui le fait voyager, et rien d'autre ne la garde.
#[test]
fn la_livraison_depose_le_fichier_d_amorces_dans_l_archive() {
    let workflow = lire(".github/workflows/livraison.yml");
    assert!(
        workflow.contains("cp amorces-par-defaut.txt livraison/q21-data/amorces.txt"),
        "la chaine de livraison ne depose plus amorces.txt dans l'archive : \
         toute archive repartirait aveugle."
    );
    assert!(
        workflow.contains("mkdir -p livraison/q21-data"),
        "le dossier q21-data n'est plus cree dans l'archive : le fichier d'amorces \
         n'atterrirait pas la ou le noeud le cherche."
    );
}
