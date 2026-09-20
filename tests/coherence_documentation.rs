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
