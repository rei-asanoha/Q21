//! Compilation reproductible : les epreuves qui gardent le dispositif.
//!
//! # Ce qui est garde ici, et pourquoi ce n'est pas dans le code
//!
//! La reproductibilite de Q21 ne tient pas a une ligne de Rust mais a un
//! accord entre cinq fichiers qui ne se parlent pas :
//!
//! - `rust-toolchain.toml` epingle le compilateur ;
//! - `outils/construire-reproductible.sh` pose `--remap-path-prefix` sous
//!   Unix ;
//! - `outils/construire-reproductible.ps1` fait de meme sous Windows ;
//! - `.github/workflows/livraison.yml` refait le geste en livraison ;
//! - `REPRODUIRE.md` annonce publiquement le prefixe obtenu.
//!
//! Si l'un derive — un prefixe change dans le script mais pas dans la
//! livraison, une version de compilateur relevee dans un fichier seulement —
//! deux compilations du meme commit cessent d'etre identiques, **en
//! silence**. Le condensat publie ne prouve alors plus rien, et personne ne
//! s'en apercoit avant qu'un tiers essaie de reproduire et n'y arrive pas.
//!
//! Ces epreuves lisent donc les fichiers du depot. C'est inhabituel pour un
//! test unitaire, et c'est deliberement le seul endroit du projet ou cela se
//! fait : l'invariant garde est une propriete du depot, pas du programme.
//!
//! Ce qu'elles ne font pas : verifier que deux compilations donnent le meme
//! binaire. Cela demande deux compilations completes, donc un travail de CI a
//! part (`reproductible` dans `essais.yml`, qui lance
//! `outils/verifier-reproductible.sh`).

use std::fs;
use std::path::PathBuf;

/// La racine du depot, deduite de l'emplacement du manifeste.
fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn lire(chemin: &str) -> String {
    let p = racine().join(chemin);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("lecture de {} impossible : {e}", p.display()))
}

/// Le prefixe d'arrivee du remappage, celui qui finit dans le binaire.
///
/// Il est arbitraire, mais il doit etre le **meme partout** : c'est lui qu'un
/// tiers retrouvera dans le binaire qu'il recompile, et REPRODUIRE.md
/// l'annonce. Le changer d'un cote seulement casse la reproductibilite sans
/// aucun message d'erreur.
const PREFIXE: &str = "=/q21";

#[test]
fn le_prefixe_de_remappage_est_le_meme_partout() {
    let endroits = [
        "outils/construire-reproductible.sh",
        "outils/construire-reproductible.ps1",
        ".github/workflows/livraison.yml",
    ];
    for e in endroits {
        let texte = lire(e);
        assert!(
            texte.contains("--remap-path-prefix"),
            "{e} ne pose plus --remap-path-prefix : la compilation n'est plus \
             reproductible, et rien d'autre ne le signalera"
        );
        assert!(
            texte.contains(PREFIXE),
            "{e} n'emploie plus le prefixe d'arrivee « {PREFIXE} » ; deux \
             compilations du meme commit vont diverger en silence"
        );
    }
    // Le document public doit annoncer le meme prefixe, sans le « = » qui
    // n'appartient qu'a la syntaxe du drapeau.
    let doc = lire("REPRODUIRE.md");
    assert!(
        doc.contains("/q21/vendor/"),
        "REPRODUIRE.md n'annonce plus les chemins remappes que le lecteur \
         doit retrouver dans son propre binaire"
    );
}

#[test]
fn la_version_du_compilateur_est_la_meme_dans_tous_les_fichiers() {
    let epingle = lire("rust-toolchain.toml");
    // `channel = "1.95.0"` — on extrait la valeur plutot que de la coder ici,
    // pour que relever la chaine d'outils reste une seule modification.
    let version = epingle
        .lines()
        .find_map(|l| {
            let l = l.trim();
            let reste = l.strip_prefix("channel")?.trim_start().strip_prefix('=')?;
            Some(reste.trim().trim_matches('"').to_string())
        })
        .expect("rust-toolchain.toml ne declare plus de `channel`");

    assert!(
        version.split('.').count() == 3,
        "la chaine d'outils doit etre une version exacte (1.95.0), pas un \
         canal mouvant comme « stable » : sinon « le meme commit » designe un \
         compilateur different toutes les six semaines. Trouve : {version}"
    );

    for w in [
        ".github/workflows/essais.yml",
        ".github/workflows/livraison.yml",
    ] {
        let texte = lire(w);
        assert!(
            texte.contains(&version),
            "{w} n'installe pas {version}, la version epinglee par \
             rust-toolchain.toml : la livraison ne serait pas reproductible \
             depuis le depot"
        );
    }
}

#[test]
fn le_banc_de_reproductibilite_est_branche_dans_la_ci() {
    let essais = lire(".github/workflows/essais.yml");
    assert!(
        essais.contains("outils/verifier-reproductible.sh"),
        "aucun travail de CI ne compile deux fois pour comparer : une \
         dependance qui inscrirait une date ou un chemin casserait la \
         reproductibilite sans que la fusion s'arrete"
    );

    let livraison = lire(".github/workflows/livraison.yml");
    assert!(
        livraison.contains("Aucun chemin de construction dans le binaire"),
        "la livraison ne verifie plus que le binaire publie est depourvu du \
         chemin de la machine qui l'a construit"
    );
}

/// Le dossier d'attestations doit exister et porter sa marche a suivre.
///
/// Vide, il n'atteste rien — et c'est l'etat honnete tant qu'une seule
/// personne compile. Absent, il empeche la premiere attestation d'arriver :
/// un tiers qui recompile n'aurait nulle part ou deposer ce qu'il obtient.
#[test]
fn le_depot_peut_recevoir_des_attestations() {
    for f in [
        "attestations/LISEZ-MOI.md",
        "attestations/clefs-constructeurs/LISEZ-MOI.md",
    ] {
        assert!(
            racine().join(f).is_file(),
            "{f} manque : le dispositif d'attestation n'est plus documente"
        );
    }
    // La regle qui compte, declaree d'avance : une clef deposee la n'autorise
    // rien. Si cette phrase disparait, le dossier devient une liste de
    // personnes de confiance, c'est-a-dire l'inverse de son objet.
    let doc = lire("attestations/clefs-constructeurs/LISEZ-MOI.md");
    assert!(
        doc.contains("Aucun droit."),
        "la regle « une clef deposee ici n'autorise rien » a disparu de \
         attestations/clefs-constructeurs/LISEZ-MOI.md"
    );
}

/// L'absence de clef maitresse est une decision, et elle doit rester ecrite.
///
/// Bitcoin a eu une clef d'alerte, retiree en 2016 apres avoir constate
/// qu'elle etait un point de compromission unique et un pouvoir sans mandat.
/// Q21 n'en a pas. Une telle clef ne s'ajoute jamais par accident, mais la
/// **declaration** qu'il n'y en aura pas peut se perdre a la faveur d'une
/// reecriture de documentation — et c'est elle qui engage.
#[test]
fn l_absence_de_clef_maitresse_reste_declaree() {
    let doc = lire("SUCCESSION.md");
    for phrase in ["Il n'y a pas de clé maîtresse", "clé d'alerte", "2016"] {
        assert!(
            doc.contains(phrase),
            "SUCCESSION.md ne declare plus « {phrase} » : la regle qui \
             interdit toute clef capable d'imposer quelque chose au reseau \
             n'est plus ecrite nulle part"
        );
    }
}
