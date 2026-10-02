//! Language policy: everything in this repository is written in American
//! English.
//!
//! Code, comments, messages, test names, documentation, workflows and scripts
//! are English. The only exceptions are listed below, each with its reason:
//! the French and Japanese translation tables of the web pages, and the
//! legacy names that the one-time migration of 0.3.x data directories must
//! still recognize.
//!
//! This test fails on any other file that contains accented Latin letters or a
//! line that reads as French, so that the policy cannot erode one commit at a
//! time. See CONTRIBUTING.md.

use std::path::{Path, PathBuf};

/// Files allowed to contain French, and why.
const ALLOWED: &[(&str, &str)] = &[
    (
        "src/wallet_ui.rs",
        "French and Japanese translation tables of the wallet page",
    ),
    (
        "src/explorer.rs",
        "French and Japanese translation tables of the explorer page",
    ),
    (
        "src/legacy.rs",
        "legacy 0.3.x file names and settings read by the migration",
    ),
    (
        "tests/upgrade_from_0_3.rs",
        "builds a real 0.3.x data directory, with its legacy file names",
    ),
    (
        "UPGRADING.md",
        "maps the old 0.3.x option names to the new ones",
    ),
    (
        "tests/english_only.rs",
        "this file: the list of marker words",
    ),
];

/// Words that are common in French and rare in English. A line containing two
/// different ones is treated as French.
const FRENCH_MARKERS: &[&str] = &[
    "aucun",
    "aucune",
    "aussi",
    "avec",
    "avertissement",
    "bloc",
    "blocs",
    "cette",
    "clef",
    "dans",
    "deja",
    "des",
    "donc",
    "elle",
    "empreinte",
    "encore",
    "entree",
    "erreur",
    "est",
    "etat",
    "fichier",
    "graine",
    "hauteur",
    "jeton",
    "joignable",
    "les",
    "leur",
    "lorsque",
    "mais",
    "minage",
    "mineur",
    "noeud",
    "noeuds",
    "nous",
    "parce",
    "portefeuille",
    "quand",
    "reglages",
    "reponse",
    "requete",
    "reseau",
    "sauvegarde",
    "sont",
    "sortie",
    "une",
    "vous",
];

/// Extensions of the text files the policy covers.
const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "md", "toml", "yml", "yaml", "sh", "ps1", "bat", "command", "txt", "html", "json", "pub",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() {
            // Third-party sources, build output and git internals are not ours.
            if matches!(name.as_str(), ".git" | "target" | "vendor") {
                continue;
            }
            collect(&p, out);
        } else {
            let ext = p.extension().map(|x| x.to_string_lossy().into_owned());
            let dotfile = name.starts_with('.');
            if dotfile || ext.is_some_and(|x| TEXT_EXTENSIONS.contains(&x.as_str())) {
                out.push(p);
            }
        }
    }
}

fn relative(p: &Path) -> String {
    p.strip_prefix(root())
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Latin letters with diacritics (and the oe ligature), as used in French.
/// The multiplication and division signs share that Unicode block and are
/// allowed.
fn accented(c: char) -> bool {
    matches!(c, 'À'..='ÿ') && c != '×' && c != '÷' || c == 'œ' || c == 'Œ'
}

fn reads_as_french(line: &str) -> bool {
    let lower = line.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
        .collect();
    let mut seen: Vec<&str> = Vec::new();
    for w in words {
        if FRENCH_MARKERS.contains(&w) && !seen.contains(&w) {
            seen.push(w);
        }
    }
    seen.len() >= 2
}

#[test]
fn the_repository_is_written_in_english() {
    let mut files = Vec::new();
    collect(&root(), &mut files);
    assert!(
        files.len() > 50,
        "the walk found only {} files",
        files.len()
    );
    let mut problems = Vec::new();
    for f in &files {
        let rel = relative(f);
        if ALLOWED.iter().any(|(a, _)| *a == rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if line.chars().any(accented) || reads_as_french(line) {
                problems.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "French text found ({} line(s)). Everything must be written in American \
         English; see CONTRIBUTING.md.\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn the_detector_recognizes_french_and_accepts_english() {
    assert!(reads_as_french("le bloc est refuse dans ce cas"));
    assert!(reads_as_french("// Le portefeuille sauvegarde la graine."));
    assert!(!reads_as_french("The block is refused in this case."));
    assert!(!reads_as_french("A node keeps its address book on disk."));
    assert!("Réseau".chars().any(accented));
    assert!(!"3 × 4 ÷ 2".chars().any(accented));
}

/// Legacy names and French identifier fragments. A single French word slips
/// past [`reads_as_french`], which needs two; these are the ones the 0.3.x
/// code base actually used. Outside [`ALLOWED`], code refers to the constants
/// of `src/legacy.rs` instead of spelling them.
const LEGACY_FRAGMENTS: &[&str] = &[
    "Q21SCEL",
    "Q21/flot",
    "Q21-DOSSIER",
    "CACHE-ADRESSES",
    "Q21AMORC",
    "serie=",
    "consommes",
    "verifie_jusqu",
    "etiquettes",
    "demandees",
    "reglages",
    "joignable",
    "amorce",
    "ancienne-chaine",
    "verrou",
    "entetes",
    "ecrire_",
    "lire_",
    "portefeuille",
];

#[test]
fn legacy_names_appear_only_in_the_migration_files() {
    let mut files = Vec::new();
    collect(&root(), &mut files);
    let mut problems = Vec::new();
    for f in &files {
        let rel = relative(f);
        if ALLOWED.iter().any(|(a, _)| *a == rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            let lower = line.to_lowercase();
            if let Some(word) = LEGACY_FRAGMENTS
                .iter()
                .find(|w| lower.contains(&w.to_lowercase()))
            {
                problems.push(format!("{rel}:{}: `{word}` in: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "legacy name outside the migration files ({} line(s)); use the constants \
         of src/legacy.rs, see CONTRIBUTING.md.\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn every_exception_still_exists() {
    for (file, why) in ALLOWED {
        assert!(
            root().join(file).exists(),
            "exception for a file that no longer exists: {file} ({why})"
        );
    }
}
