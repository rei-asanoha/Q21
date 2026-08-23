//! Verrou de repertoire : un seul q21 a la fois sur un dossier de donnees.
//!
//! # Le defaut que ce module repare
//!
//! Rien n'empechait deux processus d'ouvrir le meme repertoire. C'est le cas
//! le plus banal qui soit : le portefeuille tourne dans sa fenetre, et l'on
//! lance `q21 mine` dans une autre parce qu'on veut confirmer une transaction.
//! Ou bien le fichier a double-cliquer est double-clique deux fois.
//!
//! Trois fichiers y perdent leur coherence :
//!
//! - **`wallet.dat` et `wallet.seq`.** L'ecriture du portefeuille lit le
//!   numero de serie, scelle le contenu — six cent mille iterations de PBKDF2,
//!   soit plusieurs centaines de millisecondes — puis ecrit les deux fichiers.
//!   Deux processus entrelaces laissent un `wallet.seq` plus recent que le
//!   `wallet.dat` qu'il accompagne. Au demarrage suivant, la protection
//!   anti-rejeu fait ce qu'on lui demande : elle refuse d'ouvrir le
//!   portefeuille, en annoncant une restauration depuis une sauvegarde
//!   ancienne. Le portefeuille est intact, mais l'utilisateur lit qu'il a
//!   peut-etre revele ses clefs.
//! - **`blocks.dat` et son index.** Deux processus qui ajoutent des blocs au
//!   meme fichier ecrivent chacun a la position qu'il croit libre.
//! - **`mempool.dat` et l'instantane**, qui sont ecrits a l'arret.
//!
//! Ce n'est pas une hypothese : le defaut a ete rencontre en reproduisant un
//! scenario ordinaire, sur un repertoire qu'un second processus avait ouvert
//! pendant que le premier finissait d'ecrire.
//!
//! # Comment
//!
//! Un verrou consultatif pose par le systeme sur un fichier du repertoire.
//! `flock` sur les systemes POSIX, `LockFileEx` sur Windows — les deux memes
//! appels que ferait la bibliotheque qu'on aurait pu importer.
//!
//! Le point important est que **le systeme le relache tout seul** quand le
//! processus meurt, de quelque facon qu'il meure : sortie propre, panique,
//! `kill -9`, coupure de courant. Un verrou fabrique a la main — un fichier
//! `.lock` contenant un numero de processus — laisserait un verrou fantome
//! apres chaque arret brutal, et il faudrait alors apprendre a l'utilisateur a
//! l'effacer. Ce serait echanger une panne rare contre une panne frequente.
//!
//! # Ce qui reste vrai
//!
//! Le verrou est **consultatif** : il n'empeche pas un programme qui l'ignore
//! d'ecrire dans ces fichiers. Il empeche q21 de se marcher dessus lui-meme,
//! ce qui est le cas reel.
//!
//! Sur un systeme de fichiers en reseau, `flock` peut mentir. Un repertoire de
//! donnees sur un partage reseau est deja une mauvaise idee pour d'autres
//! raisons ; on ne pretend pas la rattraper ici.

use std::fs::File;
use std::path::Path;

/// Verrou pris sur un repertoire de donnees.
///
/// Tant que cette valeur existe, aucun autre processus q21 n'ouvrira le meme
/// repertoire. Sa destruction — ou la mort du processus — le relache.
pub struct Verrou {
    // Le descripteur porte le verrou : c'est sa fermeture qui le relache. Il
    // n'est jamais lu ni ecrit.
    _fichier: File,
}

/// Nom du fichier temoin. Il reste vide : seul son descripteur compte.
pub const NOM: &str = ".verrou";

/// Prend le verrou du repertoire.
///
/// Rend une erreur lisible si un autre processus le detient deja. L'appelant
/// doit garder la valeur rendue vivante aussi longtemps qu'il touche au
/// repertoire.
pub fn prendre(datadir: &Path) -> Result<Verrou, String> {
    if let Err(e) = std::fs::create_dir_all(datadir) {
        return Err(format!(
            "repertoire de donnees inaccessible ({}) : {e}",
            datadir.display()
        ));
    }
    let chemin = datadir.join(NOM);
    let fichier = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&chemin)
        .map_err(|e| format!("verrou illisible ({}) : {e}", chemin.display()))?;

    if essayer(&fichier) {
        Ok(Verrou { _fichier: fichier })
    } else {
        Err(format!(
            "un autre q21 utilise deja ce dossier de donnees.\n\n  \
             Dossier : {}\n\n  \
             Deux programmes qui ecrivent le meme portefeuille et le meme fichier\n  \
             de blocs les abiment tous les deux. Fermez l'autre fenetre — le bouton\n  \
             « Fermer le portefeuille » de l'onglet Informations, ou la croix de la\n  \
             fenetre — puis relancez celle-ci.\n\n  \
             Pour faire tourner un second noeud en meme temps, donnez-lui un autre\n  \
             dossier :\n\n      \
             q21 --datadir q21-data-2 wallet",
            datadir.display()
        ))
    }
}

#[cfg(unix)]
fn essayer(fichier: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    // SAFETY : le descripteur est valide pour la duree de l'appel, et `flock`
    // ne fait rien d'autre que poser le verrou.
    unsafe { flock(fichier.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
}

#[cfg(windows)]
fn essayer(fichier: &File) -> bool {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Overlapped {
        interne: usize,
        interne_haut: usize,
        decalage: u32,
        decalage_haut: u32,
        evenement: *mut core::ffi::c_void,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LockFileEx(
            fichier: *mut core::ffi::c_void,
            drapeaux: u32,
            reserve: u32,
            octets_bas: u32,
            octets_haut: u32,
            recouvrement: *mut Overlapped,
        ) -> i32;
    }
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;

    let mut recouvrement = Overlapped {
        interne: 0,
        interne_haut: 0,
        decalage: 0,
        decalage_haut: 0,
        evenement: core::ptr::null_mut(),
    };
    // SAFETY : la poignee est valide pour la duree de l'appel, et la structure
    // de recouvrement vit jusqu'a son retour. Le verrou porte sur la totalite
    // du fichier, et `LOCKFILE_FAIL_IMMEDIATELY` interdit toute attente.
    unsafe {
        LockFileEx(
            fichier.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut recouvrement,
        ) != 0
    }
}

#[cfg(not(any(unix, windows)))]
fn essayer(_fichier: &File) -> bool {
    // Aucun mecanisme connu : on n'invente pas un verrou qui ne verrouille
    // rien. Le programme reste utilisable, sans cette protection.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("q21-verrou-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Le verrou se prend sur un repertoire libre.
    #[test]
    fn un_repertoire_libre_se_verrouille() {
        let d = dossier("libre");
        let v = prendre(&d).expect("verrou refuse sur un repertoire libre");
        drop(v);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Il se reprend apres avoir ete relache.
    ///
    /// C'est ce qui fait qu'un arret propre ne laisse rien derriere lui.
    #[test]
    fn le_verrou_relache_se_reprend() {
        let d = dossier("relache");
        {
            let _v = prendre(&d).expect("premier verrou");
        }
        let _v = prendre(&d).expect("le verrou n'a pas ete relache");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le repertoire est cree s'il n'existe pas.
    ///
    /// Le verrou est pris avant tout le reste : il ne peut pas exiger un
    /// repertoire que la commande n'a pas encore eu l'occasion de creer.
    #[test]
    fn un_repertoire_absent_est_cree() {
        let d = std::env::temp_dir().join("q21-verrou-absent/sous/dossier");
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("q21-verrou-absent"));
        let _v = prendre(&d).expect("verrou refuse sur un repertoire a creer");
        assert!(d.join(NOM).exists());
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("q21-verrou-absent"));
    }

    /// Un second processus est refuse.
    ///
    /// On ne peut pas eprouver cela dans le meme processus : `flock` est
    /// accorde par descripteur ouvert, mais la plupart des systemes le
    /// reaccordent au meme processus. On lance donc un vrai second processus —
    /// l'epreuve elle-meme, avec une variable qui lui dit quoi faire.
    #[test]
    fn un_second_processus_est_refuse() {
        const TEMOIN: &str = "Q21_EPREUVE_VERROU";
        if let Ok(chemin) = std::env::var(TEMOIN) {
            // Nous sommes le second processus.
            let code = if prendre(std::path::Path::new(&chemin)).is_ok() {
                0 // le verrou a ete accorde : c'est l'echec
            } else {
                42 // refuse, comme il se doit
            };
            std::process::exit(code);
        }

        let d = dossier("concurrent");
        let _v = prendre(&d).expect("premier verrou");

        let sortie = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("verrou::tests::un_second_processus_est_refuse")
            .arg("--exact")
            .arg("--nocapture")
            .env(TEMOIN, &d)
            .output()
            .expect("second processus");

        assert_eq!(
            sortie.status.code(),
            Some(42),
            "le second processus a obtenu le verrou : {}",
            String::from_utf8_lossy(&sortie.stderr)
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
