//! Saisie d'une phrase secrete sans echo.
//!
//! # Pourquoi ce module existe
//!
//! Une phrase secrete tapee en clair finit dans l'historique du terminal, dans
//! les journaux de session, sur les captures d'ecran et dans la memoire de qui
//! passe derriere. Un logiciel de portefeuille qui affiche ce qu'on tape a
//! echoue avant meme de chiffrer quoi que ce soit.
//!
//! # Ce qu'il fait, et ce qu'il refuse de faire
//!
//! Il coupe l'echo du terminal le temps de la saisie, puis le retablit — y
//! compris si la lecture echoue. Sur Windows il passe par l'API console ; sur
//! les systemes POSIX il passe par `stty`, l'outil standard, plutot que par une
//! declaration a la main des structures `termios`, dont la disposition varie
//! d'un systeme a l'autre et dont une erreur laisserait le terminal inutilisable.
//!
//! S'il ne parvient pas a couper l'echo, il **le dit** et laisse l'utilisateur
//! decider. Faire semblant serait pire que ne rien faire.

use std::io::{self, BufRead, Write};

/// Lit une phrase secrete sur l'entree standard, sans l'afficher.
///
/// Rend aussi `false` en second membre si l'echo n'a **pas** pu etre coupe :
/// l'appelant doit alors prevenir l'utilisateur.
/// Y a-t-il un humain au clavier ?
///
/// # Pourquoi la question compte
///
/// Une application qu'on double-clique n'a pas de terminal. `read_line` y rend
/// une ligne vide immediatement, et le programme comprend « l'utilisateur ne
/// veut pas de phrase secrete » — alors que personne n'a rien choisi. Un
/// portefeuille se creait donc **sans protection, en silence**, avec sa graine
/// en clair sur le disque.
///
/// Un choix qui n'a pas ete fait n'est pas un choix. Mieux vaut refuser et le
/// dire.
pub fn entree_interactive() -> bool {
    #[cfg(unix)]
    {
        // `isatty(0)`. Une seule fonction, declaree a la main plutot que
        // d'importer une bibliotheque entiere pour un entier.
        unsafe extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        unsafe { isatty(0) == 1 }
    }
    #[cfg(windows)]
    {
        // Sous Windows, un descripteur d'entree qui n'est pas une console n'a
        // pas de mode de console : `GetConsoleMode` echoue.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
            fn GetConsoleMode(h: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        }
        const STD_INPUT_HANDLE: u32 = -10i32 as u32;
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            GetConsoleMode(h, &mut mode) != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

pub fn lire_phrase(invite: &str) -> io::Result<(String, bool)> {
    print!("{invite}");
    io::stdout().flush()?;

    let masque = echo(false);
    let mut ligne = String::new();
    let lecture = io::stdin().lock().read_line(&mut ligne);
    if masque {
        echo(true);
    }
    println!();
    lecture?;

    // On retire uniquement la fin de ligne : une phrase secrete a parfaitement
    // le droit de commencer ou de finir par une espace, et la rogner
    // silencieusement rendrait le portefeuille impossible a rouvrir.
    while ligne.ends_with('\n') || ligne.ends_with('\r') {
        ligne.pop();
    }
    Ok((ligne, masque))
}

/// Demande deux fois la phrase et verifie qu'elles concordent.
///
/// Une phrase secrete mal tapee a la creation rend le portefeuille
/// definitivement illisible, et l'erreur ne se manifeste qu'a la premiere
/// reouverture — souvent des mois plus tard.
pub fn lire_phrase_confirmee(invite: &str) -> io::Result<Option<String>> {
    let (a, masque) = lire_phrase(invite)?;
    if !masque {
        eprintln!("  avertissement : l'echo du terminal n'a pas pu etre coupe.");
        eprintln!("  Ce qui a ete tape reste visible a l'ecran et dans l'historique.");
    }
    if a.is_empty() {
        return Ok(None);
    }
    let (b, _) = lire_phrase("Confirmez la phrase secrete : ")?;
    if a != b {
        return Ok(None);
    }
    Ok(Some(a))
}

#[cfg(unix)]
fn echo(actif: bool) -> bool {
    // `stty` est l'outil POSIX standard. On l'appelle plutot que de declarer
    // `termios` a la main : sa disposition memoire differe entre Linux, macOS et
    // les BSD, et une erreur y laisserait le terminal muet apres la sortie du
    // programme.
    let arg = if actif { "echo" } else { "-echo" };
    std::process::Command::new("stty")
        .arg(arg)
        // `stty` agit sur son terminal de controle : il faut lui passer le notre.
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn echo(actif: bool) -> bool {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(h: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(h: *mut core::ffi::c_void, mode: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    // SAFETY : on lit puis reecrit le mode d'une poignee console valide ; aucune
    // memoire n'est allouee ni transferee.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        let nouveau = if actif {
            mode | ENABLE_ECHO_INPUT
        } else {
            mode & !ENABLE_ECHO_INPUT
        };
        SetConsoleMode(h, nouveau) != 0
    }
}

#[cfg(not(any(unix, windows)))]
fn echo(_actif: bool) -> bool {
    false
}
