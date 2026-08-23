//! Arret propre sur Ctrl-C.
//!
//! # Le defaut que ce module repare
//!
//! Un noeud Q21 ecrit plusieurs choses au moment de s'arreter : l'instantane de
//! l'etat monetaire, le carnet de pairs, le portefeuille, et depuis peu le
//! reservoir de transactions en attente.
//!
//! Rien de tout cela ne se produisait. La seule sortie prevue etait l'expiration
//! de `--seconds`, employee par les epreuves ; **un Ctrl-C tuait le processus
//! sur place**, et tout ce qui devait etre ecrit ne l'etait pas.
//!
//! C'est-a-dire que le chemin teste n'etait pas le chemin emprunte. Un premier
//! utilisateur a envoye une transaction puis arrete le portefeuille par Ctrl-C
//! pour lancer le minage : la transaction avait disparu. On a d'abord cru a
//! l'absence de persistance du reservoir — elle manquait effectivement — puis
//! il est apparu que meme une fois ecrite, elle ne l'aurait jamais ete, faute
//! d'avoir jamais atteint le code d'arret.
//!
//! # Comment
//!
//! Le gestionnaire ne fait qu'une chose : lever un drapeau. C'est la seule
//! operation qu'un gestionnaire de signal ait le droit de faire — allouer,
//! ecrire un fichier ou prendre un verrou depuis un handler est un moyen sur de
//! bloquer un processus pour toujours. La boucle principale voit le drapeau au
//! tour suivant, sort, et fait le travail dans un contexte normal.
//!
//! Deux systemes, deux mecanismes, aucune dependance : `signal` sur les systemes
//! POSIX, `SetConsoleCtrlHandler` sur Windows. Ce sont exactement les fonctions
//! qu'appellerait la bibliotheque qu'on aurait pu importer.
//!
//! # Ce qui reste vrai
//!
//! Un second Ctrl-C, une coupure de courant ou un `kill -9` ne laissent aucune
//! chance : c'est pour cela que rien de vital ne depend de cette ecriture. Le
//! fichier de blocs est ecrit **au fil de l'eau**, et l'instantane comme le
//! reservoir ne sont que des economies — leur perte coute un demarrage plus
//! lent et des transactions a renvoyer, jamais des fonds.

use std::sync::atomic::{AtomicBool, Ordering};

static DEMANDE: AtomicBool = AtomicBool::new(false);

/// L'utilisateur a-t-il demande l'arret ?
pub fn demande() -> bool {
    DEMANDE.load(Ordering::Relaxed)
}

/// Leve le drapeau. Exposee pour les epreuves et pour un arret provoque.
pub fn demander_arret() {
    DEMANDE.store(true, Ordering::Relaxed);
}

/// Installe le gestionnaire. A appeler une fois, au demarrage.
///
/// Rend `false` si le systeme a refuse : le programme reste utilisable, il
/// perdra simplement ce qu'il devait ecrire en cas de Ctrl-C. On ne s'arrete pas
/// pour autant — un noeud qui refuse de demarrer parce qu'il ne sait pas bien
/// mourir serait un mauvais echange.
pub fn installer() -> bool {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn signal(sig: i32, handler: usize) -> usize;
        }
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        const SIG_ERR: usize = usize::MAX;

        extern "C" fn gestionnaire(_sig: i32) {
            // Une ecriture atomique, et rien d'autre. Tout le reste se fait dans
            // la boucle principale, ou l'on a le droit d'allouer et de bloquer.
            DEMANDE.store(true, Ordering::Relaxed);
        }

        // SAFETY : on installe un gestionnaire qui n'appelle rien d'autre qu'un
        // magasin atomique. `signal` rend l'ancien gestionnaire, ou SIG_ERR.
        unsafe {
            let h = gestionnaire as *const () as usize;
            signal(SIGINT, h) != SIG_ERR && signal(SIGTERM, h) != SIG_ERR
        }
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetConsoleCtrlHandler(handler: Option<GestionnaireConsole>, ajouter: i32) -> i32;
        }
        type GestionnaireConsole = unsafe extern "system" fn(u32) -> i32;

        // Ctrl-C, Ctrl-Pause, fermeture de la fenetre, fin de session,
        // extinction. Les trois derniers laissent un delai court — quelques
        // secondes — avant que le systeme ne tranche.
        const CTRL_C_EVENT: u32 = 0;
        const CTRL_BREAK_EVENT: u32 = 1;
        const CTRL_CLOSE_EVENT: u32 = 2;
        const CTRL_LOGOFF_EVENT: u32 = 5;
        const CTRL_SHUTDOWN_EVENT: u32 = 6;

        unsafe extern "system" fn gestionnaire(evenement: u32) -> i32 {
            match evenement {
                CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
                | CTRL_SHUTDOWN_EVENT => {
                    DEMANDE.store(true, Ordering::Relaxed);
                    // Windows appelle ce gestionnaire sur un fil a lui et tue le
                    // processus des qu'il rend la main sur une fermeture de
                    // fenetre. On attend donc que la boucle principale ait fini
                    // d'ecrire — au plus quelques secondes, ce que le systeme
                    // tolere.
                    for _ in 0..100 {
                        if !DEMANDE.load(Ordering::Relaxed) {
                            break; // la boucle a fini et a rabaisse le drapeau
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    1 // evenement traite
                }
                _ => 0,
            }
        }

        // SAFETY : on enregistre un gestionnaire valide pour la duree du
        // processus.
        unsafe { SetConsoleCtrlHandler(Some(gestionnaire), 1) != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Signale que l'arret est termine.
///
/// Sur Windows, cela libere le gestionnaire de console, qui attend que le
/// travail d'ecriture soit fini avant de laisser le systeme tuer le processus.
/// Ailleurs, c'est sans effet.
pub fn arret_termine() {
    DEMANDE.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le drapeau se leve et se rabaisse.
    ///
    /// On ne peut pas envoyer un vrai signal a soi-meme dans une epreuve sans
    /// risquer d'interrompre le lanceur de tests : on verifie donc le mecanisme,
    /// pas le systeme.
    #[test]
    fn le_drapeau_se_leve_et_se_rabaisse() {
        arret_termine();
        assert!(!demande());
        demander_arret();
        assert!(demande());
        arret_termine();
        assert!(!demande());
    }

    /// L'installation ne doit jamais faire echouer un demarrage.
    #[test]
    fn l_installation_ne_panique_pas() {
        // Le resultat depend du systeme et de l'environnement d'execution ; ce
        // qui compte est qu'aucun chemin ne panique.
        let _ = installer();
        arret_termine();
    }
}
