//! L'etat du minage, partage entre la boucle du nœud et l'interface.
//!
//! # Pourquoi ce module existe
//!
//! Miner se decidait au lancement, par un drapeau `--mine`, et ne se defaisait
//! qu'en arretant le programme. C'etait tenable tant que le portefeuille se
//! pilotait en ligne de commande. Ca ne l'est plus : personne n'accepte de
//! fermer son portefeuille pour cesser de miner, et personne ne devrait avoir a
//! relire une fenetre de console pour savoir si sa machine cherche vraiment.
//!
//! Ce module porte donc deux choses, et rien d'autre :
//!
//! - **un interrupteur** que la boucle du nœud lit a chaque tour et que
//!   l'interface bascule ;
//! - **un compteur** de ce qui a ete tente, pour pouvoir afficher un debit qui
//!   soit une mesure et non une estimation.
//!
//! # Le debit est mesure sur une fenetre glissante
//!
//! Une moyenne depuis le lancement ment de deux facons : elle met plusieurs
//! minutes a refleter un arret, et elle ecrase le ralentissement d'une machine
//! qui chauffe. On garde donc le compte du dernier intervalle ferme et celui de
//! l'intervalle en cours, et le debit annonce est celui du dernier intervalle
//! d'au moins une seconde. C'est ce qu'un mineur veut savoir : ce que fait sa
//! machine maintenant.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne mine pas. Il ne connait ni la chaine, ni le portefeuille, ni la table
//! de preuve de travail. Un objet partage entre un fil qui manipule des fonds et
//! une interface exposee au navigateur doit etre le plus petit possible, et
//! celui-ci ne peut rien casser : au pire il annonce un chiffre faux.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Duree minimale d'une fenetre de mesure.
const FENETRE: std::time::Duration = std::time::Duration::from_millis(1000);

/// Etat du minage, partage par `Arc`.
pub struct Minage {
    actif: AtomicBool,
    /// Essais depuis le lancement du programme. Ne redescend jamais.
    essais_total: AtomicU64,
    /// Blocs trouves depuis le lancement.
    blocs: AtomicU64,
    /// Debit de la derniere fenetre fermee, en essais par seconde.
    debit: Mutex<f64>,
    /// Fenetre en cours : instant d'ouverture et essais comptes depuis.
    fenetre: Mutex<(Instant, u64)>,
}

impl Default for Minage {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Minage {
    pub fn new(actif: bool) -> Minage {
        Minage {
            actif: AtomicBool::new(actif),
            essais_total: AtomicU64::new(0),
            blocs: AtomicU64::new(0),
            debit: Mutex::new(0.0),
            fenetre: Mutex::new((Instant::now(), 0)),
        }
    }

    pub fn actif(&self) -> bool {
        self.actif.load(Ordering::Relaxed)
    }

    /// Allume ou eteint. Rend l'etat obtenu.
    ///
    /// Eteindre remet le debit a zero sur-le-champ : laisser le dernier chiffre
    /// affiche donnerait a croire que la machine cherche encore.
    pub fn basculer(&self, vers: bool) -> bool {
        self.actif.store(vers, Ordering::Relaxed);
        if !vers {
            *self.debit.lock().unwrap_or_else(|e| e.into_inner()) = 0.0;
            *self.fenetre.lock().unwrap_or_else(|e| e.into_inner()) = (Instant::now(), 0);
        }
        vers
    }

    /// Declare `n` essais effectues.
    ///
    /// Appelee par la boucle du nœud apres chaque tentative de bloc. C'est le
    /// seul endroit ou le compteur monte.
    pub fn compter(&self, n: u64) {
        self.essais_total.fetch_add(n, Ordering::Relaxed);
        let mut f = self.fenetre.lock().unwrap_or_else(|e| e.into_inner());
        f.1 += n;
        let ecoule = f.0.elapsed();
        if ecoule >= FENETRE {
            let d = f.1 as f64 / ecoule.as_secs_f64();
            *self.debit.lock().unwrap_or_else(|e| e.into_inner()) = d;
            *f = (Instant::now(), 0);
        }
    }

    pub fn bloc_trouve(&self) {
        self.blocs.fetch_add(1, Ordering::Relaxed);
    }

    /// Debit courant, en essais par seconde.
    ///
    /// Zero tant qu'aucune fenetre n'est fermee : mieux vaut ne rien annoncer
    /// qu'annoncer un chiffre tire d'un dixieme de seconde.
    pub fn debit(&self) -> f64 {
        *self.debit.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn essais_total(&self) -> u64 {
        self.essais_total.load(Ordering::Relaxed)
    }

    pub fn blocs(&self) -> u64 {
        self.blocs.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_interrupteur_va_dans_les_deux_sens() {
        let m = Minage::new(false);
        assert!(!m.actif());
        assert!(m.basculer(true));
        assert!(m.actif());
        assert!(!m.basculer(false));
        assert!(!m.actif());
    }

    #[test]
    fn le_debit_reste_nul_tant_qu_aucune_fenetre_n_est_fermee() {
        let m = Minage::new(true);
        m.compter(10_000);
        // La fenetre dure une seconde : rien ne doit encore etre annonce.
        assert_eq!(m.debit(), 0.0, "un debit tire d'un instant n'est pas un debit");
        assert_eq!(m.essais_total(), 10_000);
    }

    #[test]
    fn le_debit_se_calcule_quand_la_fenetre_se_ferme() {
        let m = Minage::new(true);
        m.compter(1_000);
        std::thread::sleep(FENETRE + std::time::Duration::from_millis(60));
        m.compter(1_000);
        let d = m.debit();
        assert!(d > 500.0 && d < 4_000.0, "debit hors de tout bon sens : {d}");
    }

    #[test]
    fn eteindre_remet_le_debit_a_zero() {
        // Sans cela, le dernier chiffre mesure restait a l'ecran et laissait
        // croire que la machine cherchait encore.
        let m = Minage::new(true);
        m.compter(1_000);
        std::thread::sleep(FENETRE + std::time::Duration::from_millis(60));
        m.compter(1_000);
        assert!(m.debit() > 0.0);
        m.basculer(false);
        assert_eq!(m.debit(), 0.0);
    }

    #[test]
    fn le_total_ne_redescend_pas_quand_on_eteint() {
        // Le debit est une mesure de l'instant ; le total est une histoire.
        let m = Minage::new(true);
        m.compter(4_242);
        m.basculer(false);
        assert_eq!(m.essais_total(), 4_242);
    }

    #[test]
    fn les_blocs_se_comptent_a_part() {
        let m = Minage::new(true);
        m.bloc_trouve();
        m.bloc_trouve();
        assert_eq!(m.blocs(), 2);
        assert_eq!(m.essais_total(), 0, "un bloc trouve n'est pas un essai compte");
    }
}
