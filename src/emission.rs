//! Calendrier d'emission.
//!
//! C'est le module le plus important du projet. Il repond a une seule question :
//! combien d'unites sont creees au bloc `h` ? Toute divergence entre deux noeuds
//! sur cette reponse scinde la chaine.
//!
//! Trois regles, non negociables.
//!
//! 1. **Aucun flottant.** `reward * 0.9971555` ne donne pas le meme resultat
//!    selon la plateforme, le niveau d'optimisation ou l'ordre des operations.
//!    `reward * 99_715_550 / 100_000_000` en entiers donne le meme bit partout.
//!
//! 2. **Arrondi vers le bas, toujours.** La division entiere de Rust tronque.
//!    C'est le comportement voulu et il est specifie ici : en cas de doute, le
//!    protocole emet moins, jamais plus.
//!
//! 3. **Le plafond est un maximum, et il est atteint — exactement.** La
//!    decroissance geometrique seule ne l'atteindrait jamais : tronquee a
//!    l'entier, elle s'arretait a l'annee 91 en laissant 137 899 Q21 jamais
//!    crees. Bitcoin assume ce trou ; Q21, dont le plafond est le nom, ne le
//!    pouvait pas. Un plancher de recompense ([`TAIL_REWARD`], 0,01 Q21)
//!    prend le relais quand la geometrique passe dessous, et l'emission
//!    cumulee est ecretee a [`EMISSION_CAP`] pres : le dernier bloc emetteur
//!    recoit le reliquat exact, puis la subvention est nulle pour toujours.
//!    Chaque unite du plafond finit par exister.

use crate::amount::Amount;
use crate::consensus::*;

/// Recompense de base pour une epoque donnee, rampe non appliquee.
///
/// Calculee par application repetee du facteur de decroissance. L'iteration est
/// volontaire : elle definit le resultat sans ambiguite, la ou une exponentielle
/// suivie d'un arrondi unique donnerait une valeur differente.
///
/// Cout : une multiplication u128 par epoque. Sur cent ans il y a environ 6 000
/// epoques, donc quelques microsecondes. Un noeud en production memorisera le
/// resultat ; la fonction reste la definition de reference.
pub fn epoch_base_reward(epoch: u64) -> u64 {
    let mut reward = INITIAL_REWARD;
    for _ in 0..epoch {
        reward = ((reward as u128 * DECAY_NUM) / DECAY_DEN) as u64;
        if reward == 0 {
            return 0;
        }
    }
    reward
}

/// Applique la rampe de demarrage a une recompense de base.
///
/// Sur les `SLOW_START_BLOCKS` premiers blocs, la recompense croit lineairement
/// depuis zero. Au bloc 0 elle vaut exactement zero : la seule creation
/// monetaire du bloc de genese est la piece de genese, traitee a part.
fn apply_slow_start(base: u64, height: u64) -> u64 {
    if height >= SLOW_START_BLOCKS {
        return base;
    }
    ((base as u128 * height as u128) / SLOW_START_BLOCKS as u128) as u64
}

/// Recompense de bloc a la hauteur `height`, en unites indivisibles.
///
/// C'est la fonction que le validateur appelle pour verifier qu'une coinbase
/// ne cree pas plus que son du.
///
/// # Pourquoi une difference de cumuls, et non une formule directe
///
/// La recompense vaut « ce que l'emission cumulee gagne a ce bloc ». L'ecrire
/// ainsi rend **impossible par construction** toute divergence entre la
/// recompense payee et le total emis — la ou deux formules separees peuvent
/// deriver l'une de l'autre. C'est aussi ce qui donne au dernier bloc emetteur
/// son reliquat exact : le cumul s'ecrete au plafond, la difference le suit.
pub fn block_subsidy(height: u64) -> Amount {
    if height == 0 {
        return Amount::from_units(0);
    }
    let apres = cumulative_emission(height).units();
    let avant = cumulative_emission(height - 1).units();
    Amount::from_units(apres - avant)
}

/// Total emis par le minage, du bloc 0 au bloc `height` inclus.
///
/// Hors piece de genese. Parcourt les epoques plutot que les blocs, sauf sur la
/// rampe ou chaque bloc a une valeur propre.
///
/// La recompense d'epoque est bornee en dessous par [`TAIL_REWARD`], et le
/// total est ecrete a [`EMISSION_CAP`] : c'est cette paire — plancher puis
/// ecretage — qui fait atteindre le plafond exactement, en temps fini.
pub fn cumulative_emission(height: u64) -> Amount {
    let mut total: u64 = 0;
    let mut epoch: u64 = 0;
    let mut base: u64 = INITIAL_REWARD;

    loop {
        let start = epoch * DECAY_EPOCH_BLOCKS;
        if start > height || total >= EMISSION_CAP {
            break;
        }
        let end = core::cmp::min(height, start + DECAY_EPOCH_BLOCKS - 1);
        let paye = base.max(TAIL_REWARD);

        if start < SLOW_START_BLOCKS {
            // La rampe est encore active : chaque bloc vaut une valeur differente.
            for h in start..=end {
                total = total.saturating_add(apply_slow_start(paye, h));
            }
        } else {
            let n = end - start + 1;
            total = total.saturating_add(paye.saturating_mul(n));
        }

        base = ((base as u128 * DECAY_NUM) / DECAY_DEN) as u64;
        epoch += 1;
    }

    // L'ecretage. Avant le plancher, cette ligne etait un garde-fou qui ne
    // servait jamais ; elle est desormais la regle qui termine l'emission, et
    // qui donne au dernier bloc son reliquat partiel.
    Amount::from_units(total.min(EMISSION_CAP))
}

/// Premiere hauteur dont la subvention est nulle : le plafond est atteint au
/// bloc precedent.
///
/// Recherche dichotomique sur le cumul, qui est monotone. Sert aux outils de
/// projection et aux epreuves ; le validateur, lui, n'en a pas besoin.
pub fn hauteur_de_fin_d_emission() -> u64 {
    // Borne haute sure : chaque bloc apres la rampe paie au moins le plancher,
    // donc le plafond est atteint avant `CAP / TAIL` blocs, rampe comprise. Une
    // borne astronomique ferait derouler des millions d'epoques par sondage.
    let haut_sur = EMISSION_CAP / TAIL_REWARD + SLOW_START_BLOCKS + DECAY_EPOCH_BLOCKS;
    let (mut bas, mut haut) = (0u64, haut_sur);
    while bas < haut {
        let m = bas + (haut - bas) / 2;
        if cumulative_emission(m).units() >= EMISSION_CAP {
            haut = m;
        } else {
            bas = m + 1;
        }
    }
    bas + 1
}

/// Offre totale en circulation apres le bloc `height`, piece de genese comprise.
pub fn total_supply_at(height: u64) -> Amount {
    Amount::from_units(cumulative_emission(height).units() + GENESIS_PREMINT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_bloc_de_genese_n_emet_rien_par_le_minage() {
        assert_eq!(block_subsidy(0).units(), 0);
    }

    #[test]
    fn la_rampe_monte_bien_depuis_zero() {
        let plein = epoch_base_reward(SLOW_START_BLOCKS / DECAY_EPOCH_BLOCKS);
        let a_mi_rampe = block_subsidy(SLOW_START_BLOCKS / 2).units();
        let apres = block_subsidy(SLOW_START_BLOCKS).units();

        assert!(a_mi_rampe > 0);
        assert!(a_mi_rampe < apres);
        assert_eq!(apres, plein);
        // A mi-rampe on doit etre proche de la moitie, aux effets de
        // decroissance pres sur ces quelques epoques.
        assert!(a_mi_rampe * 2 > apres * 9 / 10);
    }

    #[test]
    fn la_recompense_decroit_de_facon_monotone_apres_la_rampe() {
        let mut precedente = u64::MAX;
        for epoch in 0..500 {
            let r = epoch_base_reward(epoch);
            assert!(r <= precedente, "epoque {epoch} : la recompense a augmente");
            precedente = r;
        }
    }

    #[test]
    fn la_demi_vie_est_bien_d_environ_quatre_ans() {
        let quatre_ans = BLOCKS_PER_YEAR * 4;
        let epoch = quatre_ans / DECAY_EPOCH_BLOCKS;
        let r = epoch_base_reward(epoch);
        let moitie = INITIAL_REWARD / 2;
        // Tolerance de 1 % : la granularite des epoques ne tombe pas pile.
        assert!(
            r > moitie * 99 / 100 && r < moitie * 101 / 100,
            "demi-vie hors cible : {r} attendu ~{moitie}"
        );
    }

    /// La promesse du nom du projet : chaque unite du plafond finit par exister.
    ///
    /// # Le defaut que cette epreuve fige
    ///
    /// Sans le plancher de queue, la decroissance tronquee s'arretait a
    /// l'annee 91 en laissant 137 899 Q21 jamais crees. 21 000 001 etait une
    /// asymptote. Cette epreuve exige l'egalite exacte, au bloc pres.
    #[test]
    fn l_emission_atteint_le_plafond_exactement() {
        let fin = hauteur_de_fin_d_emission();
        // Le plafond est atteint, exactement — pas approche.
        assert_eq!(cumulative_emission(fin).units(), EMISSION_CAP);
        assert_eq!(total_supply_at(fin).units(), MAX_SUPPLY);
        // Le bloc precedent ne l'avait pas encore atteint : `fin` est bien la
        // premiere hauteur morte.
        assert!(cumulative_emission(fin.saturating_sub(2)).units() < EMISSION_CAP);
        // Apres, plus rien, pour toujours — echantillonne loin devant.
        assert_eq!(block_subsidy(fin).units(), 0);
        assert_eq!(block_subsidy(fin + 1).units(), 0);
        assert_eq!(block_subsidy(fin + BLOCKS_PER_YEAR * 100).units(), 0);
        assert_eq!(
            cumulative_emission(fin + BLOCKS_PER_YEAR * 500).units(),
            EMISSION_CAP
        );
        // Le dernier bloc emetteur recoit un reliquat partiel, jamais plus que
        // le plancher : c'est l'ecretage qui le taille.
        let reliquat = block_subsidy(fin - 1).units();
        assert!(
            reliquat > 0 && reliquat <= TAIL_REWARD,
            "reliquat : {reliquat}"
        );
    }

    /// Le plancher prend le relais quand la geometrique passe dessous — et pas
    /// avant.
    #[test]
    fn le_plancher_ne_mord_que_la_queue() {
        // A l'an 20, la geometrique domine encore tres largement.
        let a_20_ans = block_subsidy(BLOCKS_PER_YEAR * 20).units();
        assert!(a_20_ans > TAIL_REWARD * 40, "le plancher mord trop tot");
        // A l'an 60, c'est le plancher qui paie, tel quel.
        assert_eq!(block_subsidy(BLOCKS_PER_YEAR * 60).units(), TAIL_REWARD);
    }

    /// La subvention est la difference des cumuls — verifie terme a terme.
    ///
    /// C'est la coherence qui interdit qu'un validateur et un compteur d'offre
    /// divergent d'une unite. On la verifie sur la rampe (chaque bloc y a une
    /// valeur propre) et sur un morceau de plein regime.
    #[test]
    fn la_subvention_somme_exactement_au_cumul() {
        let mut somme = 0u64;
        for h in 0..=2_000u64 {
            somme += block_subsidy(h).units();
        }
        assert_eq!(somme, cumulative_emission(2_000).units());
    }

    /// Le test qui compte. Si celui-ci tombe, la monnaie est cassee.
    #[test]
    fn le_plafond_n_est_jamais_franchi_sur_deux_cents_ans() {
        for annee in [1u64, 2, 4, 8, 12, 20, 30, 45, 60, 100, 150, 200] {
            let h = BLOCKS_PER_YEAR * annee;
            let emis = cumulative_emission(h).units();
            assert!(
                emis <= EMISSION_CAP,
                "an {annee} : plafond franchi ({emis} > {EMISSION_CAP})"
            );
            let total = total_supply_at(h).units();
            assert!(
                total <= MAX_SUPPLY,
                "an {annee} : offre totale au-dela de 21 000 001"
            );
        }
    }

    #[test]
    fn l_emission_est_monotone_croissante() {
        let mut precedent = 0u64;
        for annee in 1..=60u64 {
            let e = cumulative_emission(BLOCKS_PER_YEAR * annee).units();
            assert!(e >= precedent, "an {annee} : l'emission cumulee a baisse");
            precedent = e;
        }
    }

    /// Le garde-fou le plus important du crate.
    ///
    /// Il ne teste pas une trajectoire echantillonnee : il borne la serie
    /// entiere. La somme geometrique discrete a l'infini vaut
    /// `R0 * EPOCH * DEN / (DEN - NUM)`, avant tout arrondi. Si cette borne tient
    /// sous le plafond, alors l'emission reelle — que l'arrondi vers le bas ne
    /// peut que reduire — y tient aussi, a toute hauteur, pour toujours.
    ///
    /// Ce test a mordu des la premiere execution : la valeur initialement
    /// derivee de la formule continue (13,847118 Q21) placait la borne 0,14 %
    /// au-dessus du plafond. Voir `consensus::INITIAL_REWARD`.
    #[test]
    fn la_recompense_initiale_respecte_le_plafond() {
        let denom = DECAY_DEN - DECAY_NUM;
        let total_theorique =
            (INITIAL_REWARD as u128 * DECAY_EPOCH_BLOCKS as u128 * DECAY_DEN) / denom;
        assert!(
            total_theorique <= EMISSION_CAP as u128,
            "la somme infinie theorique depasse le plafond : {total_theorique} > {EMISSION_CAP}"
        );
    }

    /// Verifie que la recompense retenue est la plus grande valeur admissible.
    ///
    /// Sans ce test, on pourrait corriger le depassement en divisant R0 par deux
    /// et en pretendant que le probleme est regle, tout en emettant moitie moins
    /// que prevu.
    #[test]
    fn la_recompense_initiale_est_maximale() {
        let denom = DECAY_DEN - DECAY_NUM;
        let borne = ((INITIAL_REWARD + 1) as u128 * DECAY_EPOCH_BLOCKS as u128 * DECAY_DEN) / denom;
        assert!(
            borne > EMISSION_CAP as u128,
            "une unite de plus tiendrait encore : R0 est sous-optimal"
        );
    }

    /// Verifie la trajectoire contre la simulation de reference du livre blanc.
    #[test]
    fn la_trajectoire_correspond_au_livre_blanc() {
        let attendu: [(u64, u64); 4] = [
            (2, 6_012_892),
            (4, 10_362_141),
            (8, 15_612_144),
            (20, 20_205_888),
        ];
        for (annee, coins_attendus) in attendu {
            // La simulation de reference somme les blocs 0..N exclu ; ici
            // `cumulative_emission` inclut le bloc N. On aligne les bornes
            // plutot que d'elargir une tolerance, sans quoi le test laisserait
            // passer une derive reelle d'un bloc de recompense.
            let emis = cumulative_emission(BLOCKS_PER_YEAR * annee - 1).units() / UNITS_PER_COIN;
            assert_eq!(
                emis, coins_attendus,
                "an {annee} : divergence avec la simulation de reference"
            );
        }
    }

    #[test]
    fn la_subvention_finit_par_s_eteindre() {
        // Loin dans le temps, l'arrondi vers le bas finit par ramener la
        // recompense a zero. La securite ne repose alors plus que sur les frais.
        // C'est la tension documentee en section 9 du livre blanc.
        assert_eq!(epoch_base_reward(20_000), 0);
    }
}
