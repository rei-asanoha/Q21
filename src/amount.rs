//! Montants monetaires.
//!
//! Un `Amount` est un entier non signe d'unites indivisibles. Il n'existe aucune
//! conversion depuis un flottant, et c'est deliberé : `0.1 + 0.2 != 0.3` en
//! IEEE 754, et une monnaie qui accepte cette approximation perd de l'argent.
//!
//! Toute arithmetique est verifiee. Un depassement rend `None`, jamais un
//! resultat silencieusement faux.

use crate::consensus::{DECIMALS, MAX_SUPPLY, UNITS_PER_COIN};
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Amount = Amount(0);
    pub const MAX: Amount = Amount(MAX_SUPPLY);

    /// Construit un montant depuis un nombre d'unites indivisibles.
    pub const fn from_units(units: u64) -> Self {
        Amount(units)
    }

    /// Construit un montant depuis un nombre entier de Q21.
    pub fn from_coins(coins: u64) -> Option<Self> {
        coins.checked_mul(UNITS_PER_COIN).map(Amount)
    }

    pub const fn units(self) -> u64 {
        self.0
    }

    /// Vrai si le montant respecte le plafond du protocole.
    ///
    /// Un montant valide en tant que nombre peut rester invalide en tant que
    /// montant : aucune sortie ne peut porter plus que l'offre totale.
    pub const fn is_within_supply(self) -> bool {
        self.0 <= MAX_SUPPLY
    }

    pub fn checked_add(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_add(rhs.0).map(Amount)
    }

    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_sub(rhs.0).map(Amount)
    }

    /// Somme d'un iterateur de montants, en echouant sur depassement.
    ///
    /// Utilisee pour totaliser les sorties d'une transaction. Un `sum()` naif
    /// qui deborde silencieusement permettrait de fabriquer de la monnaie.
    pub fn checked_sum<I: IntoIterator<Item = Amount>>(iter: I) -> Option<Amount> {
        let mut total = Amount::ZERO;
        for a in iter {
            total = total.checked_add(a)?;
        }
        Some(total)
    }
}

impl fmt::Display for Amount {
    /// Formate en Q21 avec les 8 decimales, sans jamais passer par un flottant.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entier = self.0 / UNITS_PER_COIN;
        let frac = self.0 % UNITS_PER_COIN;
        write!(f, "{}.{:0width$}", entier, frac, width = DECIMALS as usize)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} Q21)", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affichage_exact_sans_flottant() {
        assert_eq!(Amount::from_units(0).to_string(), "0.00000000");
        assert_eq!(Amount::from_units(1).to_string(), "0.00000001");
        assert_eq!(Amount::from_units(100_000_000).to_string(), "1.00000000");
        assert_eq!(Amount::from_units(1_384_711_800).to_string(), "13.84711800");
    }

    #[test]
    fn l_addition_signale_le_depassement() {
        let presque = Amount::from_units(u64::MAX);
        assert_eq!(presque.checked_add(Amount::from_units(1)), None);
    }

    #[test]
    fn la_soustraction_ne_passe_jamais_sous_zero() {
        let a = Amount::from_units(10);
        assert_eq!(a.checked_sub(Amount::from_units(11)), None);
        assert_eq!(a.checked_sub(Amount::from_units(10)), Some(Amount::ZERO));
    }

    #[test]
    fn la_somme_refuse_de_deborder() {
        let gros = Amount::from_units(u64::MAX / 2);
        assert_eq!(Amount::checked_sum([gros, gros, gros]), None);
        assert_eq!(
            Amount::checked_sum([Amount::from_units(3), Amount::from_units(4)]),
            Some(Amount::from_units(7))
        );
    }

    #[test]
    fn le_plafond_est_reconnu() {
        assert!(Amount::MAX.is_within_supply());
        assert!(!Amount::from_units(MAX_SUPPLY + 1).is_within_supply());
    }
}
