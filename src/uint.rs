//! Entiers 256 bits.
//!
//! Les cibles de difficulte vivent dans l'espace des condensats : 256 bits. Rust
//! s'arrete a 128, et importer un crate d'arithmetique large pour du code de
//! consensus reviendrait a confier la definition de la monnaie a une dependance.
//!
//! On implemente donc le minimum strictement necessaire : comparaison,
//! addition, multiplication et division par un scalaire 64 bits, et les
//! conversions. Rien de plus. Chaque operation signale son debordement plutot
//! que de l'absorber en silence.

use core::cmp::Ordering;

/// Entier non signe de 256 bits, stocke en quatre membres de 64 bits,
/// du poids faible au poids fort.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Hash)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub const fn from_u64(v: u64) -> U256 {
        U256([v, 0, 0, 0])
    }

    /// Depuis 32 octets gros-boutistes, l'ordre dans lequel se lit un condensat.
    pub fn from_be_bytes(b: &[u8; 32]) -> U256 {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().rev().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i * 8..i * 8 + 8]);
            *limb = u64::from_be_bytes(w);
        }
        U256(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().rev().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0u64; 4]
    }

    /// Les 64 bits de poids faible. Tronque en silence : a n'employer que la ou
    /// l'appelant sait deja que la valeur y tient (un quotient borne, un
    /// compteur), jamais sur une cible ou un montant.
    pub fn low_u64(self) -> u64 {
        self.0[0]
    }

    /// Nombre de bits significatifs. Zero en compte zero.
    pub fn bits(self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    pub fn checked_add(self, rhs: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (s1, c1) = a.overflowing_add(*b);
            let (s2, c2) = s1.overflowing_add(carry);
            *o = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Multiplication par un scalaire 64 bits.
    pub fn checked_mul_u64(self, rhs: u64) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for (o, a) in out.iter_mut().zip(self.0.iter()) {
            let p = *a as u128 * rhs as u128 + carry;
            *o = p as u64;
            carry = p >> 64;
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Division par un scalaire 64 bits. Rend `None` si le diviseur est nul.
    pub fn checked_div_u64(self, rhs: u64) -> Option<U256> {
        if rhs == 0 {
            return None;
        }
        let mut out = [0u64; 4];
        let mut reste: u128 = 0;
        for i in (0..4).rev() {
            let courant = (reste << 64) | self.0[i] as u128;
            out[i] = (courant / rhs as u128) as u64;
            reste = courant % rhs as u128;
        }
        Some(U256(out))
    }

    /// Addition modulo 2^256, sans signalement de debordement.
    ///
    /// Utilisee par la boucle de melange de la preuve de travail, ou le
    /// debordement est voulu : on melange, on ne compte pas de la monnaie.
    pub fn wrapping_add(self, rhs: U256) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (s1, c1) = a.overflowing_add(*b);
            let (s2, c2) = s1.overflowing_add(carry);
            *o = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        U256(out)
    }

    /// Complement a un.
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// Soustraction, `None` si le resultat serait negatif.
    pub fn checked_sub(self, rhs: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut emprunt = 0u64;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (d1, b1) = a.overflowing_sub(*b);
            let (d2, b2) = d1.overflowing_sub(emprunt);
            *o = d2;
            emprunt = (b1 as u64) + (b2 as u64);
        }
        if emprunt != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Bit d'indice `i`, du poids faible au poids fort.
    pub fn bit(self, i: usize) -> bool {
        if i >= 256 {
            return false;
        }
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, i: usize) {
        if i < 256 {
            self.0[i / 64] |= 1u64 << (i % 64);
        }
    }

    /// Decalage d'un bit vers la gauche.
    fn shl1(self) -> U256 {
        let mut out = [0u64; 4];
        let mut retenue = 0u64;
        for (o, a) in out.iter_mut().zip(self.0.iter()) {
            *o = (a << 1) | retenue;
            retenue = a >> 63;
        }
        U256(out)
    }

    /// Division euclidienne complete, par division binaire longue.
    ///
    /// Necessaire au calcul du travail d'un bloc, qui vaut `2^256 / (cible + 1)`
    /// et ne se ramene pas a une division par un scalaire 64 bits. Deux cent
    /// cinquante-six iterations : negligeable a la frequence ou on l'appelle.
    pub fn div_rem(self, rhs: U256) -> Option<(U256, U256)> {
        if rhs.is_zero() {
            return None;
        }
        let mut q = U256::ZERO;
        let mut r = U256::ZERO;
        for i in (0..256).rev() {
            r = r.shl1();
            if self.bit(i) {
                r.set_bit(0);
            }
            if r >= rhs {
                r = r.checked_sub(rhs).expect("r >= rhs verifie juste avant");
                q.set_bit(i);
            }
        }
        Some((q, r))
    }

    /// Multiplication puis division, en evitant le debordement intermediaire.
    ///
    /// Indispensable a l'ajustement de difficulte : `cible * duree / cible_duree`
    /// deborde si l'on multiplie d'abord. On divise donc d'abord quand le
    /// produit ne tient pas.
    pub fn mul_div(self, mul: u64, div: u64) -> Option<U256> {
        if div == 0 {
            return None;
        }
        match self.checked_mul_u64(mul) {
            Some(p) => p.checked_div_u64(div),
            None => {
                // Le produit deborde : on perd un peu de precision en divisant
                // d'abord, ce qui est acceptable pour une cible de difficulte.
                self.checked_div_u64(div)?.checked_mul_u64(mul)
            }
        }
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                autre => return autre,
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_aller_retour_en_octets() {
        for v in [0u64, 1, u64::MAX, 0x0123_4567_89ab_cdef] {
            let u = U256::from_u64(v);
            assert_eq!(U256::from_be_bytes(&u.to_be_bytes()), u);
        }
        let grand = U256([1, 2, 3, 4]);
        assert_eq!(U256::from_be_bytes(&grand.to_be_bytes()), grand);
    }

    #[test]
    fn l_ordre_gros_boutiste_est_respecte() {
        // La valeur 1 doit se lire comme le tout dernier octet.
        let b = U256::ONE.to_be_bytes();
        assert_eq!(b[31], 1);
        assert_eq!(b[..31], [0u8; 31]);
    }

    #[test]
    fn comparaison_sur_les_membres_hauts() {
        assert!(U256([0, 0, 0, 1]) > U256([u64::MAX, u64::MAX, u64::MAX, 0]));
        assert!(U256::ZERO < U256::ONE);
        assert_eq!(U256::MAX.cmp(&U256::MAX), Ordering::Equal);
    }

    #[test]
    fn addition_avec_retenue() {
        let a = U256([u64::MAX, 0, 0, 0]);
        assert_eq!(a.checked_add(U256::ONE), Some(U256([0, 1, 0, 0])));
        assert_eq!(U256::MAX.checked_add(U256::ONE), None);
    }

    #[test]
    fn multiplication_et_division_sont_inverses() {
        let a = U256([0x1234_5678, 0xabcd, 0, 0]);
        let p = a.checked_mul_u64(1000).unwrap();
        assert_eq!(p.checked_div_u64(1000), Some(a));
    }

    #[test]
    fn la_multiplication_signale_le_debordement() {
        assert_eq!(U256::MAX.checked_mul_u64(2), None);
        assert_eq!(U256::MAX.checked_mul_u64(1), Some(U256::MAX));
    }

    #[test]
    fn la_division_par_zero_est_refusee() {
        assert_eq!(U256::ONE.checked_div_u64(0), None);
        assert_eq!(U256::ONE.mul_div(5, 0), None);
    }

    #[test]
    fn mul_div_survit_au_debordement_intermediaire() {
        // Le produit deborderait, mais le resultat final tient largement.
        let presque_max = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1]);
        let r = presque_max.mul_div(4, 4).expect("mul_div doit s'en sortir");
        // Tolerance : la voie de repli divise d'abord et perd quelques unites.
        let ecart_relatif_ok = r <= presque_max && r >= presque_max.checked_div_u64(2).unwrap();
        assert!(ecart_relatif_ok);
    }

    #[test]
    fn comptage_des_bits() {
        assert_eq!(U256::ZERO.bits(), 0);
        assert_eq!(U256::ONE.bits(), 1);
        assert_eq!(U256::from_u64(u64::MAX).bits(), 64);
        assert_eq!(U256([0, 1, 0, 0]).bits(), 65);
        assert_eq!(U256::MAX.bits(), 256);
    }
}
