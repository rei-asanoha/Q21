//! MuHash : empreinte incrementale et sans ordre du jeu d'UTXO.
//!
//! # Le probleme que ce module resout
//!
//! Un instantane de l'etat monetaire ([`crate::state::Snapshot`]) sait deja se
//! sérialiser et se relire. Mais rien, jusqu'ici, ne permettait de dire d'un
//! instantane **venu d'ailleurs** : « c'est bien le jeu d'UTXO de la hauteur H,
//! pas une version ou l'on a discretement deplace la propriete d'une sortie ».
//! La somme de controle SHA-256 ne prouve que l'integrite du fichier, pas sa
//! fidelite a la chaine ; et le sceau du repertoire refuse par construction tout
//! fichier qui n'a pas ete ecrit sur place. Le commentaire de `state.rs` le
//! nomme comme une dette datee : « seul un engagement sur le jeu d'UTXO y
//! repondrait ». Ce module est cet engagement.
//!
//! # Ce qu'est un MuHash
//!
//! On associe a chaque sortie non depensee un element d'un grand groupe
//! multiplicatif — les entiers modulo un nombre premier de 3072 bits — puis on
//! **multiplie** tous ces elements. Le produit est l'empreinte de l'ensemble.
//!
//! Deux proprietes en decoulent, et ce sont exactement celles qu'il faut :
//!
//! 1. **L'ordre n'importe pas.** La multiplication est commutative : deux noeuds
//!    qui ont le meme jeu d'UTXO calculent la meme empreinte, quel que soit
//!    l'ordre dans lequel ils ont recu les blocs.
//! 2. **La mise a jour est incrementale.** Ajouter une sortie, c'est multiplier ;
//!    en retirer une, c'est diviser. On ne rehashe jamais l'ensemble entier — ce
//!    qui distingue un MuHash d'une simple somme SHA-256 triee, et ce qui rend
//!    possible, plus tard, un engagement tenu a jour a chaque bloc.
//!
//! # Le choix du module
//!
//! `P = 2^3072 - 1103717`, premier. C'est le module de Bitcoin Core (classe
//! `MuHash3072`), retenu pour deux raisons mesurables : 3072 bits placent la
//! resistance aux collisions bien au-dela de tout horizon pratique, et la forme
//! `2^3072 - c` avec `c` petit rend la reduction modulaire presque gratuite —
//! un produit se replie par `lo + c * hi`, sans division.
//!
//! # Ce que ce module n'importe pas
//!
//! Aucune dependance. L'arithmetique 3072 bits est ecrite ici, comme l'est celle
//! de 256 bits dans `uint.rs`, et pour la meme raison : confier la definition
//! d'un engagement de consensus a un crate d'arithmetique large reviendrait a la
//! confier a ses futures mises a jour. L'expansion d'un condensat de 256 bits en
//! un element de 3072 bits se fait au SHA-256 en mode compteur — le meme SHA-256
//! taggé qui sert partout ailleurs.

use crate::hash::{tagged_hash, tagged_hash_parts, Hash256};

/// Nombre de membres de 64 bits : 48 x 64 = 3072.
const LIMBS: usize = 48;

/// Le module est `P = 2^3072 - C`. `C` tient sur un seul mot de 64 bits, ce qui
/// est toute l'astuce : `2^3072 ≡ C (mod P)`, donc replier un produit revient a
/// remplacer sa moitie haute par `C` fois cette moitie, ajoutee a la basse.
const C: u64 = 1103717;

/// Membres de `P = 2^3072 - C`, du poids faible au poids fort.
///
/// `2^3072 - 1` vaut « tous les membres a `u64::MAX` ». Soustraire `C` ne touche
/// que le membre de poids faible : `P[0] = u64::MAX - (C - 1)`, le reste inchange.
const P_LIMBS: [u64; LIMBS] = {
    let mut p = [u64::MAX; LIMBS];
    p[0] = u64::MAX - (C - 1);
    p
};

/// Exposant de l'inverse de Fermat : `P - 2`. `P` etant premier, `x^(P-2) ≡
/// x^(-1) (mod P)` pour tout `x` non nul. `P - 2 = 2^3072 - (C + 2)`, donc seul
/// le membre de poids faible differe de `u64::MAX`.
const EXP_INVERSE: [u64; LIMBS] = {
    let mut e = [u64::MAX; LIMBS];
    e[0] = u64::MAX - (C + 1);
    e
};

/// Element du groupe multiplicatif modulo `P`, toujours maintenu reduit dans
/// `[0, P)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Num3072 {
    /// Membres de 64 bits, du poids faible (indice 0) au poids fort.
    limbs: [u64; LIMBS],
}

impl Num3072 {
    /// L'element neutre de la multiplication.
    pub const fn one() -> Num3072 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 1;
        Num3072 { limbs }
    }

    fn is_one(&self) -> bool {
        if self.limbs[0] != 1 {
            return false;
        }
        for &l in &self.limbs[1..] {
            if l != 0 {
                return false;
            }
        }
        true
    }

    /// Ajoute un scalaire de 64 bits en place, en propageant la retenue. Rend la
    /// retenue finale (0 ou 1) : ce qui deborde au-dela de `2^3072`.
    fn add_scalar(limbs: &mut [u64; LIMBS], s: u64) -> u64 {
        let mut carry = s;
        for l in limbs.iter_mut() {
            let (v, c) = l.overflowing_add(carry);
            *l = v;
            carry = c as u64;
            if carry == 0 {
                break;
            }
        }
        carry
    }

    /// Ajoute un autre nombre de 48 membres en place. Rend la retenue finale.
    fn add_assign(limbs: &mut [u64; LIMBS], autre: &[u64; LIMBS]) -> u64 {
        let mut carry = 0u128;
        for (l, a) in limbs.iter_mut().zip(autre.iter()) {
            let s = *l as u128 + *a as u128 + carry;
            *l = s as u64;
            carry = s >> 64;
        }
        carry as u64
    }

    /// `r >= P` ? Compare membre a membre depuis le poids fort.
    fn geq_p(limbs: &[u64; LIMBS]) -> bool {
        for i in (0..LIMBS).rev() {
            if limbs[i] != P_LIMBS[i] {
                return limbs[i] > P_LIMBS[i];
            }
        }
        true // egal a P : compte comme >= P, donc a reduire.
    }

    /// Reduit dans `[0, P)` un nombre deja inferieur a `2^3072`.
    ///
    /// Si `r >= P`, alors `r - P = r + C - 2^3072` : on ajoute `C` et on laisse
    /// la retenue s'evaporer au-dela de `2^3072`.
    fn reduce_once(limbs: &mut [u64; LIMBS]) {
        if Self::geq_p(limbs) {
            let _ = Self::add_scalar(limbs, C);
        }
    }

    /// Produit complet de deux nombres de 48 membres, sur 96 membres.
    #[allow(clippy::needless_range_loop)]
    fn mul_wide(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; 2 * LIMBS] {
        let mut out = [0u64; 2 * LIMBS];
        for i in 0..LIMBS {
            let ai = a[i] as u128;
            let mut carry: u128 = 0;
            for j in 0..LIMBS {
                let cur = out[i + j] as u128 + ai * b[j] as u128 + carry;
                out[i + j] = cur as u64;
                carry = cur >> 64;
            }
            let mut k = i + LIMBS;
            while carry != 0 {
                let cur = out[k] as u128 + carry;
                out[k] = cur as u64;
                carry = cur >> 64;
                k += 1;
            }
        }
        out
    }

    /// Replie un produit de 96 membres en un element reduit modulo `P`.
    ///
    /// `produit = bas + 2^3072 * haut ≡ bas + C * haut (mod P)`. Le terme
    /// `C * haut` reintroduit un petit debordement, qu'on replie a son tour :
    /// deux ou trois tours suffisent, `C` etant petit.
    fn reduce_wide(produit: &[u64; 2 * LIMBS]) -> Num3072 {
        let mut bas = [0u64; LIMBS];
        bas.copy_from_slice(&produit[..LIMBS]);

        // C * haut, membre par membre, avec sa retenue de poids fort.
        let mut ch = [0u64; LIMBS];
        let mut carry: u128 = 0;
        for i in 0..LIMBS {
            let cur = C as u128 * produit[LIMBS + i] as u128 + carry;
            ch[i] = cur as u64;
            carry = cur >> 64;
        }
        // `over` compte les paquets de `2^3072` a replier : la retenue de `C*haut`
        // plus celle de l'addition qui suit.
        let mut over = carry as u64;
        over += Self::add_assign(&mut bas, &ch);

        // Replie le debordement restant tant qu'il en reste. `C * over` tient sur
        // 64 bits (`over < 2^21`, `C < 2^21`, donc `C*over < 2^42`).
        while over != 0 {
            over = Self::add_scalar(&mut bas, C.wrapping_mul(over));
        }
        Self::reduce_once(&mut bas);
        Num3072 { limbs: bas }
    }

    /// Multiplication modulo `P`. Les deux facteurs sont supposes reduits.
    pub fn mul(&self, autre: &Num3072) -> Num3072 {
        Self::reduce_wide(&Self::mul_wide(&self.limbs, &autre.limbs))
    }

    /// Elevation a une puissance dont l'exposant est donne en 48 membres, par
    /// carres et multiplications, du bit de poids fort au bit de poids faible.
    fn pow(&self, exp: &[u64; LIMBS]) -> Num3072 {
        let mut resultat = Num3072::one();
        for i in (0..LIMBS).rev() {
            for b in (0..64).rev() {
                resultat = resultat.mul(&resultat);
                if (exp[i] >> b) & 1 == 1 {
                    resultat = resultat.mul(self);
                }
            }
        }
        resultat
    }

    /// Inverse multiplicatif modulo `P`, par le petit theoreme de Fermat.
    ///
    /// L'inverse de l'element neutre est lui-meme : on court-circuite alors les
    /// 3072 carres, ce qui rend gratuit le cas ou aucun retrait n'a eu lieu.
    pub fn inverse(&self) -> Num3072 {
        if self.is_one() {
            return Num3072::one();
        }
        self.pow(&EXP_INVERSE)
    }

    /// Construit un element a partir de 384 octets d'entropie, du poids faible au
    /// poids fort. La valeur brute est inferieure a `2^3072` : une seule
    /// soustraction conditionnelle suffit a la ramener sous `P`. La valeur nulle,
    /// d'une probabilite de `2^-3072`, est remontee a l'element neutre pour ne
    /// jamais quitter le groupe.
    fn from_wide_bytes(octets: &[u8; LIMBS * 8]) -> Num3072 {
        let mut limbs = [0u64; LIMBS];
        for (i, l) in limbs.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&octets[i * 8..i * 8 + 8]);
            *l = u64::from_le_bytes(w);
        }
        Self::reduce_once(&mut limbs);
        let n = Num3072 { limbs };
        if limbs.iter().all(|&l| l == 0) {
            Num3072::one()
        } else {
            n
        }
    }

    /// Serialise en 384 octets, du poids faible au poids fort. Sert d'entree au
    /// condensat final : deux etats identiques produisent les memes octets.
    fn to_bytes(self) -> [u8; LIMBS * 8] {
        let mut out = [0u8; LIMBS * 8];
        for (i, l) in self.limbs.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&l.to_le_bytes());
        }
        out
    }
}

/// Domaine du condensat qui amorce un element de groupe a partir d'une donnee.
const TAG_ELEMENT: &str = "Q21/muhash/element";
/// Domaine de l'expansion en mode compteur.
const TAG_EXPANSION: &str = "Q21/muhash/expansion";
/// Domaine du condensat final de l'empreinte.
const TAG_EMPREINTE: &str = "Q21/muhash/empreinte";

/// Amorce l'element de groupe associe a une donnee.
///
/// La donnee est d'abord condensee en 256 bits (resistance aux collisions du
/// SHA-256 taggé), puis ce germe est etendu a 3072 bits par douze condensats en
/// mode compteur. Le resultat est un entier de 3072 bits, uniformement reparti,
/// fonction deterministe de la donnee.
fn element(donnee: &[u8]) -> Num3072 {
    let germe = tagged_hash(TAG_ELEMENT, donnee);
    let mut large = [0u8; LIMBS * 8];
    for i in 0..12u8 {
        let bloc = tagged_hash_parts(TAG_EXPANSION, &[germe.as_bytes(), &[i]]);
        large[i as usize * 32..i as usize * 32 + 32].copy_from_slice(bloc.as_bytes());
    }
    Num3072::from_wide_bytes(&large)
}

/// Accumulateur MuHash : une empreinte de l'ensemble des sorties inserees.
///
/// On tient deux produits — un numerateur et un denominateur — plutot qu'un
/// seul. Inserer multiplie le numerateur ; retirer multiplie le denominateur.
/// L'unique division — couteuse, car elle demande un inverse — est repoussee au
/// moment du condensat : `empreinte = numerateur / denominateur`. Un ensemble
/// construit par insertions seules ne paie donc jamais d'inverse.
#[derive(Clone, Copy, Debug)]
pub struct MuHash {
    numerateur: Num3072,
    denominateur: Num3072,
}

impl Default for MuHash {
    fn default() -> Self {
        Self::new()
    }
}

impl MuHash {
    /// L'empreinte de l'ensemble vide : le produit vide, c'est-a-dire l'element
    /// neutre au numerateur comme au denominateur.
    pub fn new() -> MuHash {
        MuHash {
            numerateur: Num3072::one(),
            denominateur: Num3072::one(),
        }
    }

    /// Ajoute une sortie a l'empreinte.
    pub fn insert(&mut self, donnee: &[u8]) {
        self.numerateur = self.numerateur.mul(&element(donnee));
    }

    /// Retire une sortie de l'empreinte. `insert` puis `remove` de la meme
    /// donnee ramene exactement a l'etat de depart.
    pub fn remove(&mut self, donnee: &[u8]) {
        self.denominateur = self.denominateur.mul(&element(donnee));
    }

    /// Fond une autre empreinte dans celle-ci — utile pour replier l'ensemble en
    /// morceaux independants avant de les combiner. Associatif et commutatif.
    pub fn combine(&mut self, autre: &MuHash) {
        self.numerateur = self.numerateur.mul(&autre.numerateur);
        self.denominateur = self.denominateur.mul(&autre.denominateur);
    }

    /// Condensat de 256 bits de l'empreinte courante.
    ///
    /// C'est ici, et une seule fois, qu'on divise : `numerateur * inverse(
    /// denominateur)`. Si rien n'a ete retire, le denominateur vaut l'element
    /// neutre et l'inverse est gratuit.
    pub fn digest(&self) -> Hash256 {
        let accumule = if self.denominateur.is_one() {
            self.numerateur
        } else {
            self.numerateur.mul(&self.denominateur.inverse())
        };
        tagged_hash(TAG_EMPREINTE, &accumule.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fabrique un `Num3072` a partir de petits membres de poids faible.
    fn num(bas: &[u64]) -> Num3072 {
        let mut limbs = [0u64; LIMBS];
        limbs[..bas.len()].copy_from_slice(bas);
        Num3072 { limbs }
    }

    #[test]
    fn deux_puissance_3072_vaut_c() {
        // Un produit dont seule la moitie haute porte un 1 represente 2^3072.
        let mut produit = [0u64; 2 * LIMBS];
        produit[LIMBS] = 1;
        let r = Num3072::reduce_wide(&produit);
        assert_eq!(r, num(&[C]), "2^3072 doit se replier sur C");

        // 2^3072 + 5 -> C + 5.
        produit[0] = 5;
        assert_eq!(Num3072::reduce_wide(&produit), num(&[C + 5]));
    }

    #[test]
    fn petit_produit_sans_reduction() {
        assert_eq!(num(&[2]).mul(&num(&[3])), num(&[6]));
        assert_eq!(num(&[7]).mul(&Num3072::one()), num(&[7]));
    }

    #[test]
    fn le_carre_de_p_moins_un_vaut_un() {
        // (P-1)^2 = P^2 - 2P + 1 ≡ 1 (mod P). Test franc de la reduction sur des
        // membres tous pleins.
        let mut pm1 = P_LIMBS;
        pm1[0] -= 1; // P - 1, deja reduit (< P).
        let x = Num3072 { limbs: pm1 };
        assert_eq!(x.mul(&x), Num3072::one());
    }

    #[test]
    fn la_multiplication_est_commutative_et_associative() {
        let a = element(b"alice");
        let b = element(b"bob");
        let c = element(b"carol");
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
    }

    #[test]
    fn un_element_fois_son_inverse_vaut_un() {
        for graine in [b"x".as_slice(), b"une sortie", b"\x00\x01\x02", &[0xff; 40]] {
            let x = element(graine);
            assert_eq!(x.mul(&x.inverse()), Num3072::one(), "echec sur {graine:?}");
        }
    }

    #[test]
    fn l_empreinte_ignore_l_ordre_d_insertion() {
        let mut a = MuHash::new();
        a.insert(b"un");
        a.insert(b"deux");
        a.insert(b"trois");

        let mut b = MuHash::new();
        b.insert(b"trois");
        b.insert(b"un");
        b.insert(b"deux");

        assert_eq!(a.digest(), b.digest(), "l'ordre ne doit pas compter");
    }

    #[test]
    fn inserer_puis_retirer_annule() {
        let mut vide = MuHash::new();
        let empreinte_vide = vide.digest();

        vide.insert(b"une sortie ephemere");
        assert_ne!(vide.digest(), empreinte_vide);
        vide.remove(b"une sortie ephemere");
        assert_eq!(
            vide.digest(),
            empreinte_vide,
            "insert puis remove doit revenir a l'ensemble vide"
        );
    }

    #[test]
    fn retirer_puis_inserer_annule_aussi() {
        // Le denominateur peut passer devant : l'ordre des deux operations ne
        // change pas le resultat, car tout se resout a la division finale.
        let mut a = MuHash::new();
        a.insert(b"p");
        a.insert(b"q");
        let cible = a.digest();

        let mut b = MuHash::new();
        b.remove(b"parasite");
        b.insert(b"p");
        b.insert(b"parasite");
        b.insert(b"q");
        assert_eq!(b.digest(), cible);
    }

    #[test]
    fn combiner_equivaut_a_tout_inserer() {
        let mut entier = MuHash::new();
        for d in [b"a".as_slice(), b"b", b"c", b"d"] {
            entier.insert(d);
        }

        let mut gauche = MuHash::new();
        gauche.insert(b"a");
        gauche.insert(b"b");
        let mut droite = MuHash::new();
        droite.insert(b"c");
        droite.insert(b"d");
        gauche.combine(&droite);

        assert_eq!(gauche.digest(), entier.digest());
    }

    #[test]
    fn une_sortie_differente_change_l_empreinte() {
        let mut a = MuHash::new();
        a.insert(b"sortie A");
        let mut b = MuHash::new();
        b.insert(b"sortie B");
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn l_empreinte_vide_est_stable_et_deterministe() {
        assert_eq!(MuHash::new().digest(), MuHash::new().digest());
    }

    #[test]
    fn aller_retour_octets_sur_un_element() {
        let x = element(b"peu importe");
        let y = Num3072::from_wide_bytes(&x.to_bytes());
        assert_eq!(x, y);
    }
}
