//! BLAKE2b, tel que decrit par le RFC 7693.
//!
//! # Pourquoi une seconde fonction de hachage
//!
//! Tout le consensus tient sur SHA-256, et rien ici ne le change. BLAKE2b
//! n'entre que dans un seul endroit : la derivation de clef du fichier de
//! portefeuille, ou Argon2 ([`crate::argon2`]) l'exige — l'algorithme est
//! defini au-dessus de BLAKE2b, et le remplacer par SHA-256 donnerait autre
//! chose qu'Argon2, sans ses vecteurs de test ni sa cryptanalyse.
//!
//! # Ce qui est implemente, et ce qui ne l'est pas
//!
//! La fonction complete, pour toute longueur de sortie de 1 a 64 octets, avec
//! ou sans clef. Ni le mode arbre, ni le sel, ni la personnalisation : Argon2
//! n'en a pas besoin, et chaque option absente est une option qu'on ne peut
//! pas mal employer.
//!
//! L'implementation est verifiee contre les vecteurs de l'annexe A du RFC
//! 7693 et contre le vecteur officiel a clef de la suite BLAKE2.

/// Vecteur d'initialisation : les memes constantes que SHA-512.
const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Permutations des messages, une par tour (les tours 10 et 11 reprennent
/// les deux premieres).
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Taille d'un bloc, en octets.
pub const BLOC: usize = 128;

/// Etat incremental.
pub struct Blake2b {
    h: [u64; 8],
    /// Compteur d'octets absorbes, sur 128 bits.
    t: [u64; 2],
    tampon: [u8; BLOC],
    rempli: usize,
    longueur_sortie: usize,
}

impl Blake2b {
    /// Nouvel etat pour une sortie de `longueur_sortie` octets (1 a 64), sans
    /// clef.
    pub fn new(longueur_sortie: usize) -> Blake2b {
        Self::avec_clef(longueur_sortie, &[])
    }

    /// Nouvel etat avec une clef (0 a 64 octets). La clef, s'il y en a une,
    /// est absorbee comme premier bloc, completee de zeros : c'est le mode a
    /// clef natif de BLAKE2, qui n'a pas besoin de HMAC.
    pub fn avec_clef(longueur_sortie: usize, clef: &[u8]) -> Blake2b {
        assert!(
            (1..=64).contains(&longueur_sortie),
            "sortie de 1 a 64 octets"
        );
        assert!(clef.len() <= 64, "clef de 64 octets au plus");
        let mut h = IV;
        // Bloc de parametres : longueur de sortie, longueur de clef, fanout 1,
        // profondeur 1. Le reste a zero.
        h[0] ^= 0x0101_0000 ^ ((clef.len() as u64) << 8) ^ longueur_sortie as u64;
        let mut s = Blake2b {
            h,
            t: [0, 0],
            tampon: [0u8; BLOC],
            rempli: 0,
            longueur_sortie,
        };
        if !clef.is_empty() {
            s.tampon[..clef.len()].copy_from_slice(clef);
            s.rempli = BLOC;
        }
        s
    }

    pub fn update(&mut self, mut donnees: &[u8]) {
        while !donnees.is_empty() {
            // Un bloc plein n'est compresse que lorsqu'on sait qu'il n'est pas
            // le dernier : le dernier porte le drapeau final.
            if self.rempli == BLOC {
                self.incrementer(BLOC as u64);
                let bloc = self.tampon;
                self.compresser(&bloc, false);
                self.rempli = 0;
            }
            let n = (BLOC - self.rempli).min(donnees.len());
            self.tampon[self.rempli..self.rempli + n].copy_from_slice(&donnees[..n]);
            self.rempli += n;
            donnees = &donnees[n..];
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.incrementer(self.rempli as u64);
        for o in &mut self.tampon[self.rempli..] {
            *o = 0;
        }
        let bloc = self.tampon;
        self.compresser(&bloc, true);
        let mut sortie = Vec::with_capacity(64);
        for mot in self.h {
            sortie.extend_from_slice(&mot.to_le_bytes());
        }
        sortie.truncate(self.longueur_sortie);
        sortie
    }

    fn incrementer(&mut self, n: u64) {
        let (bas, retenue) = self.t[0].overflowing_add(n);
        self.t[0] = bas;
        if retenue {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compresser(&mut self, bloc: &[u8; BLOC], dernier: bool) {
        let mut m = [0u64; 16];
        for (i, mot) in m.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bloc[i * 8..i * 8 + 8]);
            *mot = u64::from_le_bytes(b);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if dernier {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// La fonction de melange G du RFC 7693.
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// BLAKE2b en un appel, pour une sortie de `longueur` octets.
pub fn blake2b(longueur: usize, donnees: &[u8]) -> Vec<u8> {
    let mut h = Blake2b::new(longueur);
    h.update(donnees);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 7693, annexe A : BLAKE2b-512("abc").
    #[test]
    fn vecteur_du_rfc_7693() {
        assert_eq!(
            hex(&blake2b(64, b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    /// La chaine vide, vecteur classique de la suite BLAKE2.
    #[test]
    fn la_chaine_vide() {
        assert_eq!(
            hex(&blake2b(64, b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    /// Le decoupage en blocs ne change rien : un message de plus d'un bloc,
    /// absorbe d'un coup ou octet par octet, donne le meme condensat. Et le
    /// message de 128 octets exactement — un bloc plein, qui doit quand meme
    /// etre le dernier — se traite correctement.
    #[test]
    fn l_absorption_incrementale_est_la_meme() {
        for n in [1usize, 127, 128, 129, 255, 256, 1000] {
            let m: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            let d_un_coup = blake2b(64, &m);
            let mut h = Blake2b::new(64);
            for o in &m {
                h.update(std::slice::from_ref(o));
            }
            assert_eq!(h.finish(), d_un_coup, "longueur {n}");
        }
    }

    /// Vecteur officiel a clef de la suite BLAKE2 (`blake2b-kat.txt`) :
    /// message vide, clef = 00 01 02 … 3f.
    #[test]
    fn vecteur_a_clef() {
        let clef: Vec<u8> = (0u8..64).collect();
        let mut h = Blake2b::avec_clef(64, &clef);
        h.update(b"");
        assert_eq!(
            hex(&h.finish()),
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786\
             b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"
        );
    }

    /// Une sortie tronquee n'est pas un prefixe de la sortie longue : la
    /// longueur entre dans le bloc de parametres.
    #[test]
    fn la_longueur_de_sortie_participe() {
        let court = blake2b(32, b"abc");
        let long = blake2b(64, b"abc");
        assert_eq!(court.len(), 32);
        assert_ne!(&court[..], &long[..32]);
    }
}
