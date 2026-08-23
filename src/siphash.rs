//! SipHash-2-4.
//!
//! Fonction de hachage courte, rapide, et surtout **a clef**. C'est cette
//! derniere propriete qui compte ici : les identifiants courts du relais de
//! blocs compacts font six octets, donc les collisions sont possibles. Si la
//! fonction n'etait pas a clef, un attaquant pourrait fabriquer a l'avance des
//! transactions dont l'identifiant court entre en collision avec celles d'un
//! bloc a venir, et empecher sa reconstruction.
//!
//! La clef derive de l'en-tete du bloc, donc du nonce, donc d'une valeur que
//! personne ne connait avant que le bloc soit mine. Les collisions redeviennent
//! du hasard, et le hasard on l'encaisse : une collision coute un aller-retour
//! supplementaire, pas une faille.
//!
//! Publie par Aumasson et Bernstein en 2012. Implementee ici plutot qu'importee,
//! pour la meme raison que SHA-256 : le consensus ne doit dependre que de ce
//! qu'on peut auditer et figer.

/// Etat de SipHash-2-4.
pub struct SipHasher {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tampon: [u8; 8],
    remplis: usize,
    total: usize,
}

#[inline(always)]
fn tour(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

impl SipHasher {
    pub fn new(k0: u64, k1: u64) -> SipHasher {
        SipHasher {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
            tampon: [0u8; 8],
            remplis: 0,
            total: 0,
        }
    }

    #[inline]
    fn absorbe(&mut self, m: u64) {
        self.v3 ^= m;
        tour(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        tour(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        self.v0 ^= m;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len();

        if self.remplis > 0 {
            let besoin = 8 - self.remplis;
            let pris = besoin.min(data.len());
            self.tampon[self.remplis..self.remplis + pris].copy_from_slice(&data[..pris]);
            self.remplis += pris;
            data = &data[pris..];
            if self.remplis == 8 {
                let m = u64::from_le_bytes(self.tampon);
                self.absorbe(m);
                self.remplis = 0;
            }
        }

        while data.len() >= 8 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&data[..8]);
            self.absorbe(u64::from_le_bytes(w));
            data = &data[8..];
        }

        if !data.is_empty() {
            self.tampon[..data.len()].copy_from_slice(data);
            self.remplis = data.len();
        }
    }

    pub fn finalize(mut self) -> u64 {
        // Dernier mot : les octets restants, puis la longueur totale modulo 256
        // dans l'octet de poids fort.
        let mut dernier = [0u8; 8];
        dernier[..self.remplis].copy_from_slice(&self.tampon[..self.remplis]);
        dernier[7] = (self.total % 256) as u8;
        self.absorbe(u64::from_le_bytes(dernier));

        self.v2 ^= 0xff;
        for _ in 0..4 {
            tour(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// Raccourci : SipHash-2-4 d'un message complet.
pub fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut h = SipHasher::new(k0, k1);
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteurs de reference de l'article d'Aumasson et Bernstein.
    ///
    /// Clef `00 01 02 ... 0f`, message `00 01 02 ... (len-1)`.
    #[test]
    fn vecteurs_de_reference() {
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);

        let attendus: [u64; 8] = [
            0x726f_db47_dd0e_0e31,
            0x74f8_39c5_93dc_67fd,
            0x0d6c_8009_d9a9_4f5a,
            0x8567_6696_d7fb_7e2d,
            0xcf27_94e0_2771_87b7,
            0x1876_5564_cd99_a68d,
            0xcbc9_466e_58fe_e3ce,
            0xab02_00f5_8b01_d137,
        ];

        for (len, attendu) in attendus.iter().enumerate() {
            let msg: Vec<u8> = (0..len as u8).collect();
            assert_eq!(
                siphash24(k0, k1, &msg),
                *attendu,
                "vecteur de longueur {len} incorrect"
            );
        }
    }

    #[test]
    fn le_decoupage_ne_change_pas_le_resultat() {
        let msg: Vec<u8> = (0u8..=255).cycle().take(500).collect();
        let direct = siphash24(1, 2, &msg);
        for taille in [1usize, 3, 7, 8, 9, 64, 127] {
            let mut h = SipHasher::new(1, 2);
            for morceau in msg.chunks(taille) {
                h.update(morceau);
            }
            assert_eq!(h.finalize(), direct, "echec avec des morceaux de {taille}");
        }
    }

    #[test]
    fn deux_clefs_donnent_deux_resultats() {
        let msg = b"la meme transaction";
        assert_ne!(siphash24(1, 2, msg), siphash24(3, 4, msg));
    }

    #[test]
    fn un_bit_de_message_change_tout() {
        let a = siphash24(9, 9, b"transaction A");
        let b = siphash24(9, 9, b"transaction B");
        assert_ne!(a, b);
        // Effet d'avalanche grossierement verifie : au moins un tiers des bits.
        assert!((a ^ b).count_ones() > 20, "avalanche trop faible");
    }

    #[test]
    fn le_message_vide_est_gere() {
        assert_eq!(siphash24(0, 0, b""), siphash24(0, 0, &[]));
    }
}
