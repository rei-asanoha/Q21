//! Argon2, tel que decrit par le RFC 9106.
//!
//! # Pourquoi
//!
//! Le fichier de portefeuille est chiffre par une clef derivee de la phrase
//! secrete. Avec PBKDF2, deriver cette clef coute une suite de condensats —
//! une operation qu'un circuit dedie execute des milliers de fois plus vite
//! qu'un processeur. Un attaquant qui vole `wallet.dat` teste alors les
//! phrases a une vitesse que l'utilisateur ne peut pas imaginer, et la seule
//! defense restait la longueur de la phrase.
//!
//! Argon2 rend chaque essai **couteux en memoire** : deriver une clef exige de
//! remplir et de relire des dizaines de mebioctets, dans un ordre qui depend
//! des donnees. Un circuit dedie doit embarquer autant de memoire par essai
//! qu'un processeur, et n'y gagne presque rien. C'est le laureat de la
//! Password Hashing Competition (2015), et le choix recommande par le RFC
//! 9106 comme par l'OWASP.
//!
//! # Pourquoi l'ecrire ici
//!
//! Ce projet refuse d'inventer des primitives ; il ne refuse pas de les
//! implementer d'apres leur norme quand la norme fournit de quoi verifier.
//! SHA-256 est ecrit ici et verifie contre FIPS 180-4 ; BLAKE2b contre le RFC
//! 7693 ; Argon2 l'est contre les trois vecteurs du RFC 9106 (Argon2d,
//! Argon2i, Argon2id), qui exercent les lanes, les passes et les deux modes
//! d'adressage. Une implementation qui reproduit ces trois vecteurs a
//! l'octet pres est celle du RFC.
//!
//! # Ce qui est implemente
//!
//! Les trois variantes, version 0x13, nombre de lanes quelconque (traitees
//! l'une apres l'autre : le resultat est le meme qu'en parallele), longueur
//! de sortie quelconque, secret et donnees associees facultatifs. Le
//! portefeuille n'emploie qu'Argon2id.

use crate::blake2b::{blake2b, Blake2b};

/// Version de l'algorithme.
const VERSION: u32 = 0x13;

/// Taille d'un bloc de memoire, en octets.
const BLOC: usize = 1024;

/// Mots de 64 bits par bloc.
const MOTS: usize = BLOC / 8;

/// Nombre de tranches par passe (le RFC en fixe quatre).
const TRANCHES: usize = 4;

/// Les trois variantes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variante {
    /// Adressage dependant des donnees : le plus resistant au compromis
    /// temps-memoire, vulnerable aux canaux auxiliaires.
    D = 0,
    /// Adressage independant des donnees : sans canal auxiliaire, moins
    /// resistant au compromis.
    I = 1,
    /// Hybride : independant sur la premiere moitie de la premiere passe,
    /// dependant ensuite. Le choix recommande.
    Id = 2,
}

/// Parametres de cout.
#[derive(Clone, Copy, Debug)]
pub struct Parametres {
    pub variante: Variante,
    /// Memoire, en kibioctets. Au moins `8 * lanes`.
    pub memoire_kib: u32,
    /// Passes sur la memoire. Au moins 1.
    pub passes: u32,
    /// Lanes. Au moins 1.
    pub lanes: u32,
}

/// Un bloc de 1 024 octets, vu comme 128 mots.
#[derive(Clone, Copy)]
struct Bloc([u64; MOTS]);

impl Bloc {
    const ZERO: Bloc = Bloc([0u64; MOTS]);

    fn depuis_octets(o: &[u8]) -> Bloc {
        let mut b = Bloc::ZERO;
        for (i, mot) in b.0.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&o[i * 8..i * 8 + 8]);
            *mot = u64::from_le_bytes(w);
        }
        b
    }

    fn en_octets(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(BLOC);
        for mot in self.0 {
            v.extend_from_slice(&mot.to_le_bytes());
        }
        v
    }

    fn xor(&self, autre: &Bloc) -> Bloc {
        let mut r = *self;
        for (a, b) in r.0.iter_mut().zip(autre.0.iter()) {
            *a ^= *b;
        }
        r
    }
}

/// La fonction de hachage a longueur variable H' du RFC (section 3.3).
fn h_prime(longueur: usize, entree: &[u8]) -> Vec<u8> {
    let mut prefixe = Vec::with_capacity(4 + entree.len());
    prefixe.extend_from_slice(&(longueur as u32).to_le_bytes());
    prefixe.extend_from_slice(entree);
    if longueur <= 64 {
        return blake2b(longueur, &prefixe);
    }
    let r = longueur.div_ceil(32) - 2;
    let mut sortie = Vec::with_capacity(longueur);
    let mut v = blake2b(64, &prefixe);
    sortie.extend_from_slice(&v[..32]);
    for _ in 1..r {
        v = blake2b(64, &v);
        sortie.extend_from_slice(&v[..32]);
    }
    let reste = longueur - 32 * r;
    sortie.extend_from_slice(&blake2b(reste, &v));
    sortie
}

/// La fonction GB de la permutation P : le G de BLAKE2b, ou l'addition est
/// enrichie du produit des moities basses (BlaMka), pour que le calcul
/// depende de multiplications que le silicium ne parallelise pas
/// gratuitement.
#[inline(always)]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    #[inline(always)]
    fn mele(x: u64, y: u64) -> u64 {
        let xl = x as u32 as u64;
        let yl = y as u32 as u64;
        x.wrapping_add(y)
            .wrapping_add(2u64.wrapping_mul(xl).wrapping_mul(yl))
    }
    v[a] = mele(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = mele(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = mele(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = mele(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// La permutation P sur seize mots (huit registres de seize octets).
fn p(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// La fonction de compression G(X, Y) du RFC (section 3.5).
fn compresser(x: &Bloc, y: &Bloc) -> Bloc {
    let r = x.xor(y);
    let mut q = r;
    // P sur chacune des huit lignes de 128 octets.
    for ligne in 0..8 {
        let mut v = [0u64; 16];
        v.copy_from_slice(&q.0[ligne * 16..ligne * 16 + 16]);
        p(&mut v);
        q.0[ligne * 16..ligne * 16 + 16].copy_from_slice(&v);
    }
    // P sur chacune des huit colonnes : la colonne `c` est formee des mots
    // 2c, 2c+1 de chaque ligne.
    for colonne in 0..8 {
        let mut v = [0u64; 16];
        for ligne in 0..8 {
            v[2 * ligne] = q.0[ligne * 16 + 2 * colonne];
            v[2 * ligne + 1] = q.0[ligne * 16 + 2 * colonne + 1];
        }
        p(&mut v);
        for ligne in 0..8 {
            q.0[ligne * 16 + 2 * colonne] = v[2 * ligne];
            q.0[ligne * 16 + 2 * colonne + 1] = v[2 * ligne + 1];
        }
    }
    q.xor(&r)
}

/// Derive `longueur` octets de `mot_de_passe` et `sel`.
///
/// `secret` et `donnees_associees` sont les entrees facultatives K et X du
/// RFC ; vides en pratique ici, presentes pour reproduire les vecteurs.
pub fn deriver(
    params: Parametres,
    mot_de_passe: &[u8],
    sel: &[u8],
    secret: &[u8],
    donnees_associees: &[u8],
    longueur: usize,
) -> Vec<u8> {
    let lanes = params.lanes.max(1) as usize;
    let passes = params.passes.max(1);
    assert!(longueur >= 4, "sortie de 4 octets au moins");
    // m' = 4 * p * floor(m / 4p) : la memoire est arrondie a un multiple du
    // nombre de segments.
    let memoire = (params.memoire_kib as usize).max(8 * lanes);
    let m_prime = 4 * lanes * (memoire / (4 * lanes));
    let q = m_prime / lanes;
    let segment = q / TRANCHES;

    // H0 = H^64(p, T, m, t, v, y, |P|, P, |S|, S, |K|, K, |X|, X).
    let mut h = Blake2b::new(64);
    for v in [
        lanes as u32,
        longueur as u32,
        params.memoire_kib,
        passes,
        VERSION,
        params.variante as u32,
    ] {
        h.update(&v.to_le_bytes());
    }
    for morceau in [mot_de_passe, sel, secret, donnees_associees] {
        h.update(&(morceau.len() as u32).to_le_bytes());
        h.update(morceau);
    }
    let h0 = h.finish();

    // Les deux premiers blocs de chaque lane.
    let mut memoire_blocs = vec![Bloc::ZERO; m_prime];
    for lane in 0..lanes {
        for j in 0..2u32 {
            let mut e = Vec::with_capacity(72);
            e.extend_from_slice(&h0);
            e.extend_from_slice(&j.to_le_bytes());
            e.extend_from_slice(&(lane as u32).to_le_bytes());
            memoire_blocs[lane * q + j as usize] = Bloc::depuis_octets(&h_prime(BLOC, &e));
        }
    }

    for passe in 0..passes {
        for tranche in 0..TRANCHES {
            for lane in 0..lanes {
                remplir_segment(
                    &mut memoire_blocs,
                    params.variante,
                    passe,
                    passes,
                    tranche,
                    lane,
                    lanes,
                    q,
                    segment,
                    m_prime,
                );
            }
        }
    }

    // C = XOR des derniers blocs de chaque lane ; sortie = H'^T(C).
    let mut c = memoire_blocs[q - 1];
    for lane in 1..lanes {
        c = c.xor(&memoire_blocs[lane * q + q - 1]);
    }
    let sortie = h_prime(longueur, &c.en_octets());
    // La memoire de travail portait des derives du mot de passe : on l'efface.
    for b in memoire_blocs.iter_mut() {
        crate::kdf::effacer(bytemuck_mots(&mut b.0));
    }
    sortie
}

/// Vue en octets d'un tableau de mots, pour l'effacement.
fn bytemuck_mots(mots: &mut [u64; MOTS]) -> &mut [u8] {
    // Sur : `u64` n'a aucune valeur invalide, l'alignement d'octets est
    // trivial, et la longueur est exactement celle du tableau.
    unsafe { std::slice::from_raw_parts_mut(mots.as_mut_ptr() as *mut u8, MOTS * 8) }
}

/// Remplit un segment (une lane, une tranche) d'une passe.
#[allow(clippy::too_many_arguments)]
fn remplir_segment(
    memoire: &mut [Bloc],
    variante: Variante,
    passe: u32,
    passes: u32,
    tranche: usize,
    lane: usize,
    lanes: usize,
    q: usize,
    segment: usize,
    m_prime: usize,
) {
    // Adressage independant des donnees : Argon2i partout, Argon2id sur la
    // premiere moitie de la premiere passe.
    let independant = match variante {
        Variante::I => true,
        Variante::Id => passe == 0 && tranche < TRANCHES / 2,
        Variante::D => false,
    };

    // Le generateur d'adresses de l'adressage independant : G(0, G(0, Z)),
    // ou Z decrit la position, un compteur en plus a chaque bloc de 128
    // adresses.
    let mut adresses = Bloc::ZERO;
    let mut entree = Bloc::ZERO;
    if independant {
        entree.0[0] = passe as u64;
        entree.0[1] = lane as u64;
        entree.0[2] = tranche as u64;
        entree.0[3] = m_prime as u64;
        entree.0[4] = passes as u64;
        entree.0[5] = variante as u64;
    }
    let prochaine_adresse = |entree: &mut Bloc| -> Bloc {
        entree.0[6] = entree.0[6].wrapping_add(1);
        compresser(&Bloc::ZERO, &compresser(&Bloc::ZERO, entree))
    };

    // Dans la premiere tranche de la premiere passe, les deux premiers blocs
    // existent deja.
    let depart = if passe == 0 && tranche == 0 { 2 } else { 0 };

    for i in depart..segment {
        let courant = lane * q + tranche * segment + i;
        let precedent = if tranche * segment + i == 0 {
            lane * q + q - 1
        } else {
            courant - 1
        };

        let (j1, j2) = if independant {
            if i % MOTS == 0 || (i == depart && depart == 2) {
                adresses = prochaine_adresse(&mut entree);
            }
            let mot = adresses.0[i % MOTS];
            (mot as u32 as u64, mot >> 32)
        } else {
            let mot = memoire[precedent].0[0];
            (mot as u32 as u64, mot >> 32)
        };

        // La lane de reference : la notre dans la toute premiere tranche.
        let lane_ref = if passe == 0 && tranche == 0 {
            lane
        } else {
            (j2 % lanes as u64) as usize
        };

        // La taille de la zone de reference, selon le RFC (section 3.4.1.3).
        let meme_lane = lane_ref == lane;
        let zone = if passe == 0 {
            if tranche == 0 {
                i - 1
            } else if meme_lane {
                tranche * segment + i - 1
            } else {
                tranche * segment - if i == 0 { 1 } else { 0 }
            }
        } else if meme_lane {
            q - segment + i - 1
        } else {
            q - segment - if i == 0 { 1 } else { 0 }
        };

        // Position dans la zone, biaisee vers les blocs recents.
        let x = (j1 * j1) >> 32;
        let y = ((zone as u64) * x) >> 32;
        let zz = (zone as u64) - 1 - y;
        let debut = if passe == 0 || tranche == TRANCHES - 1 {
            0
        } else {
            (tranche + 1) * segment
        };
        let ref_index = (debut + zz as usize) % q;
        let reference = lane_ref * q + ref_index;

        let nouveau = compresser(&memoire[precedent], &memoire[reference]);
        memoire[courant] = if passe == 0 {
            nouveau
        } else {
            nouveau.xor(&memoire[courant])
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Les entrees communes aux trois vecteurs du RFC 9106 (section 5) :
    /// mot de passe 32 x 0x01, sel 16 x 0x02, secret 8 x 0x03, donnees
    /// associees 12 x 0x04, t = 3, m = 32 Kio, p = 4, sortie de 32 octets.
    fn vecteur(variante: Variante) -> String {
        let p = Parametres {
            variante,
            memoire_kib: 32,
            passes: 3,
            lanes: 4,
        };
        hex(&deriver(
            p, &[1u8; 32], &[2u8; 16], &[3u8; 8], &[4u8; 12], 32,
        ))
    }

    #[test]
    fn vecteur_argon2d_du_rfc_9106() {
        assert_eq!(
            vecteur(Variante::D),
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        );
    }

    #[test]
    fn vecteur_argon2i_du_rfc_9106() {
        assert_eq!(
            vecteur(Variante::I),
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        );
    }

    #[test]
    fn vecteur_argon2id_du_rfc_9106() {
        assert_eq!(
            vecteur(Variante::Id),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// Une seule lane, plusieurs passes, sortie longue : le chemin que le
    /// portefeuille emploie reellement doit etre deterministe et sensible a
    /// chaque entree.
    #[test]
    fn une_lane_est_deterministe_et_sensible() {
        let p = Parametres {
            variante: Variante::Id,
            memoire_kib: 256,
            passes: 2,
            lanes: 1,
        };
        let a = deriver(p, b"phrase", b"sel-de-seize-oct", &[], &[], 64);
        let b = deriver(p, b"phrase", b"sel-de-seize-oct", &[], &[], 64);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert_ne!(a, deriver(p, b"phrasE", b"sel-de-seize-oct", &[], &[], 64));
        assert_ne!(a, deriver(p, b"phrase", b"sel-de-seize-ocT", &[], &[], 64));
        let plus = Parametres { passes: 3, ..p };
        assert_ne!(
            a,
            deriver(plus, b"phrase", b"sel-de-seize-oct", &[], &[], 64)
        );
    }
}
