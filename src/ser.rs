//! Serialisation deterministe.
//!
//! Le consensus ne tolere qu'un seul encodage par objet. Si deux noeuds peuvent
//! serialiser la meme transaction de deux facons, ils calculent deux
//! identifiants, et la chaine se scinde.
//!
//! D'ou trois regles, appliquees sans exception dans ce fichier.
//!
//! - **Petit-boutiste partout.** Un seul ordre d'octets, jamais celui de la
//!   machine hote.
//! - **Entiers de longueur variable canoniques.** Une valeur n'a qu'un seul
//!   encodage valide. Le decodeur refuse la forme longue d'un petit nombre :
//!   Bitcoin acceptait les encodages non canoniques et cela a servi de vecteur
//!   de malleabilite.
//! - **Aucune structure a ordre indefini.** Pas de table de hachage, pas
//!   d'ensemble : uniquement des sequences dont l'ordre est explicite.

pub struct Writer {
    buf: Vec<u8>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Entier de longueur variable, forme canonique unique.
    pub fn varint(&mut self, v: u64) -> &mut Self {
        match v {
            0..=0xfc => self.u8(v as u8),
            0xfd..=0xffff => {
                self.u8(0xfd);
                self.buf.extend_from_slice(&(v as u16).to_le_bytes());
                self
            }
            0x1_0000..=0xffff_ffff => {
                self.u8(0xfe);
                self.buf.extend_from_slice(&(v as u32).to_le_bytes());
                self
            }
            _ => {
                self.u8(0xff);
                self.buf.extend_from_slice(&v.to_le_bytes());
                self
            }
        }
    }

    /// Sequence d'octets prefixee de sa longueur.
    pub fn var_bytes(&mut self, v: &[u8]) -> &mut Self {
        self.varint(v.len() as u64);
        self.bytes(v)
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ReadError {
    FinPrematuree,
    /// Encodage de longueur variable non canonique : une seule forme est admise.
    VarintNonCanonique,
    ValeurInvalide,
    OctetsRestants(usize),
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Lit un compte d'elements, en refusant ce que la suite ne peut contenir.
    ///
    /// # Le principe
    ///
    /// **On ne reserve jamais de place pour plus d'elements que le reste de
    /// l'entree ne peut en contenir.** Chaque element ayant une taille
    /// minimale connue sur le fil, la comparaison est exacte et gratuite.
    ///
    /// # Ce que cela ferme
    ///
    /// Sans ce controle, une trame de vingt-sept octets annoncant cinquante
    /// mille elements faisait reserver un million six cent cinquante mille
    /// octets avant d'echouer sur une fin prematuree : **soixante et un mille
    /// fois** ce qui avait ete recu, pour le prix d'un envoi. Plafonner la
    /// reservation — `with_capacity(n.min(1024))` — attenuait sans fermer :
    /// il restait un facteur mille.
    ///
    /// Le rapport a ete mesure message par message, pas suppose : voir
    /// `rapport_allocation_par_message` dans `tests/audit_arith.rs`.
    ///
    /// `minimum` est le nombre d'octets qu'un element ne peut pas ne pas
    /// occuper. Le sous-estimer affaiblit le controle ; le surestimer ferait
    /// refuser des donnees valides. Dans le doute, on sous-estime.
    ///
    /// # Pourquoi `try_from` et non `as`
    ///
    /// Le compte arrive en `u64`. Sur une cible 32 bits, `as usize` tronque :
    /// `(1 << 32) + 1` devenait `1`, et un compte que tout noeud 64 bits
    /// refuse etait lu comme un seul element par un noeud 32 bits. Un meme
    /// bloc valide pour les uns et invalide pour les autres, c'est une
    /// scission de la chaine par architecture. Un compte qui ne tient pas
    /// dans `usize` ne peut pas tenir dans l'entree : il est refuse avec la
    /// meme erreur que sur 64 bits, ou le controle de contenance le refuse.
    pub fn compte(&mut self, minimum: usize) -> Result<usize, ReadError> {
        let n = usize::try_from(self.varint()?).map_err(|_| ReadError::ValeurInvalide)?;
        // `checked_div` rend None quand `minimum` vaut zero, ce qui desactive
        // le controle — c'est exactement la convention voulue.
        if let Some(tenable) = self.remaining().checked_div(minimum) {
            if n > tenable {
                return Err(ReadError::ValeurInvalide);
            }
        }
        Ok(n)
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        if self.remaining() < n {
            return Err(ReadError::FinPrematuree);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, ReadError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, ReadError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn array32(&mut self) -> Result<[u8; 32], ReadError> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// Lit un entier de longueur variable en refusant toute forme non canonique.
    pub fn varint(&mut self) -> Result<u64, ReadError> {
        let tag = self.u8()?;
        let v = match tag {
            0..=0xfc => return Ok(tag as u64),
            0xfd => {
                let b = self.take(2)?;
                let v = u16::from_le_bytes([b[0], b[1]]) as u64;
                if v < 0xfd {
                    return Err(ReadError::VarintNonCanonique);
                }
                v
            }
            0xfe => {
                let b = self.take(4)?;
                let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= 0xffff {
                    return Err(ReadError::VarintNonCanonique);
                }
                v
            }
            0xff => {
                let v = self.u64()?;
                if v <= 0xffff_ffff {
                    return Err(ReadError::VarintNonCanonique);
                }
                v
            }
        };
        Ok(v)
    }

    /// Sequence d'octets prefixee de sa longueur.
    ///
    /// Meme regle que [`Self::compte`] : une longueur qui ne tient pas dans
    /// `usize` ne peut pas etre servie par l'entree, et se solde par la
    /// meme fin prematuree que `take` rendrait sur 64 bits — jamais par une
    /// troncature silencieuse qui lirait une longueur differente.
    pub fn var_bytes(&mut self) -> Result<&'a [u8], ReadError> {
        let n = usize::try_from(self.varint()?).map_err(|_| ReadError::FinPrematuree)?;
        self.take(n)
    }

    /// Verifie qu'aucun octet ne traine apres l'objet decode.
    ///
    /// Sans ce controle, on pourrait ajouter des donnees a la fin d'une
    /// transaction sans changer son interpretation, ce qui est un vecteur de
    /// malleabilite classique.
    pub fn expect_end(&self) -> Result<(), ReadError> {
        if self.remaining() != 0 {
            return Err(ReadError::OctetsRestants(self.remaining()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour_sur_les_entiers() {
        let mut w = Writer::new();
        w.u8(0xab).u32(0xdead_beef).u64(0x0123_4567_89ab_cdef);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert_eq!(r.u8().unwrap(), 0xab);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), 0x0123_4567_89ab_cdef);
        assert!(r.expect_end().is_ok());
    }

    #[test]
    fn les_varints_franchissent_correctement_les_seuils() {
        for v in [
            0u64,
            1,
            0xfc,
            0xfd,
            0xff,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut w = Writer::new();
            w.varint(v);
            let b = w.finish();
            let mut r = Reader::new(&b);
            assert_eq!(r.varint().unwrap(), v, "echec sur {v}");
            assert!(r.expect_end().is_ok());
        }
    }

    #[test]
    fn les_varints_utilisent_la_forme_la_plus_courte() {
        let mut w = Writer::new();
        w.varint(0xfc);
        assert_eq!(w.finish().len(), 1);

        let mut w = Writer::new();
        w.varint(0xfd);
        assert_eq!(w.finish().len(), 3);
    }

    #[test]
    fn les_varints_non_canoniques_sont_refuses() {
        // 0xfd suivi d'une valeur qui tenait sur un seul octet.
        assert_eq!(
            Reader::new(&[0xfd, 0x01, 0x00]).varint(),
            Err(ReadError::VarintNonCanonique)
        );
        // 0xfe suivi d'une valeur qui tenait sur deux octets.
        assert_eq!(
            Reader::new(&[0xfe, 0x01, 0x00, 0x00, 0x00]).varint(),
            Err(ReadError::VarintNonCanonique)
        );
        // 0xff suivi d'une valeur qui tenait sur quatre octets.
        assert_eq!(
            Reader::new(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0]).varint(),
            Err(ReadError::VarintNonCanonique)
        );
    }

    /// Un compte qui ne tient pas dans 32 bits est refuse de la meme facon
    /// sur toutes les cibles.
    ///
    /// # Le defaut que cette epreuve fige
    ///
    /// `compte` et `var_bytes` convertissaient le varint par `as usize`. Sur
    /// une cible 32 bits, `(1 << 32) + 1` devenait `1` : un noeud ARMv7
    /// lisait « un element » la ou un noeud x86_64 refusait la trame. Le
    /// varint est construit a la main, octet par octet, pour que l'epreuve
    /// ne depende pas de l'encodeur : `ff` puis les huit octets
    /// petit-boutistes de `0x1_0000_0001`.
    #[test]
    fn un_compte_au_dela_de_32_bits_est_refuse_sur_toute_cible() {
        let forme_longue = [0xffu8, 0x01, 0, 0, 0, 0x01, 0, 0, 0];
        // Le varint seul se lit bien : c'est un u64 canonique.
        assert_eq!(Reader::new(&forme_longue).varint(), Ok(0x1_0000_0001));

        // Un compte suivi d'un seul octet de charge : quelle que soit la
        // largeur de `usize`, la reponse est ValeurInvalide.
        let mut trame = forme_longue.to_vec();
        trame.push(0xaa);
        for minimum in [1usize, 40, 160] {
            assert_eq!(
                Reader::new(&trame).compte(minimum),
                Err(ReadError::ValeurInvalide),
                "minimum {minimum}"
            );
        }
        // Une sequence d'octets annoncee a plus de 4 Gio : fin prematuree,
        // jamais une lecture d'un seul octet.
        assert_eq!(
            Reader::new(&trame).var_bytes(),
            Err(ReadError::FinPrematuree)
        );
        // Et la valeur maximale, pour la forme.
        let mut extreme = vec![0xffu8];
        extreme.extend_from_slice(&u64::MAX.to_le_bytes());
        extreme.push(0xaa);
        assert_eq!(
            Reader::new(&extreme).compte(1),
            Err(ReadError::ValeurInvalide)
        );
        assert_eq!(
            Reader::new(&extreme).var_bytes(),
            Err(ReadError::FinPrematuree)
        );
    }

    #[test]
    fn les_octets_en_trop_sont_signales() {
        let b = [1u8, 2, 3];
        let mut r = Reader::new(&b);
        r.u8().unwrap();
        assert_eq!(r.expect_end(), Err(ReadError::OctetsRestants(2)));
    }

    #[test]
    fn une_entree_tronquee_ne_panique_pas() {
        assert_eq!(Reader::new(&[]).u32(), Err(ReadError::FinPrematuree));
        assert_eq!(Reader::new(&[1, 2]).u32(), Err(ReadError::FinPrematuree));
        assert_eq!(
            Reader::new(&[0x05, 1, 2]).var_bytes(),
            Err(ReadError::FinPrematuree)
        );
    }

    #[test]
    fn aller_retour_sur_les_sequences() {
        let charge = vec![9u8; 500];
        let mut w = Writer::new();
        w.var_bytes(&charge);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert_eq!(r.var_bytes().unwrap(), &charge[..]);
    }

    #[test]
    fn l_encodage_est_independant_de_la_machine() {
        // Petit-boutiste explicite : le premier octet est celui de poids faible.
        let mut w = Writer::new();
        w.u32(1);
        assert_eq!(w.finish(), vec![1, 0, 0, 0]);
    }
}
