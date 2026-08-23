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

    pub fn var_bytes(&mut self) -> Result<&'a [u8], ReadError> {
        let n = self.varint()? as usize;
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
