//! Bech32m (BIP-350).
//!
//! Format d'encodage des adresses. Retenu plutot que Base58Check pour trois
//! raisons : la casse unique evite les erreurs de recopie, le code correcteur
//! BCH detecte toute erreur de 4 caracteres ou moins, et la separation
//! prefixe/donnees permet de distinguer reseau principal et reseau de test sans
//! ambiguite.
//!
//! Q21 utilise la constante Bech32m (`0x2bc830a3`) et non celle de Bech32
//! d'origine, qui souffrait d'une faiblesse sur les caracteres de rembourrage.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];
const BECH32M_CONST: u32 = 0x2bc8_30a3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Bech32Error {
    HrpInvalide,
    CaractereInvalide,
    CasseMelangee,
    ChecksumInvalide,
    TropCourt,
    TropLong,
    SeparateurAbsent,
    RembourrageInvalide,
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

/// Reconditionne des groupes de bits (8 vers 5 a l'encodage, 5 vers 8 au decodage).
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to) - 1;

    for &value in data {
        if (value as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | value as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// Encode un prefixe et une charge utile en Bech32m.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    if hrp.is_empty() || hrp.len() > 83 {
        return Err(Bech32Error::HrpInvalide);
    }
    if hrp.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(Bech32Error::HrpInvalide);
    }
    if hrp.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(Bech32Error::CasseMelangee);
    }

    let cinq = convert_bits(data, 8, 5, true).ok_or(Bech32Error::CaractereInvalide)?;

    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(&cinq);
    checksum_input.extend_from_slice(&[0u8; 6]);
    let poly = polymod(&checksum_input) ^ BECH32M_CONST;

    let mut sortie = String::with_capacity(hrp.len() + 1 + cinq.len() + 6);
    sortie.push_str(hrp);
    sortie.push('1');
    for b in &cinq {
        sortie.push(CHARSET[*b as usize] as char);
    }
    for i in 0..6 {
        let idx = ((poly >> (5 * (5 - i))) & 31) as usize;
        sortie.push(CHARSET[idx] as char);
    }

    if sortie.len() > 90 {
        return Err(Bech32Error::TropLong);
    }
    Ok(sortie)
}

/// Decode une chaine Bech32m et rend le prefixe et la charge utile.
pub fn decode(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    if s.len() < 8 {
        return Err(Bech32Error::TropCourt);
    }
    if s.len() > 90 {
        return Err(Bech32Error::TropLong);
    }

    let a_minuscule = s.bytes().any(|c| c.is_ascii_lowercase());
    let a_majuscule = s.bytes().any(|c| c.is_ascii_uppercase());
    if a_minuscule && a_majuscule {
        return Err(Bech32Error::CasseMelangee);
    }
    let s = s.to_ascii_lowercase();

    let sep = s.rfind('1').ok_or(Bech32Error::SeparateurAbsent)?;
    if sep == 0 || sep + 7 > s.len() {
        return Err(Bech32Error::SeparateurAbsent);
    }

    let hrp = &s[..sep];
    if hrp.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(Bech32Error::HrpInvalide);
    }

    let mut valeurs = Vec::with_capacity(s.len() - sep - 1);
    for c in s[sep + 1..].bytes() {
        let pos = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or(Bech32Error::CaractereInvalide)?;
        valeurs.push(pos as u8);
    }

    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(&valeurs);
    if polymod(&checksum_input) != BECH32M_CONST {
        return Err(Bech32Error::ChecksumInvalide);
    }

    let donnees = &valeurs[..valeurs.len() - 6];
    let octets = convert_bits(donnees, 5, 8, false).ok_or(Bech32Error::RembourrageInvalide)?;
    Ok((hrp.to_string(), octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour() {
        let charge = [0u8, 1, 2, 250, 255, 128, 64];
        let s = encode("q21", &charge).unwrap();
        let (hrp, sortie) = decode(&s).unwrap();
        assert_eq!(hrp, "q21");
        assert_eq!(sortie, charge);
    }

    #[test]
    fn aller_retour_sur_trente_trois_octets() {
        let charge: Vec<u8> = (0..33u8).collect();
        let s = encode("q21", &charge).unwrap();
        assert_eq!(decode(&s).unwrap().1, charge);
    }

    #[test]
    fn un_caractere_modifie_casse_le_checksum() {
        let s = encode("q21", &[1, 2, 3, 4, 5]).unwrap();
        let mut octets = s.into_bytes();
        let dernier = octets.len() - 1;
        octets[dernier] = if octets[dernier] == b'q' { b'p' } else { b'q' };
        let altere = String::from_utf8(octets).unwrap();
        assert_eq!(decode(&altere), Err(Bech32Error::ChecksumInvalide));
    }

    #[test]
    fn la_casse_melangee_est_refusee() {
        let s = encode("q21", &[1, 2, 3]).unwrap();
        let mut c: Vec<char> = s.chars().collect();
        c[0] = c[0].to_ascii_uppercase();
        let melange: String = c.into_iter().collect();
        assert_eq!(decode(&melange), Err(Bech32Error::CasseMelangee));
    }

    #[test]
    fn les_majuscules_completes_sont_acceptees() {
        let charge = [9u8, 8, 7];
        let s = encode("q21", &charge).unwrap();
        assert_eq!(decode(&s.to_ascii_uppercase()).unwrap().1, charge);
    }

    #[test]
    fn les_prefixes_de_reseau_sont_distincts() {
        let charge = [1u8, 2, 3];
        let principal = encode("q21", &charge).unwrap();
        let test = encode("tq21", &charge).unwrap();
        assert_ne!(principal, test);
        assert!(principal.starts_with("q21"));
        assert!(test.starts_with("tq21"));
        // Une adresse de test decodee ne doit pas se faire passer pour du reseau principal.
        assert_eq!(decode(&test).unwrap().0, "tq21");
    }

    #[test]
    fn les_entrees_malformees_sont_rejetees() {
        assert!(decode("").is_err());
        assert!(decode("q21").is_err());
        assert!(decode("sansseparateur").is_err());
        assert!(decode("1q21abcdef").is_err());
    }
}
