//! Adresses Q21.
//!
//! Structure de la charge utile, avant encodage Bech32m :
//!
//! ```text
//! [ schema : 1 octet ][ empreinte de clef publique : 32 octets ]
//! ```
//!
//! L'octet de schema est le coeur de l'agilite algorithmique. Un portefeuille
//! qui lit une adresse sait immediatement quel algorithme de verification
//! employer, et un schema inconnu se rejette proprement au lieu d'etre
//! interprete de travers.
//!
//! Exemple d'adresse : `q21` + 33 octets encodes + 6 caracteres de checksum.

use crate::bech32::{self, Bech32Error};
use crate::consensus::{HRP_MAINNET, HRP_REGTEST, HRP_TESTNET};
use crate::hash::Hash256;
use crate::sig::{pubkey_hash, SchemeId};
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    /// Reseau de regression : local, jetable, difficulte figee au minimum.
    Regtest,
}

impl Network {
    pub const fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => HRP_MAINNET,
            Network::Testnet => HRP_TESTNET,
            Network::Regtest => HRP_REGTEST,
        }
    }

    pub fn from_hrp(hrp: &str) -> Option<Network> {
        match hrp {
            HRP_MAINNET => Some(Network::Mainnet),
            HRP_TESTNET => Some(Network::Testnet),
            HRP_REGTEST => Some(Network::Regtest),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Address {
    pub network: Network,
    pub scheme: SchemeId,
    pub hash: Hash256,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AddressError {
    Encodage(Bech32Error),
    ReseauInconnu,
    SchemaInconnu(u8),
    LongueurInvalide(usize),
    MauvaisReseau { attendu: Network, recu: Network },
}

impl From<Bech32Error> for AddressError {
    fn from(e: Bech32Error) -> Self {
        AddressError::Encodage(e)
    }
}

impl Address {
    /// Derive une adresse depuis une clef publique.
    pub fn from_pubkey(network: Network, scheme: SchemeId, pubkey: &[u8]) -> Address {
        Address {
            network,
            scheme,
            hash: pubkey_hash(scheme, pubkey),
        }
    }

    pub fn to_string_bech32(&self) -> String {
        let mut charge = Vec::with_capacity(33);
        charge.push(self.scheme.as_u8());
        charge.extend_from_slice(self.hash.as_bytes());
        bech32::encode(self.network.hrp(), &charge).expect("charge utile d'adresse toujours valide")
    }

    pub fn parse(s: &str) -> Result<Address, AddressError> {
        let (hrp, charge) = bech32::decode(s)?;
        let network = Network::from_hrp(&hrp).ok_or(AddressError::ReseauInconnu)?;
        if charge.len() != 33 {
            return Err(AddressError::LongueurInvalide(charge.len()));
        }
        let scheme = SchemeId::from_u8(charge[0]).ok_or(AddressError::SchemaInconnu(charge[0]))?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&charge[1..33]);
        Ok(Address {
            network,
            scheme,
            hash: Hash256(h),
        })
    }

    /// Analyse une adresse en exigeant un reseau donne.
    ///
    /// A preferer systematiquement dans un portefeuille : envoyer sur le mauvais
    /// reseau est une perte de fonds definitive, et l'erreur est facile a faire.
    pub fn parse_on(s: &str, attendu: Network) -> Result<Address, AddressError> {
        let a = Address::parse(s)?;
        if a.network != attendu {
            return Err(AddressError::MauvaisReseau {
                attendu,
                recu: a.network,
            });
        }
        Ok(a)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_bech32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clef(scheme: SchemeId, graine: u8) -> Vec<u8> {
        vec![graine; scheme.pubkey_len()]
    }

    #[test]
    fn aller_retour_pour_tous_les_schemas_et_reseaux() {
        for reseau in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            for scheme in SchemeId::ALL {
                let a = Address::from_pubkey(reseau, scheme, &clef(scheme, 42));
                let texte = a.to_string_bech32();
                assert_eq!(Address::parse(&texte).unwrap(), a, "echec : {texte}");
            }
        }
    }

    #[test]
    fn le_prefixe_annonce_le_reseau() {
        let s = SchemeId::MlDsa65;
        let principal = Address::from_pubkey(Network::Mainnet, s, &clef(s, 1)).to_string_bech32();
        let test = Address::from_pubkey(Network::Testnet, s, &clef(s, 1)).to_string_bech32();
        assert!(principal.starts_with("q211"), "{principal}");
        assert!(test.starts_with("tq211"), "{test}");
    }

    #[test]
    fn une_adresse_de_test_ne_passe_pas_sur_le_reseau_principal() {
        let s = SchemeId::MlDsa65;
        let test = Address::from_pubkey(Network::Testnet, s, &clef(s, 9)).to_string_bech32();
        assert!(matches!(
            Address::parse_on(&test, Network::Mainnet),
            Err(AddressError::MauvaisReseau { .. })
        ));
    }

    #[test]
    fn deux_schemas_donnent_deux_adresses_differentes() {
        let a = Address::from_pubkey(Network::Mainnet, SchemeId::MlDsa65, &[3u8; 1952]);
        let b = Address::from_pubkey(Network::Mainnet, SchemeId::MlDsa87, &[3u8; 2592]);
        assert_ne!(a.to_string_bech32(), b.to_string_bech32());
    }

    #[test]
    fn un_schema_inconnu_est_rejete_proprement() {
        // Charge utile bien formee mais octet de schema hors registre.
        let mut charge = vec![99u8];
        charge.extend_from_slice(&[0u8; 32]);
        let texte = bech32::encode(HRP_MAINNET, &charge).unwrap();
        assert_eq!(Address::parse(&texte), Err(AddressError::SchemaInconnu(99)));
    }

    #[test]
    fn une_longueur_incorrecte_est_rejetee() {
        let texte = bech32::encode(HRP_MAINNET, &[1u8, 2, 3]).unwrap();
        assert!(matches!(
            Address::parse(&texte),
            Err(AddressError::LongueurInvalide(3))
        ));
    }

    #[test]
    fn une_faute_de_frappe_est_detectee() {
        let s = SchemeId::MlDsa65;
        let bonne = Address::from_pubkey(Network::Mainnet, s, &clef(s, 7)).to_string_bech32();
        let mut octets = bonne.clone().into_bytes();
        let milieu = octets.len() / 2;
        octets[milieu] = if octets[milieu] == b'q' { b'p' } else { b'q' };
        let fautive = String::from_utf8(octets).unwrap();
        assert!(
            Address::parse(&fautive).is_err(),
            "le checksum aurait du rattraper la faute"
        );
    }

    #[test]
    fn deux_clefs_differentes_donnent_deux_adresses() {
        let s = SchemeId::MlDsa65;
        let a = Address::from_pubkey(Network::Mainnet, s, &clef(s, 1));
        let b = Address::from_pubkey(Network::Mainnet, s, &clef(s, 2));
        assert_ne!(a, b);
    }

    #[test]
    fn une_adresse_tient_dans_les_limites_de_bech32() {
        let s = SchemeId::SphincsPlus;
        let texte = Address::from_pubkey(Network::Mainnet, s, &clef(s, 5)).to_string_bech32();
        assert!(texte.len() <= 90, "adresse trop longue : {}", texte.len());
    }
}
