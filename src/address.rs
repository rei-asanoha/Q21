//! Q21 addresses.
//!
//! Structure of the payload, before Bech32m encoding:
//!
//! ```text
//! [ scheme: 1 byte ][ public key hash: 32 bytes ]
//! ```
//!
//! The scheme byte is the heart of cryptographic agility. A wallet reading an
//! address knows immediately which verification algorithm to use, and an
//! unknown scheme is cleanly rejected instead of being misinterpreted.
//!
//! Example address: `q21` + 33 encoded bytes + 6 checksum characters.

use crate::bech32::{self, Bech32Error};
use crate::consensus::{HRP_MAINNET, HRP_REGTEST, HRP_TESTNET};
use crate::hash::Hash256;
use crate::sig::{pubkey_hash, SchemeId};
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    /// Regression test network: local, disposable, difficulty fixed at the minimum.
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
    Encoding(Bech32Error),
    UnknownNetwork,
    UnknownScheme(u8),
    InvalidLength(usize),
    WrongNetwork {
        expected: Network,
        received: Network,
    },
}

impl From<Bech32Error> for AddressError {
    fn from(e: Bech32Error) -> Self {
        AddressError::Encoding(e)
    }
}

impl Address {
    /// Derives an address from a public key.
    pub fn from_pubkey(network: Network, scheme: SchemeId, pubkey: &[u8]) -> Address {
        Address {
            network,
            scheme,
            hash: pubkey_hash(scheme, pubkey),
        }
    }

    pub fn to_string_bech32(&self) -> String {
        let mut payload = Vec::with_capacity(33);
        payload.push(self.scheme.as_u8());
        payload.extend_from_slice(self.hash.as_bytes());
        bech32::encode(self.network.hrp(), &payload).expect("address payload is always valid")
    }

    pub fn parse(s: &str) -> Result<Address, AddressError> {
        let (hrp, payload) = bech32::decode(s)?;
        let network = Network::from_hrp(&hrp).ok_or(AddressError::UnknownNetwork)?;
        if payload.len() != 33 {
            return Err(AddressError::InvalidLength(payload.len()));
        }
        let scheme =
            SchemeId::from_u8(payload[0]).ok_or(AddressError::UnknownScheme(payload[0]))?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&payload[1..33]);
        Ok(Address {
            network,
            scheme,
            hash: Hash256(h),
        })
    }

    /// Parses an address, requiring a given network.
    ///
    /// Always preferable in a wallet: sending to the wrong network is a
    /// permanent loss of funds, and the mistake is easy to make.
    pub fn parse_on(s: &str, expected: Network) -> Result<Address, AddressError> {
        let a = Address::parse(s)?;
        if a.network != expected {
            return Err(AddressError::WrongNetwork {
                expected,
                received: a.network,
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

    fn key(scheme: SchemeId, seed: u8) -> Vec<u8> {
        vec![seed; scheme.pubkey_len()]
    }

    #[test]
    fn round_trip_for_all_schemes_and_networks() {
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            for scheme in SchemeId::ALL {
                let a = Address::from_pubkey(network, scheme, &key(scheme, 42));
                let text = a.to_string_bech32();
                assert_eq!(Address::parse(&text).unwrap(), a, "failure: {text}");
            }
        }
    }

    #[test]
    fn prefix_announces_network() {
        let s = SchemeId::MlDsa65;
        let mainnet = Address::from_pubkey(Network::Mainnet, s, &key(s, 1)).to_string_bech32();
        let test = Address::from_pubkey(Network::Testnet, s, &key(s, 1)).to_string_bech32();
        assert!(mainnet.starts_with("q211"), "{mainnet}");
        assert!(test.starts_with("tq211"), "{test}");
    }

    #[test]
    fn testnet_address_is_refused_on_mainnet() {
        let s = SchemeId::MlDsa65;
        let test = Address::from_pubkey(Network::Testnet, s, &key(s, 9)).to_string_bech32();
        assert!(matches!(
            Address::parse_on(&test, Network::Mainnet),
            Err(AddressError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn two_schemes_give_two_different_addresses() {
        let a = Address::from_pubkey(Network::Mainnet, SchemeId::MlDsa65, &[3u8; 1952]);
        let b = Address::from_pubkey(Network::Mainnet, SchemeId::MlDsa87, &[3u8; 2592]);
        assert_ne!(a.to_string_bech32(), b.to_string_bech32());
    }

    #[test]
    fn unknown_scheme_is_cleanly_rejected() {
        // Well-formed payload but scheme byte outside the registry.
        let mut payload = vec![99u8];
        payload.extend_from_slice(&[0u8; 32]);
        let text = bech32::encode(HRP_MAINNET, &payload).unwrap();
        assert_eq!(Address::parse(&text), Err(AddressError::UnknownScheme(99)));
    }

    #[test]
    fn wrong_length_is_rejected() {
        let text = bech32::encode(HRP_MAINNET, &[1u8, 2, 3]).unwrap();
        assert!(matches!(
            Address::parse(&text),
            Err(AddressError::InvalidLength(3))
        ));
    }

    #[test]
    fn typo_is_detected() {
        let s = SchemeId::MlDsa65;
        let good = Address::from_pubkey(Network::Mainnet, s, &key(s, 7)).to_string_bech32();
        let mut bytes = good.clone().into_bytes();
        let middle = bytes.len() / 2;
        bytes[middle] = if bytes[middle] == b'q' { b'p' } else { b'q' };
        let faulty = String::from_utf8(bytes).unwrap();
        assert!(
            Address::parse(&faulty).is_err(),
            "the checksum should have caught the typo"
        );
    }

    #[test]
    fn two_different_keys_give_two_addresses() {
        let s = SchemeId::MlDsa65;
        let a = Address::from_pubkey(Network::Mainnet, s, &key(s, 1));
        let b = Address::from_pubkey(Network::Mainnet, s, &key(s, 2));
        assert_ne!(a, b);
    }

    #[test]
    fn address_fits_within_bech32_limits() {
        let s = SchemeId::SphincsPlus;
        let text = Address::from_pubkey(Network::Mainnet, s, &key(s, 5)).to_string_bech32();
        assert!(text.len() <= 90, "address too long: {}", text.len());
    }
}
