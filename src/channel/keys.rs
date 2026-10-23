//! Per-channel keys and the one thing the engine asks of them: to sign.
//!
//! A channel uses one key per party, of the network's default scheme
//! (ML-DSA-87). The key is derived from the wallet seed and a channel index,
//! so a wallet reconstructs every channel key from its seed alone, and two
//! channels never share a key. A second seed, derived the same way under a
//! different tag, feeds the revocation shachain ([`crate::shachain`]).
//!
//! Verification always goes through [`crate::sig::verify`], exactly as it does
//! for an ordinary spend. Only *signing* is placed behind a trait, so the
//! engine never carries a private-key format of its own and a test can sign
//! without standing up a wallet.

use crate::hash::{tagged_hash_parts, Hash256};
use crate::sig::{self, SchemeId};

/// The scheme every channel key uses: the network default, the maximum level
/// of the standard. A channel is a long-lived object; it takes the margin.
pub const CHANNEL_SCHEME: SchemeId = SchemeId::MlDsa87;

/// Derivation tag of a channel's funding (signing) key.
const TAG_FUND: &str = "Q21/channel/fund-key";
/// Derivation tag of a channel's revocation shachain root.
#[cfg(feature = "mldsa")]
const TAG_REVOKE: &str = "Q21/channel/revoke-root";

/// The 32-byte seed of a channel's signing key, from the wallet seed and a
/// channel index.
pub fn funding_key_seed(wallet_seed: &[u8; 32], channel_index: u32) -> [u8; 32] {
    tagged_hash_parts(TAG_FUND, &[wallet_seed, &channel_index.to_le_bytes()]).0
}

/// What the state machine needs of a key: to name itself, to sign, and to
/// yield its private revocation root.
///
/// A blanket [`Self::pubkey_hash`] ties the key to its scheme the one way the
/// rest of the protocol does ([`sig::pubkey_hash`]).
pub trait Signer {
    /// The public key, `CHANNEL_SCHEME.pubkey_len()` bytes.
    fn pubkey(&self) -> &[u8];

    /// The hash an output or a policy leaf commits to.
    fn pubkey_hash(&self) -> Hash256 {
        sig::pubkey_hash(CHANNEL_SCHEME, self.pubkey())
    }

    /// Signs a 32-byte message. The result is `CHANNEL_SCHEME.sig_len()` bytes.
    fn sign(&self, message: &Hash256) -> Vec<u8>;

    /// The root of this channel's revocation shachain, bound to `channel_id`.
    ///
    /// **Must derive from private material**: the counterparty, who knows our
    /// public key and the channel id, must not be able to compute it, or it
    /// could derive every revocation secret and so every penalty preimage. A
    /// public-key-only derivation here would hand the channel away.
    fn revocation_root(&self, channel_id: &Hash256) -> [u8; 32];
}

/// A concrete ML-DSA-87 channel key, holding the expanded signing key so a
/// channel that signs thousands of states pays the key expansion only once.
#[cfg(feature = "mldsa")]
pub struct ChannelKey {
    seed: [u8; 32],
    sk: ml_dsa::SigningKey<ml_dsa::MlDsa87>,
    pubkey: Vec<u8>,
}

#[cfg(feature = "mldsa")]
impl ChannelKey {
    /// Builds a key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> ChannelKey {
        use ml_dsa::{signature::Keypair, SigningKey, B32};
        let sk = SigningKey::<ml_dsa::MlDsa87>::from_seed(&B32::from(*seed));
        let pubkey = sk.verifying_key().encode()[..].to_vec();
        ChannelKey {
            seed: *seed,
            sk,
            pubkey,
        }
    }

    /// Builds a channel's signing key from the wallet seed and the index.
    pub fn derive(wallet_seed: &[u8; 32], channel_index: u32) -> ChannelKey {
        ChannelKey::from_seed(&funding_key_seed(wallet_seed, channel_index))
    }
}

#[cfg(feature = "mldsa")]
impl Signer for ChannelKey {
    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn sign(&self, message: &Hash256) -> Vec<u8> {
        use ml_dsa::Signer as _;
        // Deterministic FIPS 204 signing: a channel state is signed once and
        // the message already carries a per-state revocation point, so the
        // determinism that the wallet avoids for fault resistance is harmless
        // here and keeps every test reproducible.
        self.sk.sign(message.as_bytes()).encode()[..].to_vec()
    }

    fn revocation_root(&self, channel_id: &Hash256) -> [u8; 32] {
        // From the private seed, never the public key.
        tagged_hash_parts(TAG_REVOKE, &[&self.seed, channel_id.as_bytes()]).0
    }
}
