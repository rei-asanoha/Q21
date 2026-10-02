//! # q21-core
//!
//! Consensus core of the Q21 protocol: a peer-to-peer electronic cash system
//! designed to survive Shor's algorithm, and to be mined on an ordinary
//! machine.
//!
//! This crate corresponds to **phase 1** of the white paper roadmap: base
//! types, emission schedule, hashing, Merkle trees, versioned address format,
//! transaction and block structures. It contains neither networking, nor
//! storage, nor proof of work: those layers come next and all depend on this
//! one.
//!
//! ## Two principles that explain the rest of the code
//!
//! **No mandatory dependency.** Everything here (SHA-256, Bech32m, Merkle,
//! emission) is implemented and checked against official test vectors. A
//! dependency update that changed a hashing behavior would split the chain;
//! that risk is not acceptable in consensus code.
//!
//! **One absolute exception: ML-DSA.** Writing a lattice-based signature
//! scheme yourself is professional malpractice. The [`sig`] module defines the
//! interface and the sizes; the implementation plugs in through the `mldsa`
//! feature, on RustCrypto's `ml-dsa` crate. Without that feature, verification
//! fails loudly rather than silently accepting.
//!
//! ## Example
//!
//! ```
//! use q21_core::{address::{Address, Network}, sig::SchemeId, emission, consensus};
//!
//! // An address carries the signature scheme that protects it.
//! let pubkey = vec![0u8; SchemeId::MlDsa65.pubkey_len()];
//! let address = Address::from_pubkey(Network::Testnet, SchemeId::MlDsa65, &pubkey);
//! assert!(address.to_string_bech32().starts_with("tq21"));
//!
//! // The cap holds, whatever the height considered.
//! let in_thirty_years = consensus::BLOCKS_PER_YEAR * 30;
//! assert!(emission::total_supply_at(in_thirty_years).units() <= consensus::MAX_SUPPLY);
//! ```

pub mod addr;
pub mod address;
pub mod amount;
pub mod argon2;
pub mod bech32;
pub mod blake2b;
pub mod block;
pub mod bootstrap;
pub mod chain;
pub mod compact;
pub mod consensus;
pub mod emission;
pub mod explorer;
pub mod fast_sync;
pub mod hash;
pub mod http;
pub mod index;
pub mod json;
pub mod kdf;
pub mod lamport;
pub mod legacy;
pub mod lock;
pub mod memhard;
pub mod mempool;
pub mod merkle;
pub mod mining;
pub mod muhash;
pub mod nat;
pub mod net;
pub mod pow;
pub mod prompt;
pub mod pruning;
pub mod rng;
pub mod rpc;
pub mod ser;
pub mod settings;
pub mod setup;
pub mod sha256;
pub mod shutdown;
pub mod sig;
pub mod siphash;
pub mod state;
pub mod store;
pub mod tx;
pub mod uint;
pub mod utxo;
pub mod validate;
pub mod wallet;
pub mod wallet_ui;
pub mod wire;

pub use address::{Address, Network};
pub use amount::Amount;
pub use block::{Block, BlockHeader};
pub use chain::Chain;
pub use hash::Hash256;
pub use sig::SchemeId;
pub use tx::{OutPoint, Transaction, TxIn, TxOut};
pub use utxo::UtxoSet;
pub use wallet::Wallet;
