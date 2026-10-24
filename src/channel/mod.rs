//! A payment-channel engine: a Lightning-style second layer over Q21's
//! pay-to-policy outputs.
//!
//! The engine is a library. It carries no bytes to a peer — a separate layer
//! does that — but it defines the [`messages`] both sides share, builds every
//! on-chain transaction from real policy outputs ([`txbuild`]) and real
//! ML-DSA-87 signing, runs the crash-safe state [`machine`] over an
//! append-only [`journal`], and gives a [`watcher`] that decides what a spend
//! of the funding output was.
//!
//! Two parties: the funder F provides the whole capacity, the acceptor A
//! starts at zero. One ML-DSA-87 key per party per channel, derived from the
//! wallet seed and a channel index ([`keys`]).
//!
//! Nothing here touches layer-one consensus, mempool, relay, or mining.

pub mod journal;
pub mod keys;
pub mod machine;
/// The node's channel manager needs to construct signing keys, so it compiles
/// only with the signing backend.
#[cfg(feature = "mldsa")]
pub mod manager;
pub mod messages;
pub mod txbuild;
pub mod watcher;

#[cfg(feature = "mldsa")]
pub use keys::ChannelKey;
pub use keys::Signer;
pub use machine::{channel_id, ChannelError, Machine, Phase};
pub use messages::{initiative, Message, Revocation, WireError};
pub use txbuild::{ChannelParams, FeeTier};
pub use watcher::{classify, Watch, WatchContext};

/// Default to-self delay on regtest, in blocks.
pub const DEFAULT_DELAY_REGTEST: u16 = 12;
/// Smallest to-self delay a party should accept on regtest.
pub const MIN_DELAY_REGTEST: u16 = 6;
/// Largest to-self delay a party should accept: beyond about two weeks of
/// blocks a channel's funds would be frozen for an unreasonable time.
pub const MAX_DELAY: u16 = 2016;
/// Confirmations before a funding output is considered final.
pub const DEFAULT_FUNDING_DEPTH: u16 = 2;
/// Smallest channel capacity an acceptor will take: enough for two outputs and
/// the commitment fee, so a close can always pay both sides above dust.
pub const MIN_CAPACITY: u64 = 4 * crate::consensus::MIN_OUTPUT_VALUE;
/// Largest channel capacity an acceptor will take, a sanity bound well under
/// the money supply.
pub const MAX_CAPACITY: u64 = 21_000_000_000_000;

#[cfg(all(test, feature = "mldsa"))]
mod tests;
