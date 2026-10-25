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
/// cSHAKE256 and KMAC256 for the transport, over the vendored permutation.
#[cfg(feature = "mldsa")]
pub mod kmac;
/// The node side of the transport: sessions over P2P connections.
#[cfg(feature = "mldsa")]
pub mod link;
pub mod machine;
/// The node's channel manager needs to construct signing keys, so it compiles
/// only with the signing backend.
#[cfg(feature = "mldsa")]
pub mod manager;
pub mod messages;
/// The authenticated, encrypted session between channel peers.
#[cfg(feature = "mldsa")]
pub mod transport;
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
/// Largest to-self delay a party should accept, on any network: about three
/// days at the two-minute spacing. Beyond it a channel's funds would be
/// frozen for an unreasonable time after a forced close.
pub const MAX_DELAY: u16 = 2016;
/// Confirmations before a funding output is considered final on regtest.
pub const DEFAULT_FUNDING_DEPTH: u16 = 2;

/// Default to-self delay on testnet, in blocks: about two days at the
/// two-minute spacing. It is the time a wallet may stay offline and still
/// punish a revoked state its peer broadcasts; on a public network wallets
/// go offline for days, so the regtest delay of a few minutes would hand a
/// cheater the funds of anyone who closed a laptop.
pub const DEFAULT_DELAY_TESTNET: u16 = 1_440;
/// Smallest to-self delay an acceptor takes on testnet: about one day.
pub const MIN_DELAY_TESTNET: u16 = 720;
/// Confirmations before a funding output is considered final on testnet, and
/// the fewest an acceptor takes: a public chain reorganizes, regtest does not.
pub const FUNDING_DEPTH_TESTNET: u16 = 6;

/// The channel terms of a network: what this node proposes when it opens a
/// channel, and the least it accepts from a peer that opens one to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The to-self delay proposed by default, in blocks.
    pub default_delay: u16,
    /// The shortest to-self delay accepted (H3).
    pub min_delay: u16,
    /// The longest to-self delay accepted.
    pub max_delay: u16,
    /// Confirmations a funding waits for by default, and the fewest accepted.
    pub funding_depth: u16,
}

/// The channel terms of `network`. Regtest keeps short values, so that tests
/// run in a few blocks. Testnet uses values a public network needs; mainnet,
/// where channels do not run, would start from the same.
pub const fn terms(network: crate::address::Network) -> Terms {
    match network {
        crate::address::Network::Regtest => Terms {
            default_delay: DEFAULT_DELAY_REGTEST,
            min_delay: MIN_DELAY_REGTEST,
            max_delay: MAX_DELAY,
            funding_depth: DEFAULT_FUNDING_DEPTH,
        },
        crate::address::Network::Testnet | crate::address::Network::Mainnet => Terms {
            default_delay: DEFAULT_DELAY_TESTNET,
            min_delay: MIN_DELAY_TESTNET,
            max_delay: MAX_DELAY,
            funding_depth: FUNDING_DEPTH_TESTNET,
        },
    }
}

// Each network's default sits within what it accepts.
const _: () = {
    let nets = [
        crate::address::Network::Regtest,
        crate::address::Network::Testnet,
        crate::address::Network::Mainnet,
    ];
    let mut i = 0;
    while i < nets.len() {
        let t = terms(nets[i]);
        assert!(t.min_delay <= t.default_delay && t.default_delay <= t.max_delay);
        assert!(t.funding_depth >= 1 && t.funding_depth <= t.max_delay);
        i += 1;
    }
};
/// Smallest channel capacity an acceptor will take: enough for two outputs and
/// the commitment fee, so a close can always pay both sides above dust.
pub const MIN_CAPACITY: u64 = 4 * crate::consensus::MIN_OUTPUT_VALUE;
/// Largest channel capacity an acceptor will take, a sanity bound well under
/// the money supply.
pub const MAX_CAPACITY: u64 = 21_000_000_000_000;

#[cfg(all(test, feature = "mldsa"))]
mod tests;
