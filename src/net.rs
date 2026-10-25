//! Peer-to-peer layer.
//!
//! Plain TCP, `std::net`, one thread per peer. No networking library: in code
//! that receives bytes from strangers, every dependency is an attack surface
//! nobody has reviewed.
//!
//! # The threading model, and why it cannot deadlock
//!
//! One thread accepts incoming connections, one thread reads each peer. The
//! shared state — chain, mempool, peer table — lives behind a single lock.
//!
//! The rule that prevents deadlock fits in one sentence: **we never hold the
//! lock during a network write.** Each handler computes, under the lock, the
//! list of replies to send, releases it, then sends. A slow peer therefore
//! cannot freeze the whole node by ceasing to read.
//!
//! # What compact relay does here
//!
//! When a block is accepted, we do not send five megabytes to every peer: we
//! announce the compact block, a few kilobytes, and the peer only asks again
//! for what it is missing. This is what reduces propagation latency, hence the
//! orphan rate, hence the superlinear advantage of large miners.

use crate::addr::AddrBook;
use crate::address::Network;
use crate::block::Block;
use crate::chain::{Accept, Chain};
use crate::compact::{CompactBlock, Reconstruction};
use crate::consensus::{NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_TESTNET};
use crate::hash::Hash256;
use crate::mempool::Mempool;
use crate::outbox::{Outbox, Push};
use crate::tx::Transaction;
use crate::wire::{
    InvItem, InvKind, Message, WireError, HEADER_LEN, MAX_PAYLOAD, MIN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Ban score beyond which we disconnect.
pub const BAN_THRESHOLD: u32 = 100;

/// Cost of an unreadable frame: a peer that sends ten is disconnected.
pub const MISCONDUCT_MALFORMED: u32 = 10;
/// Cost of an invalid block: far more serious, it is wasted work.
pub const MISCONDUCT_BAD_BLOCK: u32 = 50;

/// Maximum number of simultaneous peers.
pub const MAX_PEERS: usize = 32;

/// Slots that listening always leaves free for our outbound connections.
///
/// Without this reserve, a flood of inbound connections filled the
/// `MAX_PEERS` slots and the node could no longer dial anyone from its
/// address book — the anti-eclipse address book was then never consulted.
pub const RESERVED_OUTBOUND_SLOTS: usize = 8;

/// Compact block reconstructions that a peer can leave pending.
///
/// Without a bound, a peer announced incomplete compact blocks one after
/// another and never answered the request for the missing transactions: each
/// announcement stayed in memory, with no limit and no deadline. One
/// reconstruction in flight per peer is what the protocol calls for; four
/// leave room for two blocks found back to back.
pub const MAX_PENDING_RECONSTRUCTIONS: usize = 4;

/// Time granted to a peer to deliver a block body we asked it for.
///
/// # The defect this closes
///
/// Missing bodies were requested from the peer that had announced the
/// headers, and nothing watched for the reply: a peer that answered pings but
/// withheld the bodies froze the synchronization forever. Past this timeout,
/// the request is made again to another peer and the withholder loses points;
/// a node bootstrapped from a single malicious address at least ends up
/// disconnecting it.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(60);

/// Cost of a body requested and never delivered. Two are enough to disconnect.
pub const MISCONDUCT_BODY_WITHHELD: u32 = 50;

/// Maintenance rounds in a row in which a peer let a body go overdue without
/// delivering a single one, on time or late, before it is charged with
/// withholding even though it answers our transaction requests. See
/// `Peer::body_overdue_rounds`.
pub const MAX_BODY_OVERDUE_ROUNDS: u8 = 3;

/// Block bodies we accept having requested from one peer without having
/// received them yet.
///
/// # The defect this closes
///
/// The table of requested bodies had no cap: its only purge was time-based,
/// at [`BODY_TIMEOUT`]. Yet the headers that cause a body to be requested are
/// checked only for **chaining**, not for work — checking the work of two
/// thousand headers would cost more than what it protects, since Q21's proof
/// is memory-hard. Fabricating offline a sequence of headers perfectly chained
/// onto our tip therefore costs nothing, and each batch of two thousand caused
/// two thousand more tokens to be recorded, without bound, for the minute the
/// delivery timeout lasts.
///
/// The safety bound of header-based synchronization is therefore this cap,
/// not a work check: whatever a peer announces, it never makes us request
/// more than sixteen bodies at a time. The rest waits in a queue, itself
/// bounded ([`MAX_PENDING_BODIES`]), and is only requested as bodies arrive.
/// Sixteen are enough to keep a link busy: a requested body never waits for
/// the next one to go out.
pub const MAX_BODIES_IN_FLIGHT: usize = 16;

/// Block bodies a peer can leave us to request, while waiting for an
/// in-flight slot to free up.
///
/// A batch of headers contains at most [`crate::wire::MAX_HEADERS`]; a peer's
/// queue is replaced at each batch, and therefore never exceeds one batch.
/// These are identifiers, not headers: sixty-four kibibytes at most per peer.
pub const MAX_PENDING_BODIES: usize = crate::wire::MAX_HEADERS;

/// Unsolicited compact block announcements a peer can push right away.
///
/// An honest peer only announces what it has just accepted: a few blocks per
/// minute at most, and the bodies that **we** requested from it are not
/// counted here. Eight let through two blocks found back to back and a small
/// reorg.
pub const CMPCT_BUCKET_MAX: u64 = 8;

/// Sustained rate of unsolicited compact announcements granted to a peer, per
/// second.
///
/// # The defect this closes
///
/// A compact announcement whose parent is known triggered, **under the global
/// lock**, a scan of the mempool with one SipHash per transaction and an
/// allocation of the announced size — up to sixty-five thousand slots —
/// before the slightest check rejected it. `tx` and the snapshot had a
/// bucket; compact announcements did not, and nothing penalized a peer that
/// pushed two hundred in a row. One block per second at a sustained rate is
/// still sixty times the network's cadence.
pub const CMPCT_RATE_PER_SEC: u64 = 1;

/// Cost of a rejected compact announcement: beyond the bucket, or rejected by
/// the reconstruction itself (missing coinbase, index outside the block,
/// absurd number of transactions — shapes only the sender could have
/// produced). Ten are enough to disconnect, as for unreadable frames.
pub const MISCONDUCT_CMPCT_REJECTED: u32 = 10;

/// Inbound connections admitted from the same network group (/16 in IPv4,
/// /64 in IPv6 — see [`inbound_group`]).
///
/// A single address could occupy all thirty-two slots; four per group let a
/// machine or a small network come in several times, without a single range
/// being able to shut the door on the others.
pub const INBOUND_PER_GROUP: usize = 4;

/// Network group of an inbound connection, for slot diversity.
///
/// Two families, two granularities: in IPv4 the address book's `/16`, in IPv6
/// the `/64` — that is the prefix a hosting provider gives to a single
/// machine, hence the unit below which distinct addresses cost nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetGroup {
    V4([u8; 2]),
    V6([u8; 8]),
}

/// Group of an inbound address, or `None` if it has none.
///
/// # The defect this closes
///
/// Group diversity was computed only for IPv4 addresses: every IPv6
/// connection fell into the "no group" case and escaped
/// [`INBOUND_PER_GROUP`]. A single `/64` — the allocation of any rented
/// server — could then occupy every inbound slot, as long as the node
/// listened on IPv6. The `/64` is the answer: it is the accepted equivalent
/// of the v4 `/16`.
///
/// An IPv4 address presented in its IPv6 form (`::ffff:a.b.c.d`, which is
/// what listening on `[::]` yields) is grouped with the IPv4 ones: treating
/// it as a `/64` would put the entire v4 Internet in a single group.
///
/// Loopback is not a group: several nodes on the same machine (regtest,
/// tests) do not eclipse one another.
pub fn inbound_group(address: SocketAddr) -> Option<NetGroup> {
    match address {
        SocketAddr::V4(a) if !a.ip().is_loopback() => {
            Some(NetGroup::V4(crate::addr::group(a.ip().octets())))
        }
        SocketAddr::V4(_) => None,
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) if v4.is_loopback() => None,
            Some(v4) => Some(NetGroup::V4(crate::addr::group(v4.octets()))),
            None if a.ip().is_loopback() => None,
            None => {
                let o = a.ip().octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&o[..8]);
                Some(NetGroup::V6(prefix))
            }
        },
    }
}

/// Header requests a peer can send us right away.
///
/// # The defect this closes
///
/// A header request of a few dozen bytes — a locator we do not know is
/// enough — made us serve two thousand headers from genesis: more than three
/// hundred kibibytes, prepared under the global lock. Nothing bounded the
/// rate: it was the only service without a bucket, and an amplification by a
/// factor of one hundred fifty within reach of any established peer.
///
/// An honest peer only asks for headers again once the bodies of the previous
/// batch have arrived, that is at most once per batch of two thousand blocks.
/// Eight requests right away, then one per second, cover a synchronization at
/// two thousand blocks per second — far beyond what a link delivers.
pub const HEADERS_BUCKET_MAX: u64 = 8;

/// Sustained rate of header requests granted to a peer, per second.
pub const HEADERS_RATE_PER_SEC: u64 = 1;

/// Header replies we expect at most from one peer.
///
/// # The defect this closes
///
/// A batch of headers pushed without having been requested was treated as a
/// reply: two thousand hashes under the lock, and the queue of bodies to
/// request replaced. The code said so — "we only receive headers in reply to
/// our own request" — without checking it. Now each request sent opens a
/// slot, each batch received consumes one, and a batch that arrives without a
/// slot is not read.
pub const MAX_EXPECTED_HEADERS: u8 = 4;

/// Addresses a peer can make us record right away: a full reply to our
/// `getaddr`, which we send to every new peer.
pub const ADDR_BUCKET_MAX: u64 = crate::wire::MAX_ADDR as u64;

/// Sustained rate of addresses granted to a peer, per second.
///
/// # The defect this closes
///
/// With the address book full, each address from an unknown group makes us
/// scan the five hundred twelve groups to evict one, under the global lock: an
/// `addr` frame of a thousand addresses held it for nearly eight milliseconds,
/// and nothing bounded the rate — handler fuzzing campaign. An honest peer
/// announces its address once per lease renewal, and relays what it learns
/// once in a while: ten per second leave plenty of margin. Beyond that, the
/// addresses are ignored, without penalty.
pub const ADDR_RATE_PER_SEC: u64 = 10;

/// Cost of a batch of headers nobody requested. No honest node sends one: only
/// the reply to a request produces one.
pub const MISCONDUCT_UNREQUESTED_HEADERS: u32 = 10;

/// Read timeout. A silent peer is eventually released.
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Silence after which we ask the peer to show signs of life.
///
/// Short enough for a laptop waking up to find the network again in under a
/// minute, long enough not to chatter on a slow link.
pub const PING_AFTER: Duration = Duration::from_secs(45);

/// Silence after which we consider the peer dead and free its slot.
///
/// Counted from the last frame received, not from the `Ping` sent: a peer
/// that answers something else stays alive.
pub const MAX_SILENCE: Duration = Duration::from_secs(100);

/// How long a peer has to answer the ping sent after a possible sleep before
/// it is dropped. See [`Node::probe_all_peers`].
pub const PROBE_GRACE: Duration = Duration::from_secs(20);

/// Maximum time to complete the handshake.
///
/// An inbound connection that has not introduced itself — `Version` **then**
/// `VerAck` — within this time is closed.
///
/// # The defect this timeout closes
///
/// The only liveness check was the silence since the last frame, and **any**
/// frame refreshes that marker, including a `Ping` received before the
/// handshake (to which we reply with a `Pong` without requiring the
/// introduction). An attacker could therefore open inbound connections, send
/// a `Ping` every forty seconds, and never introduce itself: the connection
/// stayed "alive" forever, `handshaked` false. A few /16 groups were enough
/// to occupy the twenty-four inbound slots and shut the door on honest
/// newcomers — a denial of service on the reachability of a bootstrap node,
/// found by the phase 8b red team. A handshake deadline removes these
/// unfinished connections, whatever their surface activity.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Sustained rate granted to a peer for the snapshot service, in bytes per
/// second.
pub const SNAPSHOT_RATE_PER_SEC: u64 = 2 * 1024 * 1024;

/// Reserve granted right away, in bytes. It lets an honest newcomer start
/// without waiting, while bounding what a peer can extract in one go.
pub const SNAPSHOT_BUCKET_MAX: u64 = 8 * 1024 * 1024;

/// Cost of a transaction that is invalid in itself — bad signature, key that
/// does not match the lock, incorrect form, value not conserved. Five are
/// enough to disconnect: a transaction made this way can only come from a
/// peer that fabricates it, never from an honest relay.
pub const MISCONDUCT_BAD_TX: u32 = 20;

/// Is `msg` unreadable on `network` for carrying a policy output?
///
/// Where the rule is not in force, a message carrying a policy output gets
/// exactly what 0.4.9 gave it — it did not decode: [`MISCONDUCT_MALFORMED`]
/// and the connection dropped — rather than the milder penalty of an invalid
/// transaction, so that a rule not yet open changes nothing in how peers are
/// treated. That is always the case on mainnet, where it never opens.
///
/// Elsewhere it depends on the height the content could be mined at:
///
/// - a block, or a compact block, carries its height: below the activation
///   height a policy output in it is malformed, from the activation height
///   on it is validated like anything else;
/// - a transaction (or the transactions of a compact block) is judged against
///   our tip, `tip`. A peer that predates the activation
///   ([`crate::wire::POLICY_ACTIVATION_VERSION`]) sending one before our next
///   block is at the activation height gets the 0.4.9 treatment. A peer that
///   follows it relays one only once its own next block is there, and it may
///   be ahead of us — we may even be syncing from far behind: its
///   transaction is refused without penalty (see `Node::tx_invalid_in_itself`)
///   unless it comes earlier than [`crate::consensus::POLICY_ACTIVATION_NOTICE`]
///   blocks before the activation height, counted from our tip or from the
///   height the peer announced at the handshake (`peer_height`), whichever is
///   higher.
pub fn policy_output_is_malformed(
    network: Network,
    tip: u64,
    peer_version: u32,
    peer_height: u64,
    msg: &Message,
) -> bool {
    if !msg.carries_policy_output() {
        return false;
    }
    if !crate::policy::may_appear_on(network) {
        return true;
    }
    let mined_at = match msg {
        Message::Block(b) => b.header.height,
        Message::CmpctBlock(c) => c.header.height,
        _ if peer_version >= crate::wire::POLICY_ACTIVATION_VERSION => tip
            .max(peer_height)
            .saturating_add(crate::consensus::POLICY_ACTIVATION_NOTICE)
            .saturating_add(1),
        _ => tip.saturating_add(1),
    };
    !crate::policy::is_active(network, mined_at)
}

/// Does a peer that announced protocol `version` follow the policy
/// activation of `network`? Always, where the network has no transition
/// ([`crate::policy::has_transition`]): there, every version reads policies
/// as this node does.
pub fn follows_activation(network: Network, version: u32) -> bool {
    !crate::policy::has_transition(network) || version >= crate::wire::POLICY_ACTIVATION_VERSION
}

/// `m` as peer `peer` may receive it.
///
/// A peer that does not follow the policy activation reads a policy output
/// as a malformed message and drops the link: it is never offered, nor
/// sent, a transaction that creates or spends one. `None` when nothing of
/// `m` is left for it.
fn for_peer<'a>(g: &Shared, peer: u64, m: &'a Message) -> Option<std::borrow::Cow<'a, Message>> {
    use std::borrow::Cow;
    let follows = g
        .peers
        .get(&peer)
        .is_some_and(|p| follows_activation(g.network, p.version));
    if follows {
        return Some(Cow::Borrowed(m));
    }
    let withheld = |hash: &Hash256| g.mempool.touches_policy(hash);
    match m {
        Message::Tx(t) => {
            let policy = t
                .outputs
                .iter()
                .any(|o| o.scheme == crate::sig::SchemeId::Policy)
                || withheld(&t.txid());
            (!policy).then_some(Cow::Borrowed(m))
        }
        Message::Inv(items)
            if items
                .iter()
                .any(|i| i.kind == InvKind::Tx && withheld(&i.hash)) =>
        {
            let kept: Vec<InvItem> = items
                .iter()
                .filter(|i| i.kind != InvKind::Tx || !withheld(&i.hash))
                .copied()
                .collect();
            (!kept.is_empty()).then_some(Cow::Owned(Message::Inv(kept)))
        }
        _ => Some(Cow::Borrowed(m)),
    }
}

/// See [`crate::validate::ValidationError::locally_unverifiable_scheme`].
pub fn locally_unverifiable_scheme(
    e: &crate::validate::ValidationError,
) -> Option<crate::sig::SchemeId> {
    e.locally_unverifiable_scheme()
}

/// Says it once per run, not at every block.
fn report_unverifiable_scheme(scheme: crate::sig::SchemeId) {
    static ALREADY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !ALREADY.swap(true, Ordering::Relaxed) {
        eprintln!(
            "warning: a block carries {} signatures that this binary cannot verify \
             (built without ML-DSA). The peer is not penalized and the block is not \
             adopted. Rebuild: cargo build --release",
            scheme.name()
        );
    }
}

/// Writes an inbound rejection to the log, at most once per minute.
///
/// A rejection used to be silent: the bootstrap node dropped the connection
/// without a word. But a rejection is also something an attacker can trigger
/// at will, by knocking in a loop; one line per rejection would give it a way
/// to flood the log. So we write the first one, then silently count the
/// following ones, and the next line says how many there were.
fn report_rejection(address: Option<SocketAddr>, reason: &str) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    static SUPPRESSED: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 60
        || LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let suppressed = SUPPRESSED.swap(0, Ordering::Relaxed);
    let who = address
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "?".into());
    let more = if suppressed > 0 {
        format!(" (and {suppressed} other rejection(s) since the previous message)")
    } else {
        String::new()
    };
    eprintln!("  inbound connection from {who} rejected: {reason}{more}");
}

/// Verification budget a peer can consume right away, in signatures.
///
/// The bucket is now denominated in **signature verifications**, not in
/// transactions: verification is what costs, and a transaction carries as
/// many of them as it has inputs. The cap covers the largest possible valid
/// transaction — bounded by weight, on the order of a few hundred inputs — so
/// that no honest transaction is ever rejected for lack of budget: it drains
/// the bucket, then the bucket refills. See the rate below.
pub const TX_BUCKET_MAX: u64 = 512;

/// Below this number of inputs, a transaction rejected for lack of budget is
/// treated as a message flood (penalizable); above it, as a single large
/// request that may be honest (deferred without penalty). See the
/// `Message::Tx` arm.
pub const FLOOD_INPUT_THRESHOLD: u64 = 16;

/// Sustained rate of signature verifications granted to a peer, per second.
///
/// # The defect this closes, and its real size
///
/// A pushed transaction costs the receiver one post-quantum signature
/// verification **per input**, under the global lock. The previous note
/// claimed "sixteen milliseconds" per ML-DSA-87 verification; the actual
/// measurement (`sig` benchmark, on the test machine) is on the order of
/// **0.33 ms** — the note was fifty times too pessimistic. The danger does
/// not disappear for all that: nothing bounded the number of inputs of a
/// transaction (only weight bounds it, ~271 inputs for ML-DSA-87), and the
/// budget was counted in transactions, not in verifications. A transaction
/// with many inputs, or a flood of such transactions, therefore held the lock
/// far longer than one token per transaction suggested — red team 8b, second
/// campaign.
///
/// Now the bucket is debited in proportion to the inputs. At this rate, the
/// verification work a peer can impose is bounded to ~0.33 ms per unit, that
/// is a negligible fraction of a core, while an ordinary transaction (one or
/// two inputs) is still served unhindered.
///
/// Sixteen since 0.4.9, eight before. In the endurance test, an entry point
/// relaying three agents to a wallet passed on nine payments a second, about
/// twelve verifications: more than one peer's budget, for a peer doing nothing
/// but its job. Sixteen covers that with room to spare, and still bounds what
/// one peer can impose to about five milliseconds of verification a second.
pub const TX_RATE_PER_SEC: u64 = 16;

/// Per-peer budget for payment-channel messages (one unit each): a burst, then
/// a steady rate. A channel update is at most three messages, so this is ample
/// for an active channel and still bounds a flood to a trickle.
pub const CHAN_BUCKET_MAX: u64 = 64;
pub const CHAN_RATE_PER_SEC: u64 = 16;

/// A malformed, oversized, or unsolicited channel message is misconduct of the
/// same order as a bad transaction.
pub const MISCONDUCT_CHANNEL: u32 = 20;

/// Inputs announced at most when the pool is offered to a peer, at the
/// handshake and every [`MEMPOOL_REBROADCAST`] (see
/// [`crate::mempool::Mempool::announcement`]).
///
/// A quarter of the receiving peer's budget ([`TX_BUCKET_MAX`]): fetching
/// everything announced can never pass for a flood, even on a link already
/// busy relaying.
pub const MEMPOOL_ANNOUNCE_INPUTS: u64 = TX_BUCKET_MAX / 4;

/// How often the node offers its pool again to its peers.
///
/// Ten minutes up to v0.4.8. In the endurance test, about forty payments
/// waited ten minutes after the queue had drained, while the blocks went out
/// almost empty: the miners had missed them while their pool was full, and
/// heard of them again only at the next offer. One block interval now. The
/// offer covers the whole pool ([`MEMPOOL_REOFFER_MAX_TXS`]); a peer that
/// holds a transaction does not ask for it again.
pub const MEMPOOL_REBROADCAST: Duration = Duration::from_secs(120);

/// Transactions requested from one peer and not yet received, at most. Fewer
/// in practice: a request is only made within the peer's budget.
pub const MAX_REQUESTED_TXS: usize = TX_BUCKET_MAX as usize;

/// Transactions remembered as refused until the next block. See
/// `Shared::rejected`.
pub const MAX_RECENT_REJECTS: usize = 20_000;

/// Blocks a full-pool refusal is remembered for. Past them the transaction is
/// worth one more download: a refusal that held only for a stale copy, or for
/// a pool that has since changed, does not keep it out for good.
pub const FULL_POOL_REFUSAL_BLOCKS: u64 = 6;

/// Announced transactions waiting, per peer, for its budget to refill before
/// they are requested. Sized to hold a re-offer of a full pool
/// ([`MEMPOOL_REOFFER_MAX_TXS`]), so that a node catching up never has to
/// drop part of what a peer offered and wait for the next round.
pub const MAX_ANNOUNCED_WAITING: usize = 9000;

/// Transactions re-offered to a peer on the periodic mempool broadcast and at
/// the handshake: the whole pool, capped so the inventory stays bounded (a
/// full pool is about eight thousand one hundred transactions). At thirty-six
/// bytes per identifier this is roughly three hundred kibibytes, once every
/// [`MEMPOOL_REBROADCAST`], to each peer.
pub const MEMPOOL_REOFFER_MAX_TXS: usize = 9000;

/// How long a transaction request is remembered. A peer that announced a
/// transaction and no longer has it never answers; its slot is freed.
pub const TX_REQUEST_MEMORY: Duration = Duration::from_secs(60);

/// How long after connecting a peer that was behind gets the pool offered.
///
/// Offered at the handshake, the pending transactions reached a node that
/// was still catching up: it could not find their inputs and refused them
/// all — measured on two local nodes, a fresh node got none of five. A minute
/// lets a node of today's testnet catch up; the ten-minute round covers a
/// slower one.
pub const MEMPOOL_OFFER_DELAY: Duration = Duration::from_secs(60);

/// Token bucket bounding how much snapshot data a peer can get served.
///
/// # The defect this closes
///
/// The other serving arms count their bytes; the snapshot arm counted
/// nothing. A peer that had passed the handshake could therefore request
/// **the same chunk** in a loop: each nine-byte request caused up to one
/// mebibyte to be copied, **under the global lock** — the one that is also
/// used to validate blocks. The ratio between the cost of the request and the
/// cost of the reply is what defines a denial-of-service vector.
///
/// A sustained rate of two mebibytes per second lets an honest newcomer
/// download its snapshot without trouble — it is an operation it only does
/// once — while reducing abuse to a trickle.
///
/// # Why the instant is a parameter
///
/// A hidden clock makes a rate rule impossible to test other than by
/// sleeping, hence poorly tested. Here the caller supplies the instant: the
/// tests control time, and the rule is checked exactly.
#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    tokens: u64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: SNAPSHOT_BUCKET_MAX,
            last: now,
        }
    }

    /// Allows `bytes` if the bucket contains them, and removes them. The
    /// bucket first refills in proportion to the elapsed time, without ever
    /// exceeding its capacity.
    pub fn allow(&mut self, bytes: u64, now: Instant) -> bool {
        self.allow_with(bytes, now, SNAPSHOT_BUCKET_MAX, SNAPSHOT_RATE_PER_SEC)
    }

    /// A transaction bucket: same rule, in units rather than bytes.
    pub fn for_transactions(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: TX_BUCKET_MAX,
            last: now,
        }
    }

    /// A compact announcement bucket: same rule, in unsolicited announcements.
    pub fn for_compact_announcements(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: CMPCT_BUCKET_MAX,
            last: now,
        }
    }

    /// A channel-message bucket: same rule, one unit per message.
    pub fn for_channel_messages(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: CHAN_BUCKET_MAX,
            last: now,
        }
    }

    /// Empties the bucket: what was granted beyond it is paid by waiting for
    /// it to refill.
    pub fn drain(&mut self, now: Instant) {
        self.tokens = 0;
        self.last = now;
    }

    /// Units the bucket holds now, refill included. Removes nothing.
    pub fn level(&self, now: Instant, max: u64, rate: u64) -> u64 {
        let elapsed = now.saturating_duration_since(self.last).as_millis() as u64;
        self.tokens
            .saturating_add(elapsed.saturating_mul(rate) / 1000)
            .min(max)
    }

    /// Would the bucket grant `cost` units now? Removes nothing.
    ///
    /// Used to decide on preliminary work done outside the lock — the proof
    /// of work of a compact announcement — without debiting the same
    /// announcement twice: the real debit remains the handler's, under the
    /// lock.
    pub fn available(&self, cost: u64, now: Instant, max: u64, rate: u64) -> bool {
        let mut copy = *self;
        copy.allow_with(cost, now, max, rate)
    }

    /// A bucket of received addresses: same rule, in addresses.
    pub fn for_addresses(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: ADDR_BUCKET_MAX,
            last: now,
        }
    }

    /// A header request bucket: same rule, in requests.
    pub fn for_header_requests(now: Instant) -> TokenBucket {
        TokenBucket {
            tokens: HEADERS_BUCKET_MAX,
            last: now,
        }
    }

    /// Allows `cost` units against a bucket of capacity `max` and a rate of
    /// `rate` per second.
    pub fn allow_with(&mut self, cost: u64, now: Instant, max: u64, rate: u64) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_millis() as u64;
        // The refill is computed in milliseconds: below a millisecond, we
        // credit nothing and do not move the marker, otherwise a burst of very
        // closely spaced requests would never credit anything.
        let gain = elapsed.saturating_mul(rate) / 1000;
        if gain > 0 {
            self.tokens = self.tokens.saturating_add(gain).min(max);
            self.last = now;
        }
        let units = cost;
        if self.tokens >= units {
            self.tokens -= units;
            true
        } else {
            false
        }
    }
}

/// Maximum time for a write to a peer.
///
/// Shorter than the read: a peer may legitimately stay silent for two
/// minutes, it cannot legitimately refuse to take in its bytes for thirty
/// seconds. Beyond that, the connection drops and propagation continues
/// without it.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn magic_for(network: Network) -> [u8; 4] {
    match network {
        Network::Mainnet => NETWORK_MAGIC_MAINNET,
        _ => NETWORK_MAGIC_TESTNET,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What Tor brings a node, see [`Node::onion_status`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OnionStatus {
    /// This node announces an onion service of its own.
    pub serving: bool,
    /// Onion names in the book.
    pub known: usize,
    /// Established connections to onion services.
    pub outbound: usize,
    /// Established inbound connections from the local Tor.
    pub inbound: usize,
}

/// Connected peer.
struct Peer {
    addr: SocketAddr,
    /// Outgoing queue, drained by a thread of its own: no producer ever
    /// writes to the socket. See [`crate::outbox`].
    writer: Arc<Outbox>,
    /// True if **we** initiated this connection (outbound). An inbound
    /// connection is chosen by the other end; only outbound ones are chosen
    /// by us, from the address book, with its group diversity. Counting
    /// inbound ones toward the peer target would let an attacker fill our
    /// slots from a single IP and **suppress every outbound dial**: the
    /// anti-eclipse address book would then never be consulted. We keep them
    /// apart.
    outbound: bool,
    /// True as soon as a valid `Version` message has been received from this
    /// peer. The handshake is only complete (`handshaked`) after `Version`
    /// **then** `VerAck`: a `VerAck` alone, without `Version`, must not open
    /// access to expensive messages nor skip the anti-loop nonce check.
    version_received: bool,
    /// True as soon as **we** have sent our `Version` to this peer — on
    /// connection for an outbound one, in reply to theirs for an inbound one.
    /// We only introduce ourselves once: see the `Version` arm.
    version_sent: bool,
    handshaked: bool,
    ban_score: u32,
    /// The peer's advertised user agent, kept to read its capabilities.
    user_agent: String,
    /// True if the peer advertised the payment-channel capability in its
    /// `Version`. A peer that did not must never receive a channel message.
    channels: bool,
    /// The peer's stable channel node id (hex), parsed from its `Version` user
    /// agent. Empty if it advertised none. Used to re-bind channels to this
    /// peer across reconnects, since the connection id and inbound port change.
    channel_id: String,
    /// Per-peer budget for channel messages. See [`CHAN_BUCKET_MAX`].
    chan_bucket: TokenBucket,
    /// Height announced by the peer at the handshake.
    start_height: u64,
    /// Compact block reconstructions waiting for transactions.
    pending: HashMap<Hash256, (CompactBlock, Vec<u32>)>,
    /// How much snapshot data this peer can still get served. See
    /// [`TokenBucket`].
    snapshot_bucket: TokenBucket,
    /// The new transactions this peer can still push. See
    /// [`TX_RATE_PER_SEC`].
    tx_bucket: TokenBucket,
    /// The unsolicited compact announcements this peer can still push.
    /// See [`CMPCT_RATE_PER_SEC`].
    cmpct_bucket: TokenBucket,
    /// The header requests this peer can still send us. See
    /// [`HEADERS_RATE_PER_SEC`].
    headers_bucket: TokenBucket,
    /// The addresses this peer can still make us record. See
    /// [`ADDR_RATE_PER_SEC`].
    addr_bucket: TokenBucket,
    /// Header replies we expect from this peer. See
    /// [`MAX_EXPECTED_HEADERS`].
    expected_headers: u8,
    /// Block bodies requested from this peer, and when. See [`BODY_TIMEOUT`].
    /// Never more than [`MAX_BODIES_IN_FLIGHT`] entries: see
    /// [`Peer::note_body_requested`].
    requested_bodies: HashMap<Hash256, Instant>,
    /// Bodies this peer made known to us and that we have not requested yet,
    /// for lack of an in-flight slot. Served in chain order.
    /// See [`MAX_PENDING_BODIES`].
    bodies_to_request: VecDeque<Hash256>,
    /// This peer's last batch of headers was full: it has more, to be
    /// requested again once the queue and the bodies in flight are drained.
    more_expected: bool,
    /// Instant of the last frame received from this peer.
    ///
    /// # The defect this field fixes
    ///
    /// The read loop sets a 120-second timeout on the socket, and handled its
    /// expiry like this:
    ///
    /// ```text
    ///     Err(e) if e.kind() == WouldBlock => continue,
    /// ```
    ///
    /// That is: it started waiting again, indefinitely. A peer that stops
    /// sending was therefore **never** removed. The peer count stayed at one,
    /// and the maintenance loop — which only reconnects if peers are missing
    /// — had nothing to do.
    ///
    /// A laptop whose lid is closed produces exactly that: the connection dies
    /// without any FIN or RST arriving, and the node keeps a ghost peer
    /// forever. Found by closing a MacBook — the chain stopped at height 442
    /// and never moved again.
    ///
    /// On a public network, it is also an eclipse path: opening connections
    /// and then going quiet is enough to occupy every slot.
    last_received: Instant,
    /// Instant this peer last delivered something we had **requested** — a
    /// transaction or a block body. A peer that is answering our requests, if
    /// slowly, is not withholding: on a saturated link a block body queues
    /// behind the transactions we also asked for, and the body arrives late
    /// through no fault of the peer. A requested body overdue past
    /// [`BODY_TIMEOUT`] is therefore charged as withholding only to a peer
    /// that has delivered nothing at all within that window. See
    /// [`Node::maintain_peers`].
    last_delivered: Instant,
    /// Maintenance rounds in a row in which a body requested from this peer
    /// went overdue, with no body delivered since. A peer that serves every
    /// transaction we ask for but never a block body kept `last_delivered`
    /// fresh, was never charged, and delayed each block by [`BODY_TIMEOUT`]
    /// for as long as it liked. A body, even one that arrives after it was
    /// asked elsewhere, resets it: a slow link delivers late, a withholder
    /// never. Charged at [`MAX_BODY_OVERDUE_ROUNDS`].
    body_overdue_rounds: u8,
    /// Bodies that went overdue from this peer, most recent last: one of them
    /// arriving late still shows the peer delivers. Bounded by
    /// [`MAX_BODIES_IN_FLIGHT`].
    late_bodies: VecDeque<Hash256>,
    /// Instant of the last `Ping` sent that has gone unanswered.
    pending_ping: Option<Instant>,
    /// Transactions we asked this peer for and that have not arrived yet.
    /// Sending them is no misconduct, budget or not: see the `Tx` arm.
    /// Bounded by [`MAX_REQUESTED_TXS`].
    requested_txs: HashMap<Hash256, Instant>,
    /// Transactions this peer announced that its budget could not pay for
    /// yet: requested as soon as it refills, instead of waiting for the next
    /// offer of its pool. Bounded by [`MAX_ANNOUNCED_WAITING`].
    announced_waiting: VecDeque<Hash256>,
    /// Instant the connection was opened, fixed at creation. Used for the
    /// handshake deadline: see [`HANDSHAKE_TIMEOUT`]. Unlike `last_received`,
    /// no frame pushes it back — a connection that does not introduce itself
    /// therefore cannot extend its stay by fidgeting.
    connected_at: Instant,
    /// Number of headers received that connect to nothing known.
    ///
    /// Counts the signs that this peer is on another chain. Without this
    /// counter, two nodes with different geneses exchange blocks indefinitely
    /// that neither can connect — a defect observed by actually running two
    /// nodes, invisible in unit tests because both shared the same genesis
    /// there.
    consecutive_orphans: u32,
    /// Has the pool been offered to this peer since it connected? At the
    /// handshake if it is up to date, otherwise a minute later: a node that
    /// is still catching up cannot check a pending transaction, and refuses
    /// it. See [`MEMPOOL_OFFER_DELAY`].
    mempool_offered: bool,
    /// Protocol version the peer announced (0 before its `version`).
    version: u32,
    /// The nonce this peer introduced itself with: two connections that
    /// carry the same one lead to the same node. See the `Version` arm.
    remote_nonce: Option<u64>,
}

impl Peer {
    /// A block body arrived from this peer: if we had asked it for that body,
    /// on time or past its deadline, it is answering, and owes us no body.
    fn note_body_delivered(&mut self, bid: &Hash256) {
        let late = self.late_bodies.iter().position(|h| h == bid);
        if let Some(i) = late {
            self.late_bodies.remove(i);
        }
        if late.is_some() || self.requested_bodies.contains_key(bid) {
            self.last_delivered = Instant::now();
            self.body_overdue_rounds = 0;
        }
    }

    /// How many more transactions can be requested from this peer now: its
    /// budget, less what is already asked and not received. Forgets the
    /// requests older than [`TX_REQUEST_MEMORY`].
    fn tx_request_room(&mut self, now: Instant) -> usize {
        self.requested_txs
            .retain(|_, at| now.duration_since(*at) < TX_REQUEST_MEMORY);
        (self.tx_bucket.level(now, TX_BUCKET_MAX, TX_RATE_PER_SEC) as usize)
            .min(MAX_REQUESTED_TXS)
            .saturating_sub(self.requested_txs.len())
    }

    /// Notes a body requested from this peer, if the in-flight room allows it.
    ///
    /// This is the only entry point into `requested_bodies`: whatever path an
    /// identifier arrives by — headers, `inv`, re-request after withholding —
    /// the table never exceeds [`MAX_BODIES_IN_FLIGHT`]. Returns true if the
    /// body is in flight (newly noted, or already).
    fn note_body_requested(&mut self, h: Hash256, now: Instant) -> bool {
        if self.requested_bodies.contains_key(&h) {
            return true;
        }
        if self.requested_bodies.len() >= MAX_BODIES_IN_FLIGHT {
            return false;
        }
        self.requested_bodies.insert(h, now);
        true
    }

    /// What a message we send to this peer commits us to expect.
    ///
    /// A requested body takes an in-flight slot; a header request opens a
    /// reply slot. This is the only place where these two counts go up, and
    /// every send to a peer goes through it: see [`Node::handle`] and
    /// [`Node::send_to`].
    fn note_sent(&mut self, m: &Message, now: Instant) {
        match m {
            Message::GetData(items) => {
                for i in items.iter().filter(|i| i.kind == InvKind::CompactBlock) {
                    self.note_body_requested(i.hash, now);
                }
            }
            Message::GetHeaders { .. } => {
                self.expected_headers = self
                    .expected_headers
                    .saturating_add(1)
                    .min(MAX_EXPECTED_HEADERS);
            }
            _ => {}
        }
    }

    /// Stores a body to request later, if the queue has room.
    fn queue_body(&mut self, h: Hash256) {
        if self.bodies_to_request.len() < MAX_PENDING_BODIES {
            self.bodies_to_request.push_back(h);
        }
    }

    /// Moves the synchronization with this peer forward.
    ///
    /// Frees the slots of the bodies that arrived, fills the remaining ones
    /// from the queue, and — when there is nothing left either in flight or
    /// pending — asks for headers again if the peer announced more.
    ///
    /// # Why the header re-request waits for this moment
    ///
    /// It used to go out as soon as a full batch was received, with a locator
    /// that did not yet contain any of the batch's blocks: the peer replied
    /// with the same batch a second time. Here it goes out once the bodies
    /// have arrived, with an up-to-date locator, and asks for what follows.
    ///
    /// `after_progress` says whether a block from this peer has just been
    /// accepted. Only then does the height announced at the handshake
    /// authorize a re-request: on a mere batch of headers that are all known,
    /// it would make two nodes loop forever when one regards the other as a
    /// side branch. A full batch, on the other hand, always authorizes the
    /// continuation — the continuation is something other than this batch,
    /// since the locator now contains it.
    fn continue_sync(
        &mut self,
        id: u64,
        chain: &Chain,
        outgoing: &mut Vec<Outgoing>,
        now: Instant,
        after_progress: bool,
    ) {
        if !self.handshaked {
            return;
        }
        self.requested_bodies.retain(|h, _| !chain.has_block(h));
        // --- Catching up: whole blocks, not compact ones (0.4.5).
        //
        // A compact block saves bandwidth only when its transactions are
        // already in our mempool: true of a fresh block, never of an old one.
        // During a catch-up, each compact block carrying transactions cost a
        // second round trip, and they came one after the other: the next one
        // waits for its parent before asking for what it lacks. Measured
        // through a link with a 300 ms delay: one block every 2.5 seconds as
        // soon as the blocks carried transactions. Whole blocks travel sixteen
        // at a time, in one round trip.
        //
        // One request per block: a reply is capped at `REPLY_BYTE_BUDGET`,
        // and sixteen large blocks in one request would have left the last
        // ones unserved, then waited for the body deadline.
        let catching_up = self.start_height > chain.height() + MAX_BODIES_IN_FLIGHT as u64;
        let mut items = Vec::new();
        while self.requested_bodies.len() < MAX_BODIES_IN_FLIGHT {
            let Some(h) = self.bodies_to_request.pop_front() else {
                break;
            };
            if chain.has_block(&h) || self.requested_bodies.contains_key(&h) {
                continue;
            }
            if self.note_body_requested(h, now) {
                items.push(InvItem {
                    kind: if catching_up {
                        InvKind::Block
                    } else {
                        InvKind::CompactBlock
                    },
                    hash: h,
                });
            }
        }
        if !items.is_empty() {
            if catching_up {
                for i in items {
                    outgoing.push(Outgoing {
                        peer: id,
                        message: Message::GetData(vec![i]),
                    });
                }
            } else {
                outgoing.push(Outgoing {
                    peer: id,
                    message: Message::GetData(items),
                });
            }
            return;
        }
        let drained = self.bodies_to_request.is_empty() && self.requested_bodies.is_empty();
        let has_more = self.more_expected || (after_progress && self.start_height > chain.height());
        if drained && has_more {
            self.more_expected = false;
            outgoing.push(Outgoing {
                peer: id,
                message: Message::GetHeaders {
                    locator: chain.locator(),
                    stop: Hash256::ZERO,
                },
            });
        }
    }
}

/// Shared state of the node.
struct Shared {
    chain: Chain,
    mempool: Mempool,
    /// Address book, organized by network group.
    ///
    /// Lives under the same lock as the rest: a peer that announces addresses
    /// does so in the same message as the rest of its traffic, and splitting
    /// the locks would save time that does not exist at the cost of a deadlock
    /// risk that does.
    book: AddrBook,
    /// Onion service addresses (protocol 4): see [`crate::addr::OnionBook`].
    onions: crate::addr::OnionBook,
    /// Addresses found to lead to a node this one is already connected to
    /// (same nonce, through Tor), with that nonce. Bounded: see the
    /// `Version` arm.
    aliases: HashMap<SocketAddr, u64>,
    /// Transactions refused since the tip `rejected_at` for a reason a new
    /// block can change on its own — a conflicting spend confirmed, a fee
    /// floor that a block resets — so that they are not downloaded again at
    /// every offer. Bounded by [`MAX_RECENT_REJECTS`]; emptied when the tip
    /// moves. A **full pool** refusal does not go here: it survives blocks,
    /// in `full_pool_rejected`.
    rejected: HashSet<Hash256>,
    rejected_at: Hash256,
    /// Transactions refused for lack of room, with the fee rate and size they
    /// were refused at. Unlike `rejected`, this survives block changes: a full
    /// pool does not empty merely because the tip moved. Such a transaction is
    /// requested again only once the pool could actually take it
    /// ([`Mempool::would_admit`]) — free space, or an eviction floor that fell
    /// below its rate. Without it, every peer re-offered its whole pool after
    /// each block and the node re-downloaded everything it had just refused
    /// (measured at 8.7 transactions received per accepted payment, against
    /// 1.7 before). Bounded by [`MAX_RECENT_REJECTS`]; each entry, with the
    /// height it was refused at, lasts [`FULL_POOL_REFUSAL_BLOCKS`].
    ///
    /// Keyed by `txid`, which announcements carry and which leaves the witness
    /// out: only a refusal of a copy whose witness has the sizes its schemes
    /// fix is recorded ([`Mempool::witness_is_canonical`]), so that a copy
    /// padded to a lower rate cannot get the honest one ignored.
    full_pool_rejected: HashMap<Hash256, (u64, usize, u64)>,
    /// Transactions that arrived before their parent. See
    /// [`crate::mempool::OrphanPool`].
    orphans: crate::mempool::OrphanPool,
    peers: HashMap<u64, Peer>,
    network: Network,
    /// The node's nonce: used to detect a connection to oneself.
    nonce: u64,
    /// Where to record accepted blocks. Absent in pure memory (tests).
    journal: Option<Arc<dyn crate::chain::Journal>>,
    /// The already-serialized fast-sync snapshot, kept as long as the tip
    /// does not move. Rebuilding it is expensive (state snapshot +
    /// commitment): we only do it on request, and only once per tip.
    snapshot_cache: Option<SnapshotCache>,
    /// Compact blocks we requested whose parent was still on its way.
    ///
    /// A synchronization requests up to sixteen bodies at once. When one of
    /// them carries a transaction this node has never seen - always the case
    /// for a block of the past - its reconstruction costs a round trip, and
    /// the next bodies arrive before their parent is connected. They used to
    /// be dropped without a word: the sync then stood still until the body
    /// deadline, and the honest peer was penalized for "withholding" them.
    /// Observed in 0.4.1: one block per connection, past the first block
    /// holding a large transaction. They now wait here and are resumed as
    /// soon as their parent is connected. Bounded, and only for bodies this
    /// node asked for.
    parked: Vec<(u64, Box<CompactBlock>)>,
    /// True once a payment-channel service is installed; gates the collection
    /// below so a node without channels pays nothing.
    channels_active: bool,
    /// Transactions of blocks connected since the last drain, for the channel
    /// watcher to scan off the chain lock. Only filled when `channels_active`.
    channel_scan: Vec<(u64, Vec<crate::tx::Transaction>)>,
    /// Transactions of blocks a reorganization took off the active chain since
    /// the last drain, handed to the channel watcher before `channel_scan`.
    channel_unscan: Vec<Hash256>,
}

/// How many requested compact blocks may wait for their parent. Two batches
/// of bodies in flight: no honest situation needs more.
const MAX_PARKED: usize = 2 * MAX_BODIES_IN_FLIGHT;

/// The served snapshot, frozen for a given tip.
struct SnapshotCache {
    tip: Hash256,
    bytes: Vec<u8>,
    height: u64,
    announced_tip: Hash256,
    commitment: Hash256,
}

/// Rebuilds the served snapshot if the tip has moved since last time.
///
/// A client downloading while the tip advances will receive chunks of a
/// snapshot different from the announced one; its commitment check detects
/// it and it starts over. Consistency is therefore never broken silently.
fn refresh_snapshot(g: &mut Shared) {
    let tip = g.chain.tip_id();
    if g.snapshot_cache.as_ref().map(|c| c.tip) == Some(tip) {
        return;
    }
    g.snapshot_cache = g.chain.build_sync_snapshot().map(|a| {
        let bytes = a.encode();
        SnapshotCache {
            tip,
            height: a.announced_height().unwrap_or(0),
            announced_tip: a.announced_tip().unwrap_or(Hash256::ZERO),
            commitment: a.announced_commitment().unwrap_or(Hash256::ZERO),
            bytes,
        }
    });
}

/// Maximum items served in reply to a single message.
///
/// An honest peer never asks for that many at once; a hostile peer will get
/// nothing more.
const MAX_SERVED_ITEMS: usize = 512;

/// Outgoing byte budget for the reply to a single message.
///
/// This is the bound that turns an amplification into a plain request. Set
/// below the protocol's `MAX_PAYLOAD`: a reply the peer could not read would
/// be nothing but one-way waste.
const REPLY_BYTE_BUDGET: usize = 4 * 1024 * 1024;

/// Reply to send after the lock is released.
struct Outgoing {
    peer: u64,
    message: Message,
}

/// What a payment-channel component plugs into the node through. The node hands
/// it the bytes of an inbound channel message and the peer they came from, and
/// it returns the replies to send back (opaque bytes, each re-wrapped in a
/// [`Message::Channel`]) and a misconduct score for a malformed one. The node
/// calls it off the chain lock, so the component may do cryptography freely.
pub trait ChannelSink: Send + Sync {
    /// Handles one inbound channel frame from `peer`, whose durable identity
    /// (used to re-bind channels across a reconnect) is `peer_identity`.
    fn deliver(&self, peer: u64, peer_identity: &str, bytes: &[u8]) -> ChannelOutcome;

    /// This node's stable channel identity (hex), advertised in the handshake so
    /// peers can re-bind channels to it across reconnects. `None` means none is
    /// advertised.
    fn node_identity(&self) -> Option<String> {
        None
    }

    /// Called after each connected block, off the chain lock, with the block's
    /// transactions, the new chain `height`, and a `depth_of` oracle giving the
    /// confirmation depth (`1` in the tip) of an unspent outpoint or `None` once
    /// it is spent or absent. The component detects funding spends, confirms a
    /// buried funding, schedules delayed sweeps and settles closes, and returns
    /// the frames to send, each paired with its destination peer. The default
    /// does nothing.
    fn on_connected_block(
        &self,
        _txs: &[crate::tx::Transaction],
        _height: u64,
        _depth_of: &dyn Fn(&crate::tx::OutPoint) -> Option<(u64, crate::tx::TxOut)>,
    ) -> Vec<(u64, Vec<u8>)> {
        Vec::new()
    }

    /// Called when a channel-capable peer completes the handshake, off the chain
    /// lock, with its live connection id and its durable identity. Returns the
    /// frames to send it — the reestablish of every channel we hold with it,
    /// re-bound to the live id. The default does nothing.
    fn on_peer_connected(&self, _peer: u64, _peer_identity: &str) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Called, off the chain lock and before the blocks that replace them,
    /// with the ids of every transaction a reorganization disconnected, so a
    /// spend the component reacted to and that left the chain can be forgotten
    /// and a different one classified afresh. The default does nothing.
    fn on_disconnected_txids(&self, _txids: &[Hash256]) {}

    /// Called once at startup, off the chain lock, with the chain height, the
    /// transactions of the active chain's block at a height, and the depth
    /// oracle, so the component can catch up with what confirmed while the
    /// node was down. The default does nothing.
    fn rescan(
        &self,
        _tip: u64,
        _txs_at: &dyn Fn(u64) -> Option<Vec<crate::tx::Transaction>>,
        _depth_of: &dyn Fn(&crate::tx::OutPoint) -> Option<(u64, crate::tx::TxOut)>,
    ) {
    }
}

/// The result of handing a channel message to the [`ChannelSink`].
#[derive(Default)]
pub struct ChannelOutcome {
    /// Opaque channel-message payloads to send back to the same peer.
    pub replies: Vec<Vec<u8>>,
    /// Misconduct points for a malformed or unsolicited message; zero is none.
    pub penalize: u32,
}

/// A connected peer, as the RPC `getpeers` reports it.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// The stable connection id, the one `channelopen`/`send_channel` take.
    pub id: u64,
    /// The peer's address (or, behind a proxy, the label it is filed under).
    pub address: String,
    /// True if this node dialed the peer.
    pub outbound: bool,
    /// True once `Version` then `VerAck` have both been exchanged.
    pub handshake_complete: bool,
    /// True if the peer advertised the payment-channel capability.
    pub supports_channels: bool,
    /// The height the peer announced at the handshake.
    pub height: u64,
    /// The peer's stable channel node id (hex), empty if none advertised. A
    /// `channelopen` may name a peer by this, surviving reconnects.
    pub channel_id: String,
}

#[derive(Clone)]
pub struct Node {
    shared: Arc<Mutex<Shared>>,
    magic: [u8; 4],
    next_id: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    /// Observation counters, useful for tests and operations.
    pub stats: Arc<Stats>,
    /// SOCKS5 proxy (Tor) through which every outgoing connection goes.
    /// `None`: direct connections. See [`Node::set_proxy`].
    proxy: Arc<std::sync::RwLock<Option<SocketAddr>>>,
    /// This node's own onion service, announced to protocol-4 peers.
    own_onion: Arc<std::sync::RwLock<Option<crate::wire::OnionAddr>>>,
    /// The labels of the bootstrap addresses the operator configured. Only a
    /// link to one of them can make a later link to the same node redundant:
    /// see the `Version` arm.
    configured: Arc<std::sync::RwLock<HashSet<SocketAddr>>>,
    /// The payment-channel component, when this node runs channels (regtest).
    /// Its presence is what makes the node advertise the channel capability and
    /// accept channel messages; without it, channel frames are never sent and a
    /// received one is ignored.
    channel_sink: Arc<std::sync::RwLock<Option<Arc<dyn ChannelSink>>>>,
    /// This node's stable channel identity (hex), advertised in the handshake
    /// when channels are enabled. Set from the sink at [`Node::set_channel_sink`].
    own_channel_id: Arc<std::sync::RwLock<Option<String>>>,
    /// The links already warned about as predating the policy activation:
    /// see [`Node::warn_peers_predating_activation`].
    activation_warned: Arc<Mutex<HashSet<u64>>>,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub blocks_received: AtomicU64,
    pub blocks_accepted: AtomicU64,
    pub txs_received: AtomicU64,
    pub compacts_received: AtomicU64,
    /// Compact blocks reconstructed without any round trip.
    pub compacts_without_round_trip: AtomicU64,
    /// Compact announcements for which a reconstruction was started — mempool
    /// scan and allocation, under the lock. This is the expense the bucket
    /// bounds; see [`CMPCT_RATE_PER_SEC`].
    pub compacts_reconstructed: AtomicU64,
    /// Requested compact blocks that arrived before their parent, and waited.
    pub compacts_parked: AtomicU64,
    /// Of those, the ones resumed once their parent was connected.
    pub compacts_resumed: AtomicU64,
    /// Compact announcements rejected by the bucket, without reconstruction.
    pub compacts_rejected: AtomicU64,
    /// Compact announcements whose header was rejected **before** any
    /// reconstruction: wrong height, difficulty, timestamp or work. Nothing
    /// was searched or allocated for them; see [`Chain::check_header`].
    pub compacts_header_rejected: AtomicU64,
    pub peers_banned: AtomicU64,
    /// Blocks whose parent was unknown at the time they arrived.
    ///
    /// Must stay close to zero: strict header-based synchronization only
    /// requests a body after it connects. A counter that runs away signals a
    /// resynchronization loop — exactly the defect that only shows up when
    /// running real processes.
    pub orphan_blocks: AtomicU64,
    /// Blocks rejected by validation.
    pub invalid_blocks: AtomicU64,
    /// `addr` frames part of which was ignored, for lack of the peer's budget.
    pub addresses_ignored: AtomicU64,
    /// Header requests rejected by the peer's bucket, without serving anything.
    pub headers_rejected: AtomicU64,
    /// Batches of headers received without having been requested, and
    /// therefore ignored.
    pub unrequested_headers: AtomicU64,
    /// Proofs of work verified **outside** the global lock, before the block
    /// or announcement is processed. See [`Node::check_work_outside_lock`].
    pub work_outside_lock: AtomicU64,
    /// Frames dropped for a peer whose outgoing queue was full, or that could
    /// not take a reply in time. See [`crate::outbox`].
    pub outbox_dropped: AtomicU64,
    /// Requested transactions that arrived beyond the peer's budget: dropped,
    /// never penalized.
    pub solicited_over_budget: AtomicU64,
    /// Transactions announced by a peer and not requested from it, for lack
    /// of budget: they come again with the next offer.
    pub tx_requests_deferred: AtomicU64,
    /// Transactions that arrived before their parent and went in once it did.
    pub orphans_adopted: AtomicU64,
    /// Warnings logged about a connected peer that predates the policy
    /// activation. See [`Node::warn_peers_predating_activation`].
    pub peers_predating_activation_warned: AtomicU64,
}

impl Node {
    pub fn new(network: Network, chain: Chain) -> Node {
        let nonce = {
            // Entropy source without dependencies: the fine-grained clock is
            // enough to tell apart two nodes on the same machine.
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
                .unwrap_or(1);
            t.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1)
        };
        Node {
            shared: Arc::new(Mutex::new(Shared {
                chain,
                mempool: Mempool::new(),
                // Loopback and private ranges only make sense on regtest,
                // where everything runs on a single machine. The testnet is a
                // public network since 0.4: accepting them there let a home
                // network address travel from book to book (0.4.7).
                book: AddrBook::new(matches!(network, Network::Regtest)),
                onions: crate::addr::OnionBook::default(),
                aliases: HashMap::new(),
                rejected: HashSet::new(),
                rejected_at: Hash256::ZERO,
                full_pool_rejected: HashMap::new(),
                orphans: crate::mempool::OrphanPool::new(),
                peers: HashMap::new(),
                network,
                nonce,
                journal: None,
                snapshot_cache: None,
                parked: Vec::new(),
                channels_active: false,
                channel_scan: Vec::new(),
                channel_unscan: Vec::new(),
            })),
            magic: magic_for(network),
            next_id: Arc::new(AtomicU64::new(1)),
            stop: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Stats::default()),
            proxy: Arc::new(std::sync::RwLock::new(None)),
            own_onion: Arc::new(std::sync::RwLock::new(None)),
            configured: Arc::new(std::sync::RwLock::new(HashSet::new())),
            channel_sink: Arc::new(std::sync::RwLock::new(None)),
            own_channel_id: Arc::new(std::sync::RwLock::new(None)),
            activation_warned: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Installs the payment-channel component. From then on this node
    /// advertises the channel capability in its handshake and routes inbound
    /// channel messages to `sink`. Meant for regtest, where channels are
    /// active; the caller gates on the network.
    pub fn set_channel_sink(&self, sink: Arc<dyn ChannelSink>) {
        if let Ok(mut g) = self.own_channel_id.write() {
            *g = sink.node_identity();
        }
        if let Ok(mut g) = self.channel_sink.write() {
            *g = Some(sink);
        }
        self.shared.lock().unwrap().channels_active = true;
    }

    /// Whether this node speaks the channel protocol (a sink is installed).
    pub fn channels_enabled(&self) -> bool {
        self.channel_sink
            .read()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    /// Our user agent, carrying the channel capability token when enabled.
    fn user_agent(&self) -> String {
        if self.channels_enabled() {
            // The channel capability, followed by this node's stable channel id
            // so peers can re-bind channels to it across reconnects. The whole
            // string stays within `MAX_USER_AGENT`: "q21:0.4" + "+chan" + 32 hex.
            let id = self
                .own_channel_id
                .read()
                .ok()
                .and_then(|g| g.clone())
                .unwrap_or_default();
            format!("q21:0.4{}{}", crate::wire::CHANNELS_CAPABILITY, id)
        } else {
            "q21:0.4".into()
        }
    }

    /// Sends a channel message to `peer`, but only if that peer advertised the
    /// channel capability. Returns false if the peer is unknown or did not
    /// advertise it — so a node that does not speak the protocol is never sent
    /// one.
    pub fn send_channel(&self, peer: u64, payload: Vec<u8>) -> bool {
        let writer = {
            let g = self.shared.lock().unwrap();
            match g.peers.get(&peer) {
                Some(p) if p.handshaked && p.channels => Some(p.writer.clone()),
                _ => None,
            }
        };
        match writer {
            Some(w) => {
                let frame = frame_of(&Message::Channel(payload), self.magic);
                self.queue(&w, frame);
                true
            }
            None => false,
        }
    }

    /// Drains the transactions of blocks connected since the last call and
    /// hands them to the channel watcher, off the chain lock. Called after
    /// handling a message and usable by a startup rescan.
    pub fn scan_connected_blocks_for_channels(&self) {
        let sink = self
            .channel_sink
            .read()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        // No channel manager, nothing queued: the queues fill only once one is
        // installed (`channels_active`). Called after every message handled,
        // so the global lock is not taken for nothing.
        let Some(sink) = sink else {
            return;
        };
        let (untxs, txs) = {
            let mut g = self.shared.lock().unwrap();
            (
                std::mem::take(&mut g.channel_unscan),
                std::mem::take(&mut g.channel_scan),
            )
        };
        if !untxs.is_empty() {
            sink.on_disconnected_txids(&untxs);
        }
        // Block by block, each at its own height: a commitment's height
        // starts its to-self delay and the penalty's deadline.
        for (height, txs) in txs {
            self.drive_channels(&sink, &txs, height);
        }
    }

    /// Queues a locally connected block's transactions for the channel scan.
    /// A block received from a peer is queued inside `integrate`; one this node
    /// mines connects on another path, so the miner announces it here too, or
    /// its own channels would never see their funding confirm.
    pub fn note_local_block_for_channels(&self, b: &Block) {
        let mut g = self.shared.lock().unwrap();
        if g.channels_active {
            let height = g.chain.height();
            g.channel_scan.push((height, b.transactions.clone()));
        }
    }

    /// Drives the channel component once against the current chain state with no
    /// newly connected block — used at startup, so a funding that was already
    /// buried while the node was down is confirmed and its channel opens.
    pub fn rescan_channels(&self) {
        let sink = self
            .channel_sink
            .read()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        if let Some(sink) = sink {
            // First what confirmed while the node was down: a spend of a
            // funding output it never saw is replayed block by block.
            let tip = self.shared.lock().unwrap().chain.height();
            let txs_at = |h: u64| {
                let g = self.shared.lock().unwrap();
                g.chain.block_at(h).map(|b| b.transactions)
            };
            let depth_of = |op: &crate::tx::OutPoint| {
                let g = self.shared.lock().unwrap();
                g.chain
                    .utxo
                    .get(op)
                    .map(|e| (tip.saturating_sub(e.height).saturating_add(1), e.output))
            };
            sink.rescan(tip, &txs_at, &depth_of);
            self.drive_channels(&sink, &[], tip);
        }
    }

    /// Hands a connected block (or nothing, at startup) to the channel
    /// component with the chain height and a depth oracle, then sends the frames
    /// it returns. Off the chain lock, so the component may sign and broadcast.
    fn drive_channels(
        &self,
        sink: &Arc<dyn ChannelSink>,
        txs: &[crate::tx::Transaction],
        height: u64,
    ) {
        // Depths are read at the current tip, whatever block is being handed.
        let tip = self.shared.lock().unwrap().chain.height();
        let depth_of = |op: &crate::tx::OutPoint| {
            let g = self.shared.lock().unwrap();
            g.chain
                .utxo
                .get(op)
                .map(|e| (tip.saturating_sub(e.height).saturating_add(1), e.output))
        };
        let frames = sink.on_connected_block(txs, height, &depth_of);
        for (peer, frame) in frames {
            self.send_channel(peer, frame);
        }
    }

    /// A stable, sorted view of every connected peer, for the RPC. The `id` is
    /// the one [`Node::send_channel`] and `channelopen` take: it is fixed for
    /// the life of the connection, so an agent can read it here and name it.
    pub fn peer_list(&self) -> Vec<PeerInfo> {
        let g = self.shared.lock().unwrap();
        let mut v: Vec<PeerInfo> = g
            .peers
            .iter()
            .map(|(id, p)| PeerInfo {
                id: *id,
                address: p.addr.to_string(),
                outbound: p.outbound,
                handshake_complete: p.handshaked,
                supports_channels: p.channels,
                height: p.start_height,
                channel_id: p.channel_id.clone(),
            })
            .collect();
        v.sort_by_key(|p| p.id);
        v
    }

    /// A durable identifier for a peer, used to re-bind channels to a new
    /// connection id after a reconnect. It is the peer's advertised channel node
    /// id — stable on both the dialing and accepting sides, unlike the
    /// connection's ephemeral port — falling back to the address only for a peer
    /// that advertised no id. Empty for an unknown peer.
    pub fn peer_identity(&self, id: u64) -> String {
        let g = self.shared.lock().unwrap();
        g.peers
            .get(&id)
            .map(|p| {
                if p.channel_id.is_empty() {
                    p.addr.to_string()
                } else {
                    p.channel_id.clone()
                }
            })
            .unwrap_or_default()
    }

    /// The peers that advertised the channel capability, by id.
    pub fn channel_peers(&self) -> Vec<u64> {
        let g = self.shared.lock().unwrap();
        g.peers
            .iter()
            .filter(|(_, p)| p.handshaked && p.channels)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Records the bootstrap addresses the operator configured, by the
    /// label their links are filed under (see `socks::Target::label`).
    pub fn set_configured_targets(&self, labels: Vec<SocketAddr>) {
        if let Ok(mut g) = self.configured.write() {
            *g = labels.into_iter().collect();
        }
    }

    /// Declares this node's own onion service, announced to every
    /// protocol-4 peer at the handshake and in replies to `getaddr`.
    pub fn set_own_onion(&self, a: Option<crate::wire::OnionAddr>) {
        if let Ok(mut g) = self.own_onion.write() {
            *g = a;
        }
    }

    fn own_onion(&self) -> Option<crate::wire::OnionAddr> {
        self.own_onion
            .read()
            .ok()
            .and_then(|g| g.clone())
            .map(|mut a| {
                a.last_seen = unix_now();
                a
            })
    }

    /// Onion names to try, at most `count`: neither already connected nor
    /// this node's own.
    pub fn onions_to_try(&self, count: usize) -> Vec<crate::wire::OnionAddr> {
        let own = self.own_onion();
        let g = self.shared.lock().unwrap();
        g.onions
            .to_try()
            .into_iter()
            .filter(|a| own.as_ref().map(|o| o.name != a.name).unwrap_or(true))
            .filter(|a| {
                let label = crate::socks::Target::Name(a.host(), a.port).label();
                let alias_of = g.aliases.get(&label).copied();
                !g.peers
                    .values()
                    .any(|p| p.addr == label || (alias_of.is_some() && p.remote_nonce == alias_of))
            })
            .take(count)
            .collect()
    }

    pub fn note_onion_result(&self, a: &crate::wire::OnionAddr, ok: bool) {
        let mut g = self.shared.lock().unwrap();
        if ok {
            g.onions.note_success(&a.name, a.port, unix_now());
        } else {
            g.onions.note_failure(&a.name, a.port, unix_now());
        }
    }

    /// The onion names known, to write at shutdown.
    pub fn onion_entries(&self) -> Vec<crate::wire::OnionAddr> {
        self.shared
            .lock()
            .unwrap()
            .onions
            .to_announce(crate::addr::MAX_ONIONS)
    }

    /// Pours onion names back into the book: from `onions.dat` at startup.
    pub fn seed_onions(&self, v: Vec<crate::wire::OnionAddr>) -> usize {
        let mut g = self.shared.lock().unwrap();
        let now = unix_now();
        let before = g.onions.len();
        for a in v {
            g.onions.add(a, now);
        }
        g.onions.len() - before
    }

    /// Number of onion names known.
    pub fn onion_count(&self) -> usize {
        self.shared.lock().unwrap().onions.len()
    }

    /// What Tor brings this node, in numbers: onion names known, established
    /// connections to onion services, and established inbound connections
    /// handed over by the local Tor (they come from the loopback). The last
    /// one is counted only when this node announces an onion service: on a
    /// machine running several nodes, loopback peers are not Tor's.
    pub fn onion_status(&self) -> OnionStatus {
        let serving = self.own_onion().is_some();
        let g = self.shared.lock().unwrap();
        let labels: HashSet<SocketAddr> = g
            .onions
            .to_announce(crate::addr::MAX_ONIONS)
            .into_iter()
            .map(|a| crate::socks::Target::Name(a.host(), a.port).label())
            .collect();
        let mut s = OnionStatus {
            serving,
            known: g.onions.len(),
            ..OnionStatus::default()
        };
        for p in g.peers.values().filter(|p| p.handshaked) {
            if p.outbound && labels.contains(&p.addr) {
                s.outbound += 1;
            } else if serving && !p.outbound && p.addr.ip().is_loopback() {
                s.inbound += 1;
            }
        }
        s
    }

    /// Sends every outgoing connection through the SOCKS5 proxy at `p`
    /// (Tor), from now on. There is no fallback to a direct connection: a
    /// node asked to hide its address that quietly connected in the clear
    /// when the proxy failed would betray the person who asked.
    pub fn set_proxy(&self, p: Option<SocketAddr>) {
        if let Ok(mut g) = self.proxy.write() {
            *g = p;
        }
    }

    /// The proxy in use, if any.
    pub fn proxy(&self) -> Option<SocketAddr> {
        self.proxy.read().ok().and_then(|g| *g)
    }

    /// Connects to a target through the proxy: an IPv4 address, a host name
    /// or an onion service, the name being resolved by the proxy. The peer is
    /// filed under [`crate::socks::Target::label`]. Refused without a proxy.
    pub fn connect_target(&self, target: &crate::socks::Target) -> std::io::Result<u64> {
        let proxy = self.proxy().ok_or_else(|| {
            std::io::Error::other("a name or an onion address needs the proxy (--tor)")
        })?;
        let stream = crate::socks::connect(proxy, target, crate::socks::TOR_CONNECT_TIMEOUT)?;
        Ok(self.start_peer_as(stream, true, Some(target.label())))
    }

    /// Plugs in the journal where accepted blocks are recorded.
    ///
    /// To be called **before** letting in the slightest block: a block
    /// accepted without a journal is a block lost at the next shutdown.
    pub fn set_journal(&self, j: Arc<dyn crate::chain::Journal>) {
        self.shared.lock().unwrap().journal = Some(j);
    }

    pub fn height(&self) -> u64 {
        self.shared.lock().unwrap().chain.height()
    }

    // -----------------------------------------------------------------------
    // Address book
    // -----------------------------------------------------------------------

    /// Pours addresses into the address book — bootstrap or reload from disk.
    pub fn seed_addresses(&self, v: &[crate::wire::NetAddr]) -> usize {
        let mut g = self.shared.lock().unwrap();
        let n = unix_now();
        v.iter().filter(|a| g.book.add(**a, n)).count()
    }

    /// Addresses to try, all from distinct network groups and distinct from
    /// those of the peers already connected.
    pub fn addresses_to_try(&self, count: usize) -> Vec<crate::wire::NetAddr> {
        let g = self.shared.lock().unwrap();
        let already: Vec<[u8; 4]> = g
            .peers
            .values()
            .filter_map(|p| match p.addr {
                SocketAddr::V4(a) => Some(a.ip().octets()),
                _ => None,
            })
            .collect();
        g.book.select(count, &already, unix_now())
    }

    /// Distinct network groups among the connected peers.
    ///
    /// This is the measure that matters for eclipse: ten peers in a single
    /// group are worth a single peer.
    pub fn peer_groups(&self) -> usize {
        let g = self.shared.lock().unwrap();
        let s: std::collections::HashSet<[u8; 2]> = g
            .peers
            .values()
            .filter_map(|p| match p.addr {
                SocketAddr::V4(a) => Some(crate::addr::group(a.ip().octets())),
                _ => None,
            })
            .collect();
        s.len()
    }

    pub fn address_count(&self) -> usize {
        self.shared.lock().unwrap().book.len()
    }

    /// Copy of the address book, to write it to disk.
    pub fn address_entries(&self) -> Vec<crate::addr::AddrEntry> {
        self.shared.lock().unwrap().book.all()
    }

    pub fn note_connect_success(&self, ip: [u8; 4], port: u16) {
        let mut g = self.shared.lock().unwrap();
        g.book.add(
            crate::wire::NetAddr {
                ip,
                port,
                last_seen: unix_now(),
            },
            unix_now(),
        );
        g.book.mark_success(ip, port, unix_now());
    }

    pub fn note_connect_failure(&self, ip: [u8; 4], port: u16) {
        self.shared.lock().unwrap().book.mark_failure(ip, port);
    }

    pub fn tip_id(&self) -> Hash256 {
        self.shared.lock().unwrap().chain.tip_id()
    }

    /// Highest height announced by a peer whose handshake is done.
    ///
    /// This is the only measure a node has to know whether it is behind. It is
    /// worth what the peers are worth: an eclipsed node will see the height its
    /// adversary shows it. The address book is what makes this situation
    /// expensive to produce.
    pub fn max_announced_height(&self) -> u64 {
        let g = self.shared.lock().unwrap();
        g.peers
            .values()
            .filter(|p| p.handshaked)
            .map(|p| p.start_height)
            .max()
            .unwrap_or(0)
    }

    /// Number of open connections, **whether the handshake is done or not**.
    ///
    /// A peer counts here as soon as it is registered, before `Version` and
    /// `VerAck`. The sends that require the introduction — `announce_block`,
    /// `announce_tx` — will only see it once `handshaked`. Waiting for
    /// `peer_count() == 1` therefore does not guarantee that an announcement
    /// will be received.
    pub fn peer_count(&self) -> usize {
        self.shared.lock().unwrap().peers.len()
    }

    /// Number of peers whose handshake is **complete**.
    ///
    /// This is the only count that says "we are really talking". A TCP
    /// connection accepted and then closed by the peer — because it is full,
    /// or because our geneses differ — counts in `peer_count` for the space of
    /// a breath and never here. A diagnostic that only looked at `peer_count`
    /// would therefore announce a link where there is none.
    pub fn peer_count_established(&self) -> usize {
        self.shared
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|p| p.handshaked)
            .count()
    }

    /// Number of **outbound** connections — the ones we initiated from the
    /// address book. It is this count, not the total, that the maintenance
    /// loop must bring back to the target: otherwise a flood of inbound
    /// connections from a single IP is enough to prevent us from going out to
    /// find diversified peers, and the anti-eclipse defense falls.
    /// Does an inbound connection have its place?
    ///
    /// Three bounds: the total, the outbound reserve, and the share of a
    /// single network group — IPv4 and IPv6 alike, see [`inbound_group`].
    /// See [`RESERVED_OUTBOUND_SLOTS`] and [`INBOUND_PER_GROUP`].
    ///
    /// Takes the address rather than the stream: this way the rule can be
    /// tested on addresses that a machine without IPv6 could not open.
    /// Listening goes through [`Self::inbound_rejection`], which also gives
    /// the reason to the log.
    #[cfg(test)]
    fn admit_inbound(&self, address: Option<SocketAddr>) -> bool {
        self.inbound_rejection(address).is_none()
    }

    /// Why an inbound connection has no place, or `None` if it has one.
    ///
    /// Same rule as [`Self::admit_inbound`], which uses it; the reason goes to
    /// the log. A rejection without explanation cost hours: a household whose
    /// devices occupied the four slots of its group saw its fifth device
    /// "waiting" endlessly, and nothing, neither on the server side nor on the
    /// wallet side, said why.
    fn inbound_rejection(&self, address: Option<SocketAddr>) -> Option<&'static str> {
        let g = self.shared.lock().unwrap();
        let total = g.peers.len();
        if total >= MAX_PEERS {
            return Some("all slots are taken");
        }
        let inbound = g.peers.values().filter(|p| !p.outbound).count();
        if inbound + RESERVED_OUTBOUND_SLOTS >= MAX_PEERS {
            return Some("all inbound slots are taken");
        }
        if let Some(gr) = address.and_then(inbound_group) {
            let same = g
                .peers
                .values()
                .filter(|p| !p.outbound)
                .filter(|p| inbound_group(p.addr) == Some(gr))
                .count();
            if same >= INBOUND_PER_GROUP {
                return Some("its address group already has all its slots");
            }
        }
        None
    }

    pub fn peer_count_outbound(&self) -> usize {
        self.shared
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|p| p.outbound)
            .count()
    }

    /// Asks every established peer for the headers past our tip.
    ///
    /// Called when the tip has not moved for a while: an announcement can be
    /// missed — a peer whose queue was full drops it, a link cut at the wrong
    /// moment loses it — and a node that missed a block only heard of the
    /// chain again at the next one. In the endurance test, a wallet stayed at
    /// one height while the network moved on. One `getheaders` per peer
    /// costs a few hundred bytes; a peer with nothing new sends nothing back,
    /// and is not asked again while that request is outstanding. Returns the
    /// number of peers asked.
    pub fn ask_headers_from_all(&self) -> usize {
        let (ids, locator): (Vec<u64>, Vec<Hash256>) = {
            let g = self.shared.lock().unwrap();
            (
                // Only peers with no header request outstanding: a peer with
                // nothing new sends no answer, and asking again would pile up
                // expected answers that never come.
                g.peers
                    .iter()
                    .filter(|(_, p)| p.handshaked && p.expected_headers == 0)
                    .map(|(id, _)| *id)
                    .collect(),
                g.chain.locator(),
            )
        };
        let m = Message::GetHeaders {
            locator,
            stop: Hash256::ZERO,
        };
        for id in &ids {
            self.send_to(*id, &m);
        }
        ids.len()
    }

    /// Checks every connection after the machine may have slept: each peer
    /// is pinged, and the ones that do not answer within [`PROBE_GRACE`] are
    /// dropped by the next [`Node::maintain_peers`] — the others stay.
    ///
    /// # Why not drop them all
    ///
    /// Up to v0.4.8 every link was cut on the spot, on the reasoning that
    /// after a sleep they are dead anyway. But the detector can be fooled — a
    /// clock stepped by the system, a process frozen for a minute without the
    /// machine sleeping — and every false alarm cut live links, including the
    /// onion ones that take a minute to rebuild through Tor. Asking costs
    /// twenty seconds after a real sleep, and nothing after a false alarm.
    ///
    /// Returns the number of peers probed.
    pub fn probe_all_peers(&self) -> usize {
        let (writers, nonce) = {
            let mut g = self.shared.lock().unwrap();
            let now = Instant::now();
            // Silent, as far as the timeout is concerned, for all but the last
            // `PROBE_GRACE`: an answer — any frame — refreshes it.
            let deadline = now
                .checked_sub(MAX_SILENCE.saturating_sub(PROBE_GRACE))
                .unwrap_or(now);
            let mut writers = Vec::new();
            // Established peers only: the others have their handshake
            // timeout, and a ping must not overtake our `Version`.
            for p in g.peers.values_mut().filter(|p| p.handshaked) {
                if p.last_received > deadline {
                    p.last_received = deadline;
                }
                p.pending_ping = Some(now);
                writers.push(p.writer.clone());
            }
            (writers, g.nonce)
        };
        let n = writers.len();
        let frame = frame_of(&Message::Ping(nonce), self.magic);
        for w in &writers {
            // Forced: a peer whose queue is full must still be asked, or a
            // slow but live one would be dropped for a ping it never got.
            let _ = w.push_force(frame.clone());
        }
        n
    }

    /// Drops every connection, and returns how many there were.
    ///
    /// Used when a machine wakes up from sleep: after a few minutes of
    /// suspension, all TCP links are dead anyway — the router has forgotten
    /// its translation table, the peer on the other end has given up. Waiting
    /// for the silence timeout would cost two more minutes to someone who has
    /// simply reopened their laptop.
    ///
    /// Being wrong only costs a reconnection.
    pub fn disconnect_all_peers(&self) -> usize {
        let ids: Vec<u64> = self.shared.lock().unwrap().peers.keys().copied().collect();
        let n = ids.len();
        for id in ids {
            self.disconnect(id);
        }
        n
    }

    /// Are we already connected to this address?
    ///
    /// Used to avoid opening a second connection to a bootstrap address that
    /// we retry periodically: two links to the same peer waste a slot and
    /// double the traffic without bringing anything.
    pub fn is_connected_to(&self, addr: SocketAddr) -> bool {
        let g = self.shared.lock().unwrap();
        // An alias of a node we are linked to counts as connected, as long as
        // that link lasts: dialing it again would only be dropped again.
        let alias_of = g.aliases.get(&addr).copied();
        g.peers
            .values()
            .any(|p| p.addr == addr || (alias_of.is_some() && p.remote_nonce == alias_of))
    }

    /// Queries silent peers, and frees the slot of those that are dead.
    ///
    /// # Why it is not the socket that says so
    ///
    /// A TCP connection can outlive the machine on the other end. A laptop
    /// whose lid is closed, an unplugged cable, a router that forgets its
    /// table: in these cases, no FIN or RST ever arrives. The socket stays
    /// open, the read waits, and the node believes it has a peer.
    ///
    /// The only reliable sign of life is **a received frame**. So we ask the
    /// peer to show signs of life after a silence, and free its slot if it
    /// does not. This is what Bitcoin does, for the same reason.
    ///
    /// Returns the number of peers disconnected.
    pub fn maintain_peers(&self) -> usize {
        let now = Instant::now();
        let mut to_ping: Vec<Arc<Outbox>> = Vec::new();
        let mut dead: Vec<u64> = Vec::new();
        let magic = self.magic;
        let mut to_rerequest: Vec<Outgoing> = Vec::new();
        let nonce = {
            let mut g = self.shared.lock().unwrap();
            let Shared {
                ref chain,
                ref mempool,
                ref mut peers,
                ..
            } = *g;
            // --- The requested bodies: delivered, pending, or withheld?
            //
            // A body overdue past the timeout is re-requested from another
            // peer, and its holder is charged with withholding ONLY if it has
            // delivered nothing we asked for within the same window. On a
            // saturated link a 2 MB body queues behind the transactions we
            // also requested; a peer that keeps answering, if slowly, is not
            // withholding, and banning it split the network into halves that
            // ignored each other until the stale-tip timer. `delivered_nothing`
            // separates the honest-but-slow peer from the one that answers
            // nothing.
            let mut withheld: Vec<Hash256> = Vec::new();
            // (peer id, delivered nothing we asked for within the window).
            let mut holders: Vec<(u64, bool)> = Vec::new();
            for (id, p) in peers.iter_mut() {
                let mut overdue = 0u32;
                let late = &mut p.late_bodies;
                p.requested_bodies.retain(|h, since| {
                    if chain.has_block(h) {
                        return false;
                    }
                    if now.duration_since(*since) >= BODY_TIMEOUT {
                        overdue += 1;
                        withheld.push(*h);
                        if late.len() >= MAX_BODIES_IN_FLIGHT {
                            late.pop_front();
                        }
                        late.push_back(*h);
                        return false;
                    }
                    true
                });
                if overdue > 0 {
                    // Nothing we asked for within the window, or not one body
                    // for several rounds while answering only transactions.
                    p.body_overdue_rounds = p.body_overdue_rounds.saturating_add(1);
                    let no_body = p.body_overdue_rounds >= MAX_BODY_OVERDUE_ROUNDS;
                    if no_body {
                        p.body_overdue_rounds = 0;
                    }
                    let delivered_nothing =
                        now.duration_since(p.last_delivered) >= BODY_TIMEOUT || no_body;
                    holders.push((*id, delivered_nothing));
                }
            }
            if !withheld.is_empty() {
                let withholders: Vec<u64> = holders.iter().map(|(id, _)| *id).collect();
                // To another peer — established, and not one of the holders.
                let other = peers
                    .iter()
                    .filter(|(id, p)| {
                        p.handshaked && !dead.contains(id) && !withholders.contains(id)
                    })
                    .map(|(id, _)| *id)
                    .next();
                // Charge withholding to a holder that delivered nothing at all
                // in the window, or — when no other peer can serve the body —
                // to the holder anyway, so a node cornered with a single
                // non-delivering peer can still free the slot for a fresh one
                // rather than stall forever. A holder that is still answering
                // our other requests while another peer can fetch the body is
                // left untouched.
                for (hid, delivered_nothing) in &holders {
                    if *delivered_nothing || other.is_none() {
                        if let Some(p) = peers.get_mut(hid) {
                            p.ban_score = p.ban_score.saturating_add(MISCONDUCT_BODY_WITHHELD);
                            if p.ban_score >= BAN_THRESHOLD {
                                self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                dead.push(*hid);
                            }
                        }
                    }
                }
                if let Some(id) = other {
                    // As a full block, and without noting it in flight: this
                    // peer announced none of these bodies, it must not be
                    // punished for not having them. Noted in flight, the
                    // re-request cost it fifty points at the next deadline —
                    // and an identifier invented by an anonymous connection
                    // thus disconnected an honest peer in two rounds. The
                    // number stays bounded: at most `MAX_BODIES_IN_FLIGHT` per
                    // withholder.
                    to_rerequest.push(Outgoing {
                        peer: id,
                        message: Message::GetData(
                            withheld
                                .iter()
                                .map(|h| InvItem {
                                    kind: InvKind::Block,
                                    hash: *h,
                                })
                                .collect(),
                        ),
                    });
                    if let Some(p) = peers.get_mut(&id) {
                        p.continue_sync(id, chain, &mut to_rerequest, now, false);
                    }
                }
            }
            // --- The pool, offered to the peers that were catching up when
            // they connected.
            let late: Vec<u64> = peers
                .iter()
                .filter(|(id, p)| {
                    p.handshaked
                        && !p.mempool_offered
                        && !dead.contains(id)
                        && now.duration_since(p.connected_at) >= MEMPOOL_OFFER_DELAY
                })
                .map(|(id, _)| *id)
                .collect();
            if !late.is_empty() {
                let pending = mempool.announcement_window(MEMPOOL_REOFFER_MAX_TXS);
                for id in late {
                    if let Some(p) = peers.get_mut(&id) {
                        p.mempool_offered = true;
                    }
                    if !pending.is_empty() {
                        to_rerequest.push(Outgoing {
                            peer: id,
                            message: Message::Inv(
                                pending
                                    .iter()
                                    .map(|hash| InvItem {
                                        kind: InvKind::Tx,
                                        hash: *hash,
                                    })
                                    .collect(),
                            ),
                        });
                    }
                }
            }
            for (id, p) in peers.iter_mut() {
                if dead.contains(id) {
                    continue;
                }
                let silence = now.duration_since(p.last_received);
                if silence >= MAX_SILENCE {
                    dead.push(*id);
                } else if !p.handshaked && now.duration_since(p.connected_at) >= HANDSHAKE_TIMEOUT {
                    // Handshake never completed within the time limit: the
                    // inbound slot must not stay squatted by a connection that
                    // only fidgets. See HANDSHAKE_TIMEOUT.
                    dead.push(*id);
                } else if silence >= PING_AFTER && p.pending_ping.is_none() {
                    p.pending_ping = Some(now);
                    to_ping.push(p.writer.clone());
                }
            }
            g.nonce
        };
        for e in to_rerequest {
            self.send_to(e.peer, &e.message);
        }
        // Announced transactions that waited for a peer's budget: asked for
        // now if it has refilled, even if that peer has gone quiet since.
        let waiting: Vec<(u64, Message)> = {
            let mut g = self.shared.lock().unwrap();
            let ids: Vec<u64> = g.peers.keys().copied().collect();
            ids.into_iter()
                .filter_map(|id| Self::request_waiting_txs(&mut g, id, now).map(|m| (id, m)))
                .collect()
        };
        for (id, m) in waiting {
            self.send_to(id, &m);
        }
        // Queued outside the lock, and never waited for: a clogged peer only
        // misses its ping, and its own silence timeout drops it.
        if !to_ping.is_empty() {
            let frame = frame_of(&Message::Ping(nonce), magic);
            for writer in to_ping {
                // Forced: its answer is awaited — `pending_ping` is set.
                let _ = writer.push_force(frame.clone());
            }
        }
        let dropped = dead.len();
        for id in dead {
            // `disconnect` closes the socket in both directions: the read
            // loop, which was waiting, exits with an error and its thread dies.
            self.disconnect(id);
        }
        self.warn_peers_predating_activation();
        dropped
    }

    /// The established peers that do not follow the policy activation of
    /// this network ([`follows_activation`]): zero where it has no
    /// transition.
    pub fn peers_predating_activation(&self) -> usize {
        let g = self.shared.lock().unwrap();
        g.peers
            .values()
            .filter(|p| p.handshaked && !follows_activation(g.network, p.version))
            .count()
    }

    /// Logs a warning, once per link, for each established peer that predates
    /// the policy activation, from [`crate::consensus::POLICY_ACTIVATION_NOTICE`]
    /// blocks before the activation height on. Such a node stops at the first
    /// block carrying a policy: its operator must upgrade it before then, and
    /// ours should know that this link will not last. Called at every
    /// maintenance round; returns how many peers were warned about now.
    pub fn warn_peers_predating_activation(&self) -> usize {
        let (network, tip, peers, older) = {
            let g = self.shared.lock().unwrap();
            let older: Vec<(u64, SocketAddr, u32, String)> = g
                .peers
                .iter()
                .filter(|(_, p)| p.handshaked && !follows_activation(g.network, p.version))
                .map(|(id, p)| (*id, p.addr, p.version, p.user_agent.clone()))
                .collect();
            let peers: HashSet<u64> = g.peers.keys().copied().collect();
            (g.network, g.chain.height(), peers, older)
        };
        let mut warned = self.activation_warned.lock().unwrap();
        warned.retain(|id| peers.contains(id));
        if !crate::policy::has_transition(network) {
            return 0;
        }
        let h = crate::policy::activation_height(network);
        if tip.saturating_add(crate::consensus::POLICY_ACTIVATION_NOTICE) < h {
            return 0;
        }
        let mut count = 0;
        for (id, addr, version, agent) in older {
            if !warned.insert(id) {
                continue;
            }
            let when = if tip < h {
                format!("at block {h}, {} blocks from now", h - tip)
            } else {
                format!("since block {h}")
            };
            eprintln!(
                "warning: peer {addr} ({agent}, protocol {version}) predates the activation                  of policy outputs {when}: it stops at the first block carrying one.                  Its operator must upgrade it to 0.4.11 or later."
            );
            count += 1;
        }
        self.stats
            .peers_predating_activation_warned
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    pub fn mempool_len(&self) -> usize {
        self.shared.lock().unwrap().mempool.len()
    }

    /// Runs `f` with exclusive access to the chain.
    pub fn with_chain<R>(&self, f: impl FnOnce(&mut Chain) -> R) -> R {
        let mut g = self.shared.lock().unwrap();
        f(&mut g.chain)
    }

    pub fn with_mempool<R>(&self, f: impl FnOnce(&mut Mempool) -> R) -> R {
        let mut g = self.shared.lock().unwrap();
        f(&mut g.mempool)
    }

    /// Runs `f` with exclusive access to the chain **and** the mempool.
    ///
    /// Both live under the same lock. Calling `with_chain` inside
    /// `with_mempool` — or the reverse — would take it twice and freeze the
    /// node on the spot. Any operation that needs both goes through here.
    pub fn with_chain_and_mempool<R>(&self, f: impl FnOnce(&mut Chain, &mut Mempool) -> R) -> R {
        let mut g = self.shared.lock().unwrap();
        let Shared {
            ref mut chain,
            ref mut mempool,
            ..
        } = *g;
        f(chain, mempool)
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Opens a listening port and accepts connections in the background.
    pub fn listen(&self, addr: &str) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        let node = self.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if node.is_stopped() {
                    break;
                }
                match stream {
                    Ok(s) => {
                        let address = s.peer_addr().ok();
                        if let Some(reason) = node.inbound_rejection(address) {
                            report_rejection(address, reason);
                            continue;
                        }
                        node.start_peer(s, false);
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(local)
    }

    /// Connects to a peer and starts the handshake.
    pub fn connect(&self, addr: SocketAddr) -> std::io::Result<u64> {
        // Through the proxy when there is one: never in the clear.
        if let Some(proxy) = self.proxy() {
            let target = match addr {
                SocketAddr::V4(a) => crate::socks::Target::V4(a.ip().octets(), a.port()),
                SocketAddr::V6(_) => {
                    return Err(std::io::Error::other(
                        "IPv6 is not supported through a proxy",
                    ))
                }
            };
            let stream = crate::socks::connect(proxy, &target, crate::socks::TOR_CONNECT_TIMEOUT)?;
            return Ok(self.start_peer_as(stream, true, Some(addr)));
        }
        // Four seconds: enough for a slow link, not enough for a batch of
        // silent addresses to hold the maintenance loop for a minute.
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(4))?;
        Ok(self.start_peer(stream, true))
    }

    fn start_peer(&self, stream: TcpStream, outbound: bool) -> u64 {
        self.start_peer_as(stream, outbound, None)
    }

    /// Like `start_peer`, filing the peer under `label` instead of the
    /// socket's remote end: behind a proxy, that end is the proxy itself.
    fn start_peer_as(&self, stream: TcpStream, outbound: bool, label: Option<SocketAddr>) -> u64 {
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        // Without a write timeout, a peer that never takes in its bytes blocks
        // the thread writing to it indefinitely — while holding the mutex of
        // its stream. Since broadcasts write to every peer, a single silent
        // peer ended up blocking the entire propagation.
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
        let _ = stream.set_nodelay(true);
        let addr = label.unwrap_or_else(|| {
            stream
                .peer_addr()
                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
        });
        let reader = match stream.try_clone() {
            Ok(f) => f,
            Err(_) => return 0,
        };

        let writer = match Outbox::start(stream) {
            Ok(w) => w,
            Err(_) => return 0,
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        {
            let mut g = self.shared.lock().unwrap();
            g.peers.insert(
                id,
                Peer {
                    addr,
                    writer: writer.clone(),
                    outbound,
                    snapshot_bucket: TokenBucket::new(Instant::now()),
                    tx_bucket: TokenBucket::for_transactions(Instant::now()),
                    cmpct_bucket: TokenBucket::for_compact_announcements(Instant::now()),
                    headers_bucket: TokenBucket::for_header_requests(Instant::now()),
                    addr_bucket: TokenBucket::for_addresses(Instant::now()),
                    expected_headers: 0,
                    requested_bodies: HashMap::new(),
                    bodies_to_request: VecDeque::new(),
                    more_expected: false,
                    version_received: false,
                    version_sent: outbound,
                    handshaked: false,
                    ban_score: 0,
                    user_agent: String::new(),
                    channels: false,
                    channel_id: String::new(),
                    chan_bucket: TokenBucket::for_channel_messages(Instant::now()),
                    start_height: 0,
                    pending: HashMap::new(),
                    consecutive_orphans: 0,
                    mempool_offered: false,
                    version: 0,
                    remote_nonce: None,
                    last_received: Instant::now(),
                    last_delivered: Instant::now(),
                    body_overdue_rounds: 0,
                    late_bodies: VecDeque::new(),
                    pending_ping: None,
                    requested_txs: HashMap::new(),
                    announced_waiting: VecDeque::new(),
                    connected_at: Instant::now(),
                },
            );
        }

        // The connecting side speaks first.
        if outbound {
            let (nonce, height) = {
                let g = self.shared.lock().unwrap();
                (g.nonce, g.chain.height())
            };
            let v = Message::Version {
                version: PROTOCOL_VERSION,
                timestamp: unix_now(),
                nonce,
                user_agent: self.user_agent(),
                start_height: height,
            };
            let _ = writer.push_force(frame_of(&v, self.magic));
        }

        let node = self.clone();
        std::thread::spawn(move || {
            node.read_loop(id, reader);
            node.disconnect(id);
        });
        id
    }

    fn disconnect(&self, id: u64) {
        // The peer leaves the table under the lock; its socket is closed after.
        // Closing never waits — up to v0.4.8 it took the socket's mutex, held
        // by any write in progress, for up to WRITE_TIMEOUT, **while holding
        // the node's lock**: one stalled peer then froze the whole node.
        let removed = self.shared.lock().unwrap().peers.remove(&id);
        if let Some(p) = removed {
            p.writer.close();
        }
    }

    /// A peer's read loop.
    ///
    /// The buffer never grows beyond the maximum size of a frame: this is what
    /// prevents a peer from exhausting memory by announcing a gigantic payload
    /// and then sending nothing.
    fn read_loop(&self, id: u64, mut stream: TcpStream) {
        let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut chunk = [0u8; 32 * 1024];

        loop {
            if self.is_stopped() {
                return;
            }
            let n = match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                // A read cut short by a signal, not by the peer. On Linux a
                // socket with a receive timeout fails every blocked read with
                // EINTR once the process resumes from a stop (SIGSTOP or
                // Ctrl-Z, then SIGCONT), handler or not: treated as fatal, a
                // pause of a few seconds dropped every live link at once.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            buffer.extend_from_slice(&chunk[..n]);

            if buffer.len() > MAX_PAYLOAD + HEADER_LEN {
                self.penalize(id, MISCONDUCT_MALFORMED * 10);
                return;
            }

            loop {
                match Message::parse(&buffer, self.magic) {
                    Ok((msg, consumed)) => {
                        buffer.drain(..consumed);
                        if msg.carries_policy_output() && self.policy_is_malformed_from(id, &msg) {
                            self.penalize(id, MISCONDUCT_MALFORMED);
                            return;
                        }
                        if !self.handle(id, msg) {
                            return;
                        }
                    }
                    Err(WireError::Incomplete) => break,
                    Err(_) => {
                        self.penalize(id, MISCONDUCT_MALFORMED);
                        // Lost framing cannot be recovered: we disconnect.
                        return;
                    }
                }
            }
        }
    }

    /// [`policy_output_is_malformed`] for a message of peer `id`, against
    /// our tip and what the peer announced at the handshake.
    fn policy_is_malformed_from(&self, id: u64, msg: &Message) -> bool {
        let (network, tip, version, height) = {
            let g = self.shared.lock().unwrap();
            let (version, height) = g
                .peers
                .get(&id)
                .map(|p| (p.version, p.start_height))
                .unwrap_or((0, 0));
            (g.network, g.chain.height(), version, height)
        };
        policy_output_is_malformed(network, tip, version, height, msg)
    }

    /// A transaction that only its author could have made invalid.
    fn tx_invalid_in_itself(e: &crate::mempool::MempoolError) -> bool {
        use crate::mempool::MempoolError as M;
        use crate::validate::ValidationError as V;
        match e {
            // "I cannot verify" is not "you are lying": see
            // `locally_unverifiable_scheme`.
            M::Validation(v) if locally_unverifiable_scheme(v).is_some() => false,
            // A policy output our next block cannot carry yet, from a peer
            // ahead of us: the height, not its author, makes it invalid. Where
            // the peer could not honestly be ahead, the message never got
            // this far (`policy_output_is_malformed`).
            M::Validation(V::SchemeForbiddenOnNetwork(crate::sig::SchemeId::Policy)) => false,
            M::Validation(
                V::Signature(_)
                | V::KeyDoesNotMatchLock
                | V::Transaction(_)
                | V::ValueNotConserved { .. }
                | V::SchemeForbiddenOnNetwork(_)
                | V::DustOutput { .. },
            ) => true,
            // A policy spend that does not satisfy its policy is made so by
            // its author — wrong preimage, branch, lock, extra bytes — except
            // a time lock not yet expired, which an honest relay can send a
            // block early.
            M::Validation(V::Policy(p)) => {
                !matches!(p, crate::policy::PolicyError::TooEarly { .. })
            }
            _ => false,
        }
    }

    /// Adds `points` to the peer's score. Returns whether the peer may stay:
    /// `false` once its score reaches [`BAN_THRESHOLD`].
    fn penalize(&self, id: u64, points: u32) -> bool {
        let mut g = self.shared.lock().unwrap();
        if let Some(p) = g.peers.get_mut(&id) {
            p.ban_score = p.ban_score.saturating_add(points);
            if p.ban_score >= BAN_THRESHOLD {
                self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        true
    }

    /// Verifies the proof of work of a received header **without** holding the
    /// global lock, and keeps the verdict for the chain.
    ///
    /// # The defect this closes
    ///
    /// A received block or compact announcement made us compute its
    /// memory-hard hash under the global lock — and, at the first block of an
    /// epoch, build that epoch's entire cache, several seconds on mainnet.
    /// During that time, no other peer was served and the wallet no longer
    /// responded. A peer only had to send headers with the correct context and
    /// wrong work to occupy the lock at will, within the limit of its score.
    ///
    /// The lock is now only taken for the cheap checks — handshake,
    /// announcement budget, connection to the chain, difficulty, timestamp:
    /// see [`Chain::header_to_prove`]. The hash is computed afterwards, with
    /// the lock released, and its verdict recorded in the chain's registry.
    /// The handler then takes its usual path, where the chain reads the
    /// verdict back instead of recomputing it. No rule changes: the checks are
    /// all redone under the lock, in the same order.
    ///
    /// A compact announcement that the peer's budget would reject is not
    /// computed: the budget comes before the work, here as under the lock.
    fn check_work_outside_lock(
        &self,
        id: u64,
        header: &crate::block::BlockHeader,
        announcement: bool,
    ) {
        let to_prove = {
            let g = self.shared.lock().unwrap();
            let Some(p) = g.peers.get(&id) else {
                return;
            };
            if !p.handshaked {
                return;
            }
            if announcement
                && !p.requested_bodies.contains_key(&header.block_id())
                && !p.cmpct_bucket.available(
                    1,
                    Instant::now(),
                    CMPCT_BUCKET_MAX,
                    CMPCT_RATE_PER_SEC,
                )
            {
                return;
            }
            g.chain.header_to_prove(header, unix_now())
        }; // --- lock released: the computation that follows blocks nobody ---
        if let Some((engine, memo)) = to_prove {
            use crate::pow::PowEngine;
            memo.record(header.block_id(), engine.check(header));
            self.stats.work_outside_lock.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Handles a message. Returns `false` if the connection must be dropped.
    fn handle(&self, id: u64, msg: Message) -> bool {
        let mut outgoing: Vec<Outgoing> = Vec::new();
        let mut drop_peer = false;
        // Set under the lock, acted on after it is released: a channel message
        // to hand to the channel component (off the chain lock, so it may do
        // cryptography), and a misconduct score for an unsolicited one.
        let mut channel_in: Option<Vec<u8>> = None;
        let mut channel_penalty: u32 = 0;
        // Set when this message completes the handshake with a channel-capable
        // peer: once the lock is released, the channel component is asked to
        // resync (reestablish) every channel it holds with that peer.
        let mut channel_peer_ready = false;

        // The work of a block or of an announcement is checked before the lock.
        match &msg {
            Message::Block(b) => self.check_work_outside_lock(id, &b.header, false),
            Message::CmpctBlock(c) => self.check_work_outside_lock(id, &c.header, true),
            _ => {}
        }

        {
            let mut g = self.shared.lock().unwrap();
            // A received frame, whatever it is, proves that the peer is alive.
            // It is the only proof that counts: an open socket is not one, it
            // can outlive the machine on the other end.
            if let Some(p) = g.peers.get_mut(&id) {
                p.last_received = Instant::now();
                p.pending_ping = None;
            }
            let network = g.network;
            let local_nonce = g.nonce;
            // The handshake gates access to expensive messages. Serving a
            // `getdata` to a mere anonymous TCP connection reduces the cost of
            // an amplification to one `connect()`.
            let handshaked = g.peers.get(&id).map(|p| p.handshaked).unwrap_or(false);

            match msg {
                Message::Version {
                    version,
                    nonce,
                    start_height,
                    ref user_agent,
                    ..
                } => {
                    // Connection to oneself: we disconnect without ceremony. A
                    // peer from another era of the protocol too: it would not
                    // validate the same rules, and each would punish the other
                    // for blocks the other considers valid.
                    // --- The same node reached twice.
                    //
                    // Through Tor, a server named in the bootstrap file by its
                    // name and by its address is dialed twice: the proxy
                    // resolves the name, this node never learns that both lead
                    // to the same machine, and it counts two peers where there
                    // is one. The nonce gives it away. Only outbound links
                    // through Tor are compared, and the newer one is dropped:
                    // a stranger who copied a nonce can never push out a
                    // connection that was there first.
                    //
                    // The nonce is chosen by the remote side, and a stranger
                    // can copy an entry point's. So a link counts as the
                    // original only if it goes to an address the operator
                    // configured: an onion name learned from gossip that
                    // claims an entry point's nonce never pushes the real
                    // entry point out.
                    let configured = self.configured.read();
                    let is_configured = |a: &SocketAddr| {
                        configured.as_ref().map(|c| c.contains(a)).unwrap_or(false)
                    };
                    let duplicate = self.proxy().is_some()
                        && g.peers
                            .get(&id)
                            .map(|p| p.outbound && !p.version_received)
                            .unwrap_or(false)
                        && g.peers.iter().any(|(other, p)| {
                            *other != id
                                && p.outbound
                                && p.remote_nonce == Some(nonce)
                                && is_configured(&p.addr)
                        });
                    if duplicate {
                        if let Some(addr) = g.peers.get(&id).map(|p| p.addr) {
                            if g.aliases.len() >= 64 {
                                g.aliases.clear();
                            }
                            g.aliases.insert(addr, nonce);
                        }
                    }
                    if nonce == local_nonce || version < MIN_PROTOCOL_VERSION || duplicate {
                        drop_peer = true;
                    } else {
                        let height = g.chain.height();
                        if let Some(p) = g.peers.get_mut(&id) {
                            // --- One `Version` per peer, and only one in return.
                            //
                            // Every `Version` received made us send back a
                            // `Version`, including to the one who had sent it
                            // in reply to ours: two nodes therefore exchanged
                            // `Version`/`VerAck`/`GetAddr`/`Addr` endlessly,
                            // tens of thousands of frames per second, and each
                            // round restarted a header request. The responder
                            // introduces itself once, before its `VerAck` so
                            // that the other end has our `Version` when the
                            // acknowledgment reaches it; a duplicate is ignored.
                            if !p.version_received {
                                p.version_received = true;
                                p.start_height = start_height;
                                p.version = version;
                                p.remote_nonce = Some(nonce);
                                p.channels =
                                    crate::wire::user_agent_advertises_channels(user_agent);
                                p.channel_id =
                                    crate::wire::channel_node_id(user_agent).unwrap_or_default();
                                p.user_agent = user_agent.clone();
                                if !p.version_sent {
                                    p.version_sent = true;
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::Version {
                                            version: PROTOCOL_VERSION,
                                            timestamp: unix_now(),
                                            nonce: local_nonce,
                                            user_agent: self.user_agent(),
                                            start_height: height,
                                        },
                                    });
                                }
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::VerAck,
                                });
                            }
                        }
                    }
                }

                Message::VerAck => {
                    let (behind, locator) = {
                        let height = g.chain.height();
                        let p = g.peers.get_mut(&id);
                        match p {
                            // A `VerAck` only completes the handshake if a
                            // `Version` preceded it. Otherwise we ignore it: no
                            // access to expensive messages, and the nonce check
                            // (connection to oneself) is not bypassed.
                            Some(p) if p.version_received => {
                                p.handshaked = true;
                                channel_peer_ready = p.channels;
                                (p.start_height > height, g.chain.locator())
                            }
                            _ => (false, Vec::new()),
                        }
                    };
                    if behind {
                        outgoing.push(Outgoing {
                            peer: id,
                            message: Message::GetHeaders {
                                locator,
                                stop: Hash256::ZERO,
                            },
                        });
                    }
                    // The pending transactions, offered to the new peer: those
                    // sent before it connected reach it now, not never. See
                    // `Mempool::announcement`. Only if it is up to date: a peer
                    // still catching up gets them later, see
                    // `MEMPOOL_OFFER_DELAY`.
                    let height = g.chain.height();
                    let offer_now = match g.peers.get_mut(&id) {
                        Some(p)
                            if p.handshaked && !p.mempool_offered && p.start_height >= height =>
                        {
                            p.mempool_offered = true;
                            true
                        }
                        _ => false,
                    };
                    if offer_now {
                        let pending = g.mempool.announcement_window(MEMPOOL_REOFFER_MAX_TXS);
                        if !pending.is_empty() {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::Inv(
                                    pending
                                        .into_iter()
                                        .map(|hash| InvItem {
                                            kind: InvKind::Tx,
                                            hash,
                                        })
                                        .collect(),
                                ),
                            });
                        }
                    }
                    // Our own onion service, to a peer that understands it.
                    let modern = g
                        .peers
                        .get(&id)
                        .map(|p| p.version >= crate::wire::ONION_ADDR_VERSION)
                        .unwrap_or(false);
                    if modern {
                        if let Some(own) = self.own_onion() {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::OnionAddr(vec![own]),
                            });
                        }
                    }
                    // We ask every new peer for its address book. It is the
                    // only discovery mechanism: without it, a node only ever
                    // knows the addresses it was given by hand.
                    outgoing.push(Outgoing {
                        peer: id,
                        message: Message::GetAddr,
                    });
                }

                Message::Ping(n) => outgoing.push(Outgoing {
                    peer: id,
                    message: Message::Pong(n),
                }),
                Message::Pong(_) => {}

                Message::GetHeaders { locator, stop } => {
                    // Like any service, the reply to headers requires the
                    // handshake: synchronization never asks for headers before
                    // it (see the VerAck arm), so nothing honest is lost, and an
                    // anonymous connection can no longer trigger serving work.
                    //
                    // And, like any service, it goes through a bucket: see
                    // [`HEADERS_RATE_PER_SEC`]. Beyond it, we serve nothing and
                    // do not disconnect — an honest client waits.
                    let allowed = handshaked
                        && g.peers
                            .get_mut(&id)
                            .map(|p| {
                                p.headers_bucket.allow_with(
                                    1,
                                    Instant::now(),
                                    HEADERS_BUCKET_MAX,
                                    HEADERS_RATE_PER_SEC,
                                )
                            })
                            .unwrap_or(false);
                    if handshaked && !allowed {
                        self.stats.headers_rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    if allowed {
                        let h = g
                            .chain
                            .headers_from(&locator, stop, crate::wire::MAX_HEADERS);
                        if !h.is_empty() {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::Headers(h),
                            });
                        }
                    }
                }

                Message::Headers(v) if v.is_empty() => {}

                Message::Headers(v) if !handshaked => {
                    // Same rule as `getheaders`: synchronization only receives
                    // headers in reply to its own request, which goes out after
                    // the handshake (VerAck arm). Nothing honest is lost, and an
                    // anonymous connection no longer makes us hash two thousand
                    // headers nor request a single body. The "pushed" message
                    // went through the door that the "requested" message kept
                    // shut.
                    let _ = v;
                }

                Message::Headers(v) if g.peers.get(&id).map(|p| p.expected_headers) == Some(0) => {
                    // Nobody asked for this batch: see [`MAX_EXPECTED_HEADERS`].
                    // It is not read — no hash, no body queue — and the peer,
                    // the only one who could have produced it, loses points.
                    let _ = v;
                    self.stats
                        .unrequested_headers
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.ban_score = p.ban_score.saturating_add(MISCONDUCT_UNREQUESTED_HEADERS);
                        if p.ban_score >= BAN_THRESHOLD {
                            self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                            drop_peer = true;
                        }
                    }
                }

                Message::Headers(v) => {
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.expected_headers = p.expected_headers.saturating_sub(1);
                    }
                    // --- Header-based synchronization, strict on chaining.
                    //
                    // We **never** request a block body before having checked
                    // that the sequence of headers connects to the chain we
                    // already know. Without this check, a peer on an
                    // incompatible chain makes us download orphan blocks
                    // indefinitely: that is the defect observed when running
                    // two nodes with different geneses, 29,850 blocks received
                    // for a height that stayed at zero.
                    //
                    // Strict on chaining, not on work: the proof of work is not
                    // checked here — it is memory-hard, and checking it on two
                    // thousand headers would cost more than what it would
                    // protect. A sequence chained onto our tip can therefore be
                    // fabricated offline, for free. What bounds what it can make
                    // us do is the per-peer cap on bodies in flight
                    // (`MAX_BODIES_IN_FLIGHT`): the work is only checked when the
                    // body arrives, sixteen at a time.
                    let connects = g.chain.has_block(&v[0].prev_block);

                    let mut contiguous = connects;
                    if contiguous {
                        for f in v.windows(2) {
                            if f[1].prev_block != f[0].block_id() {
                                contiguous = false;
                                break;
                            }
                        }
                    }

                    if !contiguous {
                        let incompatible = {
                            let p = g.peers.get_mut(&id);
                            match p {
                                Some(p) => {
                                    p.consecutive_orphans += 1;
                                    p.consecutive_orphans >= 3
                                }
                                None => true,
                            }
                        };
                        if incompatible {
                            // This peer is not on our chain. Insisting would
                            // cost everyone and lead nowhere.
                            drop_peer = true;
                        }
                    } else {
                        let Shared {
                            ref chain,
                            ref mut peers,
                            ..
                        } = *g;
                        if let Some(p) = peers.get_mut(&id) {
                            p.consecutive_orphans = 0;
                            // The batch replaces the queue: a peer only replies
                            // with headers to our request, and we only ask for
                            // the continuation once the queue is drained. This
                            // is what bounds the queue to one batch, whatever
                            // the peer pushes.
                            p.bodies_to_request.clear();
                            p.bodies_to_request.extend(
                                v.iter()
                                    .map(|h| h.block_id())
                                    .filter(|bid| !chain.has_block(bid))
                                    .take(MAX_PENDING_BODIES),
                            );
                            p.more_expected = v.len() >= crate::wire::MAX_HEADERS;
                            p.continue_sync(id, chain, &mut outgoing, Instant::now(), false);
                        }
                    }
                }

                Message::Inv(v) if !handshaked => {
                    // Same rule as `getdata` and `addr`: nothing is read before
                    // the handshake. A read `inv` made us request bodies and
                    // record them in flight on behalf of an anonymous
                    // connection — the starting point of the defect fixed in
                    // `maintain_peers`. No honest node announces before having
                    // introduced itself: see `announce_block` and `announce_tx`.
                    let _ = v;
                }

                Message::Inv(v) => {
                    let mut wanted = Vec::new();
                    let mut blocks = Vec::new();
                    for i in v {
                        match i.kind {
                            InvKind::Block | InvKind::CompactBlock => {
                                if !g.chain.has_block(&i.hash) {
                                    blocks.push(i.hash);
                                }
                            }
                            InvKind::Tx => {
                                if Self::should_request_tx(&g, &i.hash) {
                                    wanted.push(i);
                                }
                            }
                        }
                    }
                    // Only what the peer's budget can pay for is requested
                    // now; the rest waits, per peer, and is requested as the
                    // budget refills (see `request_waiting_txs`). A request
                    // is remembered for a minute, so that its answer is never
                    // misconduct (see the `Tx` arm) — and bounding the
                    // requests by the budget is what keeps that exemption
                    // from becoming free work.
                    if let Some(p) = g.peers.get_mut(&id) {
                        let now = Instant::now();
                        let room = p.tx_request_room(now);
                        if wanted.len() > room {
                            self.stats
                                .tx_requests_deferred
                                .fetch_add((wanted.len() - room) as u64, Ordering::Relaxed);
                            for i in wanted.drain(room..) {
                                if p.announced_waiting.len() >= MAX_ANNOUNCED_WAITING {
                                    p.announced_waiting.pop_front();
                                }
                                p.announced_waiting.push_back(i.hash);
                            }
                        }
                        for i in &wanted {
                            p.requested_txs.insert(i.hash, now);
                        }
                    }
                    // Blocks go through the same cap as headers: what has no
                    // in-flight slot waits in the queue, and an `inv` of fifty
                    // thousand identifiers records nothing more than a batch of
                    // headers.
                    if let Some(p) = g.peers.get_mut(&id) {
                        let now = Instant::now();
                        for h in blocks {
                            if p.requested_bodies.contains_key(&h) {
                                continue;
                            }
                            if p.note_body_requested(h, now) {
                                wanted.push(InvItem {
                                    kind: InvKind::CompactBlock,
                                    hash: h,
                                });
                            } else {
                                p.queue_body(h);
                            }
                        }
                    }
                    if !wanted.is_empty() {
                        outgoing.push(Outgoing {
                            peer: id,
                            message: Message::GetData(wanted),
                        });
                    }
                }

                Message::GetData(v) => {
                    // --- Defense: amplification.
                    //
                    // The original handler served each item as is, without
                    // deduplicating or capping. A peer sent the same hash
                    // 20,000 times — a 660 KiB request — and the node produced
                    // 20,000 copies of the block. The audit's measurement:
                    // 6.8 MiB out, and for compact blocks a complete
                    // recomputation of the short identifiers for each copy. On
                    // 4 MiB blocks, 80 GiB for a 660 KiB request.
                    //
                    // Three rules, and none is negotiable: the handshake first,
                    // an item served at most once, and an outgoing byte budget.
                    // We serve nothing, but we do not disconnect: disconnecting
                    // would punish a benign race. A legitimate peer may request
                    // an announced block before its `verack` has reached us, and
                    // breaking the connection for that amounts to inflicting a
                    // network partition on oneself. That is what happened on the
                    // first real trial: two honest nodes disconnected each other
                    // immediately, height stuck at zero.
                    let mut seen: HashSet<Hash256> = HashSet::new();
                    let mut budget = if handshaked { REPLY_BYTE_BUDGET } else { 0 };
                    for i in v.into_iter().take(MAX_SERVED_ITEMS) {
                        if !seen.insert(i.hash) || budget == 0 {
                            continue;
                        }
                        match i.kind {
                            InvKind::Block => {
                                if let Some(b) = g.chain.block_by_id(&i.hash) {
                                    budget = budget.saturating_sub(b.encode().len());
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::Block(Box::new(b)),
                                    });
                                }
                            }
                            InvKind::CompactBlock => {
                                if let Some(b) = g.chain.block_by_id(&i.hash) {
                                    let c = CompactBlock::from_block(&b, unix_now());
                                    budget = budget.saturating_sub(c.encode().len());
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::CmpctBlock(Box::new(c)),
                                    });
                                }
                            }
                            InvKind::Tx => {
                                if let Some(t) = g.mempool.get(&i.hash) {
                                    budget = budget.saturating_sub(t.encode().len());
                                    outgoing.push(Outgoing {
                                        peer: id,
                                        message: Message::Tx(Box::new(t.clone())),
                                    });
                                }
                            }
                        }
                    }
                }

                Message::Block(b) => {
                    // --- Defense: a block pushed by a stranger.
                    //
                    // Every serving message requires the handshake; a pushed
                    // block did not, and got hashed, checked and connected over
                    // a mere anonymous TCP connection. Same rule for all.
                    if handshaked {
                        self.stats.blocks_received.fetch_add(1, Ordering::Relaxed);
                        // A body we asked for: this peer is answering us, so it
                        // is not a withholder even if another body of its lags.
                        let bid = b.header.block_id();
                        if let Some(p) = g.peers.get_mut(&id) {
                            p.note_body_delivered(&bid);
                        }
                        drop_peer = !Self::integrate(&mut g, &b, &self.stats, &mut outgoing, id);
                    }
                }

                Message::CmpctBlock(c) => {
                    self.stats.compacts_received.fetch_add(1, Ordering::Relaxed);
                    let bid = c.header.block_id();
                    // A body we asked for marks this peer as answering us.
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.note_body_delivered(&bid);
                    }
                    if g.chain.has_block(&bid) {
                        // Already known: nothing to reconstruct. But if it was a
                        // body requested from this peer, its in-flight slot is
                        // freed.
                        let Shared {
                            ref chain,
                            ref mut peers,
                            ..
                        } = *g;
                        if let Some(p) = peers.get_mut(&id) {
                            if p.requested_bodies.contains_key(&bid) {
                                p.continue_sync(id, chain, &mut outgoing, Instant::now(), true);
                            }
                        }
                    } else if handshaked
                        && !g.chain.has_block(&c.header.prev_block)
                        && g.peers
                            .get(&id)
                            .is_some_and(|p| p.requested_bodies.contains_key(&bid))
                    {
                        // Requested, but its parent is still on its way: it
                        // waits for it. See `Shared::parked`.
                        if g.parked.len() >= MAX_PARKED {
                            g.parked.remove(0);
                        }
                        g.parked.push((id, c));
                        self.stats.compacts_parked.fetch_add(1, Ordering::Relaxed);
                        // Its parent is one we have never seen: this peer is on
                        // a branch we do not know. Ask it for headers — one
                        // request outstanding at a time, charged to its budget
                        // by `note_sent` — so two halves of a split re-sync
                        // promptly instead of ignoring each other until the
                        // stale-tip timer. The reply drives the normal sync
                        // path (`Message::Headers` → `continue_sync`), which
                        // fetches and connects the blocks we are missing, the
                        // parent among them; the parked block is then resumed
                        // (`resume_parked`). Without this, each half parked the
                        // other's blocks waiting for a parent it never asked
                        // for — a split that did not heal.
                        if g.peers.get(&id).is_some_and(|p| p.expected_headers == 0) {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::GetHeaders {
                                    locator: g.chain.locator(),
                                    stop: Hash256::ZERO,
                                },
                            });
                        }
                    } else if !handshaked || !g.chain.has_block(&c.header.prev_block) {
                        // --- Defense: work imposed by a stranger.
                        //
                        // A minimal compact block is about 170 bytes, and was
                        // enough to trigger a full clone of the mempool — up to
                        // 64 MiB — **under the global lock**, hence to serialize
                        // the whole node. Repeated, it froze it.
                        //
                        // We now refuse before any expense: no handshake, or a
                        // parent we do not know, and the message costs only a
                        // comparison. A block whose parent is unknown could not
                        // be connected anyway.
                    } else {
                        // --- Defense: the peer's announcement budget.
                        //
                        // A body we requested from this peer is not an
                        // announcement: it arrives because we wanted it, and the
                        // cap on bodies in flight already bounds what we want.
                        // Everything else is a spontaneous announcement, and an
                        // honest peer only makes a few per minute. Beyond that,
                        // we do not reconstruct — no scan, no allocation — and
                        // insisting costs points.
                        let solicited = g
                            .peers
                            .get(&id)
                            .map(|p| p.requested_bodies.contains_key(&bid))
                            .unwrap_or(false);
                        let allowed = solicited
                            || g.peers
                                .get_mut(&id)
                                .map(|p| {
                                    p.cmpct_bucket.allow_with(
                                        1,
                                        Instant::now(),
                                        CMPCT_BUCKET_MAX,
                                        CMPCT_RATE_PER_SEC,
                                    )
                                })
                                .unwrap_or(false);
                        if !allowed {
                            self.stats.compacts_rejected.fetch_add(1, Ordering::Relaxed);
                            if let Some(p) = g.peers.get_mut(&id) {
                                p.ban_score = p.ban_score.saturating_add(MISCONDUCT_CMPCT_REJECTED);
                                if p.ban_score >= BAN_THRESHOLD {
                                    self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                    drop_peer = true;
                                }
                            }
                        } else {
                            drop_peer =
                                !Self::accept_compact(&mut g, &self.stats, c, id, &mut outgoing);
                        }
                    }
                }

                Message::GetBlockTxn { block, indices } => {
                    // --- Defense: amplification.
                    //
                    // Without deduplication or cap, `indices: [0; 100_000]`
                    // made us clone the same transaction a hundred thousand
                    // times in a single frame. The audit's measurement: a
                    // 100 KiB request for a 15.5 MiB reply — a frame that even
                    // exceeded the protocol's MAX_PAYLOAD, hence unreadable by
                    // an honest peer. Producing a reply nobody can read is the
                    // definition of a denial-of-service vector.
                    // Same rule as above: we serve nothing, we do not disconnect.
                    let mut seen: HashSet<u32> = HashSet::new();
                    let unique: Vec<u32> = indices
                        .into_iter()
                        .take(MAX_SERVED_ITEMS)
                        .filter(|i| seen.insert(*i))
                        .collect();

                    // Loading the block (opening a file, reading, cloning)
                    // came before the handshake: an anonymous peer made the
                    // node do a disk read under the global lock for zero bytes
                    // served. We require it first.
                    if handshaked {
                        if let Some(b) = g.chain.block_by_id(&block) {
                            let mut txs = Vec::new();
                            let mut budget = if handshaked { REPLY_BYTE_BUDGET } else { 0 };
                            let mut valid = true;
                            for i in &unique {
                                match b.transactions.get(*i as usize) {
                                    Some(t) => {
                                        let size = t.encode().len();
                                        if size > budget {
                                            break;
                                        }
                                        budget -= size;
                                        txs.push(t.clone());
                                    }
                                    None => {
                                        valid = false;
                                        break;
                                    }
                                }
                            }
                            if valid && !txs.is_empty() {
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::BlockTxn { block, txs },
                                });
                            }
                        }
                    }
                }

                Message::BlockTxn { block, txs } => {
                    let waiting = g.peers.get_mut(&id).and_then(|p| p.pending.remove(&block));
                    if let Some((c, _)) = waiting {
                        let available = Self::useful_mempool_txs(&g.mempool, &c);
                        match Reconstruction::from_compact(&c, &available)
                            .and_then(|r| r.complete(txs))
                        {
                            Ok(b) => {
                                drop_peer =
                                    !Self::integrate(&mut g, &b, &self.stats, &mut outgoing, id);
                            }
                            Err(_) => {
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::GetData(vec![InvItem {
                                        kind: InvKind::Block,
                                        hash: block,
                                    }]),
                                });
                            }
                        }
                    }
                }

                Message::Tx(t) if !handshaked => {
                    // A transaction pushed before the handshake costs nothing:
                    // it is not read. See `Message::Block`.
                    let _ = t;
                }

                Message::Tx(t) => {
                    self.stats.txs_received.fetch_add(1, Ordering::Relaxed);
                    // --- Defense: the peer's budget, debited BEFORE any
                    // expensive computation, and IN PROPORTION to the
                    // verification work.
                    //
                    // # The two defects this debit closes
                    //
                    // 1. Replay (red team 8b, 1st campaign). To know whether a
                    //    transaction is new, one first needs its identifier
                    //    `t.txid()`, a hash of the whole transaction. By
                    //    replaying a large, already-known transaction, a peer
                    //    forced this computation for every message. So we debit
                    //    BEFORE the hash.
                    // 2. Verification (red team 8b, 2nd campaign). A transaction
                    //    costs one post-quantum signature PER INPUT, under the
                    //    global lock. Nothing bounds the number of inputs (only
                    //    weight does, ~271), and the old budget counted one unit
                    //    PER TRANSACTION: a transaction with many inputs, or a
                    //    flood of them, held the lock far longer. So we debit in
                    //    proportion to the inputs.
                    //
                    // The cost is capped at the bucket: the largest valid
                    // transaction drains the budget but is never refused. Beyond
                    // the budget, we DEFER without banning — a consolidation with
                    // many inputs can be perfectly honest, and the old ban on
                    // overrun could exclude a legitimate relay (a peer's score
                    // never decreases). The peer will resend when its bucket
                    // refills. A really invalid transaction, on the other hand,
                    // is always penalized further down (`tx_invalid_in_itself`).
                    // A policy input can make us verify up to eight
                    // signatures: it is charged the keys on the path its
                    // witness names, read without any lookup or hash.
                    let cost = t
                        .inputs
                        .iter()
                        .map(|i| crate::policy::verifications_claimed(&i.witness))
                        .sum::<u64>()
                        .clamp(1, TX_BUCKET_MAX);
                    let mut allowed = g
                        .peers
                        .get_mut(&id)
                        .map(|p| {
                            p.tx_bucket.allow_with(
                                cost,
                                Instant::now(),
                                TX_BUCKET_MAX,
                                TX_RATE_PER_SEC,
                            )
                        })
                        .unwrap_or(false);
                    // --- A transaction **we asked for** is served, whatever
                    // its size (0.4.9).
                    //
                    // The budget bounds what a peer pushes unasked. What we
                    // ask for is bounded already: by the budget, when asked
                    // (see the `Inv` arm). Refusing the answer only made us
                    // ask again at the next offer: in the lab, consolidations
                    // of a hundred inputs crossed the network one per offer,
                    // twelve of them in half an hour. Served, a heavy answer
                    // empties the budget instead, which slows down what we ask
                    // this peer next. An answer is served once: sent again, it
                    // is unsolicited. Recognizing it costs one hash, and only
                    // while a request is outstanding.
                    if !allowed {
                        let now = Instant::now();
                        let solicited = g
                            .peers
                            .get_mut(&id)
                            .map(|p| {
                                let asked = !p.requested_txs.is_empty()
                                    && p.requested_txs.remove(&t.txid()).is_some();
                                if asked {
                                    p.tx_bucket.drain(now);
                                    p.last_delivered = now;
                                }
                                asked
                            })
                            .unwrap_or(false);
                        if solicited {
                            self.stats
                                .solicited_over_budget
                                .fetch_add(1, Ordering::Relaxed);
                            allowed = true;
                        }
                    }
                    if !allowed {
                        // Budget overrun, two distinct cases:
                        // - small transaction: the peer sends too many MESSAGES,
                        //   it is a flood. We penalize, as always.
                        // - large transaction (many inputs): a single message
                        //   asked for a lot of work at once. It may be honest
                        //   (consolidation). We DEFER without banning — the peer
                        //   will resend when its bucket refills — because a ban
                        //   score never decreases and a legitimate relay would
                        //   end up excluded.
                        // In both cases: neither verification nor relay. The work
                        // is bounded because we stop here.
                        //
                        // What we asked for never comes this far: see above.
                        if cost <= FLOOD_INPUT_THRESHOLD {
                            if let Some(p) = g.peers.get_mut(&id) {
                                p.ban_score = p.ban_score.saturating_add(MISCONDUCT_MALFORMED);
                                if p.ban_score >= BAN_THRESHOLD {
                                    self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                    drop_peer = true;
                                }
                            }
                        }
                    } else {
                        let txid = t.txid();
                        if let Some(p) = g.peers.get_mut(&id) {
                            if p.requested_txs.remove(&txid).is_some() {
                                // It answered something we asked for: it is
                                // not a withholder, however slow a block body
                                // of its may be. See `Peer::last_delivered`.
                                p.last_delivered = Instant::now();
                            }
                        }
                        let is_new = !g.mempool.contains(&txid);
                        let height = g.chain.height();
                        // On a reference, never on a copy: duplicating the UTXO
                        // set for every transaction received cost hundreds of
                        // mebibytes per message on a real chain, under the
                        // global lock — a chatty peer was enough to freeze the
                        // node. The reborrow `&mut *g` splits the fields of the
                        // guard.
                        let shared = &mut *g;
                        let result = if is_new {
                            shared
                                .mempool
                                .accept(&t, &shared.chain.utxo, network, height)
                        } else {
                            // Already known: nothing to revalidate, nothing to
                            // relay.
                            Err(crate::mempool::MempoolError::AlreadyPresent)
                        };
                        match result {
                            Ok(txid) => {
                                // It is in the pool now: forget any earlier
                                // full-pool refusal of it.
                                g.full_pool_rejected.remove(&txid);
                                // To established peers only, like every
                                // announcement: see `announce_tx`.
                                let others: Vec<u64> = g
                                    .peers
                                    .iter()
                                    .filter(|(p, e)| **p != id && e.handshaked)
                                    .map(|(p, _)| *p)
                                    .collect();
                                for p in others {
                                    outgoing.push(Outgoing {
                                        peer: p,
                                        message: Message::Inv(vec![InvItem {
                                            kind: InvKind::Tx,
                                            hash: txid,
                                        }]),
                                    });
                                }
                                Self::adopt_orphans(&mut g, txid, &self.stats, &mut outgoing);
                            }
                            Err(crate::mempool::MempoolError::UnconfirmedDependency(_)) => {
                                // Its parent has not reached us yet: it waits for
                                // it, instead of being forgotten until the next
                                // offer.
                                g.orphans.add((*t).clone(), id, Instant::now());
                            }
                            Err(e) => {
                                // Refused for a reason only a change on our
                                // side can lift, so it is not downloaded again
                                // at every offer (0.4.9 offered every two
                                // minutes).
                                //
                                // A rate refusal is decided before any
                                // signature, on this copy's weight: it is
                                // remembered by id only if the witness has
                                // the sizes every valid copy has. A padded
                                // copy refused here, then remembered, kept the
                                // honest one from ever being fetched while the
                                // pool stayed full — a penalty included.
                                let rememberable =
                                    !matches!(
                                        e,
                                        crate::mempool::MempoolError::FullAndUnderpaid
                                            | crate::mempool::MempoolError::FeeRateTooLow { .. }
                                    ) || g.mempool.witness_is_canonical(&t, &g.chain.utxo);
                                match &e {
                                    // A full pool is lifted not by a mere block
                                    // but by room: this refusal is remembered
                                    // across blocks, with the rate and size it
                                    // was refused at, and the transaction is
                                    // asked for again only once the pool could
                                    // take it. See `full_pool_rejected` and
                                    // `should_request_tx`.
                                    crate::mempool::MempoolError::FullAndUnderpaid
                                        if rememberable =>
                                    {
                                        let size = t.encode().len();
                                        let rate = g
                                            .mempool
                                            .apparent_fee_rate(&t, &g.chain.utxo)
                                            .unwrap_or(0);
                                        if g.full_pool_rejected.len() >= MAX_RECENT_REJECTS
                                            && !g.full_pool_rejected.contains_key(&txid)
                                        {
                                            g.full_pool_rejected.retain(|_, r| {
                                                height.saturating_sub(r.2)
                                                    < FULL_POOL_REFUSAL_BLOCKS
                                            });
                                        }
                                        if g.full_pool_rejected.len() >= MAX_RECENT_REJECTS
                                            && !g.full_pool_rejected.contains_key(&txid)
                                        {
                                            if let Some(evict) =
                                                g.full_pool_rejected.keys().next().copied()
                                            {
                                                g.full_pool_rejected.remove(&evict);
                                            }
                                        }
                                        g.full_pool_rejected.insert(txid, (rate, size, height));
                                    }
                                    // A conflict or a fee below the floor can be
                                    // cleared by the next block; remembered only
                                    // until the tip moves.
                                    crate::mempool::MempoolError::SpendConflict(_)
                                    | crate::mempool::MempoolError::FeeRateTooLow { .. }
                                        if rememberable =>
                                    {
                                        let tip = g.chain.tip_id();
                                        if g.rejected_at != tip
                                            || g.rejected.len() >= MAX_RECENT_REJECTS
                                        {
                                            g.rejected.clear();
                                            g.rejected_at = tip;
                                        }
                                        g.rejected.insert(txid);
                                    }
                                    _ => {}
                                }
                                // A rejected transaction is not necessarily an
                                // aggression: it may already be known, or spend
                                // an output that a block has just consumed. But a
                                // bad signature, a key that does not match the
                                // lock, an incorrect form or a value not conserved
                                // can only come from a peer that fabricated it.
                                if Self::tx_invalid_in_itself(&e) {
                                    if let Some(p) = g.peers.get_mut(&id) {
                                        p.ban_score = p.ban_score.saturating_add(MISCONDUCT_BAD_TX);
                                        if p.ban_score >= BAN_THRESHOLD {
                                            self.stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                                            drop_peer = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // The budget this message did not use asks for what
                    // waits, in the same breath.
                    if let Some(m) = Self::request_waiting_txs(&mut g, id, Instant::now()) {
                        outgoing.push(Outgoing {
                            peer: id,
                            message: m,
                        });
                    }
                }

                Message::GetAddr if !handshaked => {
                    // Serving the address book before the handshake offered an
                    // anonymous scanner every known address, and an
                    // amplification of about 600x (24 bytes requested, up to
                    // 16 KB returned) built under the global lock — which the
                    // rest of the code already refuses ("nothing is read before
                    // the handshake"). GetAddr is aligned with GetHeaders. Red
                    // team 8b.
                }

                Message::GetAddr => {
                    // Even after the handshake, the reply is bounded by the
                    // bucket: its actual size is debited, so that a burst of
                    // `getaddr` does not turn into a bandwidth amplification
                    // under the lock.
                    let mut v = g.book.to_announce(crate::wire::MAX_ADDR);
                    let local = g.book.allows_local();
                    if v.len() < crate::wire::MAX_ADDR {
                        for p in g.peers.values() {
                            // ONLY the OUTBOUND peers: their `addr` carries the
                            // real listening port, hence a reachable address.
                            // An inbound peer is known by its ephemeral source
                            // port, which is unusable: broadcasting it polluted
                            // the address books of the whole network with dead
                            // addresses.
                            if !p.outbound {
                                continue;
                            }
                            if let SocketAddr::V4(a) = p.addr {
                                let n = crate::wire::NetAddr {
                                    ip: a.ip().octets(),
                                    port: a.port(),
                                    last_seen: unix_now(),
                                };
                                // --- A home address stays at home (0.4.7).
                                //
                                // An outbound peer on the local network — a
                                // wallet told to use the Raspberry next to it —
                                // was handed to every node asking for
                                // addresses: a private address published, and
                                // a hint about the owner's home network. The
                                // address book already refused those ranges;
                                // this reply bypassed it.
                                if !crate::addr::routable(n.ip, local) {
                                    continue;
                                }
                                if !v.iter().any(|x| x.ip == n.ip && x.port == n.port) {
                                    v.push(n);
                                }
                            }
                            if v.len() >= crate::wire::MAX_ADDR {
                                break;
                            }
                        }
                    }
                    if !v.is_empty() {
                        // ~20 bytes per address; we debit the served size from
                        // the peer's snapshot bucket. Beyond the budget, we do
                        // not reply: the peer waits, the node does not wear
                        // itself out.
                        let cost = (v.len() as u64).saturating_mul(20);
                        let allowed = g
                            .peers
                            .get_mut(&id)
                            .map(|p| p.snapshot_bucket.allow(cost, Instant::now()))
                            .unwrap_or(false);
                        if allowed {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::Addr(v),
                            });
                        }
                    }
                    // The onion names, to a protocol-4 peer only: a version-3
                    // node takes an unknown command for a malformed frame.
                    let modern = g
                        .peers
                        .get(&id)
                        .map(|p| p.handshaked && p.version >= crate::wire::ONION_ADDR_VERSION)
                        .unwrap_or(false);
                    if modern {
                        let mut o = g.onions.to_announce(crate::wire::MAX_ADDR - 1);
                        if let Some(own) = self.own_onion() {
                            o.retain(|a| a.name != own.name);
                            o.insert(0, own);
                        }
                        if !o.is_empty() {
                            let cost = (o.len() as u64).saturating_mul(70);
                            let allowed = g
                                .peers
                                .get_mut(&id)
                                .map(|p| p.snapshot_bucket.allow(cost, Instant::now()))
                                .unwrap_or(false);
                            if allowed {
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::OnionAddr(o),
                                });
                            }
                        }
                    }
                }

                Message::Addr(v) if !handshaked => {
                    // Same rule as `getaddr`: nothing is read before the
                    // handshake. With the address book full, each address from a
                    // new group makes us scan every group to evict one — nearly
                    // eight milliseconds of global lock per sixteen-kibibyte
                    // frame, with no bucket. No honest peer announces addresses
                    // before having introduced itself.
                    let _ = v;
                }

                Message::Addr(v) => {
                    // The addresses come from a stranger: the address book
                    // applies its own rules — routability, cap per group — and
                    // nothing else is done with this message. In particular, we
                    // never dial an address because a peer suggested it: the
                    // maintenance loop decides.
                    //
                    // Each address goes through the peer's bucket: see
                    // [`ADDR_RATE_PER_SEC`]. The bucket is consulted before the
                    // address book, hence before any scan.
                    let now = unix_now();
                    let instant = Instant::now();
                    let Shared {
                        ref mut book,
                        ref mut peers,
                        ..
                    } = *g;
                    let bucket = peers.get_mut(&id).map(|p| &mut p.addr_bucket);
                    if let Some(bucket) = bucket {
                        for a in v.into_iter().take(crate::wire::MAX_ADDR) {
                            if !bucket.allow_with(1, instant, ADDR_BUCKET_MAX, ADDR_RATE_PER_SEC) {
                                self.stats.addresses_ignored.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            // An address announced as seen in the future would
                            // be a way to get ahead of all the others.
                            let mut a = a;
                            a.last_seen = a.last_seen.min(now);
                            book.add(a, now);
                        }
                    }
                }
                Message::OnionAddr(v) if !handshaked => {
                    let _ = v;
                }
                Message::OnionAddr(v) => {
                    // Same rules as `addr`: the peer's bucket first, then the
                    // book, and nothing is dialed because a peer said so.
                    let now = unix_now();
                    let instant = Instant::now();
                    let Shared {
                        ref mut onions,
                        ref mut peers,
                        ..
                    } = *g;
                    if let Some(bucket) = peers.get_mut(&id).map(|p| &mut p.addr_bucket) {
                        for a in v.into_iter().take(crate::wire::MAX_ADDR) {
                            if !bucket.allow_with(1, instant, ADDR_BUCKET_MAX, ADDR_RATE_PER_SEC) {
                                self.stats.addresses_ignored.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            let mut a = a;
                            a.last_seen = a.last_seen.min(now);
                            onions.add(a, now);
                        }
                    }
                }
                Message::Reject { .. } => {}

                // --- Fast sync: serving a snapshot.
                //
                // Like any expensive message, these replies require the
                // handshake: serving an entire UTXO set to an anonymous
                // connection would bring an amplification down to the price of
                // one `connect()`.
                Message::GetSnapshot => {
                    if handshaked {
                        refresh_snapshot(&mut g);
                        if let Some(c) = &g.snapshot_cache {
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::SnapshotInfo {
                                    height: c.height,
                                    tip: c.announced_tip,
                                    commitment: c.commitment,
                                    size: c.bytes.len() as u64,
                                    chunks: crate::fast_sync::chunk_count(c.bytes.len()),
                                },
                            });
                        }
                        // No snapshot (chain too short): we reply nothing. The
                        // requester will look elsewhere.
                    }
                }
                Message::GetSnapshotChunk { index } => {
                    if handshaked {
                        refresh_snapshot(&mut g);
                        // Measure first, copy afterwards: the bucket must be
                        // consulted **before** the mebibyte of copying,
                        // otherwise it would protect against nothing.
                        let size = g
                            .snapshot_cache
                            .as_ref()
                            .map(|c| crate::fast_sync::chunk(&c.bytes, index).len())
                            .unwrap_or(0);
                        let allowed = size > 0
                            && g.peers
                                .get_mut(&id)
                                .map(|p| p.snapshot_bucket.allow(size as u64, Instant::now()))
                                .unwrap_or(false);
                        if allowed {
                            if let Some(c) = &g.snapshot_cache {
                                let chunk = crate::fast_sync::chunk(&c.bytes, index);
                                outgoing.push(Outgoing {
                                    peer: id,
                                    message: Message::SnapshotChunk {
                                        index,
                                        data: chunk.to_vec(),
                                    },
                                });
                            }
                        }
                        // Beyond the granted rate, we serve nothing and do not
                        // disconnect: an honest client slows down and resumes.
                    }
                }
                // A server does not receive snapshot replies: we ignore them.
                Message::SnapshotInfo { .. } | Message::SnapshotChunk { .. } => {}

                // A payment-channel message. Gated three ways: the handshake
                // must be complete, the peer must have advertised the channel
                // capability (otherwise it is unsolicited misconduct), and it
                // must stay within its per-peer rate. The decoded bytes are
                // handed to the channel component after the lock is released,
                // never under it.
                // Channels exist on regtest only. Anywhere else this message
                // gets what 0.4.9 gave it as an unknown command: malformed,
                // and the link is cut.
                Message::Channel(_) if network != Network::Regtest => {
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.ban_score = p.ban_score.saturating_add(MISCONDUCT_MALFORMED);
                    }
                    drop_peer = true;
                }
                Message::Channel(bytes) => {
                    let (hs, cap) = g
                        .peers
                        .get(&id)
                        .map(|p| (p.handshaked, p.channels))
                        .unwrap_or((false, false));
                    if !hs {
                        // Pre-handshake: ignored, like every other expensive
                        // message, without penalty.
                    } else if !cap {
                        // The peer never told us it speaks the protocol, yet
                        // sent a channel message: unsolicited.
                        channel_penalty = MISCONDUCT_CHANNEL;
                    } else {
                        let now = Instant::now();
                        let allowed = g
                            .peers
                            .get_mut(&id)
                            .map(|p| {
                                p.chan_bucket
                                    .allow_with(1, now, CHAN_BUCKET_MAX, CHAN_RATE_PER_SEC)
                            })
                            .unwrap_or(false);
                        if allowed {
                            channel_in = Some(bytes);
                        }
                        // Beyond the rate we drop it silently: an honest peer
                        // slows down and resends, as for snapshot chunks.
                    }
                }
            }
        } // --- lock released here, before any network write ---

        // The channel component runs off the chain lock, so it is free to sign
        // and verify. An unsolicited message is penalized the same way.
        //
        // `penalize` answers whether the peer may stay. Read the other way
        // round, the first rejected channel message cut the link, while a peer
        // already past the threshold was kept: a payment that crossed the
        // peer's own was enough to drop the link, and the reestablish that
        // followed each reconnection crossed again, so the link fell at every
        // reconnection (D14).
        if channel_penalty > 0 && !self.penalize(id, channel_penalty) {
            drop_peer = true;
        }
        if let Some(bytes) = channel_in {
            let sink = self
                .channel_sink
                .read()
                .ok()
                .and_then(|g| g.as_ref().cloned());
            if let Some(sink) = sink {
                let identity = self.peer_identity(id);
                let outcome = sink.deliver(id, &identity, &bytes);
                if outcome.penalize > 0 && !self.penalize(id, outcome.penalize) {
                    drop_peer = true;
                }
                for payload in outcome.replies {
                    outgoing.push(Outgoing {
                        peer: id,
                        message: Message::Channel(payload),
                    });
                }
            }
        }
        // A channel-capable peer that just finished the handshake is resynced:
        // we send it the reestablish of every channel we hold with it.
        if channel_peer_ready {
            let sink = self
                .channel_sink
                .read()
                .ok()
                .and_then(|g| g.as_ref().cloned());
            if let Some(sink) = sink {
                let identity = self.peer_identity(id);
                for frame in sink.on_peer_connected(id, &identity) {
                    self.send_channel(id, frame);
                }
            }
        }
        // Blocks connected during this handler are scanned by the channel
        // watcher here, off the chain lock, so a penalty or sweep may be built
        // and broadcast without holding it.
        self.scan_connected_blocks_for_channels();

        for e in outgoing {
            let sent = {
                let mut g = self.shared.lock().unwrap();
                match for_peer(&g, e.peer, &e.message) {
                    Some(m) => {
                        let m = m.into_owned();
                        // A requested body is noted, so we know whether it
                        // arrives — within the limit of in-flight slots, as
                        // everywhere. A header request too: only an expected
                        // reply will be read.
                        g.peers.get_mut(&e.peer).map(|p| {
                            p.note_sent(&m, Instant::now());
                            (p.writer.clone(), m)
                        })
                    }
                    None => None,
                }
            };
            if let Some((s, message)) = sent {
                let e = Outgoing {
                    peer: e.peer,
                    message,
                };
                let frame = frame_of(&e.message, self.magic);
                if must_deliver(&e.message) {
                    // Recorded as sent just above: it must not be dropped.
                    let _ = s.push_force(frame);
                } else if e.peer == id {
                    // A reply to the peer whose message we are handling: if it
                    // asks faster than it reads, it waits — only its own read
                    // loop is held, as before, and nobody else.
                    if s.push_wait(frame) != Push::Queued {
                        self.stats.outbox_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    // A relay to another peer: never wait for it, or a slow
                    // peer would stop us reading this one.
                    self.queue(&s, frame);
                }
            }
        }

        !drop_peer
    }

    /// Whether an announced transaction is worth requesting from a peer.
    ///
    /// It is skipped when it is already in the pool, already held as an orphan
    /// waiting for its parent (so a waiting orphan is not fetched again at
    /// every offer), refused until the next block for a conflict or a fee
    /// floor, or refused for lack of room and the pool still could not take it
    /// ([`Mempool::would_admit`]). The last check is what stops a full pool
    /// from re-downloading, after every block, everything it had just refused.
    fn should_request_tx(g: &Shared, hash: &Hash256) -> bool {
        if g.mempool.contains(hash) || g.orphans.contains(hash) {
            return false;
        }
        if g.rejected_at == g.chain.tip_id() && g.rejected.contains(hash) {
            return false;
        }
        if let Some((rate, size, at)) = g.full_pool_rejected.get(hash) {
            let fresh = g.chain.height().saturating_sub(*at) < FULL_POOL_REFUSAL_BLOCKS;
            if fresh && !g.mempool.would_admit(*rate, *size) {
                return false;
            }
        }
        true
    }

    /// Requests, from peer `id`, the announced transactions that waited for
    /// its budget, as far as the budget now allows. Those that reached the
    /// pool meanwhile, or that it is not worth asking for (see
    /// [`Self::should_request_tx`]), are skipped.
    fn request_waiting_txs(g: &mut Shared, id: u64, now: Instant) -> Option<Message> {
        match g.peers.get(&id) {
            Some(p) if !p.announced_waiting.is_empty() && p.handshaked => {}
            _ => return None,
        }
        let room = g
            .peers
            .get_mut(&id)
            .map(|p| p.tx_request_room(now))
            .unwrap_or(0);
        let mut items = Vec::new();
        while items.len() < room {
            let Some(h) = g
                .peers
                .get_mut(&id)
                .and_then(|p| p.announced_waiting.pop_front())
            else {
                break;
            };
            let p = g.peers.get(&id)?;
            if p.requested_txs.contains_key(&h) || !Self::should_request_tx(g, &h) {
                continue;
            }
            if let Some(p) = g.peers.get_mut(&id) {
                p.requested_txs.insert(h, now);
            }
            items.push(InvItem {
                kind: InvKind::Tx,
                hash: h,
            });
        }
        (!items.is_empty()).then_some(Message::GetData(items))
    }

    /// Tries again the orphans waiting for `parent`, and those waiting for
    /// them in turn, now that `parent` is in the pool or in a block. Each one
    /// accepted is announced to the established peers but the one that sent
    /// it. Bounded by the orphan pool: each orphan is taken out once.
    fn adopt_orphans(g: &mut Shared, parent: Hash256, stats: &Stats, outgoing: &mut Vec<Outgoing>) {
        if g.orphans.is_empty() {
            return;
        }
        let mut queue = vec![parent];
        while let Some(p) = queue.pop() {
            for (tx, from) in g.orphans.take_children(&p) {
                let height = g.chain.height();
                let shared = &mut *g;
                match shared
                    .mempool
                    .accept(&tx, &shared.chain.utxo, shared.network, height)
                {
                    Ok(id) => {
                        stats.orphans_adopted.fetch_add(1, Ordering::Relaxed);
                        let others: Vec<u64> = g
                            .peers
                            .iter()
                            .filter(|(p, e)| **p != from && e.handshaked)
                            .map(|(p, _)| *p)
                            .collect();
                        for peer in others {
                            outgoing.push(Outgoing {
                                peer,
                                message: Message::Inv(vec![InvItem {
                                    kind: InvKind::Tx,
                                    hash: id,
                                }]),
                            });
                        }
                        queue.push(id);
                    }
                    Err(crate::mempool::MempoolError::UnconfirmedDependency(_)) => {
                        g.orphans.add(tx, from, Instant::now());
                    }
                    Err(_) => {}
                }
            }
        }
    }

    /// Submits a block to the chain and prepares its broadcast.
    ///
    /// Returns `false` if the peer deserves to be disconnected.
    /// Mempool transactions **actually useful** to this compact block.
    ///
    /// The previous version cloned the whole mempool for each announcement.
    /// Here we only keep the transactions whose short identifier appears in the
    /// announcement: the memory cost becomes that of a block, not that of the
    /// mempool. The scan remains linear, but a scan does not compare with
    /// sixty-four megabytes of copies.
    fn useful_mempool_txs(mempool: &Mempool, c: &CompactBlock) -> HashMap<Hash256, Transaction> {
        let (k0, k1) = crate::compact::short_id_key(&c.header, c.nonce);
        let targeted: HashSet<u64> = c.short_ids.iter().copied().collect();
        let mut m = HashMap::with_capacity(targeted.len());
        for t in mempool.txids() {
            if targeted.contains(&crate::compact::short_id(k0, k1, &t)) {
                if let Some(tx) = mempool.get(&t) {
                    m.insert(t, tx.clone());
                }
            }
        }
        m
    }

    /// Checks and reconstructs a compact block whose parent is known.
    ///
    /// Shared by an announcement that arrives in order and by one parked while
    /// its parent was still on its way (see [`Shared::parked`]). Returns false
    /// when the peer must be dropped.
    fn accept_compact(
        g: &mut Shared,
        stats: &Stats,
        c: Box<CompactBlock>,
        id: u64,
        outgoing: &mut Vec<Outgoing>,
    ) -> bool {
        let bid = c.header.block_id();
        let mut drop_peer = false;
        if let Err(e) = g.chain.check_header(&c.header, unix_now()) {
            // --- Defense: the header before the body (BIP 152).
            //
            // The bucket bounds the NUMBER of announcements; it
            // says nothing about their value. An announcement
            // whose header did not carry the work its position
            // requires still made us search the mempool and
            // allocate the reconstruction, under the lock.
            // Now: height, finality, difficulty, timestamp and
            // work are checked on the 160 bytes of the header,
            // and nothing else is touched if one of them fails.
            // These are the same checks that submitting the full
            // block would apply; we only move them earlier.
            //
            // A false header can only come from whoever
            // fabricated it: same penalty as an invalid block,
            // and we request nothing again — its body is worth
            // no more.
            //
            // Exception: what this binary cannot read is not
            // the peer's fault.
            stats
                .compacts_header_rejected
                .fetch_add(1, Ordering::Relaxed);
            match e {
                crate::chain::ChainError::Validation(v)
                    if locally_unverifiable_scheme(&v).is_some() =>
                {
                    report_unverifiable_scheme(locally_unverifiable_scheme(&v).expect("guarded"));
                }
                _ => {
                    stats.invalid_blocks.fetch_add(1, Ordering::Relaxed);
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.ban_score = p.ban_score.saturating_add(MISCONDUCT_BAD_BLOCK);
                        if p.ban_score >= BAN_THRESHOLD {
                            stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                            drop_peer = true;
                        }
                    }
                }
            }
        } else {
            stats.compacts_reconstructed.fetch_add(1, Ordering::Relaxed);
            let available = Self::useful_mempool_txs(&g.mempool, &c);
            match Reconstruction::from_compact(&c, &available) {
                Ok(r) if r.is_complete() => {
                    stats
                        .compacts_without_round_trip
                        .fetch_add(1, Ordering::Relaxed);
                    match r.finish() {
                        Ok(b) => {
                            drop_peer = !Self::integrate(g, &b, stats, outgoing, id);
                        }
                        Err(_) => {
                            // Plausible but wrong reconstruction:
                            // we request the full block again.
                            outgoing.push(Outgoing {
                                peer: id,
                                message: Message::GetData(vec![InvItem {
                                    kind: InvKind::Block,
                                    hash: bid,
                                }]),
                            });
                        }
                    }
                }
                Ok(r) => {
                    let indices = r.missing().to_vec();
                    if let Some(p) = g.peers.get_mut(&id) {
                        // Beyond the bound, the oldest gives way:
                        // we never keep more than what the peer
                        // can honestly have in flight.
                        if p.pending.len() >= MAX_PENDING_RECONSTRUCTIONS {
                            let oldest = p
                                .pending
                                .iter()
                                .min_by_key(|(_, (cb, _))| cb.header.height)
                                .map(|(k, _)| *k);
                            if let Some(k) = oldest {
                                p.pending.remove(&k);
                            }
                        }
                        p.pending.insert(bid, (*c.clone(), indices.clone()));
                    }
                    outgoing.push(Outgoing {
                        peer: id,
                        message: Message::GetBlockTxn {
                            block: bid,
                            indices,
                        },
                    });
                }
                Err(_) => {
                    // Rejected before even looking for the
                    // transactions: missing coinbase, index
                    // outside the block, absurd count. An
                    // announcement made this way can only come
                    // from the peer that fabricated it — unlike
                    // a wrong Merkle root, which can arise from a
                    // collision of short identifiers. We request
                    // the full block again, and the peer loses
                    // points.
                    if let Some(p) = g.peers.get_mut(&id) {
                        p.ban_score = p.ban_score.saturating_add(MISCONDUCT_CMPCT_REJECTED);
                        if p.ban_score >= BAN_THRESHOLD {
                            stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                            drop_peer = true;
                        }
                    }
                    outgoing.push(Outgoing {
                        peer: id,
                        message: Message::GetData(vec![InvItem {
                            kind: InvKind::Block,
                            hash: bid,
                        }]),
                    });
                }
            }
        }
        !drop_peer
    }

    /// A reorganization, for the channel watcher: the abandoned blocks are
    /// handed to it as disconnected, and every block of the winning branch,
    /// from just above the real fork height to the tip, is scanned at its own
    /// height. (Only the last [`crate::chain::RETURNED_BLOCKS`] abandoned
    /// bodies are kept; the fork comes from the reorganization's depth, not
    /// from them.)
    fn queue_reorg_for_channels(g: &mut Shared, fork_height: u64) {
        // Every transaction of the abandoned branch, not only those of the
        // newest blocks offered back to the mempool.
        let gone = g.chain.take_disconnected_txids();
        g.channel_unscan.extend(gone);
        let tip = g.chain.height();
        for h in fork_height.saturating_add(1)..=tip {
            if let Some(blk) = g.chain.block_at(h) {
                g.channel_scan.push((h, blk.transactions));
            }
        }
    }

    fn integrate(
        g: &mut Shared,
        b: &Block,
        stats: &Stats,
        outgoing: &mut Vec<Outgoing>,
        source: u64,
    ) -> bool {
        let bid = b.header.block_id();
        if g.chain.has_block(&bid) {
            Self::body_arrived(g, source, outgoing);
            return true;
        }
        let before = g.chain.height();
        match g.chain.submit(b, unix_now()) {
            Ok(accepted @ (Accept::Extended | Accept::Reorganized { .. })) => {
                stats.blocks_accepted.fetch_add(1, Ordering::Relaxed);
                // An accepted block is a stored block. Before, only the blocks
                // this node mined itself reached the disk.
                if let Some(j) = &g.journal {
                    j.record(b);
                }
                g.mempool.on_block_connected(b);
                // A connected block: hand its transactions to the channel
                // watcher, which scans them for a spend of a funding output
                // after the lock is released.
                let height = g.chain.height();
                let abandoned = g.chain.take_disconnected();
                if g.channels_active {
                    match accepted {
                        Accept::Reorganized { depth } => {
                            Self::queue_reorg_for_channels(g, before.saturating_sub(depth))
                        }
                        _ => g.channel_scan.push((height, b.transactions.clone())),
                    }
                }
                // A reorganization: the transactions of the abandoned blocks
                // go back to the pool, those the winning branch does not
                // already carry. See `Chain::take_disconnected`.
                if !abandoned.is_empty() {
                    let shared = &mut *g;
                    shared.mempool.return_abandoned(
                        &abandoned,
                        &shared.chain.utxo,
                        shared.network,
                        height,
                    );
                }
                // Same rule as when receiving a transaction: the mempool reads
                // the UTXO set in place, it does not copy it.
                g.mempool.revalidate(&g.chain.utxo, g.network, height);
                // Orphans whose parent this block confirms can go in now.
                for tx in &b.transactions {
                    Self::adopt_orphans(g, tx.txid(), stats, outgoing);
                }

                // Broadcast: compact announcement, not the full block.
                //
                // Only to peers whose handshake is complete. Announcing earlier
                // creates a race: the peer requests the block, and its request
                // reaches us before its `verack`.
                let others: Vec<u64> = g
                    .peers
                    .iter()
                    .filter(|(p, e)| **p != source && e.handshaked)
                    .map(|(p, _)| *p)
                    .collect();
                for p in others {
                    outgoing.push(Outgoing {
                        peer: p,
                        message: Message::Inv(vec![InvItem {
                            kind: InvKind::CompactBlock,
                            hash: bid,
                        }]),
                    });
                }
                Self::body_arrived(g, source, outgoing);
                Self::resume_parked(g, stats, bid, source, outgoing)
            }
            Ok(Accept::SideBranch) => {
                // A side branch is valid work: if it wins later, its bodies
                // will be needed. Not writing them made any reorg impossible
                // after a restart.
                if let Some(j) = &g.journal {
                    j.record(b);
                }
                Self::body_arrived(g, source, outgoing);
                Self::resume_parked(g, stats, bid, source, outgoing)
            }
            Ok(_) => {
                Self::body_arrived(g, source, outgoing);
                true
            }
            Err(crate::chain::ChainError::UnknownParent(_)) => {
                stats.orphan_blocks.fetch_add(1, Ordering::Relaxed);
                // A block whose parent is unknown should no longer arrive:
                // strict header-based synchronization only requests a body
                // after having checked that it connects. Asking for headers
                // again here would recreate the infinite loop we just fixed. We
                // ignore it, without punishing: it may be a benign race between
                // two announcements.
                true
            }
            Err(crate::chain::ChainError::Validation(v))
                if locally_unverifiable_scheme(&v).is_some() =>
            {
                // The block is not wrong: it is this binary that cannot read
                // it. The peer is not to blame, we do not penalize it; we tell
                // the operator once, and we do not count the block as invalid
                // — it may well not be.
                report_unverifiable_scheme(locally_unverifiable_scheme(&v).expect("guarded"));
                true
            }
            Err(_) => {
                stats.invalid_blocks.fetch_add(1, Ordering::Relaxed);
                if let Some(p) = g.peers.get_mut(&source) {
                    p.ban_score = p.ban_score.saturating_add(MISCONDUCT_BAD_BLOCK);
                    if p.ban_score >= BAN_THRESHOLD {
                        stats.peers_banned.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                }
                true
            }
        }
    }

    /// The compact blocks that were waiting for `parent`, now connected, go
    /// through the normal path. A reconstruction that completes connects its
    /// block and resumes, in turn, the one waiting for it: a whole batch
    /// unrolls without a round trip of its own.
    fn resume_parked(
        g: &mut Shared,
        stats: &Stats,
        parent: Hash256,
        source: u64,
        outgoing: &mut Vec<Outgoing>,
    ) -> bool {
        let (ready, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut g.parked)
            .into_iter()
            .partition(|(_, c)| c.header.prev_block == parent);
        g.parked = keep;
        let mut keep_source = true;
        for (id, c) in ready {
            if g.chain.has_block(&c.header.block_id()) || !g.peers.contains_key(&id) {
                continue;
            }
            stats.compacts_resumed.fetch_add(1, Ordering::Relaxed);
            if !Self::accept_compact(g, stats, c, id, outgoing) {
                if id == source {
                    keep_source = false;
                } else if let Some(p) = g.peers.get_mut(&id) {
                    p.ban_score = p.ban_score.max(BAN_THRESHOLD);
                }
            }
        }
        keep_source
    }

    /// A body has arrived from a peer: its in-flight slot is freed, and the
    /// synchronization with this peer resumes where it was.
    ///
    /// This is the counterpart of the cap on bodies in flight: without this
    /// resumption, a synchronization would stop after the first sixteen bodies.
    fn body_arrived(g: &mut Shared, source: u64, outgoing: &mut Vec<Outgoing>) {
        let Shared {
            ref chain,
            ref mut peers,
            ..
        } = *g;
        if let Some(p) = peers.get_mut(&source) {
            p.continue_sync(source, chain, outgoing, Instant::now(), true);
        }
    }

    /// Announces our own external address to the peers, to get into their
    /// address books and, step by step, into those of the whole network.
    ///
    /// We send a plain `Addr`: a message that even older peers already
    /// understand. No protocol change, hence no break between versions. The
    /// announced address has been verified to be public by the caller; the
    /// peer's address book applies its own routability rules anyway before
    /// keeping it.
    pub fn announce_address(&self, n: crate::wire::NetAddr) {
        let targets: Vec<Arc<Outbox>> = {
            let g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            g.peers
                .values()
                .filter(|p| p.handshaked)
                .map(|p| p.writer.clone())
                .collect()
        };
        self.broadcast(&targets, &Message::Addr(vec![n]));
    }

    /// Announces a block we have just mined ourselves.
    pub fn announce_block(&self, b: &Block) {
        let bid = b.header.block_id();
        let targets: Vec<Arc<Outbox>> = {
            let g = self.shared.lock().unwrap();
            // Only peers whose handshake is complete: announcing earlier would
            // trigger a request that would reach us before their `verack`, and
            // that we could not serve.
            g.peers
                .values()
                .filter(|p| p.handshaked)
                .map(|p| p.writer.clone())
                .collect()
        };
        let m = Message::Inv(vec![InvItem {
            kind: InvKind::CompactBlock,
            hash: bid,
        }]);
        self.broadcast(&targets, &m);
    }

    /// Broadcasts a local transaction.
    /// Sends a message to a peer, outside the lock, noting the requested
    /// bodies as `handle` does.
    fn send_to(&self, id: u64, m: &Message) {
        let sent = {
            let mut g = self.shared.lock().unwrap();
            match for_peer(&g, id, m).map(|m| m.into_owned()) {
                Some(m) => g.peers.get_mut(&id).map(|p| {
                    p.note_sent(&m, Instant::now());
                    (p.writer.clone(), m)
                }),
                None => None,
            }
        };
        if let Some((s, m)) = sent {
            let m = &m;
            let frame = frame_of(m, self.magic);
            if must_deliver(m) {
                let _ = s.push_force(frame);
            } else {
                self.queue(&s, frame);
            }
        }
    }

    /// Offers the pending transactions again to every established peer.
    /// Called every [`MEMPOOL_REBROADCAST`] by the node's loop: a peer that
    /// missed one (refused child, connection cut, restart) gets it back.
    /// Returns the number of transactions announced.
    /// Asks the outbound peers for their addresses again. The address books
    /// were filled only at the handshake: an onion service that appeared
    /// afterwards — a Raspberry Pi turned into a hidden node — stayed unknown
    /// to every node already connected, until its next restart. Called every
    /// ten minutes; the reply is bounded by each peer's bucket.
    pub fn ask_addresses(&self) -> usize {
        let targets: Vec<Arc<Outbox>> = {
            let g = self.shared.lock().unwrap();
            g.peers
                .values()
                .filter(|p| p.handshaked && p.outbound)
                .map(|p| p.writer.clone())
                .collect()
        };
        self.broadcast(&targets, &Message::GetAddr);
        targets.len()
    }

    pub fn announce_mempool(&self) -> usize {
        let (targets, pending, older, without_policies) = {
            let g = self.shared.lock().unwrap();
            // The whole pool, not just its top: a peer behind by thousands
            // reconciles the rest here, bounding its own intake. See
            // `Mempool::announcement_window`.
            let pending = g.mempool.announcement_window(MEMPOOL_REOFFER_MAX_TXS);
            let (follow, older): (Vec<&Peer>, Vec<&Peer>) = g
                .peers
                .values()
                .filter(|p| p.handshaked)
                .partition(|p| follows_activation(g.network, p.version));
            // The peers that predate the policy activation get the pool
            // without its policy transactions: see `for_peer`.
            let without_policies: Vec<Hash256> = if older.is_empty() {
                Vec::new()
            } else {
                pending
                    .iter()
                    .filter(|h| !g.mempool.touches_policy(h))
                    .copied()
                    .collect()
            };
            (
                follow.iter().map(|p| p.writer.clone()).collect::<Vec<_>>(),
                pending,
                older.iter().map(|p| p.writer.clone()).collect::<Vec<_>>(),
                without_policies,
            )
        };
        if pending.is_empty() {
            return 0;
        }
        let inv = |hashes: &[Hash256]| {
            Message::Inv(
                hashes
                    .iter()
                    .map(|hash| InvItem {
                        kind: InvKind::Tx,
                        hash: *hash,
                    })
                    .collect(),
            )
        };
        self.broadcast(&targets, &inv(&pending));
        if !without_policies.is_empty() {
            self.broadcast(&older, &inv(&without_policies));
        }
        pending.len()
    }

    pub fn announce_tx(&self, txid: Hash256) {
        let targets: Vec<Arc<Outbox>> = {
            let g = self.shared.lock().unwrap();
            let policy = g.mempool.touches_policy(&txid);
            g.peers
                .values()
                .filter(|p| p.handshaked && (!policy || follows_activation(g.network, p.version)))
                .map(|p| p.writer.clone())
                .collect()
        };
        let m = Message::Inv(vec![InvItem {
            kind: InvKind::Tx,
            hash: txid,
        }]);
        self.broadcast(&targets, &m);
    }

    /// Queues a frame for a peer without ever waiting. A full queue drops the
    /// frame for that peer only, and is counted.
    fn queue(&self, writer: &Outbox, frame: Arc<[u8]>) {
        if writer.push(frame) == Push::Full {
            self.stats.outbox_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Queues one message for several peers: serialized once, shared by all,
    /// and never waited for — the defect of v0.4.8 was exactly this loop
    /// writing to each peer in turn, and stopping at the first that did not
    /// read.
    fn broadcast(&self, targets: &[Arc<Outbox>], m: &Message) {
        if targets.is_empty() {
            return;
        }
        let frame = frame_of(m, self.magic);
        for s in targets {
            self.queue(s, frame.clone());
        }
    }
}

/// A message framed for the wire, ready to be shared between queues.
fn frame_of(m: &Message, magic: [u8; 4]) -> Arc<[u8]> {
    m.frame(magic).into()
}

/// The small frames that are never dropped from a full queue: their sending
/// is recorded (`note_sent`, `pending_ping`) or the handshake depends on
/// them. Dropping a request while noting it as sent would later blame an
/// honest peer for not answering a question it never received.
fn must_deliver(m: &Message) -> bool {
    matches!(
        m,
        Message::GetData(_)
            | Message::GetHeaders { .. }
            | Message::Ping(_)
            | Message::Pong(_)
            | Message::Version { .. }
            | Message::VerAck
    )
}

#[cfg(test)]
mod tests {
    /// "I cannot verify" is not the peer's fault.
    ///
    /// A block or a transaction whose signature belongs to a known scheme that
    /// is absent from this build costs the peer no points. A bad signature, on
    /// the other hand, always costs points: the distinction cannot be used to
    /// flood for free.
    #[test]
    fn local_inability_is_not_the_peer_s_fault() {
        use crate::mempool::MempoolError as M;
        use crate::sig::{SchemeId, VerifyError};
        use crate::validate::ValidationError as V;
        let local = V::Signature(VerifyError::SchemeUnavailable(SchemeId::MlDsa87));
        let bad = V::Signature(VerifyError::InvalidSignature);
        assert_eq!(
            super::locally_unverifiable_scheme(&local),
            Some(SchemeId::MlDsa87)
        );
        assert_eq!(super::locally_unverifiable_scheme(&bad), None);
        let (local, bad) = (M::Validation(local), M::Validation(bad));
        assert!(!super::Node::tx_invalid_in_itself(&local));
        assert!(super::Node::tx_invalid_in_itself(&bad));
    }

    /// A policy spend that does not satisfy its policy is its author's doing
    /// and is penalized; a time lock not yet expired is not.
    #[test]
    fn policy_failures_are_penalized_except_early_ones() {
        use crate::mempool::MempoolError as M;
        use crate::policy::PolicyError as P;
        use crate::validate::ValidationError as V;
        for p in [
            P::WrongPreimage,
            P::DoesNotMatchLock,
            P::BadBranch { index: 3, arity: 2 },
            P::ExtraWitnessData(1),
            P::Malformed(crate::ser::ReadError::UnexpectedEnd),
            P::Unsigned,
        ] {
            assert!(
                super::Node::tx_invalid_in_itself(&M::Validation(V::Policy(p))),
                "{p:?}"
            );
        }
        let early = P::TooEarly {
            available_at: 10,
            height: 9,
        };
        assert!(!super::Node::tx_invalid_in_itself(&M::Validation(
            V::Policy(early)
        )));
    }

    /// ML-DSA is compiled by default: a bare `cargo build` gives a node that
    /// can verify mainnet. The dependency-free core remains available through
    /// `--no-default-features`, and it then refuses to start where it cannot
    /// verify.
    #[test]
    fn ml_dsa_is_compiled_by_default() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            manifest.contains("default = [\"mldsa\"]"),
            "the mldsa feature must be among the default features"
        );
    }
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::sig::SchemeId;

    const NETWORK: Network = Network::Regtest;
    const MAX_TRIES: u64 = 5_000_000;

    fn node() -> Node {
        let g = genesis_block(NETWORK);
        Node::new(NETWORK, Chain::new(NETWORK, g))
    }

    /// Two nodes starting from the same genesis.
    fn node_pair() -> (Node, Node) {
        let g = genesis_block(NETWORK);
        (
            Node::new(NETWORK, Chain::new(NETWORK, g.clone())),
            Node::new(NETWORK, Chain::new(NETWORK, g)),
        )
    }

    fn mine(n: &Node, count: usize) {
        for _ in 0..count {
            let b = n.with_chain(|c| {
                let t = c.tip().time + TARGET_BLOCK_SECS;
                c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, MAX_TRIES)
            });
            if let Some(b) = b {
                n.with_chain(|c| {
                    let t = b.header.time + 1;
                    c.connect(&b, t).expect("local connection")
                });
            }
        }
    }

    /// Waits for a condition to become true, without blocking indefinitely.
    fn wait_until(mut cond: impl FnMut() -> bool, seconds: u64) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(seconds) {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        cond()
    }

    /// Peer discovery, end to end: A knows addresses, B connects to A, and B
    /// learns them without anyone having given them to it.
    #[test]
    fn a_peer_learns_its_neighbor_s_addresses() {
        let (a, b) = node_pair();
        // A has heard of three peers, in three distinct ranges.
        let known = [
            crate::wire::NetAddr {
                ip: [93, 184, 216, 34],
                port: 21021,
                last_seen: 1_000,
            },
            crate::wire::NetAddr {
                ip: [8, 8, 8, 8],
                port: 21021,
                last_seen: 1_000,
            },
            crate::wire::NetAddr {
                ip: [1, 1, 1, 1],
                port: 21021,
                last_seen: 1_000,
            },
        ];
        assert_eq!(a.seed_addresses(&known), 3);
        assert_eq!(b.address_count(), 0);

        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| b.address_count() >= 3, 10),
            "B did not learn A's addresses: {}",
            b.address_count()
        );

        // And it will never propose two addresses from the same group.
        let choice = b.addresses_to_try(10);
        let groups: std::collections::HashSet<[u8; 2]> =
            choice.iter().map(|x| crate::addr::group(x.ip)).collect();
        assert_eq!(groups.len(), choice.len());

        a.shutdown();
        b.shutdown();
    }

    /// A malicious peer that announces a thousand addresses from a single range
    /// must not be able to occupy its neighbor's address book.
    #[test]
    fn an_address_flood_does_not_fill_the_address_book() {
        let n = node();
        let mut flood = Vec::new();
        for i in 0..1_000u32 {
            flood.push(crate::wire::NetAddr {
                ip: [203, 0, (i >> 8) as u8, i as u8],
                port: 21021,
                last_seen: 1_000 + u64::from(i),
            });
        }
        n.seed_addresses(&flood);
        assert!(
            n.address_count() <= crate::addr::MAX_PER_GROUP,
            "{} addresses kept",
            n.address_count()
        );
        assert_eq!(n.addresses_to_try(50).len(), 1);
    }

    #[test]
    fn a_node_listens_and_accepts_a_connection() {
        let a = node();
        let b = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| a.peer_count() == 1 && b.peer_count() == 1, 5),
            "the two nodes should have seen each other"
        );
        a.shutdown();
        b.shutdown();
    }

    /// An inbound connection does not count as outbound. This is the invariant
    /// that protects against eclipse: the maintenance loop aims for a number of
    /// **outbound** peers (chosen from the address book, with its group
    /// diversity); if an inbound connection counted toward them, an attacker
    /// would fill our slots from a single IP and we would never go looking for
    /// a diversified peer.
    #[test]
    fn an_inbound_connection_does_not_count_as_outbound() {
        let a = node();
        let b = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| a.peer_count() == 1 && b.peer_count() == 1, 5),
            "the two nodes should have seen each other"
        );

        // b initiated: it is an outbound one for b. a accepted it: an inbound
        // one for a, which must therefore count no outbound peer.
        assert_eq!(b.peer_count_outbound(), 1, "b initiated the connection");
        assert_eq!(
            a.peer_count_outbound(),
            0,
            "a only accepted: no outbound one, otherwise the eclipse gets through"
        );
        a.shutdown();
        b.shutdown();
    }

    /// The bucket bounds what a peer extracts from the snapshot service.
    ///
    /// Time is supplied by the test, never read from a clock: a rate rule that
    /// can only be tested by sleeping is a poorly tested rule.
    #[test]
    fn the_snapshot_bucket_bounds_the_rate() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(t0);

        // The initial reserve is served in one go, and not one byte more.
        assert!(
            bucket.allow(SNAPSHOT_BUCKET_MAX, t0),
            "the initial reserve must be served"
        );
        assert!(
            !bucket.allow(1, t0),
            "beyond the reserve, nothing more is served without waiting"
        );

        // One elapsed second credits exactly the granted rate.
        let t1 = t0 + Duration::from_secs(1);
        assert!(
            bucket.allow(SNAPSHOT_RATE_PER_SEC, t1),
            "one second must credit one second's worth of rate"
        );
        assert!(!bucket.allow(1, t1), "and nothing more");

        // The bucket does not overflow: a long absence does not give unlimited
        // credit, otherwise waiting would be enough to take everything back in
        // one go.
        let t2 = t1 + Duration::from_secs(3600);
        assert!(
            bucket.allow(SNAPSHOT_BUCKET_MAX, t2),
            "the capacity is owed"
        );
        assert!(
            !bucket.allow(1, t2),
            "but never more than the capacity, however long the wait"
        );
    }

    /// An honest newcomer must not be hindered: downloading an entire snapshot
    /// is an operation it only does once.
    #[test]
    fn the_bucket_lets_an_honest_download_through() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(t0);
        let chunk = crate::fast_sync::CHUNK_SIZE as u64;

        // A 64 MiB snapshot, requested chunk by chunk at the pace the network
        // delivers them: everything gets through.
        let mut served = 0u32;
        let mut t = t0;
        for _ in 0..64 {
            if bucket.allow(chunk, t) {
                served += 1;
            }
            // Half a second between two chunks: the real rate of an ordinary
            // link, well below the granted limit.
            t += Duration::from_millis(500);
        }
        assert_eq!(served, 64, "an honest download must lose nothing");
    }

    /// Abuse, on the other hand, is brought down to the granted rate: the tight
    /// loop no longer yields anything.
    #[test]
    fn the_bucket_throttles_a_tight_loop() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(t0);
        let chunk = crate::fast_sync::CHUNK_SIZE as u64;

        // A thousand requests at the same instant, as an attacker would do.
        let mut served = 0u32;
        for _ in 0..1_000 {
            if bucket.allow(chunk, t0) {
                served += 1;
            }
        }
        let cap = (SNAPSHOT_BUCKET_MAX / chunk) as u32;
        assert_eq!(
            served, cap,
            "a tight loop must only obtain the reserve, that is {cap} chunks"
        );
        assert!(
            served < 1_000,
            "without the bucket, all thousand requests would have been served"
        );
    }

    /// A lone `VerAck`, without a prior `Version`, must not complete the
    /// handshake: otherwise a peer would skip the negotiation and the nonce
    /// check, and open access to expensive messages with a single frame.
    #[test]
    fn a_lone_verack_does_not_complete_the_handshake() {
        use std::io::Write;
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        let magic = magic_for(NETWORK);

        let mut s = std::net::TcpStream::connect(addr).expect("connection");
        s.write_all(&Message::VerAck.frame(magic)).unwrap();
        s.flush().unwrap();

        assert!(
            wait_until(|| a.peer_count() == 1, 5),
            "the TCP connection must be accepted"
        );
        // But never marked handshaked on an orphan verack.
        assert!(
            !wait_until(
                || {
                    let g = a.shared.lock().unwrap();
                    g.peers.values().any(|p| p.handshaked)
                },
                2
            ),
            "a verack without version must not complete the handshake"
        );
        a.shutdown();
    }

    /// A peer from an earlier version of the protocol is disconnected at the
    /// handshake: it does not validate the same rules, and exchanging with it
    /// would only produce mutual rejections.
    #[test]
    fn a_peer_from_an_earlier_version_is_dropped_at_the_handshake() {
        use std::io::Write;
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        let magic = magic_for(NETWORK);

        let mut s = std::net::TcpStream::connect(addr).expect("connection");
        let old = Message::Version {
            version: MIN_PROTOCOL_VERSION - 1,
            timestamp: unix_now(),
            nonce: 0x1234_5678,
            user_agent: "q21:0.1".into(),
            start_height: 0,
        };
        s.write_all(&old.frame(magic)).unwrap();
        s.flush().unwrap();

        // The peer is accepted at the TCP level then dropped: it does not stay.
        assert!(
            wait_until(|| a.peer_count() == 0, 5) && {
                std::thread::sleep(std::time::Duration::from_millis(300));
                a.peer_count() == 0
            },
            "a peer from an earlier version must be dropped"
        );
        assert!(
            !{
                let g = a.shared.lock().unwrap();
                g.peers.values().any(|p| p.handshaked)
            },
            "and never marked handshaked"
        );
        a.shutdown();
    }

    /// Regtest opens policies at its first block and mainnet never does:
    /// neither has a transition, so every peer is offered everything, as in
    /// 0.4.10.
    #[test]
    fn without_a_transition_every_version_follows() {
        for network in [Network::Regtest, Network::Mainnet] {
            assert!(!crate::policy::has_transition(network));
            for version in [MIN_PROTOCOL_VERSION, 4, PROTOCOL_VERSION] {
                assert!(follows_activation(network, version));
            }
        }
    }

    /// A 0.4.10 node speaks protocol 4: it predates the policy activation but
    /// is still a peer, as it must be until the activation height.
    #[test]
    fn a_0_4_10_peer_completes_the_handshake() {
        use std::io::Write;
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        let magic = magic_for(NETWORK);
        let mut s = std::net::TcpStream::connect(addr).expect("connection");
        let v4 = Message::Version {
            version: 4,
            timestamp: unix_now(),
            nonce: 0x0410,
            user_agent: "q21:0.4".into(),
            start_height: 0,
        };
        s.write_all(&v4.frame(magic)).unwrap();
        s.write_all(&Message::VerAck.frame(magic)).unwrap();
        s.flush().unwrap();
        assert!(
            wait_until(
                || {
                    let g = a.shared.lock().unwrap();
                    g.peers.values().any(|p| p.handshaked && p.version == 4)
                },
                5
            ),
            "a version-4 peer must stay welcome"
        );
        a.shutdown();
    }

    #[test]
    fn the_handshake_announces_the_height() {
        let (a, b) = node_pair();
        mine(&a, 3);
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(
                || {
                    let g = b.shared.lock().unwrap();
                    g.peers
                        .values()
                        .any(|p| p.handshaked && p.start_height == 3)
                },
                5
            ),
            "b should have learned that a is at height 3"
        );
        a.shutdown();
        b.shutdown();
    }

    /// A silent peer ends up disconnected, and its slot freed.
    ///
    /// # The defect locked down here
    ///
    /// The read loop set a 120-second timeout on the socket and handled its
    /// expiry with `continue`: it started waiting again, indefinitely. A peer
    /// that stops sending was therefore never removed.
    ///
    /// Consequence, observed on a real laptop: you close the MacBook's lid, the
    /// connection dies without any FIN or RST arriving, and the node keeps a
    /// ghost peer. The peer count stays at one, the maintenance loop — which
    /// only searches if peers are missing — has nothing to do, and the chain
    /// stops at the height it was at. It stayed there.
    ///
    /// On a public network, it is also an eclipse path: opening connections
    /// and then going quiet is enough to occupy every slot.
    ///
    /// The test cannot wait a hundred seconds: it ages the last reception by
    /// hand, which is exactly what time would have done.
    #[test]
    fn a_silent_peer_is_dropped_and_its_slot_freed() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        assert!(wait_until(|| b.peer_count() == 1, 20), "no peer");

        // Nothing must move as long as the peer talks.
        assert_eq!(b.maintain_peers(), 0, "a live peer was dropped");
        assert_eq!(b.peer_count(), 1);

        // Time passes, and nothing arrives anymore.
        {
            let mut g = b.shared.lock().unwrap();
            let old = Instant::now()
                .checked_sub(MAX_SILENCE + Duration::from_secs(5))
                .expect("clock");
            for p in g.peers.values_mut() {
                p.last_received = old;
            }
        }
        assert_eq!(b.maintain_peers(), 1, "the silent peer was not dropped");
        assert_eq!(
            b.peer_count(),
            0,
            "the silent peer's slot was not freed: the node will always \
             believe it has a peer, and will look for no one"
        );

        // And the freed slot can be taken again: that is the whole point of the
        // operation.
        b.connect(addr).expect("reconnection");
        assert!(wait_until(|| b.peer_count() == 1, 20), "no reconnection");

        a.shutdown();
        b.shutdown();
    }

    /// After a possible sleep, live links are kept and dead ones dropped:
    /// the check is a ping, not a cut.
    #[test]
    fn a_sleep_check_keeps_live_links_and_drops_dead_ones() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        assert!(
            wait_until(|| b.peer_count_established() == 1, 20),
            "no peer"
        );
        // A second link whose other end never answers: a machine gone.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let s = TcpStream::connect(dead.local_addr().unwrap()).unwrap();
        let dead_id = b.start_peer(s, true);
        assert!(wait_until(|| b.peer_count() == 2, 5));
        // As if its handshake had completed before the machine went away:
        // the check is for established links.
        b.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&dead_id)
            .unwrap()
            .handshaked = true;

        assert_eq!(b.probe_all_peers(), 2);
        // Within the grace, nobody is dropped yet.
        assert_eq!(b.maintain_peers(), 0);
        // The live peer answers the ping.
        assert!(wait_until(
            || {
                let g = b.shared.lock().unwrap();
                g.peers
                    .values()
                    .filter(|p| p.pending_ping.is_none())
                    .count()
                    == 1
            },
            10
        ));
        // Past the grace: as if PROBE_GRACE had elapsed for the silent one.
        {
            let mut g = b.shared.lock().unwrap();
            for p in g.peers.values_mut() {
                if p.pending_ping.is_some() {
                    p.last_received = p
                        .last_received
                        .checked_sub(PROBE_GRACE + Duration::from_secs(1))
                        .unwrap();
                }
            }
        }
        assert_eq!(b.maintain_peers(), 1, "the dead link is dropped");
        assert_eq!(b.peer_count_established(), 1, "the live link is kept");
        a.shutdown();
        b.shutdown();
    }

    /// A shorter silence triggers a `Ping`, without disconnecting.
    ///
    /// Disconnecting at the first silence would be as wrong as never
    /// disconnecting: a slow link, a busy peer, and we end up reopening
    /// connections nonstop. We first ask the peer to show signs of life.
    #[test]
    fn a_brief_silence_queries_the_peer_without_dropping_it() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        assert!(wait_until(|| b.peer_count() == 1, 20), "no peer");

        {
            let mut g = b.shared.lock().unwrap();
            let old = Instant::now()
                .checked_sub(PING_AFTER + Duration::from_secs(2))
                .expect("clock");
            for p in g.peers.values_mut() {
                p.last_received = old;
            }
        }
        assert_eq!(
            b.maintain_peers(),
            0,
            "a peer that was merely silent was dropped"
        );
        assert_eq!(b.peer_count(), 1);

        // The peer answers: the reply brings it back to life, and the next
        // maintenance finds nothing more to drop.
        assert!(
            wait_until(
                || {
                    let g = b.shared.lock().unwrap();
                    g.peers
                        .values()
                        .all(|p| p.last_received.elapsed() < PING_AFTER)
                },
                20
            ),
            "the peer did not answer the Ping"
        );

        a.shutdown();
        b.shutdown();
    }

    /// The test that proves phase 4 works.
    #[test]
    fn two_nodes_synchronize_over_tcp() {
        let (a, b) = node_pair();
        mine(&a, 12);
        assert_eq!(a.height(), 12);
        assert_eq!(b.height(), 0);

        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| b.height() == 12, 30),
            "b stayed at height {}",
            b.height()
        );
        assert_eq!(b.tip_id(), a.tip_id(), "the tips must match");
        assert_eq!(
            b.with_chain(|c| c.utxo.total_value()),
            a.with_chain(|c| c.utxo.total_value()),
            "the UTXO sets must match"
        );
        // Proof that the bytes really went over the wire: without it, a test
        // that passed by accident would prove nothing.
        //
        // The counter looks at **compact** blocks: since header-based
        // synchronization requests compact announcements rather than full
        // bodies, no `block` message travels anymore during catch-up. This is
        // the intended behavior, and this assertion locks it in.
        let compacts = b.stats.compacts_received.load(Ordering::Relaxed);
        assert!(
            compacts >= 12,
            "only {compacts} compact announcements received over the wire"
        );
        assert!(
            b.stats.blocks_accepted.load(Ordering::Relaxed) >= 12,
            "blocks received but not accepted"
        );
        // A fresh node has nothing in its mempool: each block therefore
        // required a round trip. The gain of compact relay is measured in
        // steady state, not during the initial catch-up.
        assert_eq!(
            b.stats.compacts_without_round_trip.load(Ordering::Relaxed),
            12,
            "blocks without transactions are reconstructed without a round trip"
        );
        a.shutdown();
        b.shutdown();
    }

    /// The cap on bodies in flight must not stop the synchronization.
    ///
    /// With at most sixteen bodies in flight per peer, a catch-up of more than
    /// sixteen blocks only holds if each body received makes us request the
    /// next one. Three and a half caps: enough to go through several waves,
    /// and for the header re-request on a drained queue to be exercised too.
    #[test]
    fn sync_continues_beyond_the_bodies_in_flight() {
        let (a, b) = node_pair();
        let target = MAX_BODIES_IN_FLIGHT * 3 + MAX_BODIES_IN_FLIGHT / 2;
        mine(&a, target);
        assert_eq!(a.height(), target as u64);

        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        assert!(
            wait_until(|| b.height() == target as u64, 30),
            "b stayed at height {} out of {target}: the synchronization \
             stopped at the cap on bodies in flight",
            b.height()
        );
        assert_eq!(b.tip_id(), a.tip_id(), "the tips must match");
        // And never more than the in-flight cap toward this peer.
        let in_flight = {
            let g = b.shared.lock().unwrap();
            g.peers
                .values()
                .map(|p| p.requested_bodies.len())
                .max()
                .unwrap_or(0)
        };
        assert!(
            in_flight <= MAX_BODIES_IN_FLIGHT,
            "{in_flight} bodies in flight"
        );
        a.shutdown();
        b.shutdown();
    }

    /// A fake peer, to test admission on addresses that a machine without
    /// IPv6 cannot open. The socket is real — a `Peer` holds one — but the
    /// address is whatever we want.
    fn fake_peer(n: &Node, id: u64, addr: SocketAddr, outbound: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let mut g = n.shared.lock().unwrap();
        g.peers.insert(
            id,
            Peer {
                addr,
                writer: Outbox::start(stream).unwrap(),
                outbound,
                snapshot_bucket: TokenBucket::new(Instant::now()),
                tx_bucket: TokenBucket::for_transactions(Instant::now()),
                cmpct_bucket: TokenBucket::for_compact_announcements(Instant::now()),
                user_agent: String::new(),
                channels: false,
                channel_id: String::new(),
                chan_bucket: TokenBucket::for_channel_messages(Instant::now()),
                headers_bucket: TokenBucket::for_header_requests(Instant::now()),
                addr_bucket: TokenBucket::for_addresses(Instant::now()),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: false,
                version_sent: outbound,
                handshaked: false,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                mempool_offered: false,
                version: 0,
                remote_nonce: None,
                last_received: Instant::now(),
                last_delivered: Instant::now(),
                body_overdue_rounds: 0,
                late_bodies: VecDeque::new(),
                pending_ping: None,
                requested_txs: HashMap::new(),
                announced_waiting: VecDeque::new(),
                connected_at: Instant::now(),
            },
        );
    }

    /// Group diversity also applies to IPv6 inbound connections.
    ///
    /// The per-group cap was only computed for IPv4: a single `/64` could
    /// occupy every inbound slot of a node listening on IPv6. The test machine
    /// has no IPv6 and cannot open an IPv6 socket: we test the admission rule
    /// on peers with a chosen address.
    #[test]
    fn admission_also_bounds_ipv6_inbound() {
        let a = node();
        let same_64 =
            |k: u16| -> SocketAddr { format!("[2001:db8:1:2::{k:x}]:21021").parse().unwrap() };
        for k in 0..INBOUND_PER_GROUP as u16 {
            assert!(
                a.admit_inbound(Some(same_64(k + 1))),
                "connection number {} from the /64 must get through",
                k + 1
            );
            fake_peer(&a, 100 + u64::from(k), same_64(k + 1), false);
        }
        assert!(
            !a.admit_inbound(Some(same_64(0x99))),
            "a whole /64 must be bounded to {INBOUND_PER_GROUP} inbound connections, \
             like a /16 in IPv4"
        );
        // Another /64 of the same /48 is another group.
        let other_64: SocketAddr = "[2001:db8:1:3::1]:21021".parse().unwrap();
        assert!(
            a.admit_inbound(Some(other_64)),
            "another /64 must remain admitted"
        );
        // An IPv4 address presented as IPv6 counts with the IPv4 addresses of
        // its /16, not in a /64 shared by the whole v4 Internet.
        for k in 0..INBOUND_PER_GROUP as u16 {
            let v4: SocketAddr = format!("203.0.113.{}:21021", k + 1).parse().unwrap();
            fake_peer(&a, 200 + u64::from(k), v4, false);
        }
        let mapped: SocketAddr = "[::ffff:203.0.113.77]:21021".parse().unwrap();
        assert!(
            !a.admit_inbound(Some(mapped)),
            "a mapped IPv4 address must be counted in its /16"
        );
        let mapped_elsewhere: SocketAddr = "[::ffff:198.51.100.1]:21021".parse().unwrap();
        assert!(
            a.admit_inbound(Some(mapped_elsewhere)),
            "a mapped IPv4 address from another /16 must get through"
        );
        // And loopback stays outside any group, in v6 as in v4.
        assert_eq!(inbound_group("[::1]:1".parse().unwrap()), None);
        a.shutdown();
    }

    /// A household that has filled its group's slots learns why.
    ///
    /// The real-life case: four connections from the same router address, and
    /// a fifth device rejected without a word. The log must name the real
    /// cause — the group, not a full bootstrap node —, otherwise the operator
    /// looks at the server's capacity, which has nothing to do with it.
    #[test]
    fn a_group_rejection_says_it_is_the_group() {
        let a = node();
        let household =
            |k: u16| -> SocketAddr { format!("203.0.113.45:{}", 40000 + k).parse().unwrap() };
        assert_eq!(a.inbound_rejection(Some(household(0))), None);
        for k in 0..INBOUND_PER_GROUP as u16 {
            fake_peer(&a, 300 + u64::from(k), household(k), false);
        }
        let reason = a
            .inbound_rejection(Some(household(99)))
            .expect("the household's fifth device must be rejected");
        assert!(
            reason.contains("group"),
            "the reason must name the address group: {reason}"
        );
        // Another household, on the other hand, always gets in.
        let neighbor: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        assert_eq!(a.inbound_rejection(Some(neighbor)), None);
        a.shutdown();
    }

    /// Number of peers whose handshake is **complete** — the only ones
    /// `announce_block` talks to.
    ///
    /// `peer_count` also counts connections still introducing themselves. A
    /// test that waits for `peer_count() == 1` and then announces a block
    /// therefore runs a race: measured over 150 trials, in 135 cases the peer
    /// was counted before having introduced itself. The announcement then went
    /// to nobody, silently, and the test only held so far because mining the
    /// block took longer than finishing the handshake. On a loaded machine — a
    /// continuous integration runner running six hundred tests side by side —
    /// that is no longer true, and the release fails without a single line of
    /// code having changed.
    fn established_peers(n: &Node) -> usize {
        n.shared
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|p| p.handshaked)
            .count()
    }

    #[test]
    fn a_block_mined_after_connection_propagates() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        // The handshake, not just the connection: see `established_peers`.
        assert!(
            wait_until(
                || established_peers(&a) == 1 && established_peers(&b) == 1,
                5
            ),
            "handshake not completed"
        );

        mine(&a, 1);
        let block = a.with_chain(|c| c.block_by_id(&c.tip_id())).unwrap();
        a.announce_block(&block);

        assert!(
            wait_until(|| b.height() == 1, 20),
            "the announced block was not fetched"
        );
        assert_eq!(b.tip_id(), a.tip_id());
        // Propagation must have gone through compact relay.
        assert!(
            b.stats.compacts_received.load(Ordering::Relaxed) > 0,
            "the block should have traveled as compact"
        );
        a.shutdown();
        b.shutdown();
    }

    #[test]
    fn a_node_refuses_to_connect_to_itself() {
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        a.connect(addr).expect("connection");
        // Nonce detection must end up closing both sides.
        assert!(
            wait_until(|| a.peer_count() <= 1, 10),
            "the connection to itself was not dropped"
        );
        a.shutdown();
    }

    #[test]
    fn random_bytes_do_not_bring_the_node_down() {
        let a = node();
        let addr = a.listen("127.0.0.1:0").expect("listen");

        for seed in 0..20u64 {
            if let Ok(mut s) = TcpStream::connect(addr) {
                let mut raw = vec![0u8; 256];
                let mut g = seed.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(3);
                for o in raw.iter_mut() {
                    g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    *o = (g >> 33) as u8;
                }
                let _ = std::io::Write::write_all(&mut s, &raw);
            }
        }

        // The node must stay alive and answer normally afterwards.
        let b = node();
        b.connect(addr).expect("connection after aggression");
        assert!(
            wait_until(|| b.peer_count() == 1, 10),
            "the node stopped answering after random bytes"
        );
        a.shutdown();
        b.shutdown();
    }

    /// A full-pool refusal is remembered across blocks, with the rate and size
    /// it was refused at, and the transaction is not requested again while the
    /// pool still has no room for it — only once it could take it.
    ///
    /// Before, the whole refusal set was emptied at every block, so each peer's
    /// re-offer of its full pool after a block made the node re-download
    /// everything it had just refused.
    #[test]
    fn a_full_pool_refusal_survives_a_block_and_waits_for_room() {
        let n = node();
        let h = Hash256([7u8; 32]);
        // A size no pool can ever hold: the pool can never take it.
        let too_big = 1usize << 40;
        {
            let mut g = n.shared.lock().unwrap();
            g.full_pool_rejected.insert(h, (1_000, too_big, 0));
            // A stale tip-scoped set: a block has moved the tip since, so this
            // would no longer block on its own.
            g.rejected_at = Hash256([9u8; 32]);
            g.rejected.insert(h);
        }
        assert!(
            !Node::should_request_tx(&n.shared.lock().unwrap(), &h),
            "a full-pool refusal is kept across the block and not fetched again \
             while there is no room"
        );
        // Once the pool could take it (a size that fits), it is worth asking
        // for again.
        n.shared
            .lock()
            .unwrap()
            .full_pool_rejected
            .insert(h, (1_000, 500, 0));
        assert!(
            Node::should_request_tx(&n.shared.lock().unwrap(), &h),
            "once the pool has room, the transaction is requested again"
        );
    }

    /// A transaction already held as an orphan, waiting for its parent, is not
    /// requested again at every offer.
    #[test]
    fn an_orphan_already_held_is_not_requested_again() {
        let n = node();
        let tx = Transaction {
            version: 1,
            inputs: vec![crate::tx::TxIn::coinbase(vec![3])],
            outputs: Vec::new(),
            lock_time: 0,
        };
        let h = tx.txid();
        assert!(
            Node::should_request_tx(&n.shared.lock().unwrap(), &h),
            "unknown and not held: worth requesting"
        );
        n.shared.lock().unwrap().orphans.add(tx, 7, Instant::now());
        assert!(
            !Node::should_request_tx(&n.shared.lock().unwrap(), &h),
            "an orphan already waiting is not fetched again"
        );
    }
}

#[cfg(test)]
mod tests_incompatible_chains {
    use super::tests_util::*;
    use super::*;
    use crate::block::BlockHeader;

    /// The defect found by running two real nodes, turned into a test.
    ///
    /// Two different geneses: the peers must notice it and part ways, instead
    /// of exchanging orphan blocks until exhaustion.
    #[test]
    fn two_nodes_with_different_geneses_part_ways() {
        let a = node_with_genesis(7);
        let b = node_with_genesis(99);
        assert_ne!(a.tip_id(), b.tip_id(), "the geneses must differ");

        mine_locally(&a, 5);
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");

        // Node b must neither progress nor keep at it.
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(b.height(), 0, "b should not have adopted a foreign chain");
        assert!(
            b.stats.blocks_received.load(Ordering::Relaxed) < 50,
            "b downloaded {} orphan blocks: the infinite loop is back",
            b.stats.blocks_received.load(Ordering::Relaxed)
        );
        a.shutdown();
        b.shutdown();
    }

    #[test]
    fn headers_that_do_not_follow_each_other_are_rejected() {
        let a = node_with_genesis(1);
        let mut fake = BlockHeader {
            version: 1,
            prev_block: a.tip_id(),
            merkle_root: Hash256([1u8; 32]),
            uncles_root: Hash256::ZERO,
            miner: Hash256([2u8; 32]),
            time: 1,
            bits: crate::consensus::INITIAL_BITS,
            height: 1,
            nonce: 0,
        };
        let first = fake;
        // The second does not point to the first: the sequence is broken.
        fake.prev_block = Hash256([0xaa; 32]);
        fake.height = 2;

        let before = a.stats.blocks_received.load(Ordering::Relaxed);
        let _ = a.handle(999, Message::Headers(vec![first, fake]));
        assert_eq!(
            a.stats.blocks_received.load(Ordering::Relaxed),
            before,
            "no body must be requested on a broken sequence"
        );
        a.shutdown();
    }
}

#[cfg(test)]
mod tests_util {
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::sig::SchemeId;

    pub const NETWORK: Network = Network::Regtest;

    /// Node whose genesis is artificially distinct.
    ///
    /// The real genesis is deterministic per network — that is precisely the
    /// fix. To simulate two incompatible chains, we shift its timestamp.
    pub fn node_with_genesis(offset: u64) -> Node {
        let mut g = genesis_block(NETWORK);
        g.header.time += offset;
        g.header.nonce = 0;
        let table =
            crate::memhard::PowTable::build(crate::memhard::TableParams::for_network(NETWORK), 0);
        let _ = crate::pow::mine_with_table(&mut g.header, &table, 5_000_000);
        Node::new(NETWORK, Chain::new(NETWORK, g))
    }

    pub fn mine_locally(n: &Node, count: usize) {
        for _ in 0..count {
            let b = n.with_chain(|c| {
                let t = c.tip().time + TARGET_BLOCK_SECS;
                c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
            });
            if let Some(b) = b {
                n.with_chain(|c| {
                    let t = b.header.time + 1;
                    let _ = c.connect(&b, t);
                });
            }
        }
    }
}

/// Hardening 0.3.2: work outside the lock, header bucket, unrequested
/// headers.
#[cfg(test)]
mod tests_hardening {
    use super::*;
    use crate::chain::genesis_block;
    use crate::consensus::TARGET_BLOCK_SECS;
    use crate::pow::PowEngine;
    use crate::sig::SchemeId;

    const NETWORK: Network = Network::Regtest;

    fn node_pair() -> (Node, Node) {
        let g = genesis_block(NETWORK);
        (
            Node::new(NETWORK, Chain::new(NETWORK, g.clone())),
            Node::new(NETWORK, Chain::new(NETWORK, g)),
        )
    }

    /// An established peer, on a real socket whose other end nobody reads: we
    /// observe the node's state, not what it writes.
    fn established_peer(n: &Node, id: u64) -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let addr = stream.peer_addr().unwrap();
        let mut g = n.shared.lock().unwrap();
        g.peers.insert(
            id,
            Peer {
                addr,
                writer: Outbox::start(stream).unwrap(),
                outbound: true,
                snapshot_bucket: TokenBucket::new(Instant::now()),
                tx_bucket: TokenBucket::for_transactions(Instant::now()),
                cmpct_bucket: TokenBucket::for_compact_announcements(Instant::now()),
                user_agent: String::new(),
                channels: false,
                channel_id: String::new(),
                chan_bucket: TokenBucket::for_channel_messages(Instant::now()),
                headers_bucket: TokenBucket::for_header_requests(Instant::now()),
                addr_bucket: TokenBucket::for_addresses(Instant::now()),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: true,
                version_sent: true,
                handshaked: true,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                mempool_offered: false,
                version: 0,
                remote_nonce: None,
                last_received: Instant::now(),
                last_delivered: Instant::now(),
                body_overdue_rounds: 0,
                late_bodies: VecDeque::new(),
                pending_ping: None,
                requested_txs: HashMap::new(),
                announced_waiting: VecDeque::new(),
                connected_at: Instant::now(),
            },
        );
        listener
    }

    /// A valid block mined on `n`, without connecting it.
    fn next_block(n: &Node) -> Block {
        n.with_chain(|c| {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            c.mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
        })
        .expect("regtest mining")
    }

    /// Mines and connects one block on `n`; returns it.
    fn connect_block(n: &Node) -> Block {
        let b = next_block(n);
        n.with_chain(|c| c.connect(&b, b.header.time + 1))
            .expect("connect");
        b
    }

    /// A spend of `b`'s coinbase whose key and signature have the sizes the
    /// scheme fixes (their content does not matter: a rate refusal comes before
    /// any signature), paying `fee`.
    fn canonical_spend(b: &Block, fee: u64) -> Transaction {
        let cb = &b.transactions[0];
        let s = SchemeId::LamportOts;
        Transaction {
            version: 1,
            inputs: vec![crate::tx::TxIn {
                prev_out: crate::tx::OutPoint {
                    txid: cb.txid(),
                    index: 0,
                },
                witness: crate::tx::Witness {
                    pubkey: vec![1u8; s.pubkey_len()],
                    signature: vec![2u8; s.sig_len()],
                },
                sequence: 0,
            }],
            outputs: vec![crate::tx::TxOut {
                value: crate::amount::Amount::from_units(cb.outputs[0].value.units() - fee),
                scheme: s,
                pubkey_hash: Hash256([5u8; 32]),
            }],
            lock_time: 0,
        }
    }

    /// The same transaction, its signature padded: same `txid`, heavier.
    fn padded(tx: &Transaction, extra: usize) -> Transaction {
        let mut p = tx.clone();
        p.inputs[0].witness.signature.extend(vec![0u8; extra]);
        assert_eq!(p.txid(), tx.txid());
        p
    }

    /// Finding 9: a copy of a transaction padded to a lower rate, refused by a
    /// full pool, must not get the honest copy ignored. The `txid` leaves the
    /// witness out, so the refusal was remembered for every copy, and the
    /// honest one was never requested again while the pool stayed full.
    #[test]
    fn a_padded_copy_refused_by_a_full_pool_does_not_shut_out_the_honest_one() {
        let (_a, b) = node_pair();
        let _p = established_peer(&b, 7);
        let block = connect_block(&b);
        let honest = canonical_spend(&block, block.transactions[0].outputs[0].value.units() / 2);
        let bloated = padded(&honest, 50_000);
        let txid = honest.txid();

        // A pool with no room at all: refused before any signature.
        b.shared.lock().unwrap().mempool = Mempool::with_capacity(1);
        let _ = b.handle(7, Message::Tx(Box::new(bloated)));

        // Now room for the honest copy, not for the padded one.
        b.shared.lock().unwrap().mempool = Mempool::with_capacity(honest.encode().len() + 100);
        assert!(
            Node::should_request_tx(&b.shared.lock().unwrap(), &txid),
            "a padded copy's refusal shut the honest transaction out"
        );
    }

    /// The same for a fee-floor refusal: a copy padded below the minimum rate
    /// must not keep the honest one away until the next block.
    #[test]
    fn a_padded_copy_under_the_fee_floor_does_not_shut_out_the_honest_one() {
        let (_a, b) = node_pair();
        let _p = established_peer(&b, 7);
        let block = connect_block(&b);
        // Just above the floor as it is; far below it once padded.
        let probe = canonical_spend(&block, 0);
        let weight = probe.weight(crate::consensus::WITNESS_DISCOUNT);
        let fee = crate::mempool::MIN_FEE_RATE * weight / 1000 + 10;
        let honest = canonical_spend(&block, fee);
        let bloated = padded(&honest, 200_000);
        let _ = b.handle(7, Message::Tx(Box::new(bloated)));
        assert!(
            Node::should_request_tx(&b.shared.lock().unwrap(), &honest.txid()),
            "a padded copy's fee refusal shut the honest transaction out"
        );
    }

    /// What finding 9 must not undo: the refusal of a copy of the right sizes
    /// is still remembered, so a full pool does not download it again at every
    /// offer — but only for a few blocks.
    #[test]
    fn a_full_pool_refusal_of_a_canonical_copy_is_kept_for_a_few_blocks() {
        let (_a, b) = node_pair();
        let _p = established_peer(&b, 7);
        let block = connect_block(&b);
        let honest = canonical_spend(&block, block.transactions[0].outputs[0].value.units() / 2);
        let txid = honest.txid();
        b.shared.lock().unwrap().mempool = Mempool::with_capacity(1);
        let _ = b.handle(7, Message::Tx(Box::new(honest)));
        assert!(
            !Node::should_request_tx(&b.shared.lock().unwrap(), &txid),
            "a refusal that holds for every copy is remembered"
        );
        for _ in 0..FULL_POOL_REFUSAL_BLOCKS {
            connect_block(&b);
        }
        assert!(
            Node::should_request_tx(&b.shared.lock().unwrap(), &txid),
            "the refusal expired after a few blocks"
        );
    }

    /// A sink that records the blocks and transactions handed to its watcher.
    struct BlockRecorder {
        blocks: AtomicU64,
        txs: AtomicU64,
    }

    impl ChannelSink for BlockRecorder {
        fn deliver(&self, _peer: u64, _peer_identity: &str, _bytes: &[u8]) -> ChannelOutcome {
            ChannelOutcome::default()
        }
        fn on_connected_block(
            &self,
            txs: &[crate::tx::Transaction],
            _height: u64,
            _depth_of: &dyn Fn(&crate::tx::OutPoint) -> Option<(u64, crate::tx::TxOut)>,
        ) -> Vec<(u64, Vec<u8>)> {
            self.blocks.fetch_add(1, Ordering::SeqCst);
            self.txs.fetch_add(txs.len() as u64, Ordering::SeqCst);
            Vec::new()
        }
    }

    /// A sink that records the transaction ids handed to it, connected and
    /// disconnected, in order.
    #[derive(Default)]
    struct ReorgRecorder {
        connected: Mutex<Vec<Hash256>>,
        disconnected: Mutex<Vec<Hash256>>,
        /// Each call: the height handed and the transactions.
        blocks: Mutex<Vec<(u64, Vec<Hash256>)>>,
    }

    impl ChannelSink for ReorgRecorder {
        fn deliver(&self, _peer: u64, _peer_identity: &str, _bytes: &[u8]) -> ChannelOutcome {
            ChannelOutcome::default()
        }
        fn on_connected_block(
            &self,
            txs: &[crate::tx::Transaction],
            height: u64,
            _depth_of: &dyn Fn(&crate::tx::OutPoint) -> Option<(u64, crate::tx::TxOut)>,
        ) -> Vec<(u64, Vec<u8>)> {
            let mut c = self.connected.lock().unwrap();
            c.extend(txs.iter().map(|t| t.txid()));
            self.blocks
                .lock()
                .unwrap()
                .push((height, txs.iter().map(|t| t.txid()).collect()));
            Vec::new()
        }
        fn on_disconnected_txids(&self, txids: &[Hash256]) {
            let mut d = self.disconnected.lock().unwrap();
            d.extend_from_slice(txids);
        }
    }

    /// M5: a reorganization hands the channel watcher the abandoned blocks as
    /// disconnected, and every block of the winning branch as connected — not
    /// only the tip that triggered the switch.
    #[test]
    fn a_reorganization_reaches_the_channel_watcher_whole() {
        let (a, b) = node_pair();
        let (x, _) = node_pair();
        let rec = Arc::new(ReorgRecorder::default());
        b.set_channel_sink(rec.clone());
        let _e = established_peer(&b, 7);
        let mine_on = |n: &Node, who: u8| {
            let blk = n
                .with_chain(|c| {
                    let t = c.tip().time + TARGET_BLOCK_SECS;
                    c.mine_block(Hash256([who; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                })
                .expect("regtest mining");
            n.with_chain(|c| c.connect(&blk, blk.header.time + 1).expect("connect"));
            blk
        };
        let a1 = mine_on(&a, 2);
        assert!(b.handle(7, Message::Block(Box::new(a1.clone()))));
        // A heavier branch from the same genesis: the first block stays on a
        // side branch, the second switches the chain.
        let x1 = mine_on(&x, 3);
        let x2 = mine_on(&x, 3);
        assert!(b.handle(7, Message::Block(Box::new(x1.clone()))));
        assert!(b.handle(7, Message::Block(Box::new(x2.clone()))));
        assert_eq!(b.height(), 2, "the heavier branch won");
        let ids = |blk: &Block| {
            blk.transactions
                .iter()
                .map(|t| t.txid())
                .collect::<Vec<_>>()
        };
        let connected = rec.connected.lock().unwrap().clone();
        let disconnected = rec.disconnected.lock().unwrap().clone();
        assert_eq!(
            disconnected,
            ids(&a1),
            "the abandoned block is disconnected"
        );
        let mut expected = ids(&a1);
        expected.extend(ids(&x1));
        expected.extend(ids(&x2));
        assert_eq!(
            connected, expected,
            "every block of the winning branch is scanned, in order"
        );
        // Each block at its own height.
        let heights: Vec<u64> = rec.blocks.lock().unwrap().iter().map(|b| b.0).collect();
        assert_eq!(heights, vec![1, 1, 2]);
    }

    /// A reorganization deeper than the abandoned bodies the chain keeps: the
    /// winning branch is still scanned from the real fork, every block once at
    /// its own height — not from a guess at the fork that over- or
    /// under-scans.
    #[test]
    fn a_deep_reorganization_is_scanned_from_its_real_fork() {
        let (a, b) = node_pair();
        let (x, _) = node_pair();
        let rec = Arc::new(ReorgRecorder::default());
        b.set_channel_sink(rec.clone());
        let _e = established_peer(&b, 7);
        let mine_on = |n: &Node, who: u8| {
            let blk = n
                .with_chain(|c| {
                    let t = c.tip().time + TARGET_BLOCK_SECS;
                    c.mine_block(Hash256([who; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                })
                .expect("regtest mining");
            n.with_chain(|c| c.connect(&blk, blk.header.time + 1).expect("connect"));
            blk
        };
        let deep = crate::chain::RETURNED_BLOCKS as u64 + 3;
        let mut abandoned = Vec::new();
        for _ in 0..deep {
            let blk = mine_on(&a, 2);
            abandoned.push(blk.clone());
            assert!(b.handle(7, Message::Block(Box::new(blk))));
        }
        let mut branch = Vec::new();
        for _ in 0..(2 * deep) {
            branch.push(mine_on(&x, 3));
        }
        rec.blocks.lock().unwrap().clear();
        for blk in &branch {
            assert!(b.handle(7, Message::Block(Box::new(blk.clone()))));
        }
        assert_eq!(b.height(), 2 * deep, "the heavier branch won");
        let seen = rec.blocks.lock().unwrap().clone();
        let expected: Vec<(u64, Vec<Hash256>)> = branch
            .iter()
            .enumerate()
            .map(|(i, blk)| {
                (
                    i as u64 + 1,
                    blk.transactions.iter().map(|t| t.txid()).collect(),
                )
            })
            .collect();
        assert_eq!(
            seen, expected,
            "the new branch, block by block, from the fork"
        );
        // And every abandoned transaction is forgotten, from the deepest
        // block too, not only the newest ones offered back to the mempool.
        let mut gone = rec.disconnected.lock().unwrap().clone();
        gone.sort();
        let mut want: Vec<Hash256> = abandoned
            .iter()
            .flat_map(|b| b.transactions.iter().map(|t| t.txid()))
            .collect();
        want.sort();
        assert_eq!(gone, want, "every disconnected transaction");
    }

    /// A sink that rejects every channel message as misconduct.
    struct Rejecter;

    impl ChannelSink for Rejecter {
        fn deliver(&self, _peer: u64, _peer_identity: &str, _bytes: &[u8]) -> ChannelOutcome {
            ChannelOutcome {
                replies: Vec::new(),
                penalize: MISCONDUCT_CHANNEL,
            }
        }
    }

    /// D14: a rejected channel message costs its sender points, like any other
    /// misconduct, and the link falls when the score reaches the threshold —
    /// not at the first one. A payment crossing the peer's own is rejected;
    /// dropping the link for it, then again at each reestablish, kept two
    /// honest wallets cut off from each other.
    #[test]
    fn a_rejected_channel_message_costs_points_not_the_link() {
        let (a, _) = node_pair();
        a.set_channel_sink(Arc::new(Rejecter));
        let _e = established_peer(&a, 7);
        a.shared.lock().unwrap().peers.get_mut(&7).unwrap().channels = true;
        let tolerated = BAN_THRESHOLD.div_ceil(MISCONDUCT_CHANNEL) - 1;
        for i in 1..=tolerated {
            assert!(
                a.handle(7, Message::Channel(vec![0u8; 40])),
                "the link fell at rejected message {i}, below the threshold"
            );
        }
        assert!(
            !a.handle(7, Message::Channel(vec![0u8; 40])),
            "a peer at the threshold is still disconnected"
        );
    }

    /// The same rule for a channel message from a peer that never advertised
    /// the capability: points first, the link at the threshold.
    #[test]
    fn an_unsolicited_channel_message_costs_points_up_to_the_threshold() {
        let (a, _) = node_pair();
        a.set_channel_sink(Arc::new(Rejecter));
        let _e = established_peer(&a, 7);
        let tolerated = BAN_THRESHOLD.div_ceil(MISCONDUCT_CHANNEL) - 1;
        for i in 1..=tolerated {
            assert!(
                a.handle(7, Message::Channel(vec![0u8; 40])),
                "the link fell at unsolicited message {i}, below the threshold"
            );
        }
        assert!(
            !a.handle(7, Message::Channel(vec![0u8; 40])),
            "a peer at the threshold is still disconnected"
        );
    }

    /// Without a transition there is nothing to warn about, whatever the
    /// versions connected.
    #[test]
    fn no_warning_about_old_peers_without_a_transition() {
        let (a, _) = node_pair();
        let _e = established_peer(&a, 7);
        a.shared.lock().unwrap().peers.get_mut(&7).unwrap().version = 4;
        assert_eq!(a.peers_predating_activation(), 0);
        assert_eq!(a.warn_peers_predating_activation(), 0);
    }

    /// Finding 14: off regtest, where channels do not exist, a channel
    /// message gets what 0.4.9 gave an unknown command — malformed, and the
    /// link is cut — not a 20-point charge on a link that stays up.
    #[test]
    fn a_channel_message_off_regtest_is_malformed_and_cuts_the_link() {
        let net = Network::Testnet;
        let n = Node::new(net, Chain::new(net, crate::chain::genesis_block(net)));
        let _e = established_peer(&n, 7);
        assert!(
            !n.handle(7, Message::Channel(vec![0u8; 40])),
            "a channel message off regtest must cut the link"
        );
        assert_eq!(
            n.shared.lock().unwrap().peers[&7].ban_score,
            MISCONDUCT_MALFORMED
        );
    }

    /// Finding 14: with no channel manager installed, the scan run after
    /// every message handled does not take the global lock.
    #[test]
    fn the_channel_scan_takes_no_lock_without_a_channel_manager() {
        let (a, _) = node_pair();
        let held = a.shared.lock().unwrap();
        let other = a.clone();
        let (done, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            other.scan_connected_blocks_for_channels();
            let _ = done.send(());
        });
        let returned = rx.recv_timeout(Duration::from_secs(2)).is_ok();
        drop(held);
        assert!(returned, "the scan waited for the global lock");
    }

    /// A block connected through the node reaches the channel watcher, off the
    /// chain lock — the hook that lets it punish a revoked broadcast.
    #[test]
    fn a_connected_block_reaches_the_channel_watcher() {
        let (a, b) = node_pair();
        let rec = Arc::new(BlockRecorder {
            blocks: AtomicU64::new(0),
            txs: AtomicU64::new(0),
        });
        b.set_channel_sink(rec.clone());
        let _e = established_peer(&b, 7);
        let block = next_block(&a);
        assert!(b.handle(7, Message::Block(Box::new(block))));
        assert_eq!(b.height(), 1, "the block was connected");
        assert!(
            rec.blocks.load(Ordering::SeqCst) >= 1,
            "the watcher must see the connected block"
        );
        assert!(
            rec.txs.load(Ordering::SeqCst) >= 1,
            "the coinbase transaction must reach it"
        );
    }

    fn memo(n: &Node) -> std::sync::Arc<crate::pow::WorkMemo> {
        n.with_chain(|c| c.work_memo())
    }

    /// Fills a peer's pipe to the brim: its queue full and the kernel buffers
    /// behind it saturated, as with a Tor circuit that stopped moving.
    fn clog(n: &Node, id: u64) {
        let w = n.shared.lock().unwrap().peers[&id].writer.clone();
        let big: Arc<[u8]> = vec![0u8; 256 * 1024].into();
        loop {
            while w.push(big.clone()) == Push::Queued {}
            std::thread::sleep(Duration::from_millis(200));
            if w.push(big.clone()) == Push::Full {
                return;
            }
        }
    }

    /// The defect of the endurance test, end to end.
    ///
    /// Three established peers have stopped reading. Up to v0.4.8, announcing
    /// a block wrote to each of them in turn and waited `WRITE_TIMEOUT` on
    /// each — a minute and a half — before the healthy peer heard of it; and
    /// dropping one of them waited for its write while holding the node's
    /// lock. Now the announcement returns at once, the healthy peer fetches
    /// the block within seconds, and the node answers throughout.
    #[test]
    fn stalled_peers_delay_neither_propagation_nor_the_node() {
        let (a, b) = node_pair();
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connection");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5)
            && !(a.peer_count_established() == 1 && b.peer_count_established() == 1)
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _stalled: Vec<TcpListener> = (900..903u64).map(|id| established_peer(&a, id)).collect();
        for id in 900..903u64 {
            clog(&a, id);
        }

        let block = next_block(&a);
        a.with_chain(|c| c.connect(&block, block.header.time + 1).expect("local"));
        let t = Instant::now();
        a.announce_block(&block);
        a.announce_tx(Hash256([5u8; 32]));
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "announcing waited {:?}",
            t.elapsed()
        );

        // The node keeps answering — what the wallet and the RPC server see.
        let t = Instant::now();
        let _ = a.height();
        assert!(t.elapsed() < Duration::from_millis(200));

        let t = Instant::now();
        while b.height() < 1 && t.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(b.height(), 1, "the healthy peer must get the block");
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "propagation took {:?}",
            t.elapsed()
        );

        // Dropping a stalled peer does not wait for its write.
        let t = Instant::now();
        a.disconnect(900);
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "disconnect waited {:?}",
            t.elapsed()
        );
        assert!(a.stats.outbox_dropped.load(Ordering::Relaxed) > 0);
    }

    /// A relay that answers our own `getdata` beyond its budget is not
    /// flooding: the transactions we asked for cost it nothing. An
    /// unsolicited one beyond the budget still does.
    #[test]
    fn requested_transactions_are_never_misconduct() {
        let (_a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let tx = |n: u8| Transaction {
            version: 1,
            inputs: vec![crate::tx::TxIn::coinbase(vec![n])],
            outputs: Vec::new(),
            lock_time: 0,
        };
        let asked = tx(1);
        assert!(b.handle(
            7,
            Message::Inv(vec![InvItem {
                kind: InvKind::Tx,
                hash: asked.txid(),
            }])
        ));
        let drain = |b: &Node| {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            p.tx_bucket = TokenBucket {
                tokens: 0,
                last: Instant::now(),
            };
        };
        let score = |b: &Node| b.shared.lock().unwrap().peers[&7].ban_score;
        drain(&b);
        assert!(b.handle(7, Message::Tx(Box::new(asked.clone()))));
        assert_eq!(score(&b), 0, "a requested transaction is no misconduct");
        assert_eq!(b.stats.solicited_over_budget.load(Ordering::Relaxed), 1);
        // And it was examined, not dropped: its parent being unknown here, it
        // waits among the orphans.
        assert_eq!(b.shared.lock().unwrap().orphans.len(), 1);
        // Sent again, it was not asked for any more.
        drain(&b);
        assert!(b.handle(7, Message::Tx(Box::new(asked))));
        assert_eq!(score(&b), MISCONDUCT_MALFORMED);
        drain(&b);
        assert!(b.handle(7, Message::Tx(Box::new(tx(2)))));
        assert_eq!(
            score(&b),
            2 * MISCONDUCT_MALFORMED,
            "unsolicited still pays"
        );
    }

    /// A peer behind by a whole pool reconciles all of it, not a prefix.
    ///
    /// The lab of 19 October: a node that connected to a peer holding more
    /// than a thousand transactions received about a hundred and forty, then
    /// nothing. The offer now covers the whole pool, and the receiver pulls
    /// it in within its budget.
    #[test]
    fn a_peer_reconciles_the_whole_pool_not_a_prefix() {
        let (a, b) = node_pair();
        // Fill A's pool with many transactions on one chain.
        let mut w = crate::wallet::Wallet::from_seed([0x71; 32], NETWORK);
        let _ = w.new_address();
        a.with_chain(|c| {
            for _ in 1..=crate::consensus::COINBASE_MATURITY + 200 {
                let addr = w.new_address();
                let t = c.tip().time + TARGET_BLOCK_SECS;
                let blk = c
                    .mine_block(addr.hash, SchemeId::LamportOts, &[], t, 5_000_000)
                    .expect("mine");
                c.connect(&blk, blk.header.time + 1).expect("connect");
            }
        });
        let mut dest = crate::wallet::Wallet::from_seed([0x72; 32], NETWORK);
        let to = dest.new_address();
        let n = 120;
        a.with_chain_and_mempool(|c, m| {
            for _ in 0..n {
                let tx = w
                    .create_transaction(
                        &c.utxo,
                        c.height(),
                        &to,
                        crate::amount::Amount::from_units(100_000),
                        crate::amount::Amount::from_units(2_000),
                    )
                    .expect("build");
                m.accept(&tx, &c.utxo, NETWORK, c.height()).expect("accept");
            }
        });
        let pool = a.with_mempool(|m| m.len());
        assert!(pool >= n, "pool has {pool}");
        // B must reach A's height first, so the transactions' inputs resolve.
        let addr = a.listen("127.0.0.1:0").expect("listen");
        b.connect(addr).expect("connect");
        let synced = Instant::now() + Duration::from_secs(60);
        while Instant::now() < synced
            && !(b.height() == a.height() && b.peer_count_established() == 1)
        {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(b.height(), a.height(), "B did not sync the chain");
        // Drive both maintenance loops: A re-offers its whole pool, B pulls it.
        let deadline = Instant::now() + Duration::from_secs(60);
        a.announce_mempool();
        while Instant::now() < deadline {
            b.maintain_peers();
            a.maintain_peers();
            if b.with_mempool(|m| m.len()) >= pool {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let got = b.with_mempool(|m| m.len());
        assert_eq!(got, pool, "B reconciled {got} of {pool}");
        a.shutdown();
        b.shutdown();
    }

    /// What waited for a peer's budget is requested as soon as it refills,
    /// not at the next offer of its pool.
    #[test]
    fn waiting_announcements_are_requested_when_the_budget_refills() {
        let (_a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let items: Vec<InvItem> = (0..600u32)
            .map(|n| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&n.to_le_bytes());
                h[31] = 1;
                InvItem {
                    kind: InvKind::Tx,
                    hash: Hash256(h),
                }
            })
            .collect();
        assert!(b.handle(7, Message::Inv(items)));
        let waiting = |b: &Node| b.shared.lock().unwrap().peers[&7].announced_waiting.len();
        assert_eq!(waiting(&b), 600 - TX_BUCKET_MAX as usize);
        // Nothing more can be asked while the first requests are outstanding.
        let now = Instant::now();
        assert!(Node::request_waiting_txs(&mut b.shared.lock().unwrap(), 7, now).is_none());
        // A minute later the unanswered requests are forgotten and the budget
        // has refilled: the waiting ones are asked for.
        {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            let past = now
                .checked_sub(TX_REQUEST_MEMORY + Duration::from_secs(1))
                .unwrap();
            for at in p.requested_txs.values_mut() {
                *at = past;
            }
        }
        let later = now + Duration::from_secs(40);
        match Node::request_waiting_txs(&mut b.shared.lock().unwrap(), 7, later) {
            Some(Message::GetData(v)) => assert_eq!(v.len(), 600 - TX_BUCKET_MAX as usize),
            other => panic!("expected a request, got {other:?}"),
        }
        assert_eq!(waiting(&b), 0);
    }

    /// What a peer announces is requested only within its budget: the
    /// exemption for requested transactions cannot become free work.
    #[test]
    fn transaction_requests_stay_within_the_peer_s_budget() {
        let (_a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let items: Vec<InvItem> = (0..600u32)
            .map(|n| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&n.to_le_bytes());
                InvItem {
                    kind: InvKind::Tx,
                    hash: Hash256(h),
                }
            })
            .collect();
        assert!(b.handle(7, Message::Inv(items.clone())));
        let asked = b.shared.lock().unwrap().peers[&7].requested_txs.len();
        assert_eq!(asked, TX_BUCKET_MAX as usize);
        assert_eq!(
            b.stats.tx_requests_deferred.load(Ordering::Relaxed),
            600 - TX_BUCKET_MAX
        );
        // Announced again at once: nothing more is asked while those wait.
        assert!(b.handle(7, Message::Inv(items)));
        assert_eq!(
            b.shared.lock().unwrap().peers[&7].requested_txs.len(),
            asked
        );
    }

    /// The work of a received block is checked before the lock, and the chain
    /// reads the verdict back instead of recomputing it under the lock.
    #[test]
    fn the_work_of_a_received_block_is_checked_outside_the_lock() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let block = next_block(&a);
        let m = memo(&b);
        assert!(b.handle(7, Message::Block(Box::new(block))));
        assert_eq!(b.height(), 1, "the valid block must be adopted");
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 1);
        assert_eq!(
            m.computed.load(Ordering::Relaxed),
            0,
            "no work hash must be computed under the lock"
        );
        assert!(m.hits.load(Ordering::Relaxed) >= 1);
    }

    /// A header with wrong work, announced as compact: the rejection comes from
    /// the verdict computed outside the lock, with no reconstruction and no
    /// computation under the lock.
    #[test]
    fn an_announcement_with_wrong_work_is_rejected_without_computing_under_the_lock() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let mut block = next_block(&a);
        let engine = crate::pow::Q21Pow::new(NETWORK);
        while engine.check(&block.header).is_ok() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        let c = CompactBlock::from_block(&block, 1);
        let m = memo(&b);
        let _ = b.handle(7, Message::CmpctBlock(Box::new(c)));
        assert_eq!(b.height(), 0);
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 1);
        assert_eq!(b.stats.compacts_header_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(b.stats.compacts_reconstructed.load(Ordering::Relaxed), 0);
        assert_eq!(m.computed.load(Ordering::Relaxed), 0);
    }

    /// The announcement budget comes before the work, outside the lock as
    /// inside it.
    #[test]
    fn an_over_budget_announcement_computes_nothing() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        b.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .cmpct_bucket = TokenBucket {
            tokens: 0,
            last: Instant::now(),
        };
        let c = CompactBlock::from_block(&next_block(&a), 1);
        let _ = b.handle(7, Message::CmpctBlock(Box::new(c)));
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 0);
        assert_eq!(b.stats.compacts_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(memo(&b).computed.load(Ordering::Relaxed), 0);
    }

    /// A header at a height that does not follow its parent computes nothing,
    /// even outside the lock: the height chooses the epoch, and an unknown
    /// epoch costs an entire cache.
    #[test]
    fn an_out_of_context_header_computes_nothing() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let mut block = next_block(&a);
        block.header.height = 1_000_000;
        let _ = b.handle(7, Message::Block(Box::new(block)));
        assert_eq!(b.stats.work_outside_lock.load(Ordering::Relaxed), 0);
        assert_eq!(memo(&b).computed.load(Ordering::Relaxed), 0);
        assert!(memo(&b).is_empty());
    }

    /// Bodies requested together, the second arriving before the first is
    /// connected - what a round trip for a missing transaction causes during
    /// every synchronization. The second waits and follows its parent; in
    /// 0.4.1 it was dropped, and the sync stood still until the deadline.
    #[test]
    fn a_requested_compact_waits_for_its_parent() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        crate::net::tests_util::mine_locally(&a, 2);
        let (b1, b2) = a.with_chain(|c| (c.block_at(1).unwrap(), c.block_at(2).unwrap()));
        {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            p.requested_bodies
                .insert(b1.header.block_id(), Instant::now());
            p.requested_bodies
                .insert(b2.header.block_id(), Instant::now());
        }
        let _ = b.handle(
            7,
            Message::CmpctBlock(Box::new(CompactBlock::from_block(&b2, 1))),
        );
        assert_eq!(b.height(), 0);
        assert_eq!(b.stats.compacts_parked.load(Ordering::Relaxed), 1);
        assert!(b.handle(7, Message::Block(Box::new(b1))));
        assert_eq!(b.height(), 2, "the waiting block must follow its parent");
        assert_eq!(b.stats.compacts_resumed.load(Ordering::Relaxed), 1);
        let g = b.shared.lock().unwrap();
        assert!(g.parked.is_empty());
        assert_eq!(g.peers[&7].ban_score, 0, "an honest peer is not punished");
    }

    /// A whole batch arriving in reverse order unrolls as soon as its first
    /// block arrives: each connected block resumes the one waiting for it.
    /// The resumption is a recursion (`resume_parked`, `accept_compact`,
    /// `integrate`, `resume_parked`), bounded by `MAX_PARKED`; this test pins
    /// that it reaches the end of a long chain.
    #[test]
    fn a_reversed_batch_unrolls_from_its_first_block() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let n = 12;
        crate::net::tests_util::mine_locally(&a, n);
        let blocks: Vec<Block> =
            a.with_chain(|c| (1..=n as u64).map(|h| c.block_at(h).unwrap()).collect());
        {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            for blk in &blocks {
                p.requested_bodies
                    .insert(blk.header.block_id(), Instant::now());
            }
        }
        for blk in blocks[1..].iter().rev() {
            let _ = b.handle(
                7,
                Message::CmpctBlock(Box::new(CompactBlock::from_block(blk, 1))),
            );
        }
        assert_eq!(b.height(), 0);
        assert_eq!(
            b.stats.compacts_parked.load(Ordering::Relaxed),
            (n - 1) as u64
        );
        assert!(b.handle(7, Message::Block(Box::new(blocks[0].clone()))));
        assert_eq!(
            b.height(),
            n as u64,
            "the whole batch must follow its first block"
        );
        assert_eq!(
            b.stats.compacts_resumed.load(Ordering::Relaxed),
            (n - 1) as u64
        );
        assert!(b.shared.lock().unwrap().parked.is_empty());
    }

    /// The places are bounded: beyond `MAX_PARKED`, the oldest gives way.
    #[test]
    fn parked_compacts_are_bounded() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        let n = MAX_PARKED + 5;
        crate::net::tests_util::mine_locally(&a, n + 1);
        let blocks: Vec<Block> = a.with_chain(|c| {
            (2..=(n as u64 + 1))
                .map(|h| c.block_at(h).unwrap())
                .collect()
        });
        {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            for blk in &blocks {
                p.requested_bodies
                    .insert(blk.header.block_id(), Instant::now());
            }
        }
        for blk in &blocks {
            let _ = b.handle(
                7,
                Message::CmpctBlock(Box::new(CompactBlock::from_block(blk, 1))),
            );
        }
        assert_eq!(b.shared.lock().unwrap().parked.len(), MAX_PARKED);
    }

    /// An announcement nobody asked for, whose parent is unknown, does not
    /// wait: only requested bodies may take a place, and the places are
    /// bounded.
    #[test]
    fn an_unrequested_orphan_compact_does_not_wait() {
        let (a, b) = node_pair();
        let _e = established_peer(&b, 7);
        crate::net::tests_util::mine_locally(&a, 2);
        let b2 = a.with_chain(|c| c.block_at(2).unwrap());
        let _ = b.handle(
            7,
            Message::CmpctBlock(Box::new(CompactBlock::from_block(&b2, 1))),
        );
        assert_eq!(b.stats.compacts_parked.load(Ordering::Relaxed), 0);
        assert!(b.shared.lock().unwrap().parked.is_empty());
    }

    /// Header requests go through a bucket: beyond it, nothing is served.
    #[test]
    fn header_requests_are_bounded_by_a_bucket() {
        let (a, _) = node_pair();
        crate::net::tests_util::mine_locally(&a, 3);
        let _e = established_peer(&a, 7);
        let request = || Message::GetHeaders {
            locator: vec![Hash256([0x55; 32])],
            stop: Hash256::ZERO,
        };
        let burst = HEADERS_BUCKET_MAX + 5;
        for _ in 0..burst {
            assert!(a.handle(7, request()), "an overrun does not disconnect");
        }
        assert_eq!(a.stats.headers_rejected.load(Ordering::Relaxed), 5);
        // The bucket refills over time: a request gets through again.
        std::thread::sleep(Duration::from_millis(1100));
        let _ = a.handle(7, request());
        assert_eq!(a.stats.headers_rejected.load(Ordering::Relaxed), 5);
    }

    /// A batch of headers nobody requested is not read, and costs points; the
    /// same batch, requested, is read.
    #[test]
    fn an_unrequested_header_batch_is_ignored() {
        let (a, b) = node_pair();
        crate::net::tests_util::mine_locally(&a, 3);
        let headers = a.with_chain(|c| c.headers_from(&[], Hash256::ZERO, 10));
        assert_eq!(headers.len(), 3);
        let _e = established_peer(&b, 7);

        let _ = b.handle(7, Message::Headers(headers.clone()));
        {
            let g = b.shared.lock().unwrap();
            let p = &g.peers[&7];
            assert!(p.bodies_to_request.is_empty() && p.requested_bodies.is_empty());
            assert_eq!(p.ban_score, MISCONDUCT_UNREQUESTED_HEADERS);
        }
        assert_eq!(b.stats.unrequested_headers.load(Ordering::Relaxed), 1);

        // A request sent opens a slot: the reply is read.
        b.send_to(
            7,
            &Message::GetHeaders {
                locator: vec![],
                stop: Hash256::ZERO,
            },
        );
        let _ = b.handle(7, Message::Headers(headers));
        let g = b.shared.lock().unwrap();
        let p = &g.peers[&7];
        assert_eq!(p.expected_headers, 0, "the reply consumes its slot");
        assert_eq!(
            p.requested_bodies.len() + p.bodies_to_request.len(),
            3,
            "the three bodies must be requested or queued"
        );
    }

    /// Reply slots do not accumulate beyond the bound.
    #[test]
    fn reply_slots_are_bounded() {
        let (a, _) = node_pair();
        let _e = established_peer(&a, 7);
        for _ in 0..50 {
            a.send_to(
                7,
                &Message::GetHeaders {
                    locator: vec![],
                    stop: Hash256::ZERO,
                },
            );
        }
        assert_eq!(
            a.shared.lock().unwrap().peers[&7].expected_headers,
            MAX_EXPECTED_HEADERS
        );
    }

    /// An `inv` received before the handshake is not read: nothing is requested
    /// or recorded in flight on behalf of an anonymous connection.
    #[test]
    fn an_inv_before_the_handshake_is_not_read() {
        let a = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let _e = established_peer(&a, 7);
        a.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .handshaked = false;
        let announcement: Vec<InvItem> = (0..100u8)
            .map(|k| InvItem {
                kind: InvKind::Block,
                hash: Hash256([k; 32]),
            })
            .collect();
        let _ = a.handle(7, Message::Inv(announcement.clone()));
        {
            let g = a.shared.lock().unwrap();
            let p = &g.peers[&7];
            assert!(p.requested_bodies.is_empty() && p.bodies_to_request.is_empty());
        }
        // Once established, the same `inv` is read, within the limit of the
        // in-flight slots.
        a.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .handshaked = true;
        let _ = a.handle(7, Message::Inv(announcement));
        let g = a.shared.lock().unwrap();
        assert_eq!(g.peers[&7].requested_bodies.len(), MAX_BODIES_IN_FLIGHT);
    }

    /// Received addresses go through a bucket: a full reply gets through, a
    /// burst beyond it is ignored without disconnecting.
    #[test]
    fn received_addresses_are_bounded_by_a_bucket() {
        let a = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let _e = established_peer(&a, 7);
        // A thousand routable addresses from distinct groups.
        let batch = |base: u8| -> Vec<crate::wire::NetAddr> {
            (0..crate::wire::MAX_ADDR)
                .map(|k| crate::wire::NetAddr {
                    ip: [base, (k / 250) as u8 + 1, (k % 250) as u8 + 1, 7],
                    port: 21121,
                    last_seen: 1,
                })
                .collect()
        };
        assert!(a.handle(7, Message::Addr(batch(11))));
        let after_one = a.address_count();
        assert!(after_one > 0);
        assert_eq!(a.stats.addresses_ignored.load(Ordering::Relaxed), 0);
        // The bucket is empty: the next batch records nothing, and does not
        // disconnect.
        assert!(a.handle(7, Message::Addr(batch(12))));
        assert_eq!(a.stats.addresses_ignored.load(Ordering::Relaxed), 1);
        assert_eq!(a.address_count(), after_one);
    }

    /// A misbehavior score never overflows: `overflow-checks` is on in
    /// production, and an overflow there would stop the node.
    #[test]
    fn the_misbehavior_score_saturates() {
        let a = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let _e = established_peer(&a, 7);
        a.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .ban_score = u32::MAX - 1;
        assert!(!a.penalize(7, MISCONDUCT_BAD_BLOCK));
        assert_eq!(a.shared.lock().unwrap().peers[&7].ban_score, u32::MAX);
    }

    /// A body overdue on a saturated link is not misconduct as long as the
    /// peer keeps answering our other requests: it is re-requested from
    /// another peer, and the slow one is left alone.
    ///
    /// Banning such a peer — a 2 MB body queued behind the transactions we
    /// also asked for — split the network into halves that then ignored each
    /// other until the stale-tip timer.
    #[test]
    fn a_late_body_on_a_busy_link_is_not_misconduct() {
        let (_a, b) = node_pair();
        let _slow = established_peer(&b, 7); // answering, just slow on one body
        let _other = established_peer(&b, 8); // able to serve the body instead
        let overdue = Hash256([3u8; 32]);
        {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            p.requested_bodies.insert(
                overdue,
                Instant::now() - BODY_TIMEOUT - Duration::from_secs(1),
            );
            // It delivered something we asked for a moment ago.
            p.last_delivered = Instant::now();
        }
        b.maintain_peers();
        let g = b.shared.lock().unwrap();
        assert!(
            g.peers.contains_key(&7),
            "an honest but slow peer must not be dropped"
        );
        assert_eq!(
            g.peers[&7].ban_score, 0,
            "a peer that is answering keeps a clean score"
        );
        assert!(
            !g.peers[&7].requested_bodies.contains_key(&overdue),
            "the overdue body left its in-flight set, to be asked elsewhere"
        );
    }

    /// Finding 12: a peer that answers every transaction we ask for but never
    /// a block body is charged with withholding after a few rounds. Before,
    /// each answered transaction counted as a delivery, and the peer delayed
    /// every block by `BODY_TIMEOUT` for as long as it liked.
    #[test]
    fn a_peer_that_serves_transactions_but_no_body_is_charged() {
        let (_a, b) = node_pair();
        let _w = established_peer(&b, 7);
        let _other = established_peer(&b, 8);
        for round in 0..MAX_BODY_OVERDUE_ROUNDS {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            p.requested_bodies.insert(
                Hash256([10 + round; 32]),
                Instant::now() - BODY_TIMEOUT - Duration::from_secs(1),
            );
            // It answered a transaction request a moment ago.
            p.last_delivered = Instant::now();
            drop(g);
            b.maintain_peers();
        }
        assert_eq!(
            b.shared.lock().unwrap().peers[&7].ban_score,
            MISCONDUCT_BODY_WITHHELD,
            "a peer that never delivers a body is charged, transactions or not"
        );
    }

    /// What finding 12 must not undo (the L1-B partition): a peer whose bodies
    /// arrive late, on a saturated link, is never charged — each late body
    /// shows it delivers.
    #[test]
    fn a_peer_whose_bodies_arrive_late_is_never_charged() {
        let (a, b) = node_pair();
        let _slow = established_peer(&b, 7);
        let _other = established_peer(&b, 8);
        let rounds = 2 * MAX_BODY_OVERDUE_ROUNDS as u64;
        crate::net::tests_util::mine_locally(&a, rounds as usize);
        for h in 1..=rounds {
            let body = a.with_chain(|c| c.block_at(h).unwrap());
            {
                let mut g = b.shared.lock().unwrap();
                let p = g.peers.get_mut(&7).unwrap();
                p.requested_bodies.insert(
                    body.header.block_id(),
                    Instant::now() - BODY_TIMEOUT - Duration::from_secs(1),
                );
                p.last_delivered = Instant::now();
            }
            b.maintain_peers();
            // The overdue body arrives after all, late.
            assert!(b.handle(7, Message::Block(Box::new(body))));
        }
        assert_eq!(
            b.shared.lock().unwrap().peers[&7].ban_score,
            0,
            "a peer that delivers its bodies late is not a withholder"
        );
    }

    /// A peer that delivered nothing we asked for within the window is charged
    /// with withholding — a genuine withholder is still removed.
    #[test]
    fn a_peer_that_answers_nothing_is_charged_with_withholding() {
        let (_a, b) = node_pair();
        let _slow = established_peer(&b, 7);
        let _other = established_peer(&b, 8);
        let old = Instant::now() - BODY_TIMEOUT - Duration::from_secs(5);
        {
            let mut g = b.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).unwrap();
            p.requested_bodies.insert(Hash256([3u8; 32]), old);
            p.last_delivered = old; // nothing delivered within the window
        }
        b.maintain_peers();
        assert_eq!(
            b.shared.lock().unwrap().peers[&7].ban_score,
            MISCONDUCT_BODY_WITHHELD,
            "a peer that answers nothing is charged with withholding"
        );
    }

    /// Only what we asked for marks a peer as answering: an unrequested
    /// transaction does not, a requested one does.
    #[test]
    fn only_what_we_asked_for_marks_a_peer_as_answering() {
        let (_a, b) = node_pair();
        let _s = established_peer(&b, 7);
        let tx = Transaction {
            version: 1,
            inputs: vec![crate::tx::TxIn::coinbase(vec![9])],
            outputs: Vec::new(),
            lock_time: 0,
        };
        let old = Instant::now() - Duration::from_secs(120);
        b.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .last_delivered = old;
        // A transaction we never asked for.
        let _ = b.handle(7, Message::Tx(Box::new(tx.clone())));
        assert_eq!(
            b.shared.lock().unwrap().peers[&7].last_delivered,
            old,
            "a transaction we never requested is no sign the peer is answering"
        );
        // The same transaction, now requested.
        b.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .requested_txs
            .insert(tx.txid(), Instant::now());
        let _ = b.handle(7, Message::Tx(Box::new(tx)));
        assert!(
            b.shared.lock().unwrap().peers[&7].last_delivered > old,
            "a transaction we requested marks the peer as answering"
        );
    }

    /// A requested block whose parent we do not know makes us ask that peer
    /// for headers (one outstanding), so a split branch is discovered instead
    /// of being parked and forgotten.
    #[test]
    fn an_announcement_on_an_unknown_branch_triggers_a_headers_request() {
        let (a, b) = node_pair();
        let _s = established_peer(&b, 7);
        crate::net::tests_util::mine_locally(&a, 2);
        let b2 = a.with_chain(|c| c.block_at(2).unwrap());
        b.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&7)
            .unwrap()
            .requested_bodies
            .insert(b2.header.block_id(), Instant::now());
        let _ = b.handle(
            7,
            Message::CmpctBlock(Box::new(CompactBlock::from_block(&b2, 1))),
        );
        let g = b.shared.lock().unwrap();
        assert_eq!(
            g.peers[&7].expected_headers, 1,
            "an unknown-parent block makes us ask the peer for headers"
        );
        assert_eq!(b.stats.compacts_parked.load(Ordering::Relaxed), 1);
    }

    /// Two halves that diverged while split converge on one tip once
    /// reconnected: the announcement of an unknown-branch tip drives a headers
    /// request, which drives the normal sync, which fetches and connects the
    /// missing blocks and reorganizes onto the heavier branch.
    #[test]
    fn two_partitioned_halves_converge_after_reconnecting() {
        let (a, b) = node_pair();
        // Each half mined its own branch, with a distinct miner so the branches
        // really differ; A's is heavier by one block.
        let mine_as = |n: &Node, count: usize, miner: u8| {
            for _ in 0..count {
                let blk = n
                    .with_chain(|c| {
                        let t = c.tip().time + TARGET_BLOCK_SECS;
                        c.mine_block(
                            Hash256([miner; 32]),
                            SchemeId::LamportOts,
                            &[],
                            t,
                            5_000_000,
                        )
                    })
                    .expect("mining");
                n.with_chain(|c| c.connect(&blk, blk.header.time + 1).expect("local"));
            }
        };
        mine_as(&a, 4, 0xAA);
        mine_as(&b, 3, 0xBB);
        assert_ne!(a.tip_id(), b.tip_id(), "the halves diverged");

        let _s = established_peer(&b, 7);
        let a_blocks: Vec<Block> =
            a.with_chain(|c| (1..=4).map(|h| c.block_at(h).unwrap()).collect());
        let a_tip = a_blocks[3].clone();

        // A announces its tip; B requests the body.
        let _ = b.handle(
            7,
            Message::Inv(vec![InvItem {
                kind: InvKind::CompactBlock,
                hash: a_tip.header.block_id(),
            }]),
        );
        // The body's parent is unknown: B parks it and asks A for headers.
        let _ = b.handle(
            7,
            Message::CmpctBlock(Box::new(CompactBlock::from_block(&a_tip, 1))),
        );
        assert_eq!(
            b.shared.lock().unwrap().peers[&7].expected_headers,
            1,
            "B asked A for headers on the unknown branch"
        );
        // A replies with its branch's headers, then serves the bodies.
        let headers: Vec<crate::block::BlockHeader> =
            a_blocks.iter().map(|blk| blk.header).collect();
        let _ = b.handle(7, Message::Headers(headers));
        for blk in &a_blocks {
            let _ = b.handle(7, Message::Block(Box::new(blk.clone())));
        }
        assert_eq!(b.height(), 4, "B followed the heavier branch");
        assert_eq!(
            b.tip_id(),
            a.tip_id(),
            "the two halves converged on one tip"
        );
    }
}

/// Handler fuzzing: `handle` fed structured, hostile messages, over several
/// interleaved peers, with the module's bounds checked after every step.
///
/// The decoder fuzzing (`tests/fuzz_decoders.rs`) stops at `parse`; here we
/// start from already-decoded messages, with fields chosen to land on the
/// edges: limits off by one, huge counts that the decoder still accepts,
/// headers with real work chained onto the tip, and from time to time a real
/// valid block so that the chain advances and honest progress gets tested
/// too.
///
/// Reproducible: `Q21_FUZZ_SEED` sets the starting seed, `Q21_FUZZ_SEEDS` the
/// number of seeds, `Q21_FUZZ_ITERATIONS` the number of messages per seed. On
/// failure, the seed and the step are printed.
#[cfg(test)]
mod tests_handler_fuzz {
    use super::*;
    use crate::amount::Amount;
    use crate::block::BlockHeader;
    use crate::chain::genesis_block;
    use crate::sig::SchemeId;
    use crate::tx::{OutPoint, TxIn, TxOut, Witness};
    use crate::wire::NetAddr;
    use std::collections::BTreeMap;
    use std::net::TcpListener;

    const NETWORK: Network = Network::Regtest;

    /// Generous threshold for a single `handle`: far beyond anything an honest
    /// message requires, it only serves to bring out a lock held abnormally
    /// long.
    const HANDLE_THRESHOLD: Duration = Duration::from_secs(2);

    /// splitmix64: dependency-free, reproducible.
    struct Prng(u64);

    impl Prng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        /// Integer in `[0, n)`, `n > 0`.
        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n.max(1)
        }
        fn one_in(&mut self, n: u64) -> bool {
            self.below(n) == 0
        }
        fn hash(&mut self) -> Hash256 {
            let mut o = [0u8; 32];
            for c in o.chunks_mut(8) {
                c.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            Hash256(o)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next_u64() as u8).collect()
        }
        /// Fewer than `bound` arbitrary bytes.
        fn bytes_up_to(&mut self, bound: u64) -> Vec<u8> {
            let n = self.below(bound) as usize;
            self.bytes(n)
        }
        /// A u64 value on the edges: zero, one, maximum, neighbors, or
        /// arbitrary.
        fn edge_u64(&mut self, around: u64) -> u64 {
            match self.below(8) {
                0 => 0,
                1 => 1,
                2 => u64::MAX,
                3 => u64::MAX - 1,
                4 => around.wrapping_sub(1),
                5 => around,
                6 => around.wrapping_add(1),
                _ => self.next_u64(),
            }
        }
        fn edge_u32(&mut self, around: u32) -> u32 {
            match self.below(7) {
                0 => 0,
                1 => u32::MAX,
                2 => u32::MAX - 1,
                3 => around.wrapping_sub(1),
                4 => around,
                5 => around.wrapping_add(1),
                _ => self.next_u64() as u32,
            }
        }
        /// A list size: empty, one, the bound, the bound minus one, or
        /// arbitrary below it.
        fn count(&mut self, max: usize) -> usize {
            match self.below(6) {
                0 => 0,
                1 => 1.min(max),
                2 if self.one_in(4) => max,
                3 if self.one_in(4) => max.saturating_sub(1),
                _ => self.below((max as u64).min(64) + 1) as usize,
            }
        }
    }

    /// Plugs in a fake peer. The other end of its socket is read and discarded
    /// by a thread: the node's replies go out without ever blocking, and the
    /// thread dies with the socket when the peer is disconnected.
    fn plug_in(n: &Node, id: u64, established: bool, outbound: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let (mut other, _) = listener.accept().expect("accept");
        std::thread::spawn(move || {
            let mut b = [0u8; 64 * 1024];
            while let Ok(k) = other.read(&mut b) {
                if k == 0 {
                    break;
                }
            }
        });
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let addr = stream.peer_addr().unwrap();
        let now = Instant::now();
        n.shared.lock().unwrap().peers.insert(
            id,
            Peer {
                addr,
                writer: Outbox::start(stream).unwrap(),
                outbound,
                snapshot_bucket: TokenBucket::new(now),
                tx_bucket: TokenBucket::for_transactions(now),
                cmpct_bucket: TokenBucket::for_compact_announcements(now),
                user_agent: String::new(),
                channels: false,
                channel_id: String::new(),
                chan_bucket: TokenBucket::for_channel_messages(now),
                headers_bucket: TokenBucket::for_header_requests(now),
                addr_bucket: TokenBucket::for_addresses(now),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: established,
                version_sent: established || outbound,
                handshaked: established,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                mempool_offered: false,
                version: 0,
                remote_nonce: None,
                last_received: now,
                last_delivered: now,
                body_overdue_rounds: 0,
                late_bodies: VecDeque::new(),
                pending_ping: None,
                requested_txs: HashMap::new(),
                announced_waiting: VecDeque::new(),
                connected_at: now,
            },
        );
    }

    /// Mines a header as is: the work is real, the content is whatever the
    /// caller chose. This is what gets a hostile message past the header
    /// checks and down to the deep paths.
    struct Miner {
        table: Option<Arc<crate::memhard::PowTable>>,
    }

    impl Miner {
        fn mine(&mut self, mut h: BlockHeader) -> Option<BlockHeader> {
            let epoch = crate::memhard::epoch_of(h.height);
            if self.table.as_ref().map(|t| t.epoch()) != Some(epoch) {
                self.table = Some(Arc::new(crate::memhard::PowTable::build(
                    crate::memhard::TableParams::for_network(NETWORK),
                    epoch,
                )));
            }
            let t = self.table.as_ref().unwrap();
            crate::pow::mine_with_table(&mut h, t, 5_000_000).ok()?;
            Some(h)
        }
    }

    /// What the fuzzer knows about the node's chain, to aim right.
    struct Known {
        active: Vec<Hash256>,
        coinbases: Vec<Hash256>,
        pending: Vec<Hash256>,
        /// Last genuinely valid block built and not yet delivered.
        next_valid: Option<Block>,
    }

    fn header_on(tip: &BlockHeader, tip_id: Hash256, a: &mut Prng) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: tip_id,
            merkle_root: a.hash(),
            uncles_root: Hash256::ZERO,
            miner: a.hash(),
            time: tip.time.wrapping_add(1),
            bits: crate::consensus::INITIAL_BITS,
            height: tip.height.wrapping_add(1),
            nonce: a.next_u64(),
        }
    }

    /// A hostile transaction: many inputs, huge witnesses, bad signatures,
    /// amounts on the edges, real or invented inputs.
    fn hostile_tx(a: &mut Prng, known: &Known) -> Transaction {
        let n_in = match a.below(5) {
            0 => 0,
            1 => 1,
            2 => a.below(600) as usize,
            _ => 1 + a.below(4) as usize,
        };
        let big_witness = a.one_in(20);
        let inputs = (0..n_in)
            .map(|_| {
                let prev_out = match a.below(4) {
                    0 if !known.coinbases.is_empty() => OutPoint {
                        txid: known.coinbases[a.below(known.coinbases.len() as u64) as usize],
                        index: a.edge_u32(0),
                    },
                    1 => OutPoint::COINBASE,
                    _ => OutPoint {
                        txid: a.hash(),
                        index: a.edge_u32(0),
                    },
                };
                let size = if big_witness {
                    a.below(64 * 1024) as usize
                } else {
                    a.below(96) as usize
                };
                TxIn {
                    prev_out,
                    witness: Witness {
                        pubkey: a.bytes(size / 2),
                        signature: a.bytes(size),
                    },
                    sequence: a.edge_u32(0),
                }
            })
            .collect();
        let n_out = match a.below(4) {
            0 => 0,
            1 => a.below(300) as usize,
            _ => 1 + a.below(3) as usize,
        };
        let outputs = (0..n_out)
            .map(|_| TxOut {
                value: Amount::from_units(a.edge_u64(crate::consensus::MIN_OUTPUT_VALUE)),
                scheme: if a.one_in(2) {
                    SchemeId::LamportOts
                } else {
                    SchemeId::MlDsa65
                },
                pubkey_hash: a.hash(),
            })
            .collect();
        Transaction {
            version: a.edge_u32(1),
            inputs,
            outputs,
            lock_time: a.edge_u64(0),
        }
    }

    fn targeted_hash(a: &mut Prng, known: &Known) -> Hash256 {
        match a.below(4) {
            0 if !known.active.is_empty() => {
                known.active[a.below(known.active.len() as u64) as usize]
            }
            1 if !known.pending.is_empty() => {
                known.pending[a.below(known.pending.len() as u64) as usize]
            }
            2 => Hash256::ZERO,
            _ => a.hash(),
        }
    }

    fn inv_kind(a: &mut Prng) -> InvKind {
        match a.below(3) {
            0 => InvKind::Tx,
            1 => InvKind::Block,
            _ => InvKind::CompactBlock,
        }
    }

    /// A message of variant `v`, with fields chosen to hit the edges. Also
    /// returns `true` if the message carries a genuinely valid block that
    /// extends the tip.
    fn message(
        v: u64,
        a: &mut Prng,
        n: &Node,
        known: &mut Known,
        miner: &mut Miner,
    ) -> (Message, bool) {
        let (tip, tip_id, height, local_nonce) = {
            let g = n.shared.lock().unwrap();
            (g.chain.tip(), g.chain.tip_id(), g.chain.height(), g.nonce)
        };
        let m = match v {
            0 => Message::Version {
                version: match a.below(4) {
                    0 => MIN_PROTOCOL_VERSION - 1,
                    1 => PROTOCOL_VERSION,
                    2 => u32::MAX,
                    _ => a.next_u64() as u32,
                },
                timestamp: a.edge_u64(unix_now()),
                nonce: if a.one_in(8) {
                    local_nonce
                } else {
                    a.edge_u64(local_nonce)
                },
                user_agent: String::from_utf8_lossy(&a.bytes_up_to(65)).into_owned(),
                start_height: a.edge_u64(height),
            },
            1 => Message::VerAck,
            2 => Message::Ping(a.next_u64()),
            3 => Message::Pong(a.next_u64()),
            4 => Message::GetHeaders {
                locator: (0..a.count(crate::wire::MAX_LOCATOR))
                    .map(|_| targeted_hash(a, known))
                    .collect(),
                stop: targeted_hash(a, known),
            },
            5 => {
                // A sequence of headers chained onto the tip or elsewhere, with
                // right or wrong height, difficulty and time.
                let k = a.count(crate::wire::MAX_HEADERS);
                let mut prev = tip;
                let mut prev_id = if a.one_in(6) { a.hash() } else { tip_id };
                let mut v = Vec::with_capacity(k);
                for _ in 0..k {
                    let mut h = header_on(&prev, prev_id, a);
                    match a.below(10) {
                        0 => h.height = a.edge_u64(prev.height),
                        1 => h.bits = a.edge_u32(crate::consensus::INITIAL_BITS),
                        2 => h.time = a.edge_u64(prev.time),
                        3 => h.prev_block = a.hash(),
                        _ => {}
                    }
                    prev = h;
                    prev_id = h.block_id();
                    v.push(h);
                }
                Message::Headers(v)
            }
            6 | 7 => {
                let k = if a.one_in(40) {
                    crate::wire::MAX_INV
                } else {
                    a.count(crate::wire::MAX_INV)
                };
                let items: Vec<InvItem> = (0..k)
                    .map(|_| InvItem {
                        kind: inv_kind(a),
                        hash: targeted_hash(a, known),
                    })
                    .collect();
                if v == 6 {
                    Message::Inv(items)
                } else {
                    Message::GetData(items)
                }
            }
            8 => {
                // A block: genuinely valid, mutated, or forged with real work
                // but a wrong body.
                match a.below(4) {
                    0 => {
                        // A block set aside is only worth anything if it still
                        // extends the tip.
                        let kept = known
                            .next_valid
                            .take()
                            .filter(|b| b.header.prev_block == tip_id);
                        let b = kept.unwrap_or_else(|| {
                            n.with_chain(|c| {
                                c.mine_block(
                                    a.hash(),
                                    SchemeId::LamportOts,
                                    &[],
                                    c.tip().time + 1,
                                    5_000_000,
                                )
                            })
                            .expect("regtest mining")
                        });
                        return (Message::Block(Box::new(b)), true);
                    }
                    1 => {
                        let mut b = n
                            .with_chain(|c| {
                                c.mine_block(
                                    a.hash(),
                                    SchemeId::LamportOts,
                                    &[],
                                    c.tip().time + 1,
                                    5_000_000,
                                )
                            })
                            .expect("regtest mining");
                        known.next_valid = Some(b.clone());
                        match a.below(5) {
                            0 => b.header.height = a.edge_u64(b.header.height),
                            1 => b.header.time = a.edge_u64(b.header.time),
                            2 => b.transactions.clear(),
                            3 => b.transactions.push(hostile_tx(a, known)),
                            _ => b.transactions[0].outputs[0].value = Amount::from_units(u64::MAX),
                        }
                        Message::Block(Box::new(b))
                    }
                    2 => {
                        // Real work, body inconsistent with the rules.
                        let mut b = n.with_chain(|c| {
                            c.mining_candidate(
                                a.hash(),
                                SchemeId::LamportOts,
                                &[],
                                c.tip().time + 1,
                            )
                        });
                        b.transactions.push(hostile_tx(a, known));
                        b.header.merkle_root = b.compute_merkle_root();
                        if let Some(h) = miner.mine(b.header) {
                            b.header = h;
                        }
                        Message::Block(Box::new(b))
                    }
                    _ => Message::Block(Box::new(Block {
                        header: header_on(&tip, tip_id, a),
                        transactions: (0..a.below(3)).map(|_| hostile_tx(a, known)).collect(),
                        uncles: Vec::new(),
                    })),
                }
            }
            9 => Message::Tx(Box::new(hostile_tx(a, known))),
            10 => {
                // Compact block: header with or without real work, random
                // short identifiers, absurd counts, missing coinbase.
                let header = match a.below(4) {
                    0 | 1 => miner
                        .mine(header_on(&tip, tip_id, a))
                        .unwrap_or_else(|| header_on(&tip, tip_id, a)),
                    2 => n.with_chain(|c| c.tip()),
                    _ => header_on(&tip, tip_id, a),
                };
                if a.one_in(6) {
                    // Consistent announcement: the root covers the coinbase
                    // and an invalid transaction, the work is real. The
                    // reconstruction succeeds, validation must refuse.
                    let mut b = n.with_chain(|c| {
                        c.mining_candidate(a.hash(), SchemeId::LamportOts, &[], c.tip().time + 1)
                    });
                    let t = hostile_tx(a, known);
                    b.transactions.push(t);
                    b.header.merkle_root = b.compute_merkle_root();
                    if let Some(h) = miner.mine(b.header) {
                        b.header = h;
                    }
                    let mut c = CompactBlock::from_block(&b, a.next_u64());
                    if a.one_in(2) {
                        // We hold back the transaction: it will have to be
                        // requested again.
                        known.pending.push(b.header.block_id());
                    } else {
                        c.prefilled.push((1, b.transactions[1].clone()));
                        c.short_ids.clear();
                    }
                    return (Message::CmpctBlock(Box::new(c)), false);
                }
                let n_ids = match a.below(5) {
                    0 => crate::compact::MAX_TX_PER_BLOCK,
                    1 => crate::compact::MAX_TX_PER_BLOCK - 1,
                    _ => a.below(40) as usize,
                };
                let mut prefilled = Vec::new();
                match a.below(4) {
                    0 => {}
                    1 => prefilled.push((a.edge_u32(0), hostile_tx(a, known))),
                    _ => {
                        prefilled.push((0, hostile_tx(a, known)));
                        for _ in 0..a.below(4) {
                            prefilled.push((a.edge_u32(n_ids as u32), hostile_tx(a, known)));
                        }
                    }
                }
                let c = CompactBlock {
                    header,
                    nonce: a.next_u64(),
                    short_ids: (0..n_ids)
                        .map(|_| a.next_u64() & 0x0000_ffff_ffff_ffff)
                        .collect(),
                    prefilled,
                    uncles: (0..a.count(64))
                        .map(|_| header_on(&tip, tip_id, a))
                        .collect(),
                };
                known.pending.push(c.header.block_id());
                if known.pending.len() > 64 {
                    known.pending.remove(0);
                }
                Message::CmpctBlock(Box::new(c))
            }
            11 => Message::GetBlockTxn {
                block: targeted_hash(a, known),
                indices: (0..if a.one_in(30) {
                    crate::wire::MAX_BLOCK_TXN
                } else {
                    a.count(crate::wire::MAX_BLOCK_TXN)
                })
                    .map(|_| a.edge_u32(0))
                    .collect(),
            },
            12 => Message::BlockTxn {
                block: targeted_hash(a, known),
                txs: (0..a.below(4)).map(|_| hostile_tx(a, known)).collect(),
            },
            13 => Message::GetAddr,
            14 => {
                let k = if a.one_in(4) {
                    crate::wire::MAX_ADDR
                } else {
                    a.count(crate::wire::MAX_ADDR)
                };
                Message::Addr(
                    (0..k)
                        .map(|_| NetAddr {
                            ip: match a.below(6) {
                                0 => [127, 0, 0, 1],
                                1 => [10, a.next_u64() as u8, 0, 1],
                                2 => [192, 168, 1, a.next_u64() as u8],
                                3 => [255, 255, 255, 255],
                                _ => {
                                    let b = a.next_u64().to_le_bytes();
                                    [b[0], b[1], b[2], b[3]]
                                }
                            },
                            port: if a.one_in(8) { 0 } else { a.next_u64() as u16 },
                            last_seen: a.edge_u64(unix_now()),
                        })
                        .collect(),
                )
            }
            15 => Message::Reject {
                command: String::from_utf8_lossy(&a.bytes_up_to(65)).into_owned(),
                reason: String::from_utf8_lossy(&a.bytes_up_to(257)).into_owned(),
            },
            16 => Message::GetSnapshot,
            17 => Message::SnapshotInfo {
                height: a.edge_u64(height),
                tip: a.hash(),
                commitment: a.hash(),
                size: a.edge_u64(0),
                chunks: a.edge_u32(0),
            },
            18 => Message::GetSnapshotChunk {
                index: a.edge_u32(0),
            },
            _ => Message::SnapshotChunk {
                index: a.edge_u32(0),
                data: a.bytes_up_to(4096),
            },
        };
        (m, false)
    }

    const VARIANTS: u64 = 20;

    /// The module's bounds, checked after every step.
    fn check_invariants(n: &Node, context: &str, check_book: bool) {
        assert!(!n.shared.is_poisoned(), "{context}: lock poisoned");
        let g = n.shared.lock().unwrap();
        for (id, p) in &g.peers {
            assert!(
                p.pending.len() <= MAX_PENDING_RECONSTRUCTIONS,
                "{context}: peer {id}, {} pending reconstructions",
                p.pending.len()
            );
            assert!(
                p.requested_bodies.len() <= MAX_BODIES_IN_FLIGHT,
                "{context}: peer {id}, {} bodies in flight",
                p.requested_bodies.len()
            );
            assert!(
                p.bodies_to_request.len() <= MAX_PENDING_BODIES,
                "{context}: peer {id}, {} bodies queued",
                p.bodies_to_request.len()
            );
            assert!(
                p.expected_headers <= MAX_EXPECTED_HEADERS,
                "{context}: peer {id}, {} expected header replies",
                p.expected_headers
            );
            assert!(
                p.snapshot_bucket.tokens <= SNAPSHOT_BUCKET_MAX,
                "{context}: snapshot bucket"
            );
            assert!(
                p.tx_bucket.tokens <= TX_BUCKET_MAX,
                "{context}: transaction bucket"
            );
            assert!(
                p.cmpct_bucket.tokens <= CMPCT_BUCKET_MAX,
                "{context}: compact bucket"
            );
            assert!(
                p.headers_bucket.tokens <= HEADERS_BUCKET_MAX,
                "{context}: header bucket"
            );
            assert!(
                p.addr_bucket.tokens <= ADDR_BUCKET_MAX,
                "{context}: address bucket"
            );
            assert!(
                !p.handshaked || p.version_received,
                "{context}: peer {id} established without `Version`"
            );
        }
        assert!(
            g.mempool.bytes() <= crate::mempool::MEMPOOL_MAX_BYTES,
            "{context}: mempool beyond its cap"
        );
        assert!(
            g.book.groups() <= crate::addr::MAX_GROUPS,
            "{context}: {} groups in the address book",
            g.book.groups()
        );
        if check_book {
            let all = g.book.all();
            assert!(
                all.len() <= crate::addr::MAX_GROUPS * crate::addr::MAX_PER_GROUP,
                "{context}: {} addresses in the address book",
                all.len()
            );
            let limit = unix_now() + crate::addr::FUTURE_TOLERANCE;
            for e in all {
                assert!(e.addr.port != 0, "{context}: zero port in the address book");
                assert!(
                    crate::addr::routable(e.addr.ip, true),
                    "{context}: non-routable address in the address book"
                );
                assert!(
                    e.addr.last_seen <= limit,
                    "{context}: address seen in the future"
                );
            }
        }
    }

    /// Necessary conditions for an adopted block, checked without going
    /// through the chain: parent, recomputed work, shape, coinbase within the
    /// subsidy.
    fn independently_valid(b: &Block, parent: Hash256, context: &str) {
        use crate::pow::PowEngine;
        assert_eq!(
            b.header.prev_block, parent,
            "{context}: wrong parent adopted"
        );
        assert!(
            crate::pow::Q21Pow::new(NETWORK).check(&b.header).is_ok(),
            "{context}: block without work adopted"
        );
        assert!(
            b.check_shape().is_ok(),
            "{context}: malformed block adopted"
        );
        assert_eq!(
            b.transactions.len(),
            1,
            "{context}: invented transaction adopted"
        );
        let paid = b.transactions[0].total_output().expect("sum").units();
        assert!(
            paid <= crate::emission::block_subsidy(b.header.height).units(),
            "{context}: coinbase beyond the subsidy"
        );
    }

    /// What a seed observed, for the report.
    #[derive(Default)]
    struct Tally {
        messages: BTreeMap<&'static str, (u64, Duration)>,
        valid_blocks: u64,
        drops: u64,
        /// Generated messages larger than a frame, hence discarded.
        oversized: u64,
    }

    /// Prints the seed and the step if a step panics, whatever it is.
    struct FailureReporter {
        seed: u64,
        step: u64,
        command: &'static str,
    }

    impl Drop for FailureReporter {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "FUZZ FAILURE: seed {:#x}, step {}, message `{}`. \
                     Replay with Q21_FUZZ_SEED={:#x} Q21_FUZZ_SEEDS=1",
                    self.seed, self.step, self.command, self.seed
                );
            }
        }
    }

    fn env_u64(name: &str) -> Option<u64> {
        let v = std::env::var(name).ok()?;
        let v = v.trim();
        match v.strip_prefix("0x") {
            Some(h) => u64::from_str_radix(h, 16).ok(),
            None => v.parse().ok(),
        }
    }

    /// One seed: `iterations` messages spread over several peers, then the
    /// proof that the node still synchronizes an honest peer.
    fn campaign(seed: u64, iterations: u64, tally: &mut Tally) {
        let n = Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)));
        let mut a = Prng(seed);
        let mut miner = Miner { table: None };
        let mut known = Known {
            active: vec![n.tip_id()],
            coinbases: Vec::new(),
            pending: Vec::new(),
            next_valid: None,
        };
        // Four established peers, two that are not, in each direction.
        let mut ids: Vec<u64> = Vec::new();
        let mut next_id = 1u64;
        for i in 0..6u64 {
            plug_in(&n, next_id, i < 4, i % 2 == 0);
            ids.push(next_id);
            next_id += 1;
        }
        let mut reporter = FailureReporter {
            seed,
            step: 0,
            command: "",
        };

        for step in 0..iterations {
            reporter.step = step;
            let slot = a.below(ids.len() as u64) as usize;
            let id = ids[slot];
            // Handshake messages and the most common ones come back more
            // often: they open the paths of the others.
            let v = if a.one_in(5) {
                a.below(2)
            } else {
                a.below(VARIANTS)
            };
            reporter.command = "(generation)";
            let (m, valid) = message(v, &mut a, &n, &mut known, &mut miner);
            // What the decoder would refuse never reaches `handle`.
            if m.frame(n.magic).len() > HEADER_LEN + MAX_PAYLOAD {
                tally.oversized += 1;
                continue;
            }
            let cmd = m.command();
            reporter.command = cmd;
            let (before, established) = {
                let g = n.shared.lock().unwrap();
                (
                    g.chain.tip_id(),
                    g.peers.get(&id).map(|p| p.handshaked).unwrap_or(false),
                )
            };
            let block = match &m {
                Message::Block(b) => Some(b.header),
                _ => None,
            };

            let start = Instant::now();
            let keep = n.handle(id, m);
            let elapsed = start.elapsed();

            let e = tally.messages.entry(cmd).or_default();
            e.0 += 1;
            e.1 = e.1.max(elapsed);
            let context = format!("seed {seed:#x}, step {step}, `{cmd}`");
            assert!(
                elapsed < HANDLE_THRESHOLD,
                "{context}: handle took {elapsed:?}"
            );
            check_invariants(&n, &context, step % 64 == 0);
            if keep {
                // A kept peer is below the threshold: otherwise a penalty was
                // counted without anyone disconnecting.
                let score = n.shared.lock().unwrap().peers.get(&id).map(|p| p.ban_score);
                assert!(
                    score.unwrap_or(0) < BAN_THRESHOLD,
                    "{context}: peer {id} kept with a score of {score:?}"
                );
            }

            // The chain only advances on a genuinely valid block, and such a
            // block coming from an established peer is always adopted.
            let after = n.tip_id();
            if valid && established {
                let h = block.expect("valid block");
                assert_eq!(after, h.block_id(), "{context}: valid block rejected");
                tally.valid_blocks += 1;
                known.active.push(after);
                let cb = n.with_chain(|c| c.block_by_id(&after).map(|b| b.transactions[0].txid()));
                known.coinbases.extend(cb);
            } else if valid {
                assert_eq!(after, before, "{context}: block adopted from a stranger");
            } else if after != before {
                // A mutation can leave a block valid: in regtest the target is
                // easy. The tip is then only allowed to move if the adopted
                // block passes checks redone here, outside the chain's code
                // path.
                assert!(established, "{context}: block adopted from a stranger");
                let b = n
                    .with_chain(|c| c.block_by_id(&after))
                    .expect("body of the tip");
                independently_valid(&b, before, &context);
                tally.valid_blocks += 1;
                known.active.push(after);
                known.coinbases.push(b.transactions[0].txid());
            }

            // A disconnected peer is replaced by a newcomer, established or
            // not: that is what an attacker who reconnects would do.
            if !keep {
                tally.drops += 1;
                n.disconnect(id);
                plug_in(&n, next_id, a.one_in(2), a.one_in(2));
                ids[slot] = next_id;
                next_id += 1;
            }

            // From time to time, maintenance runs as if a minute had passed:
            // body deadlines, re-requests, disconnections.
            if step % 256 == 255 {
                reporter.command = "(maintenance)";
                if let Some(past) =
                    Instant::now().checked_sub(BODY_TIMEOUT + Duration::from_secs(1))
                {
                    let mut g = n.shared.lock().unwrap();
                    for p in g.peers.values_mut() {
                        for t in p.requested_bodies.values_mut() {
                            *t = past;
                        }
                    }
                }
                n.maintain_peers();
                check_invariants(
                    &n,
                    &format!("seed {seed:#x}, step {step}, maintenance"),
                    false,
                );
                for id in ids.iter_mut() {
                    if !n.shared.lock().unwrap().peers.contains_key(id) {
                        tally.drops += 1;
                        plug_in(&n, next_id, a.one_in(2), a.one_in(2));
                        *id = next_id;
                        next_id += 1;
                    }
                }
            }
        }

        // --- Honest progress after the storm: a handshake completed the
        // normal way, then a valid block adopted.
        reporter.command = "honest sync";
        plug_in(&n, next_id, false, false);
        let honest = next_id;
        let height = n.height();
        assert!(n.handle(
            honest,
            Message::Version {
                version: PROTOCOL_VERSION,
                timestamp: unix_now(),
                nonce: 0x5eed_0000_0000_0001,
                user_agent: "honest".into(),
                start_height: height + 1,
            }
        ));
        assert!(n.handle(honest, Message::VerAck));
        let b = n
            .with_chain(|c| {
                c.mine_block(
                    Hash256([7u8; 32]),
                    SchemeId::LamportOts,
                    &[],
                    c.tip().time + 1,
                    5_000_000,
                )
            })
            .expect("regtest mining");
        let bid = b.header.block_id();
        assert!(n.handle(honest, Message::Block(Box::new(b))));
        assert_eq!(
            n.tip_id(),
            bid,
            "seed {seed:#x}: the node no longer synchronizes an honest peer"
        );
        assert_eq!(n.height(), height + 1);
        check_invariants(&n, "end", true);
        drop(reporter);
        n.shutdown();
    }

    #[test]
    fn handler_fuzz() {
        let iterations = env_u64("Q21_FUZZ_ITERATIONS").unwrap_or(6_000);
        let seeds = env_u64("Q21_FUZZ_SEEDS").unwrap_or(3);
        let first = env_u64("Q21_FUZZ_SEED").unwrap_or(0x51_2100);
        let start = Instant::now();
        let mut tally = Tally::default();
        for k in 0..seeds {
            campaign(first.wrapping_add(k), iterations, &mut tally);
        }
        let total: u64 = tally.messages.values().map(|(c, _)| *c).sum();
        eprintln!(
            "handler fuzz: {seeds} seed(s) from {first:#x}, \
             {total} messages, {} valid blocks adopted, {} disconnections, \
             {} discarded as larger than a frame, in {:?}",
            tally.valid_blocks,
            tally.drops,
            tally.oversized,
            start.elapsed()
        );
        for (cmd, (c, max)) in &tally.messages {
            eprintln!("  {cmd:<12} {c:>9} messages, handle max {max:?}");
        }
    }
}

/// Targeted tests that came out of the review of the handlers.
#[cfg(test)]
mod tests_handler_review {
    use super::*;
    use crate::chain::genesis_block;
    use crate::wire::NetAddr;

    const NETWORK: Network = Network::Regtest;

    fn node() -> Node {
        Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)))
    }

    fn anonymous_peer(n: &Node, id: u64) -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let stream = TcpStream::connect(listener.local_addr().unwrap()).expect("socket");
        let addr = stream.peer_addr().unwrap();
        let now = Instant::now();
        n.shared.lock().unwrap().peers.insert(
            id,
            Peer {
                addr,
                writer: Outbox::start(stream).unwrap(),
                outbound: false,
                snapshot_bucket: TokenBucket::new(now),
                tx_bucket: TokenBucket::for_transactions(now),
                cmpct_bucket: TokenBucket::for_compact_announcements(now),
                user_agent: String::new(),
                channels: false,
                channel_id: String::new(),
                chan_bucket: TokenBucket::for_channel_messages(now),
                headers_bucket: TokenBucket::for_header_requests(now),
                addr_bucket: TokenBucket::for_addresses(now),
                expected_headers: 0,
                requested_bodies: HashMap::new(),
                bodies_to_request: VecDeque::new(),
                more_expected: false,
                version_received: false,
                version_sent: false,
                handshaked: false,
                ban_score: 0,
                start_height: 0,
                pending: HashMap::new(),
                consecutive_orphans: 0,
                mempool_offered: false,
                version: 0,
                remote_nonce: None,
                last_received: now,
                last_delivered: now,
                body_overdue_rounds: 0,
                late_bodies: VecDeque::new(),
                pending_ping: None,
                requested_txs: HashMap::new(),
                announced_waiting: VecDeque::new(),
                connected_at: now,
            },
        );
        listener
    }

    /// Two nodes meet through the proxy: one connects to the other by its
    /// onion name, the proxy alone resolves it, the handshake completes, and
    /// the peer is filed under its reserved stand-in, never under the
    /// proxy's address.
    #[test]
    fn two_nodes_meet_through_the_proxy_by_onion_name() {
        let a = node();
        let listening = a.listen("127.0.0.1:0").expect("listen");
        let onion = format!("{}.onion", "x".repeat(56));
        let (proxy, asked) = crate::socks::tests::fake_proxy(vec![(onion.clone(), listening)]);
        let b = node();
        let target = crate::socks::Target::Name(onion.clone(), 21121);
        assert!(b.connect_target(&target).is_err(), "no proxy: refused");
        b.set_proxy(Some(proxy));
        b.connect_target(&target).expect("through the proxy");
        let deadline = Instant::now() + Duration::from_secs(10);
        let handshaked = |n: &Node| {
            n.shared
                .lock()
                .unwrap()
                .peers
                .values()
                .any(|p| p.handshaked)
        };
        while !(handshaked(&a) && handshaked(&b)) {
            assert!(Instant::now() < deadline, "no handshake through the proxy");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(b.is_connected_to(target.label()));
        assert!(!b.is_connected_to(proxy));
        assert_eq!(asked.lock().unwrap()[0], format!("{onion}:21121"));
        // And an IPv4 address goes through the proxy too, never directly.
        let direct = SocketAddr::from(([10, 1, 2, 3], 21121));
        assert!(b.connect(direct).is_err());
        assert!(asked.lock().unwrap().iter().any(|x| x == "10.1.2.3:21121"));
    }

    fn test_onion() -> crate::wire::OnionAddr {
        crate::wire::OnionAddr {
            name: format!("{}d", "k".repeat(55)),
            port: 21121,
            last_seen: 0,
        }
    }

    /// Reads every frame the node wrote to `other` within 300 ms.
    fn frames_from(other: &mut TcpStream, net: Network) -> Vec<Message> {
        other
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(k) = other.read(&mut chunk) {
            if k == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..k]);
        }
        let mut out = Vec::new();
        let mut at = 0;
        while at < buf.len() {
            match Message::parse(&buf[at..], magic_for(net)) {
                Ok((m, used)) => {
                    out.push(m);
                    at += used;
                }
                Err(_) => break,
            }
        }
        out
    }

    /// A node announces its onion service to a protocol-4 peer at the
    /// handshake, and never to a protocol-3 one, which would take the
    /// unknown command for a malformed frame.
    #[test]
    fn the_onion_service_is_announced_to_modern_peers_only() {
        for (version, expected) in [(3u32, false), (4u32, true)] {
            let n = node();
            n.set_own_onion(Some(test_onion()));
            let listener = anonymous_peer(&n, 7);
            assert!(n.handle(
                7,
                Message::Version {
                    version,
                    timestamp: unix_now(),
                    nonce: 0x0123_4567,
                    user_agent: "peer".into(),
                    start_height: 0,
                }
            ));
            assert!(n.handle(7, Message::VerAck));
            let (mut other, _) = listener.accept().expect("accept");
            let got = frames_from(&mut other, NETWORK)
                .into_iter()
                .any(|m| matches!(&m, Message::OnionAddr(v) if v[0].name == test_onion().name));
            assert_eq!(got, expected, "protocol {version}");
        }
    }

    /// An `onionaddr` from an established peer fills the onion book; from a
    /// stranger, it is not read.
    #[test]
    fn onion_names_are_learned_from_established_peers_only() {
        let n = node();
        let _l = anonymous_peer(&n, 7);
        assert!(n.handle(7, Message::OnionAddr(vec![test_onion()])));
        assert_eq!(n.onion_count(), 0, "before the handshake: ignored");
        {
            let mut g = n.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).expect("peer");
            p.version_received = true;
            p.handshaked = true;
            p.version = 4;
        }
        assert!(n.handle(7, Message::OnionAddr(vec![test_onion()])));
        assert_eq!(n.onion_count(), 1);
        assert_eq!(n.onions_to_try(5).len(), 1);
        n.set_own_onion(Some(test_onion()));
        assert!(n.onions_to_try(5).is_empty(), "never this node's own");
    }

    /// Through Tor, the second outbound link to the same node (same nonce) is
    /// dropped; without Tor, or for inbound links, nothing changes.
    #[test]
    fn the_same_node_reached_twice_through_tor_counts_once() {
        for tor in [true, false] {
            let n = node();
            if tor {
                n.set_proxy(Some(SocketAddr::from(([127, 0, 0, 1], 9))));
            }
            let _a = anonymous_peer(&n, 7);
            let _b = anonymous_peer(&n, 8);
            let first = {
                let mut g = n.shared.lock().unwrap();
                for p in g.peers.values_mut() {
                    p.outbound = true;
                }
                g.peers[&7].addr
            };
            let version = |nonce| Message::Version {
                version: PROTOCOL_VERSION,
                timestamp: unix_now(),
                nonce,
                user_agent: "peer".into(),
                start_height: 0,
            };
            // A gossip-learned link that came first never makes the
            // configured one redundant: here, 7 is not configured yet.
            assert!(n.handle(7, version(0x5151)), "the first link is kept");
            let alias = n.shared.lock().unwrap().peers[&8].addr;
            if tor {
                let _c = anonymous_peer(&n, 9);
                n.shared.lock().unwrap().peers.get_mut(&9).unwrap().outbound = true;
                assert!(
                    n.handle(9, version(0x5151)),
                    "the first link is no configured target: nothing is dropped"
                );
                n.shared.lock().unwrap().peers.remove(&9);
            }
            n.set_configured_targets(vec![first]);
            let second = n.handle(8, version(0x5151));
            if tor {
                assert!(!second, "the newer link to the same node is dropped");
                n.shared.lock().unwrap().peers.remove(&8);
                assert!(
                    n.is_connected_to(alias),
                    "its address is not dialed again while the first link lasts"
                );
            } else {
                assert!(second, "without Tor, nothing is compared");
            }
        }
    }

    /// The Tor counts: an outbound peer filed under an onion name's stand-in
    /// is a connection to an onion service; an inbound loopback peer is one
    /// handed over by Tor, but only when this node serves an onion.
    #[test]
    fn the_onion_status_counts_what_tor_brings() {
        let n = node();
        let _a = anonymous_peer(&n, 7);
        let _b = anonymous_peer(&n, 8);
        let onion = test_onion();
        let label = crate::socks::Target::Name(onion.host(), onion.port).label();
        {
            let mut g = n.shared.lock().unwrap();
            for p in g.peers.values_mut() {
                p.version_received = true;
                p.handshaked = true;
            }
            let p = g.peers.get_mut(&7).expect("peer");
            p.outbound = true;
            p.addr = label;
            g.onions.add(onion.clone(), unix_now());
        }
        let s = n.onion_status();
        assert_eq!(
            (s.serving, s.known, s.outbound, s.inbound),
            (false, 1, 1, 0)
        );
        n.set_own_onion(Some(crate::wire::OnionAddr {
            name: "b".repeat(55) + "d",
            ..onion
        }));
        let s = n.onion_status();
        assert_eq!((s.serving, s.outbound, s.inbound), (true, 1, 1));
        n.shared
            .lock()
            .unwrap()
            .peers
            .get_mut(&8)
            .unwrap()
            .handshaked = false;
        assert_eq!(n.onion_status().inbound, 0, "established peers only");
    }

    /// An outbound peer on a private or loopback address is never handed out
    /// in a reply to `getaddr` on a public network.
    #[test]
    fn a_private_peer_address_is_not_handed_out() {
        let net = Network::Testnet;
        let n = Node::new(net, Chain::new(net, genesis_block(net)));
        let listener = anonymous_peer(&n, 7);
        {
            let mut g = n.shared.lock().unwrap();
            let p = g.peers.get_mut(&7).expect("peer");
            p.outbound = true;
            p.version_received = true;
            p.version_sent = true;
            p.handshaked = true;
        }
        assert!(n.handle(7, Message::GetAddr));
        let (mut other, _) = listener.accept().expect("accept");
        other
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(k) = other.read(&mut chunk) {
            if k == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..k]);
        }
        let mut handed_out = Vec::new();
        let mut at = 0;
        while at < buf.len() {
            match Message::parse(&buf[at..], magic_for(net)) {
                Ok((m, used)) => {
                    if let Message::Addr(v) = m {
                        handed_out.extend(v);
                    }
                    at += used;
                }
                Err(_) => break,
            }
        }
        assert!(
            handed_out.iter().all(|a| a.ip[0] != 127),
            "a loopback peer was handed out: {handed_out:?}"
        );
    }

    /// The requests a peer's synchronization sends for `bodies` when it
    /// announced `ahead` blocks more than we have.
    fn body_requests(ahead: u64, bodies: usize) -> Vec<Outgoing> {
        let n = node();
        let _l = anonymous_peer(&n, 7);
        let mut g = n.shared.lock().unwrap();
        let Shared {
            ref chain,
            ref mut peers,
            ..
        } = *g;
        let p = peers.get_mut(&7).expect("peer");
        p.handshaked = true;
        p.start_height = chain.height() + ahead;
        p.bodies_to_request
            .extend((0..bodies as u8).map(|i| Hash256([i.wrapping_add(1); 32])));
        let mut out = Vec::new();
        p.continue_sync(7, chain, &mut out, Instant::now(), false);
        out
    }

    /// Catching up, the bodies are asked for whole, one request each; near
    /// the tip, as compact blocks in one request. A compact block of the past
    /// cost a second round trip per block: one block every 2.5 s through a
    /// 300 ms link, against sixteen per round trip whole.
    #[test]
    fn a_catch_up_asks_for_whole_blocks_one_per_request() {
        let far = body_requests(1_000, 5);
        assert_eq!(far.len(), 5);
        for o in &far {
            match &o.message {
                Message::GetData(items) => {
                    assert_eq!(items.len(), 1);
                    assert_eq!(items[0].kind, InvKind::Block);
                }
                m => panic!("unexpected {m:?}"),
            }
        }
        let near = body_requests(3, 5);
        assert_eq!(near.len(), 1);
        match &near[0].message {
            Message::GetData(items) => {
                assert_eq!(items.len(), 5);
                assert!(items.iter().all(|i| i.kind == InvKind::CompactBlock));
            }
            m => panic!("unexpected {m:?}"),
        }
    }

    /// A thousand addresses from all-distinct /16 groups, starting at `start`.
    fn group_batch(start: u32) -> Vec<NetAddr> {
        (0..crate::wire::MAX_ADDR as u32)
            .map(|i| {
                let g = start + i;
                NetAddr {
                    ip: [11 + (g >> 8) as u8 % 100, g as u8, 1, 1],
                    port: 21021,
                    last_seen: 1,
                }
            })
            .collect()
    }

    /// An `Addr` pushed before the handshake is not read.
    ///
    /// With the address book full, each address from a new group makes us scan
    /// the five hundred twelve groups to evict one: nearly eight milliseconds of
    /// global lock for sixteen kibibytes received, with neither bucket nor
    /// introduction. A single anonymous connection thus held the lock almost
    /// continuously.
    #[test]
    fn an_addr_before_the_handshake_is_not_read() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        let mut worst = Duration::ZERO;
        for k in 0..8u32 {
            let start = Instant::now();
            assert!(n.handle(9, Message::Addr(group_batch(k * 1000))));
            worst = worst.max(start.elapsed());
        }
        eprintln!("anonymous addr: handle max {worst:?}");
        assert_eq!(
            n.address_count(),
            0,
            "an anonymous connection wrote into the address book"
        );
    }

    fn establish(n: &Node, id: u64) {
        let mut g = n.shared.lock().unwrap();
        let p = g.peers.get_mut(&id).unwrap();
        p.version_received = true;
        p.handshaked = true;
    }

    /// Suspicion refuted: `consecutive_orphans += 1` cannot overflow. The third
    /// unconnected batch disconnects the peer; the counter never goes beyond
    /// three on a live connection.
    #[test]
    fn the_orphan_counter_disconnects_before_any_overflow() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        establish(&n, 9);
        let header = n.with_chain(|c| c.tip());
        let mut foreign = header;
        foreign.prev_block = Hash256([0xab; 32]);
        for i in 1..=3u32 {
            n.shared
                .lock()
                .unwrap()
                .peers
                .get_mut(&9)
                .unwrap()
                .expected_headers = 1;
            let kept = n.handle(9, Message::Headers(vec![foreign]));
            assert_eq!(kept, i < 3, "batch {i}");
        }
    }

    /// Suspicions refuted: extreme indices and chunk numbers, on a known block
    /// and an absent snapshot, neither panic nor serve anything.
    #[test]
    fn extreme_indices_serve_nothing() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        establish(&n, 9);
        let tip = n.tip_id();
        assert!(n.handle(
            9,
            Message::GetBlockTxn {
                block: tip,
                indices: vec![u32::MAX, u32::MAX - 1, 1, 0],
            }
        ));
        for index in [0, 1, u32::MAX - 1, u32::MAX] {
            assert!(n.handle(9, Message::GetSnapshotChunk { index }));
        }
        assert_eq!(crate::fast_sync::chunk(&[1, 2, 3], u32::MAX), &[] as &[u8]);
    }

    /// Suspicion refuted: a compact announcement whose prefilled index is
    /// `u32::MAX`, or whose total count exceeds the bound, is rejected by the
    /// reconstruction without out-of-bounds indexing or oversized allocation.
    #[test]
    fn an_absurd_reconstruction_is_rejected_without_panicking() {
        let g = genesis_block(NETWORK);
        let mut c = CompactBlock::from_block(&g, 1);
        c.prefilled[0].0 = u32::MAX;
        assert!(Reconstruction::from_compact(&c, &HashMap::new()).is_err());
        let mut c = CompactBlock::from_block(&g, 1);
        c.short_ids = vec![0; crate::compact::MAX_TX_PER_BLOCK];
        assert!(matches!(
            Reconstruction::from_compact(&c, &HashMap::new()),
            Err(crate::compact::CompactError::TooManyTransactions(_))
        ));
        let mut c = CompactBlock::from_block(&g, 1);
        c.prefilled.push((0, g.transactions[0].clone()));
        // Index zero twice: one slot stays empty, and finalization says so
        // instead of panicking.
        let r = Reconstruction::from_compact(&c, &HashMap::new()).expect("accepted shape");
        assert!(r.finish().is_err());
    }

    /// Acts as if every requested body had been requested more than
    /// [`BODY_TIMEOUT`] ago: the deadline is replayed without waiting a minute.
    fn age_requests(n: &Node) {
        let past = Instant::now()
            .checked_sub(BODY_TIMEOUT + Duration::from_secs(1))
            .expect("monotonic clock advanced enough");
        let mut g = n.shared.lock().unwrap();
        for p in g.peers.values_mut() {
            for t in p.requested_bodies.values_mut() {
                *t = past;
            }
        }
    }

    /// An honest peer is never punished for a body someone else invented.
    ///
    /// An anonymous connection announces sixteen invented block identifiers.
    /// They are requested, never delivered; at the deadline, the request was
    /// made again to the first established peer — an honest one, which cannot
    /// deliver what does not exist, and in turn lost fifty points. Two rounds
    /// were enough to disconnect it, and the attacker only had to reconnect to
    /// start over: enough to drain a node of its honest peers.
    #[test]
    fn an_honest_peer_is_not_punished_for_invented_bodies() {
        let n = node();
        let _h = anonymous_peer(&n, 1);
        establish(&n, 1);
        for round in 0..2u64 {
            let attacker = 100 + round;
            let _e = anonymous_peer(&n, attacker);
            // Established: an anonymous `inv` is no longer read at all
            // (0.3.2), and it is the re-request itself that is tested here.
            establish(&n, attacker);
            let invented: Vec<InvItem> = (0..MAX_BODIES_IN_FLIGHT as u8)
                .map(|i| InvItem {
                    kind: InvKind::CompactBlock,
                    hash: Hash256([i ^ (round as u8 * 0x40) ^ 0x80; 32]),
                })
                .collect();
            assert!(n.handle(attacker, Message::Inv(invented)));
            // First deadline: the announcer withholds, the request is made
            // again.
            age_requests(&n);
            n.maintain_peers();
            // Second deadline: the peer the request was made to does not
            // deliver.
            age_requests(&n);
            n.maintain_peers();
            n.disconnect(attacker);
        }
        let g = n.shared.lock().unwrap();
        let honest = g.peers.get(&1);
        assert!(
            honest.is_some(),
            "the honest peer was disconnected for bodies the attacker invented"
        );
        assert_eq!(
            honest.unwrap().ban_score,
            0,
            "the honest peer was penalized for invented bodies"
        );
    }

    /// Counter-test: a real withheld body is always requested again from
    /// another peer, as a full block, and adopted when it arrives.
    #[test]
    fn a_withheld_body_is_requested_again_and_adopted() {
        let n = node();
        let listener = anonymous_peer(&n, 1);
        establish(&n, 1);
        let (mut honest_side, _) = listener.accept().expect("accept");
        let _ = honest_side.set_read_timeout(Some(Duration::from_secs(5)));
        let block = n
            .with_chain(|c| {
                c.mine_block(
                    Hash256([3u8; 32]),
                    crate::sig::SchemeId::LamportOts,
                    &[],
                    c.tip().time + 1,
                    5_000_000,
                )
            })
            .expect("regtest mining");
        let bid = block.header.block_id();
        let _e = anonymous_peer(&n, 2);
        establish(&n, 2);
        assert!(n.handle(
            2,
            Message::Inv(vec![InvItem {
                kind: InvKind::CompactBlock,
                hash: bid,
            }])
        ));
        age_requests(&n);
        n.maintain_peers();
        // The honest peer receives the re-request.
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let request = loop {
            match Message::parse(&buffer, n.magic) {
                Ok((Message::GetData(v), _)) => break v,
                Ok((_, k)) => {
                    buffer.drain(..k);
                }
                Err(WireError::Incomplete) => {
                    let k = honest_side.read(&mut chunk).expect("read");
                    assert!(k > 0, "connection closed without a re-request");
                    buffer.extend_from_slice(&chunk[..k]);
                }
                Err(e) => panic!("unreadable frame: {e:?}"),
            }
        };
        assert_eq!(
            request,
            vec![InvItem {
                kind: InvKind::Block,
                hash: bid,
            }]
        );
        assert!(n.handle(1, Message::Block(Box::new(block))));
        assert_eq!(n.tip_id(), bid, "the re-requested body was not adopted");
        assert_eq!(n.shared.lock().unwrap().peers[&1].ban_score, 0);
    }

    /// The same `Addr`, after the handshake, is read as before.
    #[test]
    fn an_addr_after_the_handshake_is_read() {
        let n = node();
        let _e = anonymous_peer(&n, 9);
        {
            let mut g = n.shared.lock().unwrap();
            let p = g.peers.get_mut(&9).unwrap();
            p.version_received = true;
            p.handshaked = true;
        }
        assert!(n.handle(9, Message::Addr(group_batch(0))));
        assert_eq!(n.address_count(), crate::addr::MAX_GROUPS);
    }
}
