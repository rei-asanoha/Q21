//! Wire protocol: framing and messages.
//!
//! Frame format, inspired by Bitcoin because it has twenty years of service
//! and none of its properties has aged badly:
//!
//! ```text
//! [ magic 4 B ][ command 12 B ][ length 4 B ][ checksum 4 B ][ payload ]
//! ```
//!
//! The magic separates networks: a testnet message cannot be read by mistake
//! on mainnet. The checksum detects transport corruption; it protects against
//! nothing else, and does not pretend to.
//!
//! # All data arriving here is hostile until proven otherwise
//!
//! This file is the first thing a byte coming from a stranger touches. Two
//! rules follow, applied without exception:
//!
//! - **no allocation before checking.** A peer announcing four billion
//!   elements must not cause four billion slots to be reserved. Every length
//!   is bounded before being used;
//! - **no panic.** A malformed frame returns an error, never a panic. A node
//!   that can be stopped remotely with ten bytes is not a node.

use crate::block::{Block, BlockHeader};
use crate::compact::{CompactBlock, CompactError};
use crate::consensus::MAX_BLOCK_SIZE;
use crate::hash::Hash256;
use crate::ser::{ReadError, Reader, Writer};
use crate::sha256::sha256;
use crate::tx::Transaction;

/// Protocol version, announced at the handshake.
///
/// 1: launch. 2: September 2026 review — new proof of work, signed hash
/// committing to the network and the spent output, Merkle leaf committing to
/// the witness, dust rejected, uncles removed.
/// 3: wire command names in English (`getsnapshot`, `snapshotinfo`,
/// `getsnapchunk`, `snapchunk`); a version-2 peer would not understand them.
/// 4: `onionaddr`, the addresses of Tor onion services (0.4.7). Sent only to
/// peers that announced version 4: a version-3 node treats an unknown command
/// as a malformed frame. Everything else is unchanged, and version-3 peers
/// stay welcome.
/// 5: follows the activation of policy outputs on a network that schedules
/// it (0.4.11). No new message: a version-4 peer reads a version-5 one as
/// before, and a version-5 node stays a peer of it. What changes is what the
/// version-5 node sends it: never a transaction that creates or spends a
/// policy output, which a version-4 node reads as malformed.
pub const PROTOCOL_VERSION: u32 = 5;

/// First version that understands `onionaddr`.
pub const ONION_ADDR_VERSION: u32 = 4;

/// First version that follows the activation of policy outputs: it validates
/// them from the activation height of its network, and does not take a
/// policy output received from a peer that is ahead of it for a malformed
/// message. See [`crate::policy::has_transition`].
pub const POLICY_ACTIVATION_VERSION: u32 = 5;

/// Length of a Tor v3 onion name, without `.onion`: 56 base32 characters.
pub const ONION_NAME_LEN: usize = 56;

/// Minimum version accepted from a peer.
///
/// An older peer validates other rules: every block it sent would be
/// rejected, every block sent to it would be too, and the two would punish
/// each other. We disconnect at the handshake, without penalty: it is not a
/// fault, it is another era.
pub const MIN_PROTOCOL_VERSION: u32 = 3;

/// Maximum size of a payload, in bytes.
///
/// Must stay above the maximum size of a block, otherwise a valid block would
/// be unfairly rejected. But not too far above: everything that passes this
/// bound is **decoded entirely** before a finer rule rejects it — an 8 MiB
/// block was decoded in full only to be rejected afterwards as too large
/// (phase 8b red team, 2nd campaign, item 6a).
///
/// The largest valid message is a full block ([`MAX_BLOCK_SIZE`]), or a
/// compact block that would prefill all of its transactions: the block, plus
/// six bytes per transaction. The one-quarter margin covers this case and the
/// length prefixes. Everything else is much smaller: a snapshot chunk is
/// 1 MiB, a full inventory less than 2 MiB, two thousand headers less than
/// 400 KiB.
pub const MAX_PAYLOAD: usize = MAX_BLOCK_SIZE + MAX_BLOCK_SIZE / 4;

/// Safety bounds on reading. Each one prevents an allocation dictated by a
/// stranger.
pub const MAX_INV: usize = 50_000;
pub const MAX_HEADERS: usize = 2_000;
pub const MAX_LOCATOR: usize = 64;
pub const MAX_ADDR: usize = 1_000;
pub const MAX_BLOCK_TXN: usize = 100_000;
pub const MAX_USER_AGENT: usize = 64;

/// Size of the frame header.
pub const HEADER_LEN: usize = 4 + 12 + 4 + 4;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WireError {
    UnknownMagic([u8; 4]),
    InvalidCommand,
    UnknownCommand(String),
    PayloadTooLarge(usize),
    BadChecksum,
    TooManyElements {
        max: usize,
        received: usize,
    },
    Read(ReadError),
    InvalidContent(&'static str),
    /// Incomplete frame: more bytes must be read.
    Incomplete,
}

impl From<ReadError> for WireError {
    fn from(e: ReadError) -> Self {
        WireError::Read(e)
    }
}

impl From<CompactError> for WireError {
    fn from(_: CompactError) -> Self {
        WireError::InvalidContent("compact block")
    }
}

/// Type of object announced in an inventory.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(u8)]
pub enum InvKind {
    Tx = 1,
    Block = 2,
    /// Announces that a block is available through compact relay.
    CompactBlock = 3,
}

impl InvKind {
    pub fn from_u8(v: u8) -> Option<InvKind> {
        match v {
            1 => Some(InvKind::Tx),
            2 => Some(InvKind::Block),
            3 => Some(InvKind::CompactBlock),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct InvItem {
    pub kind: InvKind,
    pub hash: Hash256,
}

/// Address of a peer, as it travels over the network.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct NetAddr {
    pub ip: [u8; 4],
    pub port: u16,
    /// Timestamp of the last known activity, used to age addresses.
    pub last_seen: u64,
}

/// Address of a Tor onion service (v3), as it travels over the network: the
/// 56 characters before `.onion`, lowercase base32. Tor checks the rest
/// (key and checksum) when someone connects; a malformed name only costs a
/// failed connection, through Tor, to the node that tries it.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct OnionAddr {
    pub name: String,
    pub port: u16,
    pub last_seen: u64,
}

impl OnionAddr {
    /// Reads `name.onion` (or `name.onion:port`, with `default_port` when
    /// absent). `None` when it is not a v3 onion name.
    pub fn parse(raw: &str, default_port: u16) -> Option<OnionAddr> {
        let raw = raw.trim().to_ascii_lowercase();
        let (host, port) = match raw.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
            None => (raw.clone(), default_port),
        };
        let name = host.strip_suffix(".onion")?;
        if !valid_onion_name(name) || port == 0 {
            return None;
        }
        Some(OnionAddr {
            name: name.to_string(),
            port,
            last_seen: 0,
        })
    }

    /// `name.onion`
    pub fn host(&self) -> String {
        format!("{}.onion", self.name)
    }
}

/// 56 characters of the base32 alphabet Tor uses (a-z, 2-7), ending in `d`:
/// the version byte 3 always encodes to a final `d`.
pub fn valid_onion_name(name: &str) -> bool {
    name.len() == ONION_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        && name.ends_with('d')
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Message {
    Version {
        version: u32,
        timestamp: u64,
        /// Random identifier, used to detect a connection to oneself.
        nonce: u64,
        user_agent: String,
        start_height: u64,
    },
    VerAck,
    Ping(u64),
    Pong(u64),
    /// Request for headers starting from a block locator.
    GetHeaders {
        locator: Vec<Hash256>,
        stop: Hash256,
    },
    Headers(Vec<BlockHeader>),
    Inv(Vec<InvItem>),
    GetData(Vec<InvItem>),
    Block(Box<Block>),
    Tx(Box<Transaction>),
    CmpctBlock(Box<CompactBlock>),
    GetBlockTxn {
        block: Hash256,
        indices: Vec<u32>,
    },
    BlockTxn {
        block: Hash256,
        txs: Vec<Transaction>,
    },
    GetAddr,
    Addr(Vec<NetAddr>),
    /// Onion service addresses (protocol 4). See [`OnionAddr`].
    OnionAddr(Vec<OnionAddr>),
    /// Rejection with a reason, so that the other end knows why.
    Reject {
        command: String,
        reason: String,
    },
    /// Asks a peer to describe the fast-sync snapshot it can serve.
    GetSnapshot,
    /// Snapshot metadata: enough to know what to ask for and what to expect,
    /// before receiving the slightest piece of it.
    SnapshotInfo {
        height: u64,
        tip: Hash256,
        commitment: Hash256,
        size: u64,
        chunks: u32,
    },
    /// Requests chunk number `index` of the serialized snapshot.
    GetSnapshotChunk {
        index: u32,
    },
    /// A chunk of the serialized snapshot, to be reassembled in order.
    SnapshotChunk {
        index: u32,
        data: Vec<u8>,
    },
    /// A payment-channel message ([`crate::channel::messages::Message`]), carried
    /// opaquely. The payload is that message's own canonical encoding; this
    /// layer only bounds it. It is sent only to a peer that advertised the
    /// channel capability (see [`user_agent_advertises_channels`]), so a node
    /// that does not understand it never receives one.
    Channel(Vec<u8>),
}

/// Capability token a node appends to its user agent to advertise that it
/// speaks the payment-channel protocol. A peer that does not carry it in its
/// `Version` never receives a [`Message::Channel`]; an older node simply reads
/// a slightly longer, still-bounded user-agent string and is untouched.
pub const CHANNELS_CAPABILITY: &str = "+chan";

/// Does this user agent advertise the channel capability?
pub fn user_agent_advertises_channels(user_agent: &str) -> bool {
    user_agent.contains(CHANNELS_CAPABILITY)
}

/// The hex characters a channel node advertises after [`CHANNELS_CAPABILITY`]:
/// its stable channel node id (32 hex = 16 bytes), used to re-bind channels to
/// a peer across reconnects regardless of the connection's ephemeral port.
/// Empty when the peer advertises the capability without an id (an older
/// channel build) or does not advertise it at all.
pub fn channel_node_id(user_agent: &str) -> Option<String> {
    let at = user_agent.find(CHANNELS_CAPABILITY)?;
    let rest = &user_agent[at + CHANNELS_CAPABILITY.len()..];
    let id: String = rest
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .take(CHANNEL_NODE_ID_HEX)
        .collect();
    (!id.is_empty()).then_some(id)
}

/// Length in hex characters of an advertised channel node id (16 bytes).
pub const CHANNEL_NODE_ID_HEX: usize = 32;

/// Largest channel message accepted on the wire. The heaviest is the funding
/// message (its three tier signatures), well under this bound.
pub const MAX_CHANNEL_MSG: usize = 16 * 1024;

impl Message {
    pub fn command(&self) -> &'static str {
        match self {
            Message::Version { .. } => "version",
            Message::VerAck => "verack",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::GetHeaders { .. } => "getheaders",
            Message::Headers(_) => "headers",
            Message::Inv(_) => "inv",
            Message::GetData(_) => "getdata",
            Message::Block(_) => "block",
            Message::Tx(_) => "tx",
            Message::CmpctBlock(_) => "cmpctblock",
            Message::GetBlockTxn { .. } => "getblocktxn",
            Message::BlockTxn { .. } => "blocktxn",
            Message::GetAddr => "getaddr",
            Message::Addr(_) => "addr",
            Message::OnionAddr(_) => "onionaddr",
            Message::Reject { .. } => "reject",
            Message::GetSnapshot => "getsnapshot",
            Message::SnapshotInfo { .. } => "snapshotinfo",
            Message::GetSnapshotChunk { .. } => "getsnapchunk",
            Message::SnapshotChunk { .. } => "snapchunk",
            Message::Channel(_) => "channel",
        }
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Message::Version {
                version,
                timestamp,
                nonce,
                user_agent,
                start_height,
            } => {
                w.u32(*version);
                w.u64(*timestamp);
                w.u64(*nonce);
                w.var_bytes(user_agent.as_bytes());
                w.u64(*start_height);
            }
            Message::VerAck | Message::GetAddr => {}
            Message::Ping(n) | Message::Pong(n) => {
                w.u64(*n);
            }
            Message::GetHeaders { locator, stop } => {
                w.varint(locator.len() as u64);
                for h in locator {
                    w.bytes(h.as_bytes());
                }
                w.bytes(stop.as_bytes());
            }
            Message::Headers(v) => {
                w.varint(v.len() as u64);
                for h in v {
                    w.bytes(&h.encode());
                }
            }
            Message::Inv(v) | Message::GetData(v) => {
                w.varint(v.len() as u64);
                for i in v {
                    w.u8(i.kind as u8);
                    w.bytes(i.hash.as_bytes());
                }
            }
            Message::Block(b) => {
                w.bytes(&b.encode());
            }
            Message::Tx(t) => {
                w.bytes(&t.encode());
            }
            Message::CmpctBlock(c) => {
                w.bytes(&c.encode());
            }
            Message::GetBlockTxn { block, indices } => {
                w.bytes(block.as_bytes());
                w.varint(indices.len() as u64);
                for i in indices {
                    w.varint(*i as u64);
                }
            }
            Message::BlockTxn { block, txs } => {
                w.bytes(block.as_bytes());
                w.varint(txs.len() as u64);
                for t in txs {
                    w.var_bytes(&t.encode());
                }
            }
            Message::Addr(v) => {
                w.varint(v.len() as u64);
                for a in v {
                    w.bytes(&a.ip);
                    w.u32(a.port as u32);
                    w.u64(a.last_seen);
                }
            }
            Message::OnionAddr(v) => {
                w.varint(v.len() as u64);
                for a in v {
                    w.bytes(a.name.as_bytes());
                    w.u32(a.port as u32);
                    w.u64(a.last_seen);
                }
            }
            Message::Reject { command, reason } => {
                w.var_bytes(command.as_bytes());
                w.var_bytes(reason.as_bytes());
            }
            Message::GetSnapshot => {}
            Message::SnapshotInfo {
                height,
                tip,
                commitment,
                size,
                chunks,
            } => {
                w.u64(*height);
                w.bytes(tip.as_bytes());
                w.bytes(commitment.as_bytes());
                w.u64(*size);
                w.u32(*chunks);
            }
            Message::GetSnapshotChunk { index } => {
                w.u32(*index);
            }
            Message::SnapshotChunk { index, data } => {
                w.u32(*index);
                w.var_bytes(data);
            }
            // The payload is the channel message's own encoding, verbatim; the
            // frame length already bounds it.
            Message::Channel(bytes) => {
                w.bytes(bytes);
            }
        }
        w.finish()
    }

    fn decode_payload(command: &str, data: &[u8]) -> Result<Message, WireError> {
        let mut r = Reader::new(data);

        /// Reads a length, bounding it before any allocation.
        ///
        /// # The defect `minimum` fixes
        ///
        /// Bounding by the protocol maximum was not enough. A twenty-seven
        /// byte frame announcing fifty thousand inventory items passed the
        /// check — fifty thousand is the bound — and caused one million six
        /// hundred fifty thousand bytes to be reserved, before failing on a
        /// premature end. That is **sixty-one thousand times** what had been
        /// received, for the price of one `send()`.
        ///
        /// The ratio was measured, not assumed: see the allocation report test
        /// in `tests/audit_arith.rs`, which prints it message by message.
        ///
        /// The rule that closes this fits in one sentence: **we never reserve
        /// room for more elements than the rest of the frame can contain.**
        /// Since each element has a known minimum size, the comparison is exact
        /// and costs nothing.
        ///
        /// `minimum` is the number of bytes an element cannot fail to occupy.
        /// Zero means "unknown" and disables the check — to be used only if no
        /// lower bound exists.
        fn bound_with(r: &mut Reader<'_>, max: usize, minimum: usize) -> Result<usize, WireError> {
            // The comparison is done in u64, before any conversion: on a
            // 32-bit target, `as usize` would have truncated a count of more
            // than four billion into a small accepted number. `received` is
            // only a diagnostic figure; if it does not fit in `usize`, it is
            // capped.
            let announced = r.varint()?;
            let received = usize::try_from(announced).unwrap_or(usize::MAX);
            if announced > max as u64 {
                return Err(WireError::TooManyElements { max, received });
            }
            let n = received;
            if let Some(fits) = r.remaining().checked_div(minimum) {
                if n > fits {
                    return Err(WireError::TooManyElements {
                        max: fits,
                        received: n,
                    });
                }
            }
            Ok(n)
        }

        let m = match command {
            "version" => {
                let version = r.u32()?;
                let timestamp = r.u64()?;
                let nonce = r.u64()?;
                let ua = r.var_bytes()?;
                if ua.len() > MAX_USER_AGENT {
                    return Err(WireError::TooManyElements {
                        max: MAX_USER_AGENT,
                        received: ua.len(),
                    });
                }
                let user_agent = String::from_utf8_lossy(ua).into_owned();
                let start_height = r.u64()?;
                r.expect_end()?;
                Message::Version {
                    version,
                    timestamp,
                    nonce,
                    user_agent,
                    start_height,
                }
            }
            "verack" => {
                r.expect_end()?;
                Message::VerAck
            }
            "getaddr" => {
                r.expect_end()?;
                Message::GetAddr
            }
            "ping" => {
                let n = r.u64()?;
                r.expect_end()?;
                Message::Ping(n)
            }
            "pong" => {
                let n = r.u64()?;
                r.expect_end()?;
                Message::Pong(n)
            }
            "getheaders" => {
                let n = bound_with(&mut r, MAX_LOCATOR, 32)?;
                let mut locator = Vec::with_capacity(n);
                for _ in 0..n {
                    locator.push(Hash256(r.array32()?));
                }
                let stop = Hash256(r.array32()?);
                r.expect_end()?;
                Message::GetHeaders { locator, stop }
            }
            "headers" => {
                let n = bound_with(&mut r, MAX_HEADERS, BlockHeader::SIZE)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut buf = [0u8; BlockHeader::SIZE];
                    for o in buf.iter_mut() {
                        *o = r.u8()?;
                    }
                    v.push(BlockHeader::decode(&buf)?);
                }
                r.expect_end()?;
                Message::Headers(v)
            }
            "inv" | "getdata" => {
                let n = bound_with(&mut r, MAX_INV, 33)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let raw = r.u8()?;
                    let kind =
                        InvKind::from_u8(raw).ok_or(WireError::InvalidContent("inventory type"))?;
                    v.push(InvItem {
                        kind,
                        hash: Hash256(r.array32()?),
                    });
                }
                r.expect_end()?;
                if command == "inv" {
                    Message::Inv(v)
                } else {
                    Message::GetData(v)
                }
            }
            "block" => Message::Block(Box::new(
                Block::decode(data).map_err(|_| WireError::InvalidContent("block"))?,
            )),
            "tx" => Message::Tx(Box::new(
                Transaction::decode(data).map_err(|_| WireError::InvalidContent("transaction"))?,
            )),
            "cmpctblock" => Message::CmpctBlock(Box::new(CompactBlock::decode(data)?)),
            "getblocktxn" => {
                let block = Hash256(r.array32()?);
                let n = bound_with(&mut r, MAX_BLOCK_TXN, 1)?;
                let mut indices = Vec::with_capacity(n);
                for _ in 0..n {
                    // Same rule as for the port: an index that does not fit in
                    // thirty-two bits is not silently wrapped to zero. Wrapping
                    // it to zero would serve transaction 0 to whoever asks for
                    // the 2^32-th one — a wrong answer, not just a redundant
                    // encoding.
                    let raw = r.varint()?;
                    if raw > u32::MAX as u64 {
                        return Err(WireError::InvalidContent(
                            "index outside thirty-two bits: non-canonical encoding",
                        ));
                    }
                    indices.push(raw as u32);
                }
                r.expect_end()?;
                Message::GetBlockTxn { block, indices }
            }
            "blocktxn" => {
                let block = Hash256(r.array32()?);
                let n = bound_with(&mut r, MAX_BLOCK_TXN, 1)?;
                let mut txs = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    let raw = r.var_bytes()?;
                    txs.push(
                        Transaction::decode(raw)
                            .map_err(|_| WireError::InvalidContent("transaction"))?,
                    );
                }
                r.expect_end()?;
                Message::BlockTxn { block, txs }
            }
            "addr" => {
                let n = bound_with(&mut r, MAX_ADDR, 16)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut ip = [0u8; 4];
                    for o in ip.iter_mut() {
                        *o = r.u8()?;
                    }
                    // --- A decoder rejects what it cannot represent.
                    //
                    // The port was written on thirty-two bits and read back
                    // truncated to sixteen: sixty-five thousand five hundred
                    // thirty-six distinct frames decoded to the same address.
                    // No funds could be stolen through it — no signature covers
                    // P2P messages — but a decoder that silently truncates is a
                    // decoder that lies about what it read, and two different
                    // byte strings became indistinguishable.
                    let raw_port = r.u32()?;
                    if raw_port > u16::MAX as u32 {
                        return Err(WireError::InvalidContent(
                            "port outside sixteen bits: non-canonical encoding",
                        ));
                    }
                    let port = raw_port as u16;
                    let last_seen = r.u64()?;
                    v.push(NetAddr {
                        ip,
                        port,
                        last_seen,
                    });
                }
                r.expect_end()?;
                Message::Addr(v)
            }
            "onionaddr" => {
                let n = bound_with(&mut r, MAX_ADDR, ONION_NAME_LEN + 12)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut raw = [0u8; ONION_NAME_LEN];
                    for o in raw.iter_mut() {
                        *o = r.u8()?;
                    }
                    let name = std::str::from_utf8(&raw)
                        .ok()
                        .filter(|n| valid_onion_name(n))
                        .ok_or(WireError::InvalidContent("onion name"))?
                        .to_string();
                    // Same canonical port rule as `addr`.
                    let raw_port = r.u32()?;
                    if raw_port == 0 || raw_port > u16::MAX as u32 {
                        return Err(WireError::InvalidContent("onion port"));
                    }
                    let last_seen = r.u64()?;
                    v.push(OnionAddr {
                        name,
                        port: raw_port as u16,
                        last_seen,
                    });
                }
                r.expect_end()?;
                Message::OnionAddr(v)
            }
            "reject" => {
                let c = r.var_bytes()?;
                let reason = r.var_bytes()?;
                if c.len() > 64 || reason.len() > 256 {
                    return Err(WireError::InvalidContent("reject too verbose"));
                }
                r.expect_end()?;
                Message::Reject {
                    command: String::from_utf8_lossy(c).into_owned(),
                    reason: String::from_utf8_lossy(reason).into_owned(),
                }
            }
            "getsnapshot" => {
                r.expect_end()?;
                Message::GetSnapshot
            }
            "snapshotinfo" => {
                let height = r.u64()?;
                let tip = Hash256(r.array32()?);
                let commitment = Hash256(r.array32()?);
                let size = r.u64()?;
                let chunks = r.u32()?;
                r.expect_end()?;
                Message::SnapshotInfo {
                    height,
                    tip,
                    commitment,
                    size,
                    chunks,
                }
            }
            "getsnapchunk" => {
                let index = r.u32()?;
                r.expect_end()?;
                Message::GetSnapshotChunk { index }
            }
            "snapchunk" => {
                let index = r.u32()?;
                // The chunk is bounded by the frame itself: the payload never
                // exceeds MAX_PAYLOAD, checked before even getting here.
                let data = r.var_bytes()?.to_vec();
                r.expect_end()?;
                Message::SnapshotChunk { index, data }
            }
            "channel" => {
                if data.len() > MAX_CHANNEL_MSG {
                    return Err(WireError::TooManyElements {
                        max: MAX_CHANNEL_MSG,
                        received: data.len(),
                    });
                }
                Message::Channel(data.to_vec())
            }
            other => return Err(WireError::UnknownCommand(other.to_string())),
        };
        Ok(m)
    }

    /// Serializes the message into a complete frame.
    pub fn frame(&self, magic: [u8; 4]) -> Vec<u8> {
        let payload = self.encode_payload();
        let checksum = sha256(&payload);

        let mut cmd = [0u8; 12];
        let name = self.command().as_bytes();
        cmd[..name.len()].copy_from_slice(name);

        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&magic);
        out.extend_from_slice(&cmd);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&checksum[..4]);
        out.extend_from_slice(&payload);
        out
    }

    /// Does this message carry a transaction with a policy output
    /// ([`crate::sig::SchemeId::Policy`])?
    ///
    /// Up to 0.4.9 such an output did not decode at all. Where policies are
    /// dormant, the node uses this to treat the message exactly as it did
    /// then: unreadable. Inputs need no look: an input spending a policy
    /// output only exists if one was created.
    pub fn carries_policy_output(&self) -> bool {
        fn any<'a>(mut txs: impl Iterator<Item = &'a Transaction>) -> bool {
            txs.any(|t| {
                t.outputs
                    .iter()
                    .any(|o| o.scheme == crate::sig::SchemeId::Policy)
            })
        }
        match self {
            Message::Tx(t) => any(std::iter::once(t.as_ref())),
            Message::Block(b) => any(b.transactions.iter()),
            Message::BlockTxn { txs, .. } => any(txs.iter()),
            Message::CmpctBlock(c) => any(c.prefilled.iter().map(|(_, t)| t)),
            _ => false,
        }
    }

    /// Tries to read a frame from a buffer.
    ///
    /// Returns the message and the number of bytes consumed, or
    /// [`WireError::Incomplete`] if the buffer does not yet contain the whole
    /// frame.
    pub fn parse(buffer: &[u8], magic: [u8; 4]) -> Result<(Message, usize), WireError> {
        if buffer.len() < HEADER_LEN {
            return Err(WireError::Incomplete);
        }
        let mut m = [0u8; 4];
        m.copy_from_slice(&buffer[..4]);
        if m != magic {
            return Err(WireError::UnknownMagic(m));
        }

        let raw_cmd = &buffer[4..16];
        let end = raw_cmd.iter().position(|c| *c == 0).unwrap_or(12);
        let command = core::str::from_utf8(&raw_cmd[..end])
            .map_err(|_| WireError::InvalidCommand)?
            .to_string();
        // The padding must be zero: otherwise two encodings would designate the
        // same command.
        if raw_cmd[end..].iter().any(|c| *c != 0) {
            return Err(WireError::InvalidCommand);
        }

        let mut lb = [0u8; 4];
        lb.copy_from_slice(&buffer[16..20]);
        let length = u32::from_le_bytes(lb) as usize;

        // Bound BEFORE waiting for the bytes: otherwise a peer announcing 4 GiB
        // would make the read buffer grow until memory is exhausted.
        if length > MAX_PAYLOAD {
            return Err(WireError::PayloadTooLarge(length));
        }
        if buffer.len() < HEADER_LEN + length {
            return Err(WireError::Incomplete);
        }

        let payload = &buffer[HEADER_LEN..HEADER_LEN + length];
        if sha256(payload)[..4] != buffer[20..24] {
            return Err(WireError::BadChecksum);
        }

        let msg = Message::decode_payload(&command, payload)?;
        Ok((msg, HEADER_LEN + length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::NETWORK_MAGIC_TESTNET as MAGIC;

    /// 0.4.11 announces the version that follows the policy activation, and
    /// still accepts the 0.4.10 nodes (version 4) it must keep talking to
    /// before the activation height.
    #[test]
    fn this_version_follows_the_policy_activation_and_accepts_0_4_10() {
        assert_eq!(PROTOCOL_VERSION, POLICY_ACTIVATION_VERSION);
        assert!(MIN_PROTOCOL_VERSION <= 4);
        assert!(ONION_ADDR_VERSION < POLICY_ACTIVATION_VERSION);
    }

    fn round_trip(m: Message) {
        let frame = m.frame(MAGIC);
        let (reread, consumed) = Message::parse(&frame, MAGIC).expect("parse");
        assert_eq!(reread, m, "unfaithful round trip for {}", m.command());
        assert_eq!(consumed, frame.len());
    }

    fn header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block: Hash256([1u8; 32]),
            merkle_root: Hash256([2u8; 32]),
            uncles_root: Hash256([3u8; 32]),
            miner: Hash256([4u8; 32]),
            time: 1_755_000_000,
            bits: 0x2000_ffff,
            height: 42,
            nonce: 7,
        }
    }

    #[test]
    fn channel_message_round_trips_and_is_bounded() {
        round_trip(Message::Channel(vec![1, 2, 3, 4, 5]));
        round_trip(Message::Channel(Vec::new()));
        // At the bound: still accepted.
        round_trip(Message::Channel(vec![7u8; MAX_CHANNEL_MSG]));
        // One byte over the bound: refused, not decoded.
        let framed = Message::Channel(vec![7u8; MAX_CHANNEL_MSG + 1]).frame(MAGIC);
        assert!(matches!(
            Message::parse(&framed, MAGIC),
            Err(WireError::TooManyElements { .. })
        ));
    }

    #[test]
    fn the_capability_token_reads_back() {
        assert!(user_agent_advertises_channels(&format!(
            "q21:0.4{CHANNELS_CAPABILITY}"
        )));
        // A plain 0.4.9 user agent does not advertise it.
        assert!(!user_agent_advertises_channels("q21:0.4"));
        assert!(!user_agent_advertises_channels("q21:0.3"));
    }

    #[test]
    fn round_trip_on_all_simple_messages() {
        round_trip(Message::VerAck);
        round_trip(Message::GetAddr);
        round_trip(Message::Ping(0x0123_4567_89ab_cdef));
        round_trip(Message::Pong(1));
        round_trip(Message::Version {
            version: PROTOCOL_VERSION,
            timestamp: 1_755_000_000,
            nonce: 0xdead_beef,
            user_agent: "q21:0.2".into(),
            start_height: 12_345,
        });
        round_trip(Message::Reject {
            command: "tx".into(),
            reason: "fee too low".into(),
        });
    }

    #[test]
    fn round_trip_on_inventories() {
        let v = vec![
            InvItem {
                kind: InvKind::Tx,
                hash: Hash256([9u8; 32]),
            },
            InvItem {
                kind: InvKind::Block,
                hash: Hash256([8u8; 32]),
            },
            InvItem {
                kind: InvKind::CompactBlock,
                hash: Hash256([7u8; 32]),
            },
        ];
        round_trip(Message::Inv(v.clone()));
        round_trip(Message::GetData(v));
    }

    #[test]
    fn round_trip_on_headers_and_locators() {
        round_trip(Message::Headers(vec![header(), header()]));
        round_trip(Message::GetHeaders {
            locator: vec![Hash256([1u8; 32]), Hash256([2u8; 32])],
            stop: Hash256::ZERO,
        });
    }

    #[test]
    fn round_trip_on_addresses() {
        round_trip(Message::Addr(vec![
            NetAddr {
                ip: [127, 0, 0, 1],
                port: 21_021,
                last_seen: 1_755_000_000,
            },
            NetAddr {
                ip: [10, 0, 0, 5],
                port: 8_333,
                last_seen: 0,
            },
        ]));
    }

    #[test]
    fn round_trip_on_snapshot_messages() {
        round_trip(Message::GetSnapshot);
        round_trip(Message::SnapshotInfo {
            height: 98_993,
            tip: Hash256([0x11; 32]),
            commitment: Hash256([0x22; 32]),
            size: 54_321_000,
            chunks: 52,
        });
        round_trip(Message::GetSnapshotChunk { index: 7 });
        round_trip(Message::SnapshotChunk {
            index: 7,
            data: vec![0xcd; 4096],
        });
        round_trip(Message::SnapshotChunk {
            index: 0,
            data: Vec::new(),
        });
    }

    #[test]
    fn round_trip_on_block_transaction_requests() {
        round_trip(Message::GetBlockTxn {
            block: Hash256([5u8; 32]),
            indices: vec![0, 1, 300, 70_000],
        });
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let frame = Message::VerAck.frame(MAGIC);
        let other = crate::consensus::NETWORK_MAGIC_MAINNET;
        assert!(matches!(
            Message::parse(&frame, other),
            Err(WireError::UnknownMagic(_))
        ));
    }

    #[test]
    fn an_incomplete_frame_asks_to_read_more() {
        let frame = Message::Ping(1).frame(MAGIC);
        for cut in 0..frame.len() {
            assert!(
                matches!(
                    Message::parse(&frame[..cut], MAGIC),
                    Err(WireError::Incomplete)
                ),
                "a cut at {cut} should have returned Incomplete"
            );
        }
        assert!(Message::parse(&frame, MAGIC).is_ok());
    }

    #[test]
    fn a_corrupted_payload_is_detected() {
        let mut frame = Message::Ping(1).frame(MAGIC);
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        assert_eq!(Message::parse(&frame, MAGIC), Err(WireError::BadChecksum));
    }

    /// The payload bound frames the largest valid message, without the double
    /// margin that made us decode 8 MiB only to reject it afterwards. Checked at
    /// compile time: a full block passes, and so does a compact block that
    /// would prefill all of its transactions (six bytes of short identifier
    /// per transaction); but we never decode more than a block and a quarter
    /// for nothing.
    const _: () = assert!(MAX_PAYLOAD >= MAX_BLOCK_SIZE + 6 * MAX_BLOCK_TXN);
    const _: () = assert!(MAX_PAYLOAD <= MAX_BLOCK_SIZE + MAX_BLOCK_SIZE / 4);

    /// The check that prevents a stranger from making us allocate gigabytes.
    #[test]
    fn an_absurd_payload_is_rejected_without_waiting_for_the_bytes() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        frame.extend_from_slice(&u32::MAX.to_le_bytes());
        frame.extend_from_slice(&[0u8; 4]);
        assert!(matches!(
            Message::parse(&frame, MAGIC),
            Err(WireError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn an_absurd_inventory_is_rejected_before_allocation() {
        let mut payload = Writer::new();
        payload.varint(MAX_INV as u64 + 1);
        let payload = payload.finish();
        let checksum = sha256(&payload);

        let mut frame = Vec::new();
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(b"inv\0\0\0\0\0\0\0\0\0");
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&checksum[..4]);
        frame.extend_from_slice(&payload);

        assert!(matches!(
            Message::parse(&frame, MAGIC),
            Err(WireError::TooManyElements { .. })
        ));
    }

    #[test]
    fn an_unknown_command_is_reported_without_panicking() {
        let payload: Vec<u8> = vec![];
        let checksum = sha256(&payload);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(b"nonexistent\0");
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&checksum[..4]);
        assert!(matches!(
            Message::parse(&frame, MAGIC),
            Err(WireError::UnknownCommand(_))
        ));
    }

    #[test]
    fn a_nonzero_command_padding_is_rejected() {
        let payload: Vec<u8> = vec![];
        let checksum = sha256(&payload);
        let mut frame = Vec::new();
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(b"ping\0X\0\0\0\0\0\0");
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&checksum[..4]);
        assert_eq!(
            Message::parse(&frame, MAGIC),
            Err(WireError::InvalidCommand)
        );
    }

    /// No input, however twisted, must stop the node.
    #[test]
    fn no_random_input_causes_a_panic() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        for _ in 0..3_000 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let n = (seed % 200) as usize;
            let mut raw = Vec::with_capacity(n + 4);
            raw.extend_from_slice(&MAGIC);
            let mut g = seed;
            for _ in 0..n {
                g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                raw.push((g >> 33) as u8);
            }
            // Must never panic, whatever the result.
            let _ = Message::parse(&raw, MAGIC);
        }
    }

    #[test]
    fn two_consecutive_messages_are_read_one_after_the_other() {
        let mut stream = Message::Ping(1).frame(MAGIC);
        stream.extend_from_slice(&Message::Pong(2).frame(MAGIC));

        let (a, n) = Message::parse(&stream, MAGIC).unwrap();
        assert_eq!(a, Message::Ping(1));
        let (b, m) = Message::parse(&stream[n..], MAGIC).unwrap();
        assert_eq!(b, Message::Pong(2));
        assert_eq!(n + m, stream.len());
    }

    #[test]
    fn onion_addresses_round_trip_and_bad_ones_are_refused() {
        let good = OnionAddr {
            name: format!("{}d", "a2".repeat(27) + "z"),
            port: 21121,
            last_seen: 7,
        };
        let m = Message::OnionAddr(vec![good.clone()]);
        let frame = m.frame(MAGIC);
        let (back, _) = Message::parse(&frame, MAGIC).expect("parse");
        assert_eq!(back, m);
        assert_eq!(
            OnionAddr::parse(&format!("{}.onion:9", good.name.to_uppercase()), 1)
                .map(|a| (a.name, a.port)),
            Some((good.name.clone(), 9))
        );
        assert!(OnionAddr::parse("short.onion", 1).is_none());
        assert!(OnionAddr::parse(&format!("{}a.onion", "a".repeat(55)), 1).is_none());
        // A name with a character outside the alphabet does not decode.
        let mut bad = good.clone();
        bad.name = format!("{}1d", "a".repeat(54));
        let frame = Message::OnionAddr(vec![bad]).frame(MAGIC);
        assert!(Message::parse(&frame, MAGIC).is_err());
    }
}
