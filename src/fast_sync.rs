//! Fast sync snapshot: the package a peer sends to a newcomer to spare it from
//! revalidating everything.
//!
//! # Two meanings that used to share one word
//!
//! The [`crate::bootstrap`] module deals with bootstrap in the sense of *how
//! one gets into a network* — the first peers to talk to. Here, the sync
//! snapshot is the **fast sync package**: the ready-made state a peer sends so
//! that the newcomer does not have to revalidate the whole history. Up to
//! 0.3.x the two shared a name because that is what users called them; they
//! share nothing else.
//!
//! # What it contains
//!
//! The same three pieces as the file-based sync snapshot (`q21 snapshot
//! export-sync`), gathered into a single byte stream to travel over the
//! network:
//!
//! - the **portable snapshot** — the UTXO set at a height H, with its
//!   commitment;
//! - the **headers** from the genesis to H — the header chain that an adopted
//!   node cannot rebuild, lacking the bodies from before H;
//! - a **bounded window of bodies** around H — the genesis, then the few
//!   blocks preceding H, which the uncle double payment rule needs on replay.
//!
//! # What it is not
//!
//! It does not carry its own trust. Whoever receives it **must** check its
//! commitment against a trusted value — the one obtained from an explorer,
//! passed on the command line. A peer that sends a sync snapshot is a source of
//! convenience, never of authority: see [`crate::chain::Chain::adopt_snapshot`].
//!
//! # Transport
//!
//! A snapshot can exceed the maximum size of a message ([`crate::wire`]). The
//! sync snapshot therefore travels **in chunks**: it is serialized once, then
//! cut into pieces sent independently and reassembled on arrival. This module
//! defines the package and its (de)coding; the chunking and the exchange belong
//! to the network layer.

use crate::address::Network;
use crate::block::{Block, BlockHeader};
use crate::hash::Hash256;
use crate::ser::{ReadError, Reader, Writer};
use crate::wire::{Message, WireError, HEADER_LEN, MAX_PAYLOAD, PROTOCOL_VERSION};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Frozen format magic (binary file format).
const MAGIC: &[u8; 8] = b"Q21SNAPS";
const VERSION: u32 = 1;

/// Size of a transfer chunk.
///
/// Below the maximum size of a message (8 MiB) and below the node's response
/// budget (4 MiB): a chunk that would not fit in a message would be a one-way
/// waste.
pub const CHUNK_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Anchors compiled into the binary
// ---------------------------------------------------------------------------

/// A point of the chain held to be true, **written into the binary itself**.
///
/// # Why this exists
///
/// Adopting a sync snapshot relies on a tip and a commitment that the operator
/// copies from a source they believe to be trustworthy. It is a human link: a
/// spoofed explorer, an interception, a malicious mirror or a mere typo are
/// enough to break it. Rechecking the work already makes the attack costly —
/// the work of the whole chain has to be redone — but it does not make it
/// impossible for someone holding a lot of power.
///
/// A compiled anchor closes that door for good, at the heights it covers: the
/// value no longer comes from a website, it comes from the **software the user
/// already runs**, reviewed by anyone who reads the repository. This is
/// Bitcoin's answer to the same question, and it is faithful to the philosophy
/// of Q21: it is not an authority that decides, it is a public value that
/// everyone can check and dispute before it is published.
///
/// # How to add one
///
/// 1. On a full node **whose whole chain you validated yourself**:
///    `q21 snapshot export-sync <folder> --network <name>` prints the height,
///    the tip and the commitment.
/// 2. Have these three values confirmed by several people, on independent
///    nodes. An anchor that only one person has seen is worth no more than
///    that person's word.
/// 3. Write them here, in the table of the network concerned, and publish the
///    change for review.
///
/// An anchor is never removed or modified: it describes a past fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub height: u64,
    pub tip: Hash256,
    pub commitment: Hash256,
}

/// The known anchors of the network, in increasing height order.
///
/// The tables are **empty as long as no value has been confirmed
/// independently**: writing in an unchecked value would be worse than writing
/// none, since it would carry the authority of the binary without having
/// earned the trust. An empty table weakens nothing — the recheck of the work
/// applies anyway.
pub fn builtin_anchors(network: Network) -> &'static [Anchor] {
    match network {
        Network::Mainnet => &[],
        Network::Testnet => &[],
        Network::Regtest => &[],
    }
}

/// Checks that the bodies of a sync snapshot really are the ones its headers
/// designate, before a single byte reaches the disk.
///
/// # What this closes
///
/// Adoption rechecked the work of the headers and the commitment of the
/// snapshot, then wrote the bodies **as is**. A sync snapshot server could
/// therefore deliver the real headers, the real snapshot — and arbitrary
/// bodies: the node stored them, served them to its peers, and ran into them
/// at the first reorg near the tip. It only got out of it by erasing its
/// directory.
///
/// Each body must: have a valid shape (Merkle roots recomputed and matching),
/// carry the identifier of the header at the same height in the list, and the
/// genesis must be that of the network. Two bodies for the same height are
/// refused.
pub fn check_bodies(
    network: Network,
    headers: &[BlockHeader],
    bodies: &[Block],
) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(bodies.len());
    for b in bodies {
        let h = b.header.height;
        let expected = headers
            .get(h as usize)
            .filter(|e| e.height == h)
            .ok_or_else(|| format!("a body at height {h} has no header in the sync snapshot"))?;
        let id = b.header.block_id();
        if id != expected.block_id() {
            return Err(format!(
                "the body at height {h} does not match the header of the sync snapshot"
            ));
        }
        if !seen.insert(id) {
            return Err(format!("two bodies for height {h}"));
        }
        b.check_shape()
            .map_err(|e| format!("malformed body at height {h}: {e:?}"))?;
        if h == 0 && id != crate::chain::genesis_id(network) {
            return Err("the genesis of the sync snapshot is not that of this network".to_string());
        }
    }
    Ok(())
}

/// Ceiling of the full download of a sync snapshot, on the client side. Same
/// bound as decoding: enough to hold a very large UTXO set, never infinity.
const MAX_SYNC_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Safety bounds when reading: a sync snapshot comes from a peer, hence from a
/// stranger. No allocation is dictated by what it announces.
const MAX_HEADERS: usize = 5_000_000;
const MAX_BODIES: usize = 100_000;
/// A serialized body cannot exceed the size of a block.
const MAX_BODY_BYTES: usize = crate::consensus::MAX_BLOCK_SIZE;
/// A serialized snapshot, generous bound: enough to hold a very large UTXO set
/// without ever reserving infinity.
const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum SyncSnapshotError {
    Magic,
    /// A sync snapshot exported by 0.3.x, whose state commitment 0.4 no
    /// longer computes.
    Legacy,
    Version(u32),
    TooManyElements {
        max: usize,
        received: usize,
    },
    Read(ReadError),
}

impl From<ReadError> for SyncSnapshotError {
    fn from(e: ReadError) -> Self {
        SyncSnapshotError::Read(e)
    }
}

impl std::fmt::Display for SyncSnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncSnapshotError::Magic => write!(f, "this stream is not a Q21 sync snapshot"),
            SyncSnapshotError::Legacy => write!(
                f,
                "this sync snapshot was exported by q21 0.3.x, whose state commitment 0.4 \
                 no longer computes: export it again with `q21 snapshot export-sync` from a 0.4 node"
            ),
            SyncSnapshotError::Version(v) => write!(f, "sync snapshot version {v}, unknown"),
            SyncSnapshotError::TooManyElements { max, received } => {
                write!(f, "{received} elements announced, {max} at most: refused")
            }
            SyncSnapshotError::Read(e) => write!(f, "unreadable sync snapshot: {e:?}"),
        }
    }
}

/// The sync snapshot package, as it travels.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncSnapshot {
    /// The portable snapshot, already serialized (it carries its own commitment
    /// and its checksum).
    pub snapshot: Vec<u8>,
    /// The headers, from the genesis to the snapshot height.
    pub headers: Vec<BlockHeader>,
    /// The window of bodies: the genesis, then the blocks around the snapshot.
    pub bodies: Vec<Block>,
}

impl SyncSnapshot {
    /// Serializes the package into a single byte stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(MAGIC);
        w.u32(VERSION);
        w.var_bytes(&self.snapshot);
        w.varint(self.headers.len() as u64);
        for h in &self.headers {
            w.bytes(&h.encode());
        }
        w.varint(self.bodies.len() as u64);
        for b in &self.bodies {
            w.var_bytes(&b.encode());
        }
        w.finish()
    }

    /// Reads back a sync snapshot package, bounding everything before
    /// allocating.
    ///
    /// Checks **neither** the commitment **nor** the trust: it is only a
    /// decoding. Adoption is what checks the commitment against a trusted
    /// value.
    pub fn decode(data: &[u8]) -> Result<SyncSnapshot, SyncSnapshotError> {
        let mut r = Reader::new(data);
        let mut magic = [0u8; 8];
        for o in &mut magic {
            *o = r.u8()?;
        }
        if &magic == crate::legacy::LEGACY_SNAPSHOT_MAGIC {
            return Err(SyncSnapshotError::Legacy);
        }
        if &magic != MAGIC {
            return Err(SyncSnapshotError::Magic);
        }
        let version = r.u32()?;
        if version != VERSION {
            return Err(SyncSnapshotError::Version(version));
        }

        let snapshot = r.var_bytes()?;
        if snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(SyncSnapshotError::TooManyElements {
                max: MAX_SNAPSHOT_BYTES,
                received: snapshot.len(),
            });
        }

        // Each header takes a known fixed size: we never reserve more slots
        // than the rest of the stream can hold.
        let n = bounded_count(&mut r, MAX_HEADERS, BlockHeader::SIZE)?;
        // Same guard as for the bodies below: we never preallocate more than a
        // few thousand slots at once, even if the stream announces millions.
        // The loop grows as needed; a peer cannot make us reserve hundreds of
        // megabytes on an announcement.
        let mut headers = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let mut buf = [0u8; BlockHeader::SIZE];
            for o in buf.iter_mut() {
                *o = r.u8()?;
            }
            headers.push(BlockHeader::decode(&buf)?);
        }

        // A body takes at least ten bytes on the wire.
        let n = bounded_count(&mut r, MAX_BODIES, 10)?;
        let mut bodies = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let raw = r.var_bytes()?;
            if raw.len() > MAX_BODY_BYTES {
                return Err(SyncSnapshotError::TooManyElements {
                    max: MAX_BODY_BYTES,
                    received: raw.len(),
                });
            }
            bodies.push(
                Block::decode(raw).map_err(|_| SyncSnapshotError::Read(ReadError::InvalidValue))?,
            );
        }

        r.expect_end()?;
        Ok(SyncSnapshot {
            snapshot: snapshot.to_vec(),
            headers,
            bodies,
        })
    }

    /// The commitment of the snapshot, read at its position without decoding
    /// the whole UTXO set.
    ///
    /// The portable snapshot stores (magic, version, network, height, tip,
    /// issued, MuHash, ...). We read the total issued and the MuHash at their
    /// offsets and derive the state commitment from them
    /// ([`crate::state::state_commitment`]), which lets a peer announce the
    /// commitment of its sync snapshot without fully deserializing it. It is
    /// the same value as [`crate::state::Snapshot::commitment`] on the decoded
    /// snapshot.
    pub fn announced_commitment(&self) -> Option<Hash256> {
        // magic(8) + version(4) + network(1) + height(8) + tip(32)
        const ISSUED_OFFSET: usize = 8 + 4 + 1 + 8 + 32;
        const MUHASH_OFFSET: usize = ISSUED_OFFSET + 8;
        let issued = self
            .snapshot
            .get(ISSUED_OFFSET..ISSUED_OFFSET + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))?;
        let muhash = self
            .snapshot
            .get(MUHASH_OFFSET..MUHASH_OFFSET + 32)
            .map(|s| Hash256(s.try_into().unwrap()))?;
        Some(crate::state::state_commitment(muhash, issued))
    }

    /// The height of the snapshot, read at its position.
    pub fn announced_height(&self) -> Option<u64> {
        const OFFSET: usize = 8 + 4 + 1;
        self.snapshot
            .get(OFFSET..OFFSET + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }

    /// The tip of the snapshot, read at its position.
    pub fn announced_tip(&self) -> Option<Hash256> {
        const OFFSET: usize = 8 + 4 + 1 + 8;
        self.snapshot
            .get(OFFSET..OFFSET + 32)
            .map(|s| Hash256(s.try_into().unwrap()))
    }
}

/// Number of chunks for a sync snapshot of `size` bytes.
pub fn chunk_count(size: usize) -> u32 {
    size.div_ceil(CHUNK_SIZE) as u32
}

/// Chunk number `index` of the bytes of a sync snapshot, or empty if the index
/// is out of range.
pub fn chunk(bytes: &[u8], index: u32) -> &[u8] {
    let start = (index as usize).saturating_mul(CHUNK_SIZE);
    if start >= bytes.len() {
        return &[];
    }
    let end = (start + CHUNK_SIZE).min(bytes.len());
    &bytes[start..end]
}

// ---------------------------------------------------------------------------
// Client: downloading a sync snapshot from a peer
// ---------------------------------------------------------------------------

/// Downloads a sync snapshot from a peer, reassembles it, and **checks its
/// commitment** against the trusted value supplied by the operator.
///
/// # The trust model, restated here
///
/// The peer supplies the bytes; it does not supply the trust. A sync snapshot
/// whose announced commitment — then the commitment of the reassembled package
/// — does not match `expected_commitment` is **rejected**: the peer is set
/// aside, nothing is adopted. It is up to the caller to try another peer.
/// `expected_commitment` comes from the operator (the commitment their explorer
/// displays), never from the peer.
///
/// # Bounds
///
/// Each read has a timeout, and the whole has a global deadline: a peer that
/// trickles out the bytes cannot hold the client forever. The total size is
/// capped before any reservation.
pub fn download_sync_snapshot(
    address: SocketAddr,
    magic: [u8; 4],
    local_height: u64,
    expected_commitment: Hash256,
    read_timeout: Duration,
    total_timeout: Duration,
) -> Result<SyncSnapshot, String> {
    let deadline = Instant::now() + total_timeout;
    let mut stream = TcpStream::connect_timeout(&address, read_timeout)
        .map_err(|e| format!("cannot connect to {address}: {e}"))?;
    let _ = stream.set_read_timeout(Some(read_timeout));
    let _ = stream.set_write_timeout(Some(read_timeout));
    let _ = stream.set_nodelay(true);

    // Handshake: we speak first, then seal it with a verack — that is what, on
    // the peer's side, opens access to the expensive messages.
    send(&mut stream, magic, &handshake(local_height))?;
    send(&mut stream, magic, &Message::VerAck)?;
    send(&mut stream, magic, &Message::GetSnapshot)?;

    let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);

    // We wait for the metadata, answering pings and ignoring the rest (the peer
    // may try to sync us in parallel: that is not what we came for).
    let (size, chunks, commitment) = loop {
        match read_message(&mut stream, &mut buffer, magic, deadline)? {
            Message::SnapshotInfo {
                size,
                chunks,
                commitment,
                ..
            } => break (size as usize, chunks, commitment),
            Message::Ping(n) => send(&mut stream, magic, &Message::Pong(n))?,
            Message::Reject { reason, .. } => return Err(format!("the peer refuses: {reason}")),
            _ => {}
        }
    };

    if commitment != expected_commitment {
        return Err(format!(
            "announced commitment {commitment} differs from the trusted value \
             {expected_commitment}: this peer is set aside"
        ));
    }
    if size > MAX_SYNC_SNAPSHOT_BYTES {
        return Err(format!("announced sync snapshot too large: {size} bytes"));
    }
    if chunk_count(size) != chunks {
        return Err("the chunk count does not match the size".into());
    }

    // We request the chunks in order, one by one.
    let mut bytes: Vec<u8> = Vec::with_capacity(size.min(64 * 1024 * 1024));
    for i in 0..chunks {
        send(&mut stream, magic, &Message::GetSnapshotChunk { index: i })?;
        loop {
            match read_message(&mut stream, &mut buffer, magic, deadline)? {
                Message::SnapshotChunk { index, data } if index == i => {
                    if bytes.len() + data.len() > size {
                        return Err("the peer sends more than the announced size".into());
                    }
                    bytes.extend_from_slice(&data);
                    break;
                }
                Message::Ping(n) => send(&mut stream, magic, &Message::Pong(n))?,
                _ => {}
            }
        }
    }

    if bytes.len() != size {
        return Err(format!(
            "received size {} differs from the announced {size}",
            bytes.len()
        ));
    }

    let sync_snapshot =
        SyncSnapshot::decode(&bytes).map_err(|e| format!("unreadable sync snapshot: {e}"))?;
    // Belt and braces: the commitment of the reassembled package must also
    // equal the trusted value.
    if sync_snapshot.announced_commitment() != Some(expected_commitment) {
        return Err("after reassembly, the commitment of the package no longer matches".into());
    }
    Ok(sync_snapshot)
}

fn handshake(height: u64) -> Message {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(1)
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    Message::Version {
        version: PROTOCOL_VERSION,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        nonce,
        user_agent: "q21:0.4".into(),
        start_height: height,
    }
}

fn send(stream: &mut TcpStream, magic: [u8; 4], m: &Message) -> Result<(), String> {
    stream
        .write_all(&m.frame(magic))
        .map_err(|e| format!("network write: {e}"))
}

/// Reads the next complete message, accumulating bytes. The buffer never grows
/// beyond one frame, and the global deadline cuts off a peer that trickles.
fn read_message(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    magic: [u8; 4],
    deadline: Instant,
) -> Result<Message, String> {
    loop {
        match Message::parse(buffer, magic) {
            Ok((m, n)) => {
                buffer.drain(..n);
                return Ok(m);
            }
            Err(WireError::Incomplete) => {}
            Err(e) => return Err(format!("invalid frame received: {e:?}")),
        }
        if Instant::now() >= deadline {
            return Err("global timeout exceeded during the download".into());
        }
        if buffer.len() > MAX_PAYLOAD + HEADER_LEN {
            return Err("frame larger than the protocol maximum".into());
        }
        let mut piece = [0u8; 32 * 1024];
        let read = stream
            .read(&mut piece)
            .map_err(|e| format!("network read: {e}"))?;
        if read == 0 {
            return Err("connection closed by the peer".into());
        }
        buffer.extend_from_slice(&piece[..read]);
    }
}

/// Reads a count, bounding it by the protocol maximum **and** by what the rest
/// of the stream can hold.
fn bounded_count(
    r: &mut Reader<'_>,
    max: usize,
    minimum: usize,
) -> Result<usize, SyncSnapshotError> {
    let n = r.varint()? as usize;
    if n > max {
        return Err(SyncSnapshotError::TooManyElements { max, received: n });
    }
    if let Some(fits) = r.remaining().checked_div(minimum) {
        if n > fits {
            return Err(SyncSnapshotError::TooManyElements {
                max: fits,
                received: n,
            });
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::genesis_block;
    use crate::Network;

    fn header(h: u64) -> BlockHeader {
        let mut e = genesis_block(Network::Regtest).header;
        e.height = h;
        e.nonce = h;
        e
    }

    fn sample_sync_snapshot() -> SyncSnapshot {
        SyncSnapshot {
            snapshot: vec![0xab; 300],
            headers: (0..5).map(header).collect(),
            bodies: vec![genesis_block(Network::Regtest)],
        }
    }

    /// The bodies are checked against the headers before any write: a foreign
    /// body, a tampered body, a genesis from another network, a duplicate — all
    /// refused; the real bodies pass.
    #[test]
    fn the_bodies_of_a_sync_snapshot_are_checked_against_its_headers() {
        use crate::chain::Chain;
        use crate::consensus::TARGET_BLOCK_SECS;
        use crate::sig::SchemeId;

        let network = Network::Regtest;
        let mut c = Chain::new(network, genesis_block(network));
        for _ in 0..4 {
            let t = c.tip().time + TARGET_BLOCK_SECS;
            let b = c
                .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }
        let headers = c.headers();
        let bodies: Vec<Block> = (0..=4).map(|h| c.block_at(h).unwrap()).collect();
        check_bodies(network, &headers, &bodies).expect("the real bodies pass");

        // A tampered body: same announced header, different contents.
        let mut tampered = bodies.clone();
        tampered[2].transactions[0].outputs[0].pubkey_hash = Hash256([9u8; 32]);
        assert!(check_bodies(network, &headers, &tampered).is_err());

        // A body whose header is not in the sync snapshot.
        let mut foreign = bodies.clone();
        foreign[3].header.nonce ^= 1;
        assert!(check_bodies(network, &headers, &foreign).is_err());

        // A duplicate.
        let mut double = bodies.clone();
        double.push(bodies[1].clone());
        assert!(check_bodies(network, &headers, &double).is_err());

        // A genesis from another network, with its headers.
        let other = genesis_block(Network::Testnet);
        assert!(check_bodies(network, &[other.header], &[other]).is_err());

        // A body beyond the supplied headers.
        assert!(check_bodies(network, &headers[..3], &bodies).is_err());
    }

    #[test]
    fn round_trip_on_a_sync_snapshot() {
        let a = sample_sync_snapshot();
        let b = SyncSnapshot::decode(&a.encode()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_sync_snapshot_without_bodies_round_trips() {
        let a = SyncSnapshot {
            snapshot: vec![1, 2, 3],
            headers: vec![header(0)],
            bodies: Vec::new(),
        };
        assert_eq!(SyncSnapshot::decode(&a.encode()).unwrap(), a);
    }

    #[test]
    fn a_stream_without_magic_is_refused() {
        assert_eq!(
            SyncSnapshot::decode(b"not a sync snapshot at all"),
            Err(SyncSnapshotError::Magic)
        );
    }

    /// A snapshot exported by 0.3.x is named as such, not as a foreign file:
    /// the operator learns what to do instead of doubting the download.
    #[test]
    fn a_snapshot_exported_by_0_3_is_recognized() {
        let mut raw = sample_sync_snapshot().encode();
        raw[..8].copy_from_slice(crate::legacy::LEGACY_SNAPSHOT_MAGIC);
        let e = SyncSnapshot::decode(&raw).unwrap_err();
        assert_eq!(e, SyncSnapshotError::Legacy);
        assert!(e.to_string().contains("export it again"), "{e}");
    }

    #[test]
    fn a_truncated_sync_snapshot_does_not_panic() {
        let raw = sample_sync_snapshot().encode();
        for cut in 0..raw.len() {
            // Must never panic: return an error, that is all.
            let _ = SyncSnapshot::decode(&raw[..cut]);
        }
    }

    #[test]
    fn an_absurd_header_count_is_refused_before_allocation() {
        let mut w = Writer::new();
        w.bytes(MAGIC);
        w.u32(VERSION);
        w.var_bytes(&[0u8; 4]);
        w.varint(u64::MAX); // announces billions of headers
        let raw = w.finish();
        assert!(matches!(
            SyncSnapshot::decode(&raw),
            Err(SyncSnapshotError::TooManyElements { .. })
        ));
    }

    #[test]
    fn the_announced_commitment_matches_the_snapshot() {
        use crate::state::Snapshot;
        use crate::utxo::UtxoSet;
        let height = 5_000;
        let utxo = UtxoSet::new();
        let muhash = utxo.commitment();
        let s = Snapshot {
            network: Network::Regtest,
            height,
            tip: Hash256([7u8; 32]),
            issued: crate::emission::total_supply_at(height).units(),
            utxo,
            muhash,
        };
        let commitment = s.commitment();
        let a = SyncSnapshot {
            snapshot: s.to_portable_bytes(),
            headers: vec![header(0)],
            bodies: Vec::new(),
        };
        assert_eq!(a.announced_commitment(), Some(commitment));
        // The announced commitment binds the total issued: a snapshot with the
        // same set but another total carries another one.
        let mut other = Snapshot::from_portable_bytes(&a.snapshot, Network::Regtest).unwrap();
        other.issued -= 1;
        let b = SyncSnapshot {
            snapshot: other.to_portable_bytes(),
            headers: vec![header(0)],
            bodies: Vec::new(),
        };
        assert_eq!(b.announced_commitment(), Some(other.commitment()));
        assert_ne!(b.announced_commitment(), Some(commitment));
        assert_eq!(
            other.muhash, muhash,
            "the MuHash, for its part, did not move"
        );
    }
}
