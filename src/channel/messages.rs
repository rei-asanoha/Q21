//! The wire messages two channel engines exchange, and their canonical
//! encoding.
//!
//! There is no peer I/O here: a separate layer carries the bytes. This module
//! defines the structs and a bounded, versioned, canonical codec so both
//! sides — written against this one file — agree on every byte. Every frame
//! begins with a version byte and a type byte; decoding refuses a trailing
//! byte, an over-long field, or an unknown type, so one frame has one meaning.

use crate::channel::keys::CHANNEL_SCHEME;
use crate::hash::Hash256;
use crate::ser::{ReadError, Reader, Writer};

/// The codec version. A future change bumps it; a decoder refuses a version it
/// does not know rather than guess.
pub const WIRE_VERSION: u8 = 1;

const T_OPEN: u8 = 1;
const T_ACCEPT: u8 = 2;
const T_FUNDING: u8 = 3;
const T_FUNDING_SIGNED: u8 = 4;
const T_READY: u8 = 5;
const T_UPDATE: u8 = 6;
const T_ACK: u8 = 7;
const T_REVOKE: u8 = 8;
const T_REESTABLISH: u8 = 9;
const T_CLOSE: u8 = 10;
const T_CLOSE_SIGNED: u8 = 11;
const T_ERROR: u8 = 12;
const T_CHALLENGE: u8 = 13;

/// Most announced revocation hashes a message may carry. A channel announces
/// the next one or two points ahead; a larger count is a malformed frame.
pub const MAX_ANNOUNCED_HASHES: usize = 8;
/// Longest error string accepted, in bytes.
pub const MAX_ERROR_LEN: usize = 256;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WireError {
    Read(ReadError),
    UnknownVersion(u8),
    UnknownType(u8),
    /// A length-prefixed field exceeds its bound.
    FieldTooLong,
    /// A signature or key field is not its scheme's length.
    BadCryptoLength,
    /// A tier count other than three.
    BadTierCount,
}

impl From<ReadError> for WireError {
    fn from(e: ReadError) -> Self {
        WireError::Read(e)
    }
}

/// A revocation: the secret of a now-abandoned state, and the hash of a future
/// state announced ahead.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Revocation {
    /// The secret revoking a state; its SHA-256 is the announced point.
    pub secret: [u8; 32],
    /// The newly announced point, two states ahead.
    pub next_hash: Hash256,
}

/// Signatures of one commitment state at the three fee tiers.
pub type TierSigs = [Vec<u8>; 3];

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Message {
    /// Funder → acceptor: proposes a channel.
    Open {
        capacity: u64,
        delay: u16,
        funding_depth: u16,
        funder_pubkey: Vec<u8>,
        first_hashes: Vec<Hash256>,
    },
    /// Acceptor → funder: accepts, with its own key and first points.
    Accept {
        acceptor_pubkey: Vec<u8>,
        first_hashes: Vec<Hash256>,
    },
    /// Funder → acceptor: the funding outpoint and the funder's signatures of
    /// the acceptor's first commitment (all tiers).
    Funding {
        funding_txid: Hash256,
        funding_index: u32,
        tier_sigs: TierSigs,
    },
    /// Acceptor → funder: the acceptor's signatures of the funder's first
    /// commitment (all tiers). The funder may now broadcast the funding.
    FundingSigned { tier_sigs: TierSigs },
    /// Either side, once the funding is buried to the agreed depth.
    Ready,
    /// Initiator → responder: a new state, with the initiator's signatures of
    /// the responder's commitment at that state (all tiers).
    Update {
        state: u64,
        balances: [u64; 2],
        tier_sigs: TierSigs,
    },
    /// Responder → initiator: the responder's signatures of the initiator's
    /// commitment at the new state, and the revocation of the previous one.
    Ack {
        state: u64,
        tier_sigs: TierSigs,
        revocation: Revocation,
    },
    /// Initiator → responder: the initiator's revocation of the previous state.
    Revoke { state: u64, revocation: Revocation },
    /// On reconnection, answering a [`Message::Challenge`]: where this side
    /// stands, the challenge's nonce, and a proof of the funding key over
    /// `(channel_id, nonce, direction)`.
    Reestablish {
        channel_id: Hash256,
        local_commit_number: u64,
        remote_commit_number: u64,
        /// Highest state this side has revealed its secret for, plus one
        /// (`0` means none revealed yet).
        next_revocation_sent: u64,
        /// Highest revocation received from the peer, plus one.
        next_revocation_recv: u64,
        nonce: [u8; 32],
        /// `0` if the sender is the funder, `1` if the acceptor.
        direction: u8,
        proof: Vec<u8>,
    },
    /// A request to close cooperatively at the current balance, with the fee
    /// the sender proposes.
    Close { fee: u64 },
    /// The sender's signature of the agreed cooperative close.
    CloseSigned { fee: u64, signature: Vec<u8> },
    /// An abort, with a short reason. The channel moves to force-close.
    Error { reason: String },
    /// On a new connection: a fresh nonce the receiver must sign, with its
    /// funding key, in the [`Message::Reestablish`] it answers with. Issued by
    /// the side that wants the connection authenticated, so a captured
    /// reestablish never answers a later challenge.
    Challenge {
        channel_id: Hash256,
        nonce: [u8; 32],
    },
}

/// The deterministic tie-break for simultaneous updates: the party whose
/// funding-pubkey hash is lexicographically smaller keeps the initiative; the
/// other withdraws its update and retries. Returns the winning party index.
pub fn initiative(funding_hashes: &[Hash256; 2]) -> usize {
    if funding_hashes[0].0 <= funding_hashes[1].0 {
        0
    } else {
        1
    }
}

fn write_crypto(w: &mut Writer, field: &[u8]) {
    w.var_bytes(field);
}

fn read_pubkey(r: &mut Reader<'_>) -> Result<Vec<u8>, WireError> {
    let b = read_bounded(r, CHANNEL_SCHEME.pubkey_len())?;
    if b.len() != CHANNEL_SCHEME.pubkey_len() {
        return Err(WireError::BadCryptoLength);
    }
    Ok(b)
}

fn read_sig(r: &mut Reader<'_>) -> Result<Vec<u8>, WireError> {
    let b = read_bounded(r, CHANNEL_SCHEME.sig_len())?;
    if b.len() != CHANNEL_SCHEME.sig_len() {
        return Err(WireError::BadCryptoLength);
    }
    Ok(b)
}

fn read_bounded(r: &mut Reader<'_>, max: usize) -> Result<Vec<u8>, WireError> {
    let b = r.var_bytes()?;
    if b.len() > max {
        return Err(WireError::FieldTooLong);
    }
    Ok(b.to_vec())
}

fn write_hashes(w: &mut Writer, hs: &[Hash256]) {
    w.varint(hs.len() as u64);
    for h in hs {
        w.bytes(h.as_bytes());
    }
}

fn read_hashes(r: &mut Reader<'_>) -> Result<Vec<Hash256>, WireError> {
    let n = r.read_count(32)?;
    if n > MAX_ANNOUNCED_HASHES {
        return Err(WireError::FieldTooLong);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(Hash256(r.array32()?));
    }
    Ok(out)
}

fn write_tier_sigs(w: &mut Writer, sigs: &TierSigs) {
    w.u8(3);
    for s in sigs {
        write_crypto(w, s);
    }
}

fn read_tier_sigs(r: &mut Reader<'_>) -> Result<TierSigs, WireError> {
    if r.u8()? != 3 {
        return Err(WireError::BadTierCount);
    }
    Ok([read_sig(r)?, read_sig(r)?, read_sig(r)?])
}

fn write_revocation(w: &mut Writer, rev: &Revocation) {
    w.bytes(&rev.secret);
    w.bytes(rev.next_hash.as_bytes());
}

fn read_revocation(r: &mut Reader<'_>) -> Result<Revocation, WireError> {
    let secret = r.array32()?;
    let next_hash = Hash256(r.array32()?);
    Ok(Revocation { secret, next_hash })
}

impl Message {
    /// The canonical byte encoding, version and type byte first.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.u8(WIRE_VERSION);
        match self {
            Message::Open {
                capacity,
                delay,
                funding_depth,
                funder_pubkey,
                first_hashes,
            } => {
                w.u8(T_OPEN).u64(*capacity);
                w.bytes(&delay.to_le_bytes());
                w.bytes(&funding_depth.to_le_bytes());
                write_crypto(&mut w, funder_pubkey);
                write_hashes(&mut w, first_hashes);
            }
            Message::Accept {
                acceptor_pubkey,
                first_hashes,
            } => {
                w.u8(T_ACCEPT);
                write_crypto(&mut w, acceptor_pubkey);
                write_hashes(&mut w, first_hashes);
            }
            Message::Funding {
                funding_txid,
                funding_index,
                tier_sigs,
            } => {
                w.u8(T_FUNDING).bytes(funding_txid.as_bytes());
                w.u32(*funding_index);
                write_tier_sigs(&mut w, tier_sigs);
            }
            Message::FundingSigned { tier_sigs } => {
                w.u8(T_FUNDING_SIGNED);
                write_tier_sigs(&mut w, tier_sigs);
            }
            Message::Ready => {
                w.u8(T_READY);
            }
            Message::Update {
                state,
                balances,
                tier_sigs,
            } => {
                w.u8(T_UPDATE).u64(*state).u64(balances[0]).u64(balances[1]);
                write_tier_sigs(&mut w, tier_sigs);
            }
            Message::Ack {
                state,
                tier_sigs,
                revocation,
            } => {
                w.u8(T_ACK).u64(*state);
                write_tier_sigs(&mut w, tier_sigs);
                write_revocation(&mut w, revocation);
            }
            Message::Revoke { state, revocation } => {
                w.u8(T_REVOKE).u64(*state);
                write_revocation(&mut w, revocation);
            }
            Message::Reestablish {
                channel_id,
                local_commit_number,
                remote_commit_number,
                next_revocation_sent,
                next_revocation_recv,
                nonce,
                direction,
                proof,
            } => {
                w.u8(T_REESTABLISH).bytes(channel_id.as_bytes());
                w.u64(*local_commit_number)
                    .u64(*remote_commit_number)
                    .u64(*next_revocation_sent)
                    .u64(*next_revocation_recv);
                w.bytes(nonce).u8(*direction);
                write_crypto(&mut w, proof);
            }
            Message::Close { fee } => {
                w.u8(T_CLOSE).u64(*fee);
            }
            Message::CloseSigned { fee, signature } => {
                w.u8(T_CLOSE_SIGNED).u64(*fee);
                write_crypto(&mut w, signature);
            }
            Message::Challenge { channel_id, nonce } => {
                w.u8(T_CHALLENGE).bytes(channel_id.as_bytes()).bytes(nonce);
            }
            Message::Error { reason } => {
                let bytes = reason.as_bytes();
                let bytes = &bytes[..bytes.len().min(MAX_ERROR_LEN)];
                w.u8(T_ERROR).var_bytes(bytes);
            }
        }
        w.finish()
    }

    /// Decodes a frame, refusing anything non-canonical.
    pub fn decode(data: &[u8]) -> Result<Message, WireError> {
        let mut r = Reader::new(data);
        let version = r.u8()?;
        if version != WIRE_VERSION {
            return Err(WireError::UnknownVersion(version));
        }
        let msg = match r.u8()? {
            T_OPEN => {
                let capacity = r.u64()?;
                let delay = u16::from_le_bytes([r.u8()?, r.u8()?]);
                let funding_depth = u16::from_le_bytes([r.u8()?, r.u8()?]);
                let funder_pubkey = read_pubkey(&mut r)?;
                let first_hashes = read_hashes(&mut r)?;
                Message::Open {
                    capacity,
                    delay,
                    funding_depth,
                    funder_pubkey,
                    first_hashes,
                }
            }
            T_ACCEPT => Message::Accept {
                acceptor_pubkey: read_pubkey(&mut r)?,
                first_hashes: read_hashes(&mut r)?,
            },
            T_FUNDING => {
                let funding_txid = Hash256(r.array32()?);
                let funding_index = r.u32()?;
                let tier_sigs = read_tier_sigs(&mut r)?;
                Message::Funding {
                    funding_txid,
                    funding_index,
                    tier_sigs,
                }
            }
            T_FUNDING_SIGNED => Message::FundingSigned {
                tier_sigs: read_tier_sigs(&mut r)?,
            },
            T_READY => Message::Ready,
            T_UPDATE => {
                let state = r.u64()?;
                let balances = [r.u64()?, r.u64()?];
                let tier_sigs = read_tier_sigs(&mut r)?;
                Message::Update {
                    state,
                    balances,
                    tier_sigs,
                }
            }
            T_ACK => {
                let state = r.u64()?;
                let tier_sigs = read_tier_sigs(&mut r)?;
                let revocation = read_revocation(&mut r)?;
                Message::Ack {
                    state,
                    tier_sigs,
                    revocation,
                }
            }
            T_REVOKE => Message::Revoke {
                state: r.u64()?,
                revocation: read_revocation(&mut r)?,
            },
            T_REESTABLISH => {
                let channel_id = Hash256(r.array32()?);
                let local_commit_number = r.u64()?;
                let remote_commit_number = r.u64()?;
                let next_revocation_sent = r.u64()?;
                let next_revocation_recv = r.u64()?;
                let nonce = r.array32()?;
                let direction = r.u8()?;
                let proof = read_sig(&mut r)?;
                Message::Reestablish {
                    channel_id,
                    local_commit_number,
                    remote_commit_number,
                    next_revocation_sent,
                    next_revocation_recv,
                    nonce,
                    direction,
                    proof,
                }
            }
            T_CLOSE => Message::Close { fee: r.u64()? },
            T_CLOSE_SIGNED => {
                let fee = r.u64()?;
                let signature = read_sig(&mut r)?;
                Message::CloseSigned { fee, signature }
            }
            T_CHALLENGE => Message::Challenge {
                channel_id: Hash256(r.array32()?),
                nonce: r.array32()?,
            },
            T_ERROR => {
                let bytes = read_bounded(&mut r, MAX_ERROR_LEN)?;
                Message::Error {
                    reason: String::from_utf8_lossy(&bytes).into_owned(),
                }
            }
            other => return Err(WireError::UnknownType(other)),
        };
        r.expect_end()?;
        Ok(msg)
    }
}
