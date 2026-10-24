//! The per-channel append-only journal: the durable record of everything the
//! state machine must never lose across a crash.
//!
//! # The shape of the guarantee
//!
//! Each fact is a [`Record`] appended to one file, framed with its length and
//! a checksum, and the file is `fsync`ed before [`Journal::append`] returns. A
//! caller that waits for `append` to return therefore knows the record is on
//! stable storage before it does anything a crash could not take back — reveal
//! a secret, acknowledge an update, broadcast. That ordering is where the
//! safety invariants live (see [`crate::channel::machine`]).
//!
//! # Surviving a torn write
//!
//! A crash can stop a write anywhere. Replay reads records in order and stops
//! at the first whose frame is short or whose checksum does not match: that is
//! the half-written tail of the interrupted append, and everything before it
//! is intact. The truncation tests cut the file at every byte offset and check
//! that replay always yields a clean prefix of the records.
//!
//! The initial creation of the file uses the atomic tmp+fsync+rename+dir-fsync
//! dance ([`atomic_write`]), so a crash during creation leaves either no file
//! or a complete empty one, never a directory entry pointing at nothing.

use crate::channel::txbuild::ChannelParams;
use crate::hash::Hash256;
use crate::ser::{ReadError, Reader, Writer};
use crate::sha256::sha256;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// A balance pair, `[funder, acceptor]`.
pub type Balances = [u64; 2];

/// One durable fact. Appended in the order the machine must persist them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// The channel's parameters, written once at creation.
    Opened {
        channel_id: Hash256,
        /// Our own index: `0` funder, `1` acceptor.
        our_index: u8,
        funding: [Hash256; 2],
        capacity: u64,
        delay: u16,
        funding_depth: u16,
        our_pubkey: Vec<u8>,
        their_pubkey: Vec<u8>,
        /// Each party's wallet payout address, `[funder, acceptor]`, exchanged
        /// at open and used to build a cooperative close that pays spendable
        /// wallet outputs.
        payout: [Hash256; 2],
    },
    /// The funding outpoint is known (funding transaction built).
    Funded {
        funding_txid: Hash256,
        funding_index: u32,
    },
    /// We hold a counterparty-signed commitment at `state`: we can enforce it.
    /// The three tier signatures are the counterparty's, over our commitment.
    LocalCommit {
        state: u64,
        balances: Balances,
        their_tier_sigs: [Vec<u8>; 3],
    },
    /// We have signed the counterparty's commitment at `state`.
    RemoteCommit { state: u64, balances: Balances },
    /// We have revealed our revocation secret for `state`.
    RevocationSent { state: u64 },
    /// We hold the counterparty's revocation secret for `state`.
    RevocationRecv { state: u64, secret: [u8; 32] },
    /// The counterparty announced its revocation point for `state`. Persisted
    /// so a resend after a crash can rebuild the counterparty's commitment.
    TheirPoint { state: u64, point: Hash256 },
    /// The funding is buried to the agreed depth; the channel is open.
    Ready,
    /// A cooperative close was agreed at `fee`, charged to the funder (the
    /// record of journals written before the payer was recorded).
    ClosingCoop { fee: u64 },
    /// A cooperative close was agreed at `fee`, charged to `payer` — the
    /// party that proposed it.
    ClosingCoopBy { fee: u64, payer: u8 },
    /// We moved to force-close (we or the peer will broadcast a commitment).
    Forcing,
    /// We punished a revoked broadcast.
    Penalised,
    /// The channel is settled on chain.
    Closed,
    /// The counterparty's revealed secrets in compact form, written by a
    /// compaction in place of every [`Record::RevocationRecv`]: the highest
    /// revoked state and the few shachain entries that derive every secret
    /// revealed so far (see [`crate::shachain::Store::entries`]).
    Revocations {
        state: u64,
        entries: Vec<([u8; 32], u64)>,
    },
    /// The block height at which the funding transaction confirmed: where a
    /// restarted node starts looking for a spend of the funding output it may
    /// have missed while it was down.
    Confirmed { height: u64 },
    /// The counterparty's signature over the cooperative close at `fee`. With
    /// it the close can be rebuilt and broadcast again until it confirms, after
    /// a crash that lost it from the mempool.
    CloseSigned { fee: u64, signature: Vec<u8> },
    /// Both sides proposed `state` at once. The peer's proposal follows as our
    /// LocalCommit at that state; neither becomes the channel's state: both
    /// are merged into the next one (see [`crate::channel::machine`]).
    Crossed { state: u64 },
}

const R_OPENED: u8 = 1;
const R_FUNDED: u8 = 2;
const R_LOCAL_COMMIT: u8 = 3;
const R_REMOTE_COMMIT: u8 = 4;
const R_REVOCATION_SENT: u8 = 5;
const R_REVOCATION_RECV: u8 = 6;
const R_READY: u8 = 7;
const R_CLOSING_COOP: u8 = 8;
const R_FORCING: u8 = 9;
const R_PENALISED: u8 = 10;
const R_CLOSED: u8 = 11;
const R_THEIR_POINT: u8 = 12;
const R_REVOCATIONS: u8 = 13;
const R_CONFIRMED: u8 = 14;
const R_CLOSE_SIGNED: u8 = 15;
const R_CROSSED: u8 = 16;
const R_CLOSING_COOP_BY: u8 = 17;

/// Most shachain entries a [`Record::Revocations`] may carry.
const MAX_STORE_ENTRIES: usize = crate::shachain::MAX_ENTRIES;

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        match self {
            Record::Opened {
                channel_id,
                our_index,
                funding,
                capacity,
                delay,
                funding_depth,
                our_pubkey,
                their_pubkey,
                payout,
            } => {
                w.u8(R_OPENED).bytes(channel_id.as_bytes()).u8(*our_index);
                w.bytes(funding[0].as_bytes()).bytes(funding[1].as_bytes());
                w.u64(*capacity);
                w.bytes(&delay.to_le_bytes())
                    .bytes(&funding_depth.to_le_bytes());
                w.var_bytes(our_pubkey).var_bytes(their_pubkey);
                w.bytes(payout[0].as_bytes()).bytes(payout[1].as_bytes());
            }
            Record::Funded {
                funding_txid,
                funding_index,
            } => {
                w.u8(R_FUNDED)
                    .bytes(funding_txid.as_bytes())
                    .u32(*funding_index);
            }
            Record::LocalCommit {
                state,
                balances,
                their_tier_sigs,
            } => {
                w.u8(R_LOCAL_COMMIT)
                    .u64(*state)
                    .u64(balances[0])
                    .u64(balances[1]);
                for s in their_tier_sigs {
                    w.var_bytes(s);
                }
            }
            Record::RemoteCommit { state, balances } => {
                w.u8(R_REMOTE_COMMIT)
                    .u64(*state)
                    .u64(balances[0])
                    .u64(balances[1]);
            }
            Record::RevocationSent { state } => {
                w.u8(R_REVOCATION_SENT).u64(*state);
            }
            Record::RevocationRecv { state, secret } => {
                w.u8(R_REVOCATION_RECV).u64(*state).bytes(secret);
            }
            Record::TheirPoint { state, point } => {
                w.u8(R_THEIR_POINT).u64(*state).bytes(point.as_bytes());
            }
            Record::Ready => {
                w.u8(R_READY);
            }
            Record::ClosingCoop { fee } => {
                w.u8(R_CLOSING_COOP).u64(*fee);
            }
            Record::Forcing => {
                w.u8(R_FORCING);
            }
            Record::Penalised => {
                w.u8(R_PENALISED);
            }
            Record::Closed => {
                w.u8(R_CLOSED);
            }
            Record::Revocations { state, entries } => {
                w.u8(R_REVOCATIONS).u64(*state).u8(entries.len() as u8);
                for (secret, index) in entries {
                    w.bytes(secret).u64(*index);
                }
            }
            Record::Confirmed { height } => {
                w.u8(R_CONFIRMED).u64(*height);
            }
            Record::CloseSigned { fee, signature } => {
                w.u8(R_CLOSE_SIGNED).u64(*fee).var_bytes(signature);
            }
            Record::Crossed { state } => {
                w.u8(R_CROSSED).u64(*state);
            }
            Record::ClosingCoopBy { fee, payer } => {
                w.u8(R_CLOSING_COOP_BY).u64(*fee).u8(*payer);
            }
        }
        w.finish()
    }

    fn decode(data: &[u8]) -> Result<Record, ReadError> {
        let mut r = Reader::new(data);
        let rec = match r.u8()? {
            R_OPENED => {
                let channel_id = Hash256(r.array32()?);
                let our_index = r.u8()?;
                let funding = [Hash256(r.array32()?), Hash256(r.array32()?)];
                let capacity = r.u64()?;
                let delay = u16::from_le_bytes([r.u8()?, r.u8()?]);
                let funding_depth = u16::from_le_bytes([r.u8()?, r.u8()?]);
                let our_pubkey = r.var_bytes()?.to_vec();
                let their_pubkey = r.var_bytes()?.to_vec();
                let payout = [Hash256(r.array32()?), Hash256(r.array32()?)];
                Record::Opened {
                    channel_id,
                    our_index,
                    funding,
                    capacity,
                    delay,
                    funding_depth,
                    our_pubkey,
                    their_pubkey,
                    payout,
                }
            }
            R_FUNDED => Record::Funded {
                funding_txid: Hash256(r.array32()?),
                funding_index: r.u32()?,
            },
            R_LOCAL_COMMIT => {
                let state = r.u64()?;
                let balances = [r.u64()?, r.u64()?];
                let their_tier_sigs = [
                    r.var_bytes()?.to_vec(),
                    r.var_bytes()?.to_vec(),
                    r.var_bytes()?.to_vec(),
                ];
                Record::LocalCommit {
                    state,
                    balances,
                    their_tier_sigs,
                }
            }
            R_REMOTE_COMMIT => Record::RemoteCommit {
                state: r.u64()?,
                balances: [r.u64()?, r.u64()?],
            },
            R_REVOCATION_SENT => Record::RevocationSent { state: r.u64()? },
            R_REVOCATION_RECV => Record::RevocationRecv {
                state: r.u64()?,
                secret: r.array32()?,
            },
            R_THEIR_POINT => Record::TheirPoint {
                state: r.u64()?,
                point: Hash256(r.array32()?),
            },
            R_READY => Record::Ready,
            R_CLOSING_COOP => Record::ClosingCoop { fee: r.u64()? },
            R_FORCING => Record::Forcing,
            R_PENALISED => Record::Penalised,
            R_CLOSED => Record::Closed,
            R_REVOCATIONS => {
                let state = r.u64()?;
                let n = r.u8()? as usize;
                if n > MAX_STORE_ENTRIES {
                    return Err(ReadError::InvalidValue);
                }
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push((r.array32()?, r.u64()?));
                }
                Record::Revocations { state, entries }
            }
            R_CONFIRMED => Record::Confirmed { height: r.u64()? },
            R_CROSSED => Record::Crossed { state: r.u64()? },
            R_CLOSING_COOP_BY => Record::ClosingCoopBy {
                fee: r.u64()?,
                payer: r.u8()?,
            },
            R_CLOSE_SIGNED => Record::CloseSigned {
                fee: r.u64()?,
                signature: r.var_bytes()?.to_vec(),
            },
            _ => return Err(ReadError::InvalidValue),
        };
        r.expect_end()?;
        Ok(rec)
    }
}

/// Reconstructs the channel parameters from the opening record.
impl Record {
    pub fn params(&self) -> Option<ChannelParams> {
        if let Record::Opened {
            funding,
            capacity,
            delay,
            ..
        } = self
        {
            Some(ChannelParams {
                funding: *funding,
                capacity: crate::amount::Amount::from_units(*capacity),
                delay: *delay,
            })
        } else {
            None
        }
    }
}

/// A 4-byte checksum: the first four bytes of the record's SHA-256. Enough to
/// catch a torn tail; the journal is not an adversarial setting, the writer is
/// ourselves.
fn checksum(bytes: &[u8]) -> [u8; 4] {
    sha256(bytes)[..4].try_into().unwrap()
}

/// Writes `bytes` to `path` atomically: a temporary file, flushed and
/// `fsync`ed, renamed over the target, then the directory `fsync`ed so the
/// rename itself is durable.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The append-only journal of one channel.
pub struct Journal {
    file: File,
    path: PathBuf,
    /// Records in the file: replayed at open, then appended or rewritten.
    records: usize,
}

/// One record, framed: its length, its checksum, its body.
fn frame(record: &Record) -> Vec<u8> {
    let body = record.encode();
    let mut frame = Vec::with_capacity(body.len() + 8);
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&checksum(&body));
    frame.extend_from_slice(&body);
    frame
}

impl Journal {
    /// Opens the journal at `path`, creating an empty one atomically if it
    /// does not exist, and returns it with every intact record replayed.
    pub fn open(path: impl AsRef<Path>) -> io::Result<(Journal, Vec<Record>)> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            atomic_write(&path, &[])?;
        }
        let mut raw = Vec::new();
        File::open(&path)?.read_to_end(&mut raw)?;
        let (records, good) = replay_prefix(&raw);
        // A torn tail — the half-written frame of an interrupted append — is
        // cut off before anything is appended after it. Left in place, every
        // record appended later would sit behind it, invisible to the next
        // replay: lost at the next restart.
        if good < raw.len() {
            let f = OpenOptions::new().write(true).open(&path)?;
            f.set_len(good as u64)?;
            f.sync_all()?;
        }
        let file = OpenOptions::new().append(true).open(&path)?;
        let count = records.len();
        Ok((
            Journal {
                file,
                path,
                records: count,
            },
            records,
        ))
    }

    /// Appends one record and `fsync`s before returning: on return, the record
    /// is durable.
    pub fn append(&mut self, record: &Record) -> io::Result<()> {
        self.file.write_all(&frame(record))?;
        self.file.flush()?;
        self.file.sync_all()?;
        self.records += 1;
        Ok(())
    }

    /// Replaces the whole journal with `records`, atomically: a crash leaves
    /// either the old file or the new one, complete ([`atomic_write`]). Used to
    /// compact a long journal into the few records that rebuild the same state.
    pub fn rewrite(&mut self, records: &[Record]) -> io::Result<()> {
        let bytes: Vec<u8> = records.iter().flat_map(frame).collect();
        atomic_write(&self.path, &bytes)?;
        self.file = OpenOptions::new().append(true).open(&self.path)?;
        self.records = records.len();
        Ok(())
    }

    /// Records in the journal file.
    pub fn records(&self) -> usize {
        self.records
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Reads every intact record from the raw journal bytes, stopping at the first
/// torn or corrupt frame.
pub fn replay(raw: &[u8]) -> Vec<Record> {
    replay_prefix(raw).0
}

/// [`replay`], with the length of the intact prefix those records occupy.
fn replay_prefix(raw: &[u8]) -> (Vec<Record>, usize) {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= raw.len() {
        let len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
        let crc: [u8; 4] = raw[pos + 4..pos + 8].try_into().unwrap();
        let body_start = pos + 8;
        let body_end = match body_start.checked_add(len) {
            Some(e) if e <= raw.len() => e,
            // The frame claims more than the file holds: a torn tail.
            _ => break,
        };
        let body = &raw[body_start..body_end];
        if checksum(body) != crc {
            break;
        }
        match Record::decode(body) {
            Ok(rec) => out.push(rec),
            // A frame that passed the checksum but does not decode is beyond
            // what a torn write can explain; stop rather than guess.
            Err(_) => break,
        }
        pos = body_end;
    }
    (out, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("q21-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("j.jrnl")
    }

    /// A crash cut the last append in the middle of its frame. Reopening must
    /// drop that torn tail, so records appended afterwards are replayed at the
    /// next restart instead of hiding behind it.
    #[test]
    fn records_appended_after_a_torn_tail_survive_the_next_restart() {
        let path = tmp("torn");
        {
            let (mut j, _) = Journal::open(&path).unwrap();
            j.append(&Record::Ready).unwrap();
            j.append(&Record::ClosingCoop { fee: 7 }).unwrap();
        }
        // Tear the second frame in its middle.
        let full = std::fs::read(&path).unwrap();
        let cut = full.len() - 5;
        std::fs::write(&path, &full[..cut]).unwrap();
        {
            let (mut j, recs) = Journal::open(&path).unwrap();
            assert_eq!(recs, vec![Record::Ready]);
            j.append(&Record::Forcing).unwrap();
        }
        let (_, recs) = Journal::open(&path).unwrap();
        assert_eq!(recs, vec![Record::Ready, Record::Forcing]);
    }
}
