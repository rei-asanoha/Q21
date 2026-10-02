//! Persistent storage.
//!
//! An append-only file: each block preceded by its length on four bytes. No
//! database stands between the disk and consensus; the file stays inspectable
//! by hand.
//!
//! # What phase 7 changed
//!
//! Until then, starting meant rereading **and revalidating everything** from
//! the genesis. On a few thousand blocks it was instantaneous; on a million,
//! with 660 us of proof of work per block and ML-DSA signatures to verify, it
//! became hours. A node that cannot be restarted is not a node.
//!
//! Two additions are enough to remove this wall, without delegating anything to
//! a library:
//!
//! - [`BlockStore::scan_headers`] walks the file decoding only the 160 header
//!   bytes of each record, and keeps the position of the body. Rebuilding the
//!   index of a chain now costs only a sequential read.
//! - [`BlockStore::read_at`] reads a body back on demand. A node therefore no
//!   longer has to keep a million blocks in memory to be able to serve a
//!   single one.
//!
//! The monetary state, for its part, is persisted by [`crate::state`].

use crate::block::{Block, BlockHeader};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    UnreadableBlock {
        index: u64,
    },
    /// The file ends in the middle of a block: interrupted write.
    TruncatedFile {
        index: u64,
    },
    BlockTooLarge {
        index: u64,
        size: u32,
    },
    /// The first record is not the genesis of this network.
    ForeignGenesis {
        expected: crate::hash::Hash256,
        seen: crate::hash::Hash256,
    },
    /// The header file does not carry the expected magic.
    HeadersMagic,
    /// A header does not link to the previous one: wrong parent or height.
    HeadersBrokenLink {
        index: u64,
    },
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "input/output error: {e}"),
            StoreError::UnreadableBlock { index } => {
                write!(f, "block {index} unreadable: corrupted file")
            }
            StoreError::TruncatedFile { index } => write!(
                f,
                "file truncated at block {index}: interrupted write, \
                 the previous blocks remain valid"
            ),
            StoreError::BlockTooLarge { index, size } => {
                write!(f, "block {index} announces {size} bytes: refused")
            }
            StoreError::ForeignGenesis { expected, seen } => write!(
                f,
                "this block file starts with {seen}, whereas the genesis of \
                 this network is {expected}: it belongs to another chain and \
                 is not adopted"
            ),
            StoreError::HeadersMagic => {
                write!(f, "this file is not a Q21 header store")
            }
            StoreError::HeadersBrokenLink { index } => write!(
                f,
                "header {index} does not link to the previous one: \
                 corrupted header chain"
            ),
        }
    }
}

/// Safety bound when reading: a corrupted file must not trigger an absurd
/// allocation.
const MAX_SERIALIZED_BLOCK: u32 = 64 * 1024 * 1024;

/// Where the cut tail of a block file is kept.
fn cut_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".cut");
    PathBuf::from(name)
}

/// Reads at most `length` bytes starting at `from`; fewer if the file ends
/// before.
fn read_range(path: &Path, from: u64, length: u64) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    // We only reserve what the file can supply: the requested bound can be
    // tens of mebibytes for a few hundred bytes read.
    let available = f.metadata()?.len().saturating_sub(from);
    f.seek(SeekFrom::Start(from))?;
    let mut bytes = Vec::with_capacity(usize::try_from(length.min(available)).unwrap_or(0));
    f.take(length).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Copies `length` bytes starting at `from` into the cut file, before they are
/// removed. A previous copy is overwritten: it concerned a repair already
/// done.
fn copy_tail(path: &Path, from: u64, length: u64) -> std::io::Result<()> {
    let bytes = read_range(path, from, length)?;
    let mut out = File::create(cut_path(path))?;
    out.write_all(&bytes)?;
    out.sync_all()
}

/// How many length prefixes an opening agrees to repair before stopping and
/// leaving the incident reported. Each repair restarts the whole scan; a card
/// that has flipped more bits than that is no longer a medium on which to
/// repair anything.
const MAX_PREFIX_REPAIRS: u32 = 64;

/// How far to walk back, from the end, to find the last record whose body
/// reads back. A prefix that is too short makes the scan accept one or two
/// ghost records behind it, rarely more; beyond that, it is no longer a damaged
/// prefix.
const MAX_WALK_BACK: usize = 64;

/// A length prefix to rewrite.
struct PrefixRepair {
    /// Position of the four prefix bytes in the file.
    position: u64,
    /// Index of the record, as the scan counts it.
    index: usize,
    /// What the prefix announces.
    read_len: u32,
    /// What the block actually takes.
    actual_len: u32,
    height: u64,
}

/// The complete block that starts `bytes`, if there is one **and** if it is
/// attached to this file; with the actual length of its record.
///
/// # Why two conditions
///
/// That a block decodes is not enough: one hundred sixty-two zero bytes are a
/// perfectly decodable block (zero header, zero transactions, zero uncles), and
/// a tail of zeros is precisely what a file system leaves after a power cut.
/// We therefore also require the block to be **attached**: its parent is a
/// record already read, or the record that follows it links to it. An
/// interrupted write satisfies neither; a record with a damaged prefix
/// satisfies at least one of the two — including the first block of a pruned
/// window, whose parent is no longer in the file but whose successor is.
///
/// Re-encoding must return exactly the bytes read: the encoding is canonical,
/// and that is what forbids accepting a length other than the one `append`
/// wrote.
fn attached_record(
    bytes: &[u8],
    known: &std::collections::HashSet<crate::hash::Hash256>,
) -> Option<(BlockHeader, usize)> {
    let (block, actual) = Block::decode_prefix(bytes).ok()?;
    if actual < BlockHeader::SIZE || actual > MAX_SERIALIZED_BLOCK as usize {
        return None;
    }
    if block.encode() != bytes[..actual] {
        return None;
    }
    let id = block.header.block_id();
    let parent_known = known.contains(&block.header.prev_block);
    let next_links = bytes.len() >= actual + 4 + BlockHeader::SIZE && {
        let size = u32::from_le_bytes([
            bytes[actual],
            bytes[actual + 1],
            bytes[actual + 2],
            bytes[actual + 3],
        ]);
        (BlockHeader::SIZE as u32..=MAX_SERIALIZED_BLOCK).contains(&size)
            && BlockHeader::decode(&bytes[actual + 4..actual + 4 + BlockHeader::SIZE])
                .map(|h| h.prev_block == id)
                .unwrap_or(false)
    };
    if parent_known || next_links {
        Some((block.header, actual))
    } else {
        None
    }
}

/// Is the genesis recognizable at the head of the file, despite damaged bytes?
/// Two clues are enough, each on its own: the header at byte 4 is the
/// genesis's (wrong length prefix, intact contents), or the record placed right
/// after the canonical length links to the genesis (wrong prefix or contents,
/// the rest of the file is indeed ours). Returns `false` if the record is
/// already canonical: there is then nothing to copy over, and the trouble is
/// elsewhere.
fn genesis_is_recognizable(
    path: &Path,
    canonical: &[u8],
    expected: crate::hash::Hash256,
) -> std::io::Result<bool> {
    let l = canonical.len();
    let bytes = read_range(path, 0, (4 + l + 4 + BlockHeader::SIZE) as u64)?;
    if bytes.len() >= 4 + l
        && bytes[..4] == (l as u32).to_le_bytes()
        && bytes[4..4 + l] == *canonical
    {
        return Ok(false);
    }
    let header_intact = bytes.len() >= 4 + BlockHeader::SIZE
        && BlockHeader::decode(&bytes[4..4 + BlockHeader::SIZE])
            .map(|h| h.block_id() == expected)
            .unwrap_or(false);
    let next_links = bytes.len() >= 4 + l + 4 + BlockHeader::SIZE
        && BlockHeader::decode(&bytes[4 + l + 4..4 + l + 4 + BlockHeader::SIZE])
            .map(|h| h.prev_block == expected)
            .unwrap_or(false);
    Ok(header_intact || next_links)
}

/// Position of a record in the file.
///
/// `offset` designates the start of the **body**, after the four length bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordRef {
    pub offset: u64,
    pub len: u32,
}

pub struct BlockStore {
    path: PathBuf,
}

impl BlockStore {
    pub fn new<P: AsRef<Path>>(path: P) -> BlockStore {
        BlockStore {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Appends a block at the end of the file and returns its position.
    pub fn append(&self, block: &Block) -> Result<RecordRef, StoreError> {
        let data = block.encode();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let start = file.metadata()?.len();
        {
            let mut f = BufWriter::new(&mut file);
            f.write_all(&(data.len() as u32).to_le_bytes())?;
            f.write_all(&data)?;
            f.flush()?;
        }
        // All the way to the disk, like the headers and the snapshot: without
        // this, a power cut could lose the last body while its header had been
        // forced to disk — the snapshot ended up ahead of the block file. One
        // block every two minutes: the cost is invisible.
        file.sync_all()?;
        Ok(RecordRef {
            offset: start + 4,
            len: data.len() as u32,
        })
    }

    /// Walks the file decoding only the headers.
    ///
    /// The header takes the first [`BlockHeader::SIZE`] bytes of each record:
    /// we read 4 + 160 bytes, then skip the rest. On a million blocks, this
    /// replaces decoding several gigabytes of transactions with a sequential
    /// read of a few tens of megabytes.
    ///
    /// Like [`Self::load_all`], a final truncation is not fatal: what precedes
    /// remains usable, and the incident is returned to the caller.
    #[allow(clippy::type_complexity)]
    pub fn scan_headers(
        &self,
    ) -> Result<(Vec<(BlockHeader, RecordRef)>, Option<StoreError>), StoreError> {
        if !self.exists() {
            return Ok((Vec::new(), None));
        }
        let file_size = std::fs::metadata(&self.path)?.len();
        let mut f = BufReader::new(File::open(&self.path)?);
        let mut v = Vec::new();
        let mut index = 0u64;
        let mut position = 0u64;

        loop {
            let mut len_prefix = [0u8; 4];
            match f.read_exact(&mut len_prefix) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StoreError::Io(e)),
            }
            let size = u32::from_le_bytes(len_prefix);
            if size < BlockHeader::SIZE as u32 || size > MAX_SERIALIZED_BLOCK {
                return Ok((v, Some(StoreError::BlockTooLarge { index, size })));
            }

            let mut raw = [0u8; BlockHeader::SIZE];
            if f.read_exact(&mut raw).is_err() {
                return Ok((v, Some(StoreError::TruncatedFile { index })));
            }
            let header = match BlockHeader::decode(&raw) {
                Ok(h) => h,
                Err(_) => return Ok((v, Some(StoreError::UnreadableBlock { index }))),
            };

            let rest = i64::from(size) - BlockHeader::SIZE as i64;
            if f.seek_relative(rest).is_err() {
                return Ok((v, Some(StoreError::TruncatedFile { index })));
            }
            // `seek_relative` succeeds beyond the end: we check that the body
            // really exists before declaring the record good.
            let end = position + 4 + u64::from(size);
            if end > file_size {
                return Ok((v, Some(StoreError::TruncatedFile { index })));
            }

            v.push((
                header,
                RecordRef {
                    offset: position + 4,
                    len: size,
                },
            ));
            position = end;
            index += 1;
        }
        Ok((v, None))
    }

    /// Reads a block back at a known position.
    pub fn read_at(&self, r: RecordRef) -> Result<Block, StoreError> {
        if r.len == 0 || r.len > MAX_SERIALIZED_BLOCK {
            return Err(StoreError::BlockTooLarge {
                index: r.offset,
                size: r.len,
            });
        }
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(r.offset))?;
        let mut data = vec![0u8; r.len as usize];
        f.read_exact(&mut data)
            .map_err(|_| StoreError::TruncatedFile { index: r.offset })?;
        Block::decode(&data).map_err(|_| StoreError::UnreadableBlock { index: r.offset })
    }

    /// Reads all blocks back, in order.
    ///
    /// A truncation at the end of the file — a power cut during a write — is
    /// not a fatal error: the complete blocks that precede remain usable. The
    /// detail is returned to the caller, who decides.
    pub fn load_all(&self) -> Result<(Vec<Block>, Option<StoreError>), StoreError> {
        if !self.exists() {
            return Ok((Vec::new(), None));
        }
        let mut f = BufReader::new(File::open(&self.path)?);
        let mut blocks = Vec::new();
        let mut index = 0u64;

        loop {
            let mut len_prefix = [0u8; 4];
            match f.read_exact(&mut len_prefix) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StoreError::Io(e)),
            }
            let size = u32::from_le_bytes(len_prefix);
            if size == 0 || size > MAX_SERIALIZED_BLOCK {
                return Ok((blocks, Some(StoreError::BlockTooLarge { index, size })));
            }

            let mut data = vec![0u8; size as usize];
            if f.read_exact(&mut data).is_err() {
                return Ok((blocks, Some(StoreError::TruncatedFile { index })));
            }
            match Block::decode(&data) {
                Ok(b) => blocks.push(b),
                Err(_) => return Ok((blocks, Some(StoreError::UnreadableBlock { index }))),
            }
            index += 1;
        }
        Ok((blocks, None))
    }

    pub fn remove(&self) -> Result<(), StoreError> {
        if self.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Archive: store + index of positions
// ---------------------------------------------------------------------------

/// What a pruning did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PruneSummary {
    pub kept: usize,
    pub removed: usize,
    pub bytes_freed: u64,
}

/// The block file, plus the index of their positions.
///
/// # The defect this type fixes
///
/// Since phase 7 the chain keeps only a window of bodies in memory; everything
/// else has to come from the disk. The first version built this index **once
/// at startup**. Blocks mined or received afterwards never entered it: as soon
/// as they left the memory window, the node could no longer serve them.
///
/// Consequence observed when running two real processes: a node joining a
/// chain in progress received thousands of blocks, all orphans, and stayed at
/// height zero forever — because its peer could no longer supply it the first
/// blocks. No unit test could see it: it takes a chain longer than the memory
/// window, and two processes.
///
/// The index therefore lives here, and follows every append.
pub struct BlockArchive {
    store: BlockStore,
    positions: std::sync::Mutex<std::collections::HashMap<crate::hash::Hash256, RecordRef>>,
    /// Bodies already reported as unreadable: a single warning per block, not
    /// one per read — a peer that requests the same block again must not fill
    /// the log.
    reported_unreadable: std::sync::Mutex<std::collections::HashSet<crate::hash::Hash256>>,
}

impl BlockArchive {
    /// Opens the archive and scans the headers already present.
    ///
    /// Also returns the headers read, which the caller needs to rebuild the
    /// index of the chain, and any incident met at the end of the file.
    #[allow(clippy::type_complexity)]
    pub fn open<P: AsRef<Path>>(
        path: P,
        network: crate::address::Network,
    ) -> Result<(BlockArchive, Vec<BlockHeader>, Option<StoreError>), StoreError> {
        Self::open_inner(path.as_ref(), network, true, 0)
    }

    /// `repair_genesis` is only true on the first attempt: a repair that would
    /// change nothing must not loop. `prefixes_repaired` counts the length
    /// prefixes already rewritten by this opening, for the same reason.
    fn open_inner(
        path: &Path,
        network: crate::address::Network,
        repair_genesis: bool,
        prefixes_repaired: u32,
    ) -> Result<(BlockArchive, Vec<BlockHeader>, Option<StoreError>), StoreError> {
        let store = BlockStore::new(path);
        let (headers, problem) = store.scan_headers()?;
        let file_size = if store.exists() {
            std::fs::metadata(store.path())?.len()
        } else {
            0
        };

        // --- The root, before everything else.
        //
        // An audit dropped a crafted block file into the data directory: a fake
        // genesis, without proof of work, whose coinbase paid 21 million to its
        // author. The node adopted it as root and credited the funds. The first
        // block was checked by nobody: `Chain::new` takes its genesis block at
        // face value, and the replay only starts at the next block.
        //
        // The genesis identifier is a constant of the network. It is compared
        // here, once, at the place where any on-disk chain enters the program.
        //
        // --- A damaged genesis is not a foreign genesis.
        //
        // The genesis is a constant of the network, rewritten without state.
        // If the header at byte 4 is its own, or if the record that follows its
        // canonical length links to it, the first record is not that of
        // another chain: it is a few flipped bytes on the card. Setting them
        // aside as an "old chain" abandoned the whole local history for one
        // bit. A first version only copied over the **contents**, at the
        // announced length: a bit in the **length prefix** of the genesis left
        // it out of reach — the scan went out of alignment or returned
        // nothing, and the node died advising `q21 init`. We now copy over the
        // whole record, prefix included, whatever prefix was read.
        let expected = crate::chain::genesis_id(network);
        let canonical = crate::chain::genesis_block(network).encode();
        let first_ok = headers
            .first()
            .map(|(h, r)| h.block_id() == expected && r.len as usize == canonical.len())
            .unwrap_or(false);
        if !first_ok && file_size > 0 {
            if repair_genesis && genesis_is_recognizable(store.path(), &canonical, expected)? {
                let mut f = OpenOptions::new().write(true).open(store.path())?;
                f.seek(SeekFrom::Start(0))?;
                f.write_all(&(canonical.len() as u32).to_le_bytes())?;
                f.write_all(&canonical)?;
                f.sync_all()?;
                eprintln!(
                    "  block file repaired: the genesis record was damaged \
                     (length prefix or contents), the network genesis was copied \
                     in its place"
                );
                // Read again: the rest of the loading must see the file as it
                // is now.
                drop(f);
                return Self::open_inner(store.path(), network, false, prefixes_repaired);
            }
            match headers.first() {
                Some((first, _)) if first.block_id() != expected => {
                    return Err(StoreError::ForeignGenesis {
                        expected,
                        seen: first.block_id(),
                    });
                }
                // The genesis is recognized but its announced length is wrong
                // and the copy has already happened: the prefix repair below
                // has the last word.
                Some(_) => {}
                None => eprintln!(
                    "warning: the block file ({file_size} byte(s)) does not start \
                     with any readable record, and nothing in it looks like the genesis of this \
                     network: it is unreadable or is not a Q21 block file \
                     ({})",
                    problem.as_ref().map(|s| s.to_string()).unwrap_or_default()
                ),
            }
        }

        // --- A damaged length prefix is rewritten, not cut.
        //
        // Each record is preceded by its length on four bytes. One bit flipped
        // in there, and the scan no longer understands what follows: too long,
        // it points beyond the file ("interrupted write") or into the middle of
        // the next record; too short, the scan accepts the block with a wrong
        // length then reads anything behind it. In both cases, **all the bytes
        // of the block are there**.
        //
        // The first version treated the "too long, near the end" case as an
        // interrupted write and cut everything after the last complete record
        // — up to `MAX_BLOCK_SIZE` bytes, that is thousands of empty blocks:
        // one bit erased three weeks of chain while announcing a successful
        // repair, and the snapshot, taken below the tip, no longer designated
        // anything. The "in the middle" case cost a revalidation from the
        // genesis and downloading again everything that followed.
        //
        // A block encodes canonically and delimits itself: its actual length is
        // found by decoding it, and it is required to be attached to the file
        // (known parent, or a successor that links to it). Then, and only then,
        // the prefix is rewritten with the actual length and the scan is
        // restarted. Nothing is cut.
        let mut damaged_prefix = false;
        if problem.is_some() && !headers.is_empty() {
            if let Some(p) = Self::prefix_to_repair(&store, &headers, file_size)? {
                if prefixes_repaired < MAX_PREFIX_REPAIRS {
                    let mut f = OpenOptions::new().write(true).open(store.path())?;
                    f.seek(SeekFrom::Start(p.position))?;
                    f.write_all(&p.actual_len.to_le_bytes())?;
                    f.sync_all()?;
                    drop(f);
                    eprintln!(
                        "  block file repaired: the length prefix of record {} \
                         (block at height {}) announced {} byte(s) instead of {}; it was \
                         rewritten, no block was cut",
                        p.index, p.height, p.read_len, p.actual_len
                    );
                    return Self::open_inner(
                        store.path(),
                        network,
                        repair_genesis,
                        prefixes_repaired + 1,
                    );
                }
                // The budget is exhausted: we know that a complete block
                // follows, so nothing will be cut, but the scan is not
                // restarted anymore.
                damaged_prefix = true;
                eprintln!(
                    "warning: more than {MAX_PREFIX_REPAIRS} damaged length prefixes \
                     in the block file; the repair stops at \
                     record {}, the rest is not touched",
                    p.index
                );
            }
        }

        // --- A damaged tail is cut, not worked around.
        //
        // A power cut in the middle of a write leaves a half-written record at
        // the end of the file. The scan stops there and reports the incident:
        // the previous blocks remain valid, and the node can start again. That
        // was already the case.
        //
        // What was not: the following blocks were written **after** those
        // damaged bytes. They reached the disk, were served as long as the
        // process lived, and disappeared at the next restart — since the scan
        // always stopped at the same place. The file grew while returning
        // nothing more. It is the most insidious form of data loss: silent,
        // and worse at every restart.
        //
        // So the file is brought back to the end of the last complete record.
        // The half-written block is lost — it already was — and will be
        // requested again from the network. What follows will be written on
        // sound ground.
        // Safeguards, and they are not negotiable — a repair that gets it wrong
        // erases blocks:
        //
        // 1. **Only a truncated tail gets repaired.** A lying size or an
        //    undecipherable header in the middle of the file are not an
        //    interrupted write: they are the traces of something else, and
        //    cutting them would mean obeying whoever wrote them. These cases
        //    stay reported, and nothing is touched.
        // 2. **Never down to zero.** A first version cut at the end of the last
        //    valid record, including when there was none: a lie about the size
        //    of the **first** record would therefore have erased the whole
        //    file. The audit test `aa_lying_size_in_the_block_file` saw it; the
        //    review did not.
        // 3. **Never more than one block.** What is thrown away must have the
        //    size of an interrupted write — so at most one consensus block,
        //    `MAX_BLOCK_SIZE`, and not the read allocation bound, which is
        //    sixteen times that. A single flipped bit in a length prefix in the
        //    middle of the file makes a record point beyond the end, and looks
        //    like a truncated tail: with the wide bound, the repair erased
        //    everything that followed — dozens of valid blocks — while
        //    announcing a successful repair. Beyond one block, we no longer
        //    understand what we see, and we refrain.
        // 4. **Nothing is thrown away without a copy.** What is cut is first
        //    written next to the file, in `blocks.dat.cut`: if the repair got
        //    it wrong, nothing is lost for good.
        // 5. **Never a complete block.** The byte bound of item 3 is not a
        //    block bound: four mebibytes are fifteen thousand empty blocks. If
        //    a complete block attached to the file starts after the last valid
        //    record, it is not an interrupted write but a damaged prefix —
        //    handled above, by rewriting. We only get here if there is none:
        //    what remains really is a fragment.
        let mut problem = problem;
        if matches!(problem, Some(StoreError::TruncatedFile { .. }))
            && !headers.is_empty()
            && !damaged_prefix
        {
            let end = headers
                .last()
                .map(|(_, r)| r.offset + r.len as u64)
                .unwrap_or(0);
            let size = file_size;
            let discarded = size.saturating_sub(end);
            if end > 0 && discarded <= crate::consensus::MAX_BLOCK_SIZE as u64 + 4 {
                let copy = copy_tail(store.path(), end, discarded);
                match copy.and_then(|_| std::fs::OpenOptions::new().write(true).open(store.path()))
                {
                    Ok(f) => match f.set_len(end) {
                        Ok(()) => {
                            problem = None;
                            eprintln!(
                                "  block file repaired: {discarded} byte(s) of interrupted write cut \
                                 (copy kept in {})",
                                cut_path(store.path()).display()
                            );
                        }
                        Err(e) => eprintln!("warning: damaged tail not cut ({e})"),
                    },
                    Err(e) => eprintln!("warning: damaged tail not cut ({e})"),
                }
            } else if end > 0 {
                eprintln!(
                    "warning: {discarded} byte(s) beyond the last complete record, \
                     more than one block: this is not an interrupted write, nothing is cut"
                );
            }
        }

        let positions = headers
            .iter()
            .map(|(h, r)| (h.block_id(), *r))
            .collect::<std::collections::HashMap<_, _>>();
        let bare_headers: Vec<BlockHeader> = headers.into_iter().map(|(h, _)| h).collect();
        Ok((
            BlockArchive {
                store,
                positions: std::sync::Mutex::new(positions),
                reported_unreadable: std::sync::Mutex::new(std::collections::HashSet::new()),
            },
            bare_headers,
            problem,
        ))
    }

    /// Looks, where the scan stopped, for a length prefix whose value does not
    /// match the block it precedes.
    ///
    /// # The method
    ///
    /// We walk back from the last accepted record to the last one whose
    /// **body** reads back: it is the last safe point. The suspect is the
    /// record that follows it — either accepted by the scan with a length that
    /// does not let it read back (prefix too short, or too long but still
    /// within the file), or refused by the scan (prefix pointing outside the
    /// file or outside the bounds). In both cases, its bytes start right after
    /// the last sound body, and [`attached_record`] tells whether they form a
    /// complete block that belongs to this file, and how many bytes it takes.
    ///
    /// Does nothing — and lets nothing be done — if the prefix read is already
    /// the actual length: the trouble is then elsewhere, and it is not for this
    /// function to make it up.
    fn prefix_to_repair(
        store: &BlockStore,
        headers: &[(BlockHeader, RecordRef)],
        file_size: u64,
    ) -> Result<Option<PrefixRepair>, StoreError> {
        // The last record whose body reads back.
        let mut sound = headers.len();
        let mut walked_back = 0usize;
        while sound > 0 && walked_back < MAX_WALK_BACK {
            if store.read_at(headers[sound - 1].1).is_ok() {
                break;
            }
            sound -= 1;
            walked_back += 1;
        }
        if walked_back >= MAX_WALK_BACK {
            return Ok(None);
        }
        let known: std::collections::HashSet<crate::hash::Hash256> =
            headers[..sound].iter().map(|(h, _)| h.block_id()).collect();

        // The suspect: where its bytes start, and what its prefix says.
        let (start, read_len) = if sound < headers.len() {
            let r = headers[sound].1;
            (r.offset, r.len)
        } else {
            let end = headers
                .last()
                .map(|(_, r)| r.offset + u64::from(r.len))
                .unwrap_or(0);
            if end == 0 || file_size < end + 4 + BlockHeader::SIZE as u64 {
                return Ok(None);
            }
            let prefix = read_range(store.path(), end, 4)?;
            if prefix.len() < 4 {
                return Ok(None);
            }
            (
                end + 4,
                u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]),
            )
        };
        let bytes = read_range(
            store.path(),
            start,
            u64::from(MAX_SERIALIZED_BLOCK) + 4 + BlockHeader::SIZE as u64,
        )?;
        let Some((header, actual)) = attached_record(&bytes, &known) else {
            return Ok(None);
        };
        if actual as u64 == u64::from(read_len) {
            return Ok(None);
        }
        Ok(Some(PrefixRepair {
            position: start - 4,
            index: sound,
            read_len,
            actual_len: actual as u32,
            height: header.height,
        }))
    }

    pub fn len(&self) -> usize {
        self.positions.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends a block and **records its position in the same step**.
    ///
    /// The two must never be separated: a block written but not indexed is a
    /// block this node will no longer be able to serve.
    ///
    /// The positions lock is taken **before** the write: it serializes appends
    /// with pruning ([`Self::prune`]), which rewrites the file. Without this,
    /// a block written during the rewrite would land in the old file, and its
    /// position in the index of the new one.
    pub fn append(&self, block: &Block) -> Result<(), StoreError> {
        let mut g = self.positions.lock().unwrap_or_else(|e| e.into_inner());
        let r = self.store.append(block)?;
        g.insert(block.header.block_id(), r);
        Ok(())
    }

    /// Reads a block back. The lock is held during the read, for the same
    /// reason as in [`Self::append`]: a position read before a pruning no
    /// longer designates anything after it.
    ///
    /// A body that is **indexed but unreadable** is not a missing body: these
    /// are damaged bytes in the middle of the file. The caller only sees a
    /// `None` and will say "missing"; it is stated here, once per block, so
    /// that the operator knows it is their disk, and that the block will be
    /// requested again from the network — a cost, not a loss.
    ///
    /// # What is checked, beyond decoding
    ///
    /// Bytes that decode are not for all that **the** requested block. The
    /// index only read the header of each record; the body that follows it was
    /// never checked against it. A block file in which a body does not match
    /// its header — wrong Merkle root, made-up uncle list — was therefore read
    /// back without a blink, and the chain used it as truth: uncles claimed, a
    /// body served to a peer, a reorg. A snapshot folder supplied by a third
    /// party could thus freeze a node on a fake branch until it was erased
    /// (phase 8b red team, 2nd campaign, item 5).
    ///
    /// We therefore require the block read back to carry the requested
    /// identifier, and its shape to be right ([`Block::check_shape`]: roots
    /// recomputed). What fails is treated as unreadable — hence missing, hence
    /// requested again from the network, which will deliver the real one. The
    /// cost is one root recomputation per disk read, and disk reads are rare:
    /// the in-memory window of bodies serves everything recent.
    pub fn read(&self, id: &crate::hash::Hash256) -> Option<Block> {
        let g = self.positions.lock().ok()?;
        let r = *g.get(id)?;
        let result = self.store.read_at(r).and_then(|b| {
            if b.header.block_id() != *id {
                return Err(StoreError::UnreadableBlock { index: r.offset });
            }
            b.check_shape()
                .map_err(|_| StoreError::UnreadableBlock { index: r.offset })?;
            Ok(b)
        });
        match result {
            Ok(b) => Some(b),
            Err(e) => {
                let first_time = self
                    .reported_unreadable
                    .lock()
                    .map(|mut s| s.insert(*id))
                    .unwrap_or(false);
                if first_time {
                    let cause = match e {
                        StoreError::TruncatedFile { .. } => "the file stops before its end",
                        StoreError::Io(_) => "disk read error",
                        _ => "its bytes do not form the block its header announces",
                    };
                    eprintln!(
                        "warning: the body of block {id} is indexed in the block \
                         file (position {}, {} bytes) but does not read back: {cause}. Damaged \
                         bytes on the disk; the block will be requested again from the network",
                        r.offset, r.len
                    );
                }
                None
            }
        }
    }

    /// Rewrites the file keeping only the blocks that `keep` retains.
    ///
    /// # Why
    ///
    /// The block file only ever grew. A node that mines only for itself yet
    /// only needs what it can still undo (the reorg window) and what its
    /// history displays: everything before that is summed up in the snapshot.
    /// A Raspberry Pi SD card does not hold ten years of bodies; it holds ten
    /// years of snapshots.
    ///
    /// # What is guaranteed
    ///
    /// - The order of the records is kept, the genesis stays first: the root
    ///   check of [`Self::open`] keeps applying.
    /// - The new file is written alongside, synced to disk, then renamed over
    ///   the old one: at every instant, the path designates a complete file —
    ///   the old one or the new one, never a mix.
    /// - The positions lock is held from start to finish: no append and no
    ///   read gets in between, and the index is rebuilt before anyone consults
    ///   it.
    ///
    /// The caller is responsible for what `keep` retains: at a minimum, the
    /// genesis and everything the chain may still have to read again.
    pub fn prune(&self, keep: impl Fn(&BlockHeader) -> bool) -> Result<PruneSummary, StoreError> {
        let mut positions = self.positions.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.store.path().to_path_buf();
        if !path.exists() {
            return Ok(PruneSummary::default());
        }
        let tmp = path.with_extension("pruning");
        let mut summary = PruneSummary::default();
        let mut new_positions: std::collections::HashMap<crate::hash::Hash256, RecordRef> =
            std::collections::HashMap::new();
        {
            let mut reader = BufReader::new(File::open(&path)?);
            let out_file = File::create(&tmp)?;
            let mut writer = BufWriter::new(&out_file);
            let mut out_position = 0u64;
            loop {
                let mut prefix = [0u8; 4];
                match reader.read_exact(&mut prefix) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(StoreError::Io(e)),
                }
                let size = u32::from_le_bytes(prefix);
                if size < BlockHeader::SIZE as u32 || size > MAX_SERIALIZED_BLOCK {
                    // A record we do not understand: we stop there, like the
                    // scan. What precedes is sound.
                    break;
                }
                let mut raw = vec![0u8; size as usize];
                if reader.read_exact(&mut raw).is_err() {
                    break; // truncated tail: cut, as at opening
                }
                let header = match BlockHeader::decode(&raw[..BlockHeader::SIZE]) {
                    Ok(h) => h,
                    Err(_) => break,
                };
                if keep(&header) {
                    writer.write_all(&prefix)?;
                    writer.write_all(&raw)?;
                    new_positions.insert(
                        header.block_id(),
                        RecordRef {
                            offset: out_position + 4,
                            len: size,
                        },
                    );
                    out_position += 4 + u64::from(size);
                    summary.kept += 1;
                } else {
                    summary.removed += 1;
                    summary.bytes_freed += 4 + u64::from(size);
                }
            }
            writer.flush()?;
            out_file.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        if let Some(parent) = path.parent() {
            if let Ok(d) = File::open(parent) {
                let _ = d.sync_all();
            }
        }
        *positions = new_positions;
        Ok(summary)
    }

    pub fn store(&self) -> &BlockStore {
        &self.store
    }
}

impl crate::chain::Journal for BlockArchive {
    /// Writes the block if it is not already in the file.
    ///
    /// The index of positions serves as the membership test: it is in memory,
    /// so the question does not cost a disk read.
    fn record(&self, block: &Block) {
        let id = block.header.block_id();
        if self
            .positions
            .lock()
            .map(|g| g.contains_key(&id))
            .unwrap_or(false)
        {
            return;
        }
        if let Err(e) = self.append(block) {
            eprintln!("warning: block {id} not written to disk: {e}");
        }
    }
}

impl crate::chain::BodySource for BlockArchive {
    fn body(&self, id: &crate::hash::Hash256) -> Option<Block> {
        self.read(id)
    }
}

// ---------------------------------------------------------------------------
// Header store: the header chain, without the bodies
// ---------------------------------------------------------------------------

/// Magic of the header file. Frozen format magic (binary file format), not a
/// word to translate.
const HEADERS_MAGIC: &[u8; 8] = b"Q21HDRS\0";
/// Version of the header format.
const HEADERS_VERSION: u32 = 1;
/// Length of the prefix: magic (8) + version (4).
const HEADERS_PREFIX_LEN: u64 = 12;

/// Store of headers alone, independent of the block file.
///
/// # Why it exists
///
/// A node that **adopts** a snapshot starts again at height H without holding
/// blocks 1..H. It still needs their header chain: it is what proves that the
/// tip carries a proof of work, and what gives the difficulty of the next
/// block. The block file cannot supply it — it only keeps the bodies it has.
/// This store keeps it separately.
///
/// A full node does not need it: its headers are read back from the block file
/// ([`BlockStore::scan_headers`]). This store therefore only serves the node
/// resumed from a snapshot.
///
/// # The format
///
/// A prefix (magic, version), then fixed-size headers ([`BlockHeader::SIZE`])
/// placed end to end. No length prefix per record: a header always has the
/// same size. An interrupted write leaves a partial record at the end of the
/// file, cut on reread — as for the block file.
///
/// # What it checks, and what it does not
///
/// On reread: the magic, that the first header is indeed the genesis of the
/// network, and that each header links to the previous one (parent and height).
/// It **does not check** the proof of work: this local file is trusted, as the
/// block file is — whoever can rewrite the directory has already won. The
/// proof of work of headers **coming from elsewhere** is checked at adoption,
/// before they enter here.
pub struct HeaderStore {
    path: PathBuf,
}

impl HeaderStore {
    pub fn new<P: AsRef<Path>>(path: P) -> HeaderStore {
        HeaderStore {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Appends headers at the end, creating the file (with its prefix) if
    /// needed. The caller guarantees that they link to what precedes; the
    /// reread checks it again anyway.
    pub fn append(&self, headers: &[BlockHeader]) -> Result<(), StoreError> {
        if headers.is_empty() {
            return Ok(());
        }
        let is_new = !self.exists() || std::fs::metadata(&self.path)?.len() < HEADERS_PREFIX_LEN;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        {
            let mut f = BufWriter::new(&mut file);
            if is_new {
                f.write_all(HEADERS_MAGIC)?;
                f.write_all(&HEADERS_VERSION.to_le_bytes())?;
            }
            for h in headers {
                f.write_all(&h.encode())?;
            }
            f.flush()?;
        }
        file.sync_all()?;
        Ok(())
    }

    /// Number of complete headers the file contains, from its size alone —
    /// without reading it. `None` if the store does not exist or does not even
    /// have its prefix.
    ///
    /// This is what the snapshot loop consults every five minutes to know how
    /// far to complete the store: rereading the whole file — 160 bytes per
    /// block, the whole history — at that frequency would wear out an SD card
    /// for nothing. The chain reread at startup by [`Self::load`] guarantees
    /// that the headers counted here do link.
    pub fn count(&self) -> Option<u64> {
        let size = std::fs::metadata(&self.path).ok()?.len();
        if size < HEADERS_PREFIX_LEN {
            return None;
        }
        Some((size - HEADERS_PREFIX_LEN) / BlockHeader::SIZE as u64)
    }

    /// The last complete header of the file, read on its own — without walking
    /// the rest. `None` if the store is empty, missing, or if that header does
    /// not decode.
    pub fn last(&self) -> Option<BlockHeader> {
        let n = self.count()?;
        if n == 0 {
            return None;
        }
        self.header_at(n - 1)
    }

    /// The header at index `index` (the index is also the height, the store
    /// starting from the genesis without gaps), read on its own. `None` if it
    /// does not exist or does not decode.
    pub fn header_at(&self, index: u64) -> Option<BlockHeader> {
        if index >= self.count()? {
            return None;
        }
        let mut f = File::open(&self.path).ok()?;
        f.seek(SeekFrom::Start(
            HEADERS_PREFIX_LEN + index * BlockHeader::SIZE as u64,
        ))
        .ok()?;
        let mut raw = [0u8; BlockHeader::SIZE];
        f.read_exact(&mut raw).ok()?;
        BlockHeader::decode(&raw).ok()
    }

    /// Keeps only the first `n` headers. Used to remove a tail that the
    /// in-memory chain contradicts — a damaged last header that still links to
    /// its parent but is no longer itself.
    pub fn truncate(&self, n: u64) -> Result<(), StoreError> {
        let Some(current) = self.count() else {
            return Ok(());
        };
        if n >= current {
            return Ok(());
        }
        let fh = OpenOptions::new().write(true).open(&self.path)?;
        fh.set_len(HEADERS_PREFIX_LEN + n * BlockHeader::SIZE as u64)?;
        fh.sync_all()?;
        Ok(())
    }

    /// Reads back the whole header chain.
    ///
    /// Checks the magic, the genesis, the linking (parent and height), and cuts
    /// any partial tail.
    ///
    /// # An unreadable or unlinked header in the middle: we cut, we no longer refuse
    ///
    /// A first version reported any break in the linking in the middle of the
    /// file as corruption and refused the whole store. On a pruned or adopted
    /// node, this store is the **only** source of the header chain from before
    /// the snapshot: a single flipped bit on the SD card — in any of the 160
    /// bytes of any block of the whole history — made the directory unable to
    /// start, with as sole advice to "sync again into an empty directory".
    /// That is the defect this closes: the file is truncated at the last sound
    /// position, the operator is warned, and the caller starts again from what
    /// remains — the network will supply the missing headers again, since the
    /// proof of work of a header received from the network is checked anyway.
    ///
    /// Truncating rather than keeping the sound prefix in memory: the next
    /// `append` must write after the last **sound** header, not after the
    /// damaged bytes. If the truncation itself fails, the old error
    /// [`StoreError::HeadersBrokenLink`] is returned: nothing is trusted.
    pub fn load(&self, network: crate::address::Network) -> Result<Vec<BlockHeader>, StoreError> {
        if !self.exists() {
            return Ok(Vec::new());
        }
        let size = std::fs::metadata(&self.path)?.len();
        if size < HEADERS_PREFIX_LEN {
            return Err(StoreError::HeadersMagic);
        }

        let mut f = BufReader::new(File::open(&self.path)?);
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic)?;
        if &magic != HEADERS_MAGIC {
            return Err(StoreError::HeadersMagic);
        }
        let mut v = [0u8; 4];
        f.read_exact(&mut v)?;
        if u32::from_le_bytes(v) != HEADERS_VERSION {
            return Err(StoreError::HeadersMagic);
        }

        // A partial tail — interrupted write — is cut cleanly.
        let body_len = size - HEADERS_PREFIX_LEN;
        let header_size = BlockHeader::SIZE as u64;
        let n = body_len / header_size;
        if body_len % header_size != 0 {
            let clean_len = HEADERS_PREFIX_LEN + n * header_size;
            if let Ok(fh) = OpenOptions::new().write(true).open(&self.path) {
                if fh.set_len(clean_len).is_ok() {
                    eprintln!(
                        "  header store repaired: {} byte(s) of interrupted write cut",
                        size - clean_len
                    );
                }
            }
        }

        // Each header is decoded, then checked against the previous one, **as
        // it is read**: the first one that does not decode or does not link
        // marks the end of what can be trusted. `None` = nothing abnormal.
        let mut headers: Vec<BlockHeader> = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        let mut raw = [0u8; BlockHeader::SIZE];
        let mut first_doubtful: Option<u64> = None;
        for index in 0..n {
            if f.read_exact(&mut raw).is_err() {
                first_doubtful = Some(index);
                break;
            }
            let Ok(h) = BlockHeader::decode(&raw) else {
                first_doubtful = Some(index);
                break;
            };
            if let Some(previous) = headers.last() {
                if h.prev_block != previous.block_id() || h.height != previous.height + 1 {
                    first_doubtful = Some(index);
                    break;
                }
            }
            headers.push(h);
        }

        // The genesis, before everything: a header file from another chain must
        // not be adopted.
        //
        // But a **damaged** genesis is not a foreign genesis. It is a constant
        // of the network; if the header that follows links to the real genesis,
        // the first record is only a few flipped bytes: it is copied over, as
        // the block file does.
        let expected = crate::chain::genesis_id(network);
        let genesis_read = headers.first().map(|h| h.block_id());
        let genesis_doubtful = match genesis_read {
            Some(seen) => seen != expected,
            None => n >= 1, // the first record does not decode
        };
        if genesis_doubtful {
            let foreign = || match genesis_read {
                Some(seen) => StoreError::ForeignGenesis { expected, seen },
                None => StoreError::UnreadableBlock { index: 0 },
            };
            if n < 2 {
                return Err(foreign());
            }
            // The second header, read directly: the loop above may have stopped
            // on it, since it does not link to the fake genesis.
            let mut second = [0u8; BlockHeader::SIZE];
            let mut g = File::open(&self.path)?;
            g.seek(SeekFrom::Start(HEADERS_PREFIX_LEN + header_size))?;
            let s = g
                .read_exact(&mut second)
                .ok()
                .and_then(|_| BlockHeader::decode(&second).ok());
            let links_to_real = s.is_some_and(|s| s.prev_block == expected && s.height == 1);
            if !links_to_real {
                return Err(foreign());
            }
            let canonical = crate::chain::genesis_block(network).header;
            let mut fh = OpenOptions::new().write(true).open(&self.path)?;
            fh.seek(SeekFrom::Start(HEADERS_PREFIX_LEN))?;
            fh.write_all(&canonical.encode())?;
            fh.sync_all()?;
            eprintln!("  header store repaired: damaged genesis header, copied over");
            // Read everything again: the linking must be checked again from the
            // real genesis, and any truncation is decided on this repaired
            // file.
            return self.load(network);
        }

        // Then the cut: everything after the first doubtful header is removed
        // from the file, and the operator knows it.
        if let Some(index) = first_doubtful {
            let clean_len = HEADERS_PREFIX_LEN + index * header_size;
            let cut_bytes = std::fs::metadata(&self.path)?
                .len()
                .saturating_sub(clean_len);
            let fh = OpenOptions::new().write(true).open(&self.path)?;
            if fh.set_len(clean_len).is_err() {
                return Err(StoreError::HeadersBrokenLink { index });
            }
            let _ = fh.sync_all();
            eprintln!(
                "  header store repaired: header {index} is unreadable or does not \
                 link to the previous one; {} header(s) ({cut_bytes} bytes) \
                 removed from height {index}. The network will supply them again",
                n.saturating_sub(index)
            );
        }

        Ok(headers)
    }

    pub fn remove(&self) -> Result<(), StoreError> {
        if self.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::chain::genesis_block;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-test-{name}-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Regtest and not Testnet: the genesis is much cheaper to mine there, and
    /// this module does not test the proof of work.
    fn block() -> Block {
        genesis_block(Network::Regtest)
    }

    #[test]
    fn a_missing_store_reads_as_empty() {
        let s = BlockStore::new(temp_path("missing"));
        let (blocks, err) = s.load_all().unwrap();
        assert!(blocks.is_empty());
        assert!(err.is_none());
    }

    /// Pruning keeps what it is told to keep, in order, the genesis first; what
    /// remains reads back, can be extended, and reopens.
    #[test]
    fn pruning_keeps_the_genesis_and_the_window_and_the_file_reopens() {
        let p = temp_path("pruning");
        let g = block();
        // Distinct "blocks": the genesis modified in its nonce and its height.
        // This module does not check the proof of work.
        let mut blocks = vec![g.clone()];
        for h in 1..=20u64 {
            let mut b = g.clone();
            b.header.height = h;
            b.header.nonce = 1000 + h;
            b.header.prev_block = blocks[(h - 1) as usize].header.block_id();
            blocks.push(b);
        }
        let (archive, _, _) = BlockArchive::open(&p, Network::Regtest).unwrap();
        for b in &blocks {
            archive.append(b).unwrap();
        }
        let before = std::fs::metadata(&p).unwrap().len();

        // We keep only the genesis and the blocks at height >= 15.
        let summary = archive.prune(|h| h.height == 0 || h.height >= 15).unwrap();
        assert_eq!(summary.kept, 7);
        assert_eq!(summary.removed, 14);
        assert!(summary.bytes_freed > 0);
        assert!(std::fs::metadata(&p).unwrap().len() < before);
        assert!(
            !p.with_extension("pruning").exists(),
            "no forgotten temporary file"
        );

        // What is kept reads back; what is removed no longer reads.
        assert_eq!(
            archive.read(&blocks[0].header.block_id()),
            Some(blocks[0].clone())
        );
        assert_eq!(
            archive.read(&blocks[20].header.block_id()),
            Some(blocks[20].clone())
        );
        assert_eq!(
            archive.read(&blocks[15].header.block_id()),
            Some(blocks[15].clone())
        );
        assert_eq!(archive.read(&blocks[14].header.block_id()), None);
        assert_eq!(archive.len(), 7);

        // Writing can continue afterwards.
        let mut next = g.clone();
        next.header.height = 21;
        next.header.nonce = 1021;
        archive.append(&next).unwrap();
        assert_eq!(archive.read(&next.header.block_id()), Some(next.clone()));

        // And reopen: the genesis is still first, the order is that of the
        // heights, and nothing is reported.
        let (reopened, headers, problem) = BlockArchive::open(&p, Network::Regtest).unwrap();
        assert!(problem.is_none());
        assert_eq!(headers.len(), 8);
        assert_eq!(headers[0].height, 0);
        assert_eq!(
            headers.iter().map(|h| h.height).collect::<Vec<_>>(),
            vec![0, 15, 16, 17, 18, 19, 20, 21]
        );
        assert_eq!(
            reopened.read(&blocks[18].header.block_id()),
            Some(blocks[18].clone())
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn round_trip_on_several_blocks() {
        let p = temp_path("round-trip");
        let s = BlockStore::new(&p);
        let b = block();
        s.append(&b).unwrap();
        s.append(&b).unwrap();
        s.append(&b).unwrap();

        let (read_back, err) = s.load_all().unwrap();
        assert!(err.is_none());
        assert_eq!(read_back.len(), 3);
        assert_eq!(read_back[0], b);
        assert_eq!(read_back[2], b);
        s.remove().unwrap();
    }

    #[test]
    fn a_truncation_keeps_the_complete_blocks() {
        let p = temp_path("truncated");
        let s = BlockStore::new(&p);
        s.append(&block()).unwrap();
        s.append(&block()).unwrap();

        // Simulates a power cut in the middle of a write.
        let size = std::fs::metadata(&p).unwrap().len();
        let f = OpenOptions::new().write(true).open(&p).unwrap();
        f.set_len(size - 10).unwrap();
        drop(f);

        let (blocks, err) = s.load_all().unwrap();
        assert_eq!(blocks.len(), 1, "the first block had to survive");
        assert!(matches!(err, Some(StoreError::TruncatedFile { index: 1 })));
        s.remove().unwrap();
    }

    /// A damaged tail is **cut**, not worked around.
    ///
    /// # The defect, and why it got worse at every restart
    ///
    /// A power cut in the middle of a write leaves a half-written record at the
    /// end of the file. The scan stopped there and reported the incident:
    /// correct. But the following blocks were written **after** those damaged
    /// bytes. They reached the disk, were served as long as the process lived,
    /// and disappeared at the next restart — since the scan always stopped at
    /// the same place. The file grew while returning nothing more: a silent,
    /// cumulative data loss.
    #[test]
    fn a_damaged_tail_is_cut_on_opening() {
        let p = temp_path("damaged-tail");
        let s = BlockStore::new(&p);
        let g = crate::chain::genesis_block(crate::address::Network::Regtest);
        s.append(&g).unwrap();
        let sound_len = std::fs::metadata(&p).unwrap().len();

        // An interrupted write: a few bytes of a following record.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&[0x40, 0x01, 0x00, 0x00, 0xaa, 0xbb]).unwrap();
        }
        assert!(std::fs::metadata(&p).unwrap().len() > sound_len);

        let (_a, headers, problem) =
            BlockArchive::open(&p, crate::address::Network::Regtest).unwrap();
        assert_eq!(headers.len(), 1, "the complete block must survive");
        assert!(
            problem.is_none(),
            "the tail having been cut, there is no incident left to report"
        );
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            sound_len,
            "the file must be back at the end of the last complete record"
        );
        // Nothing is thrown away without a copy: the six cut bytes are alongside.
        let cut = std::fs::read(cut_path(&p)).expect("the copy of the cut tail");
        assert_eq!(cut, vec![0x40, 0x01, 0x00, 0x00, 0xaa, 0xbb]);
        let _ = std::fs::remove_file(cut_path(&p));

        // And above all: what is written next is read back at the next restart.
        s.append(&g).unwrap();
        let (_a2, headers2, problem2) =
            BlockArchive::open(&p, crate::address::Network::Regtest).unwrap();
        assert_eq!(
            headers2.len(),
            2,
            "a block written after the repair must read back"
        );
        assert!(problem2.is_none());
        s.remove().unwrap();
    }

    /// A tail longer than a block is not an interrupted write: nothing is cut,
    /// and the incident stays reported.
    #[test]
    fn a_tail_longer_than_a_block_is_not_cut() {
        let p = temp_path("tail-too-long");
        let s = BlockStore::new(&p);
        let g = crate::chain::genesis_block(crate::address::Network::Regtest);
        s.append(&g).unwrap();
        let sound_len = std::fs::metadata(&p).unwrap().len();
        {
            // A length prefix that promises a giant record, followed by more
            // than a block of bytes: this is not a truncated tail.
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&(MAX_SERIALIZED_BLOCK - 1).to_le_bytes())
                .unwrap();
            let padding = vec![0u8; crate::consensus::MAX_BLOCK_SIZE + 64];
            f.write_all(&padding).unwrap();
        }
        let (_a, headers, problem) =
            BlockArchive::open(&p, crate::address::Network::Regtest).unwrap();
        assert_eq!(headers.len(), 1);
        assert!(problem.is_some(), "the incident must stay reported");
        assert!(
            std::fs::metadata(&p).unwrap().len() > sound_len,
            "nothing must have been cut"
        );
        s.remove().unwrap();
    }

    /// A genesis with a flipped byte is copied over, not set aside as a foreign
    /// chain.
    #[test]
    fn a_damaged_genesis_is_copied_over() {
        use crate::address::Network::Regtest;
        let p = temp_path("damaged-genesis");
        let s = BlockStore::new(&p);
        let g = crate::chain::genesis_block(Regtest);
        s.append(&g).unwrap();
        // A second block that links to the real genesis.
        let c = crate::chain::Chain::new(Regtest, g.clone());
        let b = c
            .mine_block(
                crate::hash::Hash256([3u8; 32]),
                crate::sig::SchemeId::LamportOts,
                &[],
                g.header.time + 120,
                5_000_000,
            )
            .expect("mining");
        s.append(&b).unwrap();

        // A flipped byte in the nonce of the genesis (in the body, not in the
        // length prefix).
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
            let encoded = g.encode();
            // The nonce is at the end of the header: we flip byte 4 + 100.
            let position = 4 + (BlockHeader::SIZE as u64 - 1);
            f.seek(SeekFrom::Start(position)).unwrap();
            let mut byte = [0u8; 1];
            f.read_exact(&mut byte).unwrap();
            f.seek(SeekFrom::Start(position)).unwrap();
            f.write_all(&[byte[0] ^ 0x01]).unwrap();
            assert!(encoded.len() > 4);
        }
        let (_a, headers, problem) = BlockArchive::open(&p, Regtest).expect("repair");
        assert!(problem.is_none());
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].block_id(), crate::chain::genesis_id(Regtest));
        s.remove().unwrap();
    }

    #[test]
    fn an_absurd_size_is_refused_without_allocating() {
        let p = temp_path("absurd-size");
        {
            let mut f = File::create(&p).unwrap();
            f.write_all(&u32::MAX.to_le_bytes()).unwrap();
        }
        let s = BlockStore::new(&p);
        let (blocks, err) = s.load_all().unwrap();
        assert!(blocks.is_empty());
        assert!(matches!(err, Some(StoreError::BlockTooLarge { .. })));
        s.remove().unwrap();
    }

    /// The defect the archive fixes, locked in by a test.
    ///
    /// A block appended **after** opening must stay servable. The previous
    /// version built the index once and for all: the block was indeed written,
    /// but could not be found as soon as it left the chain's memory window. A
    /// node joining a chain in progress then stayed at height zero forever.
    #[test]
    fn a_block_appended_after_opening_stays_servable() {
        let p = temp_path("archive");
        let store = BlockStore::new(&p);
        store.append(&block()).unwrap();

        let (archive, headers, problem) = BlockArchive::open(&p, Network::Regtest).unwrap();
        assert!(problem.is_none());
        assert_eq!(headers.len(), 1);
        assert_eq!(archive.len(), 1);

        // A different block, appended afterwards.
        let mut new_block = block();
        new_block.header.nonce = 12_345;
        let id = new_block.header.block_id();
        assert!(archive.read(&id).is_none(), "not written yet");

        archive.append(&new_block).unwrap();
        assert_eq!(archive.len(), 2);
        assert_eq!(
            archive.read(&id).map(|b| b.header.nonce),
            Some(12_345),
            "a written block must be readable immediately"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_reread_archive_finds_all_its_blocks() {
        let p = temp_path("archive-reread");
        {
            let (a, _, _) = BlockArchive::open(&p, Network::Regtest).unwrap();
            // The first record must stay the real genesis: an archive that
            // starts elsewhere is now refused.
            a.append(&block()).unwrap();
            for n in 1..5u64 {
                let mut b = block();
                b.header.nonce = n;
                a.append(&b).unwrap();
            }
        }
        let (a, headers, problem) = BlockArchive::open(&p, Network::Regtest).unwrap();
        assert!(problem.is_none());
        assert_eq!(headers.len(), 5);
        assert_eq!(a.read(&block().header.block_id()), Some(block()));
        for n in 1..5u64 {
            let mut b = block();
            b.header.nonce = n;
            assert_eq!(a.read(&b.header.block_id()), Some(b));
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_corrupted_block_is_reported() {
        let p = temp_path("corrupted");
        {
            let mut f = File::create(&p).unwrap();
            let payload = [0xffu8; 40];
            f.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&payload).unwrap();
        }
        let s = BlockStore::new(&p);
        let (_, err) = s.load_all().unwrap();
        assert!(matches!(
            err,
            Some(StoreError::UnreadableBlock { index: 0 })
        ));
        s.remove().unwrap();
    }

    // -----------------------------------------------------------------------
    // Header store
    // -----------------------------------------------------------------------

    /// Structurally linked header chain: the real genesis, then headers that
    /// point to the previous one. The proof of work is not valid — the store
    /// does not check it, that is adoption's business.
    fn header_chain(n: u64) -> Vec<BlockHeader> {
        let g = genesis_block(Network::Regtest).header;
        let mut v = vec![g];
        for i in 1..n {
            let mut h = g;
            h.height = i;
            h.nonce = i;
            h.prev_block = v[(i - 1) as usize].block_id();
            v.push(h);
        }
        v
    }

    #[test]
    fn a_missing_header_store_reads_as_empty() {
        let s = HeaderStore::new(temp_path("hdr-missing"));
        assert!(s.load(Network::Regtest).unwrap().is_empty());
    }

    #[test]
    fn round_trip_on_the_header_chain() {
        let p = temp_path("hdr-round-trip");
        let s = HeaderStore::new(&p);
        let chain = header_chain(12);
        s.append(&chain).unwrap();
        assert_eq!(s.load(Network::Regtest).unwrap(), chain);
        s.remove().unwrap();
    }

    #[test]
    fn headers_are_appended_in_batches() {
        let p = temp_path("hdr-batches");
        let s = HeaderStore::new(&p);
        let chain = header_chain(10);
        s.append(&chain[..4]).unwrap();
        s.append(&chain[4..]).unwrap();
        assert_eq!(s.load(Network::Regtest).unwrap(), chain);
        s.remove().unwrap();
    }

    #[test]
    fn a_partial_header_tail_is_cut() {
        let p = temp_path("hdr-tail");
        let s = HeaderStore::new(&p);
        let chain = header_chain(6);
        s.append(&chain).unwrap();
        // An interrupted write: half of one more header.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(&[0xaa; BlockHeader::SIZE / 2]).unwrap();
        }
        assert_eq!(
            s.load(Network::Regtest).unwrap(),
            chain,
            "the partial tail must be cut, the complete chain read back"
        );
        s.remove().unwrap();
    }

    /// A broken link in the middle no longer dooms the store: it is cut at the
    /// last sound position, and what follows will come back from the network.
    #[test]
    fn a_broken_link_is_cut_at_the_last_sound_position() {
        let p = temp_path("hdr-link");
        let s = HeaderStore::new(&p);
        let mut chain = header_chain(5);
        // We break the linking of the third header.
        chain[3].prev_block = crate::hash::Hash256([0x77; 32]);
        s.append(&chain).unwrap();
        let read_back = s.load(Network::Regtest).expect("the store repairs itself");
        assert_eq!(
            read_back,
            chain[..3],
            "0..=2 are sound, 3 and 4 are removed"
        );
        assert_eq!(
            std::fs::metadata(&p).unwrap().len(),
            HEADERS_PREFIX_LEN + 3 * BlockHeader::SIZE as u64,
            "the file is truncated, not just read short"
        );
        // And writing can continue: the sound headers come back.
        let good = header_chain(5);
        s.append(&good[3..]).unwrap();
        assert_eq!(s.load(Network::Regtest).unwrap(), good);
        s.remove().unwrap();
    }

    /// A damaged genesis header is not a foreign genesis: it is copied over
    /// from the network constant, as in the block file.
    #[test]
    fn a_damaged_genesis_in_the_store_is_copied_over() {
        let p = temp_path("hdr-damaged-genesis");
        let s = HeaderStore::new(&p);
        let chain = header_chain(4);
        s.append(&chain).unwrap();
        // A bit in the nonce of the genesis: its identifier changes, the
        // second header no longer links to it.
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&p).unwrap();
            f.seek(SeekFrom::Start(
                HEADERS_PREFIX_LEN + BlockHeader::SIZE as u64 - 1,
            ))
            .unwrap();
            let mut o = [0u8; 1];
            f.read_exact(&mut o).unwrap();
            f.seek(SeekFrom::Start(
                HEADERS_PREFIX_LEN + BlockHeader::SIZE as u64 - 1,
            ))
            .unwrap();
            f.write_all(&[o[0] ^ 0x01]).unwrap();
        }
        assert_eq!(s.load(Network::Regtest).unwrap(), chain);
        s.remove().unwrap();
    }

    #[test]
    fn a_foreign_genesis_in_the_headers_is_refused() {
        let p = temp_path("hdr-genesis");
        let s = HeaderStore::new(&p);
        let mut chain = header_chain(3);
        // The first header is no longer the real genesis.
        chain[0].nonce = 999;
        // The second is pointed at it again so that only the genesis check
        // bites.
        chain[1].prev_block = chain[0].block_id();
        s.append(&chain).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StoreError::ForeignGenesis { .. })
        ));
        s.remove().unwrap();
    }

    #[test]
    fn a_file_without_magic_is_not_a_header_store() {
        let p = temp_path("hdr-magic");
        std::fs::write(&p, b"this is not a header store at all").unwrap();
        let s = HeaderStore::new(&p);
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StoreError::HeadersMagic)
        ));
        s.remove().unwrap();
    }
}
