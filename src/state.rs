//! Snapshot of the monetary state, persisted on disk.
//!
//! # The wall this module knocks down
//!
//! Up to phase 7, starting a node meant revalidating the whole chain from the
//! genesis. With the proof of work fixed in phase 6 — 660 us per block — and
//! ML-DSA signatures to verify, a million blocks took hours. A node that cannot
//! be restarted in a few seconds is not usable, and software that one does not
//! dare restart never gets updated.
//!
//! # What is persisted, and what is not
//!
//! **Persisted**: the UTXO set, the tip, the height, the total issued. It is
//! the state of the currency, and it is what is expensive to rebuild.
//!
//! **Not persisted**: the header index, which is rebuilt by a sequential read
//! of the block file ([`crate::store::BlockStore::scan_headers`]) without
//! decoding a single transaction.
//!
//! # What this snapshot is not
//!
//! It is **not** a proof. A node that loads this snapshot trusts its own disk:
//! the checksum detects accidental corruption, not an adversary with access to
//! the file. This is exactly the status of Bitcoin Core's `chainstate`, and for
//! the same reason: whoever can rewrite your files has already won.
//!
//! What remains guaranteed: every block **arriving after** the snapshot is
//! fully validated, and an unreadable or inconsistent snapshot falls back to
//! full revalidation rather than to silent acceptance.
//!
//! # Atomic write
//!
//! We write to a temporary file, force its physical write, then rename. A
//! rename is atomic on the usual file systems: at no instant does a half-written
//! snapshot exist. A power cut leaves either the old snapshot or the new one —
//! never a mix.

use crate::address::Network;
use crate::amount::Amount;
use crate::hash::Hash256;
use crate::ser::{Reader, Writer};
use crate::sha256::sha256;
use crate::sig::SchemeId;
use crate::tx::{OutPoint, TxOut};
use crate::utxo::{UtxoEntry, UtxoSet};
use std::path::{Path, PathBuf};

/// Frozen format magic of `state.dat` (binary file format), not a word to
/// translate.
const MAGIC: &[u8; 8] = b"Q21STATE";
const VERSION: u32 = 1;

/// Version of the snapshot format, distinct from [`VERSION`] (which remains the
/// one of the transaction pool). It moved to 2 with the arrival of the MuHash
/// commitment: a snapshot now carries the commitment to its UTXO set, and an
/// old version 1 file is simply replayed from the blocks.
const SNAPSHOT_VERSION: u32 = 2;

/// Safety bound: a corrupted file must not trigger an absurd allocation even
/// before the checksum is verified.
const MAX_UTXO: u64 = 500_000_000;

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    /// The file is not a Q21 snapshot.
    InvalidMagic,
    /// Written by a version that did not know this format.
    UnknownVersion(u32),
    /// Snapshot from another network: loading it would mix two currencies.
    WrongNetwork,
    /// The checksum does not match: corrupted file.
    InvalidChecksum,
    /// The seal does not match: corrupted file **or** one crafted by a third
    /// party. The two cases are not told apart, and the file is treated as
    /// absent in both.
    InvalidSeal,
    /// The snapshot contradicts itself: total issued impossible at this height,
    /// or sum of outputs greater than what was ever issued.
    Inconsistent(&'static str),
    /// The MuHash commitment written in the snapshot does not match the UTXO
    /// set it contains: the file was altered without the commitment being
    /// recomputed, or it was corrupted.
    InvalidCommitment,
    /// Unreadable structure.
    Unreadable,
    /// Announced number of entries beyond all plausibility.
    TooManyEntries(u64),
}

impl From<std::io::Error> for StateError {
    fn from(e: std::io::Error) -> Self {
        StateError::Io(e)
    }
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Io(e) => write!(f, "input/output error: {e}"),
            StateError::InvalidMagic => write!(f, "this file is not a Q21 snapshot"),
            StateError::UnknownVersion(v) => {
                write!(f, "snapshot version {v}, unknown to this binary")
            }
            StateError::WrongNetwork => write!(f, "snapshot from another network"),
            StateError::InvalidChecksum => write!(
                f,
                "invalid checksum: corrupted snapshot, \
                 the chain will be fully revalidated"
            ),
            StateError::InvalidSeal => write!(
                f,
                "invalid seal: this file was not written by this node, \
                 it is ignored"
            ),
            StateError::Inconsistent(what) => write!(f, "inconsistent snapshot: {what}"),
            StateError::InvalidCommitment => write!(
                f,
                "wrong UTXO set commitment: the snapshot does not match \
                 the state it claims to carry, it is ignored"
            ),
            StateError::Unreadable => write!(f, "unreadable snapshot"),
            StateError::TooManyEntries(n) => write!(f, "{n} entries announced: refused"),
        }
    }
}

/// Monetary state at a precise point of the chain.
#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    pub network: Network,
    pub height: u64,
    pub tip: Hash256,
    /// Total issued, in units.
    pub issued: u64,
    pub utxo: UtxoSet,
    /// MuHash commitment of the UTXO set above, computed on write and checked
    /// on load. It is the commitment to the set: two nodes at the same height
    /// carry the same one, and a file whose set does not reproduce it is
    /// rejected.
    ///
    /// It is not the value one copies to adopt a snapshot: that one is
    /// [`Snapshot::commitment`], which also commits to the total issued.
    pub muhash: Hash256,
}

/// Label of the state commitment, distinct from those of the MuHash.
///
/// Renamed in 0.4; the 0.3.x label is kept in
/// [`crate::legacy::LEGACY_STATE_TAG`]. The label is not part of consensus:
/// no block or header commits to it.
const TAG_STATE_COMMITMENT: &str = "Q21/state/commitment";

/// The commitment of a state: what one copies, compares and gives to
/// `--commitment`.
///
/// # Why it commits to more than the UTXO set
///
/// The MuHash only commits to the unspent outputs. The **total issued** does
/// not follow from it: what was spent then destroyed as fees no longer appears
/// in it, and a miner can claim less than its subsidy. A snapshot whose total
/// issued is rewritten — within the range the invariants tolerate — therefore
/// carried the same MuHash commitment, and got adopted with the right trusted
/// value: the displayed money supply was wrong, and the anti-inflation bound of
/// the cap was computed on a wrong total (phase 8b red team, 2nd campaign,
/// item 6c).
///
/// The state commitment binds the two: MuHash and total issued, under a label
/// of its own. The MuHash stays what it is — the incremental commitment to the
/// set, kept up to date as blocks come — and the snapshot format does not
/// change: only the value compared against a trusted source now derives from
/// it.
pub fn state_commitment(muhash: Hash256, issued: u64) -> Hash256 {
    state_commitment_with_tag(TAG_STATE_COMMITMENT, muhash, issued)
}

/// [`state_commitment`] under an explicit label. Only the upgrade of a 0.3.x
/// data directory uses a label other than the current one: see
/// [`crate::legacy`].
pub fn state_commitment_with_tag(tag: &str, muhash: Hash256, issued: u64) -> Hash256 {
    crate::hash::tagged_hash_parts(tag, &[muhash.as_bytes(), &issued.to_le_bytes()])
}

impl Snapshot {
    /// The commitment of this state: see [`state_commitment`].
    pub fn commitment(&self) -> Hash256 {
        state_commitment(self.muhash, self.issued)
    }

    /// Invariants that every honest snapshot satisfies, checked **without
    /// trusting anyone**.
    ///
    /// # Why this check exists
    ///
    /// An audit crafted a `state.dat` by adding to it an output of one billion
    /// units in the attacker's name. The node loaded it without a blink: the
    /// checksum was right — the attacker had recomputed it — and nothing else
    /// was checked. The node therefore started again with money that had never
    /// been mined.
    ///
    /// The rules below require no key and no trust: they confront the snapshot
    /// with the **emission schedule**, which is pure consensus. No money can
    /// exist beyond what the schedule allows at this height, whatever the
    /// origin of the file.
    ///
    /// # What they do not catch, and what now takes care of it
    ///
    /// A forgery that *moves* ownership without creating anything — rewriting
    /// the key hash of an existing output — respects these emission invariants.
    /// It is the **MuHash commitment** ([`Snapshot::muhash`]) that sees it: it
    /// depends on every key hash, so any move changes it.
    ///
    /// Be careful about what this proves, and what it does not. Checking that
    /// the set reproduces the recorded commitment only binds the file to
    /// itself: a forger who rewrites the set recomputes the commitment to
    /// match. The defense is only complete when this commitment is compared
    /// against a **trusted value coming from elsewhere** — a checkpoint shipped
    /// with the binary, or the commitment that an already synced peer
    /// announces. That anchoring is the next step; the present module computes,
    /// carries and checks the commitment to make it possible.
    pub fn check_consistency(&self) -> Result<(), StateError> {
        use crate::consensus::{GENESIS_PREMINT, MAX_SUPPLY};

        // 1. The absolute cap. It depends on nothing else.
        if self.issued > MAX_SUPPLY {
            return Err(StateError::Inconsistent("total issued beyond the cap"));
        }

        // 2. The emission schedule bounds what can exist at this height. A
        //    miner can claim less than its subsidy — never more. The inequality
        //    is therefore loose in one direction only.
        let cap_at_this_height = crate::emission::total_supply_at(self.height).units();
        if self.issued > cap_at_this_height {
            return Err(StateError::Inconsistent(
                "total issued greater than what the schedule allows at this height",
            ));
        }
        if self.issued < GENESIS_PREMINT {
            return Err(StateError::Inconsistent(
                "total issued lower than the genesis coin",
            ));
        }

        // 3. No unspent money can exceed the money issued. This is the rule
        //    that defeats forgery by addition.
        let mut sum: u64 = 0;
        for (_, e) in self.utxo.iter() {
            sum = sum
                .checked_add(e.output.value.units())
                .ok_or(StateError::Inconsistent("sum of outputs beyond u64"))?;
            // 4. An output cannot come from a block that does not exist yet.
            if e.height > self.height {
                return Err(StateError::Inconsistent(
                    "an output is dated from a block after the tip",
                ));
            }
        }
        if sum > self.issued {
            return Err(StateError::Inconsistent(
                "sum of outputs greater than the total issued",
            ));
        }

        Ok(())
    }
}

fn network_code(n: Network) -> u8 {
    match n {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Regtest => 2,
    }
}

impl Snapshot {
    fn encode(&self) -> Vec<u8> {
        // 105 bytes per entry, plus the header: this avoids a few hundred
        // reallocations on a real UTXO set.
        let mut w = Writer::with_capacity(96 + self.utxo.len() * 112);
        w.bytes(MAGIC);
        w.u32(SNAPSHOT_VERSION);
        w.u8(network_code(self.network));
        w.u64(self.height);
        w.bytes(self.tip.as_bytes());
        w.u64(self.issued);
        w.bytes(self.muhash.as_bytes());
        w.varint(self.utxo.len() as u64);

        // Deterministic order: two nodes in the same state write the same file,
        // which makes snapshots comparable byte for byte.
        let mut entries: Vec<(&OutPoint, &UtxoEntry)> = self.utxo.iter().collect();
        entries.sort_by_key(|(o, _)| **o);

        for (o, e) in entries {
            w.bytes(o.txid.as_bytes());
            w.u32(o.index);
            w.u64(e.output.value.units());
            w.u8(e.output.scheme.as_u8());
            w.bytes(e.output.pubkey_hash.as_bytes());
            w.u64(e.height);
            w.u8(u8::from(e.is_coinbase));
        }

        let mut data = w.finish();
        let checksum = sha256(&data);
        data.extend_from_slice(&checksum);
        data
    }

    fn decode(data: &[u8], expected_network: Network) -> Result<Snapshot, StateError> {
        Snapshot::decode_with(data, expected_network, None)
    }

    /// Decodes a snapshot. With `legacy_muhash_tag`, the recorded MuHash must
    /// match the UTXO set under that older label instead of the current one;
    /// the decoded snapshot then carries the commitment under the **current**
    /// label. Only the upgrade of a 0.3.x data directory passes a label.
    fn decode_with(
        data: &[u8],
        expected_network: Network,
        legacy_muhash_tag: Option<&str>,
    ) -> Result<Snapshot, StateError> {
        if data.len() < 32 {
            return Err(StateError::Unreadable);
        }
        let (payload, checksum) = data.split_at(data.len() - 32);
        if sha256(payload) != checksum {
            return Err(StateError::InvalidChecksum);
        }

        let mut r = Reader::new(payload);
        let mut magic = [0u8; 8];
        for o in &mut magic {
            *o = r.u8().map_err(|_| StateError::Unreadable)?;
        }
        if &magic != MAGIC {
            return Err(StateError::InvalidMagic);
        }
        let version = r.u32().map_err(|_| StateError::Unreadable)?;
        if version != SNAPSHOT_VERSION {
            return Err(StateError::UnknownVersion(version));
        }
        let network_byte = r.u8().map_err(|_| StateError::Unreadable)?;
        if network_byte != network_code(expected_network) {
            return Err(StateError::WrongNetwork);
        }

        let height = r.u64().map_err(|_| StateError::Unreadable)?;
        let tip = Hash256(r.array32().map_err(|_| StateError::Unreadable)?);
        let issued = r.u64().map_err(|_| StateError::Unreadable)?;
        let muhash = Hash256(r.array32().map_err(|_| StateError::Unreadable)?);
        let n = r.varint().map_err(|_| StateError::Unreadable)?;
        if n > MAX_UTXO {
            return Err(StateError::TooManyEntries(n));
        }

        let mut utxo = UtxoSet::new();
        for _ in 0..n {
            let txid = Hash256(r.array32().map_err(|_| StateError::Unreadable)?);
            let index = r.u32().map_err(|_| StateError::Unreadable)?;
            let value = Amount::from_units(r.u64().map_err(|_| StateError::Unreadable)?);
            let scheme = SchemeId::from_u8(r.u8().map_err(|_| StateError::Unreadable)?)
                .ok_or(StateError::Unreadable)?;
            let pubkey_hash = Hash256(r.array32().map_err(|_| StateError::Unreadable)?);
            let entry_height = r.u64().map_err(|_| StateError::Unreadable)?;
            let coinbase = r.u8().map_err(|_| StateError::Unreadable)? != 0;

            utxo.insert(
                OutPoint { txid, index },
                UtxoEntry {
                    output: TxOut {
                        value,
                        scheme,
                        pubkey_hash,
                    },
                    height: entry_height,
                    is_coinbase: coinbase,
                },
            );
        }
        r.expect_end().map_err(|_| StateError::Unreadable)?;

        // The commitment first: the UTXO set must reproduce the recorded
        // commitment. A file in which an output was altered without
        // recomputing the commitment fails here, even before the emission
        // invariants.
        let muhash = match legacy_muhash_tag {
            None if utxo.commitment() == muhash => muhash,
            Some(tag) if utxo.commitment_with_tag(tag) == muhash => utxo.commitment(),
            _ => return Err(StateError::InvalidCommitment),
        };

        let s = Snapshot {
            network: expected_network,
            height,
            tip,
            issued,
            utxo,
            muhash,
        };
        // A snapshot that contradicts itself is not loaded, whatever the
        // validity of its checksum.
        s.check_consistency()?;
        Ok(s)
    }
}

impl Snapshot {
    /// Serializes the snapshot in its **portable** form: the same encoding as
    /// the local snapshot, but **without the directory seal**.
    ///
    /// # What this format is, and what it is not
    ///
    /// It can be shared: no local key goes into it, so any machine can read it
    /// back. Its **faithfulness** — does the set match the recorded commitment
    /// — is checked on reading, as for a local snapshot. What it does not carry
    /// is **trust**: nothing in the file proves that this commitment is the one
    /// of the real chain. It is up to whoever adopts it to compare
    /// [`Snapshot::commitment`] with a value obtained from a trusted source —
    /// the commitment their own explorer displays, for example.
    pub fn to_portable_bytes(&self) -> Vec<u8> {
        self.encode()
    }

    /// Reads back a portable snapshot: checks the checksum, then that the set
    /// reproduces the recorded commitment, then emission consistency.
    ///
    /// Does **not** check trust. The caller must still compare the commitment
    /// read back with a trusted value before adopting the state.
    pub fn from_portable_bytes(data: &[u8], network: Network) -> Result<Snapshot, StateError> {
        Snapshot::decode(data, network)
    }
}

/// Secret unique to a data directory.
///
/// # What it is for, and what it is not for
///
/// It **does not protect** against an adversary who already has write access
/// to the directory: that one can read the key, or simply replace the binary.
/// On this point the position is that of Bitcoin Core, and it is honest:
/// whoever can rewrite your files has already won.
///
/// It protects against a different and much more common case: a state file
/// **coming from elsewhere**. A downloaded "fast sync snapshot", a backup from
/// another computer, a shared volume. That file does not have the seal of this
/// directory, and it is not adopted — it is ignored, and the chain is
/// revalidated from the block file, which for its part carries a proof of
/// work.
///
/// The key is drawn from the system generator on first opening, written with
/// restricted permissions, and never transmitted.
pub fn datadir_key(datadir: &Path) -> Result<[u8; 32], StateError> {
    let path = datadir.join("node.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return Ok(k);
        }
        // A key file of the wrong size is a broken file: it is replaced rather
        // than stopping, the snapshot will simply be replayed.
    }
    let k = crate::rng::bytes::<32>().map_err(|_| {
        StateError::Io(std::io::Error::other("system random generator unavailable"))
    })?;
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&k)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    restrict(&path);
    Ok(k)
}

fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Creates a temporary file **already** restricted to its owner.
///
/// # The defect this closes
///
/// Temporary files were created with the `umask` permissions — 0644 most of
/// the time — then filled, synced, renamed; the restriction, when there was
/// one, came afterwards. Between creation and rename, any account on the
/// machine could open the file, and an open descriptor survives `chmod`. For
/// `addresses.dat`, which lists every key hash of the holder, the restriction
/// did not even exist: the file stayed at 0644 forever, publicly linking
/// addresses that the protocol strives not to link.
///
/// On Unix, the mode is set at creation, through `O_CREAT`: there is no
/// window. `create_new` refuses a temporary file that would already exist — a
/// leftover of an interrupted write is removed first, never reopened in place.
/// Elsewhere, we fall back on ordinary creation followed by the available
/// restriction.
pub(crate) fn create_private_temp(tmp: &Path) -> std::io::Result<std::fs::File> {
    let _ = std::fs::remove_file(tmp);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)
    }
    #[cfg(not(unix))]
    {
        let f = std::fs::File::create(tmp)?;
        restrict(tmp);
        Ok(f)
    }
}

/// Snapshot file.
pub struct StateStore {
    path: PathBuf,
    key: [u8; 32],
}

impl StateStore {
    /// Snapshot sealed by the directory key.
    pub fn new_sealed<P: AsRef<Path>>(path: P, key: [u8; 32]) -> StateStore {
        StateStore {
            path: path.as_ref().to_path_buf(),
            key,
        }
    }

    pub fn new<P: AsRef<Path>>(path: P) -> StateStore {
        StateStore {
            path: path.as_ref().to_path_buf(),
            key: [0u8; 32],
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Writes the snapshot atomically.
    ///
    /// Temporary file, `sync_all`, then rename. The `sync_all` is not
    /// decorative: without it, the rename can become visible before the
    /// contents are actually on disk, and a power cut would leave a snapshot
    /// that looks valid and is in fact empty.
    pub fn save(&self, s: &Snapshot) -> Result<(), StateError> {
        let mut data = s.encode();
        data.extend_from_slice(&crate::kdf::hmac_sha256(&self.key, &data));
        let tmp = self.path.with_extension("tmp");

        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;

        // The rename itself must be durable: on most systems this requires
        // syncing the parent directory. Failure is not fatal — we will simply
        // have fewer guarantees than hoped.
        if let Some(parent) = self.path.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    pub fn load(&self, network: Network) -> Result<Snapshot, StateError> {
        let data = std::fs::read(&self.path)?;
        Snapshot::decode(self.unseal(&data)?, network)
    }

    /// Upgrade only: rewrites a snapshot whose MuHash was recorded under the
    /// 0.3.x label `legacy_muhash_tag`, so that it loads under the current
    /// label.
    ///
    /// The file must still pass every check a normal load makes (seal,
    /// checksum, format, emission invariants), and its UTXO set must
    /// reproduce the recorded MuHash under the old label: nothing is trusted
    /// that a normal load would refuse. Returns `Ok(true)` when the file was
    /// rewritten, `Ok(false)` when it already loads under the current label.
    pub fn migrate_commitment_label(&self, legacy_muhash_tag: &str) -> Result<bool, StateError> {
        let data = std::fs::read(&self.path)?;
        let payload = self.unseal(&data)?;
        for n in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            match Snapshot::decode(payload, n) {
                Ok(_) => return Ok(false),
                Err(StateError::WrongNetwork) => continue,
                Err(StateError::InvalidCommitment) => {}
                Err(e) => return Err(e),
            }
            let s = Snapshot::decode_with(payload, n, Some(legacy_muhash_tag))?;
            self.save(&s)?;
            return Ok(true);
        }
        Err(StateError::WrongNetwork)
    }

    /// Checks the directory seal and returns the sealed payload.
    fn unseal<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], StateError> {
        if data.len() < 32 {
            return Err(StateError::Unreadable);
        }
        let (payload, seal) = data.split_at(data.len() - 32);
        let expected = crate::kdf::hmac_sha256(&self.key, payload);
        if !crate::kdf::constant_time_eq(&expected, seal) {
            return Err(StateError::InvalidSeal);
        }
        Ok(payload)
    }

    /// What the snapshot **on disk** announces: its height and its tip.
    ///
    /// # The defect this closes
    ///
    /// Pruning decided what it could remove based on a height **passed by the
    /// caller** — that of the snapshot it had just tried to write. If the
    /// write had failed (full disk, `rename` refused on Windows by an
    /// antivirus holding the file), the height was fictitious: the bodies
    /// between the snapshot actually on disk and the kept window were removed,
    /// and the node fell back on restart. The only height that counts is the
    /// file's; it is the one read back here, before removing anything.
    ///
    /// The directory seal and the checksum are verified on the whole file — a
    /// damaged snapshot must not serve as a guarantee either — but only the
    /// header is decoded: the UTXO set can weigh hundreds of megabytes, and
    /// pruning does not need it.
    pub fn header_on_disk(&self, network: Network) -> Result<(u64, Hash256), StateError> {
        let data = std::fs::read(&self.path)?;
        let payload = self.unseal(&data)?;
        if payload.len() < 32 {
            return Err(StateError::Unreadable);
        }
        let (contents, checksum) = payload.split_at(payload.len() - 32);
        if sha256(contents) != checksum {
            return Err(StateError::InvalidChecksum);
        }
        let mut r = Reader::new(contents);
        let mut magic = [0u8; 8];
        for o in &mut magic {
            *o = r.u8().map_err(|_| StateError::Unreadable)?;
        }
        if &magic != MAGIC {
            return Err(StateError::InvalidMagic);
        }
        let version = r.u32().map_err(|_| StateError::Unreadable)?;
        if version != SNAPSHOT_VERSION {
            return Err(StateError::UnknownVersion(version));
        }
        let network_byte = r.u8().map_err(|_| StateError::Unreadable)?;
        if network_byte != network_code(network) {
            return Err(StateError::WrongNetwork);
        }
        let height = r.u64().map_err(|_| StateError::Unreadable)?;
        let tip = Hash256(r.array32().map_err(|_| StateError::Unreadable)?);
        Ok((height, tip))
    }

    pub fn remove(&self) -> Result<(), StateError> {
        if self.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Wallet address cache
// ---------------------------------------------------------------------------

/// Frozen format magic of `addresses.dat` (binary file format), not a word to
/// translate.
const ADDR_MAGIC: &[u8; 8] = b"Q21ADDRS";
/// The address cache moved from a bare checksum to an authenticated seal. An
/// old file has no valid seal: it will be rejected and derived again, which
/// costs a second and loses nothing.
const ADDR_VERSION: u32 = 2;

/// Hashes of addresses already derived, in a local cache.
///
/// # The second startup wall
///
/// Once the chain was made incremental, the startup time moved elsewhere: a
/// wallet of sixty thousand ML-DSA addresses needed twenty seconds of
/// derivation, against half a second for the whole chain. The measurement
/// pointed to the culprit, as always.
///
/// This file is only a cache: it holds no secret — a public key hash is
/// already public — and losing it only costs a full derivation. The wallet
/// spot-checks it before adopting it
/// ([`crate::wallet::Wallet::adopt_hashes`]).
pub struct AddressCache {
    path: PathBuf,
}

impl AddressCache {
    pub fn new<P: AsRef<Path>>(path: P) -> AddressCache {
        AddressCache {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn save(
        &self,
        scheme: SchemeId,
        hashes: &[Hash256],
        key: &[u8; 32],
    ) -> Result<(), StateError> {
        let mut w = Writer::with_capacity(32 + hashes.len() * 32);
        w.bytes(ADDR_MAGIC);
        w.u32(ADDR_VERSION);
        w.u8(scheme.as_u8());
        w.varint(hashes.len() as u64);
        for h in hashes {
            w.bytes(h.as_bytes());
        }
        let mut data = w.finish();
        let seal = crate::kdf::hmac_sha256(key, &data);
        data.extend_from_slice(&seal);

        // The cache is created already restricted: it carries no secret, but it
        // designates every address of the holder, and that is none of the
        // other accounts' business on the machine.
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = create_private_temp(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        restrict(&self.path);
        Ok(())
    }

    pub fn load(&self, scheme: SchemeId, key: &[u8; 32]) -> Result<Vec<Hash256>, StateError> {
        let data = std::fs::read(&self.path)?;
        if data.len() < 32 {
            return Err(StateError::Unreadable);
        }
        let (payload, seal) = data.split_at(data.len() - 32);
        // Constant-time comparison: the seal is checked before any reading of
        // the payload, and an attacker must not be able to rebuild it byte by
        // byte by timing the refusal.
        let expected = crate::kdf::hmac_sha256(key, payload);
        if !crate::kdf::constant_time_eq(&expected, seal) {
            return Err(StateError::InvalidSeal);
        }

        let mut r = Reader::new(payload);
        let mut magic = [0u8; 8];
        for o in &mut magic {
            *o = r.u8().map_err(|_| StateError::Unreadable)?;
        }
        if &magic != ADDR_MAGIC {
            return Err(StateError::InvalidMagic);
        }
        let version = r.u32().map_err(|_| StateError::Unreadable)?;
        if version != ADDR_VERSION {
            return Err(StateError::UnknownVersion(version));
        }
        // A cache derived for another scheme would designate other keys.
        if r.u8().map_err(|_| StateError::Unreadable)? != scheme.as_u8() {
            return Err(StateError::Unreadable);
        }

        let n = r.varint().map_err(|_| StateError::Unreadable)?;
        if n > MAX_UTXO {
            return Err(StateError::TooManyEntries(n));
        }
        let mut v = Vec::with_capacity(n.min(1_000_000) as usize);
        for _ in 0..n {
            v.push(Hash256(r.array32().map_err(|_| StateError::Unreadable)?));
        }
        r.expect_end().map_err(|_| StateError::Unreadable)?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Transaction pool
// ---------------------------------------------------------------------------

/// Frozen format magic of `mempool.dat` (binary file format), not a word to
/// translate.
const MEMPOOL_MAGIC: &[u8; 8] = b"Q21MEMPL";

/// Safety bound when reading.
const MAX_MEMPOOL_TX: u64 = 200_000;

/// The transaction pool, kept between two runs.
///
/// # The transaction that disappeared
///
/// A sent transaction enters the pool — an in-memory waiting room — and waits
/// there for a miner to take it. The pool was written nowhere: stopping the
/// software before it was mined erased it.
///
/// This is not a hypothesis. An early user sent a transaction, stopped the
/// wallet to start mining, and saw it disappear. Nothing was lost — the funds
/// had not moved — but the payment had never happened, without a word of
/// explanation.
///
/// On a populated network, a peer would have relayed the transaction and kept
/// it. So it was mostly the isolated node — precisely that of a desktop wallet
/// — that paid for this defect. Bitcoin Core writes its `mempool.dat` at
/// shutdown for this exact reason.
///
/// # What is written, and what is not
///
/// **The transactions, nothing else.** All the rest of the pool state —
/// committed outputs, parent links, memory accounting — is derived again by
/// replaying them. Writing a derived state means giving oneself two sources of
/// truth for a single thing.
///
/// **And the replay revalidates.** The chain may have moved on during the
/// shutdown: a transaction may have been confirmed in the meantime, or become
/// impossible. Each one goes through `accept` again, which refuses it where
/// appropriate. A pool read back is never taken at its word.
pub struct MempoolStore {
    path: PathBuf,
    key: [u8; 32],
}

impl MempoolStore {
    pub fn new<P: AsRef<Path>>(path: P, key: [u8; 32]) -> MempoolStore {
        MempoolStore {
            path: path.as_ref().to_path_buf(),
            key,
        }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Writes the pending transactions, parents before children.
    pub fn save(&self, transactions: &[crate::tx::Transaction]) -> Result<(), StateError> {
        let mut w = Writer::with_capacity(64 + transactions.len() * 256);
        w.bytes(MEMPOOL_MAGIC);
        w.u32(VERSION);
        w.varint(transactions.len() as u64);
        for tx in transactions {
            let raw = tx.encode();
            w.varint(raw.len() as u64);
            w.bytes(&raw);
        }
        let mut data = w.finish();
        data.extend_from_slice(&crate::kdf::hmac_sha256(&self.key, &data));

        // Same discipline as the address cache: pending transactions tell who
        // pays whom, and the file is born restricted.
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = create_private_temp(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        restrict(&self.path);
        Ok(())
    }

    /// Reads back the pending transactions.
    ///
    /// They are not validated here: it is up to the caller to pass them again
    /// through `Mempool::accept`, the only place that knows the state of the
    /// chain.
    pub fn load(&self) -> Result<Vec<crate::tx::Transaction>, StateError> {
        let data = std::fs::read(&self.path)?;
        if data.len() < 32 {
            return Err(StateError::Unreadable);
        }
        let (payload, seal) = data.split_at(data.len() - 32);
        let expected = crate::kdf::hmac_sha256(&self.key, payload);
        if !crate::kdf::constant_time_eq(&expected, seal) {
            return Err(StateError::InvalidSeal);
        }

        let mut r = Reader::new(payload);
        let mut magic = [0u8; 8];
        for o in &mut magic {
            *o = r.u8().map_err(|_| StateError::Unreadable)?;
        }
        if &magic != MEMPOOL_MAGIC {
            return Err(StateError::InvalidMagic);
        }
        let version = r.u32().map_err(|_| StateError::Unreadable)?;
        if version != VERSION {
            return Err(StateError::UnknownVersion(version));
        }
        let n = r.varint().map_err(|_| StateError::Unreadable)?;
        if n > MAX_MEMPOOL_TX {
            return Err(StateError::TooManyEntries(n));
        }

        let mut v = Vec::with_capacity(n.min(10_000) as usize);
        for _ in 0..n {
            // `try_from` and not `as`: on 32 bits, a truncated length would
            // slip under the bound that follows.
            let len = r
                .varint()
                .ok()
                .and_then(|t| usize::try_from(t).ok())
                .ok_or(StateError::Unreadable)?;
            if len > crate::consensus::MAX_BLOCK_SIZE {
                return Err(StateError::Unreadable);
            }
            let mut raw = vec![0u8; len];
            for o in raw.iter_mut() {
                *o = r.u8().map_err(|_| StateError::Unreadable)?;
            }
            let tx = crate::tx::Transaction::decode(&raw).map_err(|_| StateError::Unreadable)?;
            v.push(tx);
        }
        r.expect_end().map_err(|_| StateError::Unreadable)?;
        Ok(v)
    }

    pub fn remove(&self) -> Result<(), StateError> {
        if self.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-state-{name}-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn sample_snapshot(n: u32) -> Snapshot {
        let mut utxo = UtxoSet::new();
        for i in 0..n {
            utxo.insert(
                OutPoint {
                    txid: Hash256([i as u8; 32]),
                    index: i,
                },
                UtxoEntry {
                    output: TxOut {
                        value: Amount::from_units(1_000 + u64::from(i)),
                        scheme: SchemeId::MlDsa65,
                        pubkey_hash: Hash256([(i + 1) as u8; 32]),
                    },
                    height: u64::from(i),
                    is_coinbase: i % 3 == 0,
                },
            );
        }
        // A test snapshot must stay *consistent*: since loading compares the
        // total issued with the emission schedule, a fanciful fixture would be
        // refused — rightly so.
        let height = 5_000;
        let muhash = utxo.commitment();
        Snapshot {
            network: Network::Regtest,
            height,
            tip: Hash256([7u8; 32]),
            issued: crate::emission::total_supply_at(height).units(),
            utxo,
            muhash,
        }
    }

    #[test]
    fn round_trip_on_disk() {
        let p = temp_path("round-trip");
        let s = StateStore::new(&p);
        let a = sample_snapshot(50);
        s.save(&a).unwrap();
        let b = s.load(Network::Regtest).unwrap();

        assert_eq!(a.height, b.height);
        assert_eq!(a.tip, b.tip);
        assert_eq!(a.issued, b.issued);
        assert_eq!(a.utxo.len(), b.utxo.len());
        for (o, e) in a.utxo.iter() {
            assert_eq!(b.utxo.get(o), Some(e), "lost entry: {o:?}");
        }
        s.remove().unwrap();
    }

    /// The header read back from disk tells the height and the tip of the file,
    /// checks its seal and its checksum, and does not believe a damaged file.
    #[test]
    fn the_header_on_disk_tells_the_file_height_and_nothing_else() {
        let p = temp_path("header");
        let s = StateStore::new_sealed(&p, [9u8; 32]);
        let a = sample_snapshot(30);
        s.save(&a).unwrap();
        assert_eq!(
            s.header_on_disk(Network::Regtest).unwrap(),
            (a.height, a.tip)
        );
        // Another seal: refused.
        assert!(matches!(
            StateStore::new_sealed(&p, [8u8; 32]).header_on_disk(Network::Regtest),
            Err(StateError::InvalidSeal)
        ));
        // A flipped byte in the body of the file: refused, even if the header
        // itself is intact.
        let mut bytes = std::fs::read(&p).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        std::fs::write(&p, &bytes).unwrap();
        assert!(s.header_on_disk(Network::Regtest).is_err());
        // Missing: an error, not a height.
        s.remove().unwrap();
        assert!(s.header_on_disk(Network::Regtest).is_err());
    }

    #[test]
    fn the_commitment_survives_the_round_trip() {
        let p = temp_path("commitment");
        let s = StateStore::new(&p);
        let a = sample_snapshot(40);
        s.save(&a).unwrap();
        let b = s.load(Network::Regtest).unwrap();
        assert_eq!(a.muhash, b.muhash, "the commitment must survive the disk");
        assert_eq!(
            b.muhash,
            b.utxo.commitment(),
            "the commitment read back must match the set read back"
        );
        s.remove().unwrap();
    }

    #[test]
    fn a_stale_commitment_gets_the_snapshot_rejected() {
        let p = temp_path("stale-commitment");
        let s = StateStore::new(&p);
        let mut a = sample_snapshot(15);
        // The commitment no longer matches the set: altered or corrupted file.
        a.muhash = Hash256([0xAB; 32]);
        s.save(&a).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::InvalidCommitment)
        ));
        s.remove().unwrap();
    }

    #[test]
    fn a_portable_snapshot_round_trips() {
        let a = sample_snapshot(30);
        let bytes = a.to_portable_bytes();
        let b = Snapshot::from_portable_bytes(&bytes, Network::Regtest).unwrap();
        assert_eq!(a.muhash, b.muhash);
        assert_eq!(a.height, b.height);
        assert_eq!(a.tip, b.tip);
        assert_eq!(a.utxo.len(), b.utxo.len());
        assert_eq!(b.utxo.commitment(), b.muhash);
    }

    #[test]
    fn a_corrupted_portable_snapshot_is_refused() {
        let mut bytes = sample_snapshot(20).to_portable_bytes();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        assert!(matches!(
            Snapshot::from_portable_bytes(&bytes, Network::Regtest),
            Err(StateError::InvalidChecksum)
        ));
    }

    #[test]
    fn a_portable_snapshot_from_another_network_is_refused() {
        // The mechanism that automatic network detection relies on: read back
        // under the wrong network, a snapshot hits WrongNetwork.
        let bytes = sample_snapshot(5).to_portable_bytes();
        assert!(matches!(
            Snapshot::from_portable_bytes(&bytes, Network::Mainnet),
            Err(StateError::WrongNetwork)
        ));
        assert!(Snapshot::from_portable_bytes(&bytes, Network::Regtest).is_ok());
    }

    #[test]
    fn the_encoding_is_deterministic() {
        // Two identical sets built in a different order must produce the same
        // file: otherwise two nodes cannot be compared.
        let a = sample_snapshot(30);
        let mut b = Snapshot {
            utxo: UtxoSet::new(),
            ..a.clone()
        };
        let mut entries: Vec<_> = a.utxo.iter().map(|(o, e)| (*o, *e)).collect();
        entries.reverse();
        for (o, e) in entries {
            b.utxo.insert(o, e);
        }
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn a_modified_byte_invalidates_the_snapshot() {
        let p = temp_path("corrupted");
        let s = StateStore::new(&p);
        s.save(&sample_snapshot(20)).unwrap();

        let mut data = std::fs::read(&p).unwrap();
        let middle = data.len() / 2;
        data[middle] ^= 0x01;
        std::fs::write(&p, &data).unwrap();

        // The seal fails before the checksum: it is the outermost check, and
        // it covers exactly the same bytes.
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::InvalidSeal)
        ));
        s.remove().unwrap();
    }

    #[test]
    fn a_truncated_snapshot_is_refused() {
        let p = temp_path("truncated");
        let s = StateStore::new(&p);
        s.save(&sample_snapshot(20)).unwrap();

        let data = std::fs::read(&p).unwrap();
        std::fs::write(&p, &data[..data.len() - 40]).unwrap();

        assert!(s.load(Network::Regtest).is_err());
        s.remove().unwrap();
    }

    /// Loading the state of another network would mix two currencies.
    #[test]
    fn a_snapshot_from_another_network_is_refused() {
        let p = temp_path("network");
        let s = StateStore::new(&p);
        s.save(&sample_snapshot(5)).unwrap();
        assert!(matches!(
            s.load(Network::Mainnet),
            Err(StateError::WrongNetwork)
        ));
        s.remove().unwrap();
    }

    /// The atomic write must leave the old snapshot intact if the new one
    /// fails. We check it by observing that no temporary file remains and that
    /// the contents are those of the last successful write.
    #[test]
    fn writing_leaves_no_temporary_file() {
        let p = temp_path("atomic");
        let s = StateStore::new(&p);
        s.save(&sample_snapshot(10)).unwrap();
        s.save(&sample_snapshot(20)).unwrap();

        assert!(
            !p.with_extension("tmp").exists(),
            "temporary file not cleaned up"
        );
        assert_eq!(s.load(Network::Regtest).unwrap().utxo.len(), 20);
        s.remove().unwrap();
    }

    #[test]
    fn an_arbitrary_file_is_not_a_snapshot() {
        let p = temp_path("foreign");
        let s = StateStore::new(&p);

        // A foreign file, sealed by a key that is not ours: refused on the
        // seal, without a single structure being decoded.
        let foreign = StateStore::new_sealed(&p, [0x42u8; 32]);
        foreign.save(&sample_snapshot(4)).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::InvalidSeal)
        ));

        // And a file that is no snapshot of any kind, sealed by the right key:
        // refused further on, on the magic.
        // Both layers are satisfied — inner checksum and outer seal — and the
        // contents remain gibberish: the refusal must come from the magic.
        let mut payload = b"this is not a snapshot".to_vec();
        let checksum = sha256(&payload);
        payload.extend_from_slice(&checksum);
        let mut data = payload.clone();
        data.extend_from_slice(&crate::kdf::hmac_sha256(&[0u8; 32], &payload));
        std::fs::write(&p, &data).unwrap();
        assert!(matches!(
            s.load(Network::Regtest),
            Err(StateError::InvalidMagic)
        ));
        let _ = s.remove();
    }
}
