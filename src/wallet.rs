//! Wallet.
//!
//! Deterministic: everything is derived from a 32-byte seed. Backing up this
//! seed and a counter is enough to recover everything.
//!
//! # The counter is not a convenience detail
//!
//! Lamport signs **once**. Reusing a key reveals the private key. The wallet
//! therefore guarantees uniqueness by never using the same index twice, and
//! by refusing to sign with an index already consumed.
//!
//! This constraint only holds for Lamport. ML-DSA is stateless: a key there
//! signs as many times as one wants. The wallet nevertheless keeps changing
//! address on every payment, but for a different reason — privacy, not the
//! survival of the key. The distinction is carried by
//! [`SchemeId::is_one_time`], not by a comment.
//!
//! This is exactly the operational trap that section 4 of the white paper
//! holds against QRL's XMSS scheme. Living through it once is better than
//! reading about it.

use crate::address::{Address, Network};
use crate::amount::Amount;
use crate::consensus::COINBASE_MATURITY;
use crate::hash::{tagged_hash_parts, tags, Hash256};
use crate::lamport::SecretKey;
use crate::sig::{pubkey_hash, SchemeId};
use crate::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
use crate::utxo::UtxoSet;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WalletError {
    InsufficientFunds {
        available: u64,
        requested: u64,
    },
    /// The key index has already been used. Signing again would reveal the
    /// private key.
    KeyAlreadyUsed(u32),
    UnknownKey,
    ZeroAmount,
    UnsupportedScheme(SchemeId),
    /// The system random number generator is unavailable or suspicious.
    ///
    /// No key is created in that case: a predictable wallet is worse than no
    /// wallet.
    RandomnessUnavailable,
    /// Unreadable backup code: wrong checksum, or unexpected length.
    InvalidBackup,
    /// Backup code of another network.
    BackupForOtherNetwork,
    /// What was received is a receiving address, not a backup code.
    ///
    /// Both are written the same way — Bech32m, same alphabet — and differ
    /// only by the prefix. A lost wallet, an address in front of you, and the
    /// mix-up is made. Rejecting it as a "wrong checksum" sent the person off
    /// to check a perfect copy: it is the object that is wrong, not the copy,
    /// and that is what must be said.
    BackupIsAnAddress,
    /// The key derived at this index does not match the lock of the output
    /// the wallet believed it could spend.
    ///
    /// This refusal is the last barrier before a wasted signature: for a
    /// one-time scheme, signing with the wrong key would burn it without
    /// spending anything. We stop **before** signing, and nothing is
    /// consumed.
    LockMismatch {
        index: u32,
    },
    /// Amount or fee beyond what can exist.
    ///
    /// No legitimate sum exceeds the emission cap. Refusing here avoids an
    /// addition that overflows — and, in release, a process abort.
    AmountOutOfRange,
    /// An amount below the dust floor ([`crate::consensus::MIN_OUTPUT_VALUE`]).
    ///
    /// The network would refuse the transaction; building it would have
    /// consumed a one-time key for nothing. We refuse beforehand.
    AmountBelowFloor {
        minimum: u64,
        received: u64,
    },
    /// Saving the consumed indices failed **before** signing.
    ///
    /// Nothing was signed: the indices are reserved in memory, but no
    /// signature exists, so no key is exposed. Full disk, locked file,
    /// removed media — the spend is refused rather than risk, on the next
    /// send, signing again with a key the disk still believes is fresh.
    SaveFailed,
    /// Between reserving the coins and signing, one of them disappeared from
    /// the output set: spent by another transaction, or carried away by a
    /// reorg. Nothing was signed, the reservation is lifted.
    ///
    /// Only happens on the two-step path ([`Wallet::prepare_spend`] then
    /// [`Wallet::sign_spend`]), where the chain lock is released between the
    /// two while the wallet is written.
    CoinsGone,
    /// One-time scheme: the chain has not been scanned up to the current
    /// height, and block bodies are missing to do so. Signing without knowing
    /// which keys have already been used could sign with one again.
    VerificationBehind {
        verified: u64,
        height: u64,
    },
}

/// Below this number of addresses, a cache is re-probed **in full**.
///
/// One thousand twenty-four ML-DSA derivations cost about a third of a
/// second: that is invisible at startup, and it covers almost all real
/// wallets. The cache only really matters beyond that.
const FULL_CHECK_THRESHOLD: usize = 1024;

/// Human-readable prefix of the backup code, per network.
/// The prefix of a backup code, to name it in a message.
///
/// Made public so that the interface can say what it expects to see, without
/// copying the table here and there — a copied table drifts.
pub fn backup_code_hrp(n: Network) -> &'static str {
    seed_hrp(n)
}

fn seed_hrp(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "q21seed",
        Network::Testnet => "tq21seed",
        Network::Regtest => "rq21seed",
    }
}

pub struct Wallet {
    seed: [u8; 32],
    network: Network,
    scheme: SchemeId,
    /// Next free index.
    next_index: u32,
    /// Public key hash -> derivation index.
    known: HashMap<Hash256, u32>,
    /// Indices already used to sign. Forbidden from reuse.
    consumed: Vec<u32>,
    /// Indices **reserved** for a spend in progress, with the chain height at
    /// the time of the reservation.
    ///
    /// # Reserved is not revealed
    ///
    /// The early write puts the index on disk before signing — that is what
    /// prevents signing again after a power cut. But the reserved index
    /// carries the coin being spent: counting it as consumed from the
    /// reservation on froze that coin forever if the process died between the
    /// reservation and the broadcast, without any signature ever having
    /// existed. The balance dropped, and nothing explained it.
    ///
    /// A reservation is lifted by signing (the index moves to `consumed`), by
    /// canceling before signing (it becomes free again), or by
    /// [`Wallet::recheck_reservations`]: if the chain carries no signature of
    /// this key [`Wallet::RESERVATION_TIMEOUT`] blocks after the reservation,
    /// the index becomes free again. On disk, a reserved index **also**
    /// appears in `consumed=`: a reader that does not know `reserved=` takes
    /// it as consumed, which is the safe reading.
    reserved: std::collections::BTreeMap<u32, u64>,
    /// Height up to which the chain has been scanned for signatures of this
    /// wallet.
    ///
    /// The scan is the safety net that catches a restore: it finds in the
    /// chain the keys already revealed. But it costs a full read, and without
    /// memory it started over on every command.
    verified_up_to: u64,
    /// Free-form labels set by the holder on their addresses.
    ///
    /// # Why they live in the wallet
    ///
    /// A Q21 address is a string of characters nobody recognizes. Whoever
    /// hands out several — one per correspondent, as the protocol encourages
    /// — very quickly loses track of who received what. The address book is
    /// therefore the answer to a need created by privacy itself.
    ///
    /// They are **strictly local**: never transmitted, never written into the
    /// chain, never visible to a peer. And they are sealed with the rest of
    /// the wallet when a passphrase exists — "for the plumber" says a lot about
    /// whom one spends time with, and that is nobody's business.
    labels: HashMap<u32, String>,
    /// Indices the holder **requested** themselves: through the "New address"
    /// button, through `q21 address`, through `getnewaddress`.
    ///
    /// # Why this distinction exists
    ///
    /// Mining derives one address per block found, and that is the right
    /// granularity: it avoids publicly linking all rewards together. But
    /// after a few days, a miner owns a thousand addresses they never asked
    /// for and have no reason to hand out. Presenting those as "their
    /// addresses" drowns the two or three they actually gave to someone.
    ///
    /// The set changes nothing in the balance or in security: all derived
    /// addresses remain recognized and spendable. It only serves to know
    /// which ones to show first.
    requested: BTreeSet<u32>,
}

/// Wipes the seed when the wallet is dropped.
///
/// Does not protect against an adversary who reads the process memory while
/// it runs, nor against a page swapped to disk by the system. What it
/// prevents: a seed lingering in a reused heap, then in a core dump after a
/// crash. It is little, and it is not nothing.
impl Drop for Wallet {
    fn drop(&mut self) {
        crate::kdf::wipe(&mut self.seed);
    }
}

impl Wallet {
    pub fn from_seed(seed: [u8; 32], network: Network) -> Wallet {
        Wallet {
            seed,
            network,
            scheme: SchemeId::LamportOts,
            next_index: 0,
            known: HashMap::new(),
            consumed: Vec::new(),
            reserved: std::collections::BTreeMap::new(),
            verified_up_to: 0,
            labels: HashMap::new(),
            requested: BTreeSet::new(),
        }
    }

    /// Wallet on a chosen scheme.
    ///
    /// Two possible refusals, and neither is negotiable:
    /// - the scheme is not allowed on this network (Lamport outside a test
    ///   network);
    /// - the scheme is not compiled into this binary.
    ///
    /// The second case is the most insidious: a wallet that derives ML-DSA
    /// addresses without knowing how to sign would produce inaccessible funds.
    /// We fail at construction rather than at spending.
    pub fn from_seed_scheme(
        seed: [u8; 32],
        network: Network,
        scheme: SchemeId,
    ) -> Result<Wallet, WalletError> {
        if !scheme.allowed_on(network) || !scheme.is_available() {
            return Err(WalletError::UnsupportedScheme(scheme));
        }
        Ok(Wallet {
            seed,
            network,
            scheme,
            next_index: 0,
            known: HashMap::new(),
            consumed: Vec::new(),
            reserved: std::collections::BTreeMap::new(),
            verified_up_to: 0,
            labels: HashMap::new(),
            requested: BTreeSet::new(),
        })
    }

    /// Random seed drawn from the system.
    ///
    /// # What changed in phase 8
    ///
    /// This function read `/dev/urandom` directly. Two consequences: it
    /// **failed on Windows**, where that device does not exist, and it
    /// checked nothing of what it got. A degraded source — misconfigured
    /// virtual machine, exotic container — would have produced a predictable
    /// seed without any message saying so, and the funds would have been lost
    /// from the first payment.
    ///
    /// It now goes through [`crate::rng`], which queries the system generator
    /// on every platform and **fails rather than return randomness of unknown
    /// quality**.
    pub fn generate(network: Network) -> Result<Wallet, crate::rng::RngError> {
        Ok(Wallet::from_seed(crate::rng::bytes()?, network))
    }

    /// Random wallet on a chosen scheme.
    pub fn generate_scheme(network: Network, scheme: SchemeId) -> Result<Wallet, WalletError> {
        let seed = crate::rng::bytes().map_err(|_| WalletError::RandomnessUnavailable)?;
        Wallet::from_seed_scheme(seed, network, scheme)
    }

    /// Backup code of the seed, in Bech32m.
    ///
    /// # Why not simply hexadecimal
    ///
    /// The seed used to be returned as sixty-four hexadecimal characters,
    /// without any check. Copying that kind of string by hand is an operation
    /// where people make mistakes — and a single typo gives a perfectly valid
    /// seed that opens nothing. The loss is silent and permanent.
    ///
    /// Bech32m (BIP 350) is designed exactly for this: an alphabet without
    /// confusable characters — no `1`/`l`, no `0`/`o` — and a checksum that
    /// **detects up to four errors** and indicates their approximate
    /// position. It is the same encoding as Q21 addresses, already
    /// implemented and already tested.
    ///
    /// The prefix designates the network: a test seed cannot be mistaken for
    /// a mainnet seed.
    pub fn backup_code(&self) -> String {
        crate::bech32::encode(seed_hrp(self.network), &self.seed).expect("32 bytes always encode")
    }

    /// Recovers a seed from its backup code.
    pub fn seed_from_backup(code: &str, network: Network) -> Result<[u8; 32], WalletError> {
        // The Bech32m alphabet of a backup code contains no whitespace. A
        // copy-paste can still slip one into the middle — a line break, a
        // tab, a non-breaking space, a zero-width character. All of them are
        // removed before decoding, so that a correct code is always accepted,
        // whatever its formatting.
        let cleaned: String = code
            .chars()
            .filter(|c| {
                !c.is_whitespace()
                    && !matches!(
                        *c,
                        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
                    )
            })
            .collect();
        let code = cleaned.as_str();
        // A receiving address pasted here is recognized by its prefix, even
        // before decoding: it is the most likely mix-up, and it deserves its
        // own answer rather than the generic verdict.
        if let Some((prefix, _)) = code.rsplit_once('1') {
            if Network::from_hrp(&prefix.to_ascii_lowercase()).is_some() {
                return Err(WalletError::BackupIsAnAddress);
            }
        }
        let (hrp, data) = crate::bech32::decode(code).map_err(|_| WalletError::InvalidBackup)?;
        if hrp != seed_hrp(network) {
            return Err(WalletError::BackupForOtherNetwork);
        }
        if data.len() != 32 {
            return Err(WalletError::InvalidBackup);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data);
        Ok(seed)
    }

    pub fn seed_hex(&self) -> String {
        self.seed.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn seed_from_hex(s: &str) -> Option<[u8; 32]> {
        Hash256::from_hex(s).map(|h| h.0)
    }

    /// Authentication key of the address cache.
    ///
    /// An address cache contains no secret — a public key hash is public by
    /// construction. But it *designates* the keys the wallet believes are its
    /// own, and a single substituted entry was enough to make it sign with
    /// the wrong key. The cache must therefore be authenticated: only the
    /// holder of the seed can produce one that this wallet will accept.
    ///
    /// The key is **derived** from the seed, never the seed itself: even a
    /// leaked cache file says nothing about the private keys.
    pub fn cache_key(&self) -> [u8; 32] {
        // Frozen label: it keys the `addresses.dat` cache on disk. Never
        // rename it.
        self.public_fingerprint(b"Q21-ADDRESS-CACHE-v1")
    }

    /// The key that authenticated the address cache up to 0.3.x. Only used
    /// to accept a cache written by 0.3.x, which is then rewritten under
    /// [`Wallet::cache_key`].
    pub fn legacy_cache_key(&self) -> [u8; 32] {
        self.public_fingerprint(crate::legacy::LEGACY_ADDRESS_CACHE_LABEL)
    }

    /// A public fingerprint of the seed under a label:
    /// `HMAC(seed, label)`.
    ///
    /// It says nothing about the seed — HMAC under a secret key is a
    /// pseudo-random function — but it is enough to recognize the same seed
    /// from one time to the next, or to tell another one apart. That is what
    /// anchors a data directory to *its* wallet: a file from another seed is
    /// recognized there as foreign. Each use has its own label, so that a
    /// fingerprint never serves two purposes.
    pub fn public_fingerprint(&self, label: &[u8]) -> [u8; 32] {
        crate::kdf::hmac_sha256(&self.seed, label)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    fn key(&self, index: u32) -> SecretKey {
        SecretKey::from_seed(self.seed, index)
    }

    /// Private seed of index `index`, for schemes other than Lamport.
    ///
    /// The scheme goes into the derivation: two wallets from the same seed but
    /// of different schemes have no key in common. Without that, the same
    /// secret value would serve two distinct cryptographies, which is exactly
    /// the kind of reuse that ends badly.
    #[cfg_attr(not(feature = "mldsa"), allow(dead_code))]
    fn derived_seed(&self, index: u32) -> [u8; 32] {
        tagged_hash_parts(
            tags::WALLET_SEED,
            &[&self.seed, &index.to_le_bytes(), &[self.scheme.as_u8()]],
        )
        .0
    }

    /// Public key of index `index`.
    ///
    /// # Panics
    ///
    /// If the wallet's scheme is not available. This is an invariant
    /// established at construction ([`Wallet::from_seed_scheme`]): reaching
    /// this point would mean that the wallet was built through a path that
    /// does not validate its own scheme.
    fn public_key(&self, index: u32) -> Vec<u8> {
        match self.scheme {
            SchemeId::LamportOts => self.key(index).public_key(),
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa65 => {
                let mut g = self.derived_seed(index);
                let pk = mldsa_wallet::public_key::<ml_dsa::MlDsa65>(&g);
                crate::kdf::wipe(&mut g);
                pk
            }
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa87 => {
                let mut g = self.derived_seed(index);
                let pk = mldsa_wallet::public_key::<ml_dsa::MlDsa87>(&g);
                crate::kdf::wipe(&mut g);
                pk
            }
            other => panic!("wallet on an unavailable scheme: {}", other.name()),
        }
    }

    /// Signs `message` with index `index`.
    ///
    /// ML-DSA signs in the "hedged" variant: thirty-two bytes of system
    /// randomness go into each signature. If randomness is missing, we
    /// **refuse to sign** rather than fall back to the deterministic variant
    /// — see `mldsa_wallet::sign`.
    ///
    /// # Panics
    ///
    /// Same invariant as [`Wallet::public_key`].
    fn sign_at(&self, index: u32, message: &Hash256) -> Result<Vec<u8>, WalletError> {
        match self.scheme {
            SchemeId::LamportOts => Ok(self.key(index).sign(message)),
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa65 => {
                let mut g = self.derived_seed(index);
                let sig = mldsa_wallet::sign::<ml_dsa::MlDsa65>(&g, message);
                crate::kdf::wipe(&mut g);
                sig
            }
            #[cfg(feature = "mldsa")]
            SchemeId::MlDsa87 => {
                let mut g = self.derived_seed(index);
                let sig = mldsa_wallet::sign::<ml_dsa::MlDsa87>(&g, message);
                crate::kdf::wipe(&mut g);
                sig
            }
            other => panic!("wallet on an unavailable scheme: {}", other.name()),
        }
    }

    /// Produces a fresh address, never used.
    ///
    /// Each call consumes an index. With Lamport this is mandatory, not a
    /// privacy best practice.
    pub fn new_address(&mut self) -> Address {
        let index = self.next_index;
        self.next_index += 1;
        let h = pubkey_hash(self.scheme, &self.public_key(index));
        self.known.insert(h, index);
        Address {
            network: self.network,
            scheme: self.scheme,
            hash: h,
        }
    }

    /// Produces a fresh address **at the holder's request**, and remembers
    /// it.
    ///
    /// That is the only difference with [`Wallet::new_address`]: the index is
    /// recorded as requested, so that the interface shows it among the
    /// addresses the holder has actually handed out, and not among the
    /// hundreds that mining derives on its own.
    pub fn request_address(&mut self) -> Address {
        let a = self.new_address();
        self.requested.insert(self.next_index - 1);
        a
    }

    /// Was this address requested by the holder, rather than derived by
    /// mining or by a restore?
    pub fn is_requested(&self, index: u32) -> bool {
        self.requested.contains(&index)
    }

    /// Indices requested by the holder, sorted, for writing the wallet.
    pub fn requested_indices(&self) -> Vec<u32> {
        self.requested.iter().copied().collect()
    }

    /// Restores the requested indices read from the file.
    ///
    /// A file written before this distinction existed does not have the
    /// line: all its addresses then pass for derived by mining, and the
    /// holder finds them by searching or by naming them. Nothing is lost,
    /// only the display order changes.
    pub fn load_requested(&mut self, indices: &[u32]) {
        self.requested.extend(indices.iter().copied());
    }

    /// Replays the derivation to recover the addresses after a restart.
    pub fn rescan(&mut self, up_to: u32) {
        for index in 0..up_to {
            let h = pubkey_hash(self.scheme, &self.public_key(index));
            self.known.insert(h, index);
        }
        self.next_index = self.next_index.max(up_to);
    }

    /// Discovery gap: how many empty addresses are derived before concluding
    /// there is nothing more.
    ///
    /// The value is the one the ecosystem has used since BIP44, and it was not
    /// chosen at random: it covers the case of a holder who handed out dozens
    /// of addresses without any being paid, while bounding the cost of a
    /// restore. Each index derives an ML-DSA key, which is not free.
    pub const DISCOVERY_GAP: u32 = 200;

    /// Finds the addresses of this wallet by querying a set of outputs, and
    /// moves the index past the last one found.
    ///
    /// # The defect this function fixes
    ///
    /// A wallet restored from its backup code only knew the addresses it had
    /// derived itself — that is, none. It therefore showed **zero** on a chain
    /// that held its funds. The promise "this code is enough to recover
    /// everything" was false, and the test that showed it takes three
    /// commands: create, mine, restore elsewhere.
    ///
    /// # How it proceeds
    ///
    /// It derives in windows of [`Self::DISCOVERY_GAP`] indices and asks for
    /// each whether `owned` recognizes it. As soon as a window finds
    /// something, it starts again after the find; when a whole window finds
    /// nothing, it stops. That is the gap rule, the one every deterministic
    /// wallet uses.
    ///
    /// Returns the number of addresses recognized.
    pub fn discover<F>(&mut self, owned: F) -> usize
    where
        F: Fn(&Hash256) -> bool,
    {
        let mut found = 0usize;
        // Last index **included** that was used, if any.
        let mut last: Option<u32> = None;
        let mut i: u32 = 0;
        // `checked_add` bounds the loop: at the end of the possible indices,
        // we stop rather than wrap around to zero.
        while let Some(end) = i.checked_add(Self::DISCOVERY_GAP) {
            let mut seen_in_window = false;
            for index in i..end {
                let h = pubkey_hash(self.scheme, &self.public_key(index));
                self.known.insert(h, index);
                if owned(&h) {
                    found += 1;
                    last = Some(index);
                    seen_in_window = true;
                }
            }
            if !seen_in_window {
                break;
            }
            i = end;
        }
        // The next index goes after the last address that was used. It is not
        // placed after the last one **derived**: that would skip the two
        // hundred empty indices the window has just explored, and a holder who
        // restores twice in a row would skip them twice.
        if let Some(d) = last {
            self.next_index = self.next_index.max(d + 1);
        }
        found
    }

    /// Catches up with addresses handed out but never saved.
    ///
    /// # The defect this closes
    ///
    /// Mining derives one address per block found, and the wallet was only
    /// written on a clean shutdown. After a cut — power, `kill`, SD card
    /// removed — `next_index` went backward on disk, and the rewards of the
    /// blocks found since then remained invisible: the wallet saw *some*
    /// funds, so restore discovery did not trigger, and nothing was ever
    /// repaired. Measured: 16 Q21 shown for 803 actually held.
    ///
    /// Here we do not start from zero: we derive a window **beyond**
    /// `next_index`, and move forward as long as something is found there.
    /// When nothing is missing, it is one window of keys derived for nothing
    /// — a few tens of milliseconds, once per startup.
    pub fn catch_up<F>(&mut self, owned: F) -> usize
    where
        F: Fn(&Hash256) -> bool,
    {
        let mut found = 0usize;
        let mut last: Option<u32> = None;
        let mut i: u32 = self.next_index;
        while let Some(end) = i.checked_add(Self::DISCOVERY_GAP) {
            let mut seen = false;
            for index in i..end {
                let h = pubkey_hash(self.scheme, &self.public_key(index));
                if owned(&h) {
                    self.known.insert(h, index);
                    found += 1;
                    last = Some(index);
                    seen = true;
                }
            }
            if !seen {
                break;
            }
            i = end;
        }
        if let Some(d) = last {
            // The intermediate indices, also handed out, are recognized too.
            for index in self.next_index..=d {
                let h = pubkey_hash(self.scheme, &self.public_key(index));
                self.known.insert(h, index);
            }
            self.next_index = self.next_index.max(d + 1);
        }
        found
    }

    /// Hashes already derived, in index order.
    pub fn known_hashes(&self) -> Vec<Hash256> {
        let mut v: Vec<(u32, Hash256)> = self.known.iter().map(|(h, i)| (*i, *h)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, h)| h).collect()
    }

    /// Reloads the hashes from a local cache, without deriving again.
    ///
    /// # Why this cache exists
    ///
    /// [`Wallet::rescan`] derives every address again. With Lamport it was a
    /// handful of hashes; with ML-DSA it is one lattice key generation per
    /// address. A wallet of sixty thousand addresses took twenty seconds **at
    /// every startup** — more than revalidating the whole chain.
    ///
    /// # Why it is not taken at its word
    ///
    /// A cache from another seed or another scheme would make the wallet
    /// believe it holds funds it will not be able to spend.
    ///
    /// The previous version only re-probed the first and the last hash. An
    /// audit substituted **a single** entry in the middle: it went through.
    /// The wallet then believed it owned the attacker's address, showed its
    /// funds instead of its own, and — worse — signed a spend with a Lamport
    /// key that did not open that lock: a key burned for a transaction the
    /// network rejected.
    ///
    /// We now re-probe a **spread-out sample** of square root of `n` indices,
    /// ends included. The cost remains negligible — 245 derivations for sixty
    /// thousand addresses, a few tens of milliseconds — and a mass
    /// substitution no longer goes through.
    ///
    /// # What the sample is not enough to guarantee
    ///
    /// A single, well-placed substitution can still escape the draw. It is
    /// neutralized elsewhere, by two barriers that, for their part, are not
    /// probabilistic:
    ///
    /// - the cache on disk is **sealed** by a key derived from the seed
    ///   ([`Wallet::cache_key`]): a third party cannot fabricate one;
    /// - [`Wallet::create_transaction`] checks, before signing, that the
    ///   derived key does open the lock of the output being spent.
    ///
    /// Returns `false` if the cache is refused; the caller must then call
    /// [`Wallet::rescan`].
    pub fn adopt_hashes(&mut self, hashes: &[Hash256]) -> bool {
        if hashes.is_empty() {
            return true;
        }
        let n = hashes.len();
        let last = n - 1;

        // Below the threshold, we check **everything**. That is the case of
        // almost all real wallets, and a sample there would be a luxury paid
        // for with a hole: on six addresses, a substitution at the third
        // position slipped between the checkpoints.
        //
        // Beyond it, the cost of the full derivation is precisely what this
        // cache exists to avoid: we fall back to a spread-out sample.
        let mut step = if n <= FULL_CHECK_THRESHOLD {
            1
        } else {
            (n as f64).sqrt() as usize
        };
        if step == 0 {
            step = 1;
        }

        let mut i = 0usize;
        loop {
            if pubkey_hash(self.scheme, &self.public_key(i as u32)) != hashes[i] {
                return false;
            }
            if i == last {
                break;
            }
            i = (i + step).min(last);
        }

        for (i, h) in hashes.iter().enumerate() {
            self.known.insert(*h, i as u32);
        }
        self.next_index = self.next_index.max(hashes.len() as u32);
        true
    }

    pub fn owns(&self, h: &Hash256) -> bool {
        self.known.contains_key(h)
    }

    /// Does the wallet recognize at least one unspent output of this set as
    /// its own?
    ///
    /// That is the real signal of an "up to date" wallet: not the number of
    /// addresses it has derived, but the fact that it **sees its funds**. A
    /// wallet restored and then simply opened has already derived a few
    /// addresses — the home page draws one — without recognizing the
    /// slightest of its holdings on the chain. That is the case discovery
    /// must catch, and that the old `next_index <= 1` trigger missed.
    pub fn sees_funds(&self, utxo: &crate::utxo::UtxoSet) -> bool {
        self.known.keys().any(|h| utxo.knows(h))
    }

    /// Has this index already been used to sign?
    ///
    /// For a one-time scheme, a `true` answer is final: the key is dead.
    /// Exposing it makes it possible to check that a refusal burned
    /// **nothing**.
    pub fn is_consumed(&self, index: u32) -> bool {
        self.consumed.contains(&index)
    }

    /// Indices already used to sign, sorted.
    ///
    /// This list **must** be persisted. It was not: it died with the
    /// process. A restarted Lamport wallet therefore started again with a
    /// clean slate, and two signatures from the same Lamport key reveal the
    /// private key.
    ///
    /// Contains only the **revealed** keys. The indices that are only
    /// reserved are returned by [`Wallet::reserved_indices`], and the file
    /// line by [`Wallet::consumed_indices_for_file`].
    pub fn consumed_indices(&self) -> Vec<u32> {
        let mut v = self.consumed.clone();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Is this index reserved for a spend in progress?
    pub fn is_reserved(&self, index: u32) -> bool {
        self.reserved.contains_key(&index)
    }

    /// Reserved indices, with the height of their reservation, sorted.
    pub fn reserved_indices(&self) -> Vec<(u32, u64)> {
        self.reserved.iter().map(|(i, h)| (*i, *h)).collect()
    }

    /// What the `consumed=` line of the file must carry: the revealed keys
    /// **and** the reserved indices.
    ///
    /// A reserved index appears there on purpose. A binary that ignores the
    /// `reserved=` line will take it as consumed: that is the safe reading,
    /// the one that never signs again. The current binary removes it from
    /// `consumed` when rereading `reserved=`
    /// ([`Wallet::load_reservations`]).
    pub fn consumed_indices_for_file(&self) -> Vec<u32> {
        let mut v = self.consumed.clone();
        v.extend(self.reserved.keys().copied());
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Restores the reservations read from the file.
    ///
    /// Each index is removed from `consumed` — where it also appears, as a
    /// precaution for older readers — and becomes a reservation again, which
    /// will be confirmed or lifted by [`Wallet::recheck_reservations`]. An
    /// index that the file gives as consumed without giving it as reserved
    /// stays consumed: we never release on a doubt.
    pub fn load_reservations(&mut self, reservations: &[(u32, u64)]) {
        for (i, h) in reservations {
            if !self.reserved.contains_key(i) {
                self.consumed.retain(|c| c != i);
                self.reserved.insert(*i, *h);
            }
        }
    }

    /// Blocks after which a reservation with no signature in the chain is
    /// lifted.
    ///
    /// Twenty blocks, about forty minutes at the target pace. A broadcast
    /// transaction is mined well before that; a reservation still there after
    /// this delay is that of a process that died between the reservation and
    /// the broadcast — the coin has no reason to stay frozen because of it.
    /// The residual risk is a transaction signed, announced, not mined within
    /// twenty blocks and then mined afterwards: it would conflict with the
    /// next spend of the same coin, and both signatures would be public. That
    /// is the accepted limit, and it only concerns test networks.
    pub const RESERVATION_TIMEOUT: u64 = 20;

    /// Re-examines the reservations in the light of the chain.
    ///
    /// `read_block` returns the active block at a height, if available. For
    /// each reservation whose delay has expired, the blocks written since the
    /// reservation are reread looking for a signature of this key: found, the
    /// index is consumed; absent, it becomes free again. A reservation younger
    /// than the delay is left as is. If a block of the window is missing,
    /// nothing is released: releasing on an incomplete read would be releasing
    /// on a doubt.
    ///
    /// Returns `(confirmed, released)`.
    pub fn recheck_reservations<L>(&mut self, height: u64, read_block: L) -> (usize, usize)
    where
        L: Fn(u64) -> Option<crate::block::Block>,
    {
        let expired: Vec<(u32, u64)> = self
            .reserved
            .iter()
            .filter(|(_, h)| height >= h.saturating_add(Self::RESERVATION_TIMEOUT))
            .map(|(i, h)| (*i, *h))
            .collect();
        if expired.is_empty() {
            return (0, 0);
        }
        let since = expired.iter().map(|(_, h)| *h).min().unwrap_or(height);
        let mut complete = true;
        for h in since..=height {
            match read_block(h) {
                Some(b) => {
                    self.record_spends(&b);
                }
                None => complete = false,
            }
        }
        let confirmed = expired
            .iter()
            .filter(|(i, _)| self.consumed.contains(i))
            .count();
        let mut released = 0;
        if complete {
            for (i, _) in &expired {
                if self.reserved.remove(i).is_some() {
                    released += 1;
                }
            }
        }
        (confirmed, released)
    }

    /// Amount tied up by the reservations in progress, so that the interface
    /// can name what is missing from the balance and why.
    pub fn reserved_amount(&self, utxo: &UtxoSet, height: u64) -> Amount {
        if !self.scheme.is_one_time() {
            return Amount::ZERO;
        }
        let mut total: u64 = 0;
        for (h, index) in &self.known {
            if !self.reserved.contains_key(index) {
                continue;
            }
            let largest = utxo
                .spendable_for(h, height, COINBASE_MATURITY)
                .iter()
                .map(|(_, e)| e.output.value.units())
                .max()
                .unwrap_or(0);
            total = total.saturating_add(largest);
        }
        Amount::from_units(total)
    }

    /// Height up to which the chain has already been scanned.
    pub fn verified_up_to(&self) -> u64 {
        self.verified_up_to
    }

    /// Sets, replaces or removes the label of an address.
    ///
    /// An empty string — or one made of spaces — **removes** the label rather
    /// than record an invisible one: otherwise the address book fills up with
    /// empty lines that can no longer be told apart from an unnamed address.
    ///
    /// The text is capped at [`Wallet::MAX_LABEL_LEN`] characters. The cut is
    /// made on **characters** and not on bytes: cutting a byte in the middle of
    /// an accented letter would produce a string that is not UTF-8, and the
    /// wallet file would become unreadable. It is an address book, not a
    /// diary: a name, a first name, a short reason.
    pub fn set_label(&mut self, index: u32, text: &str) {
        let clean: String = text
            .trim()
            // Line breaks and tabs would break the file format, which is one
            // line per key. They are replaced rather than refused: the user
            // pasted some text, they do not want an error message.
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(Self::MAX_LABEL_LEN)
            .collect();
        let clean = clean.trim().to_string();
        if clean.is_empty() {
            self.labels.remove(&index);
        } else {
            self.labels.insert(index, clean);
        }
    }

    /// Maximum length of a label, in characters.
    pub const MAX_LABEL_LEN: usize = 64;

    /// The label of an address, if it has one.
    pub fn label(&self, index: u32) -> Option<&str> {
        self.labels.get(&index).map(|s| s.as_str())
    }

    /// All the labels, for writing the wallet.
    pub fn labels(&self) -> &HashMap<u32, String> {
        &self.labels
    }

    /// Restores the labels read from the file.
    pub fn load_labels(&mut self, e: HashMap<u32, String>) {
        self.labels = e;
    }

    /// Records that a scan covered the chain up to this height.
    ///
    /// Never goes backward: a verification once obtained is not lost.
    pub fn record_verification(&mut self, height: u64) {
        self.verified_up_to = self.verified_up_to.max(height);
    }

    /// Forgets how far the chain has been verified: to be used only when the
    /// chain itself has changed — a test network restarted from a new
    /// genesis. The heights of the old chain no longer designate anything
    /// there, and keeping them would skip the scan of the first blocks of the
    /// new one.
    pub fn forget_verification(&mut self) {
        self.verified_up_to = 0;
    }

    /// Declares indices as already used.
    ///
    /// Used when reloading from disk and when observing the chain. The set
    /// only grows: a consumption is never erased, since forgetting it is
    /// precisely the defect to fix.
    pub fn mark_consumed(&mut self, indices: &[u32]) {
        for i in indices {
            if !self.consumed.contains(i) {
                self.consumed.push(*i);
            }
        }
    }

    /// Observes a block and marks as consumed any key that signed in it.
    ///
    /// # Why the chain is the best source
    ///
    /// A file can be replaced by an earlier version; the chain cannot — it is
    /// backed by proof of work. If a signature of this wallet appears in a
    /// block, the corresponding key has been revealed once, period. It is an
    /// observation, not bookkeeping.
    ///
    /// Returns the number of newly marked indices.
    pub fn record_spends(&mut self, block: &crate::block::Block) -> usize {
        let mut new_count = 0;
        for tx in &block.transactions {
            for input in &tx.inputs {
                if input.witness.pubkey.is_empty() {
                    continue; // coinbase
                }
                let h = pubkey_hash(self.scheme, &input.witness.pubkey);
                if let Some(index) = self.known.get(&h).copied() {
                    // A signature in a block lifts the reservation: the key is
                    // no longer reserved, it is revealed.
                    self.reserved.remove(&index);
                    if !self.consumed.contains(&index) {
                        self.consumed.push(index);
                        new_count += 1;
                    }
                }
            }
        }
        new_count
    }

    /// Scans the active blocks since the last verified height, and records
    /// the keys of this wallet that signed in them.
    ///
    /// # The defect this closes
    ///
    /// The scan only existed at load time. On a new machine, the order is
    /// reversed — one restores, *then* the chain arrives — and address
    /// discovery happened in the node loop without rereading a single block.
    /// Until the next restart, a Lamport key already revealed in a block was
    /// announced as spendable, and the wallet signed a second time. The node
    /// calls this after any successful discovery, and sending funds calls it
    /// before choosing its coins.
    ///
    /// `read_block` returns the active block at a height, if available. The
    /// scan stops at the first missing block, and the verified height only
    /// advances up to there: we do not declare verified what we have not
    /// read. Returns the number of newly marked keys.
    pub fn scan_chain<L>(&mut self, height: u64, read_block: L) -> usize
    where
        L: Fn(u64) -> Option<crate::block::Block>,
    {
        let mut found = 0usize;
        let mut h = self.verified_up_to.saturating_add(1);
        while h <= height {
            match read_block(h) {
                Some(b) => found += self.record_spends(&b),
                None => break,
            }
            self.verified_up_to = h;
            h += 1;
        }
        found
    }

    /// Forces the association of a hash with an index, for the audit tests.
    ///
    /// Only exists in test builds: it is precisely the inconsistent state a
    /// forged cache would produce, and it must be possible to build it to
    /// prove that the signing barrier holds.
    #[cfg(any(test, feature = "audit"))]
    pub fn force_association_for_test(&mut self, hash: Hash256, index: u32) {
        self.known.insert(hash, index);
    }

    /// Outputs belonging to the wallet that are actually spendable.
    ///
    /// "Actually" is not decoration. With a one-time scheme, a key signs only
    /// once: if an address received two payments — because the payer reused
    /// the address — only one of the two coins can ever be spent. Announcing
    /// them all would show a balance that spending would then refuse, without
    /// explanation. This method therefore returns only what is true;
    /// [`Wallet::frozen_amount`] says what is missing and why.
    pub fn spendable(&self, utxo: &UtxoSet, height: u64) -> Vec<(OutPoint, TxOut, u32)> {
        let one_time = self.scheme.is_one_time();
        let mut v = Vec::new();
        for (h, index) in &self.known {
            // A consumed Lamport key is dead: the funds it holds can no longer
            // be spent without revealing the private key. ML-DSA does not have
            // this constraint, and hiding its funds would be a bug.
            if one_time && (self.consumed.contains(index) || self.reserved.contains_key(index)) {
                continue;
            }
            let coins = utxo.spendable_for(h, height, COINBASE_MATURITY);
            if one_time {
                // A single coin per index, and the largest: it is the one that
                // leaves the most value accessible. At equal amounts, the
                // outpoint breaks the tie, so that two runs of the same wallet
                // always choose the same coin.
                if let Some((o, e)) =
                    coins
                        .into_iter()
                        .max_by_key(|(o, e): &(OutPoint, crate::utxo::UtxoEntry)| {
                            (e.output.value.units(), std::cmp::Reverse(*o))
                        })
                {
                    v.push((o, e.output, *index));
                }
            } else {
                for (o, e) in coins {
                    v.push((o, e.output, *index));
                }
            }
        }
        v.sort_by_key(|(o, _, _)| *o);
        v
    }

    /// Amount tied up by the one-time discipline, and by it alone.
    ///
    /// A Lamport key signs only once. Two coins on the same address therefore
    /// mean one spendable coin and one frozen coin: signing both would reveal
    /// the private key, and the wallet refuses to do so.
    ///
    /// This sum does belong to the user and yet will never be spent. Keeping
    /// quiet about it would be the worst possible choice — they would see a
    /// balance drop for no reason, or a spend fail with no reason shown. So
    /// it is named, so that the interface can explain it.
    ///
    /// Always zero for a scheme that is not one-time (ML-DSA).
    pub fn frozen_amount(&self, utxo: &UtxoSet, height: u64) -> Amount {
        if !self.scheme.is_one_time() {
            return Amount::ZERO;
        }
        let mut total: u64 = 0;
        for (h, index) in &self.known {
            let coins = utxo.spendable_for(h, height, COINBASE_MATURITY);
            let sum = coins
                .iter()
                .fold(0u64, |a, (_, e)| a.saturating_add(e.output.value.units()));
            // Key already used: everything left on it is frozen. Otherwise,
            // everything except the coin that `spendable` will keep.
            let kept = if self.consumed.contains(index) {
                0
            } else {
                coins
                    .iter()
                    .map(|(_, e)| e.output.value.units())
                    .max()
                    .unwrap_or(0)
            };
            total = total.saturating_add(sum.saturating_sub(kept));
        }
        Amount::from_units(total)
    }

    /// What belongs to the wallet but is not yet mature, and the height at
    /// which the **next** part will be released.
    ///
    /// # Why go through the index
    ///
    /// The interface queried this amount by walking **the whole** UTXO set,
    /// and did so every six seconds, under the global lock — the one that is
    /// also used to validate blocks. On a mature chain, every open wallet
    /// would therefore have frozen validation at regular intervals, without
    /// anyone making the connection: it is one's own wallet slowing down
    /// one's own node.
    ///
    /// The wallet knows its addresses, and the UTXO set can find them through
    /// its index. The cost goes from the size of the whole set to the number
    /// of outputs actually held.
    ///
    /// # What the second value brings
    ///
    /// "When?" is the question one asks in front of a locked balance.
    /// Returning the height of the next release and the amount it carries
    /// makes it possible to show a countdown rather than a mystery. At equal
    /// heights the amounts add up: several outputs of the same block are
    /// released together.
    pub fn immature(&self, utxo: &UtxoSet, height: u64) -> (Amount, Option<(u64, Amount)>) {
        let mut total: u64 = 0;
        let mut next: Option<(u64, u64)> = None;
        for hash in self.known.keys() {
            for (_, e) in utxo.outputs_of(hash) {
                if !e.is_coinbase || height >= e.height + COINBASE_MATURITY {
                    continue;
                }
                let value = e.output.value.units();
                total = total.saturating_add(value);
                let free_at = e.height + COINBASE_MATURITY;
                next = match next {
                    Some((h, m)) if h == free_at => Some((h, m.saturating_add(value))),
                    // Always keep the nearest release.
                    Some((h, m)) if h < free_at => Some((h, m)),
                    _ => Some((free_at, value)),
                };
            }
        }
        (
            Amount::from_units(total),
            next.map(|(h, m)| (h, Amount::from_units(m))),
        )
    }

    /// Addresses that received more than one payment, with the number of
    /// coins.
    ///
    /// It is the cause, where [`Wallet::frozen_amount`] gives the amount: it
    /// lets the interface say *which* address was reused, and therefore teach
    /// the user not to give it out again. Empty for a scheme that is not
    /// one-time.
    pub fn reused_addresses(&self, utxo: &UtxoSet, height: u64) -> Vec<(Hash256, usize)> {
        if !self.scheme.is_one_time() {
            return Vec::new();
        }
        let mut v: Vec<(Hash256, usize)> = self
            .known
            .keys()
            .filter_map(|h| {
                let n = utxo.spendable_for(h, height, COINBASE_MATURITY).len();
                (n > 1).then_some((*h, n))
            })
            .collect();
        v.sort_by_key(|(h, _)| *h);
        v
    }

    pub fn balance(&self, utxo: &UtxoSet, height: u64) -> Amount {
        Amount::checked_sum(self.spendable(utxo, height).iter().map(|(_, o, _)| o.value))
            .unwrap_or(Amount::ZERO)
    }

    /// Builds and signs a transaction.
    ///
    /// Naive input selection: oldest first, until the amount is covered.
    /// Enough for phase 2; a real selection will come with the phase 5
    /// wallet.
    /// Chooses the coins to spend to cover `needed`.
    ///
    /// # Why this selection is exposed
    ///
    /// Fees depend on the **size** of the transaction, and the size depends on
    /// the number of inputs — with ML-DSA-87 each input carries 7,219 bytes of
    /// witness. But the number of inputs is only known after selection.
    ///
    /// An estimate that asks the caller to *assume* a number of inputs is
    /// therefore always wrong. A real test showed it: an estimate made for one
    /// input proposed eight units, the real transaction used two inputs, and
    /// the mempool refused it for a fee rate that was too low. The user saw an
    /// incomprehensible refusal on a transaction they had just confirmed.
    ///
    /// Exposing the selection makes it possible to estimate on the
    /// transaction **that will actually be built**.
    ///
    /// Returns the chosen coins and their total.
    #[allow(clippy::type_complexity)]
    pub fn select_coins(
        &self,
        utxo: &UtxoSet,
        height: u64,
        needed: u64,
    ) -> Result<(Vec<(OutPoint, TxOut, u32)>, u64), WalletError> {
        let available = self.spendable(utxo, height);

        // A one-time scheme (Lamport) can sign only once per key, never
        // twice: signing two different messages with the same key reveals
        // both preimages, and **gives away the private key**. The `consumed`
        // guard closes that risk *between* two transactions; closing it
        // *within* a single transaction was missing. Two coins received on the
        // same index (an address reused by the payer) would otherwise be
        // co-signed here, each over its own hash, and the key would leave in
        // the block. So only one per index is kept; the other stays unspent —
        // a frozen coin is infinitely better than a burned key.
        let one_time = self.scheme.is_one_time();
        let mut taken_indices: std::collections::HashSet<u32> = std::collections::HashSet::new();

        let mut chosen: Vec<(OutPoint, TxOut, u32)> = Vec::new();
        let mut total: u64 = 0;
        for e in available {
            if one_time && !taken_indices.insert(e.2) {
                continue;
            }
            total += e.1.value.units();
            chosen.push(e);
            if total >= needed {
                break;
            }
        }
        if total < needed {
            return Err(WalletError::InsufficientFunds {
                available: total,
                requested: needed,
            });
        }

        // No chosen index may have been used already — for a one-time scheme
        // only.
        if self.scheme.is_one_time() {
            for (_, _, index) in &chosen {
                if self.consumed.contains(index) || self.reserved.contains_key(index) {
                    return Err(WalletError::KeyAlreadyUsed(*index));
                }
            }
        }
        Ok((chosen, total))
    }

    pub fn create_transaction(
        &mut self,
        utxo: &UtxoSet,
        height: u64,
        recipient: &Address,
        amount: Amount,
        fee: Amount,
    ) -> Result<Transaction, WalletError> {
        self.create_transaction_multi(utxo, height, &[(*recipient, amount)], fee)
    }

    /// A transaction that pays **several** recipients at once.
    ///
    /// # Why it exists
    ///
    /// Paying ten people in ten transactions means ten skeletons, ten input
    /// signatures, ten trips through the mempool. Grouping them into a single
    /// transaction with N outputs shares the skeleton and commits the coins
    /// only once: the payment rate per second climbs by an order of
    /// magnitude, and total fees drop accordingly.
    ///
    /// The rest does not change: coin selection, change on a fresh address,
    /// one one-time signature per input, and the same last barrier that
    /// refuses to sign if the derived key does not open the lock.
    pub fn create_transaction_multi(
        &mut self,
        utxo: &UtxoSet,
        height: u64,
        destinations: &[(Address, Amount)],
        fee: Amount,
    ) -> Result<Transaction, WalletError> {
        self.create_transaction_multi_guarded(utxo, height, destinations, fee, &mut |_| Ok(()))
    }

    /// Like [`Self::create_transaction_multi`], with an **early write**.
    ///
    /// # The order of operations, and why it matters
    ///
    /// Before, the order was: sign, place in the mempool, save, announce. The
    /// transaction existed — and could be mined by this very node — before
    /// the disk knew that its keys had been used. A power cut or a full disk
    /// in between, and the next send signed again with a one-time key already
    /// used: two Lamport signatures from the same key are enough to forge a
    /// third.
    ///
    /// The order is now: reserve the indices, **save**, then sign. `guard`
    /// receives the wallet with the indices already reserved and must put
    /// them on disk durably; if it fails, nothing is signed, the reservation
    /// is lifted and the spend is refused.
    ///
    /// It is [`Self::prepare_spend`] then [`Self::sign_spend`] in a single
    /// call, for a caller who holds the output set from start to finish. The
    /// node, for its part, releases the chain lock between the two while it
    /// writes the wallet.
    pub fn create_transaction_multi_guarded(
        &mut self,
        utxo: &UtxoSet,
        height: u64,
        destinations: &[(Address, Amount)],
        fee: Amount,
        guard: &mut dyn FnMut(&Wallet) -> Result<(), String>,
    ) -> Result<Transaction, WalletError> {
        let spend = self.prepare_spend(utxo, height, destinations, fee)?;
        if guard(&*self).is_err() {
            // Nothing was signed and the disk retained nothing: the index
            // becomes free again. Keeping it reserved would freeze the coin
            // for nothing.
            self.cancel_spend(spend);
            return Err(WalletError::SaveFailed);
        }
        self.sign_spend(utxo, spend)
    }

    /// First step of a spend: choose the coins, check the keys, **reserve**
    /// the indices. Nothing is signed.
    ///
    /// # Why the spend is cut in two
    ///
    /// Between the reservation and the signature, the wallet must be written
    /// to disk — and that write is an Argon2id seal of several tenths of a
    /// second. The node did it under the chain and mempool lock: block
    /// validation and serving peers stopped on every send. Cutting here makes
    /// it possible to release the lock, write, then take it again for
    /// [`Self::sign_spend`], which checks again that the coins are still
    /// there.
    ///
    /// The change address is drawn here: it is part of what the disk must
    /// know before the signature.
    pub fn prepare_spend(
        &mut self,
        utxo: &UtxoSet,
        height: u64,
        destinations: &[(Address, Amount)],
        fee: Amount,
    ) -> Result<PreparedSpend, WalletError> {
        if destinations.is_empty() {
            return Err(WalletError::ZeroAmount);
        }
        if !self.scheme.is_available() {
            return Err(WalletError::UnsupportedScheme(self.scheme));
        }

        // --- The overflow that stopped the node.
        //
        // `amount + fee` was a bare addition. With `overflow-checks` on all
        // profiles and `panic = "abort"` in release, an RPC call carrying an
        // amount close to `u64::MAX` **stopped the daemon**. And the JSON
        // parser did not close the door: `as_u64` accepts a string, so the
        // `i64::MAX` bound is bypassed by passing the number in quotes. A
        // batch adds only one thing: the sum of the amounts must, too, stay
        // under the cap at every step.
        //
        // No legitimate amount exceeds the emission cap. We refuse both: the
        // overflow, and the implausible.
        if fee.units() > crate::consensus::MAX_SUPPLY {
            return Err(WalletError::AmountOutOfRange);
        }
        let mut total_out: u64 = 0;
        for (_, amount) in destinations {
            if amount.units() == 0 {
                return Err(WalletError::ZeroAmount);
            }
            if amount.units() < crate::consensus::MIN_OUTPUT_VALUE {
                return Err(WalletError::AmountBelowFloor {
                    minimum: crate::consensus::MIN_OUTPUT_VALUE,
                    received: amount.units(),
                });
            }
            total_out = total_out
                .checked_add(amount.units())
                .filter(|t| *t <= crate::consensus::MAX_SUPPLY)
                .ok_or(WalletError::AmountOutOfRange)?;
        }
        let needed = total_out
            .checked_add(fee.units())
            .filter(|t| *t <= crate::consensus::MAX_SUPPLY)
            .ok_or(WalletError::AmountOutOfRange)?;
        let (chosen, total) = self.select_coins(utxo, height, needed)?;

        let mut outputs: Vec<TxOut> = destinations
            .iter()
            .map(|(address, amount)| TxOut {
                value: *amount,
                scheme: address.scheme,
                pubkey_hash: address.hash,
            })
            .collect();

        let change = total - needed;
        // Change below the dust floor would be refused by the network: it is
        // left to the fee rather than creating an output nobody could ever
        // usefully spend.
        if change >= crate::consensus::MIN_OUTPUT_VALUE {
            // Change goes to a fresh address: reusing the original address
            // would reuse a Lamport key already consumed.
            let change_address = self.new_address();
            outputs.push(TxOut {
                value: Amount::from_units(change),
                scheme: change_address.scheme,
                pubkey_hash: change_address.hash,
            });
        }

        let tx = Transaction {
            version: 1,
            inputs: chosen
                .iter()
                .map(|(o, _, _)| TxIn {
                    prev_out: *o,
                    witness: Witness::default(),
                    sequence: u32::MAX,
                })
                .collect(),
            outputs,
            lock_time: 0,
        };

        // Last barrier before signing: does the key derived at this index
        // really open this lock?
        //
        // The wallet knows which indices belong to it through its `known`
        // table, fed by the derivation — but also by a cache on disk. A cache
        // forged on a single entry was enough to make it sign a spend with the
        // wrong key: the transaction was rejected by the whole network, and for
        // a one-time scheme the key was **burned for nothing**. The seed is
        // here, the derivation is deterministic: we check, we do not assume.
        //
        // The cost is zero: the public key computed here is exactly the one
        // the witness carries afterwards.
        let mut keys = Vec::with_capacity(chosen.len());
        for (_, output, index) in &chosen {
            let pubkey = self.public_key(*index);
            if pubkey_hash(self.scheme, &pubkey) != output.pubkey_hash {
                return Err(WalletError::LockMismatch { index: *index });
            }
            keys.push(pubkey);
        }

        // Reservation: the indices are held, and the caller must put them on
        // disk **before** any signature exists. They are not yet consumed:
        // nothing is revealed as long as nothing is signed.
        for (_, _, index) in &chosen {
            self.reserved.entry(*index).or_insert(height);
        }
        Ok(PreparedSpend { chosen, keys, tx })
    }

    /// Gives up a prepared spend: the reserved indices become free again. To
    /// be called only if **nothing has been signed**, which the type
    /// guarantees — a signed spend no longer exists in this form.
    pub fn cancel_spend(&mut self, spend: PreparedSpend) {
        for (_, _, index) in &spend.chosen {
            self.reserved.remove(index);
        }
    }

    /// Second step: check the coins again, sign, consume.
    ///
    /// The output set may have changed while the lock was released: a coin
    /// spent elsewhere, a reorg. Each chosen coin must still be there,
    /// identical. Otherwise nothing is signed, the reservation is lifted, and
    /// the caller starts again on the current state.
    ///
    /// After signing, the indices move from reserved to consumed: the key is
    /// revealed, whether the transaction is broadcast or not — it exists.
    pub fn sign_spend(
        &mut self,
        utxo: &UtxoSet,
        spend: PreparedSpend,
    ) -> Result<Transaction, WalletError> {
        let still_there = spend
            .chosen
            .iter()
            .all(|(o, output, _)| utxo.get(o).map(|e| e.output == *output).unwrap_or(false));
        if !still_there {
            self.cancel_spend(spend);
            return Err(WalletError::CoinsGone);
        }
        let PreparedSpend {
            chosen,
            keys,
            mut tx,
        } = spend;

        // Signing: the hash covers the stripped transaction, so it does not
        // change as the witnesses are filled in. A randomness failure stops
        // everything before the first signature is written: the witnesses
        // already computed do not leave this function.
        let mut witnesses = Vec::with_capacity(chosen.len());
        for (i, ((_, spent, index), pubkey)) in chosen.iter().zip(keys).enumerate() {
            let message = tx.sighash(i as u32, self.network, spent);
            let signature = match self.sign_at(*index, &message) {
                Ok(s) => s,
                Err(e) => {
                    // The signatures already produced in memory are thrown
                    // away; for a one-time scheme, they are nevertheless
                    // treated as revealed — they existed.
                    for (_, _, index) in chosen.iter().take(witnesses.len()) {
                        self.consume(*index);
                    }
                    return Err(e);
                }
            };
            witnesses.push(Witness { pubkey, signature });
        }
        for (i, ((_, _, index), witness)) in chosen.iter().zip(witnesses).enumerate() {
            tx.inputs[i].witness = witness;
            self.consume(*index);
        }
        Ok(tx)
    }

    /// A reserved index becomes consumed: the key has signed.
    fn consume(&mut self, index: u32) {
        self.reserved.remove(&index);
        if !self.consumed.contains(&index) {
            self.consumed.push(index);
        }
    }
}

/// A prepared, unsigned spend: chosen coins, verified public keys, stripped
/// transaction. See [`Wallet::prepare_spend`].
///
/// The type is only built by the wallet and is consumed by
/// [`Wallet::sign_spend`] or [`Wallet::cancel_spend`]: a prepared spend can
/// neither be signed twice nor be silently forgotten.
pub struct PreparedSpend {
    chosen: Vec<(OutPoint, TxOut, u32)>,
    keys: Vec<Vec<u8>>,
    tx: Transaction,
}

impl PreparedSpend {
    /// Indices whose coins are committed in this spend.
    pub fn indices(&self) -> Vec<u32> {
        self.chosen.iter().map(|(_, _, i)| *i).collect()
    }
}

/// Signing side of ML-DSA, isolated as verification is in `sig`.
///
/// The node never compiles this module: it has no need to know how to sign.
/// Only the wallet needs it.
#[cfg(feature = "mldsa")]
mod mldsa_wallet {
    use super::WalletError;
    use crate::hash::Hash256;
    use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
    use ml_dsa::{signature::Keypair, MlDsaParams, SigningKey, B32};

    /// The system generator, presented to `ml-dsa` under the trait it
    /// expects. No state: each call queries [`crate::rng`], which fails
    /// rather than degrade.
    struct SystemRng;

    impl TryRng for SystemRng {
        type Error = crate::rng::RngError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from_le_bytes(crate::rng::bytes()?))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from_le_bytes(crate::rng::bytes()?))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            crate::rng::fill(dst)
        }
    }

    impl TryCryptoRng for SystemRng {}

    pub fn public_key<P: MlDsaParams>(seed: &[u8; 32]) -> Vec<u8> {
        SigningKey::<P>::from_seed(&B32::from(*seed))
            .verifying_key()
            .encode()[..]
            .to_vec()
    }

    /// ML-DSA signature in the "hedged" variant (FIPS 204, algorithm 2 with
    /// `rnd` drawn at random).
    ///
    /// # The defect this closes
    ///
    /// The wallet signed in the deterministic variant (`rnd = 0`): two
    /// signatures of the same message were identical. FIPS 204 allows it but
    /// recommends the randomized variant, which protects against fault
    /// attacks — a fault during the computation of `z` with a replayable `y`
    /// reveals `s1`. The verifier accepts both variants: nothing changes for
    /// the network.
    ///
    /// If the system generator is missing, we **refuse to sign**: never a
    /// fallback to `rnd = 0`, which would be exactly the variant being left
    /// behind.
    pub fn sign<P: MlDsaParams>(
        seed: &[u8; 32],
        message: &Hash256,
    ) -> Result<Vec<u8>, WalletError> {
        let key = SigningKey::<P>::from_seed(&B32::from(*seed));
        let signature = key
            .expanded_key()
            .sign_randomized(message.as_bytes(), b"", &mut SystemRng)
            .map_err(|_| WalletError::RandomnessUnavailable)?;
        Ok(signature.encode()[..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mining derives addresses; only those the holder requests are recorded
    /// as such, and the record survives a reload.
    ///
    /// A miner quickly owns a thousand addresses they never handed out:
    /// presenting them at the same rank as the two they gave drowns those
    /// two. The distinction touches neither the balance nor the keys.
    #[test]
    fn only_requested_addresses_are_recorded_as_such() {
        let mut w = Wallet::from_seed([7u8; 32], Network::Regtest);
        let mining = w.new_address();
        let given = w.request_address();
        let _ = w.new_address();
        assert!(
            !w.is_requested(0),
            "a mining address is not a requested one"
        );
        assert!(w.is_requested(1), "a requested address is one");
        assert!(!w.is_requested(2));
        assert_ne!(mining.hash, given.hash);
        assert_eq!(w.requested_indices(), vec![1]);
        // Both remain recognized as its own: nothing changes in the balance.
        assert!(w.owns(&mining.hash));
        assert!(w.owns(&given.hash));

        // Reloading from the file: the record comes back, and an earlier file
        // without the line simply gives an empty set.
        let mut r = Wallet::from_seed([7u8; 32], Network::Regtest);
        r.rescan(3);
        assert!(!r.is_requested(1), "without the line, nothing is requested");
        r.load_requested(&w.requested_indices());
        assert!(r.is_requested(1));
        assert_eq!(r.requested_indices(), vec![1]);
    }
    use crate::chain::{genesis_block, Chain, GENESIS_TIME};
    use crate::consensus::TARGET_BLOCK_SECS;

    fn test_wallet() -> Wallet {
        Wallet::from_seed([0x11; 32], Network::Regtest)
    }

    /// A file behind the chain — abrupt stop during mining — is caught up:
    /// the addresses handed out beyond `next_index` are recognized, and the
    /// next index starts again after the last one used.
    #[test]
    fn catch_up_finds_addresses_handed_out_after_the_last_write() {
        // The wallet "from before the cut" handed out indices 0 to 9.
        let mut before = test_wallet();
        let served: Vec<Hash256> = (0..10).map(|_| before.new_address().hash).collect();
        // The reread file only knows three of them.
        let mut after = test_wallet();
        for _ in 0..3 {
            let _ = after.new_address();
        }
        assert_eq!(after.next_index(), 3);
        let n = after.catch_up(|h| served.contains(h));
        assert_eq!(n, 7, "the seven addresses handed out after the write");
        assert_eq!(after.next_index(), 10);
        for h in &served {
            assert!(
                after.known.contains_key(h),
                "every address served is recognized"
            );
        }
        // Nothing more to catch up: an empty window, and the index does not
        // move.
        assert_eq!(after.catch_up(|h| served.contains(h)), 0);
        assert_eq!(after.next_index(), 10);
    }

    /// Prepares a chain where `w` holds mature funds.
    fn chain_with_funds(w: &mut Wallet) -> Chain {
        let _ = w.new_address();
        let g = genesis_block(Network::Regtest);
        let mut c = Chain::new(Network::Regtest, g);

        // Mine enough blocks for the genesis coin to be mature.
        for i in 0..(COINBASE_MATURITY + 2) {
            let a = w.new_address();
            let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, 20_000_000)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }
        c
    }

    #[test]
    fn every_address_is_fresh() {
        let mut w = test_wallet();
        let a = w.new_address();
        let b = w.new_address();
        assert_ne!(a.hash, b.hash);
        assert_eq!(w.next_index(), 2);
    }

    #[test]
    fn addresses_carry_the_right_network() {
        let mut w = test_wallet();
        assert!(w.new_address().to_string_bech32().starts_with("rq21"));
    }

    #[test]
    fn the_seed_reproduces_the_same_addresses() {
        let mut a = Wallet::from_seed([7u8; 32], Network::Regtest);
        let mut b = Wallet::from_seed([7u8; 32], Network::Regtest);
        assert_eq!(a.new_address().hash, b.new_address().hash);
        assert_eq!(a.new_address().hash, b.new_address().hash);
    }

    #[test]
    fn rescan_finds_the_addresses() {
        let mut a = Wallet::from_seed([9u8; 32], Network::Regtest);
        let expected: Vec<Hash256> = (0..5).map(|_| a.new_address().hash).collect();

        let mut b = Wallet::from_seed([9u8; 32], Network::Regtest);
        b.rescan(5);
        for h in &expected {
            assert!(b.owns(h), "address lost after rescan");
        }
    }

    #[test]
    fn balance_reflects_mature_funds() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        assert!(
            w.balance(&c.utxo, c.height()).units() > 0,
            "the wallet should hold funds"
        );
    }

    #[test]
    fn an_immature_coinbase_does_not_count_in_the_balance() {
        let mut w = test_wallet();
        let _ = w.new_address();
        let g = genesis_block(Network::Regtest);
        let c = Chain::new(Network::Regtest, g);
        // Height 0: the genesis coin is a brand-new coinbase.
        assert_eq!(w.balance(&c.utxo, 0), Amount::ZERO);
    }

    #[test]
    fn a_built_transaction_is_valid() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(50_000),
                Amount::from_units(1_000),
            )
            .expect("build");

        let mut seen = std::collections::HashSet::new();
        let fee = crate::validate::check_transaction(
            &tx,
            &c.utxo,
            Network::Regtest,
            c.height() + 1,
            &mut seen,
        )
        .expect("the transaction should validate");
        assert_eq!(fee, Amount::from_units(1_000));
    }

    /// The early write: the indices are on disk **before** signing, and a disk
    /// that refuses prevents signing.
    ///
    /// The guard plays the disk. It checks that at the time it is called, the
    /// indices of the chosen coins are already reserved — and appear in what
    /// the file will write under `consumed=` — and that no signature exists
    /// yet; then it refuses. Nothing must have been signed, and the
    /// reservation is lifted: the disk retained nothing, the coin has no
    /// reason to stay frozen for a write that did not happen.
    #[test]
    fn indices_are_saved_before_signing_and_a_refusing_disk_blocks() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        let before: Vec<u32> = w.consumed_indices_for_file();

        let mut seen_by_guard: Vec<u32> = Vec::new();
        let mut reserved_by_guard: Vec<(u32, u64)> = Vec::new();
        let r = w.create_transaction_multi_guarded(
            &c.utxo,
            c.height(),
            &[(a, Amount::from_units(50_000))],
            Amount::from_units(1_000),
            &mut |wallet| {
                seen_by_guard = wallet.consumed_indices_for_file();
                reserved_by_guard = wallet.reserved_indices();
                assert!(
                    wallet.consumed_indices().is_empty(),
                    "nothing is revealed before signing"
                );
                Err("disk full".to_string())
            },
        );
        assert_eq!(r, Err(WalletError::SaveFailed));
        assert!(
            seen_by_guard.len() > before.len(),
            "the guard must see the reserved indices in the file line"
        );
        assert!(
            !reserved_by_guard.is_empty()
                && reserved_by_guard.iter().all(|(_, h)| *h == c.height()),
            "the reservation carries the current height"
        );
        assert!(
            w.reserved_indices().is_empty() && w.consumed_indices().is_empty(),
            "a refusing disk freezes nothing: nothing was signed"
        );

        // The same send, with a disk that accepts: the indices seen by the
        // guard are exactly those that sign, and they are consumed afterwards.
        let mut seen: Vec<u32> = Vec::new();
        let tx = w
            .create_transaction_multi_guarded(
                &c.utxo,
                c.height(),
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
                &mut |wallet| {
                    seen = wallet.consumed_indices_for_file();
                    Ok(())
                },
            )
            .expect("the disk accepts");
        for input in &tx.inputs {
            let h = pubkey_hash(w.scheme(), &input.witness.pubkey);
            let index = *w.known.get(&h).expect("wallet key");
            assert!(
                seen.contains(&index),
                "index {index} signed without being saved first"
            );
            assert!(w.is_consumed(index) && !w.is_reserved(index));
        }
    }

    /// The two-step spend: between the reservation and the signature, a coin
    /// that disappears lifts the reservation without signing anything; a coin
    /// still there is signed, and the index moves from reserved to consumed.
    #[test]
    fn a_coin_gone_between_reservation_and_signing_burns_nothing() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        let prepared = w
            .prepare_spend(
                &c.utxo,
                c.height(),
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .expect("preparation");
        let indices = prepared.indices();
        assert!(!indices.is_empty());
        assert!(indices
            .iter()
            .all(|i| w.is_reserved(*i) && !w.is_consumed(*i)));
        // Reserved, the coin is no longer offered for a second spend.
        assert!(!w
            .spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| indices.contains(i)));

        // The output set changes: the coin is no longer there.
        let empty = UtxoSet::new();
        assert_eq!(
            w.sign_spend(&empty, prepared).err(),
            Some(WalletError::CoinsGone)
        );
        assert!(
            indices
                .iter()
                .all(|i| !w.is_reserved(*i) && !w.is_consumed(*i)),
            "nothing was signed: the indices are given back"
        );

        // On the unchanged set, signing succeeds and consumes.
        let prepared = w
            .prepare_spend(
                &c.utxo,
                c.height(),
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .expect("preparation");
        let indices = prepared.indices();
        let tx = w.sign_spend(&c.utxo, prepared).expect("signature");
        assert_eq!(tx.inputs.len(), indices.len());
        assert!(indices
            .iter()
            .all(|i| w.is_consumed(*i) && !w.is_reserved(*i)));
    }

    /// A reservation reread from disk is confirmed by the chain if the
    /// signature appears there, and lifted if it does not once the delay has
    /// passed — never before, never on an incomplete read.
    #[test]
    fn a_reservation_is_confirmed_or_lifted_by_the_chain() {
        let mut w = test_wallet();
        let mut c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        let h0 = c.height();

        // Two prepared spends, only one signed and mined.
        let signed = w
            .prepare_spend(
                &c.utxo,
                h0,
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .unwrap();
        let abandoned = w
            .prepare_spend(
                &c.utxo,
                h0,
                &[(a, Amount::from_units(50_000))],
                Amount::from_units(1_000),
            )
            .unwrap();
        let i_signed = signed.indices()[0];
        let i_abandoned = abandoned.indices()[0];
        assert_ne!(i_signed, i_abandoned);
        let tx = w.sign_spend(&c.utxo, signed).unwrap();
        // "Shutdown": a wallet is reread from what the file carries.
        let file_consumed = w.consumed_indices_for_file();
        let file_reserved = w.reserved_indices();
        assert!(file_consumed.contains(&i_abandoned));
        assert_eq!(file_reserved, vec![(i_abandoned, h0)]);
        drop(abandoned);

        let miner = w.new_address();
        let t = GENESIS_TIME + (h0 + 1) * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(miner.hash, miner.scheme, &[tx], t, 20_000_000)
            .unwrap();
        c.connect(&b, t + 1).unwrap();

        let mut r = Wallet::from_seed([0x11; 32], Network::Regtest);
        r.rescan(w.next_index());
        r.mark_consumed(&file_consumed);
        r.load_reservations(&file_reserved);
        assert!(r.is_consumed(i_signed));
        assert!(r.is_reserved(i_abandoned) && !r.is_consumed(i_abandoned));

        // Too early: nothing moves.
        assert_eq!(
            r.recheck_reservations(c.height(), |h| c.block_at(h)),
            (0, 0)
        );
        assert!(r.is_reserved(i_abandoned));

        // The delay passes, but a block is missing: nothing is released.
        for _ in 0..Wallet::RESERVATION_TIMEOUT {
            let m = w.new_address();
            let t = GENESIS_TIME + (c.height() + 1) * TARGET_BLOCK_SECS;
            let b = c.mine_block(m.hash, m.scheme, &[], t, 20_000_000).unwrap();
            c.connect(&b, t + 1).unwrap();
        }
        let gap = h0 + 3;
        assert_eq!(
            r.recheck_reservations(c.height(), |h| if h == gap { None } else { c.block_at(h) }),
            (0, 0)
        );
        assert!(
            r.is_reserved(i_abandoned),
            "an incomplete read releases nothing"
        );

        // Complete read: the abandoned index is free, and a reservation whose
        // signature is in the chain would be confirmed.
        let mut r2 = Wallet::from_seed([0x11; 32], Network::Regtest);
        r2.rescan(w.next_index());
        r2.load_reservations(&[(i_signed, h0), (i_abandoned, h0)]);
        assert_eq!(
            r2.recheck_reservations(c.height(), |h| c.block_at(h)),
            (1, 1)
        );
        assert!(r2.is_consumed(i_signed) && !r2.is_reserved(i_signed));
        assert!(!r2.is_consumed(i_abandoned) && !r2.is_reserved(i_abandoned));
    }

    /// The incremental scan: the blocks beyond the verified height are
    /// reread, the height advances up to the first missing block, and a key
    /// seen in a block is no longer offered.
    #[test]
    fn incremental_scan_stops_at_the_first_missing_block() {
        let mut w = test_wallet();
        let mut c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(50_000),
                Amount::from_units(1_000),
            )
            .unwrap();
        let signer = pubkey_hash(w.scheme(), &tx.inputs[0].witness.pubkey);
        let index = *w.known.get(&signer).unwrap();
        let h_spend = c.height() + 1;
        let miner = w.new_address();
        let t = GENESIS_TIME + h_spend * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(miner.hash, miner.scheme, &[tx], t, 20_000_000)
            .unwrap();
        c.connect(&b, t + 1).unwrap();

        // A wallet from the same seed, which knows nothing of the spend.
        let mut r = Wallet::from_seed([0x11; 32], Network::Regtest);
        r.rescan(w.next_index());
        assert!(!r.is_consumed(index));
        // A gap before the block of the spend: the scan stops in front of it.
        let gap = h_spend - 2;
        let marked = r.scan_chain(c.height(), |h| if h == gap { None } else { c.block_at(h) });
        assert_eq!(marked, 0);
        assert_eq!(r.verified_up_to(), gap - 1);
        // Complete read: the key is marked, the height reaches the tip.
        assert_eq!(r.scan_chain(c.height(), |h| c.block_at(h)), 1);
        assert_eq!(r.verified_up_to(), c.height());
        assert!(r.is_consumed(index));
        assert!(!r
            .spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| *i == index));
    }

    /// Tests of the ML-DSA wallet — the path that mainnet will use. Lamport is
    /// only a development crutch.
    #[cfg(feature = "mldsa")]
    mod mldsa {
        use super::*;

        fn mldsa_test_wallet(seed: [u8; 32]) -> Wallet {
            Wallet::from_seed_scheme(seed, Network::Regtest, SchemeId::MlDsa65)
                .expect("ML-DSA-65 must be available with --features mldsa")
        }

        fn chain_with_funds_mldsa(w: &mut Wallet) -> Chain {
            let _ = w.new_address();
            let g = genesis_block(Network::Regtest);
            let mut c = Chain::new(Network::Regtest, g);
            for i in 0..(COINBASE_MATURITY + 2) {
                let a = w.new_address();
                let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
                let b = c
                    .mine_block(a.hash, SchemeId::MlDsa65, &[], t, 20_000_000)
                    .expect("mining");
                c.connect(&b, t + 1).expect("connect");
            }
            c
        }

        /// The test that matters: a transaction signed with ML-DSA, validated
        /// by the same consensus code as any other.
        #[test]
        fn an_ml_dsa_transaction_is_validated_by_consensus() {
            let mut w = mldsa_test_wallet([0x11; 32]);
            let c = chain_with_funds_mldsa(&mut w);
            let mut dest = mldsa_test_wallet([0x99; 32]);
            let a = dest.new_address();

            let tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(50_000),
                    Amount::from_units(1_000),
                )
                .expect("build");

            assert_eq!(tx.inputs[0].witness.pubkey.len(), 1952);
            assert_eq!(tx.inputs[0].witness.signature.len(), 3309);

            let mut seen = std::collections::HashSet::new();
            let fee = crate::validate::check_transaction(
                &tx,
                &c.utxo,
                Network::Regtest,
                c.height() + 1,
                &mut seen,
            )
            .expect("the ML-DSA transaction should validate");
            assert_eq!(fee, Amount::from_units(1_000));
        }

        /// A forged witness must be refused by consensus, not only by the
        /// wallet.
        #[test]
        fn a_forged_ml_dsa_witness_is_refused() {
            let mut w = mldsa_test_wallet([0x11; 32]);
            let c = chain_with_funds_mldsa(&mut w);
            let mut dest = mldsa_test_wallet([0x99; 32]);
            let a = dest.new_address();

            let mut tx = w
                .create_transaction(
                    &c.utxo,
                    c.height(),
                    &a,
                    Amount::from_units(50_000),
                    Amount::from_units(1_000),
                )
                .expect("build");

            tx.inputs[0].witness.signature[100] ^= 0x01;

            let mut seen = std::collections::HashSet::new();
            assert!(crate::validate::check_transaction(
                &tx,
                &c.utxo,
                Network::Regtest,
                c.height() + 1,
                &mut seen,
            )
            .is_err());
        }

        /// Lamport's one-time constraint must not have survived the change of
        /// scheme: an ML-DSA key signs as many times as one wants.
        #[test]
        fn an_ml_dsa_key_signs_several_times() {
            let w = mldsa_test_wallet([0x11; 32]);
            assert!(!w.scheme().is_one_time());

            let pk = w.public_key(0);
            let m1 = crate::hash::tagged_hash("Q21/test", b"one");
            let m2 = crate::hash::tagged_hash("Q21/test", b"two");

            for m in [m1, m2] {
                let s = w.sign_at(0, &m).expect("randomness available");
                assert_eq!(crate::sig::verify(SchemeId::MlDsa65, &pk, &m, &s), Ok(()));
            }
        }

        /// ML-DSA signs in the "hedged" variant: two signatures of the same
        /// message differ, and each verifies. The deterministic variant
        /// (`rnd = 0`) gave two identical signatures, the one most exposed to
        /// fault attacks.
        #[test]
        fn two_ml_dsa_signatures_of_the_same_message_differ_and_verify() {
            let w = mldsa_test_wallet([0x11; 32]);
            let pk = w.public_key(0);
            let m = crate::hash::tagged_hash("Q21/test", b"the same message");
            let a = w.sign_at(0, &m).expect("randomness available");
            let b = w.sign_at(0, &m).expect("randomness available");
            assert_ne!(a, b, "two identical signatures: deterministic variant");
            assert_eq!(crate::sig::verify(SchemeId::MlDsa65, &pk, &m, &a), Ok(()));
            assert_eq!(crate::sig::verify(SchemeId::MlDsa65, &pk, &m, &b), Ok(()));
        }

        /// Two schemes from the same seed share no key.
        #[test]
        fn the_scheme_goes_into_the_derivation() {
            let mut a = mldsa_test_wallet([0x11; 32]);
            let mut b = Wallet::from_seed_scheme([0x11; 32], Network::Regtest, SchemeId::MlDsa87)
                .expect("available");
            assert_ne!(a.public_key(0), b.public_key(0));
            assert_ne!(a.new_address().hash, b.new_address().hash);
        }

        /// Same seed, same scheme: same addresses. That is what makes a 32-byte
        /// backup sufficient.
        #[test]
        fn ml_dsa_addresses_are_reproducible() {
            let mut a = mldsa_test_wallet([0x77; 32]);
            let mut b = mldsa_test_wallet([0x77; 32]);
            for _ in 0..3 {
                assert_eq!(a.new_address(), b.new_address());
            }
        }

        /// ML-DSA is the only scheme usable on mainnet.
        #[test]
        fn mainnet_accepts_ml_dsa_and_refuses_lamport() {
            assert!(
                Wallet::from_seed_scheme([0x01; 32], Network::Mainnet, SchemeId::MlDsa65).is_ok()
            );
            assert!(
                Wallet::from_seed_scheme([0x01; 32], Network::Mainnet, SchemeId::MlDsa87).is_ok()
            );
            // `.err()` rather than the full Result: `Wallet` implements
            // neither Debug nor PartialEq, and that is not an oversight — a
            // wallet that can display itself is a wallet whose seed ends up in
            // a log.
            assert_eq!(
                Wallet::from_seed_scheme([0x01; 32], Network::Mainnet, SchemeId::LamportOts).err(),
                Some(WalletError::UnsupportedScheme(SchemeId::LamportOts))
            );
        }

        /// SPHINCS+ is declared by the protocol but not implemented. A wallet
        /// must not be able to derive addresses it will not know how to spend.
        #[test]
        fn an_unimplemented_scheme_is_refused_at_construction() {
            assert_eq!(
                Wallet::from_seed_scheme([0x01; 32], Network::Regtest, SchemeId::SphincsPlus).err(),
                Some(WalletError::UnsupportedScheme(SchemeId::SphincsPlus))
            );
        }
    }

    #[test]
    fn insufficient_funds_are_reported() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        // A plausible amount but larger than the funds: refused for lack of
        // funds.
        let r = w.create_transaction(
            &c.utxo,
            c.height(),
            &a,
            Amount::from_units(crate::consensus::MAX_SUPPLY),
            Amount::ZERO,
        );
        assert!(
            matches!(r, Err(WalletError::InsufficientFunds { .. })),
            "{r:?}"
        );

        // An amount that makes no sense: refused **before** any arithmetic.
        // This is the path that made an addition overflow and, in release with
        // `panic = "abort"`, stopped the node on a simple RPC call.
        for (m, f) in [
            (u64::MAX, 0),
            (u64::MAX / 2, u64::MAX / 2 + 2),
            (crate::consensus::MAX_SUPPLY, u64::MAX),
        ] {
            let r = w.create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(m),
                Amount::from_units(f),
            );
            assert!(
                matches!(r, Err(WalletError::AmountOutOfRange)),
                "amount {m} fee {f}: {r:?}"
            );
        }
    }

    #[test]
    fn a_zero_amount_is_refused() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();
        assert_eq!(
            w.create_transaction(&c.utxo, c.height(), &a, Amount::ZERO, Amount::ZERO),
            Err(WalletError::ZeroAmount)
        );
    }

    /// The critical point of Lamport.
    #[test]
    fn a_key_is_never_used_twice() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);

        let a1 = dest.new_address();
        let tx1 = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a1,
                Amount::from_units(50_000),
                Amount::ZERO,
            )
            .expect("first spend");

        // The inputs of tx1 are still in the UTXO set as long as the block is
        // not mined. A second build must not take them again.
        let a2 = dest.new_address();
        let tx2 = w.create_transaction(
            &c.utxo,
            c.height(),
            &a2,
            Amount::from_units(1_000),
            Amount::ZERO,
        );

        if let Ok(t2) = tx2 {
            for e1 in &tx1.inputs {
                for e2 in &t2.inputs {
                    assert_ne!(
                        e1.prev_out, e2.prev_out,
                        "the same Lamport key would sign two messages: private key revealed"
                    );
                }
            }
        }
    }

    /// Two coins received on the **same** one-time index must never go
    /// together into a transaction: co-signing them would sign two different
    /// hashes with a Lamport key, which reveals both of its preimages and
    /// **gives away the private key**. The `consumed` guard closes this risk
    /// between transactions; this test locks in its closing *within* a single
    /// transaction. The wallet prefers to refuse (a frozen coin) rather than
    /// burn the key.
    #[test]
    fn two_utxos_of_the_same_index_are_never_co_signed() {
        let mut w = test_wallet();
        let a = w.new_address(); // index 0 — every coinbase goes there
        let g = genesis_block(Network::Regtest);
        let mut c = Chain::new(Network::Regtest, g);
        for i in 0..(COINBASE_MATURITY + 2) {
            let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a.hash, SchemeId::LamportOts, &[], t, 20_000_000)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }

        // The address received well over one coin...
        let reused = w.reused_addresses(&c.utxo, c.height());
        assert_eq!(reused.len(), 1, "a reused address must be reported as such");
        assert!(reused[0].1 >= 2, "it carries several coins");

        // ... but only one is spendable, and it is the largest.
        let coins = w.spendable(&c.utxo, c.height());
        assert_eq!(
            coins.len(),
            1,
            "a one-time key can only give one spendable coin"
        );
        let one_coin = coins[0].1.value.units();

        // The announced balance is exactly what is spendable, and the rest is
        // named "frozen" rather than kept quiet.
        let balance = w.balance(&c.utxo, c.height()).units();
        assert_eq!(balance, one_coin, "the balance must be what can be paid");
        assert!(
            w.frozen_amount(&c.utxo, c.height()).units() > 0,
            "the tied-up coins must be visible"
        );

        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);

        // An amount beyond the announced balance: a plain refusal, never a
        // co-signature (which would reveal the Lamport key).
        let d = dest.new_address();
        let r = w.create_transaction(
            &c.utxo,
            c.height(),
            &d,
            Amount::from_units(balance + 1),
            Amount::ZERO,
        );
        assert!(
            matches!(r, Err(WalletError::InsufficientFunds { .. })),
            "the wallet co-signed two coins of the same index: Lamport key revealed"
        );

        // The reverse promise, the one that makes the wallet usable:
        // everything announced can really be paid, and with a single input.
        let d2 = dest.new_address();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &d2,
                Amount::from_units(balance),
                Amount::ZERO,
            )
            .expect("the announced balance must always be payable");
        assert_eq!(
            tx.inputs.len(),
            1,
            "a single input for an amount covered by one coin"
        );
    }

    #[test]
    fn change_goes_to_a_fresh_address() {
        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);
        let mut dest = Wallet::from_seed([0x99; 32], Network::Regtest);
        let a = dest.new_address();

        let before = w.next_index();
        let tx = w
            .create_transaction(
                &c.utxo,
                c.height(),
                &a,
                Amount::from_units(50_000),
                Amount::ZERO,
            )
            .expect("build");

        assert_eq!(tx.outputs.len(), 2, "there should be change");
        assert!(w.next_index() > before, "no fresh address created");
        assert!(w.owns(&tx.outputs[1].pubkey_hash));
    }

    /// The backup must survive being copied by hand: that is its whole point
    /// compared to sixty-four hexadecimal characters.
    #[test]
    fn the_backup_code_rebuilds_the_seed() {
        let w = test_wallet();
        let code = w.backup_code();
        assert!(code.starts_with("rq21seed1"), "unexpected prefix: {code}");
        assert_eq!(
            Wallet::seed_from_backup(&code, Network::Regtest).unwrap(),
            [0x11; 32]
        );
    }

    /// A single typo must be caught. That is the property that avoids a
    /// silent loss of funds.
    #[test]
    fn a_typo_in_the_backup_is_detected() {
        let w = test_wallet();
        let code = w.backup_code();
        let chars: Vec<char> = code.chars().collect();
        let mut caught = 0;
        let mut attempts = 0;

        // Each character of the data part is replaced by another one of the
        // Bech32 alphabet.
        for i in (code.find('1').unwrap() + 1)..chars.len() {
            for replacement in ['q', 'p', 'z', 'r', 'y', '9', 'x', '8'] {
                if chars[i] == replacement {
                    continue;
                }
                let mut wrong: Vec<char> = chars.clone();
                wrong[i] = replacement;
                let s: String = wrong.into_iter().collect();
                attempts += 1;
                if Wallet::seed_from_backup(&s, Network::Regtest).is_err() {
                    caught += 1;
                }
            }
        }
        assert!(attempts > 100, "the test must cover the whole code");
        assert_eq!(
            caught,
            attempts,
            "{} typo(s) out of {} went unnoticed",
            attempts - caught,
            attempts
        );
    }

    /// A test seed must never be mistaken for a mainnet seed.
    #[test]
    fn a_backup_from_another_network_is_refused() {
        let w = test_wallet();
        let code = w.backup_code();
        assert_eq!(
            Wallet::seed_from_backup(&code, Network::Mainnet),
            Err(WalletError::BackupForOtherNetwork)
        );
    }

    /// An address pasted in place of the code is recognized for what it is.
    ///
    /// The real case: a lost wallet, a receiving address in front of you, and
    /// the certainty that "it's the same thing". The generic verdict — "wrong
    /// checksum, check your copy" — had people hunting for a typo in a
    /// perfect copy. The program must name the object received, on all three
    /// networks, whatever the case.
    #[test]
    fn an_address_pasted_in_place_of_the_code_is_named() {
        for network in [Network::Regtest, Network::Testnet, Network::Mainnet] {
            let mut w = Wallet::from_seed([7u8; 32], network);
            let address = w.new_address().to_string();
            assert!(address.starts_with(network.hrp()), "address: {address}");
            assert_eq!(
                Wallet::seed_from_backup(&address, network),
                Err(WalletError::BackupIsAnAddress),
                "a {network:?} address is not named as such"
            );
            // Whatever the case and the spaces around it: we read what a
            // person pastes, not what a program produces.
            let messy = format!("  {}  ", address.to_ascii_uppercase());
            assert_eq!(
                Wallet::seed_from_backup(&messy, network),
                Err(WalletError::BackupIsAnAddress)
            );
        }
        // And the real code still goes through, exactly as before.
        let w = test_wallet();
        assert_eq!(
            Wallet::seed_from_backup(&w.backup_code(), w.network()),
            Ok([0x11; 32])
        );
        // An arbitrary string stays "unreadable", not "an address".
        assert_eq!(
            Wallet::seed_from_backup("just anything", Network::Testnet),
            Err(WalletError::InvalidBackup)
        );
    }

    /// A clumsy copy-paste must not make a restore fail.
    ///
    /// The real case: the code, pasted from a notebook or a password manager,
    /// arrives cut by a line break in the middle, or surrounded by spaces. It
    /// is still the same code; since the Bech32m alphabet has no whitespace,
    /// any whitespace is formatting noise. The restore must therefore rebuild
    /// the same seed, however the code was pasted.
    #[test]
    fn a_code_riddled_with_whitespace_restores_the_same_seed() {
        let w = test_wallet();
        let code = w.backup_code();
        let expected = Wallet::seed_from_backup(&code, Network::Regtest).unwrap();

        // Cut in the middle by a line break.
        let middle = code.len() / 2;
        let cut = format!("{}\n{}", &code[..middle], &code[middle..]);
        // A mix of all the whitespace a paste can introduce: spaces, tab, line
        // breaks, non-breaking space, zero width, around and in the middle.
        let noisy = format!(
            "  {}\t{}\u{00A0}{}\u{200B}\r\n{}  ",
            &code[..8],
            &code[8..middle],
            &code[middle..code.len() - 4],
            &code[code.len() - 4..]
        );
        for attempt in [cut, noisy] {
            assert_eq!(
                Wallet::seed_from_backup(&attempt, Network::Regtest).unwrap(),
                expected,
                "a code pasted with whitespace must restore the same seed: {attempt:?}"
            );
        }
    }

    /// The seed drawn from the system must be different every time.
    #[test]
    fn two_generated_wallets_differ() {
        let a = Wallet::generate(Network::Regtest).expect("randomness");
        let b = Wallet::generate(Network::Regtest).expect("randomness");
        assert_ne!(a.seed_hex(), b.seed_hex());
    }

    #[test]
    fn hex_seed_round_trip() {
        let w = test_wallet();
        assert_eq!(Wallet::seed_from_hex(&w.seed_hex()), Some([0x11u8; 32]));
        assert_eq!(Wallet::seed_from_hex("not hexadecimal"), None);
    }

    /// The backup code recovers everything, including what was never derived
    /// on this machine.
    ///
    /// # The defect this test pins down
    ///
    /// A restored wallet only knew the addresses it had derived itself — none.
    /// It therefore showed zero on a chain that held its funds, and the promise
    /// of the backup code was false.
    #[test]
    fn a_restored_wallet_finds_its_addresses() {
        let mut origin = Wallet::from_seed([42u8; 32], Network::Regtest);
        // The holder handed out forty addresses; the thirtieth was paid.
        let mut paid = Vec::new();
        for i in 0..40 {
            let a = origin.new_address();
            if i == 29 {
                paid.push(a.hash);
            }
        }

        // A new machine: same seed, no address derived.
        let mut restored = Wallet::from_seed([42u8; 32], Network::Regtest);
        assert!(
            !restored.owns(&paid[0]),
            "without discovery, the paid address must be unknown"
        );

        let found = restored.discover(|h| paid.contains(h));
        assert_eq!(found, 1, "the paid address was not found");
        assert!(restored.owns(&paid[0]), "it did not become its own");
        // The next index goes after the last address that was used, not after
        // the last one explored.
        assert_eq!(restored.next_index(), 30);
    }

    /// Beyond the gap, we stop — and we do not pretend to have searched.
    #[test]
    fn discovery_stops_after_an_empty_gap() {
        let mut origin = Wallet::from_seed([7u8; 32], Network::Regtest);
        // An address far ahead, well beyond the allowed gap.
        let mut far = Hash256::ZERO;
        for i in 0..(Wallet::DISCOVERY_GAP + 50) {
            let a = origin.new_address();
            if i == Wallet::DISCOVERY_GAP + 49 {
                far = a.hash;
            }
        }
        let mut restored = Wallet::from_seed([7u8; 32], Network::Regtest);
        let found = restored.discover(|h| *h == far);
        assert_eq!(
            found, 0,
            "an address beyond the gap must not be found: \
             claiming it findable would give a false guarantee"
        );
    }

    /// An address just before the gap limit stays findable, and the next
    /// window is explored as well.
    #[test]
    fn discovery_spans_windows() {
        let mut origin = Wallet::from_seed([11u8; 32], Network::Regtest);
        let mut targets = Vec::new();
        for i in 0..(Wallet::DISCOVERY_GAP * 2 + 5) {
            let a = origin.new_address();
            // One in the first window, one in the second.
            if i == Wallet::DISCOVERY_GAP - 1 || i == Wallet::DISCOVERY_GAP + 3 {
                targets.push(a.hash);
            }
        }
        let mut restored = Wallet::from_seed([11u8; 32], Network::Regtest);
        let found = restored.discover(|h| targets.contains(h));
        assert_eq!(found, 2, "the second window was not explored");
        assert_eq!(restored.next_index(), Wallet::DISCOVERY_GAP + 4);
    }

    /// Two different seeds do not recognize each other.
    ///
    /// That is the other half of the promise: the backup code recovers
    /// **your** funds, and nothing else.
    #[test]
    fn another_seed_discovers_nothing() {
        let mut a = Wallet::from_seed([1u8; 32], Network::Regtest);
        let its_own = a.new_address().hash;
        let mut b = Wallet::from_seed([2u8; 32], Network::Regtest);
        assert_eq!(b.discover(|h| *h == its_own), 0);
    }

    /// Builds a UTXO set holding one output to `hash`.
    fn utxo_with(hash: Hash256) -> crate::utxo::UtxoSet {
        let mut u = crate::utxo::UtxoSet::new();
        u.insert(
            OutPoint {
                txid: Hash256([9u8; 32]),
                index: 0,
            },
            crate::utxo::UtxoEntry {
                output: TxOut {
                    value: crate::amount::Amount::from_units(1),
                    scheme: SchemeId::LamportOts,
                    pubkey_hash: hash,
                },
                height: 1,
                is_coinbase: false,
            },
        );
        u
    }

    /// The real restore trigger: seeing one's funds, not counting one's
    /// addresses.
    ///
    /// The defect fixed: discovery only started if `next_index <= 1`. But a
    /// restored wallet derives an address as soon as it is opened, another at
    /// the first click — and from the second index on, discovery was cut off.
    /// The holder then saw **zero** on a chain that carried their funds. The
    /// right signal is not the index counter: it is that the wallet does not
    /// yet recognize any of its holdings.
    #[test]
    fn a_wallet_already_in_use_still_sees_its_funds_are_missing() {
        // The holder owns the address of index 30 on the chain.
        let mut origin = Wallet::from_seed([64u8; 32], Network::Regtest);
        let mut paid = Hash256::ZERO;
        for i in 0..40 {
            let a = origin.new_address();
            if i == 30 {
                paid = a.hash;
            }
        }
        let utxo = utxo_with(paid);

        // New machine: restored, then ALREADY in use — two addresses drawn, as
        // when the page opens. The old `next_index <= 1` test would have
        // skipped discovery here.
        let mut restored = Wallet::from_seed([64u8; 32], Network::Regtest);
        restored.new_address();
        restored.new_address();
        assert!(restored.next_index() > 1);

        // Before discovery: the wallet sees none of its funds.
        assert!(
            !restored.sees_funds(&utxo),
            "it should not recognize the paid address yet"
        );

        // That is exactly what the fixed trigger looks at. We search.
        let found = restored.discover(|h| utxo.knows(h));
        assert_eq!(found, 1, "the paid address was not found");

        // After discovery: it sees its funds, and will therefore not start
        // anything again.
        assert!(
            restored.sees_funds(&utxo),
            "after discovery, its funds must be visible"
        );
    }

    /// A truly blank wallet, for its part, sees nothing — and that is correct:
    /// the trigger will stay active as long as no funds appear, without ever
    /// claiming otherwise.
    #[test]
    fn a_wallet_without_funds_sees_nothing() {
        let w = Wallet::from_seed([65u8; 32], Network::Regtest);
        // An output that pays the address of ANOTHER wallet.
        let mut other = Wallet::from_seed([66u8; 32], Network::Regtest);
        let foreign = other.new_address().hash;
        assert!(!w.sees_funds(&utxo_with(foreign)));
    }

    #[test]
    fn an_address_can_be_named_and_renamed() {
        let mut w = Wallet::from_seed([3u8; 32], Network::Regtest);
        assert_eq!(w.label(0), None, "nothing is named at first");
        w.set_label(0, "  for the plumber  ");
        assert_eq!(
            w.label(0),
            Some("for the plumber"),
            "the surrounding spaces do not belong to the name"
        );
        w.set_label(0, "rent");
        assert_eq!(w.label(0), Some("rent"), "a name can be replaced");
    }

    #[test]
    fn an_empty_name_removes_the_label() {
        // Otherwise the address book fills up with empty lines that can no
        // longer be told apart from an unnamed address, and that no button can
        // delete.
        let mut w = Wallet::from_seed([4u8; 32], Network::Regtest);
        w.set_label(7, "temporary");
        w.set_label(7, "   ");
        assert_eq!(w.label(7), None);
        assert!(w.labels().is_empty());
    }

    #[test]
    fn a_name_cannot_break_the_file_or_grow_without_end() {
        let mut w = Wallet::from_seed([5u8; 32], Network::Regtest);
        // Control characters would break the wallet format, which is one line
        // per key: a line break in a name would shift the reading of
        // everything after it.
        w.set_label(0, "Marie\nBakery\tdowntown");
        let e = w.label(0).expect("name set");
        assert!(
            !e.contains('\n') && !e.contains('\t'),
            "control character survived: {e:?}"
        );
        assert_eq!(e, "Marie Bakery downtown");

        // The cut is made on characters, never on bytes: cutting an accented
        // letter in two would produce a string that is not UTF-8, and the
        // wallet would become unreadable.
        w.set_label(1, &"€".repeat(200));
        let long = w.label(1).expect("name set");
        assert_eq!(long.chars().count(), Wallet::MAX_LABEL_LEN);
        assert!(long.chars().all(|c| c == '€'));
    }

    /// The immature amount returned through the index must match a full scan
    /// exactly — amount **and** height of the next release.
    ///
    /// That is the counterpart of an optimization: it is only worth it if it
    /// does not change the answer. A miner who saw a wrong countdown would
    /// still prefer the old slow scan.
    #[test]
    fn immature_amount_matches_the_full_scan() {
        fn full_scan(w: &Wallet, utxo: &UtxoSet, height: u64) -> (u64, Option<(u64, u64)>) {
            let mut immature = 0u64;
            let mut next: Option<(u64, u64)> = None;
            for (_, e) in utxo.iter() {
                if e.is_coinbase
                    && height < e.height + COINBASE_MATURITY
                    && w.owns(&e.output.pubkey_hash)
                {
                    immature += e.output.value.units();
                    let free_at = e.height + COINBASE_MATURITY;
                    match next {
                        Some((h, m)) if h == free_at => {
                            next = Some((h, m + e.output.value.units()))
                        }
                        Some((h, _)) if h < free_at => {}
                        _ => next = Some((free_at, e.output.value.units())),
                    }
                }
            }
            (immature, next)
        }

        let mut w = test_wallet();
        let c = chain_with_funds(&mut w);

        // At several heights: before maturity, during, and well after. The
        // three cases vary both the amount and the next release.
        for h in [
            0u64,
            1,
            c.height() / 2,
            c.height(),
            c.height() + COINBASE_MATURITY,
        ] {
            let expected = full_scan(&w, &c.utxo, h);
            let (m, p) = w.immature(&c.utxo, h);
            let got = (m.units(), p.map(|(x, y)| (x, y.units())));
            assert_eq!(
                got, expected,
                "the index diverges from the full scan at height {h}"
            );
        }

        // And there must be at least one height where the answer is not empty,
        // otherwise the test would prove nothing.
        let (m, p) = w.immature(&c.utxo, c.height());
        assert!(
            m.units() > 0 && p.is_some(),
            "the setup must produce immature funds"
        );
    }
}
