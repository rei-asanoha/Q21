//! JSON-RPC 2.0 API.
//!
//! # Why this API exists, and why it is local
//!
//! To look at a chain, almost everyone today opens a third party's website.
//! That is, they **trust someone** to tell them what a system designed
//! precisely so as to trust no one contains. The Q21 explorer is served by the
//! node itself, on the local loopback. What you read, your machine has
//! validated.
//!
//! # Two families of methods, kept apart on purpose
//!
//! - **Read**: chain state, blocks, transactions, mempool, emission.
//!   They cannot move anything.
//! - **Wallet**: balance, new address, send. They can lose funds, and are
//!   therefore **disabled by default** - they must be requested explicitly. A
//!   read-only RPC port must never become a spending port by accident.
//!
//! # Amounts
//!
//! Every amount goes out twice: as an integer of indivisible units, and as a
//! formatted string. Never as a float. A client that reads a balance back as a
//! `double` loses units, and nobody notices until it is too late.

use crate::address::{Address, Network};
use crate::amount::Amount;
use crate::block::Block;
use crate::consensus::*;
use crate::emission;
use crate::hash::Hash256;
use crate::json::{parse, Json};
use crate::memhard;
use crate::net::Node;
use crate::sig::SchemeId;
use crate::tx::Transaction;
use crate::wallet::Wallet;
use std::sync::{Arc, Mutex};

/// JSON-RPC 2.0 error codes.
pub const ERR_PARSE: i64 = -32700;

/// Message returned to the caller for a wallet error.
///
/// # What used to leak
///
/// The error was returned through `format!("{e:?}")`, so with its contents:
/// `InsufficientFunds { available: 43120000, requested: ... }`. The exact
/// balance thus went out to a caller who only had to ask for an absurd sum to
/// get it. A refusal does not need to be an account statement.
///
/// The other variants carry nothing sensitive and keep a precise message: a
/// user who makes a mistake must understand why.
/// Seconds since 1970, to timestamp what is not in a block yet.
///
/// A mempool transaction has no protocol time: its time will be that of the
/// block that includes it. In the meantime, the interface needs something to
/// display, and "now" is the least wrong of the answers.
fn now_utc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Message returned to the caller for a mempool rejection.
///
/// # What was returned before
///
/// `format!("{e:?}")`, so the raw Rust structure:
/// `SpendConflict(OutPoint { txid: Hash256(3f2a...), index: 0 })`.
/// Unreadable for anyone who does not have the definition in front of them,
/// and without the slightest hint of what to do. A real trial of the
/// interface ran into it twice in a row.
///
/// Each rejection now says **what happened** and **what can fix it**. The
/// numeric values stay, they are useful; it is the debug syntax that goes
/// away.
fn mempool_message(e: &crate::mempool::MempoolError) -> String {
    use crate::mempool::MempoolError as M;
    match e {
        M::AlreadyPresent => "this transaction is already pending".to_string(),
        M::SpendConflict(_) => "a transaction already pending spends the same funds. \
             Wait for it to be confirmed before sending another one."
            .to_string(),
        M::UnconfirmedDependency(_) => "this spend relies on funds received in a transaction \
             that is not confirmed yet. Wait for a block."
            .to_string(),
        M::FeeRateTooLow { received, minimum } => format!(
            "fee too low to be relayed: {received} per thousand weight units, \
             minimum {minimum}. Request a new estimate."
        ),
        M::Unmineable { weight, size } => format!(
            "transaction too heavy to fit in a block: {size} bytes, \
             weight {weight}. Send an amount that needs fewer inputs."
        ),
        M::FullAndUnderpaid => "the mempool is full and this transaction pays less \
             than the lowest bidder. Raise the fee."
            .to_string(),
        M::Validation(v) => format!("rejected by validation: {v:?}"),
    }
}

fn wallet_message(e: &crate::wallet::WalletError) -> &'static str {
    use crate::wallet::WalletError as W;
    match e {
        W::InsufficientFunds { .. } => "insufficient funds",
        W::KeyAlreadyUsed(_) => {
            "this key has already signed: on a one-time scheme, signing again \
             would reveal the private key"
        }
        W::UnknownKey => "key unknown to this wallet",
        W::ZeroAmount => "zero amount",
        W::AmountOutOfRange => "amount or fee beyond what can exist",
        W::UnsupportedScheme(_) => "signature scheme not available in this binary",
        W::RandomnessUnavailable => "system random generator unavailable",
        W::InvalidBackup => "unreadable backup code",
        W::BackupForOtherNetwork => "backup code from another network",
        W::BackupIsAnAddress => "this is a receiving address, not a backup code",
        W::LockMismatch { .. } => {
            "mismatch between the derived key and the output to spend: nothing \
             was signed"
        }
        W::AmountBelowFloor { .. } => {
            "amount too small: an output must be worth at least 0.0001 Q21 \
             (10,000 units), otherwise the network rejects it as dust"
        }
        W::SaveFailed => {
            "the wallet could not be saved before signing: nothing was \
             signed, check the disk"
        }
        W::CoinsGone => {
            "one of the chosen coins disappeared while the wallet was being \
             saved (spent elsewhere, or a reorg): nothing was signed, try again"
        }
        W::VerificationBehind { .. } => {
            "one-time keys: the chain could not be scanned up to the current \
             height (missing block bodies). Signing without knowing which keys \
             have already been used could reveal one: send refused"
        }
    }
}

/// Calls accepted in a single JSON-RPC batch.
///
/// A batch only exists to save network round trips. A hundred is enough for
/// that; ten thousand only serve to multiply the node's work by ten thousand
/// for the price of one request.
pub const MAX_BATCH: usize = 100;

/// Cumulative size of a batch's responses, in bytes.
///
/// The response used to be assembled entirely in memory before being sent,
/// without any bound: a one-mebibyte request produced tens of mebibytes of
/// heap.
pub const MAX_BATCH_RESPONSE: usize = 8 * 1024 * 1024;

/// Maximum number of blocks walked back by `gettransaction` without an index.
///
/// Scanning the whole chain backward, under the node's global lock, is a work
/// amplification: the cost grows with the height, and a batch multiplied it.
/// Until there is an index by transaction id, we bound the search and **say
/// so** in the response rather than lie by omission.
pub const MAX_SCANNED_BLOCKS: u64 = 2_000;

/// Fee used when the caller proposes none, in units.
///
/// Deliberately modest: on a lightly loaded chain, paying more speeds nothing
/// up. `estimatefee` proposes a value measured on the real state of the
/// mempool; this one is only a fallback.
pub const DEFAULT_FEE: u64 = 1_000;

/// Blocks walked back by `listtransactions`.
///
/// Without an index by address, finding the history requires rereading the
/// bodies. The window is bounded and **announced in the response**: a wallet
/// that shows a truncated history without saying so lies to its owner.
pub const HISTORY_WINDOW: u64 = 5_000;

/// Default unlock duration, in seconds.
pub const DEFAULT_UNLOCK_SECS: u64 = 300;
pub const ERR_REQUEST: i64 = -32600;
pub const ERR_METHOD: i64 = -32601;
pub const ERR_PARAMS: i64 = -32602;
pub const ERR_INTERNAL: i64 = -32603;
/// Application errors.
pub const ERR_NOT_FOUND: i64 = -1;
pub const ERR_WALLET_DISABLED: i64 = -2;
pub const ERR_WALLET: i64 = -3;

/// What is called after any operation that modified the wallet.
///
/// # The defect this callback fixes
///
/// `sendtoaddress` and `getnewaddress` mutate the wallet: the first marks a
/// key as consumed, the second advances the index counter. **Nothing wrote
/// these changes to disk.** They lived in the process memory and died with
/// it.
///
/// For ML-DSA the consequence is limited to a reused address - a privacy
/// defect. For a one-time scheme, it is a Lamport key that would be used
/// again, hence a published private key. The chain scan at startup catches
/// this precise case, but a safety net is no excuse for leaving the hole.
///
/// The callback is supplied by the caller, which alone knows where the file
/// lives.
/// Wallet save callback.
///
/// Returns a result: when it serves as a write-ahead before a signature, a
/// failure must **prevent** the signature, not merely be displayed.
pub type OnChange = Arc<dyn Fn(&Wallet) -> Result<(), String> + Send + Sync>;

/// Callback that persists the "reachable" setting. See [`RpcContext`].
pub type SetReachable = Arc<dyn Fn(bool) -> Result<(), String> + Send + Sync>;

pub struct RpcContext {
    pub node: Arc<Node>,
    /// Absent if the wallet methods are disabled.
    pub wallet: Option<Arc<Mutex<Wallet>>>,
    pub network: Network,
    /// Address index, if the node was started with `--address-index`.
    ///
    /// When it is absent, address and transaction lookups fall back to the
    /// bounded scan. The difference shows on screen: the response carries a
    /// field that says which of the two paths was used, and how far back it
    /// searched. An incomplete answer that presents itself as complete is
    /// worse than no answer.
    pub index: Option<Arc<Mutex<crate::index::Index>>>,
    /// Mining switch and counters, if this node can mine.
    ///
    /// When it is absent, `getmining` answers that the machine is not mining
    /// and `setmining` refuses: a node without a wallet has nowhere to pay a
    /// subsidy to, and letting it believe otherwise would be worse than
    /// refusing.
    pub mining: Option<Arc<crate::mining::Mining>>,
    /// Called after each operation that modifies the wallet.
    ///
    /// Absent in pure memory (tests). In production it **must** be supplied:
    /// without it, a spend is not saved.
    pub on_change: Option<OnChange>,
    /// Budget for chain scans, when this service is exposed to the public.
    ///
    /// Absent locally: whoever queries their own node can make it wait.
    /// Present in public mode: see [`ScanBucket`].
    pub scans: Option<Arc<Mutex<ScanBucket>>>,
    /// How many entry points this node received at launch.
    ///
    /// Zero means it will look for no one: no `--bootstrap`, no
    /// `bootstrap.txt` in its folder, no built-in list. The command window
    /// already says so, but that is precisely the window the guide teaches
    /// people to ignore. Without this count, a page cannot tell "I have
    /// nobody's address" - where a two-line file is missing - from "I knocked
    /// and nobody answered" - where it is the server or the network that
    /// needs looking at. Both look the same, and one of the two makes people
    /// give up.
    pub configured_bootstrap: usize,
    /// The "is this node reachable from outside" setting, as the user last
    /// **wanted** it.
    ///
    /// It changes as soon as `setreachable` has written it to disk, and it is
    /// what paints the switch. v0.2.0 only kept the value read at launch: the
    /// Network tab, refreshed every four seconds, repainted the old value and
    /// the switch flipped back on its own.
    pub reachable: std::sync::atomic::AtomicBool,
    /// The same setting as it was at launch: it is the one that governs this
    /// session, because listening and opening the router port are decided at
    /// startup. When the two differ, the interface says the change takes
    /// effect at the next launch.
    pub reachable_session: bool,
    /// Status of opening the port on the router, in plain words, when this
    /// node tries to open itself up. Absent (or empty): no attempt - client
    /// node, or bootstrap node with a direct address. Filled in by the
    /// dedicated thread.
    pub router_status: Option<Arc<Mutex<String>>>,
    /// Persists a change of the "reachable" setting. Supplied by the caller,
    /// which alone knows where the file lives. Absent in pure memory (tests).
    pub set_reachable: Option<SetReachable>,
}

/// Chain scans a public service grants: a budget **per client**, and a net
/// for everyone together.
///
/// # The defect this closes
///
/// `getamount`, `getaddress` without an index and `gettransaction` with no
/// index result reread up to [`MAX_SCANNED_BLOCKS`] bodies from disk, **under
/// the global lock** - the one used to validate blocks. In public mode, these
/// methods answer without a token, and a batch allows a hundred of them: an
/// anonymous visitor, looping over nonexistent ids, froze validation on the
/// only public entry point.
///
/// # What the first version did not close
///
/// It bounded the total, all requests combined, because the node only saw
/// the front server. A single visitor therefore emptied the burst in one
/// request, and **everyone else** read "try again in a minute" - a denial of
/// service on search, anonymous and free, which replaced the validation freeze
/// with depriving everyone.
///
/// The front server knows the client address and passes it on; the HTTP
/// server sets it on the request (see `http::client_address`, which only
/// trusts the header from the local loopback). Each client therefore has its
/// own burst and its own refill, in a bounded table where the oldest gives up
/// its place. The global bucket remains, larger, as a net: against a thousand
/// addresses joining in together, it still bounds what the lock endures, and
/// the node keeps validating.
///
/// A client with no known address - a direct call without an HTTP server -
/// only goes through the net.
pub struct ScanBucket {
    global: Bucket,
    clients: Vec<(ClientKey, Bucket, std::time::Instant)>,
}

/// A token bucket: a burst, a refill.
struct Bucket {
    tokens: u32,
    last: std::time::Instant,
}

/// Scans granted up front to each client.
pub const SCAN_BURST: u32 = 30;
/// Scans regained per minute, per client.
pub const SCANS_PER_MINUTE: u32 = 12;
/// Burst of the global net: five full clients at once.
pub const GLOBAL_SCAN_BURST: u32 = 150;
/// Refill of the global net per minute: one scan per second, sustained.
pub const GLOBAL_SCANS_PER_MINUTE: u32 = 60;
/// Clients tracked at once. Beyond that, the least recently seen gives up its
/// place - it then starts again with a fresh burst, which costs the net
/// nothing.
pub const MAX_TRACKED_CLIENTS: usize = 1024;

/// What identifies a client in the table.
///
/// An IPv4 address as is. An IPv6 address reduced to its `/64`: a subscriber
/// receives a whole one, and counting each of its 2^64 addresses as a
/// different client would give it as many bursts. An IPv4 carried in IPv6
/// (`::ffff:a.b.c.d`) is reduced to the IPv4.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ClientKey {
    V4(std::net::Ipv4Addr),
    V6([u8; 8]),
}

impl ClientKey {
    fn from_ip(ip: std::net::IpAddr) -> ClientKey {
        match ip {
            std::net::IpAddr::V4(a) => ClientKey::V4(a),
            std::net::IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => ClientKey::V4(v4),
                None => {
                    let o = a.octets();
                    let mut p = [0u8; 8];
                    p.copy_from_slice(&o[..8]);
                    ClientKey::V6(p)
                }
            },
        }
    }
}

impl Bucket {
    fn full(burst: u32, now: std::time::Instant) -> Bucket {
        Bucket {
            tokens: burst,
            last: now,
        }
    }

    fn allow(&mut self, burst: u32, per_minute: u32, now: std::time::Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs();
        let gain = (elapsed.min(u32::MAX as u64) as u32).saturating_mul(per_minute) / 60;
        if gain > 0 {
            self.tokens = self.tokens.saturating_add(gain).min(burst);
            self.last = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

impl Default for ScanBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanBucket {
    pub fn new() -> ScanBucket {
        ScanBucket {
            global: Bucket::full(GLOBAL_SCAN_BURST, std::time::Instant::now()),
            clients: Vec::new(),
        }
    }

    /// Grants a scan to this client, or not.
    ///
    /// The client's bucket is checked first: a client that has run dry is
    /// refused without touching the net, so that it does not empty it for
    /// the others. The net is only charged for a scan that is really going to
    /// happen.
    pub fn allow(&mut self, client: Option<std::net::IpAddr>, now: std::time::Instant) -> bool {
        if let Some(ip) = client {
            if !self.allow_client(ClientKey::from_ip(ip), now) {
                return false;
            }
        }
        self.global
            .allow(GLOBAL_SCAN_BURST, GLOBAL_SCANS_PER_MINUTE, now)
    }

    fn allow_client(&mut self, key: ClientKey, now: std::time::Instant) -> bool {
        if let Some(entry) = self.clients.iter_mut().find(|(c, _, _)| *c == key) {
            entry.2 = now;
            return entry.1.allow(SCAN_BURST, SCANS_PER_MINUTE, now);
        }
        if self.clients.len() >= MAX_TRACKED_CLIENTS {
            // The least recently seen goes away. A table full of active
            // clients stays bounded: it is then the net that holds.
            if let Some((i, _)) = self
                .clients
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, _, seen))| *seen)
            {
                self.clients.swap_remove(i);
            }
        }
        let mut bucket = Bucket::full(SCAN_BURST, now);
        let granted = bucket.allow(SCAN_BURST, SCANS_PER_MINUTE, now);
        self.clients.push((key, bucket, now));
        granted
    }

    /// Number of clients tracked right now. For tests.
    pub fn tracked_clients(&self) -> usize {
        self.clients.len()
    }
}

impl RpcContext {
    /// Read-only context: no wallet method.
    pub fn read_only(node: Arc<Node>, network: Network) -> RpcContext {
        RpcContext {
            node,
            wallet: None,
            network,
            index: None,
            mining: None,
            on_change: None,
            scans: None,
            configured_bootstrap: 0,
            reachable: std::sync::atomic::AtomicBool::new(true),
            reachable_session: true,
            router_status: None,
            set_reachable: None,
        }
    }

    /// Is a chain scan granted to this client? Always locally; within the
    /// budget in public mode.
    fn allow_scan(&self, client: Option<std::net::IpAddr>) -> Result<(), Json> {
        let Some(bucket) = &self.scans else {
            return Ok(());
        };
        let granted = bucket
            .lock()
            .map(|mut s| s.allow(client, std::time::Instant::now()))
            .unwrap_or(false);
        if granted {
            Ok(())
        } else {
            Err(rpc_error(
                ERR_REQUEST,
                "too many searches in progress on this public service: try again in a minute",
            ))
        }
    }
}

fn rpc_error(code: i64, message: &str) -> Json {
    Json::obj()
        .set("code", Json::Int(code))
        .set("message", Json::str(message))
        .build()
}

fn amount_json(a: Amount) -> Json {
    Json::obj()
        .set("units", Json::u64(a.units()))
        .set("q21", Json::str(a.to_string()))
        .build()
}

fn header_json(h: &crate::block::BlockHeader) -> Json {
    Json::obj()
        .set("id", Json::str(h.block_id().to_hex()))
        .set("height", Json::u64(h.height))
        .set("parent", Json::str(h.prev_block.to_hex()))
        .set("merkle", Json::str(h.merkle_root.to_hex()))
        .set("uncles_root", Json::str(h.uncles_root.to_hex()))
        .set("miner", Json::str(h.miner.to_hex()))
        .set("timestamp", Json::u64(h.time))
        .set("bits", Json::str(format!("{:#010x}", h.bits)))
        .set("nonce", Json::u64(h.nonce))
        .build()
}

/// Rendering of a transaction.
///
/// The network is required because an output must show an **address**, not
/// only the key hash it carries. The key hash is what the protocol handles;
/// the address is what a human copies, pastes and recognizes - and an address
/// cannot be formed without knowing which network it belongs to. An explorer
/// that only showed key hashes would force people to do the conversion in
/// their head to find an address in their wallet.
fn tx_json(t: &Transaction, network: Network) -> Json {
    let inputs: Vec<Json> = t
        .inputs
        .iter()
        .map(|e| {
            Json::obj()
                .set("txid", Json::str(e.prev_out.txid.to_hex()))
                .set("index", Json::u64(e.prev_out.index as u64))
                .set(
                    "witness_bytes",
                    Json::u64((e.witness.pubkey.len() + e.witness.signature.len()) as u64),
                )
                .build()
        })
        .collect();
    let outputs: Vec<Json> = t
        .outputs
        .iter()
        .map(|o| {
            Json::obj()
                .set("value", amount_json(o.value))
                .set("scheme", Json::str(o.scheme.name()))
                .set("key_hash", Json::str(o.pubkey_hash.to_hex()))
                .set(
                    "address",
                    Json::str(
                        crate::address::Address {
                            network,
                            scheme: o.scheme,
                            hash: o.pubkey_hash,
                        }
                        .to_string_bech32(),
                    ),
                )
                .build()
        })
        .collect();

    let full = t.encode().len();
    let body = t.encode_without_witness().len();
    Json::obj()
        .set("txid", Json::str(t.txid().to_hex()))
        .set("wtxid", Json::str(t.wtxid().to_hex()))
        .set("coinbase", Json::Bool(t.is_coinbase()))
        .set("inputs", Json::array(inputs))
        .set("outputs", Json::array(outputs))
        .set("size_bytes", Json::u64(full as u64))
        .set("witness_bytes", Json::u64((full - body) as u64))
        .set(
            "witness_percent",
            Json::u64(((full - body) * 100).checked_div(full).unwrap_or(0) as u64),
        )
        .set("weight", Json::u64(t.weight(WITNESS_DISCOUNT)))
        .build()
}

/// Shortest identifier prefix the search completes. See `search`.
const MIN_ID_PREFIX: usize = 8;

/// What the search reads: the text without any space, line break or
/// invisible character, and without a trailing ellipsis.
fn compact_search(raw: &str) -> String {
    let t: String = raw
        .chars()
        .filter(|c| {
            !c.is_whitespace() && !matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}')
        })
        .collect();
    t.trim_end_matches('…').trim_end_matches("...").to_string()
}

/// If `q` reads as an amount, its text in the form `amount_to_units` takes.
///
/// An amount carries a separator - `1.5` or, as written in French, `1,5` - or
/// the unit after it: `2 Q21`. With both a comma and a point, the comma
/// separates thousands (`1,000.5`). Anything else is not an amount, and the
/// search goes on.
fn amount_candidate(q: &str) -> Option<String> {
    let lower = q.to_ascii_lowercase();
    let (number, with_unit) = match lower.strip_suffix("q21") {
        Some(n) => (n.to_string(), true),
        None => (lower.clone(), false),
    };
    if number.is_empty()
        || !number
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ',' || c == '\'')
        || !number.chars().any(|c| c.is_ascii_digit())
    {
        return None;
    }
    let number = number.replace('\'', "");
    let normalized = if number.contains('.') {
        number.replace(',', "")
    } else {
        number.replace(',', ".")
    };
    if normalized.contains('.') || with_unit {
        Some(normalized)
    } else {
        None
    }
}

/// Does the hexadecimal writing of `h` start with `prefix` (lowercase)?
fn hex_starts_with(h: &Hash256, prefix: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    prefix.len() <= 64
        && prefix.bytes().enumerate().all(|(i, c)| {
            let byte = h.0[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            HEX[nibble as usize] == c
        })
}

/// Reads an amount in Q21 (e.g. `1.5`, `0.005`) and returns it in units,
/// without ever going through a float. Returns `None` on input that is not an
/// amount: more than eight decimals, a foreign character, or nothing at all.
fn amount_to_units(s: &str) -> Option<u64> {
    let s = s.trim();
    let (int_part, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if int_part.is_empty() && frac.is_empty() {
        return None;
    }
    if frac.len() > DECIMALS as usize {
        return None;
    }
    if !int_part.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let e: u64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().ok()?
    };
    let mut f: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().ok()?
    };
    for _ in frac.len()..DECIMALS as usize {
        f = f.checked_mul(10)?;
    }
    e.checked_mul(UNITS_PER_COIN)?.checked_add(f)
}

fn block_json(b: &Block, network: Network) -> Json {
    let txs: Vec<Json> = b.transactions.iter().map(|t| tx_json(t, network)).collect();
    let uncles: Vec<Json> = b.uncles.iter().map(header_json).collect();
    Json::obj()
        .set("header", header_json(&b.header))
        .set("size_bytes", Json::u64(b.encode().len() as u64))
        .set(
            "subsidy",
            amount_json(emission::block_subsidy(b.header.height)),
        )
        .set("tx_count", Json::u64(b.transactions.len() as u64))
        .set("transactions", Json::array(txs))
        .set("uncles", Json::array(uncles))
        .build()
}

impl RpcContext {
    /// Handles a JSON-RPC document and returns the encoded response, with no
    /// identified client: in public mode, only the global net then applies.
    pub fn handle(&self, body: &str) -> String {
        self.handle_from(body, None)
    }

    /// Handles a JSON-RPC document coming from `client`, and returns the
    /// response.
    ///
    /// The address is only used for the scan budget: it is neither logged nor
    /// returned. The HTTP server supplies it (see `http::Request::client`); a
    /// direct call passes `None`.
    pub fn handle_from(&self, body: &str, client: Option<std::net::IpAddr>) -> String {
        let request = match parse(body) {
            Ok(v) => v,
            Err(_) => {
                return Json::obj()
                    .set("jsonrpc", Json::str("2.0"))
                    .set("id", Json::Null)
                    .set("error", rpc_error(ERR_PARSE, "unreadable JSON document"))
                    .build()
                    .encode()
            }
        };

        // --- Batch of requests: each one handled independently, but not for
        //     free.
        //
        // An audit measured the amplification: a one-mebibyte request - the
        // maximum size of a body - contains tens of thousands of calls, each
        // producing its response, the whole thing assembled **in memory**
        // before being sent. Some calls cost far more than their size: a
        // `gettransaction` scans the whole chain, under the node's global
        // lock.
        //
        // The batch stays useful - it saves round trips - but it is bounded,
        // and so is the response.
        if let Some(batch) = request.as_array() {
            if batch.len() > MAX_BATCH {
                return Json::obj()
                    .set("jsonrpc", Json::str("2.0"))
                    .set("id", Json::Null)
                    .set(
                        "error",
                        rpc_error(
                            ERR_REQUEST,
                            &format!("batch of {} calls: maximum {MAX_BATCH}", batch.len()),
                        ),
                    )
                    .build()
                    .encode();
            }
            let mut responses: Vec<Json> = Vec::with_capacity(batch.len());
            let mut bytes = 0usize;
            for r in batch {
                let resp = self.handle_one(r, client);
                bytes += resp.encode().len();
                if bytes > MAX_BATCH_RESPONSE {
                    responses.push(
                        Json::obj()
                            .set("jsonrpc", Json::str("2.0"))
                            .set("id", Json::Null)
                            .set(
                                "error",
                                rpc_error(ERR_REQUEST, "batch response too large: truncated"),
                            )
                            .build(),
                    );
                    break;
                }
                responses.push(resp);
            }
            return Json::array(responses).encode();
        }
        self.handle_one(&request, client).encode()
    }

    fn handle_one(&self, request: &Json, client: Option<std::net::IpAddr>) -> Json {
        let id = request.get("id").cloned().unwrap_or(Json::Null);
        let method = match request.get("method").and_then(|m| m.as_str()) {
            Some(m) => m.to_string(),
            None => {
                return Json::obj()
                    .set("jsonrpc", Json::str("2.0"))
                    .set("id", id)
                    .set("error", rpc_error(ERR_REQUEST, "missing 'method' field"))
                    .build()
            }
        };
        let params = request.get("params").cloned().unwrap_or(Json::Null);

        match self.dispatch(&method, &params, client) {
            Ok(r) => Json::obj()
                .set("jsonrpc", Json::str("2.0"))
                .set("id", id)
                .set("result", r)
                .build(),
            Err(e) => Json::obj()
                .set("jsonrpc", Json::str("2.0"))
                .set("id", id)
                .set("error", e)
                .build(),
        }
    }

    /// List of the exposed methods.
    pub fn methods() -> Vec<(&'static str, &'static str)> {
        vec![
            ("getinfo", "State of the chain, the network and the mempool"),
            ("getblock", "Full block, by height or by id"),
            ("getblockheader", "Header only"),
            (
                "gettransaction",
                "Transaction, in a block or in the mempool",
            ),
            ("getmempool", "Contents of the transaction mempool"),
            ("getpeers", "Connected peers"),
            ("getemission", "Emission curve at a given height"),
            ("getpow", "Parameters of the memory-hard proof of work"),
            ("getsecurity", "What is protected against a 51 % attack"),
            ("getsupply", "Money supply issued, and the cap"),
            (
                "getutxocommitment",
                "State commitment at the tip (MuHash of the UTXO set, bound to the total issued)",
            ),
            ("listmethods", "This list"),
            ("getbalance", "[wallet] Spendable balance"),
            ("getnewaddress", "[wallet] New receiving address"),
            ("sendtoaddress", "[wallet] Send funds"),
            (
                "sendmany",
                "[wallet] Send to several recipients in one transaction",
            ),
            (
                "getwalletinfo",
                "[wallet] Scheme, network, addresses, keys consumed",
            ),
            ("listaddresses", "[wallet] Addresses known to the wallet"),
            (
                "setaddresslabel",
                "[wallet] Names an address in the local address book",
            ),
            ("listtransactions", "[wallet] History of movements"),
            (
                "estimatefee",
                "[wallet] Suggested fee, for an assumed number of inputs",
            ),
            (
                "preparesend",
                "[wallet] Exact figures for a send, with the coins actually selected",
            ),
            (
                "getmining",
                "Mining status: active, measured rate, blocks found",
            ),
            (
                "getnetworkhashrate",
                "Mining effort of the network, measured from the difficulty of recent blocks",
            ),
            (
                "setmining",
                "[wallet] Turns mining on or off without restarting the program",
            ),
            (
                "setreachable",
                "[wallet] Makes this node reachable or not (takes effect at the next launch)",
            ),
            (
                "getsyncstatus",
                "Status of synchronization with the network",
            ),
            (
                "stop",
                "[wallet] Requests a clean shutdown of the node serving this page",
            ),
            (
                "search",
                "Guesses what it is given: height, block, transaction, address or amount",
            ),
            (
                "getaddress",
                "Movements and balance of an address, without it belonging to the wallet",
            ),
            (
                "getamount",
                "Transactions carrying an output of a given amount, over a bounded window",
            ),
        ]
    }

    fn dispatch(
        &self,
        method: &str,
        params: &Json,
        client: Option<std::net::IpAddr>,
    ) -> Result<Json, Json> {
        match method {
            "getinfo" => Ok(self.getinfo()),
            "getutxocommitment" => Ok(self.getutxocommitment()),
            "getblock" => self.getblock(params, true),
            "getblockheader" => self.getblock(params, false),
            "gettransaction" => self.gettransaction(params, client),
            "getmempool" => Ok(self.getmempool()),
            "getpeers" => Ok(self.getpeers()),
            "getemission" => self.getemission(params),
            "getpow" => Ok(self.getpow()),
            "getsecurity" => Ok(Self::getsecurity()),
            "getsupply" => Ok(self.getsupply()),
            "listmethods" => Ok(Json::array(
                Self::methods()
                    .into_iter()
                    .map(|(n, d)| {
                        Json::obj()
                            .set("name", Json::str(n))
                            .set("description", Json::str(d))
                            .build()
                    })
                    .collect(),
            )),
            "getbalance" => self.getbalance(),
            "getnewaddress" => self.getnewaddress(),
            "sendtoaddress" => self.sendtoaddress(params),
            "sendmany" => self.sendmany(params),
            "getwalletinfo" => self.getwalletinfo(),
            "listaddresses" => self.listaddresses(),
            "setaddresslabel" => self.setaddresslabel(params),
            "listtransactions" => self.listtransactions(params),
            "estimatefee" => self.estimatefee(params),
            "preparesend" => self.preparesend(params),
            "getsyncstatus" => Ok(self.getsyncstatus()),
            "getmining" => Ok(self.getmining()),
            "getnetworkhashrate" => Ok(self.getnetworkhashrate()),
            "setmining" => self.setmining(params),
            "setreachable" => self.setreachable(params),
            "stop" => self.stop(),
            "search" => self.search(params, client),
            "getaddress" => self.getaddress(params, client),
            "getamount" => self.getamount(params, client),
            other => Err(rpc_error(
                ERR_METHOD,
                &format!("unknown method: {other}. Try listmethods."),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    fn getinfo(&self) -> Json {
        use std::sync::atomic::Ordering;
        let (height, tip, work, known, issued, utxo, bits) = self.node.with_chain(|c| {
            (
                c.height(),
                c.tip_id().to_hex(),
                c.total_work().bits(),
                c.known_blocks(),
                c.total_issued(),
                c.utxo.len(),
                c.tip().bits,
            )
        });
        let s = &self.node.stats;

        Json::obj()
            // The version of the program that answers. Same reason as the two
            // constants further down: a page that hard-coded it would lie at
            // the very next release. And without it, whoever holds a binary six
            // months later has no way of knowing what they are running - the
            // trusted comment of the signature carries the version, but it is
            // attached to the checksum file, not to the program.
            .set("version", Json::str(env!("CARGO_PKG_VERSION")))
            .set(
                "configured_bootstrap",
                Json::u64(self.configured_bootstrap as u64),
            )
            .set("network", Json::str(format!("{:?}", self.network)))
            .set("height", Json::u64(height))
            .set("tip", Json::str(tip))
            .set("cumulative_work_bits", Json::u64(work as u64))
            .set("known_blocks", Json::u64(known as u64))
            .set("difficulty_bits", Json::str(format!("{bits:#010x}")))
            .set("issued", amount_json(issued))
            .set("utxo_total", Json::u64(utxo as u64))
            .set("peers", Json::u64(self.node.peer_count() as u64))
            .set("mempool", Json::u64(self.node.mempool_len() as u64))
            .set("wallet_enabled", Json::Bool(self.wallet.is_some()))
            // --- Reachability: the setting, and the real state of the port
            //     opening.
            //
            // We never claim "reachable" - we cannot prove it from here. We
            // return the wanted setting, and what the router answered as a
            // short code: `open NAT-PMP`, `open UPnP`, `failed`, or empty when
            // nothing was asked. Never the public address.
            .set(
                "reachable",
                Json::Bool(self.reachable.load(std::sync::atomic::Ordering::SeqCst)),
            )
            .set("reachable_session", Json::Bool(self.reachable_session))
            .set(
                "port_mapping",
                match &self.router_status {
                    Some(e) => Json::str(e.lock().map(|s| s.clone()).unwrap_or_default()),
                    None => Json::str(String::new()),
                },
            )
            // --- Two protocol constants, returned with the state.
            //
            // An interface that wants to announce *when* a reward will be
            // available needs both: how many blocks to wait, and how long a
            // block lasts. Copying them into the page would freeze them by
            // hand, and so lie the day they changed. The node is the only
            // source entitled to state them.
            .set("coinbase_maturity", Json::u64(COINBASE_MATURITY))
            .set("target_interval_seconds", Json::u64(TARGET_BLOCK_SECS))
            .set(
                "network_stats",
                Json::obj()
                    .set(
                        "blocks_received",
                        Json::u64(s.blocks_received.load(Ordering::Relaxed)),
                    )
                    .set(
                        "blocks_accepted",
                        Json::u64(s.blocks_accepted.load(Ordering::Relaxed)),
                    )
                    .set(
                        "compacts_received",
                        Json::u64(s.compacts_received.load(Ordering::Relaxed)),
                    )
                    .set(
                        "compacts_without_round_trip",
                        Json::u64(s.compacts_without_round_trip.load(Ordering::Relaxed)),
                    )
                    .set(
                        "txs_received",
                        Json::u64(s.txs_received.load(Ordering::Relaxed)),
                    )
                    .set(
                        "peers_banned",
                        Json::u64(s.peers_banned.load(Ordering::Relaxed)),
                    )
                    .build(),
            )
            .build()
    }

    /// Commitment on the state of the currency at the tip: the **state
    /// commitment** (the one you copy to adopt a snapshot - MuHash and total
    /// issued bound together, see [`q21_core::state::state_commitment`]), the
    /// MuHash alone, the number of outputs and the total in circulation.
    ///
    /// This is a call made on demand, when you want to compare two nodes or
    /// check a snapshot, not a value refreshed in a loop. `getinfo` therefore
    /// stays light.
    fn getutxocommitment(&self) -> Json {
        let (height, tip, entries, issued, commitment, muhash) = self.node.with_chain(|c| {
            (
                c.height(),
                c.tip_id().to_hex(),
                c.utxo_count(),
                c.total_issued(),
                c.state_commitment().to_hex(),
                c.utxo_commitment().to_hex(),
            )
        });
        Json::obj()
            .set("height", Json::u64(height))
            .set("tip", Json::str(tip))
            .set("inputs", Json::u64(entries as u64))
            .set("total", amount_json(issued))
            .set("commitment", Json::str(commitment))
            .set("muhash", Json::str(muhash))
            .build()
    }

    fn getblock(&self, params: &Json, full: bool) -> Result<Json, Json> {
        let block = self.node.with_chain(|c| {
            if let Some(h) = params.get("height").and_then(|v| v.as_u64()) {
                return c.block_at(h);
            }
            if let Some(id) = params.get("id").and_then(|v| v.as_str()) {
                if let Some(h) = Hash256::from_hex(id) {
                    return c.block_by_id(&h);
                }
            }
            // Without a parameter: the tip block.
            c.block_at(c.height())
        });

        match block {
            Some(b) if full => Ok(block_json(&b, self.network)),
            Some(b) => Ok(header_json(&b.header)),
            None => Err(rpc_error(ERR_NOT_FOUND, "block not found")),
        }
    }

    fn gettransaction(
        &self,
        params: &Json,
        client: Option<std::net::IpAddr>,
    ) -> Result<Json, Json> {
        let txid = params
            .get("txid")
            .and_then(|v| v.as_str())
            .and_then(Hash256::from_hex)
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'txid' expected, in hexadecimal"))?;

        // The mempool first: that is where someone who has just sent looks.
        if let Some(t) = self.node.with_mempool(|m| m.get(&txid).cloned()) {
            return Ok(Json::obj()
                .set("confirmed", Json::Bool(false))
                .set("transaction", tx_json(&t, self.network))
                .set_all(self.fee_fields(&t))
                .build());
        }

        // The index, if there is one: a table read rather than a scan.
        if let Some((height, rank)) = self.locate_transaction(&txid) {
            let found = self.node.with_chain(|c| {
                let b = c.block_at(height)?;
                let t = b.transactions.get(rank as usize)?.clone();
                Some((t, b.header.block_id()))
            });
            if let Some((t, block)) = found {
                return Ok(Json::obj()
                    .set("confirmed", Json::Bool(true))
                    .set("height", Json::u64(height))
                    .set("block", Json::str(block.to_hex()))
                    .set("transaction", tx_json(&t, self.network))
                    .set_all(self.fee_fields(&t))
                    .build());
            }
        }

        // Otherwise, in the chain. Backward scan: a transaction being looked
        // up is almost always recent. Without an index, we stay honest about
        // the cost - and about the bound.
        self.allow_scan(client)?;
        let mut bottom_reached = false;
        let found = self.node.with_chain(|c| {
            let mut h = c.height() as i64;
            let floor = (c.height().saturating_sub(MAX_SCANNED_BLOCKS)) as i64;
            while h >= 0 {
                if h < floor {
                    bottom_reached = true;
                    return None;
                }
                if let Some(b) = c.block_at(h as u64) {
                    if let Some(t) = b.transactions.iter().find(|t| t.txid() == txid) {
                        return Some((t.clone(), b.header.height, b.header.block_id()));
                    }
                }
                h -= 1;
            }
            None
        });

        if found.is_none() && bottom_reached {
            return Err(rpc_error(
                ERR_REQUEST,
                &format!(
                    "transaction not found in the last {MAX_SCANNED_BLOCKS} \
                     blocks. This node has no index by identifier: beyond that, \
                     the search is not carried out."
                ),
            ));
        }

        match found {
            Some((t, height, block)) => Ok(Json::obj()
                .set("confirmed", Json::Bool(true))
                .set("height", Json::u64(height))
                .set("block", Json::str(block.to_hex()))
                .set("transaction", tx_json(&t, self.network))
                .set_all(self.fee_fields(&t))
                .build()),
            None => Err(rpc_error(ERR_NOT_FOUND, "transaction not found")),
        }
    }

    fn getmempool(&self) -> Json {
        let (n, bytes, ids) = self.node.with_mempool(|m| (m.len(), m.bytes(), m.txids()));
        Json::obj()
            .set("tx_count", Json::u64(n as u64))
            .set("bytes", Json::u64(bytes as u64))
            .set(
                "txids",
                Json::array(
                    ids.iter()
                        .take(200)
                        .map(|h| Json::str(h.to_hex()))
                        .collect(),
                ),
            )
            .build()
    }

    fn getpeers(&self) -> Json {
        Json::obj()
            .set("peer_count", Json::u64(self.node.peer_count() as u64))
            .set("maximum", Json::u64(crate::net::MAX_PEERS as u64))
            .build()
    }

    fn getemission(&self, params: &Json) -> Result<Json, Json> {
        let height = match params.get("height").and_then(|v| v.as_u64()) {
            Some(h) => h,
            None => self.node.with_chain(|c| c.height()),
        };
        let cumulative = emission::total_supply_at(height);
        Ok(Json::obj()
            .set("height", Json::u64(height))
            .set("approx_year", Json::u64(height / BLOCKS_PER_YEAR))
            .set("subsidy", amount_json(emission::block_subsidy(height)))
            .set("cumulative_issued", amount_json(cumulative))
            .set("cap", amount_json(Amount::from_units(MAX_SUPPLY)))
            .set(
                "permille_of_cap",
                Json::u64(cumulative.units().saturating_mul(100_000) / MAX_SUPPLY),
            )
            .build())
    }

    fn getpow(&self) -> Json {
        let params = self.node.with_chain(|c| c.pow_params());
        let height = self.node.with_chain(|c| c.height());
        let epoch = memhard::epoch_of(height);
        let n = memhard::table_size(params, epoch);
        let c = memhard::cache_size(params, epoch);
        Json::obj()
            .set(
                "algorithm",
                Json::str("Q21 two-level memory-hard, growing table"),
            )
            .set("epoch", Json::u64(epoch))
            .set("table_elements", Json::u64(n as u64))
            .set("cache_elements", Json::u64(c as u64))
            .set(
                "miner_memory_bytes",
                Json::u64(n as u64 * POW_ELEMENT_SIZE as u64),
            )
            .set(
                "node_memory_bytes",
                Json::u64(c as u64 * POW_ELEMENT_SIZE as u64),
            )
            .set("accesses_per_attempt", Json::u64(POW_K as u64))
            .set("cache_accesses_per_element", Json::u64(POW_J as u64))
            .set("growth_percent", Json::u64(POW_TABLE_GROWTH_PCT))
            .set("blocks_per_epoch", Json::u64(POW_EPOCH_BLOCKS))
            .set(
                "note",
                Json::str(
                    "A node holds the cache (level 1), not the table (level 2). \
                     That is the price of the phase 6 fix: without it, doing \
                     without memory only cost 2.86 x.",
                ),
            )
            .build()
    }

    fn getsupply(&self) -> Json {
        let (issued, utxo) = self
            .node
            .with_chain(|c| (c.total_issued(), c.utxo.total_value()));
        Json::obj()
            .set("issued", amount_json(issued))
            .set("in_utxo_set", amount_json(utxo))
            .set("cap", amount_json(Amount::from_units(MAX_SUPPLY)))
            .set("cap_q21", Json::u64(MAX_SUPPLY_COINS))
            .set("under_cap", Json::Bool(issued.units() <= MAX_SUPPLY))
            .build()
    }

    /// Exposes the project's position on the 51 % attack, as data.
    ///
    /// An API that only says what is reassuring lies by omission.
    fn getsecurity() -> Json {
        Json::obj()
            .set("full_protection_possible", Json::Bool(false))
            .set(
                "reason",
                Json::str(
                    "Consensus defines the valid chain as the one carrying the most \
                     work. A majority produces more of it than everyone else, by \
                     definition. Refusing its chain would require knowing that it is \
                     them: an identity, hence an authority, hence the end of \
                     permissionlessness. This is a theorem, not an implementation gap.",
                ),
            )
            .set(
                "an_attacker_can",
                Json::array(vec![
                    Json::str("reorganize recent blocks, and so undo its own payments"),
                    Json::str("refuse to include certain transactions"),
                ]),
            )
            .set(
                "an_attacker_cannot",
                Json::array(vec![
                    Json::str("steal a coin it holds no key for"),
                    Json::str("create a single unit beyond the subsidy"),
                    Json::str("raise the cap of 21,000,001"),
                    Json::str("change a rule: its blocks are simply rejected"),
                ]),
            )
            .set(
                "defenses",
                Json::obj()
                    .set("choice_by_cumulative_work", Json::Bool(true))
                    .set("rolling_finality_blocks", Json::u64(MAX_REORG_DEPTH))
                    .set(
                        "rolling_finality_hours",
                        Json::u64(MAX_REORG_DEPTH * TARGET_BLOCK_SECS / 3600),
                    )
                    .set("penalty_from_blocks", Json::u64(REORG_PENALTY_FROM_DEPTH))
                    .set(
                        "penalty_percent_per_block",
                        Json::u64(REORG_PENALTY_PCT_PER_BLOCK),
                    )
                    .set("penalty_cap_percent", Json::u64(REORG_PENALTY_MAX_PCT))
                    .set("uncle_rewards", Json::Bool(false))
                    .set("pow_memory_hard", Json::Bool(true))
                    .build(),
            )
            .set(
                "rolling_finality_cost",
                Json::str(
                    "It does not remove the attack, it changes its nature. A \
                     prolonged network partition produces two chains that will not \
                     reconcile on their own. A silent rewrite is traded for a \
                     visible split.",
                ),
            )
            .build()
    }

    // -----------------------------------------------------------------------
    // Wallet
    // -----------------------------------------------------------------------

    /// Writes the wallet to disk after a modification.
    ///
    /// Silent if no callback is supplied - the case of in-memory tests. In
    /// production the lack of a callback would be a defect, and the launcher
    /// always supplies one.
    /// Saves the wallet after a modification.
    ///
    /// A failure is returned to the caller; modifications that put no key at
    /// stake (a label, a new address) can make do with reporting it, a spend
    /// must stop on it.
    fn save_wallet(&self, w: &Wallet) -> Result<(), String> {
        match &self.on_change {
            Some(f) => f(w),
            None => Ok(()),
        }
    }

    fn require_wallet(&self) -> Result<&Arc<Mutex<Wallet>>, Json> {
        self.wallet.as_ref().ok_or_else(|| {
            rpc_error(
                ERR_WALLET_DISABLED,
                "wallet methods disabled. They can move funds and must be \
                 requested explicitly at startup.",
            )
        })
    }

    /// Requests a clean shutdown of the node serving this page.
    ///
    /// # The defect this method fixes
    ///
    /// The only way to stop the wallet was Ctrl-C in the black window. On
    /// Windows, a Ctrl-C received during a `.bat` file makes the interpreter
    /// ask its own question - "Terminate batch job (Y/N)?" - to which both
    /// answers close the window. The first user read that as a crash. It was
    /// not one: the write had already happened. But you cannot ask someone to
    /// trust a message that looks like an error.
    ///
    /// An application is closed with a button. This one raises the same flag
    /// as Ctrl-C, the main loop sees it on the next turn, writes what it has
    /// to write and returns: the interpreter then has no question to ask,
    /// since nothing was interrupted.
    ///
    /// # Why it is reserved for wallet mode
    ///
    /// A public node exposes read methods to whoever asks for them. "Stop" is
    /// not one of them. It therefore goes through the same check as the
    /// methods that move funds: the token, and wallet mode requested explicitly
    /// at startup.
    fn stop(&self) -> Result<Json, Json> {
        self.require_wallet()?;
        crate::shutdown::request_shutdown();
        Ok(Json::obj()
            .set("shutdown", Json::Bool(true))
            .set(
                "note",
                Json::str(
                    "shutdown requested: the node writes its state and then exits, \
                     usually in less than a second",
                ),
            )
            .build())
    }

    // -----------------------------------------------------------------------
    // Exploration
    // -----------------------------------------------------------------------

    /// Where this transaction is, without scanning if the index is there.
    fn locate_transaction(&self, txid: &Hash256) -> Option<(u64, u32)> {
        if let Some(index) = &self.index {
            if let Ok(i) = index.lock() {
                if let Some(p) = i.position(txid) {
                    return Some((p.height, p.rank));
                }
            }
        }
        None
    }

    /// Finds an output designated by an outpoint.
    ///
    /// Used to say what a transaction **spent**: an input only carries the
    /// reference of the output it consumes, not its amount or its owner.
    /// Without an index, we do not search: an answer that costs a full scan per
    /// input is not an answer, and the page then simply says it does not know.
    fn resolve_output(&self, outpoint: &crate::tx::OutPoint) -> Option<crate::tx::TxOut> {
        let (height, rank) = self.locate_transaction(&outpoint.txid)?;
        self.node.with_chain(|c| {
            let b = c.block_at(height)?;
            let t = b.transactions.get(rank as usize)?;
            t.outputs.get(outpoint.index as usize).cloned()
        })
    }

    /// The amount of each input, the incoming sum, and whether everything is
    /// resolved.
    ///
    /// An input only carries the reference of the output it consumes, not its
    /// amount. We find it through the index - a table read, not a scan. If a
    /// single input escapes the index (no index, or a coin too old for it),
    /// `known` becomes `false`: the fee is not computed on a partial sum, and
    /// the page will say so rather than deliver a wrong figure.
    ///
    /// Returns `(inputs, amount_in, known)`: `inputs` is aligned with the
    /// transaction's inputs, each element carrying `value` when it is known.
    fn resolve_inputs(&self, t: &Transaction) -> (Vec<Json>, u64, bool) {
        let mut inputs = Vec::with_capacity(t.inputs.len());
        let mut amount_in = 0u64;
        let mut known = true;
        for e in &t.inputs {
            if e.prev_out.is_coinbase() {
                inputs.push(Json::obj().set("known", Json::Bool(true)).build());
                continue;
            }
            match self.resolve_output(&e.prev_out) {
                Some(o) => {
                    amount_in = amount_in.saturating_add(o.value.units());
                    inputs.push(
                        Json::obj()
                            .set("value", amount_json(o.value))
                            .set("known", Json::Bool(true))
                            .build(),
                    );
                }
                None => {
                    known = false;
                    inputs.push(Json::obj().set("known", Json::Bool(false)).build());
                }
            }
        }
        (inputs, amount_in, known)
    }

    /// Enriches a confirmed transaction response with the input amounts and
    /// the fee, when they are resolved.
    ///
    /// The fee of a coinbase makes no sense - it *collects* the block's fees,
    /// it pays none - so we do not show it for one.
    fn fee_fields(&self, t: &Transaction) -> Vec<(&'static str, Json)> {
        let (inputs, amount_in, known) = self.resolve_inputs(t);
        let coinbase = t.is_coinbase();
        let amount_out: u64 = t.outputs.iter().map(|o| o.value.units()).sum();
        let fee_known = known && !coinbase;
        vec![
            ("input_amounts", Json::array(inputs)),
            ("fee_known", Json::Bool(fee_known)),
            (
                "amount_in",
                if fee_known {
                    amount_json(Amount::from_units(amount_in))
                } else {
                    Json::Null
                },
            ),
            (
                "fee",
                if fee_known {
                    amount_json(Amount::from_units(amount_in.saturating_sub(amount_out)))
                } else {
                    Json::Null
                },
            ),
        ]
    }

    /// Guesses what it is given, and says where to go.
    ///
    /// An explorer has only one input field. It is up to it to recognize a
    /// height, a block id, a transaction id or an address - not up to the user
    /// to pick from a menu what they already hold in the clipboard.
    fn search(&self, params: &Json, client: Option<std::net::IpAddr>) -> Result<Json, Json> {
        let raw = params
            .get("q")
            .and_then(|v| v.as_str())
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'q' expected"))?
            .trim()
            .to_string();
        if raw.is_empty() {
            return Err(rpc_error(ERR_PARAMS, "empty search"));
        }
        // Too long to be anything at all: refuse before doing any work.
        if raw.len() > 200 {
            return Err(rpc_error(ERR_PARAMS, "search too long"));
        }
        // What people paste is rarely what the node prints. The wallet shows
        // an address in groups of eight: selected by hand, it arrives with
        // spaces or line breaks. An identifier copied from a list ends with
        // "…". Neither an address, nor an identifier, nor an amount ever
        // contains a space: removing them all loses nothing, and the 0.4.1
        // audit showed that refusing them made the search look broken.
        let q = compact_search(&raw);
        if q.is_empty() {
            return Err(rpc_error(ERR_PARAMS, "empty search"));
        }

        let found = |kind: &str, value: String| {
            Ok(Json::obj()
                .set("kind", Json::str(kind))
                .set("value", Json::str(&value))
                .build())
        };

        // A string of digits: a height.
        if q.chars().all(|c| c.is_ascii_digit()) {
            let h: u64 = q
                .parse()
                .map_err(|_| rpc_error(ERR_PARAMS, "unreadable height"))?;
            let exists = self.node.with_chain(|c| h <= c.height());
            if !exists {
                return Err(rpc_error(
                    ERR_NOT_FOUND,
                    &format!(
                        "no block at height {h}: the chain stops lower. \
                         For an amount, write {h}.0"
                    ),
                ));
            }
            return found("block", h.to_string());
        }

        // An amount: a decimal point or a decimal comma, or the unit written
        // after it. A height is an integer - the separator is enough to remove
        // the ambiguity, with no menu to choose from.
        if let Some(text) = amount_candidate(&q) {
            let units = amount_to_units(&text)
                .ok_or_else(|| rpc_error(ERR_PARAMS, "unreadable amount: at most 8 decimals"))?;
            // Canonical form in Q21: readable in the URL, and parseable again
            // as is by `getamount`.
            return found("amount", Amount::from_units(units).to_string());
        }

        // An address: it carries its own checksum, so a typo is detected
        // instead of leading somewhere else.
        if let Ok(a) = crate::address::Address::parse(&q) {
            if a.network != self.network {
                return Err(rpc_error(
                    ERR_PARAMS,
                    &format!(
                        "this address belongs to the {:?} network, this node follows {:?}",
                        a.network, self.network
                    ),
                ));
            }
            // Lowercase, as the node writes it: the same address must give the
            // same page, whatever case it was pasted in.
            return found("address", a.to_string_bech32());
        }
        let lower = q.to_ascii_lowercase();
        if [
            crate::consensus::HRP_MAINNET,
            crate::consensus::HRP_TESTNET,
            crate::consensus::HRP_REGTEST,
        ]
        .iter()
        .any(|hrp| lower.starts_with(&format!("{hrp}1")))
        {
            // Said instead of the generic refusal: the checksum is there
            // precisely to catch this, and the reader must know it did.
            return Err(rpc_error(
                ERR_PARAMS,
                "this looks like an address, but it does not check out: a character \
                 is wrong, missing or extra. Copy it again with the copy button",
            ));
        }

        // Sixty-four hexadecimal characters: a block or a transaction. Blocks
        // are checked first, since their table is immediate.
        if let Some(h) = Hash256::from_hex(&lower) {
            if self.node.with_chain(|c| c.block_by_id(&h).is_some()) {
                return found("block-id", h.to_hex());
            }
            if self.node.with_mempool(|m| m.get(&h).is_some()) {
                return found("transaction", h.to_hex());
            }
            if self.locate_transaction(&h).is_some() {
                return found("transaction", h.to_hex());
            }
            // Without an index, we cannot conclude it is absent: we still send
            // the user to the transaction page, which will scan and say what it
            // was able to see.
            if self.index.is_none() {
                return found("transaction", h.to_hex());
            }
            return Err(rpc_error(
                ERR_NOT_FOUND,
                "neither a block nor a transaction known to this node",
            ));
        }

        // The beginning of an identifier: lists show sixteen characters and an
        // ellipsis, and that is what gets copied. Eight characters at least -
        // below that, too many identifiers would share them.
        if (MIN_ID_PREFIX..64).contains(&lower.len())
            && lower.chars().all(|c| c.is_ascii_hexdigit())
        {
            return match self.complete_identifier(&lower, client)? {
                Some((kind, id)) => found(kind, id.to_hex()),
                None => Err(rpc_error(
                    ERR_NOT_FOUND,
                    &format!(
                        "incomplete identifier: {} characters out of 64, and no block or \
                         recent transaction starts with them. Copy the full identifier",
                        lower.len()
                    ),
                )),
            };
        }

        Err(rpc_error(
            ERR_PARAMS,
            "not recognized: type a height, an amount (1.5 or 1,5), an address, \
             or a block or transaction identifier",
        ))
    }

    /// The only block or transaction whose identifier starts with `prefix`.
    ///
    /// Looks in the mempool, the active chain's block identifiers, and the
    /// transactions of the index - or, without one, those of the last
    /// [`MAX_SCANNED_BLOCKS`] blocks. Two different matches are an error: the
    /// page must never open the wrong transaction on a guess.
    fn complete_identifier(
        &self,
        prefix: &str,
        client: Option<std::net::IpAddr>,
    ) -> Result<Option<(&'static str, Hash256)>, Json> {
        let mut hits: Vec<(&'static str, Hash256)> = Vec::new();
        let starts = |h: &Hash256| hex_starts_with(h, prefix);
        for t in self.node.with_mempool(|m| m.txids()) {
            if starts(&t) {
                hits.push(("transaction", t));
            }
        }
        self.allow_scan(client)?;
        self.node.with_chain(|c| {
            for h in 0..=c.height() {
                if let Some(id) = c.active_at(h) {
                    if starts(&id) {
                        hits.push(("block-id", id));
                    }
                }
            }
        });
        match &self.index {
            Some(index) => {
                let i = index
                    .lock()
                    .map_err(|_| rpc_error(ERR_REQUEST, "index unavailable"))?;
                for t in i.find_txids(starts, 3) {
                    hits.push(("transaction", t));
                }
            }
            None => self.node.with_chain(|c| {
                let floor = c.height().saturating_sub(MAX_SCANNED_BLOCKS);
                for h in floor..=c.height() {
                    if let Some(b) = c.block_at(h) {
                        for t in &b.transactions {
                            let id = t.txid();
                            if starts(&id) {
                                hits.push(("transaction", id));
                            }
                        }
                    }
                }
            }),
        }
        hits.sort_by_key(|(_, h)| h.0);
        hits.dedup_by_key(|(_, h)| h.0);
        match hits.len() {
            0 => Ok(None),
            1 => Ok(Some(hits[0])),
            n => Err(rpc_error(
                ERR_PARAMS,
                &format!(
                    "ambiguous: {n} identifiers start with these characters. Paste more of them"
                ),
            )),
        }
    }

    /// Movements and balance of any address at all.
    ///
    /// "Any" is the important word: this method does not require the address
    /// to belong to the wallet. That is what distinguishes an explorer from a
    /// wallet.
    ///
    /// It always says **how** it answered - through the index or through a
    /// bounded scan - and how far back it searched. An incomplete answer that
    /// presented itself as complete would be worse than no answer: it would
    /// lead people to wrongly conclude that an address is empty.
    fn getaddress(&self, params: &Json, client: Option<std::net::IpAddr>) -> Result<Json, Json> {
        let raw = params
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'address' expected"))?;
        let address = crate::address::Address::parse(raw)
            .map_err(|e| rpc_error(ERR_PARAMS, &format!("unreadable address: {e:?}")))?;
        if address.network != self.network {
            return Err(rpc_error(
                ERR_PARAMS,
                &format!(
                    "this address belongs to the {:?} network, this node follows {:?}",
                    address.network, self.network
                ),
            ));
        }
        let key_hash = address.hash;
        let maximum = params
            .get("max")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .clamp(1, 200) as usize;

        let height = self.node.with_chain(|c| c.height());

        // --- Where this address appears.
        let (mut positions, via_index, floor) = match &self.index {
            Some(index) => {
                let i = index
                    .lock()
                    .map_err(|_| rpc_error(ERR_REQUEST, "index unavailable"))?;
                let v: Vec<(u64, u32)> = i
                    .positions(&key_hash)
                    .iter()
                    .map(|p| (p.height, p.rank))
                    .collect();
                (v, true, 0u64)
            }
            None => {
                // Bounded backward scan. The response will say so.
                self.allow_scan(client)?;
                let floor = height.saturating_sub(MAX_SCANNED_BLOCKS);
                let v = self.node.with_chain(|c| {
                    let mut v: Vec<(u64, u32)> = Vec::new();
                    for h in floor..=height {
                        if let Some(b) = c.block_at(h) {
                            for (rank, t) in b.transactions.iter().enumerate() {
                                if t.outputs.iter().any(|o| o.pubkey_hash == key_hash) {
                                    v.push((h, rank as u32));
                                }
                            }
                        }
                    }
                    v
                });
                (v, false, floor)
            }
        };
        positions.sort_unstable();
        positions.dedup();

        // --- What waits in the mempool. Someone who has just paid this address
        // looks it up at once; until 0.4.2 it showed nothing for the two
        // minutes a block takes, and the payment looked lost. Mempool lock
        // first, chain lock second: the order `listtransactions` uses.
        let pending_txs: Vec<Transaction> = self.node.with_mempool(|m| {
            m.txids()
                .iter()
                .filter_map(|id| m.get(id).cloned())
                .collect()
        });
        let now = now_utc();
        let pending: Vec<Json> = self.node.with_chain(|c| {
            pending_txs
                .iter()
                .filter_map(|tx| {
                    let received: u64 = tx
                        .outputs
                        .iter()
                        .filter(|o| o.pubkey_hash == key_hash)
                        .map(|o| o.value.units())
                        .sum();
                    // A coin spent by a mempool transaction is still in the
                    // UTXO set: only a block removes it.
                    let sent: u64 = tx
                        .inputs
                        .iter()
                        .filter_map(|i| c.utxo.get(&i.prev_out))
                        .filter(|e| e.output.pubkey_hash == key_hash)
                        .map(|e| e.output.value.units())
                        .sum();
                    if received == 0 && sent == 0 {
                        return None;
                    }
                    Some(
                        Json::obj()
                            .set("txid", Json::str(tx.txid().to_hex()))
                            .set("height", Json::Null)
                            .set("timestamp", Json::u64(now))
                            .set("confirmations", Json::u64(0))
                            .set("pending", Json::Bool(true))
                            .set("coinbase", Json::Bool(false))
                            .set("received", amount_json(Amount::from_units(received)))
                            .set("sent", amount_json(Amount::from_units(sent)))
                            .set("amount_out_known", Json::Bool(true))
                            .build(),
                    )
                })
                .collect()
        });
        let total_movements = positions.len() + pending.len();
        // Most recent first: that is what you want to see first.
        positions.reverse();
        positions.truncate(maximum);

        // --- The detail of each movement, the pending ones first.
        let mut movements = pending;
        let mut all_out_resolved = true;
        for (h, rank) in positions {
            let Some(block) = self.node.with_chain(|c| c.block_at(h)) else {
                continue;
            };
            let Some(tx) = block.transactions.get(rank as usize).cloned() else {
                continue;
            };
            let received: u64 = tx
                .outputs
                .iter()
                .filter(|o| o.pubkey_hash == key_hash)
                .map(|o| o.value.units())
                .sum();
            let mut sent: u64 = 0;
            let mut known = true;
            for input in &tx.inputs {
                if input.prev_out.is_coinbase() {
                    continue;
                }
                match self.resolve_output(&input.prev_out) {
                    Some(o) if o.pubkey_hash == key_hash => sent += o.value.units(),
                    Some(_) => {}
                    None => known = false,
                }
            }
            if !known {
                all_out_resolved = false;
            }
            movements.push(
                Json::obj()
                    .set("txid", Json::str(tx.txid().to_hex()))
                    .set("height", Json::u64(h))
                    .set("timestamp", Json::u64(block.header.time))
                    .set("confirmations", Json::u64(height.saturating_sub(h) + 1))
                    .set("coinbase", Json::Bool(tx.is_coinbase()))
                    .set("received", amount_json(Amount::from_units(received)))
                    .set("sent", amount_json(Amount::from_units(sent)))
                    .set("amount_out_known", Json::Bool(known))
                    .build(),
            );
        }

        // --- The balance: what the UTXO set holds for this key hash.
        //
        // It depends neither on the index nor on the scan: it is the state this
        // node validated itself, and it is therefore always exact, even when
        // the history shown is bounded.
        // Through the key hash index, never through a scan: this request is
        // public and unauthenticated, and the lock it takes is the consensus
        // lock. See `UtxoSet::balance_of`.
        let (balance, outputs) = self.node.with_chain(|c| c.utxo.balance_of(&key_hash));

        Ok(Json::obj()
            .set("address", Json::str(raw))
            .set("key_hash", Json::str(key_hash.to_hex()))
            .set("balance", amount_json(Amount::from_units(balance)))
            .set("unspent_outputs", Json::u64(outputs))
            .set("movements", Json::array(movements))
            .set("total_movements", Json::u64(total_movements as u64))
            .set("via_index", Json::Bool(via_index))
            .set("amounts_out_all_resolved", Json::Bool(all_out_resolved))
            .set("complete_history", Json::Bool(via_index || floor == 0))
            .set("floor", Json::u64(floor))
            .set("height", Json::u64(height))
            .set(
                "note",
                Json::str(if via_index {
                    "Full history: the address index covers the whole chain."
                } else {
                    "Bounded history: this node runs without an address index. Sends \
                     are not resolved, and the search stops at the floor shown. \
                     Restart it with --address-index for a complete answer."
                }),
            )
            .build())
    }

    /// Transactions carrying an output of exactly this amount.
    ///
    /// # The trade-off, accepted
    ///
    /// There is no index by amount: building one would double the size of the
    /// index for a rare search, in which a common sum - `1.00000000` - returns
    /// thousands of results. So we scan backward over a **bounded window**,
    /// exactly like `gettransaction` without an index: the request costs at
    /// most [`MAX_SCANNED_BLOCKS`] reads, never the whole chain, and the
    /// response **says how far back** it searched. It is the same honest "here
    /// is what I was able to see" as elsewhere, rather than a promise that the
    /// cost would contradict as the chain grows.
    ///
    /// The results are capped: nobody reads a thousand lines, and a cap
    /// protects the service as much as the reader.
    fn getamount(&self, params: &Json, client: Option<std::net::IpAddr>) -> Result<Json, Json> {
        const MAX_RESULTS: usize = 100;
        let units = params
            .get("units")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                params
                    .get("amount")
                    .and_then(|v| v.as_str())
                    .and_then(amount_to_units)
            })
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'units' or 'amount' expected"))?;

        self.allow_scan(client)?;
        // The mempool first: an amount just sent is the one looked for.
        let pending: Vec<Json> = self.node.with_mempool(|m| {
            let mut v = Vec::new();
            for id in m.txids() {
                let Some(tx) = m.get(&id) else { continue };
                for (i, o) in tx.outputs.iter().enumerate() {
                    if o.value.units() == units {
                        v.push(
                            Json::obj()
                                .set("txid", Json::str(id.to_hex()))
                                .set("height", Json::Null)
                                .set("pending", Json::Bool(true))
                                .set("index", Json::u64(i as u64))
                                .set(
                                    "address",
                                    Json::str(
                                        crate::address::Address {
                                            network: self.network,
                                            scheme: o.scheme,
                                            hash: o.pubkey_hash,
                                        }
                                        .to_string_bech32(),
                                    ),
                                )
                                .set("value", amount_json(o.value))
                                .build(),
                        );
                    }
                }
            }
            v.truncate(MAX_RESULTS);
            v
        });
        let (results, height, since, capped) = self.node.with_chain(|c| {
            let height = c.height();
            let since = height.saturating_sub(MAX_SCANNED_BLOCKS);
            let mut out: Vec<Json> = pending;
            let mut capped = false;
            let mut h = height as i64;
            'blocks: while h >= since as i64 {
                if let Some(b) = c.block_at(h as u64) {
                    for tx in &b.transactions {
                        let txid = tx.txid();
                        for (i, o) in tx.outputs.iter().enumerate() {
                            if o.value.units() != units {
                                continue;
                            }
                            if out.len() >= MAX_RESULTS {
                                capped = true;
                                break 'blocks;
                            }
                            out.push(
                                Json::obj()
                                    .set("txid", Json::str(txid.to_hex()))
                                    .set("height", Json::u64(h as u64))
                                    .set("index", Json::u64(i as u64))
                                    .set(
                                        "address",
                                        Json::str(
                                            crate::address::Address {
                                                network: self.network,
                                                scheme: o.scheme,
                                                hash: o.pubkey_hash,
                                            }
                                            .to_string_bech32(),
                                        ),
                                    )
                                    .set("value", amount_json(o.value))
                                    .build(),
                            );
                        }
                    }
                }
                h -= 1;
            }
            (out, height, since, capped)
        });

        Ok(Json::obj()
            .set("amount", amount_json(Amount::from_units(units)))
            .set("results", Json::array(results))
            .set("height", Json::u64(height))
            .set("since", Json::u64(since))
            .set("window", Json::u64(MAX_SCANNED_BLOCKS))
            .set("capped", Json::Bool(capped))
            .build())
    }

    // -----------------------------------------------------------------------
    // Wallet: what a desktop application must be able to ask for
    // -----------------------------------------------------------------------

    /// Wallet status, without revealing anything secret.
    ///
    /// Everything an owner needs to see when opening their application: which
    /// signature scheme, which network, how many addresses handed out, how many
    /// one-time keys already burned.
    fn getwalletinfo(&self) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        let g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
        let scheme = g.scheme();
        let consumed = g.consumed_indices().len() as u64;
        Ok(Json::obj()
            .set("network", Json::str(format!("{:?}", self.network)))
            .set("scheme", Json::str(scheme.name()))
            .set("scheme_id", Json::u64(u64::from(scheme.as_u8())))
            .set("one_time", Json::Bool(scheme.is_one_time()))
            .set("derived_addresses", Json::u64(u64::from(g.next_index())))
            .set("keys_consumed", Json::u64(consumed))
            .set("public_key_bytes", Json::u64(scheme.pubkey_len() as u64))
            .set("signature_bytes", Json::u64(scheme.sig_len() as u64))
            .build())
    }

    /// Every address this wallet recognizes as its own.
    ///
    /// A public key hash is public by construction: returning it reveals
    /// nothing. What would be serious would be returning the seed, and no
    /// method does that.
    fn listaddresses(&self) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        let g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
        let scheme = g.scheme();
        let consumed = g.consumed_indices();
        let v: Vec<Json> = g
            .known_hashes()
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let a = crate::address::Address {
                    network: self.network,
                    scheme,
                    hash: *h,
                };
                let mut o = Json::obj()
                    .set("key_index", Json::u64(i as u64))
                    .set("address", Json::str(a.to_string_bech32()))
                    .set("consumed", Json::Bool(consumed.contains(&(i as u32))))
                    // Requested by the owner, or derived by mining: that is
                    // what decides whether to show it first or file it away.
                    .set("requested", Json::Bool(g.is_requested(i as u32)));
                // The label is only present if it exists: an empty string in
                // the response would force every caller to tell "no name"
                // from "named with nothing".
                if let Some(e) = g.label(i as u32) {
                    o = o.set("label", Json::str(e));
                }
                o.build()
            })
            .collect();
        Ok(Json::array(v))
    }

    /// Names an address in the local address book.
    ///
    /// # Why this exists
    ///
    /// Q21 encourages giving a different address to each correspondent: that
    /// is what keeps your payments from being linked together. The price to pay
    /// is that after a month you have four hundred strings of characters and
    /// no idea who is who. The address book gives back to the owner what
    /// privacy cost them.
    ///
    /// # What this is not
    ///
    /// These names **never leave the machine**. They are not passed to peers,
    /// not written into the chain, and not visible to anyone who receives a
    /// payment. They are sealed with the wallet when a passphrase exists,
    /// because "for my therapist" says a lot about who you associate with.
    fn setaddresslabel(&self, params: &Json) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        let key_index = params
            .get("key_index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| rpc_error(-32602, "integer parameter `key_index` expected"))?;
        let key_index = u32::try_from(key_index)
            .map_err(|_| rpc_error(-32602, "address index outside the possible values"))?;
        let text = params
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
        // We refuse to name an address that does not exist: accepting would
        // leave orphan names in the file, and would hide a typo by the
        // caller.
        if key_index as usize >= g.known_hashes().len() {
            return Err(rpc_error(
                -32602,
                "this address does not exist yet in this wallet",
            ));
        }
        g.set_label(key_index, &text);
        if let Err(e) = self.save_wallet(&g) {
            eprintln!("WARNING: label not saved: {e}");
        }
        Ok(Json::obj()
            .set("key_index", Json::u64(key_index as u64))
            .set(
                "label",
                match g.label(key_index) {
                    Some(e) => Json::str(e),
                    None => Json::Null,
                },
            )
            .set("max_length", Json::u64(Wallet::MAX_LABEL_LEN as u64))
            .build())
    }

    /// History of this wallet's movements.
    ///
    /// # The cost, and why it is announced
    ///
    /// Q21 has no index by address. Finding the history requires rereading
    /// the block bodies and looking for our key hashes in them. The window is
    /// therefore bounded to [`HISTORY_WINDOW`] blocks, and the response **says
    /// how far back it looked**. A wallet that shows a truncated history
    /// without flagging it lies to its owner - and it is the kind of lie that
    /// makes people believe funds have vanished.
    fn listtransactions(&self, params: &Json) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            // A page asks for more with "Show more"; two thousand rows are
            // read once, on demand, not at every refresh of a closed tab.
            .clamp(1, 2000);
        // Filtered here, before the limit. The page used to filter the rows
        // it had received: with a hundred mining rewards in a row, "Sent"
        // showed nothing at all, and a transfer looked as if it had never left.
        let kind_filter: Option<String> = match params.get("kind").and_then(|v| v.as_str()) {
            None | Some("all") => None,
            Some(k @ ("send" | "receive" | "mining")) => Some(k.to_string()),
            Some(_) => {
                return Err(rpc_error(
                    ERR_PARAMS,
                    "parameter 'kind': send, receive, mining or all",
                ))
            }
        };

        let g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
        let scheme = g.scheme();

        // --- With the address index, the whole history and nothing else.
        //
        // The heights where one of our key hashes appears, read from a table:
        // no window, and no block read for nothing. The index lock is released
        // before the chain lock is taken.
        let indexed: Option<(u64, Vec<u64>)> = match &self.index {
            Some(index) => {
                let i = index
                    .lock()
                    .map_err(|_| rpc_error(ERR_REQUEST, "index unavailable"))?;
                if i.is_empty() {
                    None
                } else {
                    let mut ours: Vec<u64> = g
                        .known_hashes()
                        .iter()
                        .flat_map(|h| i.positions(h).iter().map(|p| p.height))
                        .collect();
                    ours.sort_unstable_by(|a, b| b.cmp(a));
                    ours.dedup();
                    Some((i.height(), ours))
                }
            }
            None => None,
        };

        // --- What is waiting in the mempool counts as a movement.
        //
        // The history only read blocks. A send just broadcast therefore
        // appeared **nowhere** until a miner had included it - two minutes on
        // average, and much more if the network is busy. From the point of
        // view of someone who has just paid, their money had vanished: the
        // balance had dropped, and nothing explained why. That is the kind of
        // silence that makes people doubt a wallet, and doubting a wallet is
        // worse than an error on screen.
        //
        // So we read the mempool before the blocks. These rows carry `pending`
        // and zero confirmations: they tell the truth, which is "it has gone
        // out, it is not set in stone yet".
        //
        // The mempool lock is taken and released **before** the chain lock:
        // two locks nested in two different orders are the recipe for a
        // deadlock.
        let pending_txs: Vec<Transaction> = self.node.with_mempool(|m| {
            m.txids()
                .iter()
                .filter_map(|id| m.get(id).cloned())
                .collect()
        });

        let (movements, since, height, all_resolved, missing_bodies) = self.node.with_chain(|c| {
            let height = c.height();
            // --- Which blocks to read, most recent first.
            //
            // With the index: only those where one of our key hashes appears,
            // over the whole chain, plus the few the index may not have
            // followed yet. Without it: every block of the window.
            let (since, heights): (u64, Vec<u64>) = match &indexed {
                Some((indexed_up_to, ours)) => {
                    let mut v: Vec<u64> = ((indexed_up_to + 1)..=height).rev().collect();
                    v.extend(ours.iter().copied().filter(|h| *h <= height));
                    (0, v)
                }
                None => {
                    let since = height.saturating_sub(HISTORY_WINDOW);
                    (since, (since..=height).rev().collect())
                }
            };

            let mut v: Vec<Json> = Vec::new();
            let mut all_resolved = true;

            // The mempool first: it is the most recent, and it is what
            // someone who has just pressed "Send" looks for.
            for tx in &pending_txs {
                if v.len() as u64 >= limit {
                    break;
                }
                let received: u64 = tx
                    .outputs
                    .iter()
                    .filter(|o| g.owns(&o.pubkey_hash))
                    .map(|o| o.value.units())
                    .sum();
                let mut committed: u64 = 0;
                let mut committed_complete = true;
                let mut is_send = false;
                for e in &tx.inputs {
                    if e.witness.pubkey.is_empty() {
                        continue;
                    }
                    if !g.owns(&crate::sig::pubkey_hash(scheme, &e.witness.pubkey)) {
                        continue;
                    }
                    is_send = true;
                    // A coin consumed by a mempool transaction is still in the
                    // UTXO set: the mempool does not touch it, only a block
                    // does. That is therefore where its amount is read.
                    match c.utxo.get(&e.prev_out) {
                        Some(entry) => committed += entry.output.value.units(),
                        None => committed_complete = false,
                    }
                }
                if received == 0 && !is_send {
                    continue;
                }
                let kind = if is_send { "send" } else { "receive" };
                if kind_filter.as_deref().is_some_and(|k| k != kind) {
                    continue;
                }
                if is_send && !committed_complete {
                    all_resolved = false;
                }
                let net_out = committed.saturating_sub(received);
                let mut row = Json::obj()
                    .set("txid", Json::str(tx.txid().to_hex()))
                    // No height: it will only exist at the block that includes
                    // it. Zero would be a readable lie - the height of the
                    // genesis block.
                    .set("height", Json::Null)
                    .set("timestamp", Json::u64(now_utc()))
                    .set("confirmations", Json::u64(0))
                    .set("pending", Json::Bool(true))
                    .set("kind", Json::str(kind))
                    .set("received", amount_json(Amount::from_units(received)))
                    // A mempool transaction is never a coinbase: maturity does
                    // not concern it.
                    .set("mature", Json::Bool(true));
                if is_send {
                    row = row
                        .set("committed", amount_json(Amount::from_units(committed)))
                        .set("net_out", amount_json(Amount::from_units(net_out)))
                        .set("amount_out_known", Json::Bool(committed_complete));
                }
                v.push(row.build());
            }

            // --- The blocks, read lazily.
            //
            // A send does not carry its amount: each input designates an
            // earlier output, and what this wallet committed is the sum of
            // those. They are always **older** than the spend, so reading
            // backward finds them on the way. The rows are drafted first, and
            // the reading goes on only while a row still waits for one of its
            // coins - never the whole window when the first blocks suffice.
            // An unreadable block must not silently erase a payment either: its
            // height is counted, and the response announces it.
            struct Draft {
                txid: Hash256,
                height: u64,
                time: u64,
                kind: &'static str,
                received: u64,
                coinbase: bool,
                inputs: Vec<(Hash256, u32)>,
            }
            let mut drafts: Vec<Draft> = Vec::new();
            let mut wanted: std::collections::HashSet<(Hash256, u32)> =
                std::collections::HashSet::new();
            let mut seen_outputs: std::collections::HashMap<(Hash256, u32), u64> =
                std::collections::HashMap::new();
            let mut missing_bodies: Vec<u64> = Vec::new();
            let room = limit.saturating_sub(v.len() as u64) as usize;
            let mut last: Option<u64> = None;
            for h in heights {
                // The index may list a height twice (two of our hashes).
                if last == Some(h) {
                    continue;
                }
                last = Some(h);
                if drafts.len() >= room && wanted.is_empty() {
                    break;
                }
                let Some(b) = c.block_at(h) else {
                    missing_bodies.push(h);
                    continue;
                };
                for tx in &b.transactions {
                    if drafts.len() >= room {
                        break;
                    }
                    let received: u64 = tx
                        .outputs
                        .iter()
                        .filter(|o| g.owns(&o.pubkey_hash))
                        .map(|o| o.value.units())
                        .sum();
                    let mut inputs: Vec<(Hash256, u32)> = Vec::new();
                    for e in &tx.inputs {
                        if e.witness.pubkey.is_empty() {
                            continue; // coinbase
                        }
                        if g.owns(&crate::sig::pubkey_hash(scheme, &e.witness.pubkey)) {
                            inputs.push((e.prev_out.txid, e.prev_out.index));
                        }
                    }
                    if received == 0 && inputs.is_empty() {
                        continue;
                    }
                    let coinbase =
                        tx.inputs.len() == 1 && tx.inputs[0].prev_out.txid == Hash256::ZERO;
                    let kind = if coinbase {
                        "mining"
                    } else if !inputs.is_empty() {
                        "send"
                    } else {
                        "receive"
                    };
                    if kind_filter.as_deref().is_some_and(|k| k != kind) {
                        continue;
                    }
                    wanted.extend(inputs.iter().copied());
                    drafts.push(Draft {
                        txid: tx.txid(),
                        height: b.header.height,
                        time: b.header.time,
                        kind,
                        received,
                        coinbase,
                        inputs,
                    });
                }
                // The coins a row waits for, found in this block - including a
                // coin created and spent within the same block.
                if !wanted.is_empty() {
                    for tx in &b.transactions {
                        let id = tx.txid();
                        for (i, o) in tx.outputs.iter().enumerate() {
                            if wanted.remove(&(id, i as u32)) {
                                seen_outputs.insert((id, i as u32), o.value.units());
                            }
                        }
                    }
                }
            }

            for d in drafts {
                let is_send = !d.inputs.is_empty();
                let mut committed: u64 = 0;
                let mut committed_complete = true;
                for k in &d.inputs {
                    match seen_outputs.get(k) {
                        Some(m) => committed += m,
                        None => committed_complete = false,
                    }
                }
                if is_send && !committed_complete {
                    all_resolved = false;
                }
                // Gone out for good: what was committed, minus what came back
                // as change.
                let net_out = committed.saturating_sub(d.received);
                let mut row = Json::obj()
                    .set("txid", Json::str(d.txid.to_hex()))
                    .set("height", Json::u64(d.height))
                    .set("timestamp", Json::u64(d.time))
                    .set("confirmations", Json::u64(height - d.height + 1))
                    .set("kind", Json::str(d.kind))
                    .set("received", amount_json(Amount::from_units(d.received)))
                    .set(
                        "mature",
                        Json::Bool(!d.coinbase || height >= d.height + COINBASE_MATURITY),
                    );
                if is_send {
                    row = row
                        .set("committed", amount_json(Amount::from_units(committed)))
                        .set("net_out", amount_json(Amount::from_units(net_out)))
                        .set("amount_out_known", Json::Bool(committed_complete));
                }
                v.push(row.build());
            }
            (v, since, height, all_resolved, missing_bodies)
        });

        let complete = since == 0 && missing_bodies.is_empty();
        let mut response = Json::obj()
            .set("movements", Json::array(movements))
            .set("scanned_from_height", Json::u64(since))
            .set("height", Json::u64(height))
            .set("complete_history", Json::Bool(complete))
            .set("amounts_out_all_resolved", Json::Bool(all_resolved))
            .set("unreadable_blocks", Json::u64(missing_bodies.len() as u64));
        // The heights concerned, bounded: enough to act on without drowning
        // the response.
        if !missing_bodies.is_empty() {
            let preview: Vec<Json> = missing_bodies
                .iter()
                .take(20)
                .map(|h| Json::u64(*h))
                .collect();
            response = response.set("unreadable_heights", Json::array(preview));
        }
        Ok(response
            .set(
                "note",
                Json::str(if !missing_bodies.is_empty() {
                    "INCOMPLETE history: the body of some blocks of the active chain \
                     could not be read, and what they contained does not appear here. \
                     This is not a loss of funds - the balance itself stays correct. \
                     Restart the node: it will request these blocks from the network \
                     again."
                } else if complete {
                    "Full history: the search went all the way back to genesis."
                } else {
                    "Partial history. This node has no index by address: \
                     the search stops at the height shown."
                }),
            )
            .build())
    }

    /// Prepares a send: selects the coins, and returns the exact figures.
    ///
    /// # Why this method exists
    ///
    /// `estimatefee` asked the caller to **assume** a number of inputs. That
    /// is an assumption impossible to get right: the coins are only chosen
    /// when the transaction is built, and with ML-DSA-87 each input adds 7,219
    /// bytes of witness.
    ///
    /// A real trial of the interface showed it beyond doubt: an estimate made
    /// for one input proposed eight units of fee, the real transaction consumed
    /// two inputs, and the mempool rejected it for a fee rate too low. The user
    /// saw an incomprehensible rejection on a transaction they had just
    /// confirmed.
    ///
    /// This method does the **real** selection, without signing or spending
    /// anything, and returns the figures of the transaction that will actually
    /// be built. The confirmation screen can then tell the truth.
    ///
    /// It modifies nothing: no index is consumed, no counter moves forward.
    fn preparesend(&self, params: &Json) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        let address = params
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'address' expected"))?;
        let units = params
            .get("units")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'units' expected (integer)"))?;
        if units == 0 {
            return Err(rpc_error(ERR_PARAMS, "zero amount"));
        }
        let dest = Address::parse_on(address, self.network)
            .map_err(|e| rpc_error(ERR_PARAMS, &format!("invalid address: {e:?}")))?;

        let g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
        let scheme = g.scheme();

        let (median_rate, pending_count) = self
            .node
            .with_mempool(|m| (m.median_fee_rate().unwrap_or(0), m.len() as u64));
        let rate = median_rate.max(crate::mempool::MIN_FEE_RATE);

        // Two passes: the first to know the number of inputs, the second
        // because a higher fee can require one more. Two are enough in
        // practice; we do not loop indefinitely.
        let mut fee = DEFAULT_FEE;
        let mut result = None;
        for _ in 0..2 {
            let needed = units
                .checked_add(fee)
                .ok_or_else(|| rpc_error(ERR_PARAMS, "amount plus fee overflows"))?;
            let (chosen, total) = self
                .node
                .with_chain(|c| g.select_coins(&c.utxo, c.height(), needed))
                .map_err(|e| rpc_error(ERR_WALLET, wallet_message(&e)))?;

            let n = chosen.len() as u64;
            let change = total - needed;
            // One output for the recipient, one for the change if there is any.
            let n_outputs = if change > 0 { 2 } else { 1 };
            let base_size = 8 + n * 48 + n_outputs * 41;
            let witness = n * (scheme.pubkey_len() as u64 + scheme.sig_len() as u64);
            let weight = base_size * WITNESS_DISCOUNT + witness + n_outputs * WEIGHT_PER_OUTPUT;
            // Rounded up: below the floor, the transaction is not relayed at
            // all.
            let computed = weight.saturating_mul(rate).div_ceil(1000).max(1);

            result = Some((n, base_size + witness, weight, change, total));
            if computed <= fee {
                break;
            }
            fee = computed;
        }

        let (n_inputs, size, weight, change, total) =
            result.ok_or_else(|| rpc_error(ERR_INTERNAL, "selection failed"))?;

        Ok(Json::obj()
            .set("address", Json::str(dest.to_string_bech32()))
            .set("amount", amount_json(Amount::from_units(units)))
            .set("fee", amount_json(Amount::from_units(fee)))
            .set(
                "total_debited",
                amount_json(Amount::from_units(units + fee)),
            )
            .set("change", amount_json(Amount::from_units(change)))
            .set("coins_committed", amount_json(Amount::from_units(total)))
            .set("inputs", Json::u64(n_inputs))
            .set("size_bytes", Json::u64(size))
            .set("weight", Json::u64(weight))
            .set("rate_per_kilo_weight", Json::u64(rate))
            .set("pending_transactions", Json::u64(pending_count))
            .set(
                "note",
                Json::str(
                    "Exact figures: the coins were actually selected. Nothing was \
                     signed or consumed. Pass this fee as is to sendtoaddress.",
                ),
            )
            .build())
    }

    /// Suggested fee for a transaction from this wallet.
    ///
    /// **Prefer [`Self::preparesend`]**: this method asks for a number of
    /// inputs the caller cannot know, and is therefore wrong as soon as the
    /// selection keeps a different one. It remains to answer the general
    /// question "how much does a transaction cost here".
    ///
    /// The suggestion is based on the real size the transaction will have -
    /// with ML-DSA-87 the witness weighs 99 % of the total - and on what the
    /// transactions already pending pay.
    fn estimatefee(&self, params: &Json) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        let n_inputs = params
            .get("inputs")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .clamp(1, 100);
        let n_outputs = params
            .get("outputs")
            .and_then(|v| v.as_u64())
            .unwrap_or(2)
            .clamp(1, 100);

        let scheme = {
            let g = w
                .lock()
                .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
            g.scheme()
        };
        // --- Size, weight, and rate: three quantities not to be confused.
        //
        // The mempool orders by **fee rate per weighted weight**, expressed in
        // units per thousand weight units. Weight is not size: the base
        // counts for `WITNESS_DISCOUNT` times its size, the witness for just
        // once.
        //
        // Multiplying the size by this rate - which the first version of this
        // method did - overestimated the fee by a factor of a thousand. Nobody
        // would have lost funds, but everyone would have paid a thousand times
        // too much.
        let base_size = 8 + n_inputs * 48 + n_outputs * 41;
        let witness = n_inputs * (scheme.pubkey_len() as u64 + scheme.sig_len() as u64);
        let size = base_size + witness;
        // Each output created weighs extra: it occupies the UTXO set.
        let weight = base_size * WITNESS_DISCOUNT + witness + n_outputs * WEIGHT_PER_OUTPUT;

        let (mempool_rate, pending_count) = self.node.with_mempool(|m| {
            let n = m.len() as u64;
            let rate = m.median_fee_rate().unwrap_or(0);
            (rate, n)
        });
        // The network floor, or the observed rate if it is higher.
        let rate = mempool_rate.max(crate::mempool::MIN_FEE_RATE);
        // Rounded up: a transaction below the floor is not relayed at all, and
        // rounding down would make it land there.
        let suggested = weight.saturating_mul(rate).div_ceil(1000).max(1);

        Ok(Json::obj()
            .set("estimated_size_bytes", Json::u64(size))
            .set("estimated_weight", Json::u64(weight))
            .set("inputs", Json::u64(n_inputs))
            .set("outputs", Json::u64(n_outputs))
            .set("rate_per_kilo_weight", Json::u64(rate))
            .set("pending_transactions", Json::u64(pending_count))
            .set("suggested_fee", amount_json(Amount::from_units(suggested)))
            .build())
    }

    /// Where synchronization with the network stands.
    ///
    /// A wallet that shows a balance without saying it is a thousand blocks
    /// behind shows a wrong figure. This method exists so that the interface
    /// can say so.
    fn getsyncstatus(&self) -> Json {
        let height = self.node.height();
        let peers = self.node.peer_count() as u64;
        let target = self.node.max_announced_height().max(height);
        let remaining = target.saturating_sub(height);
        Json::obj()
            .set("height", Json::u64(height))
            .set("network_height", Json::u64(target))
            .set("blocks_remaining", Json::u64(remaining))
            .set("peers", Json::u64(peers))
            .set("synced", Json::Bool(remaining == 0 && peers > 0))
            .set(
                "note",
                Json::str(if peers == 0 {
                    "No peer connected: this node cannot know whether it is up to date."
                } else if remaining == 0 {
                    "Up to date with the known peers."
                } else {
                    "Synchronization in progress. The balances shown are incomplete."
                }),
            )
            .build()
    }

    /// Mining status: what the machine is doing right now.
    ///
    /// Always served, even without a wallet - knowing that you are not mining
    /// is a useful answer, and it reveals nothing.
    fn getmining(&self) -> Json {
        let (active, rate, blocks, total, earned, found) = match &self.mining {
            Some(m) => (
                m.is_active(),
                m.rate(),
                m.blocks(),
                m.total_attempts(),
                m.total_earned(),
                m.found(),
            ),
            None => (false, 0.0, 0, 0, 0, Vec::new()),
        };
        // The proof-of-work table of the current epoch: its size is what mining
        // really occupies in RAM on this machine.
        let (mining_memory, epoch) = self.node.with_chain(|c| {
            let epoch = crate::memhard::epoch_of(c.height().saturating_add(1));
            let n = crate::memhard::table_size(c.pow_params(), epoch) as u64;
            (n * crate::consensus::POW_ELEMENT_SIZE as u64, epoch)
        });

        // The last twenty finds are enough for the screen; the counter and the
        // earnings carry the total since launch.
        let list: Vec<Json> = found
            .iter()
            .take(20)
            .map(|t| {
                Json::obj()
                    .set("height", Json::u64(t.height))
                    .set("block_id", Json::str(t.block_id.to_string()))
                    .set("reward", amount_json(Amount::from_units(t.reward)))
                    .set("timestamp", Json::u64(t.timestamp))
                    .build()
            })
            .collect();
        Json::obj()
            .set("active", Json::Bool(active))
            .set(
                "possible",
                Json::Bool(self.mining.is_some() && self.wallet.is_some()),
            )
            .set("attempts_per_second", Json::Int(rate as i64))
            .set("total_attempts", Json::u64(total))
            .set("blocks_found", Json::u64(blocks))
            .set("earned", amount_json(Amount::from_units(earned)))
            .set("found", Json::array(list))
            // --- Memory: the whole point of this proof of work, and it was
            // shown nowhere.
            //
            // Q21 mines with a table that must fit in RAM, and that grows by
            // 5 % every 71 days. It is what makes a specialized machine
            // pointless: you cannot etch memory into silicon. The size used
            // **now**, on this machine, is therefore the figure that explains
            // why mining stays within everyone's reach - and it has to be
            // readable.
            .set("memory_bytes", Json::u64(mining_memory))
            .set("epoch_memory", Json::u64(epoch))
            .build()
    }

    /// What the network spends in work, and what cannot be deduced from it.
    ///
    /// # The question one would like to ask
    ///
    /// "How many miners are there?" Everyone asks it, and **no chain can
    /// answer it**. A miner does not announce itself; it lays down blocks.
    /// Nothing distinguishes a thousand machines from one person who owns a
    /// thousand, and nothing distinguishes one machine from someone who rents a
    /// thousand for an hour.
    ///
    /// We first tried counting the distinct miner key hashes in the recent
    /// blocks. That was already a lower bound and not a count; it became
    /// unusable the day the miner stopped reusing its address. It derives one
    /// per block found - so as not to publicly link all its rewards together -
    /// so that the number of distinct key hashes now equals the number of
    /// blocks. The good privacy property destroyed the bad measurement, and
    /// that is just fine.
    ///
    /// # The question that can be answered
    ///
    /// **How much work does the network spend?** That can be read from the
    /// difficulty: it adjusts so that a block lands every two minutes, so the
    /// accumulated work divided by the elapsed time is the rate of the whole
    /// network. It is a measurement, not a declaration, and nobody can inflate
    /// it without really spending.
    ///
    /// The rest - how many people, how many machines - is deduced by dividing
    /// by the rate of **one** machine, and the interface presents it as an
    /// equivalence, never as a headcount.
    fn getnetworkhashrate(&self) -> Json {
        // One day of blocks, or whatever exists if the chain is younger.
        const WINDOW: usize = 720;
        let headers = self.node.with_chain(|c| c.headers());
        let n = headers.len();
        // --- Genesis never counts as a starting point.
        //
        // Its timestamp is a protocol constant, not the moment someone mined.
        // On a young chain, the window included it and the measured span
        // became the distance between that constant and today: 141 blocks
        // mined in nine seconds announced themselves as "371.8 days of chain",
        // and the resulting rate was zero. The anchor is the first block of
        // the window: its timestamp opens the interval, and the work is summed
        // over the ones that follow it. It never goes below height 1.
        //
        // A first draft wrote `.max(1)` and then reread `headers[start - 1..]`,
        // which brought back exactly the genesis that had just been excluded.
        // The test `genesis_is_not_used_as_the_starting_point` caught it right
        // away; the review did not.
        let anchor = n.saturating_sub(WINDOW + 1).max(1);
        let slice = if n > anchor {
            &headers[anchor..]
        } else {
            &headers[..0]
        };

        let mut work: u128 = 0;
        for h in slice.iter().skip(1) {
            work = work.saturating_add(work_to_u128(crate::pow::block_work(h.bits)));
        }
        // A chain's timestamps are not monotonic: the median time rule lets a
        // block be earlier than its parent. So we take the extremes of the
        // slice, and refuse to divide by a zero or negative span rather than
        // announce an infinite rate.
        let (t0, t1) = (
            slice.first().map(|h| h.time).unwrap_or(0),
            slice.last().map(|h| h.time).unwrap_or(0),
        );
        let seconds = t1.saturating_sub(t0);
        let blocks = slice.len().saturating_sub(1) as u64;
        // --- The rate is computed in thousandths.
        //
        // The integer division `work / seconds` returned zero as soon as the
        // network produced less than one unit of work per second - which is
        // the normal case for a testnet with low difficulty. A zero reads as
        // "the network has stopped", and that was false. So we multiply before
        // dividing, and the unit announced is thousandths.
        let rate_milli = if seconds > 0 && blocks > 0 {
            work.saturating_mul(1000) / seconds as u128
        } else {
            0
        };

        Json::obj()
            .set("peers", Json::u64(self.node.peer_count() as u64))
            // --- The address book: the closest thing to a "how many
            // machines".
            //
            // The number of miners remains unknowable, and will stay so. But
            // the number of machines this node has **learned exist** is a fact:
            // each handshake exchanges addresses, and the address book keeps
            // them. It is not a headcount of the network - a machine that is
            // switched off still appears in it, a machine that has just
            // arrived does not yet - and the interface says so as is.
            .set("address_book", Json::u64(self.node.address_count() as u64))
            .set("blocks_examined", Json::u64(blocks))
            .set("seconds_examined", Json::u64(seconds))
            .set("total_work", Json::str(work.to_string()))
            .set("network_rate_milli", Json::str(rate_milli.to_string()))
            .set("measurable", Json::Bool(seconds > 0 && blocks > 0))
            .set(
                "note",
                Json::str(
                    "The number of miners cannot be known: a miner does not announce \
                     itself, and this one changes address at every block found. What \
                     can be measured is the work spent, read from the difficulty.",
                ),
            )
            .build()
    }

    /// Turns mining on or off.
    ///
    /// Filed among the wallet methods, for a fundamental reason: mining pays a
    /// subsidy to an address of the wallet. Without a wallet being served,
    /// allowing it would mean letting a page decide on work whose product would
    /// go nowhere.
    fn setmining(&self, params: &Json) -> Result<Json, Json> {
        let m = self
            .mining
            .as_ref()
            .ok_or_else(|| rpc_error(-32004, "this node cannot mine"))?;
        if self.wallet.is_none() {
            return Err(rpc_error(
                -32004,
                "mining requires a wallet: without one the subsidy would go nowhere",
            ));
        }
        let on = match params.get("active") {
            Some(Json::Bool(b)) => *b,
            _ => return Err(rpc_error(-32602, "boolean parameter `active` expected")),
        };
        m.set_active(on);
        Ok(self.getmining())
    }

    /// Changes the "is this node reachable from outside" setting.
    ///
    /// The change is written to disk and takes effect **at the next launch**:
    /// listening and opening the router port are decided at startup. The
    /// response says so, so that the interface does not suggest an immediate
    /// effect.
    fn setreachable(&self, params: &Json) -> Result<Json, Json> {
        // Reserved for the wallet: a public node does not let just anyone
        // reconfigure it.
        self.require_wallet()?;
        let on = match params.get("active") {
            Some(Json::Bool(b)) => *b,
            _ => return Err(rpc_error(-32602, "boolean parameter `active` expected")),
        };
        let set_fn = self.set_reachable.as_ref().ok_or_else(|| {
            rpc_error(
                ERR_INTERNAL,
                "this node does not know where to write this setting",
            )
        })?;
        set_fn(on).map_err(|e| rpc_error(ERR_INTERNAL, &format!("setting not saved: {e}")))?;
        // The choice is on disk: it becomes the wanted choice, which every
        // following `getinfo` will return. Without that, refreshing the page
        // repainted the launch value and canceled the click.
        self.reachable
            .store(on, std::sync::atomic::Ordering::SeqCst);
        Ok(Json::obj()
            .set("reachable", Json::Bool(on))
            .set("reachable_session", Json::Bool(self.reachable_session))
            .set("takes_effect", Json::str("at the next launch"))
            .build())
    }

    fn getbalance(&self) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        // --- Do not copy the whole UTXO set at every call.
        //
        // `c.utxo.clone()` duplicated the entire UTXO set - hundreds of
        // mebibytes on a real chain - to read a balance, and a batch asked for
        // as many copies. We work under the lock, on a reference: the
        // computation is identical, the allocation goes away.
        let g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
        let (balance, n_spendable, immature, height, next, frozen, reused) =
            self.node.with_chain(|c| {
                let height = c.height();
                let balance = g.balance(&c.utxo, height);
                let n_spendable = g.spendable(&c.utxo, height).len();
                // --- "When?" is the question people ask in front of a locked
                //     balance.
                //
                // The wallet announced a sum awaiting maturity without ever
                // saying on what date it would be released. A miner therefore
                // saw their earnings rise and their available balance stay at
                // zero, for hours, without the slightest landmark. Several took
                // it for a malfunction. So we return the height of the **next**
                // release and the amount it carries.
                //
                // The computation goes through the key hash index of the UTXO
                // set: this request comes back every six seconds, and a full
                // scan under the consensus lock would have frozen block
                // validation at the pace of the interface refresh.
                let (immature_amount, next_amount) = g.immature(&c.utxo, height);
                let immature = immature_amount.units();
                let next: Option<(u64, u64)> = next_amount.map(|(h, m)| (h, m.units()));
                // What a reused address has locked up. A one-time key signs
                // only once: the second coin received on the same address will
                // never be spendable. Keeping quiet about it would make funds
                // vanish without explanation; we name it, with its cause.
                let frozen = g.frozen_amount(&c.utxo, height);
                let reused = g.reused_addresses(&c.utxo, height).len();
                (balance, n_spendable, immature, height, next, frozen, reused)
            });

        let mut response = Json::obj()
            .set("spendable", amount_json(balance))
            .set("immature", amount_json(Amount::from_units(immature)))
            .set("spendable_outputs", Json::u64(n_spendable as u64))
            .set("derived_addresses", Json::u64(g.next_index() as u64))
            .set("height", Json::u64(height));
        if frozen.units() > 0 {
            response = response
                .set("frozen_by_reuse", amount_json(frozen))
                .set("reused_addresses", Json::u64(reused as u64))
                .set(
                    "warning",
                    Json::str(
                        "A one-time key signs only once: on an address that has \
                         received several payments, only the largest coin stays \
                         spendable. Give a new address for each payment.",
                    ),
                );
        }
        if let Some((free_at, released_amount)) = next {
            response = response
                .set("next_maturity_height", Json::u64(free_at))
                .set(
                    "next_maturity_blocks",
                    Json::u64(free_at.saturating_sub(height)),
                )
                .set(
                    "next_maturity_amount",
                    amount_json(Amount::from_units(released_amount)),
                );
        }
        Ok(response.build())
    }

    fn getnewaddress(&self) -> Result<Json, Json> {
        let w = self.require_wallet()?;
        let mut g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
        let a = g.request_address();
        // The index counter has just moved forward: without a write, a restart
        // would hand out the same address again. So we do not give it out if
        // the disk has not seen it.
        self.save_wallet(&g).map_err(|e| {
            rpc_error(
                ERR_WALLET,
                &format!("address not saved, so not handed out: {e}"),
            )
        })?;
        Ok(Json::obj()
            .set("address", Json::str(a.to_string_bech32()))
            .set("scheme", Json::str(a.scheme.name()))
            .set("one_time", Json::Bool(a.scheme.is_one_time()))
            .set(
                "warning",
                Json::str(if a.scheme.is_one_time() {
                    "One-time address: Lamport reveals the private key if it signs \
                     twice. Never reuse it."
                } else {
                    "Address reusable without weakening the key. A new address per \
                     payment is still recommended, for privacy."
                }),
            )
            .build())
    }

    fn sendtoaddress(&self, params: &Json) -> Result<Json, Json> {
        let w = self.require_wallet()?;

        let address = params
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'address' expected"))?;
        let units = params
            .get("units")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| rpc_error(ERR_PARAMS, "parameter 'units' expected (integer)"))?;
        // --- A badly typed fee must not become the default fee.
        //
        // `.and_then(as_u64).unwrap_or(1_000)` silently replaced any unreadable
        // value with the default value: the transaction built was not the one
        // the client had written. A field that is present and invalid is an
        // error, not an invitation to guess.
        let fee = match params.get("fee") {
            None | Some(Json::Null) => DEFAULT_FEE,
            Some(v) => v.as_u64().ok_or_else(|| {
                rpc_error(
                    ERR_PARAMS,
                    "parameter 'fee' present but unreadable: an integer number of units is expected",
                )
            })?,
        };

        let dest = Address::parse_on(address, self.network)
            .map_err(|e| rpc_error(ERR_PARAMS, &format!("invalid address: {e:?}")))?;

        let (tx, txid) = self.spend(w, &[(dest, Amount::from_units(units))], fee)?;

        self.node.announce_tx(txid);

        Ok(Json::obj()
            .set("txid", Json::str(txid.to_hex()))
            .set("transaction", tx_json(&tx, self.network))
            .build())
    }

    /// Builds, saves, signs and places a spend in the mempool - in three
    /// steps, so as never to seal the wallet under the chain lock.
    ///
    /// # The defect this closes
    ///
    /// The write-ahead is necessary: the indices must be on disk before the
    /// signature. But it was done **under the chain and mempool lock**, and
    /// writing the wallet means sealing it - Argon2id, 64 MiB, three passes: a
    /// third of a second on a PC, a second on a Raspberry Pi. Block validation
    /// and serving peers stopped at every send, for the duration of a key
    /// derivation that has nothing to do with them.
    ///
    /// # The three steps
    ///
    /// 1. Under the lock: scan the blocks not seen yet (one-time scheme),
    ///    choose the coins, check the keys, **reserve** the indices.
    /// 2. Without the lock: write the wallet. A failure lifts the reservation,
    ///    and nothing was signed.
    /// 3. Under the lock: check again that the coins are still there, sign,
    ///    accept into the mempool. A coin that has disappeared in the meantime
    ///    lifts the reservation, and the caller starts over.
    ///
    /// The wallet lock, on the other hand, is held from start to finish: it
    /// only protects the wallet, and nobody else waits for it during a send.
    fn spend(
        &self,
        w: &Arc<Mutex<Wallet>>,
        destinations: &[(crate::address::Address, Amount)],
        fee: u64,
    ) -> Result<(crate::tx::Transaction, crate::hash::Hash256), Json> {
        let mut g = w
            .lock()
            .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;

        // 1. Reservation, under the chain lock - without the mempool, which is
        //    not needed yet.
        //
        // On a reference, never on a copy: copying the UTXO set to build a
        // transaction cost hundreds of mebibytes on a real chain, and a batch
        // asked for as many copies.
        let prepare = self.node.with_chain(|c| {
            // A one-time scheme must know which keys have already signed up to
            // the tip: the blocks that arrived since the last scan are reread
            // here. They are recent, so in memory; if one is missing, we refuse
            // rather than sign blindly.
            if g.scheme().is_one_time() && g.verified_up_to() < c.height() {
                g.scan_chain(c.height(), |h| c.block_at(h));
                if g.verified_up_to() < c.height() {
                    return Err(crate::wallet::WalletError::VerificationBehind {
                        verified: g.verified_up_to(),
                        height: c.height(),
                    });
                }
            }
            g.prepare_spend(&c.utxo, c.height(), destinations, Amount::from_units(fee))
        });
        let prepare = prepare.map_err(|e| rpc_error(ERR_WALLET, wallet_message(&e)))?;

        // 2. Write-ahead, outside the chain lock: the reserved indices reach
        //    the disk before the slightest signature exists. A failure signs
        //    nothing and gives the indices back.
        if self.save_wallet(&g).is_err() {
            g.cancel_spend(prepare);
            return Err(rpc_error(
                ERR_WALLET,
                wallet_message(&crate::wallet::WalletError::SaveFailed),
            ));
        }

        // 3. Signature and acceptance, under the chain and mempool lock: both
        //    live under the same one, and taking one inside the other would
        //    freeze the node.
        let result = self.node.with_chain_and_mempool(|c, m| {
            let tx = g.sign_spend(&c.utxo, prepare)?;
            let r = m.accept(&tx, &c.utxo, self.network, c.height());
            Ok((tx, r))
        });
        // The reserved indices are on disk; we save again for what has moved
        // since - indices gone from reserved to consumed, or given back if the
        // coins had disappeared.
        if let Err(e) = self.save_wallet(&g) {
            eprintln!("WARNING: wallet not saved after the send: {e}");
        }
        let (tx, accepted) = result.map_err(|e| rpc_error(ERR_WALLET, wallet_message(&e)))?;
        let txid = accepted.map_err(|e| rpc_error(ERR_WALLET, &mempool_message(&e)))?;
        Ok((tx, txid))
    }

    /// Pays several recipients in **a single** transaction.
    ///
    /// Same path as `sendtoaddress` - a single lock to build and accept, the
    /// consumed key written to disk whatever happens - but over a list of
    /// outputs. The number of recipients is bounded: an oversized transaction
    /// would be rejected by weight anyway, and a plain cap is better than an
    /// obscure rejection from the mempool.
    fn sendmany(&self, params: &Json) -> Result<Json, Json> {
        const MAX_RECIPIENTS: usize = 1000;
        let w = self.require_wallet()?;

        let list = params
            .get("destinations")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                rpc_error(
                    ERR_PARAMS,
                    "parameter 'destinations' expected: a list of {address, units} objects",
                )
            })?;
        if list.is_empty() {
            return Err(rpc_error(ERR_PARAMS, "at least one recipient is expected"));
        }
        if list.len() > MAX_RECIPIENTS {
            return Err(rpc_error(
                ERR_PARAMS,
                &format!("at most {MAX_RECIPIENTS} recipients per send"),
            ));
        }

        let mut destinations = Vec::with_capacity(list.len());
        for d in list {
            let address = d.get("address").and_then(|v| v.as_str()).ok_or_else(|| {
                rpc_error(ERR_PARAMS, "each destination expects an 'address' field")
            })?;
            let units = d.get("units").and_then(|v| v.as_u64()).ok_or_else(|| {
                rpc_error(
                    ERR_PARAMS,
                    "each destination expects a 'units' field (integer)",
                )
            })?;
            let dest = Address::parse_on(address, self.network)
                .map_err(|e| rpc_error(ERR_PARAMS, &format!("invalid address: {e:?}")))?;
            destinations.push((dest, Amount::from_units(units)));
        }

        let fee = match params.get("fee") {
            None | Some(Json::Null) => DEFAULT_FEE,
            Some(v) => v.as_u64().ok_or_else(|| {
                rpc_error(
                    ERR_PARAMS,
                    "parameter 'fee' present but unreadable: an integer number of units is expected",
                )
            })?,
        };

        let (tx, txid) = {
            let mut g = w
                .lock()
                .map_err(|_| rpc_error(ERR_INTERNAL, "wallet locked"))?;
            let result = self.node.with_chain_and_mempool(|c, m| {
                let tx = g.create_transaction_multi_guarded(
                    &c.utxo,
                    c.height(),
                    &destinations,
                    Amount::from_units(fee),
                    &mut |w| self.save_wallet(w),
                );
                match tx {
                    Ok(tx) => {
                        let r = m.accept(&tx, &c.utxo, self.network, c.height());
                        Ok((tx, r))
                    }
                    Err(e) => Err(e),
                }
            });
            if let Err(e) = self.save_wallet(&g) {
                eprintln!("WARNING: wallet not saved after the send: {e}");
            }
            let (tx, accepted) = result.map_err(|e| rpc_error(ERR_WALLET, wallet_message(&e)))?;
            let txid = accepted.map_err(|e| rpc_error(ERR_WALLET, &mempool_message(&e)))?;
            (tx, txid)
        };

        self.node.announce_tx(txid);

        Ok(Json::obj()
            .set("txid", Json::str(txid.to_hex()))
            .set("recipients", Json::u64(destinations.len() as u64))
            .set("transaction", tx_json(&tx, self.network))
            .build())
    }
}

/// Default wallet scheme, exposed for the documentation.
///
/// Depends on the build: ML-DSA-87 as soon as the `mldsa` feature is enabled,
/// Lamport otherwise. A node without ML-DSA has no place on mainnet.
///
/// This constant announced ML-DSA-65 while the binary had been creating
/// ML-DSA-87 wallets since the move to NIST level 5. A constant that
/// contradicts the real behavior is worse than none: it serves as a reference
/// for whoever reads the code, and it lies.
pub const WALLET_SCHEME: SchemeId = if cfg!(feature = "mldsa") {
    SchemeId::MlDsa87
} else {
    SchemeId::LamportOts
};

/// Converts a block's work to a 128-bit integer, saturating.
///
/// A block's work fits very comfortably in 128 bits at reachable
/// difficulties; saturation is a precaution, not an expected case. A capped
/// figure is preferred to a panic or to a silent fallback to zero, which would
/// suggest a stopped network.
fn work_to_u128(t: crate::uint::U256) -> u128 {
    let o = t.to_be_bytes();
    if o[..16].iter().any(|&x| x != 0) {
        return u128::MAX;
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&o[16..]);
    u128::from_be_bytes(low)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis_block, Chain};
    use crate::json::parse as jparse;

    const NETWORK: Network = Network::Regtest;

    fn context(with_wallet: bool) -> RpcContext {
        let g = genesis_block(NETWORK);
        let node = Arc::new(Node::new(NETWORK, Chain::new(NETWORK, g)));
        RpcContext {
            on_change: None,
            scans: None,
            configured_bootstrap: 0,
            reachable: std::sync::atomic::AtomicBool::new(true),
            reachable_session: true,
            router_status: None,
            set_reachable: None,
            index: None,
            // The RPC tests see mining as possible: that is what makes it
            // possible to check that the switch responds, and that without a
            // wallet it refuses.
            mining: Some(Arc::new(crate::mining::Mining::new(false))),
            node,
            wallet: if with_wallet {
                Some(Arc::new(Mutex::new(Wallet::from_seed([9u8; 32], NETWORK))))
            } else {
                None
            },
            network: NETWORK,
        }
    }

    /// A context whose wallet really has spendable coins.
    ///
    /// Mines until coinbase maturity is passed, otherwise nothing is spendable
    /// and only the "insufficient funds" message gets tested.
    fn context_with_funds() -> RpcContext {
        let mut w = Wallet::from_seed([0x5a; 32], NETWORK);
        let g = genesis_block(NETWORK);
        let mut c = Chain::new(NETWORK, g);
        for i in 1..=(COINBASE_MATURITY + 3) {
            let a = w.new_address();
            let t = crate::chain::GENESIS_TIME + i * TARGET_BLOCK_SECS;
            // The scheme comes from the address itself, never from a constant:
            // the hash of a public key depends on the scheme, and mining to a
            // scheme other than the wallet's produces a lock it cannot open.
            // The defect only showed with ML-DSA enabled, where the constant
            // and the wallet diverge.
            let b = c
                .mine_block(a.hash, a.scheme, &[], t, 5_000_000)
                .expect("mining");
            c.connect(&b, t + 1).expect("connect");
        }
        RpcContext {
            on_change: None,
            scans: None,
            configured_bootstrap: 0,
            reachable: std::sync::atomic::AtomicBool::new(true),
            reachable_session: true,
            router_status: None,
            set_reachable: None,
            index: None,
            mining: Some(Arc::new(crate::mining::Mining::new(false))),
            node: Arc::new(Node::new(NETWORK, c)),
            wallet: Some(Arc::new(Mutex::new(w))),
            network: NETWORK,
        }
    }

    fn call(c: &RpcContext, method: &str, params: &str) -> Json {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        jparse(&c.handle(&body)).expect("valid JSON response")
    }

    fn call_ok(c: &RpcContext, method: &str, params: &str) -> Json {
        let r = call(c, method, params);
        assert!(
            r.get("error").is_none(),
            "{method} returned an error: {}",
            r.encode()
        );
        r.get("result").cloned().expect("result field")
    }

    #[test]
    fn the_reachable_choice_survives_refresh() {
        // v0.2.0 regression: the "reachable" switch flipped back on its own,
        // because `getinfo` returned the value read at launch and the Network
        // tab rereads it every four seconds.
        let written = Arc::new(Mutex::new(None::<bool>));
        let witness = written.clone();
        let mut c = context(true);
        c.reachable = std::sync::atomic::AtomicBool::new(true);
        c.reachable_session = true;
        c.set_reachable = Some(Arc::new(move |v: bool| {
            *witness.lock().unwrap() = Some(v);
            Ok(())
        }));

        let r = call_ok(&c, "setreachable", r#"{"active":false}"#);
        assert_eq!(r.get("reachable"), Some(&Json::Bool(false)));
        assert_eq!(
            *written.lock().unwrap(),
            Some(false),
            "the choice must be written"
        );

        // The next refresh must return the choice, not the launch value.
        for _ in 0..3 {
            let info = call_ok(&c, "getinfo", "{}");
            assert_eq!(
                info.get("reachable"),
                Some(&Json::Bool(false)),
                "getinfo repainted the launch value"
            );
            assert_eq!(
                info.get("reachable_session"),
                Some(&Json::Bool(true)),
                "the current session stays the launch one"
            );
        }

        // And switching back is just as stable.
        call_ok(&c, "setreachable", r#"{"active":true}"#);
        let info = call_ok(&c, "getinfo", "{}");
        assert_eq!(info.get("reachable"), Some(&Json::Bool(true)));
    }

    #[test]
    fn getinfo_describes_the_chain() {
        let c = context(false);
        let r = call_ok(&c, "getinfo", "{}");
        assert_eq!(r.get("height").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(r.get("network").and_then(|v| v.as_str()), Some("Regtest"));
        assert_eq!(
            r.get("wallet_enabled"),
            Some(&Json::Bool(false)),
            "the wallet must be announced as disabled"
        );
        // The program version. A binary that cannot say what it is cannot be
        // troubleshot remotely, and its owner cannot compare it with the
        // version announced by the release.
        assert_eq!(
            r.get("version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION")),
            "getinfo must announce the program version"
        );
    }

    #[test]
    fn getutxocommitment_returns_the_state_commitment() {
        let c = context(false);
        let r = call_ok(&c, "getutxocommitment", "{}");
        assert_eq!(r.get("height").and_then(|v| v.as_u64()), Some(0));
        let commitment = r
            .get("commitment")
            .and_then(|v| v.as_str())
            .expect("commitment field");
        assert_eq!(commitment.len(), 64, "a 256-bit digest in hex");
        // It must equal what the chain computes directly: the state
        // commitment, which binds the MuHash to the total issued, and the
        // MuHash alone next to it.
        let (expected, muhash) = c.node.with_chain(|ch| {
            (
                ch.state_commitment().to_hex(),
                ch.utxo_commitment().to_hex(),
            )
        });
        assert_eq!(commitment, expected);
        assert_eq!(
            r.get("muhash").and_then(|v| v.as_str()),
            Some(muhash.as_str())
        );
        assert_ne!(
            commitment, muhash,
            "the state commitment is not the bare MuHash"
        );
    }

    #[test]
    fn getblock_returns_genesis() {
        let c = context(false);
        let r = call_ok(&c, "getblock", r#"{"height":0}"#);
        let e = r.get("header").expect("header");
        assert_eq!(e.get("height").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(r.get("tx_count").and_then(|v| v.as_u64()), Some(1));
        // The genesis coinbase issues exactly the coin.
        let txs = r.get("transactions").and_then(|v| v.as_array()).unwrap();
        assert!(txs[0].get("coinbase") == Some(&Json::Bool(true)));
    }

    #[test]
    fn getblock_without_parameter_returns_the_tip() {
        let c = context(false);
        let r = call_ok(&c, "getblock", "{}");
        assert!(r.get("header").is_some());
    }

    /// The fee is always stated - known, or admitted as unknown.
    ///
    /// A coinbase pays no fee: it collects it. The field therefore exists,
    /// and it is `false`, rather than an amount that would make no sense.
    /// Without an index (the case of this test context), an ordinary spend
    /// would likewise be "unresolved" - never a made-up figure.
    #[test]
    fn gettransaction_states_the_fee_or_admits_not_knowing() {
        let c = context_with_funds();
        let block = call_ok(&c, "getblock", r#"{"height":1}"#);
        let txid = block
            .get("transactions")
            .and_then(|v| v.as_array())
            .unwrap()[0]
            .get("txid")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let r = call_ok(&c, "gettransaction", &format!(r#"{{"txid":"{txid}"}}"#));

        // The field is always there: the page never guesses its absence.
        assert_eq!(
            r.get("fee_known"),
            Some(&Json::Bool(false)),
            "a coinbase pays no fee"
        );
        assert_eq!(r.get("fee"), Some(&Json::Null));
        // One amount per input, aligned with the transaction - here the single
        // coinbase input.
        let m = r
            .get("input_amounts")
            .and_then(|v| v.as_array())
            .expect("input_amounts present");
        assert_eq!(m.len(), 1);
    }

    /// A number with a decimal point is recognized as an amount, in its
    /// canonical form.
    #[test]
    fn search_recognizes_an_amount() {
        let c = context(false);
        let r = call_ok(&c, "search", r#"{"q":"1.5"}"#);
        assert_eq!(r.get("kind").and_then(|v| v.as_str()), Some("amount"));
        assert_eq!(
            r.get("value").and_then(|v| v.as_str()),
            Some("1.50000000"),
            "the amount must come back in its canonical form in Q21"
        );
    }

    /// Search by amount finds an output that exists, and only returns outputs
    /// of that exact amount.
    #[test]
    fn getamount_finds_an_output_of_that_amount() {
        let c = context_with_funds();
        // The exact value of the genesis coin, read from the chain.
        let g = call_ok(&c, "getblock", r#"{"height":0}"#);
        let val = g.get("transactions").and_then(|v| v.as_array()).unwrap()[0]
            .get("outputs")
            .and_then(|v| v.as_array())
            .unwrap()[0]
            .get("value")
            .and_then(|v| v.get("q21"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let r = call_ok(&c, "getamount", &format!(r#"{{"amount":"{val}"}}"#));
        let res = r.get("results").and_then(|v| v.as_array()).unwrap();
        assert!(
            !res.is_empty(),
            "an output of {val} Q21 exists and should be found"
        );
        assert!(
            res.iter().all(|s| s
                .get("value")
                .and_then(|v| v.get("q21"))
                .and_then(|v| v.as_str())
                == Some(val.as_str())),
            "every output returned must be worth exactly the amount searched"
        );
    }

    /// A public context: no wallet, with the scan budget.
    fn public_context() -> RpcContext {
        let mut c = context(false);
        c.scans = Some(Arc::new(Mutex::new(ScanBucket::new())));
        c
    }

    fn ip(s: &str) -> Option<std::net::IpAddr> {
        Some(s.parse().unwrap())
    }

    fn scan_refused(c: &RpcContext, client: Option<std::net::IpAddr>) -> bool {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"getamount","params":{"amount":"1.0"}}"#;
        c.handle_from(body, client).contains("too many searches")
    }

    /// A client that empties its budget does not empty the others'.
    ///
    /// The bucket used to be single: an anonymous visitor looping on
    /// `getamount` deprived the whole public explorer of its search. Each
    /// address now has its own.
    #[test]
    fn one_client_does_not_empty_the_others_bucket() {
        let c = public_context();
        let (a, b) = (ip("198.51.100.7"), ip("203.0.113.9"));
        let mut n = 0;
        while !scan_refused(&c, a) {
            n += 1;
            assert!(n <= SCAN_BURST, "client A is never refused");
        }
        assert_eq!(n, SCAN_BURST, "A has exactly its burst");
        // A has run dry; B has spent nothing.
        assert!(!scan_refused(&c, b), "B is deprived by A's loop");
        // And A stays dry: refusing B gave nothing back to A.
        assert!(scan_refused(&c, a));
        // A batch from A, full of `getamount`, gets no further.
        let batch = format!(
            "[{}]",
            std::iter::repeat_n(
                r#"{"jsonrpc":"2.0","id":1,"method":"getamount","params":{"amount":"1.0"}}"#,
                MAX_BATCH
            )
            .collect::<Vec<_>>()
            .join(",")
        );
        let r = c.handle_from(&batch, a);
        assert_eq!(r.matches("too many searches").count(), MAX_BATCH);
        assert!(!scan_refused(&c, b), "B is deprived by A's batch");
    }

    /// The bucket itself: burst per client, `/64` in IPv6, bounded table with
    /// eviction of the least recently seen, and a global net that holds on its
    /// own.
    #[test]
    fn the_bucket_tells_clients_apart_and_stays_bounded() {
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        let mut s = ScanBucket::new();
        let a = ip("198.51.100.7").unwrap();
        let b = ip("203.0.113.9").unwrap();

        // Each one has its own burst.
        for _ in 0..SCAN_BURST {
            assert!(s.allow(Some(a), t0));
        }
        assert!(!s.allow(Some(a), t0));
        assert!(s.allow(Some(b), t0));

        // The refill is per client: one minute gives A its quota back.
        let t1 = t0 + Duration::from_secs(60);
        for _ in 0..SCANS_PER_MINUTE {
            assert!(s.allow(Some(a), t1));
        }
        assert!(!s.allow(Some(a), t1));

        // Two addresses from the same IPv6 /64 share a bucket; two distinct
        // /64s do not.
        let v6a = ip("2001:db8:1:2::1").unwrap();
        let v6b = ip("2001:db8:1:2:ffff::9").unwrap();
        let v6c = ip("2001:db8:1:3::1").unwrap();
        for _ in 0..SCAN_BURST {
            assert!(s.allow(Some(v6a), t1));
        }
        assert!(!s.allow(Some(v6b), t1), "same /64: same bucket");
        assert!(s.allow(Some(v6c), t1), "other /64: other bucket");
        // An IPv4 carried in IPv6 is the IPv4.
        assert!(!s.allow(ip("::ffff:198.51.100.7"), t1));

        // The table is bounded: the least recently seen goes away. Here we
        // talk to the table alone - the net, narrower than the table, would
        // refuse before it is full, and that is its role.
        let mut s = ScanBucket::new();
        let key = |ip: std::net::IpAddr| ClientKey::from_ip(ip);
        for i in 0..MAX_TRACKED_CLIENTS {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, (i >> 8) as u8, i as u8, 1));
            assert!(s.allow_client(key(ip), t0 + Duration::from_millis(i as u64)));
        }
        assert_eq!(s.tracked_clients(), MAX_TRACKED_CLIENTS);
        let first = ip("10.0.0.1").unwrap();
        // The first comer has already spent a token.
        assert!(s.allow_client(key(first), t0));
        let newcomer = ip("192.0.2.1").unwrap();
        assert!(s.allow_client(key(newcomer), t0 + Duration::from_secs(1)));
        assert_eq!(
            s.tracked_clients(),
            MAX_TRACKED_CLIENTS,
            "the table does not grow"
        );
        // The first comer, least recently seen, is gone: it comes back with a
        // fresh burst - the proof that it was indeed evicted.
        for _ in 0..SCAN_BURST {
            assert!(s.allow_client(key(first), t0 + Duration::from_secs(1)));
        }
        assert!(!s.allow_client(key(first), t0 + Duration::from_secs(1)));

        // The global net holds on its own against ever-new clients.
        let mut s = ScanBucket::new();
        let mut granted = 0u32;
        for i in 0..(GLOBAL_SCAN_BURST + 50) {
            let ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, (i >> 8) as u8, i as u8));
            if s.allow(Some(ip), t0) {
                granted += 1;
            }
        }
        assert_eq!(granted, GLOBAL_SCAN_BURST, "the net must bound the total");
        // A client without an address only goes through the net, already dry.
        assert!(!s.allow(None, t0));
        // A dry client does not charge the net: it is refused before.
        let mut s = ScanBucket::new();
        for _ in 0..SCAN_BURST {
            assert!(s.allow(Some(a), t0));
        }
        for _ in 0..1000 {
            assert!(!s.allow(Some(a), t0));
        }
        assert!(s.allow(Some(b), t0), "A's refusals emptied the net");
    }

    /// A single send pays several recipients: the transaction does carry all
    /// their outputs, and the change comes back to the wallet.
    #[test]
    fn sendmany_pays_several_recipients_in_one_transaction() {
        let c = context_with_funds();
        let mut other = Wallet::from_seed([0x11; 32], NETWORK);
        let a1 = other.new_address().to_string_bech32();
        let a2 = other.new_address().to_string_bech32();

        let params = format!(
            r#"{{"destinations":[{{"address":"{a1}","units":100000}},{{"address":"{a2}","units":200000}}]}}"#
        );
        let r = call_ok(&c, "sendmany", &params);

        assert!(
            r.get("txid").and_then(|v| v.as_str()).is_some(),
            "an accepted send must return an id"
        );
        assert_eq!(r.get("recipients").and_then(|v| v.as_u64()), Some(2));

        let outputs = r
            .get("transaction")
            .and_then(|t| t.get("outputs"))
            .and_then(|v| v.as_array())
            .expect("outputs present");
        // Two recipients, plus the change: at least two outputs.
        assert!(outputs.len() >= 2);
        let units: Vec<u64> = outputs
            .iter()
            .filter_map(|s| {
                s.get("value")
                    .and_then(|v| v.get("units"))
                    .and_then(|v| v.as_u64())
            })
            .collect();
        assert!(
            units.contains(&100_000) && units.contains(&200_000),
            "both requested amounts must appear among the outputs: {units:?}"
        );
    }

    /// A send without a recipient is cleanly refused, not built empty.
    #[test]
    fn sendmany_refuses_an_empty_list() {
        let c = context_with_funds();
        let r = call(&c, "sendmany", r#"{"destinations":[]}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_PARAMS)
        );
    }

    #[test]
    fn a_nonexistent_height_is_a_clean_error() {
        let c = context(false);
        let r = call(&c, "getblock", r#"{"height":9999}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_NOT_FOUND)
        );
    }

    #[test]
    fn an_unknown_method_is_reported() {
        let c = context(false);
        let r = call(&c, "doesnotexist", "{}");
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_METHOD)
        );
    }

    #[test]
    fn an_unreadable_document_returns_a_parse_error() {
        let c = context(false);
        let r = jparse(&c.handle("{this is not json")).unwrap();
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_PARSE)
        );
    }

    /// The separation that keeps a read-only port from becoming a spending
    /// port.
    #[test]
    fn wallet_methods_are_refused_by_default() {
        let c = context(false);
        for m in ["getbalance", "getnewaddress", "sendtoaddress"] {
            let r = call(&c, m, "{}");
            assert_eq!(
                r.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|v| v.as_i64()),
                Some(ERR_WALLET_DISABLED),
                "{m} should have been refused"
            );
        }
    }

    #[test]
    fn wallet_methods_answer_when_it_is_enabled() {
        let c = context(true);
        let r = call_ok(&c, "getbalance", "{}");
        assert_eq!(
            r.get("spendable")
                .and_then(|m| m.get("units"))
                .and_then(|v| v.as_u64()),
            Some(0)
        );

        let a = call_ok(&c, "getnewaddress", "{}");
        let addr = a.get("address").and_then(|v| v.as_str()).unwrap();
        assert!(addr.starts_with("rq21"), "unexpected address: {addr}");
        assert!(
            a.get("warning").is_some(),
            "the one-time use must be pointed out"
        );
    }

    /// No amount may travel as a float.
    ///
    /// The check is indirect but strong: the `crate::json` parser **rejects**
    /// floats. If the encoder produced one, reading the response back would
    /// fail. Every method is therefore put through the round trip.
    #[test]
    fn no_response_contains_a_float() {
        let c = context(true);
        for (m, p) in [
            ("getinfo", "{}"),
            ("getsupply", "{}"),
            ("getemission", r#"{"height":1051200}"#),
            ("getblock", r#"{"height":0}"#),
            ("getpow", "{}"),
            ("getsecurity", "{}"),
            ("getbalance", "{}"),
            ("getmempool", "{}"),
        ] {
            let raw = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}","params":{p}}}"#);
            let out = c.handle(&raw);
            assert!(
                jparse(&out).is_ok(),
                "{m} produces a document our own parser rejects - \
                 a sign that a float slipped in: {out}"
            );
        }

        // And the shape of amounts stays the promised one: integer plus text.
        let r = call_ok(&c, "getsupply", "{}");
        let issued = r.get("issued").unwrap();
        assert!(issued.get("units").and_then(|v| v.as_u64()).is_some());
        assert_eq!(
            issued.get("q21").and_then(|v| v.as_str()),
            Some("1.00000000")
        );
    }

    #[test]
    fn getsecurity_does_not_only_say_what_reassures() {
        let c = context(false);
        let r = call_ok(&c, "getsecurity", "{}");
        assert_eq!(
            r.get("full_protection_possible"),
            Some(&Json::Bool(false)),
            "the API must not suggest any immunity"
        );
        assert!(
            r.get("an_attacker_can")
                .and_then(|v| v.as_array())
                .unwrap()
                .len()
                >= 2
        );
        assert!(r.get("rolling_finality_cost").is_some());
    }

    /// The balance says when the next sum will be released.
    ///
    /// Without that, the interface announces "awaiting maturity" and nothing
    /// else: a miner sees their earnings rise and their available balance stay
    /// at zero for hours, with no landmark. The question in front of a locked
    /// balance is not "how much", it is "when".
    #[test]
    fn the_balance_announces_the_next_maturity() {
        let c = context_with_funds();
        let r = call_ok(&c, "getbalance", "{}");
        // The test chain mines past maturity: so there are still immature
        // coinbases at the top, and the response must date them.
        assert!(
            r.get("next_maturity_height").is_some(),
            "no release date announced: {}",
            r.encode()
        );
        let blocks = r
            .get("next_maturity_blocks")
            .and_then(|v| v.as_u64())
            .expect("blocks remaining");
        assert!(
            blocks > 0 && blocks <= COINBASE_MATURITY,
            "absurd wait: {blocks}"
        );
        assert!(r.get("next_maturity_amount").is_some());

        // And the constants that make it possible to turn this wait into time
        // come from the node, so they are written in only one place in the
        // world.
        let i = call_ok(&c, "getinfo", "{}");
        assert_eq!(
            i.get("coinbase_maturity").and_then(|v| v.as_u64()),
            Some(COINBASE_MATURITY)
        );
        assert_eq!(
            i.get("target_interval_seconds").and_then(|v| v.as_u64()),
            Some(TARGET_BLOCK_SECS)
        );
    }

    /// An unreadable block does not silently make a payment disappear.
    ///
    /// # The incident this test pins down
    ///
    /// The history scan used to skip without a word the heights whose body
    /// could not be read. On a real network, after a hard shutdown and a
    /// resync, a received transfer had purely and simply vanished from the
    /// history - while the balance still counted it. A wallet that loses a
    /// row without saying so is worse than a broken wallet: people believe it.
    #[test]
    fn the_history_admits_the_blocks_it_could_not_read() {
        // The response always carries the count, even when it is zero: a
        // caller must not have to tell "missing field" from "zero".
        let c = context(true);
        let r = call_ok(&c, "listtransactions", r#"{"limit":5}"#);
        assert_eq!(
            r.get("unreadable_blocks").and_then(|v| v.as_u64()),
            Some(0),
            "the count must be announced even at zero"
        );
        assert_eq!(r.get("complete_history"), Some(&Json::Bool(true)));
        // And the text of the RPC page must name the remedy, not only the
        // problem.
        let s = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"listtransactions"}"#);
        assert!(s.contains("complete_history"));
    }

    /// An address gets a name, and the name comes back with the list.
    ///
    /// Q21 encourages one address per correspondent. Without an address book,
    /// after a month you end up with four hundred strings of characters and
    /// no idea who is who: the address book gives back to the owner what
    /// privacy cost them.
    #[test]
    fn an_address_gets_a_name_and_the_name_comes_back() {
        let c = context(true);
        let _ = call_ok(&c, "getnewaddress", "{}");
        let r = call_ok(
            &c,
            "setaddresslabel",
            r#"{"key_index":0,"label":"for the plumber"}"#,
        );
        assert_eq!(
            r.get("label").and_then(|v| v.as_str()),
            Some("for the plumber")
        );

        let list = call_ok(&c, "listaddresses", "{}");
        let a = list.as_array().expect("array of addresses");
        assert_eq!(
            a[0].get("label").and_then(|v| v.as_str()),
            Some("for the plumber"),
            "the name must come back with the address it designates"
        );

        // An empty name erases, and the address goes back to having no
        // `label` field: an empty string would force every caller to tell
        // "no name" from "named with nothing".
        let _ = call_ok(&c, "setaddresslabel", r#"{"key_index":0,"label":""}"#);
        let list = call_ok(&c, "listaddresses", "{}");
        assert!(list.as_array().expect("array")[0].get("label").is_none());
    }

    /// `listaddresses` says which ones the owner requested.
    ///
    /// The interface files away the addresses derived by mining and only shows
    /// first the ones the owner really handed out. It can only do so if the
    /// node tells it.
    #[test]
    fn the_list_tells_requested_addresses_from_mining_ones() {
        let c = context(true);
        // An address derived without going through `getnewaddress`: the
        // mining one.
        {
            let w = c.wallet.as_ref().expect("wallet");
            let mut g = w.lock().expect("lock");
            let _ = g.new_address();
        }
        let _ = call_ok(&c, "getnewaddress", "{}");
        let list = call_ok(&c, "listaddresses", "{}");
        let a = list.as_array().expect("array of addresses");
        assert_eq!(a.len(), 2);
        assert!(
            matches!(a[0].get("requested"), Some(Json::Bool(false))),
            "the mining address is not requested"
        );
        assert!(
            matches!(a[1].get("requested"), Some(Json::Bool(true))),
            "the `getnewaddress` address is requested"
        );
    }

    /// An address that does not exist cannot be named.
    ///
    /// Accepting it would leave orphan names in the file and would hide a
    /// typo by the caller.
    #[test]
    fn naming_a_nonexistent_address_is_refused() {
        let c = context(true);
        let r = call(&c, "setaddresslabel", r#"{"key_index":9999,"label":"x"}"#);
        assert!(r.get("error").is_some(), "an unknown index must be refused");
    }

    /// The wallet is never written under the chain lock.
    ///
    /// # The defect this test pins down
    ///
    /// The write-ahead - which is necessary - was done under the chain and
    /// mempool lock, and writing the wallet means sealing it: Argon2id, a
    /// third of a second on a PC, a second on a Raspberry Pi. Block validation
    /// and serving peers stopped at every send.
    ///
    /// The save callback plays the role of sealing here: at each call, another
    /// thread tries to take the chain lock. If it does not manage within the
    /// time limit, the send was holding it during the write.
    #[test]
    fn the_wallet_is_not_written_under_the_chain_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut c = context_with_funds();
        let node = c.node.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(0));
        let (a, t) = (calls.clone(), held.clone());
        c.on_change = Some(Arc::new(move |_w: &Wallet| {
            a.fetch_add(1, Ordering::SeqCst);
            let n = node.clone();
            let probe = std::thread::spawn(move || n.with_chain(|c| c.height()));
            let start = std::time::Instant::now();
            while !probe.is_finished() {
                if start.elapsed() > std::time::Duration::from_millis(1500) {
                    t.fetch_add(1, Ordering::SeqCst);
                    // We do not join: the thread will finish when the lock is
                    // released, after this call.
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let _ = probe.join();
            Ok(())
        }));
        let mut dest = Wallet::from_seed([0xcc; 32], NETWORK);
        let address = dest.new_address().to_string_bech32();
        let sent = call_ok(
            &c,
            "sendtoaddress",
            &format!(r#"{{"address":"{address}","units":100000}}"#),
        );
        assert!(sent.get("txid").is_some());
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "the write-ahead and the final write must both have happened"
        );
        assert_eq!(
            held.load(Ordering::SeqCst),
            0,
            "FINDING: the chain lock was held while the wallet was being written"
        );
        assert_eq!(c.node.mempool_len(), 1);
    }

    /// A send on a one-time scheme first rereads the blocks the wallet has not
    /// seen yet, and refuses if bodies are missing.
    ///
    /// Restored on a new machine, a Lamport wallet learns its addresses
    /// through discovery without knowing which ones have already signed.
    /// Signing in that state can sign again with a key revealed in a block.
    /// The send therefore catches up with the chain before choosing its
    /// coins; and if the bodies are not there to do so, it refuses rather than
    /// sign blindly.
    #[test]
    fn a_one_time_send_catches_up_with_the_chain_or_refuses() {
        // A chain where index 0 receives all the coinbases and then spends
        // one: its key is revealed in a block.
        let seed = [0x21u8; 32];
        let mut origin = Wallet::from_seed(seed, NETWORK);
        let a0 = origin.new_address();
        let g = genesis_block(NETWORK);
        let mut chain = Chain::new(NETWORK, g);
        for i in 1..=(COINBASE_MATURITY + 2) {
            let t = crate::chain::GENESIS_TIME + i * TARGET_BLOCK_SECS;
            let b = chain
                .mine_block(a0.hash, a0.scheme, &[], t, 5_000_000)
                .expect("mining");
            chain.connect(&b, t + 1).expect("connect");
        }
        let mut third_party = Wallet::from_seed([0x99; 32], NETWORK);
        let dest = third_party.new_address();
        let tx1 = origin
            .create_transaction(
                &chain.utxo,
                chain.height(),
                &dest,
                Amount::from_units(50_000),
                Amount::from_units(1_000),
            )
            .unwrap();
        let pk0 = tx1.inputs[0].witness.pubkey.clone();
        let t = crate::chain::GENESIS_TIME + (COINBASE_MATURITY + 3) * TARGET_BLOCK_SECS;
        let b = chain
            .mine_block(a0.hash, a0.scheme, &[tx1], t, 5_000_000)
            .unwrap();
        chain.connect(&b, t + 1).unwrap();

        // A restored wallet: discovery only, no scan.
        let restore = |chain: &Chain| {
            let mut r = Wallet::from_seed(seed, NETWORK);
            assert!(r.discover(|h| chain.utxo.knows(h)) > 0);
            assert!(!r.is_consumed(0));
            assert_eq!(r.verified_up_to(), 0);
            r
        };
        let make_context = |chain: Chain, w: Wallet| RpcContext {
            on_change: None,
            scans: None,
            configured_bootstrap: 0,
            reachable: std::sync::atomic::AtomicBool::new(true),
            reachable_session: true,
            router_status: None,
            set_reachable: None,
            index: None,
            mining: None,
            node: Arc::new(Node::new(NETWORK, chain)),
            wallet: Some(Arc::new(Mutex::new(w))),
            network: NETWORK,
        };

        // 1. The bodies are missing - a chain restarted from a snapshot, with
        //    no body provider: the send is refused, nothing is reserved.
        let snapshot = chain.snapshot_at_depth(1).expect("snapshot");
        let headers = chain.headers();
        let without_bodies = Chain::from_snapshot(NETWORK, snapshot, &headers)
            .expect("resume")
            .chain;
        assert!(
            without_bodies.block_at(1).is_none(),
            "the bodies must be missing"
        );
        let restored = restore(&without_bodies);
        let c = make_context(without_bodies, restored);
        let r = call(
            &c,
            "sendtoaddress",
            &format!(
                r#"{{"address":"{}","units":50000}}"#,
                dest.to_string_bech32()
            ),
        );
        let message = r
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        assert!(
            message.contains("scanned"),
            "the send must be refused for lack of a scan: {}",
            r.encode()
        );
        let w = c.wallet.as_ref().unwrap().lock().unwrap();
        assert!(w.reserved_indices().is_empty() && w.consumed_indices().is_empty());
        drop(w);

        // 2. The bodies are there: the send catches up with the chain, and key
        //    0 does not sign again. The balance requested covers everything:
        //    without key 0 a coin is missing, and the send is refused for
        //    insufficient funds - that is the expected behavior, the reverse
        //    was the defect.
        let restored = restore(&chain);
        let balance = restored.balance(&chain.utxo, chain.height()).units();
        let c = make_context(chain, restored);
        let r = call(
            &c,
            "sendtoaddress",
            &format!(
                r#"{{"address":"{}","units":{}}}"#,
                dest.to_string_bech32(),
                balance - 1_000
            ),
        );
        let w = c.wallet.as_ref().unwrap().lock().unwrap();
        assert_eq!(
            w.verified_up_to(),
            c.node.height(),
            "the chain has been caught up"
        );
        assert!(
            w.is_consumed(0),
            "key 0, revealed in a block, must be consumed"
        );
        drop(w);
        let message = r
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        assert!(
            message.contains("insufficient funds"),
            "without key 0, the whole balance is no longer covered: {}",
            r.encode()
        );
        let resigned = c.node.with_mempool(|m| {
            m.ordered_transactions()
                .iter()
                .any(|t| t.inputs.iter().any(|e| e.witness.pubkey == pk0))
        });
        assert!(!resigned, "FINDING: key 0 signed again");

        // And a send that fits without key 0 goes through.
        let sent = call_ok(
            &c,
            "sendtoaddress",
            &format!(
                r#"{{"address":"{}","units":50000}}"#,
                dest.to_string_bech32()
            ),
        );
        assert!(sent.get("txid").is_some());
        let resigned = c.node.with_mempool(|m| {
            m.ordered_transactions()
                .iter()
                .any(|t| t.inputs.iter().any(|e| e.witness.pubkey == pk0))
        });
        assert!(!resigned, "FINDING: key 0 signed again");
    }

    /// A funded wallet that sends, then mines `after` more blocks: the send
    /// sinks under the mining rewards, as on the 0.4.1 testnet.
    fn context_send_then_mine(after: u64, with_index: bool) -> (RpcContext, String) {
        let mut c = context_with_funds();
        let mut dest = Wallet::from_seed([0xcd; 32], NETWORK);
        let address = dest.new_address().to_string_bech32();
        let sent = call_ok(
            &c,
            "sendtoaddress",
            &format!(r#"{{"address":"{address}","units":100000}}"#),
        );
        let txid = sent
            .get("txid")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let w = c.wallet.clone().unwrap();
        c.node.with_chain_and_mempool(|ch, m| {
            for i in 0..=after {
                let pool: Vec<crate::tx::Transaction> = if i == 0 {
                    m.txids()
                        .iter()
                        .filter_map(|id| m.get(id).cloned())
                        .collect()
                } else {
                    Vec::new()
                };
                let a = w.lock().unwrap().new_address();
                let t =
                    crate::chain::GENESIS_TIME + (COINBASE_MATURITY + 4 + i) * TARGET_BLOCK_SECS;
                let b = ch
                    .mine_block(a.hash, a.scheme, &pool, t, 5_000_000)
                    .expect("mining");
                ch.connect(&b, t + 1).expect("connect");
                m.on_block_connected(&b);
            }
        });
        if with_index {
            let d = std::env::temp_dir().join(format!(
                "q21-rpc-index-{}-{}",
                std::process::id(),
                after
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            let mut index = crate::index::Index::open(&d.join("index.dat"));
            c.node.with_chain(|ch| {
                for h in 0..=ch.height() {
                    index.index_block(&ch.block_at(h).unwrap()).unwrap();
                }
            });
            c.index = Some(Arc::new(Mutex::new(index)));
        }
        (c, txid)
    }

    fn rows(r: &Json) -> Vec<Json> {
        r.get("movements")
            .and_then(|v| v.as_array())
            .unwrap()
            .to_vec()
    }

    /// The defect of 0.4.1: with a hundred mining rewards after it, a send
    /// fell out of the hundred rows the page asked for, and the "Sent" filter,
    /// applied by the page to those rows, showed nothing. The filter now runs
    /// in the node, before the limit.
    #[test]
    fn a_send_is_not_hidden_behind_mining_rewards() {
        let (c, txid) = context_send_then_mine(120, false);
        let all = call_ok(&c, "listtransactions", r#"{"limit":100}"#);
        assert!(
            rows(&all)
                .iter()
                .all(|m| m.get("kind").and_then(|v| v.as_str()) == Some("mining")),
            "the precondition: a hundred rewards bury the send"
        );
        let sends = call_ok(&c, "listtransactions", r#"{"limit":100,"kind":"send"}"#);
        let sends = rows(&sends);
        assert_eq!(sends.len(), 1);
        assert_eq!(
            sends[0].get("txid").and_then(|v| v.as_str()),
            Some(txid.as_str())
        );
        assert_eq!(
            sends[0].get("amount_out_known"),
            Some(&Json::Bool(true)),
            "the coins it spent were found on the way back"
        );
        let r = call(&c, "listtransactions", r#"{"kind":"gift"}"#);
        assert!(r.get("error").is_some(), "an unknown kind is refused");
    }

    /// With the address index, the history covers the whole chain, says so,
    /// and gives the same rows as the scan.
    #[test]
    fn with_the_index_the_history_is_complete() {
        let (scan, _) = context_send_then_mine(30, false);
        let (indexed, txid) = context_send_then_mine(30, true);
        let a = call_ok(&scan, "listtransactions", r#"{"limit":500}"#);
        let b = call_ok(&indexed, "listtransactions", r#"{"limit":500}"#);
        assert_eq!(b.get("complete_history"), Some(&Json::Bool(true)));
        assert_eq!(
            b.get("scanned_from_height").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            rows(&a),
            rows(&b),
            "the index changes the cost, not the answer"
        );
        let sends = call_ok(&indexed, "listtransactions", r#"{"kind":"send"}"#);
        assert_eq!(
            rows(&sends)[0].get("txid").and_then(|v| v.as_str()),
            Some(txid.as_str())
        );
    }

    /// A send shows in the history **before** it is in a block.
    ///
    /// That is the defect this test pins down. The history only read blocks:
    /// between the moment you press "Send" and the block that includes the
    /// transaction - two minutes on average, more if the network is busy - the
    /// payment appeared nowhere, while the balance had already dropped.
    /// Observed on a real node, by someone who thought their money was lost.
    #[test]
    fn a_send_appears_in_the_history_from_the_mempool() {
        let c = context_with_funds();
        let mut dest = Wallet::from_seed([0xcc; 32], NETWORK);
        let address = dest.new_address().to_string_bech32();

        // Nothing pending before the send: what follows really measures the
        // effect of the send, and not a row left lying around.
        let before = call_ok(&c, "listtransactions", r#"{"limit":5}"#);
        assert!(
            before
                .get("movements")
                .and_then(|v| v.as_array())
                .expect("movements")
                .iter()
                .all(|m| m.get("pending").is_none()),
            "no row may be pending before the send"
        );

        let sent = call_ok(
            &c,
            "sendtoaddress",
            &format!(r#"{{"address":"{address}","units":100000}}"#),
        );
        let txid = sent
            .get("txid")
            .and_then(|v| v.as_str())
            .expect("txid")
            .to_string();
        assert_eq!(
            c.node.mempool_len(),
            1,
            "the transaction must be in the mempool"
        );

        let after = call_ok(&c, "listtransactions", r#"{"limit":5}"#);
        let movements = after
            .get("movements")
            .and_then(|v| v.as_array())
            .expect("movements");
        assert_eq!(
            movements
                .iter()
                .filter(|m| m.get("pending").is_some())
                .count(),
            1,
            "the send must add exactly one pending row"
        );

        // The most recent is at the top: it is the one people look for.
        let l = &movements[0];
        assert_eq!(l.get("txid").and_then(|v| v.as_str()), Some(txid.as_str()));
        assert_eq!(l.get("pending"), Some(&Json::Bool(true)));
        assert_eq!(
            l.get("confirmations").and_then(|v| v.as_u64()),
            Some(0),
            "nothing confirms it yet, and that must be said"
        );
        assert_eq!(
            l.get("height"),
            Some(&Json::Null),
            "no height as long as no block carries it: zero would be genesis"
        );
        assert_eq!(l.get("kind").and_then(|v| v.as_str()), Some("send"));
        // The committed amount is read from the UTXO set: the mempool does not
        // touch it, so the consumed coins are still there.
        assert_eq!(l.get("amount_out_known"), Some(&Json::Bool(true)));
        assert!(
            l.get("net_out")
                .and_then(|v| v.get("units"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                >= 100_000,
            "the outgoing amount must be announced, not left at zero"
        );
    }

    /// A pending transaction is not counted as confirmed.
    ///
    /// The reverse would be worse than the original silence: showing
    /// "confirmed" for something that can still be evicted from the mempool
    /// would get goods shipped against a payment that does not exist.
    #[test]
    fn the_mempool_does_not_pass_itself_off_as_a_block() {
        let c = context_with_funds();
        let mut dest = Wallet::from_seed([0xcd; 32], NETWORK);
        let address = dest.new_address().to_string_bech32();
        let _ = call_ok(
            &c,
            "sendtoaddress",
            &format!(r#"{{"address":"{address}","units":100000}}"#),
        );
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"listtransactions"}"#);
        assert!(r.contains("\"pending\":true"));
        // Keys are serialized in alphabetical order, so `pending` and `kind`
        // are not adjacent: check each pending movement instead.
        let h = call_ok(&c, "listtransactions", "{}");
        let movements = h
            .get("movements")
            .and_then(|m| m.as_array())
            .expect("movements");
        for m in movements {
            if m.get("pending") == Some(&Json::Bool(true)) {
                assert_ne!(
                    m.get("kind").and_then(|k| k.as_str()),
                    Some("mining"),
                    "a coinbase never goes through the mempool"
                );
            }
        }
    }

    /// The address book is reported, and it does not claim to count the
    /// network.
    #[test]
    fn getnetworkhashrate_reports_the_address_book_without_claiming_to_count() {
        let c = context(false);
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getnetworkhashrate"}"#);
        assert!(
            r.contains("\"address_book\""),
            "the address book must be reported: {r}"
        );
        // The name matters: "address book" says what it is - learned
        // addresses - where "machines" would have suggested a headcount of the
        // network.
        assert!(!r.contains("\"machines\":"));
    }

    /// The network is measured in work, and refuses to count miners.
    ///
    /// The temptation was to count the distinct miner key hashes. This test
    /// pins down the refusal: the response must contain no field that claims
    /// to count people or machines.
    #[test]
    fn getnetworkhashrate_measures_work_and_counts_nobody() {
        let c = context(false);
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getnetworkhashrate"}"#);
        for expected in [
            "\"peers\"",
            "\"blocks_examined\"",
            "\"network_rate_milli\"",
            "\"total_work\"",
            "\"measurable\"",
        ] {
            assert!(r.contains(expected), "missing field: {expected} in {r}");
        }
        // We look for **keys**, not words: the note rightly uses the word
        // "miners" to say that they are not counted. A first draft of this
        // test looked for the bare substring and ran into its own
        // explanation.
        for forbidden in [
            "\"miners\":",
            "\"miner_count\":",
            "\"number_of_miners\":",
            "\"machines\":",
        ] {
            assert!(
                !r.contains(forbidden),
                "the response claims to count what cannot be counted: {forbidden}"
            );
        }
        // And it must say so, not merely refrain from it.
        assert!(
            r.contains("cannot be known"),
            "the response does not say why it does not count miners"
        );
    }

    /// Genesis is never the anchor of the measurement.
    ///
    /// Its timestamp is a protocol constant. Including it measured the
    /// distance between that constant and today: on a chain mined in nine
    /// seconds, the response announced "371.8 days".
    #[test]
    fn genesis_is_not_used_as_the_starting_point() {
        let g = genesis_block(NETWORK);
        let mut chain = Chain::new(NETWORK, g);
        // Three blocks mined now, very far from the genesis timestamp.
        let now = chain.tip().time + 10_000_000;
        for i in 0..3u64 {
            let t = now + i;
            let b = chain
                .mine_block(Hash256([7u8; 32]), SchemeId::LamportOts, &[], t, 5_000_000)
                .expect("mining");
            chain.connect(&b, t + 1).expect("connect");
        }
        let node = Arc::new(Node::new(NETWORK, chain));
        let c = RpcContext {
            on_change: None,
            scans: None,
            configured_bootstrap: 0,
            reachable: std::sync::atomic::AtomicBool::new(true),
            reachable_session: true,
            router_status: None,
            set_reachable: None,
            index: None,
            mining: None,
            node,
            wallet: None,
            network: NETWORK,
        };
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getnetworkhashrate"}"#);
        // Three blocks one second apart: the measured span must stay small,
        // and not be worth the ten million seconds that separate them from
        // genesis.
        let d = r
            .find("\"seconds_examined\":")
            .map(|i| {
                r[i + "\"seconds_examined\":".len()..]
                    .split(&[',', '}'][..])
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .expect("field present");
        let seconds: u64 = d.trim().parse().expect("a number");
        assert!(
            seconds < 100,
            "genesis is still used as the anchor: {seconds} seconds measured"
        );
    }

    /// A chain of a single block does not produce an infinite rate.
    ///
    /// On genesis alone, the time span of the window is zero. Dividing by it
    /// would give a division by zero, or worse an enormous figure shown as a
    /// measurement.
    #[test]
    fn a_network_without_history_admits_it_measures_nothing() {
        let c = context(false);
        let r = c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getnetworkhashrate"}"#);
        assert!(r.contains(r#""measurable":false"#), "{r}");
        assert!(r.contains(r#""network_rate_milli":"0""#), "{r}");
    }

    #[test]
    fn block_work_saturates_instead_of_overflowing() {
        // Work that does not fit in 128 bits must return the cap, and not
        // zero: a zero would read as "the network has stopped".
        let huge = crate::uint::U256::from_be_bytes(&[0xff; 32]);
        assert_eq!(work_to_u128(huge), u128::MAX);
        assert_eq!(work_to_u128(crate::uint::U256::ZERO), 0);
    }

    #[test]
    fn getpow_exposes_the_asymmetry_between_node_and_miner() {
        let c = context(false);
        let r = call_ok(&c, "getpow", "{}");
        let node = r
            .get("node_memory_bytes")
            .and_then(|v| v.as_u64())
            .expect("node_memory_bytes");
        let miner = r
            .get("miner_memory_bytes")
            .and_then(|v| v.as_u64())
            .expect("miner_memory_bytes");

        // This test used to assert `node == 0`. Phase 6 showed that this
        // free ride was precisely what made the proof of work bypassable: a
        // table element was recomputed for the price of one hash. The
        // asymmetry remains, it is simply no longer infinite.
        assert!(node > 0, "a node now holds the cache");
        assert!(miner > node, "and a miner holds much more");
        assert_eq!(
            miner / node,
            u64::from(POW_CACHE_RATIO),
            "the ratio between the two levels is a consensus constant"
        );
    }

    #[test]
    fn a_batch_of_requests_is_handled() {
        let c = context(false);
        let body = r#"[{"jsonrpc":"2.0","id":1,"method":"getinfo"},
                        {"jsonrpc":"2.0","id":2,"method":"getsupply"}]"#;
        let r = jparse(&c.handle(body)).expect("response");
        let v = r.as_array().expect("an array of responses");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].get("id").and_then(|x| x.as_u64()), Some(1));
        assert_eq!(v[1].get("id").and_then(|x| x.as_u64()), Some(2));
    }

    #[test]
    fn listmethods_documents_the_api() {
        let c = context(false);
        let r = call_ok(&c, "listmethods", "{}");
        let v = r.as_array().expect("array");
        assert!(v.len() >= 10);
        assert!(v
            .iter()
            .all(|m| m.get("name").is_some() && m.get("description").is_some()));
    }

    #[test]
    fn an_unknown_transaction_is_reported() {
        let c = context(false);
        let r = call(&c, "gettransaction", r#"{"txid":"00"}"#);
        assert!(r.get("error").is_some());
    }

    #[test]
    fn getemission_follows_the_curve() {
        let c = context(false);
        let r = call_ok(&c, "getemission", r#"{"height":1051200}"#);
        assert_eq!(r.get("approx_year").and_then(|v| v.as_u64()), Some(4));
        let cumulative = r
            .get("cumulative_issued")
            .and_then(|m| m.get("units"))
            .and_then(|v| v.as_u64())
            .unwrap();
        assert!(cumulative <= MAX_SUPPLY, "the cap must never be exceeded");
    }

    /// Search recognizes a height.
    #[test]
    fn search_recognizes_a_height() {
        let c = context(false);
        let r = call_ok(&c, "search", r#"{"q":"0"}"#);
        assert_eq!(r.get("kind").and_then(|v| v.as_str()), Some("block"));
        assert_eq!(r.get("value").and_then(|v| v.as_str()), Some("0"));
    }

    /// A height above the tip is refused, and says so.
    #[test]
    fn search_refuses_a_missing_height() {
        let c = context(false);
        let r = call(&c, "search", r#"{"q":"999999"}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_NOT_FOUND)
        );
    }

    /// Search recognizes a block id.
    #[test]
    fn search_recognizes_a_block_id() {
        let c = context(false);
        let id = c
            .node
            .with_chain(|ch| ch.block_at(0).unwrap().header.block_id());
        let r = call_ok(&c, "search", &format!(r#"{{"q":"{}"}}"#, id.to_hex()));
        assert_eq!(r.get("kind").and_then(|v| v.as_str()), Some("block-id"));
    }

    /// Search recognizes an address, and refuses one from another network.
    ///
    /// An address carries its own checksum **and** its network. Letting a
    /// mainnet address through on a test node would look for one chain in
    /// another: the answer would be "nothing found", which is true and
    /// thoroughly misleading.
    #[test]
    fn search_recognizes_an_address_and_refuses_another_network() {
        let c = context(true);
        let a = {
            let mut w = c.wallet.as_ref().unwrap().lock().unwrap();
            w.new_address()
        };
        let r = call_ok(
            &c,
            "search",
            &format!(r#"{{"q":"{}"}}"#, a.to_string_bech32()),
        );
        assert_eq!(r.get("kind").and_then(|v| v.as_str()), Some("address"));

        let foreign = crate::address::Address {
            network: Network::Mainnet,
            scheme: a.scheme,
            hash: a.hash,
        };
        let r = call(
            &c,
            "search",
            &format!(r#"{{"q":"{}"}}"#, foreign.to_string_bech32()),
        );
        assert!(
            r.get("error").is_some(),
            "an address from another network was accepted"
        );
    }

    /// Input that is nothing at all is refused without any work.
    #[test]
    fn search_refuses_what_is_nothing() {
        let c = context(false);
        for q in ["hello", "", "0x1234", &"a".repeat(300)] {
            let r = call(&c, "search", &format!(r#"{{"q":"{q}"}}"#));
            assert!(r.get("error").is_some(), "wrongly accepted: {q}");
        }
    }

    fn kind_and_value(r: &Json) -> (String, String) {
        (
            r.get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            r.get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        )
    }

    /// What people paste, not what the node prints: an address selected by
    /// hand in its groups of eight, in capitals, over two lines. All found in
    /// 0.4.1's audit as "nothing works".
    #[test]
    fn search_accepts_an_address_as_people_paste_it() {
        let c = context(true);
        let a = {
            let mut w = c.wallet.as_ref().unwrap().lock().unwrap();
            w.new_address()
        }
        .to_string_bech32();
        let grouped: Vec<String> = a
            .as_bytes()
            .chunks(8)
            .map(|g| String::from_utf8(g.to_vec()).unwrap())
            .collect();
        for pasted in [
            grouped.join(" "),
            grouped.join("\\n"),
            format!("  {}  ", a.to_uppercase()),
            grouped.join("\\u00a0"),
        ] {
            let r = call_ok(&c, "search", &format!(r#"{{"q":"{pasted}"}}"#));
            assert_eq!(
                kind_and_value(&r),
                ("address".into(), a.clone()),
                "{pasted}"
            );
        }
        // One character changed: the checksum says so, in words.
        let last = a.chars().last().unwrap();
        let wrong = format!(
            "{}{}",
            &a[..a.len() - 1],
            if last == 'q' { 'p' } else { 'q' }
        );
        let r = call(&c, "search", &format!(r#"{{"q":"{wrong}"}}"#));
        let m = r
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(m.contains("does not check out"), "{m}");
    }

    /// Amounts as written in French, with the unit, with separators.
    #[test]
    fn search_accepts_amounts_as_people_write_them() {
        let c = context(false);
        for (q, expected) in [
            ("1,5", "1.50000000"),
            ("1.5 Q21", "1.50000000"),
            ("2 q21", "2.00000000"),
            ("1 000,5", "1000.50000000"),
            ("1,000.5", "1000.50000000"),
            ("0,12345678", "0.12345678"),
        ] {
            let r = call_ok(&c, "search", &format!(r#"{{"q":"{q}"}}"#));
            assert_eq!(
                kind_and_value(&r),
                ("amount".into(), expected.into()),
                "{q}"
            );
        }
        // A bare integer stays a height, and the refusal says how to write an
        // amount.
        let r = call(&c, "search", r#"{"q":"999999"}"#);
        let m = r
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(m.contains("For an amount, write 999999.0"), "{m}");
    }

    /// The beginning of an identifier, as lists show it, leads to it.
    #[test]
    fn search_completes_a_truncated_identifier() {
        let c = context(false);
        let id = c
            .node
            .with_chain(|ch| ch.block_at(0).unwrap().header.block_id())
            .to_hex();
        for q in [format!("{}…", &id[..16]), id[..8].to_uppercase()] {
            let r = call_ok(&c, "search", &format!(r#"{{"q":"{q}"}}"#));
            assert_eq!(kind_and_value(&r), ("block-id".into(), id.clone()), "{q}");
        }
        // Too short to mean anything: refused, not guessed.
        let r = call(&c, "search", &format!(r#"{{"q":"{}"}}"#, &id[..7]));
        assert!(r.get("error").is_some());
        // Nothing starts with it: said, with the count.
        let other = if id.starts_with('f') {
            "eeeeeeeeee"
        } else {
            "ffffffffff"
        };
        let r = call(&c, "search", &format!(r#"{{"q":"{other}"}}"#));
        let m = r
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            m.starts_with("incomplete identifier: 10 characters out of 64"),
            "{m}"
        );
    }

    #[test]
    fn search_helpers() {
        assert_eq!(compact_search(" ab cd\n\u{a0}ef\u{200b}… "), "abcdef");
        assert_eq!(compact_search("abcdef..."), "abcdef");
        assert_eq!(amount_candidate("12"), None, "an integer is a height");
        assert_eq!(amount_candidate("12q21").as_deref(), Some("12"));
        assert_eq!(amount_candidate("0,5").as_deref(), Some("0.5"));
        assert_eq!(amount_candidate("1'000.25").as_deref(), Some("1000.25"));
        assert_eq!(amount_candidate("q21"), None);
        assert_eq!(amount_candidate("abc.5"), None);
        let h = Hash256::from_hex(&format!("ab{}", "0".repeat(62))).unwrap();
        assert!(hex_starts_with(&h, "ab00"));
        assert!(!hex_starts_with(&h, "ab01"));
        assert!(!hex_starts_with(&h, &"0".repeat(65)));
    }

    /// Any address at all has a balance and a history, without belonging to
    /// the wallet.
    ///
    /// That is what separates an explorer from a wallet: it answers for
    /// addresses that are not its own.
    #[test]
    fn getaddress_answers_for_any_address() {
        let c = context(true);
        let a = {
            let mut w = c.wallet.as_ref().unwrap().lock().unwrap();
            w.new_address()
        };
        let r = call_ok(
            &c,
            "getaddress",
            &format!(r#"{{"address":"{}"}}"#, a.to_string_bech32()),
        );
        assert_eq!(
            r.get("balance")
                .and_then(|m| m.get("units"))
                .and_then(|v| v.as_u64()),
            Some(0)
        );
        // Without an index, the response must admit it.
        assert_eq!(r.get("via_index"), Some(&Json::Bool(false)));
        assert!(r
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("Bounded"));
    }

    /// An unreadable address does not make the node work.
    #[test]
    fn getaddress_refuses_an_unreadable_address() {
        let c = context(false);
        let r = call(&c, "getaddress", r#"{"address":"tq21notarealaddress"}"#);
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_PARAMS)
        );
    }

    /// "Stop" is not a read method.
    ///
    /// A public node gladly answers whoever asks for its height; it must not
    /// shut down because someone asks it to. The method therefore goes through
    /// the same check as the ones that move funds.
    #[test]
    fn stop_is_refused_to_a_node_without_a_wallet() {
        let _v = crate::shutdown::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::shutdown::shutdown_done();
        let c = context(false);
        let r = call(&c, "stop", "{}");
        assert_eq!(
            r.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|v| v.as_i64()),
            Some(ERR_WALLET_DISABLED)
        );
        assert!(
            !crate::shutdown::requested(),
            "a node without a wallet raised the shutdown flag anyway"
        );
    }

    /// In wallet mode, the button raises the same flag as Ctrl-C.
    ///
    /// That is all it does: the main loop sees it on the next turn and does
    /// the work - mempool, state snapshot, address book, wallet - in a normal
    /// context. Nothing is written from the response to a request.
    #[test]
    fn stop_raises_the_flag_in_wallet_mode() {
        let _v = crate::shutdown::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::shutdown::shutdown_done();
        let c = context(true);
        let r = call_ok(&c, "stop", "{}");
        assert_eq!(r.get("shutdown"), Some(&Json::Bool(true)));
        assert!(
            crate::shutdown::requested(),
            "the shutdown flag is not raised"
        );
        // The flag is global to the process: leaving it raised would make any
        // loop that checks it afterward exit.
        crate::shutdown::shutdown_done();
    }
}
