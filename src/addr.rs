//! Address book and eclipse defense.
//!
//! # The attack this module targets
//!
//! An eclipse attack does not try to break the cryptography: it tries to
//! **isolate** a node. If all of its connections end up at machines
//! controlled by the same person, that node no longer sees the real
//! network. It can then be hidden blocks, shown a fabricated chain, made to
//! accept a payment already spent elsewhere. No proof of work protects it:
//! it perfectly verifies blocks that are addressed only to it.
//!
//! Eclipsing a node costs far less than attacking the network. It is the
//! most profitable attack against a small chain, and Q21 will be one.
//!
//! # The defense: count groups, not addresses
//!
//! An adversary easily obtains thousands of IP addresses, but rarely in
//! thousands of different ranges: they come from one or two hosting
//! providers, hence from a small number of `/16` blocks. The countermeasure
//! follows this asymmetry, as Bitcoin Core has done since 2015:
//!
//! - the book is **organized by network group** (`/16`), with a cap per
//!   group: flooding a range buys almost nothing;
//! - the selection **never returns two addresses from the same group**, nor
//!   an address from a group already represented among the connected peers.
//!
//! Holding 10,000 addresses in one `/16` therefore gives as much influence as
//! holding a single one. To carry weight, one must own entire ranges — which
//! is counted in money and administrative traces, not in scripts.
//!
//! # What this does not guarantee
//!
//! An adversary with truly diverse ranges — a large hosting provider, an
//! operator — remains dangerous. Diversity by group raises the cost, it does
//! not make it infinite. And a node whose **all** bootstrap addresses come
//! from the attacker is lost from the start: the bootstrap point remains the
//! weak link, here as elsewhere.

use crate::ser::{Reader, Writer};
use crate::sha256::sha256;
use crate::wire::NetAddr;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Addresses kept per `/16` group.
///
/// Beyond that, the oldest ones give way. This cap is what makes flooding
/// useless.
pub const MAX_PER_GROUP: usize = 32;

/// Distinct groups kept.
pub const MAX_GROUPS: usize = 512;

/// Age beyond which an address stops being proposed, in seconds.
///
/// Thirty days, as in Bitcoin. An older address has not disappeared from the
/// book: it simply comes after the ones that have shown signs of life.
pub const MAX_AGE: u64 = 30 * 24 * 3600;

/// File format magic. Frozen: changing it would orphan existing
/// `peers.dat` files.
const MAGIC: &[u8; 8] = b"Q21ADDRB";
const VERSION: u32 = 1;

/// Network group of an address: its first two bytes.
///
/// Coarse, and on purpose: the point is not to describe the Internet's
/// topology but to force an adversary to pay for distinct ranges.
pub fn group(ip: [u8; 4]) -> [u8; 2] {
    [ip[0], ip[1]]
}

/// An address routable on a public network?
///
/// Private and reserved ranges make no sense on a public network, and
/// propagating them would let someone make a node dial addresses on its own
/// local network — a port scan carried out on someone else's behalf.
///
/// Loopback remains accepted on test networks, where everything happens on a
/// single machine.
pub fn routable(ip: [u8; 4], allow_local: bool) -> bool {
    match ip {
        [127, ..] | [0, ..] => allow_local,
        [10, ..] => allow_local,
        [192, 168, ..] => allow_local,
        [169, 254, ..] => allow_local,
        [172, b, ..] if (16..32).contains(&b) => allow_local,
        [100, b, ..] if (64..128).contains(&b) => allow_local,
        [a, ..] if a >= 224 => false, // multicast and reserved
        [255, ..] => false,
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrEntry {
    pub addr: NetAddr,
    /// Consecutive connection attempts that failed.
    pub failures: u32,
    /// Last successful connection, in seconds since the epoch. Zero if never.
    pub last_success: u64,
}

/// Tolerance on a timestamp announced by a third party.
///
/// An address announced as "seen" in the future makes no sense. An audit
/// exploited it: by writing `last_seen = u64::MAX`, its addresses won **all**
/// freshness comparisons, forever. They could no longer be evicted and always
/// came out first in the selection. A timestamp coming from the network is a
/// claim, not a fact: it is bounded.
pub const FUTURE_TOLERANCE: u64 = 10 * 60;

/// Address book organized by network group.
#[derive(Debug)]
pub struct AddrBook {
    groups: HashMap<[u8; 2], Vec<AddrEntry>>,
    /// Allows loopback addresses: test networks only.
    local: bool,
    /// Salt specific to this node, drawn at startup.
    ///
    /// It orders the candidates for selection. Without it, the order was a
    /// public function of data the adversary supplies itself: announcing the
    /// right timestamp was enough to get ahead. With it, the order is
    /// unpredictable **to anyone who does not know the salt**, and the salt
    /// never leaves the process. It is the same idea as addrman's `nKey` in
    /// Bitcoin Core.
    salt: (u64, u64),
}

impl Default for AddrBook {
    fn default() -> AddrBook {
        AddrBook::new(false)
    }
}

impl AddrBook {
    pub fn new(allow_local: bool) -> AddrBook {
        // An unpredictable salt if the system can provide one; failing that, a
        // fixed salt. A generator failure must not prevent a node from
        // starting: we lose the unpredictability of the order, not the
        // partitioning by group, which remains the main defense.
        let salt = match crate::rng::bytes::<16>() {
            Ok(o) => (
                u64::from_le_bytes(o[..8].try_into().unwrap()),
                u64::from_le_bytes(o[8..].try_into().unwrap()),
            ),
            Err(_) => (0x5171_2953_5f43_4152, 0x4e45_545f_5145_3231),
        };
        AddrBook::new_with_salt(allow_local, salt)
    }

    /// Book with an imposed salt: makes the selection reproducible for tests.
    pub fn new_with_salt(allow_local: bool, salt: (u64, u64)) -> AddrBook {
        AddrBook {
            groups: HashMap::new(),
            local: allow_local,
            salt,
        }
    }

    /// Rank of an address in this node's secret order.
    fn rank(&self, a: &NetAddr) -> u64 {
        let mut raw = [0u8; 6];
        raw[..4].copy_from_slice(&a.ip);
        raw[4..].copy_from_slice(&a.port.to_le_bytes());
        crate::siphash::siphash24(self.salt.0, self.salt.1, &raw)
    }

    /// A group none of whose addresses has ever answered.
    ///
    /// This is the raw material of an eclipse: an adversary can announce as
    /// many groups as it wants, but it cannot make a machine that does not
    /// exist answer.
    fn group_never_proven(v: &[AddrEntry]) -> bool {
        v.iter().all(|e| e.last_success == 0)
    }

    pub fn len(&self) -> usize {
        self.groups.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn groups(&self) -> usize {
        self.groups.len()
    }

    /// Adds or refreshes an address.
    ///
    /// Returns `false` if the address is rejected: not routable, zero port, or
    /// group already full with no older candidate to replace.
    pub fn add(&mut self, a: NetAddr, now: u64) -> bool {
        if a.port == 0 || !routable(a.ip, self.local) {
            return false;
        }
        // An announced timestamp cannot be in the future.
        let mut a = a;
        a.last_seen = a.last_seen.min(now.saturating_add(FUTURE_TOLERANCE));
        let g = group(a.ip);

        if let Some(v) = self.groups.get_mut(&g) {
            if let Some(e) = v
                .iter_mut()
                .find(|e| e.addr.ip == a.ip && e.addr.port == a.port)
            {
                e.addr.last_seen = e.addr.last_seen.max(a.last_seen);
                return true;
            }
            if v.len() >= MAX_PER_GROUP {
                // The group is full: the new address only takes the place of
                // an older one. An adversary who floods a range therefore only
                // replaces its own addresses.
                let (pos, oldest) = v
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.addr.last_seen)
                    .map(|(i, e)| (i, e.addr.last_seen))
                    .expect("non-empty group");
                if a.last_seen <= oldest {
                    return false;
                }
                v[pos] = AddrEntry {
                    addr: a,
                    failures: 0,
                    last_success: 0,
                };
                return true;
            }
            v.push(AddrEntry {
                addr: a,
                failures: 0,
                last_success: 0,
            });
            return true;
        }

        if self.groups.len() >= MAX_GROUPS {
            // --- The group cap must not become a lock.
            //
            // An audit filled the 512 groups with its own addresses. No honest
            // address could get in anymore: the book was permanently frozen on
            // the attacker's view, and the selection only returned its
            // addresses. That is a complete eclipse, obtained without owning a
            // single reachable machine.
            //
            // A group none of whose addresses has **ever** answered has proven
            // nothing. It gives way. A group that contains a peer this node has
            // really talked to is kept: that one has paid the price of a
            // machine that exists.
            let victim = self
                .groups
                .iter()
                .filter(|(_, v)| Self::group_never_proven(v))
                .min_by_key(|(g, v)| {
                    let freshness = v.iter().map(|e| e.addr.last_seen).max().unwrap_or(0);
                    (freshness, **g)
                })
                .map(|(g, _)| *g);
            match victim {
                Some(g) => {
                    self.groups.remove(&g);
                }
                // Every group contains a proven peer: the book is full of real
                // peers, and there is nothing to gain by evicting one.
                None => return false,
            }
        }
        self.groups.insert(
            g,
            vec![AddrEntry {
                addr: a,
                failures: 0,
                last_success: 0,
            }],
        );
        true
    }

    pub fn mark_success(&mut self, ip: [u8; 4], port: u16, now: u64) {
        if let Some(e) = self.find(ip, port) {
            e.failures = 0;
            e.last_success = now;
            e.addr.last_seen = now;
        }
    }

    pub fn mark_failure(&mut self, ip: [u8; 4], port: u16) {
        if let Some(e) = self.find(ip, port) {
            e.failures = e.failures.saturating_add(1);
        }
    }

    fn find(&mut self, ip: [u8; 4], port: u16) -> Option<&mut AddrEntry> {
        self.groups
            .get_mut(&group(ip))?
            .iter_mut()
            .find(|e| e.addr.ip == ip && e.addr.port == port)
    }

    /// Chooses up to `count` addresses to try, **all from distinct groups**
    /// and different from those already connected.
    ///
    /// This is where the defense plays out: no matter how many addresses an
    /// adversary has managed to insert, it can only occupy one slot per group
    /// it really owns.
    pub fn select(&self, count: usize, already: &[[u8; 4]], now: u64) -> Vec<NetAddr> {
        let mut forbidden: HashSet<[u8; 2]> = already.iter().map(|ip| group(*ip)).collect();
        let connected: HashSet<[u8; 4]> = already.iter().copied().collect();

        // A stable order with no clock: by group, then by quality.
        let mut candidates: Vec<(&[u8; 2], &AddrEntry)> = Vec::new();
        for (g, v) in &self.groups {
            if forbidden.contains(g) {
                continue;
            }
            // The group's best representative: the fewest failures, then the
            // most recently seen.
            if let Some(e) = v
                .iter()
                .filter(|e| !connected.contains(&e.addr.ip))
                .min_by_key(|e| (e.failures, u64::MAX - e.last_success, self.rank(&e.addr)))
            {
                candidates.push((g, e));
            }
        }

        // The order must owe nothing to a value the adversary writes.
        //
        // It relied on `last_seen`, a field announced by the peer itself:
        // setting it to the maximum was enough to get ahead of everyone,
        // indefinitely. We keep what is **observed by this node** — failures,
        // successes, age beyond thirty days — and break the remaining ties
        // with the local salt, unpredictable from the outside.
        candidates.sort_by_key(|(g, e)| {
            let stale = u8::from(now.saturating_sub(e.addr.last_seen) > MAX_AGE);
            let never_proven = u8::from(e.last_success == 0);
            (stale, e.failures, never_proven, self.rank(&e.addr), **g)
        });

        let mut out = Vec::new();
        for (g, e) in candidates {
            if out.len() >= count {
                break;
            }
            if forbidden.insert(*g) {
                out.push(e.addr);
            }
        }
        out
    }

    /// Addresses to announce to a peer that sends `getaddr`.
    ///
    /// Spread across groups, so as not to propagate the biased view of a book
    /// that an adversary may have partially filled.
    pub fn to_announce(&self, count: usize) -> Vec<NetAddr> {
        let mut v: Vec<NetAddr> = Vec::new();
        let mut groups: Vec<&[u8; 2]> = self.groups.keys().collect();
        groups.sort();
        let mut rank = 0;
        while v.len() < count {
            let mut added = false;
            for g in &groups {
                if let Some(e) = self.groups[*g].get(rank) {
                    v.push(e.addr);
                    added = true;
                    if v.len() >= count {
                        break;
                    }
                }
            }
            if !added {
                break;
            }
            rank += 1;
        }
        v
    }

    pub fn all(&self) -> Vec<AddrEntry> {
        let mut v: Vec<AddrEntry> = self.groups.values().flatten().copied().collect();
        v.sort_by_key(|e| (e.addr.ip, e.addr.port));
        v
    }
}

/// Address book persisted on disk.
pub struct AddrStore {
    path: PathBuf,
}

impl AddrStore {
    pub fn new<P: AsRef<Path>>(path: P) -> AddrStore {
        AddrStore {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn save(&self, book: &AddrBook) -> std::io::Result<()> {
        self.save_entries(&book.all())
    }

    /// Writes entries as they are.
    ///
    /// The binary used to rebuild a fresh book from the addresses alone
    /// before writing: the failure counters and, above all, the date of the
    /// last success were reset to zero **at every shutdown**. A node therefore
    /// forgot at every restart which peers had really answered it — that is,
    /// exactly what distinguishes a real peer from an announced address.
    pub fn save_entries(&self, entries: &[AddrEntry]) -> std::io::Result<()> {
        let mut w = Writer::with_capacity(32 + entries.len() * 24);
        w.bytes(MAGIC);
        w.u32(VERSION);
        w.varint(entries.len() as u64);
        for e in entries {
            w.bytes(&e.addr.ip);
            w.u32(u32::from(e.addr.port));
            w.u64(e.addr.last_seen);
            w.u32(e.failures);
            w.u64(e.last_success);
        }
        let mut data = w.finish();
        data.extend_from_slice(&sha256(&data));

        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }

    /// Reloads the book. A corrupted file yields an empty book, never a fatal
    /// error: we start over from the bootstrap.
    /// Reads the book back.
    ///
    /// `now` is used to bound the timestamps: a book coming from elsewhere
    /// could announce addresses "seen" and "proven" in the future, which would
    /// make them both unevictable and prioritized. These are claims from a
    /// file, not observations by this node.
    pub fn load(&self, allow_local: bool, now: u64) -> AddrBook {
        let mut book = AddrBook::new(allow_local);
        let Ok(data) = std::fs::read(&self.path) else {
            return book;
        };
        if data.len() < 32 {
            return book;
        }
        let (payload, checksum) = data.split_at(data.len() - 32);
        if sha256(payload) != checksum {
            return book;
        }
        let mut r = Reader::new(payload);
        let mut magic = [0u8; 8];
        for o in &mut magic {
            match r.u8() {
                Ok(v) => *o = v,
                Err(_) => return book,
            }
        }
        if &magic != MAGIC || r.u32().ok() != Some(VERSION) {
            return book;
        }
        let Ok(n) = r.varint() else { return book };
        for _ in 0..n.min(1_000_000) {
            let (Ok(a), Ok(b), Ok(c), Ok(d)) = (r.u8(), r.u8(), r.u8(), r.u8()) else {
                break;
            };
            let (Ok(port), Ok(last_seen), Ok(failures), Ok(success)) =
                (r.u32(), r.u64(), r.u32(), r.u64())
            else {
                break;
            };
            let addr = NetAddr {
                ip: [a, b, c, d],
                port: port as u16,
                last_seen,
            };
            if book.add(addr, now) {
                if let Some(e) = book.find(addr.ip, addr.port) {
                    e.failures = failures;
                    // A success cannot have happened in the future.
                    e.last_success = success.min(now);
                }
            }
        }
        book
    }
}

#[cfg(test)]
mod tests {
    /// Reference clock for the tests: well beyond the timestamps used below,
    /// so that none of them gets bounded by accident.
    const NOW: u64 = 2_000_000_000;

    use super::*;

    fn a(ip: [u8; 4], port: u16, seen: u64) -> NetAddr {
        NetAddr {
            ip,
            port,
            last_seen: seen,
        }
    }

    #[test]
    fn private_ranges_are_rejected_on_a_public_network() {
        let mut b = AddrBook::new(false);
        for ip in [
            [127, 0, 0, 1],
            [10, 0, 0, 5],
            [192, 168, 1, 1],
            [172, 20, 0, 1],
            [169, 254, 1, 1],
            [100, 70, 0, 1],
            [0, 0, 0, 0],
            [239, 1, 1, 1],
        ] {
            assert!(
                !b.add(a(ip, 21021, 100), NOW),
                "{ip:?} should have been rejected"
            );
        }
        assert!(b.add(a([93, 184, 216, 34], 21021, 100), NOW));
    }

    #[test]
    fn loopback_remains_usable_on_a_test_network() {
        let mut b = AddrBook::new(true);
        assert!(b.add(a([127, 0, 0, 1], 21021, 100), NOW));
    }

    #[test]
    fn a_zero_port_is_rejected() {
        let mut b = AddrBook::new(true);
        assert!(!b.add(a([127, 0, 0, 1], 0, 100), NOW));
    }

    /// The heart of the defense: flooding a range buys almost nothing.
    #[test]
    fn flooding_a_group_gives_only_one_slot() {
        let mut b = AddrBook::new(false);

        // The adversary inserts ten thousand addresses, all in 203.0.x.x.
        for i in 0..10_000u32 {
            let ip = [203, 0, (i >> 8) as u8, i as u8];
            b.add(a(ip, 21021, 1_000 + u64::from(i)), NOW);
        }
        assert!(
            b.len() <= MAX_PER_GROUP,
            "{} addresses kept for a single group",
            b.len()
        );

        // Four honest peers, in four distinct ranges.
        for (i, ip) in [
            [93, 184, 216, 34],
            [8, 8, 8, 8],
            [1, 1, 1, 1],
            [198, 51, 100, 7],
        ]
        .into_iter()
        .enumerate()
        {
            b.add(a(ip, 21021, 900 + i as u64), NOW);
        }

        let choice = b.select(8, &[], 2_000);
        let from_adversary = choice.iter().filter(|x| x.ip[0] == 203).count();
        assert_eq!(
            from_adversary, 1,
            "ten thousand addresses are entitled to only one slot: {choice:?}"
        );
        assert_eq!(
            choice.len(),
            5,
            "the four honest ones plus one from the attacker"
        );
    }

    #[test]
    fn selection_never_returns_the_same_group_twice() {
        let mut b = AddrBook::new(false);
        for i in 0..40u8 {
            for j in 0..5u8 {
                b.add(a([50 + i, 10, j, 1], 21021, 100 + u64::from(j)), NOW);
            }
        }
        let choice = b.select(20, &[], 200);
        let groups: HashSet<[u8; 2]> = choice.iter().map(|x| group(x.ip)).collect();
        assert_eq!(groups.len(), choice.len(), "a group appeared twice");
    }

    /// A group already represented among the connected peers is excluded: this
    /// is what prevents an adversary from eventually occupying every slot.
    #[test]
    fn an_already_connected_group_is_excluded() {
        let mut b = AddrBook::new(false);
        b.add(a([93, 184, 216, 34], 21021, 100), NOW);
        b.add(a([93, 184, 9, 9], 21021, 100), NOW);
        b.add(a([8, 8, 8, 8], 21021, 100), NOW);

        let choice = b.select(5, &[[93, 184, 216, 34]], 200);
        assert_eq!(choice.len(), 1);
        assert_eq!(choice[0].ip, [8, 8, 8, 8]);
    }

    #[test]
    fn failures_push_an_address_back_without_erasing_it() {
        let mut b = AddrBook::new(false);
        b.add(a([93, 184, 216, 34], 21021, 100), NOW);
        b.add(a([93, 184, 216, 35], 21021, 100), NOW);
        b.mark_failure([93, 184, 216, 34], 21021);

        let choice = b.select(1, &[], 200);
        assert_eq!(
            choice[0].ip,
            [93, 184, 216, 35],
            "the healthy address goes first"
        );
        assert_eq!(b.len(), 2, "and the other one stays in the book");
    }

    #[test]
    fn the_number_of_groups_is_bounded() {
        let mut b = AddrBook::new(false);
        for i in 0..2_000u32 {
            let ip = [1 + (i / 256) as u8 % 200, (i % 256) as u8, 1, 1];
            b.add(a(ip, 21021, 100), NOW);
        }
        assert!(b.groups() <= MAX_GROUPS);
    }

    #[test]
    fn the_announcement_spreads_across_groups() {
        let mut b = AddrBook::new(false);
        for g in 0..10u8 {
            for k in 0..20u8 {
                b.add(a([100 + g, 1, k, 1], 21021, 100), NOW);
            }
        }
        let v = b.to_announce(10);
        let groups: HashSet<[u8; 2]> = v.iter().map(|x| group(x.ip)).collect();
        assert_eq!(groups.len(), 10, "the announcement must cover every group");
    }

    #[test]
    fn disk_round_trip() {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-peers-{}.dat", std::process::id()));
        let _ = std::fs::remove_file(&p);

        let mut b = AddrBook::new(false);
        for i in 0..30u8 {
            b.add(a([50 + i, 10, 1, 1], 21021, 1_000 + u64::from(i)), NOW);
        }
        b.mark_success([50, 10, 1, 1], 21021, 4_242);
        b.mark_failure([51, 10, 1, 1], 21021);

        let s = AddrStore::new(&p);
        s.save(&b).unwrap();
        let reread = s.load(false, NOW);

        assert_eq!(reread.len(), b.len());
        assert_eq!(reread.all(), b.all());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_corrupted_book_reads_as_empty() {
        let mut p = std::env::temp_dir();
        p.push(format!("q21-peers-corrupted-{}.dat", std::process::id()));
        std::fs::write(&p, b"any old junk").unwrap();
        assert!(AddrStore::new(&p).load(false, NOW).is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_re_announced_address_is_not_duplicated() {
        let mut b = AddrBook::new(false);
        assert!(b.add(a([93, 184, 216, 34], 21021, 100), NOW));
        assert!(b.add(a([93, 184, 216, 34], 21021, 500), NOW));
        assert_eq!(b.len(), 1);
        assert_eq!(b.all()[0].addr.last_seen, 500);
    }
}
