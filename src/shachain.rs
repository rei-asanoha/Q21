//! Compact storage of revocation secrets, in the manner of BOLT 3.
//!
//! A channel party reveals one secret per state it abandons. Kept naively,
//! the counterparty's store grows by thirty-two bytes per payment, forever,
//! and that is what a watchtower would have to hold for every channel it
//! watches. Here every secret derives from a single seed, along a binary
//! tree of SHA-256 applications, so that the receiver keeps at most 49
//! secrets, however many states the channel has gone through, and can still
//! rebuild any secret revealed earlier.
//!
//! The derivation is BOLT 3's (`generate_from_seed`), with the same 48-bit
//! indices counting *down* from [`MAX_INDEX`], so its published vectors hold.
//! State `n` uses index `MAX_INDEX - n`.

use crate::sha256::sha256;

/// The first index; the following states count down from it.
pub const MAX_INDEX: u64 = (1 << 48) - 1;

/// Most entries a [`Store`] ever holds: one per bit of an index, plus one.
pub const MAX_ENTRIES: usize = 49;

/// The secret of `index`, derived from `seed`.
pub fn derive(seed: &[u8; 32], index: u64) -> [u8; 32] {
    derive_from(seed, 48, index)
}

/// Derives the secret of `index` from a secret that holds for every index
/// sharing its bits from `bits` up: only the lower bits remain to apply.
fn derive_from(base: &[u8; 32], bits: u32, index: u64) -> [u8; 32] {
    let mut p = *base;
    for b in (0..bits).rev() {
        if index >> b & 1 == 1 {
            p[(b / 8) as usize] ^= 1 << (b % 8);
            p = sha256(&p);
        }
    }
    p
}

/// Where a secret goes: the number of trailing zero bits of its index. A
/// secret with `k` trailing zeros derives every index that shares its upper
/// bits, which is what lets it replace the `k` entries below it.
fn bucket(index: u64) -> usize {
    (index.trailing_zeros() as usize).min(48)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ShachainError {
    /// The new secret does not derive a secret already received: one of the
    /// two is false, and the sender is cheating or broken.
    Inconsistent {
        index: u64,
    },
    /// Secrets must arrive in order, each index one below the previous one.
    OutOfOrder {
        expected: u64,
        received: u64,
    },
    IndexOutOfRange(u64),
}

/// What the receiver keeps: at most [`MAX_ENTRIES`] secrets.
#[derive(Default, Clone, Debug)]
pub struct Store {
    known: Vec<Option<([u8; 32], u64)>>,
    next: Option<u64>,
}

/// The revealed secrets are wiped when the store is dropped: they are what a
/// penalty is built from, and no copy needs to survive in a reused heap.
impl Drop for Store {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl Store {
    pub fn new() -> Store {
        Store {
            known: vec![None; MAX_ENTRIES],
            next: Some(MAX_INDEX),
        }
    }

    /// Records the secret of `index`, after checking that it derives every
    /// secret it is meant to replace.
    pub fn insert(&mut self, secret: [u8; 32], index: u64) -> Result<(), ShachainError> {
        if index > MAX_INDEX {
            return Err(ShachainError::IndexOutOfRange(index));
        }
        if self.known.is_empty() {
            *self = Store::new();
        }
        let expected = self.next.unwrap_or(0);
        if self.next.is_none() || index != expected {
            return Err(ShachainError::OutOfOrder {
                expected,
                received: index,
            });
        }
        let at = bucket(index);
        for (older_secret, older) in self.known[..at].iter().flatten() {
            if derive_from(&secret, at as u32, *older) != *older_secret {
                return Err(ShachainError::Inconsistent { index });
            }
        }
        self.known[at] = Some((secret, index));
        self.next = index.checked_sub(1);
        Ok(())
    }

    /// The secret of `index`, if it was revealed.
    pub fn get(&self, index: u64) -> Option<[u8; 32]> {
        for (b, entry) in self.known.iter().enumerate() {
            if let Some((secret, at)) = entry {
                // An entry derives the indices that share its bits from `b`
                // up — and only those at or above it, which were revealed.
                if index >> b == at >> b && index >= *at {
                    return Some(derive_from(secret, b as u32, index));
                }
            }
        }
        None
    }

    /// Secrets currently held.
    pub fn len(&self) -> usize {
        self.known.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Zeroes every secret held, in place.
    fn wipe(&mut self) {
        for (secret, _) in self.known.iter_mut().flatten() {
            crate::kdf::wipe(secret);
        }
    }

    /// Bytes held: each entry is a secret and its index.
    pub fn bytes(&self) -> usize {
        self.len() * (32 + 8)
    }

    /// The entries held, `(secret, index)`, highest index first: everything
    /// needed to rebuild the store with [`Store::restore`], so a journal can
    /// keep these few entries instead of every secret ever revealed.
    pub fn entries(&self) -> Vec<([u8; 32], u64)> {
        let mut v: Vec<([u8; 32], u64)> = self.known.iter().flatten().copied().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v
    }

    /// Rebuilds a store from its [`Store::entries`]. Each entry goes back in
    /// its bucket and must derive the entries below it, exactly as when it was
    /// first inserted; the next expected index follows the lowest one.
    pub fn restore(entries: &[([u8; 32], u64)]) -> Result<Store, ShachainError> {
        let mut store = Store::new();
        let mut lowest: Option<u64> = None;
        for &(secret, index) in entries {
            if index > MAX_INDEX {
                return Err(ShachainError::IndexOutOfRange(index));
            }
            let at = bucket(index);
            if store.known[at].is_some() {
                return Err(ShachainError::Inconsistent { index });
            }
            store.known[at] = Some((secret, index));
            lowest = Some(lowest.map_or(index, |l: u64| l.min(index)));
        }
        // Every entry must derive the lower-bucket entries that were already
        // there when it was inserted — those of higher index — as on insertion.
        for (at, entry) in store.known.iter().enumerate() {
            if let Some((secret, index)) = entry {
                for (older_secret, older) in store.known[..at].iter().flatten() {
                    if *older > *index && derive_from(secret, at as u32, *older) != *older_secret {
                        return Err(ShachainError::Inconsistent { index: *index });
                    }
                }
            }
        }
        store.next = match lowest {
            Some(l) => l.checked_sub(1),
            None => Some(MAX_INDEX),
        };
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The published vectors of BOLT 3, "generate_from_seed".
    #[test]
    fn bolt3_vectors() {
        assert_eq!(
            hex(&derive(&[0; 32], MAX_INDEX)),
            "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148"
        );
        assert_eq!(
            hex(&derive(&[0xff; 32], MAX_INDEX)),
            "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"
        );
        assert_eq!(
            hex(&derive(&[0xff; 32], 0xaaa_aaaa_aaaa)),
            "56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"
        );
        assert_eq!(
            hex(&derive(&[0xff; 32], 0x5555_5555_5555)),
            "9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31"
        );
        assert_eq!(
            hex(&derive(&[0x01; 32], 1)),
            "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"
        );
    }

    /// A thousand and more states: the store stays at a few entries, and
    /// every secret revealed so far can be rebuilt.
    #[test]
    fn revealed_secrets_are_wiped() {
        let seed = [0x24u8; 32];
        let mut store = Store::new();
        for i in 0..5 {
            store
                .insert(derive(&seed, MAX_INDEX - i), MAX_INDEX - i)
                .unwrap();
        }
        assert!(store.entries().iter().all(|(s, _)| *s != [0u8; 32]));
        // What `Drop` runs: every held secret is zeroed in place.
        store.wipe();
        assert!(!store.entries().is_empty());
        assert!(store.entries().iter().all(|(s, _)| *s == [0u8; 32]));
    }

    #[test]
    fn a_store_restores_from_its_entries() {
        let seed = [0x42u8; 32];
        let mut full = Store::new();
        for i in 0..1000u64 {
            full.insert(derive(&seed, MAX_INDEX - i), MAX_INDEX - i)
                .unwrap();
            let mut back = Store::restore(&full.entries()).unwrap();
            assert_eq!(back.len(), full.len());
            // Every revealed secret is still derivable, and the next insert
            // is accepted exactly as by the original store.
            for j in [0, i / 2, i] {
                assert_eq!(back.get(MAX_INDEX - j), Some(derive(&seed, MAX_INDEX - j)));
            }
            assert_eq!(back.get(MAX_INDEX - i - 1), None);
            let next = MAX_INDEX - i - 1;
            back.insert(derive(&seed, next), next).unwrap();
        }
        assert!(full.len() <= MAX_ENTRIES);
        // An entry that does not derive the older entry below it is refused.
        let mut two = Store::new();
        two.insert(derive(&seed, MAX_INDEX), MAX_INDEX).unwrap();
        two.insert(derive(&seed, MAX_INDEX - 1), MAX_INDEX - 1)
            .unwrap();
        let mut forged = two.entries();
        assert_eq!(forged.len(), 2);
        forged[1].0[0] ^= 1;
        assert!(Store::restore(&two.entries()).is_ok());
        assert!(Store::restore(&forged).is_err());
        let entries = full.entries();
        // Two entries in one bucket are refused.
        let mut doubled = entries.clone();
        doubled.push(entries[0]);
        assert!(Store::restore(&doubled).is_err());
        assert_eq!(Store::restore(&[]).unwrap().len(), 0);
    }

    #[test]
    fn a_long_channel_fits_in_a_few_entries() {
        let seed = [0x5a; 32];
        let mut s = Store::new();
        for n in 0..1_500u64 {
            s.insert(derive(&seed, MAX_INDEX - n), MAX_INDEX - n)
                .expect("consistent");
            assert!(s.len() <= MAX_ENTRIES);
        }
        assert!(s.len() <= 11, "{} entries", s.len());
        for n in 0..1_500u64 {
            assert_eq!(s.get(MAX_INDEX - n), Some(derive(&seed, MAX_INDEX - n)));
        }
        // Not yet revealed: unknown.
        assert_eq!(s.get(MAX_INDEX - 1_500), None);
    }

    #[test]
    fn an_inconsistent_secret_is_refused() {
        let seed = [0x5a; 32];
        let mut s = Store::new();
        s.insert(derive(&seed, MAX_INDEX), MAX_INDEX).unwrap();
        // Index MAX - 1 has one trailing zero: it must derive MAX.
        let forged = derive(&[0x5b; 32], MAX_INDEX - 1);
        assert_eq!(
            s.insert(forged, MAX_INDEX - 1),
            Err(ShachainError::Inconsistent {
                index: MAX_INDEX - 1
            })
        );
        // Out of order, and out of range.
        assert!(matches!(
            s.insert(derive(&seed, MAX_INDEX - 5), MAX_INDEX - 5),
            Err(ShachainError::OutOfOrder { .. })
        ));
        assert_eq!(
            s.insert([0; 32], MAX_INDEX + 1),
            Err(ShachainError::IndexOutOfRange(MAX_INDEX + 1))
        );
        // The honest one still goes in.
        s.insert(derive(&seed, MAX_INDEX - 1), MAX_INDEX - 1)
            .unwrap();
    }
}
