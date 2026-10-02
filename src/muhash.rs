//! MuHash: an incremental, order-independent commitment to the UTXO set.
//!
//! # The problem this module solves
//!
//! A snapshot of the monetary state ([`crate::state::Snapshot`]) already knows
//! how to serialize and read itself back. But nothing, until now, made it
//! possible to say of a snapshot **coming from elsewhere**: "this really is the
//! UTXO set at height H, not a version where the ownership of an output was
//! quietly moved". The SHA-256 checksum only proves the integrity of the file,
//! not its faithfulness to the chain; and the directory seal by construction
//! refuses any file that was not written in place. The comment in `state.rs`
//! names it as a dated debt: "only a commitment to the UTXO set would answer
//! it". This module is that commitment.
//!
//! # What a MuHash is
//!
//! Each unspent output is mapped to an element of a large multiplicative group
//! — the integers modulo a 3072-bit prime — and then all these elements are
//! **multiplied**. The product is the commitment of the set.
//!
//! Two properties follow, and they are exactly the ones needed:
//!
//! 1. **Order does not matter.** Multiplication is commutative: two nodes that
//!    have the same UTXO set compute the same commitment, whatever the order in
//!    which they received the blocks.
//! 2. **The update is incremental.** Adding an output is a multiplication;
//!    removing one is a division. The whole set is never rehashed — which is
//!    what sets a MuHash apart from a plain sorted SHA-256 sum, and what makes
//!    it possible, later, to keep a commitment up to date at every block.
//!
//! # The choice of modulus
//!
//! `P = 2^3072 - 1103717`, prime. It is Bitcoin Core's modulus (class
//! `MuHash3072`), chosen for two measurable reasons: 3072 bits put collision
//! resistance far beyond any practical horizon, and the form `2^3072 - c` with
//! a small `c` makes modular reduction nearly free — a product folds as
//! `lo + c * hi`, without division.
//!
//! # What this module does not import
//!
//! No dependency. The 3072-bit arithmetic is written here, as the 256-bit one
//! is in `uint.rs`, and for the same reason: handing the definition of a
//! consensus commitment to a big-integer crate would mean handing it to that
//! crate's future updates. Expanding a 256-bit hash into a 3072-bit element is
//! done with SHA-256 in counter mode — the same tagged SHA-256 used everywhere
//! else.

use crate::hash::{tagged_hash, tagged_hash_parts, Hash256};

/// Number of 64-bit limbs: 48 x 64 = 3072.
const LIMBS: usize = 48;

/// The modulus is `P = 2^3072 - C`. `C` fits in a single 64-bit word, which is
/// the whole trick: `2^3072 ≡ C (mod P)`, so folding a product amounts to
/// replacing its high half with `C` times that half, added to the low half.
const C: u64 = 1103717;

/// Limbs of `P = 2^3072 - C`, from least to most significant.
///
/// `2^3072 - 1` is "every limb at `u64::MAX`". Subtracting `C` only touches the
/// least significant limb: `P[0] = u64::MAX - (C - 1)`, the rest unchanged.
const P_LIMBS: [u64; LIMBS] = {
    let mut p = [u64::MAX; LIMBS];
    p[0] = u64::MAX - (C - 1);
    p
};

/// Exponent of the Fermat inverse: `P - 2`. Since `P` is prime, `x^(P-2) ≡
/// x^(-1) (mod P)` for every nonzero `x`. `P - 2 = 2^3072 - (C + 2)`, so only
/// the least significant limb differs from `u64::MAX`.
const EXP_INVERSE: [u64; LIMBS] = {
    let mut e = [u64::MAX; LIMBS];
    e[0] = u64::MAX - (C + 1);
    e
};

/// Element of the multiplicative group modulo `P`, always kept reduced in
/// `[0, P)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Num3072 {
    /// 64-bit limbs, from least significant (index 0) to most significant.
    limbs: [u64; LIMBS],
}

impl Num3072 {
    /// The identity element of multiplication.
    pub const fn one() -> Num3072 {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 1;
        Num3072 { limbs }
    }

    fn is_one(&self) -> bool {
        if self.limbs[0] != 1 {
            return false;
        }
        for &l in &self.limbs[1..] {
            if l != 0 {
                return false;
            }
        }
        true
    }

    /// Adds a 64-bit scalar in place, propagating the carry. Returns the final
    /// carry (0 or 1): what overflows beyond `2^3072`.
    fn add_scalar(limbs: &mut [u64; LIMBS], s: u64) -> u64 {
        let mut carry = s;
        for l in limbs.iter_mut() {
            let (v, c) = l.overflowing_add(carry);
            *l = v;
            carry = c as u64;
            if carry == 0 {
                break;
            }
        }
        carry
    }

    /// Adds another 48-limb number in place. Returns the final carry.
    fn add_assign(limbs: &mut [u64; LIMBS], other: &[u64; LIMBS]) -> u64 {
        let mut carry = 0u128;
        for (l, a) in limbs.iter_mut().zip(other.iter()) {
            let s = *l as u128 + *a as u128 + carry;
            *l = s as u64;
            carry = s >> 64;
        }
        carry as u64
    }

    /// `r >= P`? Compares limb by limb starting from the most significant.
    fn geq_p(limbs: &[u64; LIMBS]) -> bool {
        for i in (0..LIMBS).rev() {
            if limbs[i] != P_LIMBS[i] {
                return limbs[i] > P_LIMBS[i];
            }
        }
        true // equal to P: counts as >= P, hence to be reduced.
    }

    /// Reduces into `[0, P)` a number already below `2^3072`.
    ///
    /// If `r >= P`, then `r - P = r + C - 2^3072`: we add `C` and let the carry
    /// vanish beyond `2^3072`.
    fn reduce_once(limbs: &mut [u64; LIMBS]) {
        if Self::geq_p(limbs) {
            let _ = Self::add_scalar(limbs, C);
        }
    }

    /// Full product of two 48-limb numbers, on 96 limbs.
    #[allow(clippy::needless_range_loop)]
    fn mul_wide(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> [u64; 2 * LIMBS] {
        let mut out = [0u64; 2 * LIMBS];
        for i in 0..LIMBS {
            let ai = a[i] as u128;
            let mut carry: u128 = 0;
            for j in 0..LIMBS {
                let cur = out[i + j] as u128 + ai * b[j] as u128 + carry;
                out[i + j] = cur as u64;
                carry = cur >> 64;
            }
            let mut k = i + LIMBS;
            while carry != 0 {
                let cur = out[k] as u128 + carry;
                out[k] = cur as u64;
                carry = cur >> 64;
                k += 1;
            }
        }
        out
    }

    /// Folds a 96-limb product into an element reduced modulo `P`.
    ///
    /// `product = low + 2^3072 * high ≡ low + C * high (mod P)`. The term
    /// `C * high` reintroduces a small overflow, which is folded in turn: two
    /// or three rounds are enough, since `C` is small.
    fn reduce_wide(product: &[u64; 2 * LIMBS]) -> Num3072 {
        let mut low = [0u64; LIMBS];
        low.copy_from_slice(&product[..LIMBS]);

        // C * high, limb by limb, with its most significant carry.
        let mut ch = [0u64; LIMBS];
        let mut carry: u128 = 0;
        for i in 0..LIMBS {
            let cur = C as u128 * product[LIMBS + i] as u128 + carry;
            ch[i] = cur as u64;
            carry = cur >> 64;
        }
        // `over` counts the multiples of `2^3072` to fold: the carry of
        // `C*high` plus that of the addition that follows.
        let mut over = carry as u64;
        over += Self::add_assign(&mut low, &ch);

        // Fold the remaining overflow as long as there is some. `C * over` fits
        // in 64 bits (`over < 2^21`, `C < 2^21`, so `C*over < 2^42`).
        while over != 0 {
            over = Self::add_scalar(&mut low, C.wrapping_mul(over));
        }
        Self::reduce_once(&mut low);
        Num3072 { limbs: low }
    }

    /// Multiplication modulo `P`. Both factors are assumed reduced.
    pub fn mul(&self, other: &Num3072) -> Num3072 {
        Self::reduce_wide(&Self::mul_wide(&self.limbs, &other.limbs))
    }

    /// Raises to a power whose exponent is given as 48 limbs, by squaring and
    /// multiplying, from the most significant bit to the least significant.
    fn pow(&self, exp: &[u64; LIMBS]) -> Num3072 {
        let mut result = Num3072::one();
        for i in (0..LIMBS).rev() {
            for b in (0..64).rev() {
                result = result.mul(&result);
                if (exp[i] >> b) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Multiplicative inverse modulo `P`, by Fermat's little theorem.
    ///
    /// The inverse of the identity element is itself: the 3072 squarings are
    /// then skipped, which makes the case where nothing was removed free.
    pub fn inverse(&self) -> Num3072 {
        if self.is_one() {
            return Num3072::one();
        }
        self.pow(&EXP_INVERSE)
    }

    /// Builds an element from 384 bytes of entropy, from least to most
    /// significant. The raw value is below `2^3072`: a single conditional
    /// subtraction is enough to bring it under `P`. The zero value, with a
    /// probability of `2^-3072`, is raised to the identity element so as never
    /// to leave the group.
    fn from_wide_bytes(bytes: &[u8; LIMBS * 8]) -> Num3072 {
        let mut limbs = [0u64; LIMBS];
        for (i, l) in limbs.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            *l = u64::from_le_bytes(w);
        }
        Self::reduce_once(&mut limbs);
        let n = Num3072 { limbs };
        if limbs.iter().all(|&l| l == 0) {
            Num3072::one()
        } else {
            n
        }
    }

    /// Serializes into 384 bytes, from least to most significant. Used as the
    /// input of the final hash: two identical states produce the same bytes.
    fn to_bytes(self) -> [u8; LIMBS * 8] {
        let mut out = [0u8; LIMBS * 8];
        for (i, l) in self.limbs.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&l.to_le_bytes());
        }
        out
    }
}

/// Domain of the hash that seeds a group element from a piece of data.
const TAG_ELEMENT: &str = "Q21/muhash/element";
/// Domain of the counter-mode expansion.
const TAG_EXPANSION: &str = "Q21/muhash/expansion";
/// Domain of the final hash of the commitment.
///
/// Renamed in 0.4; the 0.3.x label is kept in
/// [`crate::legacy::LEGACY_MUHASH_TAG`]. The label is not part of consensus:
/// no block or header commits to it.
const TAG_COMMITMENT: &str = "Q21/muhash/commitment";

/// Seeds the group element associated with a piece of data.
///
/// The data is first hashed to 256 bits (collision resistance of tagged
/// SHA-256), then this seed is expanded to 3072 bits by twelve hashes in
/// counter mode. The result is a 3072-bit integer, uniformly distributed, a
/// deterministic function of the data.
fn element(data: &[u8]) -> Num3072 {
    let seed = tagged_hash(TAG_ELEMENT, data);
    let mut wide = [0u8; LIMBS * 8];
    for i in 0..12u8 {
        let block = tagged_hash_parts(TAG_EXPANSION, &[seed.as_bytes(), &[i]]);
        wide[i as usize * 32..i as usize * 32 + 32].copy_from_slice(block.as_bytes());
    }
    Num3072::from_wide_bytes(&wide)
}

/// MuHash accumulator: a commitment to the set of inserted outputs.
///
/// Two products are kept — a numerator and a denominator — rather than one.
/// Inserting multiplies the numerator; removing multiplies the denominator.
/// The single division — expensive, since it requires an inverse — is deferred
/// to the moment of the hash: `commitment = numerator / denominator`. A set
/// built by insertions alone therefore never pays for an inverse.
#[derive(Clone, Copy, Debug)]
pub struct MuHash {
    numerator: Num3072,
    denominator: Num3072,
}

impl Default for MuHash {
    fn default() -> Self {
        Self::new()
    }
}

impl MuHash {
    /// The commitment of the empty set: the empty product, that is the identity
    /// element in both the numerator and the denominator.
    pub fn new() -> MuHash {
        MuHash {
            numerator: Num3072::one(),
            denominator: Num3072::one(),
        }
    }

    /// Adds an output to the commitment.
    pub fn insert(&mut self, data: &[u8]) {
        self.numerator = self.numerator.mul(&element(data));
    }

    /// Removes an output from the commitment. `insert` then `remove` of the
    /// same data returns exactly to the starting state.
    pub fn remove(&mut self, data: &[u8]) {
        self.denominator = self.denominator.mul(&element(data));
    }

    /// Merges another commitment into this one — useful to fold the set in
    /// independent pieces before combining them. Associative and commutative.
    pub fn combine(&mut self, other: &MuHash) {
        self.numerator = self.numerator.mul(&other.numerator);
        self.denominator = self.denominator.mul(&other.denominator);
    }

    /// 256-bit hash of the current commitment.
    ///
    /// This is where, and the only time, the division happens: `numerator *
    /// inverse(denominator)`. If nothing was removed, the denominator is the
    /// identity element and the inverse is free.
    pub fn digest(&self) -> Hash256 {
        self.digest_with_tag(TAG_COMMITMENT)
    }

    /// The digest under an explicit final label.
    ///
    /// Only the upgrade of a 0.3.x data directory uses a label other than the
    /// current one: see [`crate::legacy`].
    pub fn digest_with_tag(&self, tag: &str) -> Hash256 {
        let accumulated = if self.denominator.is_one() {
            self.numerator
        } else {
            self.numerator.mul(&self.denominator.inverse())
        };
        tagged_hash(tag, &accumulated.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `Num3072` from small least significant limbs.
    fn num(low: &[u64]) -> Num3072 {
        let mut limbs = [0u64; LIMBS];
        limbs[..low.len()].copy_from_slice(low);
        Num3072 { limbs }
    }

    #[test]
    fn two_to_the_3072_equals_c() {
        // A product whose high half alone carries a 1 represents 2^3072.
        let mut product = [0u64; 2 * LIMBS];
        product[LIMBS] = 1;
        let r = Num3072::reduce_wide(&product);
        assert_eq!(r, num(&[C]), "2^3072 must fold to C");

        // 2^3072 + 5 -> C + 5.
        product[0] = 5;
        assert_eq!(Num3072::reduce_wide(&product), num(&[C + 5]));
    }

    #[test]
    fn small_product_without_reduction() {
        assert_eq!(num(&[2]).mul(&num(&[3])), num(&[6]));
        assert_eq!(num(&[7]).mul(&Num3072::one()), num(&[7]));
    }

    #[test]
    fn the_square_of_p_minus_one_is_one() {
        // (P-1)^2 = P^2 - 2P + 1 ≡ 1 (mod P). A blunt test of the reduction on
        // limbs that are all full.
        let mut pm1 = P_LIMBS;
        pm1[0] -= 1; // P - 1, already reduced (< P).
        let x = Num3072 { limbs: pm1 };
        assert_eq!(x.mul(&x), Num3072::one());
    }

    #[test]
    fn multiplication_is_commutative_and_associative() {
        let a = element(b"alice");
        let b = element(b"bob");
        let c = element(b"carol");
        assert_eq!(a.mul(&b), b.mul(&a));
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)));
    }

    #[test]
    fn an_element_times_its_inverse_is_one() {
        for seed in [b"x".as_slice(), b"an output", b"\x00\x01\x02", &[0xff; 40]] {
            let x = element(seed);
            assert_eq!(x.mul(&x.inverse()), Num3072::one(), "failed on {seed:?}");
        }
    }

    #[test]
    fn the_commitment_ignores_insertion_order() {
        let mut a = MuHash::new();
        a.insert(b"one");
        a.insert(b"two");
        a.insert(b"three");

        let mut b = MuHash::new();
        b.insert(b"three");
        b.insert(b"one");
        b.insert(b"two");

        assert_eq!(a.digest(), b.digest(), "order must not matter");
    }

    #[test]
    fn insert_then_remove_cancels_out() {
        let mut empty = MuHash::new();
        let empty_commitment = empty.digest();

        empty.insert(b"an ephemeral output");
        assert_ne!(empty.digest(), empty_commitment);
        empty.remove(b"an ephemeral output");
        assert_eq!(
            empty.digest(),
            empty_commitment,
            "insert then remove must return to the empty set"
        );
    }

    #[test]
    fn remove_then_insert_cancels_out_too() {
        // The denominator can go first: the order of the two operations does
        // not change the result, since everything resolves at the final
        // division.
        let mut a = MuHash::new();
        a.insert(b"p");
        a.insert(b"q");
        let target = a.digest();

        let mut b = MuHash::new();
        b.remove(b"parasite");
        b.insert(b"p");
        b.insert(b"parasite");
        b.insert(b"q");
        assert_eq!(b.digest(), target);
    }

    #[test]
    fn combining_equals_inserting_everything() {
        let mut whole = MuHash::new();
        for d in [b"a".as_slice(), b"b", b"c", b"d"] {
            whole.insert(d);
        }

        let mut left = MuHash::new();
        left.insert(b"a");
        left.insert(b"b");
        let mut right = MuHash::new();
        right.insert(b"c");
        right.insert(b"d");
        left.combine(&right);

        assert_eq!(left.digest(), whole.digest());
    }

    #[test]
    fn a_different_output_changes_the_commitment() {
        let mut a = MuHash::new();
        a.insert(b"output A");
        let mut b = MuHash::new();
        b.insert(b"output B");
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn the_empty_commitment_is_stable_and_deterministic() {
        assert_eq!(MuHash::new().digest(), MuHash::new().digest());
    }

    #[test]
    fn byte_round_trip_on_an_element() {
        let x = element(b"whatever");
        let y = Num3072::from_wide_bytes(&x.to_bytes());
        assert_eq!(x, y);
    }
}
