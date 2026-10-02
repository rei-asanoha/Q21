//! 256-bit integers.
//!
//! Difficulty targets live in the space of hashes: 256 bits. Rust stops at
//! 128, and importing a big-integer crate for consensus code would amount to
//! entrusting the definition of the currency to a dependency.
//!
//! So we implement the strict minimum: comparison, addition, multiplication
//! and division by a 64-bit scalar, and the conversions. Nothing more. Every
//! operation reports its overflow rather than silently absorbing it.

use core::cmp::Ordering;

/// 256-bit unsigned integer, stored as four 64-bit limbs, from least to most
/// significant.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Hash)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub const fn from_u64(v: u64) -> U256 {
        U256([v, 0, 0, 0])
    }

    /// From 32 big-endian bytes, the order in which a hash is read.
    pub fn from_be_bytes(b: &[u8; 32]) -> U256 {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().rev().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i * 8..i * 8 + 8]);
            *limb = u64::from_be_bytes(w);
        }
        U256(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().rev().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0u64; 4]
    }

    /// The 64 least significant bits. Truncates silently: use only where the
    /// caller already knows the value fits (a bounded quotient, a counter),
    /// never on a target or an amount.
    pub fn low_u64(self) -> u64 {
        self.0[0]
    }

    /// Number of significant bits. Zero has zero.
    pub fn bits(self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    pub fn checked_add(self, rhs: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (s1, c1) = a.overflowing_add(*b);
            let (s2, c2) = s1.overflowing_add(carry);
            *o = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Multiplication by a 64-bit scalar.
    pub fn checked_mul_u64(self, rhs: u64) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for (o, a) in out.iter_mut().zip(self.0.iter()) {
            let p = *a as u128 * rhs as u128 + carry;
            *o = p as u64;
            carry = p >> 64;
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Division by a 64-bit scalar. Returns `None` if the divisor is zero.
    pub fn checked_div_u64(self, rhs: u64) -> Option<U256> {
        if rhs == 0 {
            return None;
        }
        let mut out = [0u64; 4];
        let mut rem: u128 = 0;
        for i in (0..4).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            out[i] = (cur / rhs as u128) as u64;
            rem = cur % rhs as u128;
        }
        Some(U256(out))
    }

    /// Addition modulo 2^256, without overflow reporting.
    ///
    /// Used by the mixing loop of the proof of work, where overflow is
    /// intended: we are mixing, not counting money.
    pub fn wrapping_add(self, rhs: U256) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (s1, c1) = a.overflowing_add(*b);
            let (s2, c2) = s1.overflowing_add(carry);
            *o = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        U256(out)
    }

    /// Ones' complement.
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> U256 {
        U256([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    /// Subtraction, `None` if the result would be negative.
    pub fn checked_sub(self, rhs: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for ((o, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (d1, b1) = a.overflowing_sub(*b);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *o = d2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        if borrow != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Bit at index `i`, from least to most significant.
    pub fn bit(self, i: usize) -> bool {
        if i >= 256 {
            return false;
        }
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, i: usize) {
        if i < 256 {
            self.0[i / 64] |= 1u64 << (i % 64);
        }
    }

    /// Shift left by one bit.
    fn shl1(self) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (o, a) in out.iter_mut().zip(self.0.iter()) {
            *o = (a << 1) | carry;
            carry = a >> 63;
        }
        U256(out)
    }

    /// Full Euclidean division, by binary long division.
    ///
    /// Needed to compute the work of a block, which is `2^256 / (target + 1)`
    /// and does not reduce to a division by a 64-bit scalar. Two hundred
    /// fifty-six iterations: negligible at the rate it is called.
    pub fn div_rem(self, rhs: U256) -> Option<(U256, U256)> {
        if rhs.is_zero() {
            return None;
        }
        let mut q = U256::ZERO;
        let mut r = U256::ZERO;
        for i in (0..256).rev() {
            r = r.shl1();
            if self.bit(i) {
                r.set_bit(0);
            }
            if r >= rhs {
                r = r.checked_sub(rhs).expect("r >= rhs checked just above");
                q.set_bit(i);
            }
        }
        Some((q, r))
    }

    /// Multiplication then division, avoiding intermediate overflow.
    ///
    /// Essential to difficulty adjustment: `target * duration / target_duration`
    /// overflows if one multiplies first. So we divide first when the product
    /// does not fit.
    pub fn mul_div(self, mul: u64, div: u64) -> Option<U256> {
        if div == 0 {
            return None;
        }
        match self.checked_mul_u64(mul) {
            Some(p) => p.checked_div_u64(div),
            None => {
                // The product overflows: we lose a little precision by dividing
                // first, which is acceptable for a difficulty target.
                self.checked_div_u64(div)?.checked_mul_u64(mul)
            }
        }
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                other_order => return other_order,
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_round_trip() {
        for v in [0u64, 1, u64::MAX, 0x0123_4567_89ab_cdef] {
            let u = U256::from_u64(v);
            assert_eq!(U256::from_be_bytes(&u.to_be_bytes()), u);
        }
        let big = U256([1, 2, 3, 4]);
        assert_eq!(U256::from_be_bytes(&big.to_be_bytes()), big);
    }

    #[test]
    fn big_endian_order_is_respected() {
        // The value 1 must read as the very last byte.
        let b = U256::ONE.to_be_bytes();
        assert_eq!(b[31], 1);
        assert_eq!(b[..31], [0u8; 31]);
    }

    #[test]
    fn comparison_on_high_limbs() {
        assert!(U256([0, 0, 0, 1]) > U256([u64::MAX, u64::MAX, u64::MAX, 0]));
        assert!(U256::ZERO < U256::ONE);
        assert_eq!(U256::MAX.cmp(&U256::MAX), Ordering::Equal);
    }

    #[test]
    fn addition_with_carry() {
        let a = U256([u64::MAX, 0, 0, 0]);
        assert_eq!(a.checked_add(U256::ONE), Some(U256([0, 1, 0, 0])));
        assert_eq!(U256::MAX.checked_add(U256::ONE), None);
    }

    #[test]
    fn multiplication_and_division_are_inverses() {
        let a = U256([0x1234_5678, 0xabcd, 0, 0]);
        let p = a.checked_mul_u64(1000).unwrap();
        assert_eq!(p.checked_div_u64(1000), Some(a));
    }

    #[test]
    fn multiplication_reports_overflow() {
        assert_eq!(U256::MAX.checked_mul_u64(2), None);
        assert_eq!(U256::MAX.checked_mul_u64(1), Some(U256::MAX));
    }

    #[test]
    fn division_by_zero_is_refused() {
        assert_eq!(U256::ONE.checked_div_u64(0), None);
        assert_eq!(U256::ONE.mul_div(5, 0), None);
    }

    #[test]
    fn mul_div_survives_intermediate_overflow() {
        // The product would overflow, but the final result fits easily.
        let almost_max = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1]);
        let r = almost_max.mul_div(4, 4).expect("mul_div must cope");
        // Tolerance: the fallback path divides first and loses a few units.
        let relative_gap_ok = r <= almost_max && r >= almost_max.checked_div_u64(2).unwrap();
        assert!(relative_gap_ok);
    }

    #[test]
    fn bit_count() {
        assert_eq!(U256::ZERO.bits(), 0);
        assert_eq!(U256::ONE.bits(), 1);
        assert_eq!(U256::from_u64(u64::MAX).bits(), 64);
        assert_eq!(U256([0, 1, 0, 0]).bits(), 65);
        assert_eq!(U256::MAX.bits(), 256);
    }
}
