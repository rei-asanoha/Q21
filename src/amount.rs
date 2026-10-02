//! Monetary amounts.
//!
//! An `Amount` is an unsigned integer number of indivisible units. There is no
//! conversion from a float, and that is deliberate: `0.1 + 0.2 != 0.3` in
//! IEEE 754, and a currency that accepts that approximation loses money.
//!
//! All arithmetic is checked. An overflow returns `None`, never a silently
//! wrong result.

use crate::consensus::{DECIMALS, MAX_SUPPLY, UNITS_PER_COIN};
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Amount = Amount(0);
    pub const MAX: Amount = Amount(MAX_SUPPLY);

    /// Builds an amount from a number of indivisible units.
    pub const fn from_units(units: u64) -> Self {
        Amount(units)
    }

    /// Builds an amount from a whole number of Q21.
    pub fn from_coins(coins: u64) -> Option<Self> {
        coins.checked_mul(UNITS_PER_COIN).map(Amount)
    }

    pub const fn units(self) -> u64 {
        self.0
    }

    /// True if the amount respects the protocol cap.
    ///
    /// An amount that is valid as a number can still be invalid as an
    /// amount: no output can carry more than the total supply.
    pub const fn is_within_supply(self) -> bool {
        self.0 <= MAX_SUPPLY
    }

    pub fn checked_add(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_add(rhs.0).map(Amount)
    }

    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_sub(rhs.0).map(Amount)
    }

    /// Sum of an iterator of amounts, failing on overflow.
    ///
    /// Used to total the outputs of a transaction. A naive `sum()` that
    /// silently overflows would allow money to be created out of thin air.
    pub fn checked_sum<I: IntoIterator<Item = Amount>>(iter: I) -> Option<Amount> {
        let mut total = Amount::ZERO;
        for a in iter {
            total = total.checked_add(a)?;
        }
        Some(total)
    }
}

impl fmt::Display for Amount {
    /// Formats in Q21 with the 8 decimals, without ever going through a float.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / UNITS_PER_COIN;
        let frac = self.0 % UNITS_PER_COIN;
        write!(f, "{}.{:0width$}", whole, frac, width = DECIMALS as usize)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} Q21)", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_display_without_float() {
        assert_eq!(Amount::from_units(0).to_string(), "0.00000000");
        assert_eq!(Amount::from_units(1).to_string(), "0.00000001");
        assert_eq!(Amount::from_units(100_000_000).to_string(), "1.00000000");
        assert_eq!(Amount::from_units(1_384_711_800).to_string(), "13.84711800");
    }

    #[test]
    fn addition_reports_overflow() {
        let almost = Amount::from_units(u64::MAX);
        assert_eq!(almost.checked_add(Amount::from_units(1)), None);
    }

    #[test]
    fn subtraction_never_goes_below_zero() {
        let a = Amount::from_units(10);
        assert_eq!(a.checked_sub(Amount::from_units(11)), None);
        assert_eq!(a.checked_sub(Amount::from_units(10)), Some(Amount::ZERO));
    }

    #[test]
    fn sum_refuses_to_overflow() {
        let big = Amount::from_units(u64::MAX / 2);
        assert_eq!(Amount::checked_sum([big, big, big]), None);
        assert_eq!(
            Amount::checked_sum([Amount::from_units(3), Amount::from_units(4)]),
            Some(Amount::from_units(7))
        );
    }

    #[test]
    fn cap_is_recognized() {
        assert!(Amount::MAX.is_within_supply());
        assert!(!Amount::from_units(MAX_SUPPLY + 1).is_within_supply());
    }
}
