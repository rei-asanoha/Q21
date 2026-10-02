//! Deterministic serialization.
//!
//! Consensus tolerates only one encoding per object. If two nodes can
//! serialize the same transaction in two ways, they compute two ids, and the
//! chain splits.
//!
//! Hence three rules, applied without exception in this file.
//!
//! - **Little-endian everywhere.** A single byte order, never the host
//!   machine's.
//! - **Canonical variable-length integers.** A value has only one valid
//!   encoding. The decoder refuses the long form of a small number: Bitcoin
//!   accepted non-canonical encodings and that served as a malleability
//!   vector.
//! - **No structure with undefined order.** No hash table, no set: only
//!   sequences whose order is explicit.

pub struct Writer {
    buf: Vec<u8>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Variable-length integer, single canonical form.
    pub fn varint(&mut self, v: u64) -> &mut Self {
        match v {
            0..=0xfc => self.u8(v as u8),
            0xfd..=0xffff => {
                self.u8(0xfd);
                self.buf.extend_from_slice(&(v as u16).to_le_bytes());
                self
            }
            0x1_0000..=0xffff_ffff => {
                self.u8(0xfe);
                self.buf.extend_from_slice(&(v as u32).to_le_bytes());
                self
            }
            _ => {
                self.u8(0xff);
                self.buf.extend_from_slice(&v.to_le_bytes());
                self
            }
        }
    }

    /// Byte sequence prefixed with its length.
    pub fn var_bytes(&mut self, v: &[u8]) -> &mut Self {
        self.varint(v.len() as u64);
        self.bytes(v)
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ReadError {
    UnexpectedEnd,
    /// Non-canonical variable-length encoding: only one form is allowed.
    NonCanonicalVarint,
    InvalidValue,
    TrailingBytes(usize),
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Reads an element count, refusing what the rest of the input cannot
    /// hold.
    ///
    /// # The principle
    ///
    /// **We never reserve room for more elements than the rest of the input
    /// can hold.** Since each element has a known minimum size on the wire,
    /// the comparison is exact and free.
    ///
    /// # What this closes
    ///
    /// Without this check, a twenty-seven-byte frame announcing fifty
    /// thousand elements made us reserve one million six hundred fifty
    /// thousand bytes before failing on an unexpected end: **sixty-one
    /// thousand times** what had been received, for the price of one send.
    /// Capping the reservation (`with_capacity(n.min(1024))`) mitigated
    /// without closing: a factor of one thousand remained.
    ///
    /// The ratio was measured message by message, not assumed: see
    /// `rapport_allocation_par_message` in `tests/audit_arith.rs`.
    ///
    /// `minimum` is the number of bytes an element cannot fail to occupy.
    /// Underestimating it weakens the check; overestimating it would refuse
    /// valid data. When in doubt, underestimate.
    ///
    /// # Why `try_from` and not `as`
    ///
    /// The count arrives as a `u64`. On a 32-bit target, `as usize`
    /// truncates: `(1 << 32) + 1` became `1`, and a count that every 64-bit
    /// node refuses was read as a single element by a 32-bit node. The same
    /// block valid for some and invalid for others is a chain split by
    /// architecture. A count that does not fit in `usize` cannot fit in the
    /// input: it is refused with the same error as on 64 bits, where the
    /// capacity check refuses it.
    pub fn read_count(&mut self, minimum: usize) -> Result<usize, ReadError> {
        let n = usize::try_from(self.varint()?).map_err(|_| ReadError::InvalidValue)?;
        // `checked_div` returns None when `minimum` is zero, which disables
        // the check; that is exactly the intended convention.
        if let Some(max_fit) = self.remaining().checked_div(minimum) {
            if n > max_fit {
                return Err(ReadError::InvalidValue);
            }
        }
        Ok(n)
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        if self.remaining() < n {
            return Err(ReadError::UnexpectedEnd);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, ReadError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, ReadError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    pub fn array32(&mut self) -> Result<[u8; 32], ReadError> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// Reads a variable-length integer, refusing any non-canonical form.
    pub fn varint(&mut self) -> Result<u64, ReadError> {
        let tag = self.u8()?;
        let v = match tag {
            0..=0xfc => return Ok(tag as u64),
            0xfd => {
                let b = self.take(2)?;
                let v = u16::from_le_bytes([b[0], b[1]]) as u64;
                if v < 0xfd {
                    return Err(ReadError::NonCanonicalVarint);
                }
                v
            }
            0xfe => {
                let b = self.take(4)?;
                let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= 0xffff {
                    return Err(ReadError::NonCanonicalVarint);
                }
                v
            }
            0xff => {
                let v = self.u64()?;
                if v <= 0xffff_ffff {
                    return Err(ReadError::NonCanonicalVarint);
                }
                v
            }
        };
        Ok(v)
    }

    /// Byte sequence prefixed with its length.
    ///
    /// Same rule as [`Self::read_count`]: a length that does not fit in
    /// `usize` cannot be served by the input, and ends in the same
    /// unexpected end that `take` would return on 64 bits, never in a silent
    /// truncation that would read a different length.
    pub fn var_bytes(&mut self) -> Result<&'a [u8], ReadError> {
        let n = usize::try_from(self.varint()?).map_err(|_| ReadError::UnexpectedEnd)?;
        self.take(n)
    }

    /// Checks that no byte trails after the decoded object.
    ///
    /// Without this check, one could append data at the end of a transaction
    /// without changing its interpretation, which is a classic malleability
    /// vector.
    pub fn expect_end(&self) -> Result<(), ReadError> {
        if self.remaining() != 0 {
            return Err(ReadError::TrailingBytes(self.remaining()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_on_integers() {
        let mut w = Writer::new();
        w.u8(0xab).u32(0xdead_beef).u64(0x0123_4567_89ab_cdef);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert_eq!(r.u8().unwrap(), 0xab);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), 0x0123_4567_89ab_cdef);
        assert!(r.expect_end().is_ok());
    }

    #[test]
    fn varints_cross_thresholds_correctly() {
        for v in [
            0u64,
            1,
            0xfc,
            0xfd,
            0xff,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut w = Writer::new();
            w.varint(v);
            let b = w.finish();
            let mut r = Reader::new(&b);
            assert_eq!(r.varint().unwrap(), v, "failure on {v}");
            assert!(r.expect_end().is_ok());
        }
    }

    #[test]
    fn varints_use_shortest_form() {
        let mut w = Writer::new();
        w.varint(0xfc);
        assert_eq!(w.finish().len(), 1);

        let mut w = Writer::new();
        w.varint(0xfd);
        assert_eq!(w.finish().len(), 3);
    }

    #[test]
    fn non_canonical_varints_are_refused() {
        // 0xfd followed by a value that fit in a single byte.
        assert_eq!(
            Reader::new(&[0xfd, 0x01, 0x00]).varint(),
            Err(ReadError::NonCanonicalVarint)
        );
        // 0xfe followed by a value that fit in two bytes.
        assert_eq!(
            Reader::new(&[0xfe, 0x01, 0x00, 0x00, 0x00]).varint(),
            Err(ReadError::NonCanonicalVarint)
        );
        // 0xff followed by a value that fit in four bytes.
        assert_eq!(
            Reader::new(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0]).varint(),
            Err(ReadError::NonCanonicalVarint)
        );
    }

    /// A count that does not fit in 32 bits is refused the same way on every
    /// target.
    ///
    /// # The defect this test pins down
    ///
    /// `read_count` and `var_bytes` converted the varint with `as usize`. On
    /// a 32-bit target, `(1 << 32) + 1` became `1`: an ARMv7 node read "one
    /// element" where an x86_64 node refused the frame. The varint is built
    /// by hand, byte by byte, so that the test does not depend on the
    /// encoder: `ff` then the eight little-endian bytes of `0x1_0000_0001`.
    #[test]
    fn count_beyond_32_bits_is_refused_on_every_target() {
        let long_form = [0xffu8, 0x01, 0, 0, 0, 0x01, 0, 0, 0];
        // The varint alone reads fine: it is a canonical u64.
        assert_eq!(Reader::new(&long_form).varint(), Ok(0x1_0000_0001));

        // A count followed by a single payload byte: whatever the width of
        // `usize`, the answer is InvalidValue.
        let mut frame = long_form.to_vec();
        frame.push(0xaa);
        for minimum in [1usize, 40, 160] {
            assert_eq!(
                Reader::new(&frame).read_count(minimum),
                Err(ReadError::InvalidValue),
                "minimum {minimum}"
            );
        }
        // A byte sequence announced at more than 4 GiB: unexpected end, never
        // a read of a single byte.
        assert_eq!(
            Reader::new(&frame).var_bytes(),
            Err(ReadError::UnexpectedEnd)
        );
        // And the maximum value, for good measure.
        let mut extreme = vec![0xffu8];
        extreme.extend_from_slice(&u64::MAX.to_le_bytes());
        extreme.push(0xaa);
        assert_eq!(
            Reader::new(&extreme).read_count(1),
            Err(ReadError::InvalidValue)
        );
        assert_eq!(
            Reader::new(&extreme).var_bytes(),
            Err(ReadError::UnexpectedEnd)
        );
    }

    #[test]
    fn trailing_bytes_are_reported() {
        let b = [1u8, 2, 3];
        let mut r = Reader::new(&b);
        r.u8().unwrap();
        assert_eq!(r.expect_end(), Err(ReadError::TrailingBytes(2)));
    }

    #[test]
    fn truncated_input_does_not_panic() {
        assert_eq!(Reader::new(&[]).u32(), Err(ReadError::UnexpectedEnd));
        assert_eq!(Reader::new(&[1, 2]).u32(), Err(ReadError::UnexpectedEnd));
        assert_eq!(
            Reader::new(&[0x05, 1, 2]).var_bytes(),
            Err(ReadError::UnexpectedEnd)
        );
    }

    #[test]
    fn round_trip_on_sequences() {
        let payload = vec![9u8; 500];
        let mut w = Writer::new();
        w.var_bytes(&payload);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert_eq!(r.var_bytes().unwrap(), &payload[..]);
    }

    #[test]
    fn encoding_is_machine_independent() {
        // Explicit little-endian: the first byte is the least significant.
        let mut w = Writer::new();
        w.u32(1);
        assert_eq!(w.finish(), vec![1, 0, 0, 0]);
    }
}
