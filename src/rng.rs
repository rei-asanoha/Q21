//! System entropy. The building block everything else depends on.
//!
//! # Why this module exists
//!
//! A private key is only worth its randomness. A wallet whose seed is
//! predictable is an empty wallet: it does not matter that the signature is
//! post-quantum, that the proof of work is memory-hard, that the cap is
//! inviolable. It is the weakest link in the chain, and it is the one people
//! look at least.
//!
//! # What phase 8 fixed
//!
//! The previous version did:
//!
//! ```text
//! std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?
//! ```
//!
//! Two defects, one functional and one of design.
//!
//! **Functional**: `/dev/urandom` does not exist on Windows. `q21 init` simply
//! failed there. Wallet software that does not start on the most widespread
//! system is not wallet software.
//!
//! **Design**: no check of what came out. A device returning zeros —
//! misconfigured virtual machine, exotic container, disk mounted read-only —
//! would have produced an all-zero seed without anyone noticing before losing
//! their funds.
//!
//! # What this module does not do, deliberately
//!
//! It does not **mix** anything. No clock, no process identifier, no memory
//! addresses added "for good measure". Mixing a strong source with weak
//! sources strengthens nothing and hides the failure: if the system generator
//! is broken, we need to know it and stop, not fabricate an illusion of
//! randomness with a clock.
//!
//! So the rule is: **we get entropy from the system, or we fail.**

use std::fmt;

#[derive(Debug)]
pub enum RngError {
    /// The system generator cannot be reached.
    Unavailable(String),
    /// The generator returned something implausible.
    SuspiciousOutput(&'static str),
}

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RngError::Unavailable(d) => write!(
                f,
                "system random number generator unavailable: {d}\n  \
                 No key will be created: better no wallet than a \
                 predictable wallet."
            ),
            RngError::SuspiciousOutput(d) => write!(
                f,
                "the system random number generator returned a suspicious output ({d}).\n  \
                 Creation aborted."
            ),
        }
    }
}

impl std::error::Error for RngError {}

/// Fills `out` with cryptographic randomness from the system.
///
/// # Errors
///
/// Fails rather than return randomness of unknown quality. No fallback is
/// provided, and that is the important point of this module.
pub fn fill(out: &mut [u8]) -> Result<(), RngError> {
    imp::fill(out)?;
    check(out)
}

/// Draws `N` random bytes from the system.
pub fn bytes<const N: usize>() -> Result<[u8; N], RngError> {
    let mut b = [0u8; N];
    fill(&mut b)?;
    Ok(b)
}

/// Plausibility checks on the generator output.
///
/// These checks prove nothing about cryptographic quality — no statistical
/// test can on 32 bytes. They catch outright failures: a device returning
/// zeros, a buffer never written, a constant value. It is little, and it is
/// infinitely better than nothing.
///
/// # Constant time
///
/// The bytes examined are secrets: the wallet seed, the "hedged" randomness
/// of each ML-DSA signature. The previous version indexed a table by the
/// value of each byte (`seen[x]`) and branched on it: a cache or
/// branch-predictor neighbor could thus read part of the seed at the very
/// moment it was born. Here, no memory access and no branch depends on the
/// value of the bytes; only the final verdict, which is not secret, does.
fn check(b: &[u8]) -> Result<(), RngError> {
    if b.len() < 8 {
        return Ok(());
    }
    let mut or_all = 0u8;
    let mut diff = 0u8;
    for &x in b {
        or_all |= x;
        diff |= x ^ b[0];
    }
    // On 32 uniformly drawn bytes, seeing fewer than 8 distinct values is
    // overwhelmingly likely to be a failure, not bad luck. The count sweeps
    // the 256 possible values instead of indexing a table.
    let mut distinct = 0u32;
    if b.len() >= 32 {
        for v in 0..=255u8 {
            let mut present = 0u8;
            for &x in b {
                present |= bytes_equal(x, v);
            }
            distinct += u32::from(present);
        }
    }
    if or_all == 0 {
        return Err(RngError::SuspiciousOutput("all bytes are zero"));
    }
    if diff == 0 {
        return Err(RngError::SuspiciousOutput("all bytes are identical"));
    }
    if b.len() >= 32 && distinct < 8 {
        return Err(RngError::SuspiciousOutput("too few distinct values"));
    }
    Ok(())
}

/// 1 if `a == b`, 0 otherwise, without branching: `(a ^ b) - 1` only
/// overflows into the ninth bit when the difference is zero.
fn bytes_equal(a: u8, b: u8) -> u8 {
    let d = u16::from(a ^ b);
    ((d.wrapping_sub(1) >> 8) & 1) as u8
}

// ---------------------------------------------------------------------------
// Unix: /dev/urandom
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::RngError;
    use std::io::Read;

    /// What an entropy system call can tell us other than success.
    ///
    /// Used only by the `getrandom`/`getentropy` paths; on another Unix, only
    /// `/dev/urandom` is used and this type does not exist.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    enum Failure {
        /// The call does not exist on this kernel/version: we can fall back
        /// to `/dev/urandom` without losing anything.
        Unavailable,
        /// The call exists but failed outright: we stop, we do not invent
        /// randomness.
        Fatal(String),
    }

    pub fn fill(out: &mut [u8]) -> Result<(), RngError> {
        // The point of this fix: `/dev/urandom` NEVER BLOCKS. At the very
        // first boot of a machine — a virtual machine cloned from a snapshot,
        // a container, an embedded image — the kernel entropy pool may not be
        // initialized yet, and `/dev/urandom` then returns predictable bytes
        // without saying so. The plausibility checks of `check` do not catch
        // such a state: the output "looks" random.
        //
        // `getrandom(2)` (Linux) and `getentropy(3)` (macOS/BSD) share the
        // SAME generator as `/dev/urandom`, but BLOCK until the pool is
        // initialized, once, and then never block again. That is exactly the
        // guarantee that was missing. We fall back to the file only if the
        // call does not exist (kernel older than 3.17).
        #[cfg(any(target_os = "linux", target_os = "android"))]
        match getrandom_blocking(out) {
            Ok(()) => return Ok(()),
            Err(Failure::Unavailable) => {}
            Err(Failure::Fatal(d)) => return Err(RngError::Unavailable(d)),
        }

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        match getentropy_blocking(out) {
            Ok(()) => return Ok(()),
            Err(Failure::Unavailable) => {}
            Err(Failure::Fatal(d)) => return Err(RngError::Unavailable(d)),
        }

        from_urandom(out)
    }

    /// Historical fallback. `/dev/urandom` and not `/dev/random`: since Linux
    /// 4.8 both share the same generator, and `/dev/random` can block
    /// indefinitely without adding anything.
    fn from_urandom(out: &mut [u8]) -> Result<(), RngError> {
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| RngError::Unavailable(format!("/dev/urandom: {e}")))?;
        f.read_exact(out)
            .map_err(|e| RngError::Unavailable(format!("/dev/urandom: {e}")))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn getrandom_blocking(out: &mut [u8]) -> Result<(), Failure> {
        let mut filled = 0usize;
        while filled < out.len() {
            // Flag 0: `/dev/urandom` source, blocking until the pool is
            // initialized. SAFETY: the pointer and length designate the part
            // of `out` not yet filled, valid and exclusive; the call writes
            // only into this buffer.
            let n = unsafe {
                libc::getrandom(
                    out[filled..].as_mut_ptr() as *mut libc::c_void,
                    out.len() - filled,
                    0,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    // Interrupted by a signal before any byte: try again.
                    Some(libc::EINTR) => continue,
                    // Kernel older than 3.17: the call does not exist.
                    Some(libc::ENOSYS) => return Err(Failure::Unavailable),
                    _ => return Err(Failure::Fatal(format!("getrandom: {e}"))),
                }
            }
            filled += n as usize;
        }
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn getentropy_blocking(out: &mut [u8]) -> Result<(), Failure> {
        // `getentropy` accepts at most 256 bytes per call: we split. A 32-byte
        // seed fits in a single call anyway.
        for chunk in out.chunks_mut(256) {
            // SAFETY: `chunk` is a valid and exclusive slice of length
            // <= 256; the call writes only into this buffer.
            let r =
                unsafe { libc::getentropy(chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
            if r != 0 {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::ENOSYS) => return Err(Failure::Unavailable),
                    _ => return Err(Failure::Fatal(format!("getentropy: {e}"))),
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windows: BCryptGenRandom
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::RngError;

    // Official interface of the Windows generator, exposed by bcrypt.dll.
    // It is the one Microsoft has recommended since Vista, and the one the
    // Rust ecosystem uses. We declare it by hand rather than depend on a
    // crate: the Q21 core has no mandatory dependency.
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    /// Asks Windows to use its system generator without our having to open
    /// an algorithm provider.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    pub fn fill(out: &mut [u8]) -> Result<(), RngError> {
        // `BCryptGenRandom` takes a 32-bit length: we split, which will never
        // happen in practice for a 32-byte seed but avoids a silent
        // truncation if this module is ever used for something else.
        for chunk in out.chunks_mut(u32::MAX as usize) {
            // SAFETY: `chunk` is a valid and exclusive slice, its length fits
            // in 32 bits by construction of `chunks_mut`, and the API writes
            // only into this buffer.
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(RngError::Unavailable(format!(
                    "BCryptGenRandom returned status 0x{status:08x}"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Everything else: we refuse rather than invent
// ---------------------------------------------------------------------------

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::RngError;

    pub fn fill(_out: &mut [u8]) -> Result<(), RngError> {
        Err(RngError::Unavailable(
            "no known entropy source on this platform".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_provides_randomness() {
        let a: [u8; 32] = bytes().expect("the system must provide entropy");
        assert!(!a.iter().all(|&x| x == 0));
    }

    /// Two identical successive draws would mean a broken generator. The
    /// probability of an honest collision on 32 bytes is 2^-256.
    #[test]
    fn two_draws_differ() {
        let a: [u8; 32] = bytes().unwrap();
        let b: [u8; 32] = bytes().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn degenerate_outputs_are_refused() {
        assert!(matches!(
            check(&[0u8; 32]),
            Err(RngError::SuspiciousOutput(_))
        ));
        assert!(matches!(
            check(&[0x42u8; 32]),
            Err(RngError::SuspiciousOutput(_))
        ));
        // Only two distinct values: still suspicious.
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = if i % 2 == 0 { 1 } else { 2 };
        }
        assert!(matches!(check(&b), Err(RngError::SuspiciousOutput(_))));
    }

    /// The branchless comparison is exact on all 65,536 pairs.
    #[test]
    fn branchless_comparison_is_exact() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(bytes_equal(a, b), u8::from(a == b), "{a} {b}");
            }
        }
    }

    /// The eight-distinct-values threshold did not move with the
    /// constant-time rewrite: seven values are refused, eight pass.
    #[test]
    fn distinct_values_threshold_is_unchanged() {
        let make = |n: u8| {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = 0x10 + (i as u8 % n);
            }
            b
        };
        assert!(matches!(
            check(&make(7)),
            Err(RngError::SuspiciousOutput(_))
        ));
        assert!(check(&make(8)).is_ok());
        // Extreme values 0x00 and 0xff counted like the others.
        let mut b = make(6);
        b[0] = 0x00;
        b[1] = 0xff;
        assert!(check(&b).is_ok());
    }

    #[test]
    fn a_normal_output_passes() {
        let a: [u8; 32] = bytes().unwrap();
        assert!(check(&a).is_ok());
    }

    /// A draw of any length must remain correct.
    #[test]
    fn unusual_lengths_work() {
        for n in [1usize, 7, 33, 100, 1024] {
            let mut v = vec![0u8; n];
            fill(&mut v).unwrap();
        }
    }

    /// Rough measure of uniformity: over 4096 bytes, each bit must be one
    /// about half the time. This test attests nothing about the
    /// cryptography; it catches an outright biased generator.
    #[test]
    fn output_is_not_grossly_biased() {
        let mut v = vec![0u8; 4096];
        fill(&mut v).unwrap();
        let ones: u32 = v.iter().map(|b| b.count_ones()).sum();
        let total = (v.len() * 8) as u32;
        let deviation = (ones as i64 - (total / 2) as i64).unsigned_abs();
        assert!(
            deviation < total as u64 / 20,
            "{ones} one bits out of {total}: abnormal bias"
        );
    }
}
