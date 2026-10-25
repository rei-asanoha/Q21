//! cSHAKE256 and KMAC256 (NIST SP 800-185), for the channel transport.
//!
//! Both are defined over the Keccak-f\[1600\] sponge at the 256-bit security
//! level (rate 136 bytes). The permutation is the vendored `keccak` crate's,
//! the one `sha3` and `shake` run; only the SP 800-185 layer is written here,
//! because none of the vendored crates carries it. That layer is small:
//!
//! - `left_encode` / `right_encode` / `encode_string` / `bytepad` (§2.3);
//! - cSHAKE256(X, L, N, S) = KECCAK\[512\](bytepad(encode_string(N) ||
//!   encode_string(S), 136) || X || 00, L), and plain SHAKE256 when `N` and `S`
//!   are both empty (§3);
//! - KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X ||
//!   right_encode(L), L, "KMAC", S) (§4).
//!
//! The tests check every path against the NIST sample values ("cSHAKE
//! samples" 3 and 4, "KMAC samples" 4 to 6) and SHAKE256 against the
//! platform's own implementation.

/// The cSHAKE256 / KMAC256 rate in bytes.
const RATE: usize = 136;

/// A Keccak-f\[1600\] sponge absorbing and squeezing bytes at [`RATE`]. Its
/// state is wiped when dropped: it holds key material while a KMAC runs.
#[derive(Clone)]
struct Sponge {
    state: [u64; 25],
    /// Next byte of the rate to absorb into or squeeze from.
    pos: usize,
    squeezing: bool,
}

impl Sponge {
    fn new() -> Sponge {
        Sponge {
            state: [0; 25],
            pos: 0,
            squeezing: false,
        }
    }

    fn permute(&mut self) {
        keccak::Keccak::new().with_f1600(|f| f(&mut self.state));
    }

    fn absorb(&mut self, data: &[u8]) {
        debug_assert!(!self.squeezing);
        for &b in data {
            self.state[self.pos / 8] ^= u64::from(b) << (8 * (self.pos % 8));
            self.pos += 1;
            if self.pos == RATE {
                self.permute();
                self.pos = 0;
            }
        }
    }

    /// Absorbs zero bytes up to the next multiple of `RATE` from the
    /// position `absorbed` bytes into the padded string: `bytepad`'s tail.
    fn pad_zeros(&mut self, absorbed: usize) {
        let rem = absorbed % RATE;
        if rem != 0 {
            self.absorb(&[0u8; RATE][..RATE - rem]);
        }
    }

    /// Closes absorption with the domain bits and pad10*1 already merged in
    /// `suffix` (0x1F for SHAKE, 0x04 for cSHAKE).
    fn finish(&mut self, suffix: u8) {
        self.state[self.pos / 8] ^= u64::from(suffix) << (8 * (self.pos % 8));
        self.state[(RATE - 1) / 8] ^= 0x80u64 << (8 * ((RATE - 1) % 8));
        self.permute();
        self.pos = 0;
        self.squeezing = true;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        debug_assert!(self.squeezing);
        for o in out.iter_mut() {
            if self.pos == RATE {
                self.permute();
                self.pos = 0;
            }
            *o = (self.state[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
            self.pos += 1;
        }
    }
}

impl Drop for Sponge {
    fn drop(&mut self) {
        for w in self.state.iter_mut() {
            // Safe: each pointer comes from a valid element of the array.
            unsafe { std::ptr::write_volatile(w, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// `left_encode(x)` (SP 800-185 §2.3.1): the byte count, then `x` big-endian
/// in the fewest bytes (at least one). Returns the buffer and its length.
fn left_encode(x: u64) -> ([u8; 9], usize) {
    let mut out = [0u8; 9];
    let n = (8 - (x.leading_zeros() as usize / 8)).max(1);
    out[0] = n as u8;
    out[1..=n].copy_from_slice(&x.to_be_bytes()[8 - n..]);
    (out, n + 1)
}

/// `right_encode(x)` (SP 800-185 §2.3.1): `x` big-endian in the fewest bytes
/// (at least one), then the byte count.
fn right_encode(x: u64) -> ([u8; 9], usize) {
    let mut out = [0u8; 9];
    let n = (8 - (x.leading_zeros() as usize / 8)).max(1);
    out[..n].copy_from_slice(&x.to_be_bytes()[8 - n..]);
    out[n] = n as u8;
    (out, n + 1)
}

/// Absorbs `encode_string(s)` and returns how many bytes that was.
fn absorb_encoded_string(sponge: &mut Sponge, s: &[u8]) -> usize {
    let (len, n) = left_encode((s.len() as u64) * 8);
    sponge.absorb(&len[..n]);
    sponge.absorb(s);
    n + s.len()
}

/// cSHAKE256 (SP 800-185 §3), absorbing incrementally. Cloning it forks the
/// hash, which a transcript uses to take intermediate values.
#[derive(Clone)]
pub struct CShake256 {
    sponge: Sponge,
    /// `N` and `S` both empty: plain SHAKE256, as §3.3 requires.
    plain: bool,
}

impl CShake256 {
    /// A cSHAKE256 instance with function name `n` and customization `s`.
    pub fn new(n: &[u8], s: &[u8]) -> CShake256 {
        let mut sponge = Sponge::new();
        let plain = n.is_empty() && s.is_empty();
        if !plain {
            let (w, k) = left_encode(RATE as u64);
            sponge.absorb(&w[..k]);
            let mut absorbed = k;
            absorbed += absorb_encoded_string(&mut sponge, n);
            absorbed += absorb_encoded_string(&mut sponge, s);
            sponge.pad_zeros(absorbed);
        }
        CShake256 { sponge, plain }
    }

    pub fn update(&mut self, x: &[u8]) {
        self.sponge.absorb(x);
    }

    /// Fills `out` with the first `out.len()` bytes of output: `L` is
    /// `8 * out.len()`, and a longer `L` extends a shorter one.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        self.sponge.finish(if self.plain { 0x1F } else { 0x04 });
        self.sponge.squeeze(out);
    }

    /// The first 32 bytes of output.
    pub fn finalize32(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.finalize_into(&mut out);
        out
    }

    /// Absorbs `bytepad(encode_string(key), 136)`: a key in blocks of its
    /// own, as KMAC places it (§4.3).
    pub fn absorb_key(&mut self, key: &[u8]) {
        let (w, k) = left_encode(RATE as u64);
        self.sponge.absorb(&w[..k]);
        let absorbed = k + absorb_encoded_string(&mut self.sponge, key);
        self.sponge.pad_zeros(absorbed);
    }
}

/// KMAC256 (SP 800-185 §4) with key `key` and customization `s`, absorbing
/// incrementally; its output length is fixed at [`Kmac256::finalize_into`].
pub struct Kmac256 {
    inner: CShake256,
}

impl Kmac256 {
    pub fn new(key: &[u8], s: &[u8]) -> Kmac256 {
        let mut inner = CShake256::new(b"KMAC", s);
        inner.absorb_key(key);
        Kmac256 { inner }
    }

    pub fn update(&mut self, x: &[u8]) {
        self.inner.update(x);
    }

    /// Fills `out` with KMAC256(K, X, 8 * `out.len()`, S). Unlike cSHAKE,
    /// the length is part of the input: outputs of two lengths are unrelated.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        let (l, n) = right_encode((out.len() as u64) * 8);
        self.inner.update(&l[..n]);
        self.inner.finalize_into(out);
    }
}

/// KMAC256 of the concatenation of `parts`, into `out`.
pub fn kmac256(key: &[u8], s: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut k = Kmac256::new(key, s);
    for p in parts {
        k.update(p);
    }
    k.finalize_into(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn range(a: u8, b: u8) -> Vec<u8> {
        (a..=b).collect()
    }

    #[test]
    fn encodings_follow_sp_800_185() {
        let le = |x| {
            let (b, n) = left_encode(x);
            b[..n].to_vec()
        };
        let re = |x| {
            let (b, n) = right_encode(x);
            b[..n].to_vec()
        };
        assert_eq!(le(0), vec![1, 0]);
        assert_eq!(le(136), vec![1, 136]);
        assert_eq!(le(256), vec![2, 1, 0]);
        assert_eq!(re(0), vec![0, 1]);
        assert_eq!(re(512), vec![2, 0, 2]);
        assert_eq!(le(u64::MAX), {
            let mut v = vec![8];
            v.extend([0xff; 8]);
            v
        });
    }

    /// SHAKE256 (empty `N` and `S`) against the platform's implementation:
    /// one-block, multi-block and rate-boundary inputs, with a multi-block
    /// squeeze. Expected values computed with Python's `hashlib.shake_256`.
    #[test]
    fn plain_cshake_is_shake256() {
        let cases: [(Vec<u8>, &str); 3] = [
            (
                Vec::new(),
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
            ),
            (
                vec![0xa3; 200],
                "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d",
            ),
            (
                (0..=135u8).collect(),
                "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a",
            ),
        ];
        for (input, want) in cases {
            let mut h = CShake256::new(b"", b"");
            h.update(&input);
            let mut out = [0u8; 32];
            h.finalize_into(&mut out);
            assert_eq!(out.to_vec(), hex(want));
        }
        // A squeeze across three permutations.
        let mut h = CShake256::new(b"", b"");
        h.update(b"abc");
        let mut out = vec![0u8; 300];
        h.finalize_into(&mut out);
        assert_eq!(out[268..300].to_vec(), hex(SHAKE256_ABC_268_300));
    }

    /// Bytes 268..300 of SHAKE256("abc"), from `hashlib.shake_256`.
    const SHAKE256_ABC_268_300: &str =
        "2ddf384af3334560ea1d363966caa7d8ddcbec7da52b42215c11d5f8ee57f341";

    /// NIST SP 800-185 "cSHAKE samples", samples #3 and #4 (cSHAKE256).
    #[test]
    fn cshake256_matches_the_nist_samples() {
        let mut h = CShake256::new(b"", b"Email Signature");
        h.update(&[0x00, 0x01, 0x02, 0x03]);
        let mut out = [0u8; 64];
        h.finalize_into(&mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD1
                 64020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C"
            )
        );

        let mut h = CShake256::new(b"", b"Email Signature");
        h.update(&range(0x00, 0xC7));
        let mut out = [0u8; 64];
        h.finalize_into(&mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917
                 27F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB"
            )
        );
    }

    /// NIST SP 800-185 "KMAC samples", samples #4, #5 and #6 (KMAC256).
    #[test]
    fn kmac256_matches_the_nist_samples() {
        let key = range(0x40, 0x5F);
        let mut out = [0u8; 64];

        kmac256(
            &key,
            b"My Tagged Application",
            &[&[0x00, 0x01, 0x02, 0x03]],
            &mut out,
        );
        assert_eq!(
            out.to_vec(),
            hex(
                "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7
                 F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"
            )
        );

        kmac256(&key, b"", &[&range(0x00, 0xC7)], &mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691
                 589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"
            )
        );

        // Split across updates: the same as one input.
        let data = range(0x00, 0xC7);
        kmac256(
            &key,
            b"My Tagged Application",
            &[&data[..7], &data[7..150], &data[150..]],
            &mut out,
        );
        assert_eq!(
            out.to_vec(),
            hex(
                "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D9
                 70FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"
            )
        );
    }

    #[test]
    fn the_sponge_state_is_wiped_on_drop() {
        let mut k = std::mem::ManuallyDrop::new(Kmac256::new(&[0x55; 32], b"t"));
        k.update(b"x");
        let p: *const [u64; 25] = &k.inner.sponge.state;
        assert_ne!(unsafe { *p }, [0u64; 25]);
        let after = unsafe {
            std::mem::ManuallyDrop::drop(&mut k);
            std::ptr::read_volatile(p)
        };
        assert_eq!(after, [0u64; 25]);
    }
}
