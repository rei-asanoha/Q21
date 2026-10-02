//! Bech32m (BIP-350).
//!
//! Encoding format of addresses. Chosen over Base58Check for three reasons:
//! the single case avoids transcription errors, the BCH error-correcting code
//! detects any error of 4 characters or fewer, and the prefix/data separation
//! distinguishes mainnet from testnet without ambiguity.
//!
//! Q21 uses the Bech32m constant (`0x2bc830a3`) and not the one of the original
//! Bech32, which suffered from a weakness on padding characters.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];
const BECH32M_CONST: u32 = 0x2bc8_30a3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Bech32Error {
    InvalidHrp,
    InvalidChar,
    MixedCase,
    InvalidChecksum,
    TooShort,
    TooLong,
    MissingSeparator,
    InvalidPadding,
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GENERATOR.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

/// Regroups bits (8 to 5 when encoding, 5 to 8 when decoding).
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv: u32 = (1 << to) - 1;

    for &value in data {
        if (value as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | value as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// Encodes a prefix and a payload in Bech32m.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    if hrp.is_empty() || hrp.len() > 83 {
        return Err(Bech32Error::InvalidHrp);
    }
    if hrp.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(Bech32Error::InvalidHrp);
    }
    if hrp.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(Bech32Error::MixedCase);
    }

    let fives = convert_bits(data, 8, 5, true).ok_or(Bech32Error::InvalidChar)?;

    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(&fives);
    checksum_input.extend_from_slice(&[0u8; 6]);
    let poly = polymod(&checksum_input) ^ BECH32M_CONST;

    let mut out = String::with_capacity(hrp.len() + 1 + fives.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for b in &fives {
        out.push(CHARSET[*b as usize] as char);
    }
    for i in 0..6 {
        let idx = ((poly >> (5 * (5 - i))) & 31) as usize;
        out.push(CHARSET[idx] as char);
    }

    if out.len() > 90 {
        return Err(Bech32Error::TooLong);
    }
    Ok(out)
}

/// Decodes a Bech32m string and returns the prefix and the payload.
pub fn decode(s: &str) -> Result<(String, Vec<u8>), Bech32Error> {
    if s.len() < 8 {
        return Err(Bech32Error::TooShort);
    }
    if s.len() > 90 {
        return Err(Bech32Error::TooLong);
    }

    let has_lower = s.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = s.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let s = s.to_ascii_lowercase();

    let sep = s.rfind('1').ok_or(Bech32Error::MissingSeparator)?;
    if sep == 0 || sep + 7 > s.len() {
        return Err(Bech32Error::MissingSeparator);
    }

    let hrp = &s[..sep];
    if hrp.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err(Bech32Error::InvalidHrp);
    }

    let mut values = Vec::with_capacity(s.len() - sep - 1);
    for c in s[sep + 1..].bytes() {
        let pos = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or(Bech32Error::InvalidChar)?;
        values.push(pos as u8);
    }

    let mut checksum_input = hrp_expand(hrp);
    checksum_input.extend_from_slice(&values);
    if polymod(&checksum_input) != BECH32M_CONST {
        return Err(Bech32Error::InvalidChecksum);
    }

    let data = &values[..values.len() - 6];
    let bytes = convert_bits(data, 5, 8, false).ok_or(Bech32Error::InvalidPadding)?;
    Ok((hrp.to_string(), bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let payload = [0u8, 1, 2, 250, 255, 128, 64];
        let s = encode("q21", &payload).unwrap();
        let (hrp, out) = decode(&s).unwrap();
        assert_eq!(hrp, "q21");
        assert_eq!(out, payload);
    }

    #[test]
    fn round_trip_on_thirty_three_bytes() {
        let payload: Vec<u8> = (0..33u8).collect();
        let s = encode("q21", &payload).unwrap();
        assert_eq!(decode(&s).unwrap().1, payload);
    }

    #[test]
    fn one_changed_char_breaks_checksum() {
        let s = encode("q21", &[1, 2, 3, 4, 5]).unwrap();
        let mut bytes = s.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'q' { b'p' } else { b'q' };
        let altered = String::from_utf8(bytes).unwrap();
        assert_eq!(decode(&altered), Err(Bech32Error::InvalidChecksum));
    }

    #[test]
    fn mixed_case_is_refused() {
        let s = encode("q21", &[1, 2, 3]).unwrap();
        let mut c: Vec<char> = s.chars().collect();
        c[0] = c[0].to_ascii_uppercase();
        let mixed: String = c.into_iter().collect();
        assert_eq!(decode(&mixed), Err(Bech32Error::MixedCase));
    }

    #[test]
    fn all_uppercase_is_accepted() {
        let payload = [9u8, 8, 7];
        let s = encode("q21", &payload).unwrap();
        assert_eq!(decode(&s.to_ascii_uppercase()).unwrap().1, payload);
    }

    #[test]
    fn network_prefixes_are_distinct() {
        let payload = [1u8, 2, 3];
        let mainnet = encode("q21", &payload).unwrap();
        let test = encode("tq21", &payload).unwrap();
        assert_ne!(mainnet, test);
        assert!(mainnet.starts_with("q21"));
        assert!(test.starts_with("tq21"));
        // A decoded testnet address must not pass for mainnet.
        assert_eq!(decode(&test).unwrap().0, "tq21");
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert!(decode("").is_err());
        assert!(decode("q21").is_err());
        assert!(decode("noseparator").is_err());
        assert!(decode("1q21abcdef").is_err());
    }
}
