//! Adversarial attack on the Q21 vault, before launch.
//!
//! Defensive goal: prove that an attacker can neither get a silently wrong
//! seed out of a damaged backup code, nor confuse an address with a backup,
//! nor cross a network, nor open a sealed file without the passphrase, nor
//! corrupt its plaintext without being detected, nor lower its derivation
//! cost.
//!
//! Each test PASSES when the ATTACK FAILS: a green test means the barrier
//! held. A red test would be a breach to fix.
//!
//! Build/run: `cargo test --locked --features audit --test attack_vault`

use q21_core::address::Network;
use q21_core::kdf::{self, SealError, DEFAULT_COST, TEST_COST};
use q21_core::wallet::{Wallet, WalletError};

/// Bech32(m) alphabet. Used to make a typo that stays within the character
/// set — therefore rejected by the checksum, not by a character outside the
/// alphabet.
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// A reproducible but arbitrary seed.
fn test_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, o) in s.iter_mut().enumerate() {
        *o = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    s
}

// ---------------------------------------------------------------------------
// 1. Typo in the backup code.
//
//    A single character changed in the data part must always be rejected by
//    the Bech32m checksum. Never a different seed returned silently.
// ---------------------------------------------------------------------------
#[test]
fn typo_in_the_backup_code_is_rejected() {
    let network = Network::Regtest;
    let seed = test_seed();
    let w = Wallet::from_seed(seed, network);
    let code = w.backup_code();

    // Position of the Bech32 separator: the last '1'. The data follows.
    let sep = code.rfind('1').expect("a Bech32 code has a separator");
    let bytes = code.as_bytes();

    let mut positions_tested = 0usize;
    for i in (sep + 1)..code.len() {
        let original = bytes[i];
        // Another character of the same alphabet: a real typo.
        let replacement = *CHARSET
            .iter()
            .find(|&&c| c != original)
            .expect("another character exists");
        let mut damaged: Vec<u8> = bytes.to_vec();
        damaged[i] = replacement;
        let damaged = String::from_utf8(damaged).unwrap();

        match Wallet::seed_from_backup(&damaged, network) {
            Err(_) => positions_tested += 1,
            Ok(other) => panic!(
                "BREACH: a typo at position {i} returned a seed silently ({}). \
                 Expected: checksum error.\n\
                 origin={seed:02x?}\nreturned={other:02x?}",
                if other == seed {
                    "identical"
                } else {
                    "DIFFERENT"
                },
            ),
        }
    }
    assert!(positions_tested > 0, "no data position tested");
}

// ---------------------------------------------------------------------------
// 2. Address / seed confusion.
//
//    A receiving address pasted in place of a backup code must be recognized
//    as such — dedicated error — and never decoded into a seed.
// ---------------------------------------------------------------------------
#[test]
fn an_address_is_never_taken_for_a_backup() {
    for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let mut w = Wallet::from_seed(test_seed(), network);
        let address = w.new_address().to_string_bech32();

        let r = Wallet::seed_from_backup(&address, network);
        assert_eq!(
            r,
            Err(WalletError::BackupIsAnAddress),
            "BREACH: the address {address} was not recognized as an address \
             (network {network:?}), result = {r:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Wrong network.
//
//    A Testnet backup code must never open a Regtest or Mainnet wallet:
//    network error, no seed.
// ---------------------------------------------------------------------------
#[test]
fn a_code_from_another_network_is_refused() {
    let w_testnet = Wallet::from_seed(test_seed(), Network::Testnet);
    let code = w_testnet.backup_code();

    for network in [Network::Regtest, Network::Mainnet] {
        let r = Wallet::seed_from_backup(&code, network);
        assert_eq!(
            r,
            Err(WalletError::BackupForOtherNetwork),
            "BREACH: a Testnet code was accepted (or misdiagnosed) \
             on {network:?}, result = {r:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Honest round trip (non-regression).
//
//    The intact code gives back exactly the original seed.
// ---------------------------------------------------------------------------
#[test]
fn honest_backup_code_round_trip() {
    for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let seed = test_seed();
        let w = Wallet::from_seed(seed, network);
        let returned = Wallet::seed_from_backup(&w.backup_code(), network)
            .expect("an intact code must read back");
        assert_eq!(
            returned, seed,
            "the round trip changed the seed ({network:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Sealed file — wrong passphrase.
//
//    Seal with passphrase A, try to open with passphrase B: authentication
//    refused, the plaintext never appears.
// ---------------------------------------------------------------------------
#[test]
fn unsealing_with_the_wrong_passphrase_fails() {
    let secret = b"seed=deadbeef, must never leak";
    let passphrase_a = b"correct horse battery staple";
    let passphrase_b = b"correct horse battery stapler"; // one more letter

    let sealed = kdf::seal(passphrase_a, secret, TEST_COST).expect("sealing");

    let r = kdf::unseal(passphrase_b, &sealed);
    match r {
        Err(SealError::AuthenticationFailed) => {}
        Ok(plaintext) => panic!(
            "BREACH: a wrong passphrase opened the vault. plaintext returned = {:02x?}",
            plaintext
        ),
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    }
    // And above all: the secret did not leak, not even partially.
    if let Ok(plaintext) = &r {
        assert_ne!(plaintext.as_slice(), secret, "the plaintext leaked");
    }
}

// ---------------------------------------------------------------------------
// 6. Sealed file — one byte altered.
//
//    No flipped byte (body, header, salt, MAC) may produce a plaintext. Two
//    points are checked:
//      a) exhaustive — any flip of one byte makes unsealing fail;
//      b) targeted — a byte of the encrypted body and a byte of the salt do
//         give AuthenticationFailed (the MAC covers the header and the body).
// ---------------------------------------------------------------------------
#[test]
fn altering_a_byte_of_the_sealed_file_is_always_detected() {
    let secret = b"32 bytes of very secret seed!!!!";
    let passphrase = b"passphrase of the legitimate owner";
    let sealed = kdf::seal(passphrase, secret, TEST_COST).expect("sealing");

    // a) Exhaustive: every byte, flipped, must make opening fail, NEVER
    //    return a plaintext (corrupted or not).
    for i in 0..sealed.len() {
        let mut damaged = sealed.clone();
        damaged[i] ^= 0x01;
        match kdf::unseal(passphrase, &damaged) {
            Err(_) => {}
            Ok(plaintext) => panic!(
                "BREACH: byte {i} flipped, unseal returned a plaintext {:02x?} \
                 (original secret {:02x?})",
                plaintext, secret
            ),
        }
    }

    // b) Targeted, encrypted body: format
    //    MAGIC_V2(8) memory(4) passes(4) salt(16) ciphertext(n) mac(32).
    //    The first byte of the ciphertext is at offset 32.
    const CIPHERTEXT_START: usize = 8 + 4 + 4 + 16;
    let mut corrupted_body = sealed.clone();
    corrupted_body[CIPHERTEXT_START] ^= 0xFF;
    assert_eq!(
        kdf::unseal(passphrase, &corrupted_body),
        Err(SealError::AuthenticationFailed),
        "BREACH: a byte of the encrypted body did not trigger the MAC",
    );

    // b') Targeted, salt (header, within bounds): covered by the MAC as well.
    let mut corrupted_salt = sealed.clone();
    corrupted_salt[16] ^= 0xFF; // first byte of the salt
    assert_eq!(
        kdf::unseal(passphrase, &corrupted_salt),
        Err(SealError::AuthenticationFailed),
        "BREACH: a byte of the salt did not trigger the MAC",
    );
}

// ---------------------------------------------------------------------------
// 7. Lowering the KDF cost.
//
//    The header exposes memory_kib and passes. An attacker rewrites them to
//    force a weak derivation. The MAC covers the header: opening must be
//    refused, never return the plaintext.
//
//    Two variants:
//      a) LOW value but within bounds (TEST_COST) -> the cost becomes legal,
//         but the MAC (computed over the original header) fails:
//         AuthenticationFailed;
//      b) ABSURD value out of bounds -> rejected BEFORE any derivation:
//         CostOutOfRange.
//    In both cases: no plaintext.
// ---------------------------------------------------------------------------
#[test]
fn lowering_the_kdf_cost_is_rejected() {
    let secret = b"secret protected by 64 MiB of Argon2id";
    let passphrase = b"the right passphrase, the owner's";

    // Sealed at the default cost (64 MiB, 3 passes).
    let sealed = kdf::seal(passphrase, secret, DEFAULT_COST).expect("sealing");

    // The header does announce the default cost.
    assert_eq!(kdf::stored_cost(&sealed), Some(DEFAULT_COST));

    // a) Rewritten to a low but legal cost (TEST_COST: 64 KiB, 1 pass).
    let mut lowered = sealed.clone();
    lowered[8..12].copy_from_slice(&TEST_COST.memory_kib.to_le_bytes());
    lowered[12..16].copy_from_slice(&TEST_COST.passes.to_le_bytes());
    // The header now lies, but with the RIGHT passphrase:
    let r = kdf::unseal(passphrase, &lowered);
    match r {
        Err(SealError::AuthenticationFailed) => {}
        Ok(plaintext) => panic!(
            "BREACH: cost lowered to 64 KiB/1 pass accepted, plaintext returned {:02x?}",
            plaintext
        ),
        other => panic!(
            "legal lowered cost: expected AuthenticationFailed (the MAC covers \
             the header), got {other:?}"
        ),
    }

    // b) Rewritten to an absurd out-of-bounds value (memory = 1 KiB).
    let mut absurd = sealed.clone();
    absurd[8..12].copy_from_slice(&1u32.to_le_bytes());
    match kdf::unseal(passphrase, &absurd) {
        Err(SealError::CostOutOfRange { .. }) => {}
        Ok(plaintext) => panic!(
            "BREACH: absurd cost accepted, plaintext returned {:02x?}",
            plaintext
        ),
        other => panic!("out-of-bounds cost: expected CostOutOfRange, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 8. Honest sealed round trip.
//
//    unseal(passphrase, seal(passphrase, secret)) gives back exactly the
//    secret.
// ---------------------------------------------------------------------------
#[test]
fn honest_sealed_round_trip() {
    let secret = b"the original plaintext, intact";
    let passphrase = b"passphrase of the vault";

    let sealed = kdf::seal(passphrase, secret, TEST_COST).expect("sealing");
    let returned = kdf::unseal(passphrase, &sealed).expect("legitimate opening");
    assert_eq!(returned.as_slice(), secret, "sealing altered the plaintext");
}
