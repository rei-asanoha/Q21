//! Upgrade of a data directory written by q21 0.3.x.
//!
//! The binary must translate the legacy file names, keys and values at
//! startup, before anything reads the directory. The security-critical case:
//! a wallet that was told not to be reachable (`joignable=non` in
//! `reglages.txt`) must stay closed after the upgrade. An absent setting means
//! "reachable", so losing that line would open the router port and publish the
//! user's home address.

use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::TARGET_BLOCK_SECS;
use q21_core::hash::Hash256;
use q21_core::legacy;
use q21_core::sig::SchemeId;
use q21_core::state::{StateError, StateStore};
use q21_core::Network;
use std::path::{Path, PathBuf};
use std::process::Command;

const NETWORK: Network = Network::Regtest;

fn fresh_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("q21-upgrade-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Runs the binary on `datadir` with a command that touches the directory.
/// Its outcome does not matter here (there is no wallet): what matters is
/// what it did to the directory before running the command.
fn start_binary(datadir: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_q21"))
        .arg("--datadir")
        .arg(datadir)
        .arg("info")
        .output()
        .expect("run q21");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A 0.3.x directory as that version left it: settings, wallet anchor,
/// bootstrap list, header store and lock file under their legacy names.
fn write_legacy_dir(d: &Path, reachable: &str) {
    std::fs::write(d.join("reglages.txt"), format!("joignable={reachable}\n")).unwrap();
    std::fs::write(
        d.join("wallet.ancre"),
        "scelle=1\ngraine=4d1eaf81102523ada2edc0051c6258c1dce30c7b03d5fb69bd5d24147e06d32c\n",
    )
    .unwrap();
    std::fs::write(
        d.join("amorces.txt"),
        "# my entry points\nnode.example.org:21221\n198.51.100.7:21221\n",
    )
    .unwrap();
    std::fs::write(d.join("entetes.dat"), b"not a real header store").unwrap();
    std::fs::write(d.join(".verrou"), b"").unwrap();
}

/// Security regression: `joignable=non` survives the upgrade as
/// `reachable=no`, through the real startup path of the binary.
#[test]
fn a_not_reachable_wallet_stays_not_reachable_after_upgrade() {
    let d = fresh_dir("closed");
    write_legacy_dir(&d, "non");
    // Before the upgrade, the new reader sees no setting: the default would
    // be "reachable". This is exactly what must not happen.
    assert!(q21_core::settings::reachable(&d));

    let stderr = start_binary(&d);

    assert!(
        !d.join("reglages.txt").exists(),
        "the old settings file is still there: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(d.join("settings.txt")).unwrap(),
        "reachable=no\n"
    );
    assert!(
        !q21_core::settings::reachable(&d),
        "the node would become reachable after the upgrade"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_reachable_wallet_stays_reachable_after_upgrade() {
    let d = fresh_dir("open");
    write_legacy_dir(&d, "oui");
    start_binary(&d);
    assert!(q21_core::settings::reachable(&d));
    let _ = std::fs::remove_dir_all(&d);
}

/// The other legacy files are carried over by the same startup path.
#[test]
fn the_other_legacy_files_are_carried_over() {
    let d = fresh_dir("files");
    write_legacy_dir(&d, "non");
    start_binary(&d);

    assert_eq!(
        q21_core::bootstrap::bootstrap_from_datadir(&d),
        vec![
            "node.example.org:21221".to_string(),
            "198.51.100.7:21221".to_string()
        ]
    );
    assert!(!d.join("amorces.txt").exists());
    let anchor = std::fs::read_to_string(d.join("wallet.anchor")).unwrap();
    assert!(anchor.contains("sealed=1"), "{anchor}");
    assert!(!d.join("wallet.ancre").exists());
    assert_eq!(
        std::fs::read(d.join("headers.dat")).unwrap(),
        b"not a real header store"
    );
    assert!(!d.join(".verrou").exists());
    assert!(d.join(".lock").exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// A state snapshot written by 0.3.x records its MuHash under the old label.
/// The upgrade rewrites it under the new one, after a full check, so that a
/// pruned or adopted directory keeps its state instead of resynchronizing.
#[test]
fn a_legacy_state_snapshot_loads_after_upgrade() {
    let d = fresh_dir("state");
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=8 {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([2u8; 32]), SchemeId::LamportOts, &[], t, 50_000_000)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }
    let mut legacy_snapshot = c.snapshot_at_depth(2).expect("snapshot");
    let expected = legacy_snapshot.clone();
    legacy_snapshot.muhash = legacy_snapshot
        .utxo
        .commitment_with_tag(legacy::LEGACY_MUHASH_TAG);

    let key = q21_core::state::datadir_key(&d).unwrap();
    let store = StateStore::new_sealed(d.join("state.dat"), key);
    store.save(&legacy_snapshot).unwrap();
    assert!(
        matches!(store.load(NETWORK), Err(StateError::InvalidCommitment)),
        "a 0.3.x snapshot does not load under the new label"
    );

    start_binary(&d);

    let loaded = store
        .load(NETWORK)
        .expect("the snapshot loads after the upgrade");
    assert_eq!(loaded, expected);
    assert_eq!(
        loaded.commitment(),
        c.snapshot_at_depth(2).unwrap().commitment()
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A snapshot whose content does not reproduce its recorded MuHash under the
/// old label is not trusted by the upgrade: it stays unusable, and the node
/// rebuilds its state from the block file as for any damaged snapshot.
#[test]
fn a_forged_legacy_snapshot_is_not_relabeled() {
    let d = fresh_dir("forged");
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=4 {
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(Hash256([3u8; 32]), SchemeId::LamportOts, &[], t, 50_000_000)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }
    let mut forged = c.snapshot_at_depth(2).expect("snapshot");
    forged.muhash = Hash256([0xAB; 32]);
    let key = q21_core::state::datadir_key(&d).unwrap();
    let store = StateStore::new_sealed(d.join("state.dat"), key);
    store.save(&forged).unwrap();

    start_binary(&d);

    assert!(matches!(
        store.load(NETWORK),
        Err(StateError::InvalidCommitment)
    ));
    let _ = std::fs::remove_dir_all(&d);
}

/// Seals `plaintext` as 0.3.x did (format 2: Argon2id, `Q21SCEL2`, legacy
/// keystream label). Written from the format's description rather than with
/// the library, so that the test does not merely agree with itself.
fn seal_like_0_3(passphrase: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use q21_core::argon2::{derive_key, Params, Variant};
    use q21_core::kdf::hmac_sha256;
    // The default cost of 0.3.x, which 0.4 keeps: a real 0.3.x wallet is not
    // resealed for its cost, only converted.
    let (memory_kib, passes) = (64 * 1024u32, 3u32);
    let salt = [0x5au8; 16];
    let params = Params {
        variant: Variant::Id,
        memory_kib,
        passes,
        lanes: 1,
    };
    let raw = derive_key(params, passphrase, &salt, &[], &[], 64);
    let (encryption, authentication) = raw.split_at(32);
    let mut out = Vec::new();
    out.extend_from_slice(legacy::LEGACY_SEAL_V2_MAGIC);
    out.extend_from_slice(&memory_kib.to_le_bytes());
    out.extend_from_slice(&passes.to_le_bytes());
    out.extend_from_slice(&salt);
    for (counter, chunk) in (0u64..).zip(plaintext.chunks(32)) {
        let mut input = legacy::LEGACY_KEYSTREAM_LABEL.to_vec();
        input.extend_from_slice(&counter.to_le_bytes());
        let block = hmac_sha256(encryption, &input);
        out.extend(chunk.iter().zip(block.iter()).map(|(p, k)| p ^ k));
    }
    let mac = hmac_sha256(authentication, &out);
    out.extend_from_slice(&mac);
    out
}

fn run_with_passphrase(d: &Path, passphrase: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_q21"))
        .arg("--datadir")
        .arg(d)
        .arg("--passphrase-file")
        .arg(passphrase)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run q21")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A wallet left by 0.3.x — sealed in format 2, with the old `wallet.dat`
/// keys, a `wallet.ancre` holding the fingerprint under the old label, and an
/// address cache authenticated under the old key — opens under 0.4: it is
/// neither refused as "another seed" nor rescanned from scratch, it keeps its
/// next index and its consumed keys, and it is converted on the spot.
#[test]
fn a_wallet_left_by_0_3_opens_and_is_converted() {
    use q21_core::kdf;
    use q21_core::state::AddressCache;
    use q21_core::wallet::Wallet;

    let d = fresh_dir("wallet");
    let passphrase = d.with_extension("passphrase");
    std::fs::write(&passphrase, "upgrade test passphrase\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&passphrase, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let phrase = b"upgrade test passphrase";

    // A real wallet with two addresses handed out.
    let s = run_with_passphrase(&d, &passphrase, &["init", "regtest", "lamport"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let mut handed_out = Vec::new();
    for _ in 0..2 {
        let s = run_with_passphrase(&d, &passphrase, &["address"]);
        assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
        handed_out.push(String::from_utf8_lossy(&s.stdout).trim().to_string());
    }

    // Turned back into what 0.3.x wrote.
    let current = kdf::unseal(phrase, &std::fs::read(d.join("wallet.dat")).unwrap()).unwrap();
    let current = String::from_utf8(current).unwrap();
    let seed_hex = current
        .lines()
        .find_map(|l| l.strip_prefix("seed="))
        .unwrap()
        .to_string();
    let seed = Wallet::seed_from_hex(&seed_hex).unwrap();
    let next_index = current
        .lines()
        .find_map(|l| l.strip_prefix("next_index="))
        .unwrap()
        .to_string();
    let serial = current
        .lines()
        .find_map(|l| l.strip_prefix("serial="))
        .unwrap()
        .to_string();
    let scheme = current
        .lines()
        .find_map(|l| l.strip_prefix("scheme="))
        .unwrap()
        .to_string();
    assert_eq!(scheme, SchemeId::LamportOts.as_u8().to_string());
    let old_plaintext = format!(
        "seed={seed_hex}\nnext_index={next_index}\nnetwork=regtest\nscheme={scheme}\n\
         serie={serial}\nverifie_jusqu_a=0\nconsommes=0\netiquettes=\ndemandees=0,1\nreserves=\n"
    );
    std::fs::write(
        d.join("wallet.dat"),
        seal_like_0_3(phrase, old_plaintext.as_bytes()),
    )
    .unwrap();

    let w = Wallet::from_seed(seed, NETWORK);
    let legacy_fingerprint = w.public_fingerprint(legacy::LEGACY_DATADIR_LABEL);
    std::fs::remove_file(d.join(legacy::ANCHOR_FILE)).unwrap();
    std::fs::write(
        d.join(legacy::LEGACY_ANCHOR_FILE),
        format!("scelle=1\ngraine={}\n", hex(&legacy_fingerprint)),
    )
    .unwrap();

    let cache = AddressCache::new(d.join("addresses.dat"));
    let hashes = cache.load(SchemeId::LamportOts, &w.cache_key()).unwrap();
    cache
        .save(SchemeId::LamportOts, &hashes, &w.legacy_cache_key())
        .unwrap();

    // Opened by 0.4.
    let s = run_with_passphrase(&d, &passphrase, &["address"]);
    let (out, err) = (
        String::from_utf8_lossy(&s.stdout).to_string(),
        String::from_utf8_lossy(&s.stderr).to_string(),
    );
    assert!(s.status.success(), "{out}\n{err}");
    assert!(
        out.contains("Wallet converted to the 0.4 file format"),
        "{out}\n{err}"
    );
    assert!(!err.contains("address cache ignored"), "{err}");
    let third = out.lines().last().unwrap().trim().to_string();
    assert!(
        !handed_out.contains(&third),
        "an address was handed out twice"
    );

    // Converted: format 3, new key names, consumed keys kept, new anchor, new
    // cache key.
    let raw = std::fs::read(d.join("wallet.dat")).unwrap();
    assert!(kdf::is_current_format(&raw));
    let content = String::from_utf8(kdf::unseal(phrase, &raw).unwrap()).unwrap();
    for (old, new) in legacy::LEGACY_WALLET_KEYS {
        assert!(!content.contains(&format!("\n{old}=")), "{content}");
        assert!(content.contains(&format!("\n{new}=")), "{content}");
    }
    assert!(content.contains("\nconsumed=0\n"), "{content}");
    let expected_next = next_index.parse::<u32>().unwrap() + 1;
    assert!(
        content.contains(&format!("\nnext_index={expected_next}\n")),
        "{content}"
    );
    let anchor = std::fs::read_to_string(d.join(legacy::ANCHOR_FILE)).unwrap();
    assert!(anchor.contains("sealed=1"), "{anchor}");
    assert!(!anchor.contains(&hex(&legacy_fingerprint)), "{anchor}");
    assert!(cache.load(SchemeId::LamportOts, &w.cache_key()).is_ok());

    // And converted once: the next opening says nothing.
    let s = run_with_passphrase(&d, &passphrase, &["address"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    assert!(!String::from_utf8_lossy(&s.stdout).contains("converted"));

    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&passphrase);
}
