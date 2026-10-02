//! Regressions of the adversarial audit v2 — wallet and cryptography.
//!
//! Each test replays the audit's proof against the binary or the library,
//! and requires the fixed behavior: the backup code no longer goes through
//! the command line (V1), the wallet temporary file is born restricted and
//! the directory is private (V2), a substituted wallet is refused (V3), two
//! ML-DSA signatures of the same message differ (V6), a file sealed below
//! the default cost is resealed (V9), and an abandoned Lamport reservation
//! becomes free again (V8).

use q21_core::address::Network;
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::sig::SchemeId;
use q21_core::wallet::Wallet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn q21() -> &'static str {
    env!("CARGO_BIN_EXE_q21")
}

fn test_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("q21-regression-v2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A file readable by its owner only, as the documentation asks.
fn private_file(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0)
}

fn run(datadir: &Path, passphrase: &Path, args: &[&str]) -> std::process::Output {
    Command::new(q21())
        .arg("--datadir")
        .arg(datadir)
        .arg("--passphrase-file")
        .arg(passphrase)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("starting q21")
}

fn first_address(output: &[u8]) -> String {
    String::from_utf8_lossy(output)
        .lines()
        .find(|l| l.starts_with("rq21") || l.starts_with("tq21"))
        .unwrap_or("")
        .to_string()
}

/// V1 — the backup code no longer goes through `argv`.
///
/// A code given as an argument is refused with the reason (terminal history,
/// `/proc`), and the documented path — `--backup-code-file` — restores
/// exactly the wallet of the seed without the code ever appearing in the
/// process command line.
#[test]
fn v1_the_backup_code_no_longer_goes_through_the_command_line() {
    let d = test_dir("restore-argv");
    std::fs::create_dir_all(&d).unwrap();
    let passphrase = d.join("passphrase.txt");
    private_file(&passphrase, "test passphrase\n");
    let code = Wallet::from_seed([0x5a; 32], Network::Regtest).backup_code();

    // The code as an argument: refused, and the reason is given.
    let target = d.join("by-argument");
    let s = run(
        &target,
        &passphrase,
        &["restore", &code, "regtest", "lamport"],
    );
    let err = String::from_utf8_lossy(&s.stderr);
    assert!(
        !s.status.success(),
        "FINDING: `q21 restore <code>` accepted the code through argv:\n{}",
        String::from_utf8_lossy(&s.stdout)
    );
    assert!(
        err.contains("history") && err.contains("--backup-code-file"),
        "the refusal must explain why and what to do:\n{err}"
    );
    assert!(
        !target.join("wallet.dat").exists(),
        "nothing must have been written after a refusal"
    );

    // The documented path: a file readable by its owner only.
    let code_file = d.join("code.txt");
    private_file(&code_file, &format!("{code}\n"));
    let target = d.join("by-file");
    // The `mut` is for the Linux block below, which calls `child.try_wait()`
    // in a loop to read `/proc/<pid>/cmdline` while the process lives.
    // Outside Linux that block does not exist, `child` is only consumed by
    // `wait_with_output`, and the `mut` becomes useless — where the warning
    // is expected, it is silenced; on Linux it stays active.
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut child = Command::new(q21())
        .arg("--datadir")
        .arg(&target)
        .arg("--passphrase-file")
        .arg(&passphrase)
        .arg("--backup-code-file")
        .arg(&code_file)
        .args(["restore", "regtest", "lamport"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start");
    #[cfg(target_os = "linux")]
    {
        let pid = child.id();
        loop {
            if let Ok(c) = std::fs::read(format!("/proc/{pid}/cmdline")) {
                let text = String::from_utf8_lossy(&c).replace('\0', " ");
                assert!(
                    !text.contains(&code[..12]),
                    "the code is visible in /proc/{pid}/cmdline: {text}"
                );
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    let s = child.wait_with_output().unwrap();
    assert!(
        s.status.success(),
        "`--backup-code-file` must restore:\n{}",
        String::from_utf8_lossy(&s.stderr)
    );
    // The restored wallet is indeed that of the seed: the next address is
    // that of index 1 (index 0 is the recipient of the genesis).
    let mut expected_wallet = Wallet::from_seed([0x5a; 32], Network::Regtest);
    expected_wallet.rescan(1);
    let expected = expected_wallet.new_address().to_string();
    let s = run(&target, &passphrase, &["address"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    assert_eq!(first_address(&s.stdout), expected);

    let _ = std::fs::remove_dir_all(&d);
}

/// V2 — `wallet.tmp` is born 0600, `addresses.dat` is 0600, the directory
/// 0700.
///
/// A watcher probes the temporary file during several sealed writes and must
/// never see it under a mode other than 0600: the window between creation
/// and restriction no longer exists.
#[cfg(unix)]
#[test]
fn v2_the_temporary_file_is_born_restricted_and_the_directory_is_private() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let d = test_dir("permissions");
    let passphrase = std::env::temp_dir().join(format!(
        "q21-regression-v2-passphrase-{}",
        std::process::id()
    ));
    private_file(&passphrase, "test passphrase\n");
    let s = run(&d, &passphrase, &["init", "regtest", "lamport"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));

    let (m_dir, m_wallet, m_seq, m_addr) = (
        mode(&d),
        mode(&d.join("wallet.dat")),
        mode(&d.join("wallet.seq")),
        mode(&d.join("addresses.dat")),
    );
    println!("directory {m_dir:o}  wallet.dat {m_wallet:o}  wallet.seq {m_seq:o}  addresses.dat {m_addr:o}");
    assert_eq!(m_wallet, 0o600);
    assert_eq!(m_seq, 0o600);
    assert_eq!(
        m_addr, 0o600,
        "FINDING: addresses.dat is readable by other accounts"
    );
    assert_eq!(
        m_dir, 0o700,
        "FINDING: the directory is readable by other accounts"
    );

    let tmp = d.join("wallet.tmp");
    let done = Arc::new(AtomicBool::new(false));
    let (f2, t2) = (done.clone(), tmp.clone());
    let watcher = std::thread::spawn(move || {
        let mut modes: Vec<u32> = Vec::new();
        while !f2.load(Ordering::Relaxed) {
            if let Ok(m) = std::fs::metadata(&t2) {
                use std::os::unix::fs::PermissionsExt;
                modes.push(m.permissions().mode() & 0o777);
            }
        }
        modes
    });
    for _ in 0..4 {
        let s = run(&d, &passphrase, &["address"]);
        assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    }
    done.store(true, Ordering::Relaxed);
    let modes = watcher.join().unwrap();
    let mut m = modes.clone();
    m.sort_unstable();
    m.dedup();
    println!(
        "wallet.tmp observed {} times, modes: {:?}",
        modes.len(),
        m.iter().map(|x| format!("{x:o}")).collect::<Vec<_>>()
    );
    assert!(!modes.is_empty(), "the watcher never saw wallet.tmp");
    assert!(
        modes.iter().all(|m| *m == 0o600),
        "FINDING: wallet.tmp was seen under a mode other than 0600: {m:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&passphrase);
}

/// V3 — a substituted wallet is refused.
///
/// A plaintext `wallet.dat` from another seed, carrying the current serial
/// number, was adopted without a passphrase and without a word. The
/// directory now remembers that it has seen a sealed file and the public
/// fingerprint of its seed: the plaintext file is refused, naming the cause,
/// a sealed file from another seed is refused without explicit confirmation,
/// and accepted with it.
#[test]
fn v3_a_substituted_wallet_is_refused_naming_the_cause() {
    let d = test_dir("substitution");
    let passphrase = std::env::temp_dir().join(format!(
        "q21-regression-v2-passphrase-subst-{}",
        std::process::id()
    ));
    private_file(&passphrase, "test passphrase\n");
    let s = run(&d, &passphrase, &["init", "regtest", "lamport"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let legitimate = std::fs::read(d.join("wallet.dat")).unwrap();

    let serial: u64 = std::fs::read_to_string(d.join("wallet.seq"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let seed_hex: String = [0x77u8; 32].iter().map(|b| format!("{b:02x}")).collect();
    let foreign_content = format!(
        "seed={seed_hex}\nnext_index=1\nnetwork=regtest\nscheme=4\nserial={serial}\nverified_up_to=0\nconsumed=\n"
    );

    // 1. Plaintext, from another seed.
    std::fs::write(d.join("wallet.dat"), &foreign_content).unwrap();
    let s = Command::new(q21())
        .arg("--datadir")
        .arg(&d)
        .arg("address")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&s.stderr);
    assert!(
        !s.status.success(),
        "FINDING: the substituted plaintext wallet was adopted:\n{}",
        String::from_utf8_lossy(&s.stdout)
    );
    assert!(
        err.contains("passphrase"),
        "the refusal must say that this directory was protected by a passphrase:\n{err}"
    );

    // 2. Sealed with the same passphrase, but from another seed.
    let sealed = q21_core::kdf::seal(
        b"test passphrase",
        foreign_content.as_bytes(),
        q21_core::kdf::DEFAULT_COST,
    )
    .unwrap();
    std::fs::write(d.join("wallet.dat"), &sealed).unwrap();
    let s = run(&d, &passphrase, &["address"]);
    let err = String::from_utf8_lossy(&s.stderr);
    assert!(
        !s.status.success(),
        "FINDING: a sealed file from another seed was adopted without confirmation"
    );
    assert!(
        err.contains("seed") && err.contains("--accept-other-seed"),
        "the refusal must name the seed and the way forward:\n{err}"
    );

    // 3. The same substitution, explicitly confirmed: accepted.
    let s = run(&d, &passphrase, &["--accept-other-seed", "address"]);
    assert!(
        s.status.success(),
        "the explicit confirmation must open it:\n{}",
        String::from_utf8_lossy(&s.stderr)
    );
    let mut foreign = Wallet::from_seed([0x77u8; 32], Network::Regtest);
    foreign.rescan(1);
    assert_eq!(first_address(&s.stdout), foreign.new_address().to_string());

    // 4. The legitimate wallet, put back in place, is refused in turn: the
    //    directory now belongs to the new seed.
    std::fs::write(d.join("wallet.dat"), &legitimate).unwrap();
    let s = run(&d, &passphrase, &["address"]);
    assert!(!s.status.success());

    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&passphrase);
}

/// V9 — a file sealed below the default cost is resealed on opening.
///
/// A `wallet.dat` sealed at 8 KiB / 1 pass opened in forty microseconds
/// without a word. The binary must warn and rewrite it at the default cost.
#[test]
fn v9_a_file_sealed_below_the_default_cost_is_resealed() {
    let d = test_dir("cost");
    let passphrase = std::env::temp_dir().join(format!(
        "q21-regression-v2-passphrase-cost-{}",
        std::process::id()
    ));
    private_file(&passphrase, "test passphrase\n");
    let s = run(&d, &passphrase, &["init", "regtest", "lamport"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));

    // The same content, resealed at a trivial cost.
    let sealed = std::fs::read(d.join("wallet.dat")).unwrap();
    let plaintext = q21_core::kdf::unseal(b"test passphrase", &sealed).unwrap();
    let weak = q21_core::kdf::seal(
        b"test passphrase",
        &plaintext,
        q21_core::kdf::Cost {
            memory_kib: 8,
            passes: 1,
        },
    )
    .unwrap();
    std::fs::write(d.join("wallet.dat"), &weak).unwrap();

    let s = run(&d, &passphrase, &["balance"]);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let err = String::from_utf8_lossy(&s.stderr);
    let after = std::fs::read(d.join("wallet.dat")).unwrap();
    let memory = u32::from_le_bytes([after[8], after[9], after[10], after[11]]);
    let passes = u32::from_le_bytes([after[12], after[13], after[14], after[15]]);
    println!("cost after opening: {memory} KiB, {passes} pass(es)");
    assert_eq!(
        (memory, passes),
        (
            q21_core::kdf::DEFAULT_COST.memory_kib,
            q21_core::kdf::DEFAULT_COST.passes
        ),
        "FINDING: the file sealed at 8 KiB / 1 pass was not resealed"
    );
    assert!(
        err.contains("cost"),
        "opening must warn about the insufficient cost:\n{err}"
    );
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_file(&passphrase);
}

/// V6 — ML-DSA signs in the "hedged" variant: two signatures of the same
/// message differ, and both verify.
#[cfg(feature = "mldsa")]
#[test]
fn v6_two_ml_dsa_signatures_of_the_same_message_differ_and_verify() {
    let seed = [0x31u8; 32];
    let mut w = Wallet::from_seed_scheme(seed, Network::Regtest, SchemeId::MlDsa65).unwrap();
    let a0 = w.new_address();
    let mut c = Chain::new(Network::Regtest, genesis_block(Network::Regtest));
    for i in 0..(COINBASE_MATURITY + 2) {
        let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(a0.hash, SchemeId::MlDsa65, &[], t, 20_000_000)
            .unwrap();
        c.connect(&b, t + 1).unwrap();
    }
    let mut third_party = Wallet::from_seed([0x99; 32], Network::Regtest);
    let dest = third_party.new_address();
    let sign = || {
        let mut w = Wallet::from_seed_scheme(seed, Network::Regtest, SchemeId::MlDsa65).unwrap();
        w.rescan(1);
        w.create_transaction(
            &c.utxo,
            c.height(),
            &dest,
            Amount::from_units(50_000),
            Amount::from_units(1_000),
        )
        .unwrap()
    };
    let t1 = sign();
    let t2 = sign();
    assert_eq!(t1.txid(), t2.txid(), "same stripped transaction");
    let s1 = &t1.inputs[0].witness.signature;
    let s2 = &t2.inputs[0].witness.signature;
    assert_ne!(
        s1, s2,
        "FINDING: two ML-DSA signatures of the same message are identical (deterministic variant)"
    );
    let spent = c.utxo.get(&t1.inputs[0].prev_out).unwrap().output;
    for t in [&t1, &t2] {
        let m = t.sighash(0, Network::Regtest, &spent);
        assert!(
            q21_core::sig::verify(
                SchemeId::MlDsa65,
                &t.inputs[0].witness.pubkey,
                &m,
                &t.inputs[0].witness.signature
            )
            .is_ok(),
            "each variant must verify"
        );
    }
}

/// V8 — a shutdown between the reservation and the broadcast does not freeze
/// the coin.
///
/// The index is reserved and written to disk before signing; the process dies
/// before broadcasting. On restart, the reservation is reread: the coin stays
/// unavailable for the duration of the delay, then, since the chain carries
/// no signature of this key, the index becomes free again.
#[test]
fn v8_an_abandoned_reservation_becomes_free_again() {
    let seed = [0x21u8; 32];
    let mut w = Wallet::from_seed(seed, Network::Regtest);
    let a0 = w.new_address();
    let mut c = Chain::new(Network::Regtest, genesis_block(Network::Regtest));
    let mine = |c: &mut Chain, n: u64| {
        for _ in 0..n {
            let h = c.height();
            let t = GENESIS_TIME + (h + 1) * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a0.hash, SchemeId::LamportOts, &[], t, 20_000_000)
                .unwrap();
            c.connect(&b, t + 1).unwrap();
        }
    };
    mine(&mut c, COINBASE_MATURITY + 2);
    let mut third_party = Wallet::from_seed([0x99; 32], Network::Regtest);
    let dest = third_party.new_address();

    // Reservation, early write... and shutdown before signing.
    let prepared = w
        .prepare_spend(
            &c.utxo,
            c.height(),
            &[(dest, Amount::from_units(50_000))],
            Amount::from_units(1_000),
        )
        .unwrap();
    assert!(w.is_reserved(0), "index 0 must be reserved");
    assert!(!w.is_consumed(0), "nothing was signed: nothing is revealed");
    let on_disk_consumed = w.consumed_indices_for_file();
    let on_disk_reserved = w.reserved_indices();
    assert!(
        on_disk_consumed.contains(&0),
        "conservative for an older reader"
    );
    drop(prepared);
    drop(w);

    // Restart: the file is reread.
    let mut r = Wallet::from_seed(seed, Network::Regtest);
    r.rescan(2);
    r.mark_consumed(&on_disk_consumed);
    r.load_reservations(&on_disk_reserved);
    assert!(r.is_reserved(0) && !r.is_consumed(0));
    assert!(
        !r.spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| *i == 0),
        "reserved, the coin is not offered"
    );

    // Too early: the reservation holds.
    let (confirmed, released) = r.recheck_reservations(c.height(), |h| c.block_at(h));
    assert_eq!((confirmed, released), (0, 0));
    assert!(r.is_reserved(0));

    // The delay passes, the chain carries no signature: the index is free.
    mine(&mut c, Wallet::RESERVATION_TIMEOUT);
    let (confirmed, released) = r.recheck_reservations(c.height(), |h| c.block_at(h));
    assert_eq!((confirmed, released), (0, 1));
    assert!(!r.is_reserved(0) && !r.is_consumed(0));
    assert!(
        r.spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| *i == 0),
        "FINDING: the coin stays frozen after a shutdown between reservation and broadcast"
    );
}
