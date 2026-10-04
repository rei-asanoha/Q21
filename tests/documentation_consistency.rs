//! Test — the genesis published in the documentation is the one the code computes.
//!
//! `NETWORK.md` asks anyone who joins the network to compare the genesis
//! identifier computed on their machine with the published one, and to refuse
//! to go on if they differ. It is the only act of trust in the whole process.
//!
//! Consensus changed several times; the published identifier, however, had
//! been copied by hand. The document therefore gave a value that no longer
//! matched anything: whoever conscientiously applied the prescribed check
//! concluded that they were not on the right chain — when they were.
//!
//! A reference value copied by hand drifts. This test ties it to the code: any
//! consensus change that alters the genesis makes the build fail until the
//! documentation has followed.

use q21_core::chain::genesis_block;
use q21_core::Network;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(name: &str) -> String {
    let path: PathBuf = root().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn testnet_genesis() -> String {
    genesis_block(Network::Testnet)
        .header
        .block_id()
        .to_string()
}

/// A hexadecimal token, possibly followed by an ellipsis.
///
/// The documents sometimes quote the full hash, sometimes a prefix followed by
/// `...` or by `…`. Both forms are normalized.
fn hex_prefix(token: &str) -> Option<&str> {
    let token = token
        .trim_end_matches('…')
        .trim_end_matches("...")
        .trim_end_matches('`')
        .trim_start_matches('`');
    let hex = token.trim();
    if hex.len() >= 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hex)
    } else {
        None
    }
}

#[test]
fn network_md_publishes_the_genesis_identifier_the_code_computes() {
    let expected = testnet_genesis();
    let text = read("NETWORK.md");

    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("identifier"))
        .expect("NETWORK.md no longer publishes a genesis identifier");

    let published = line
        .split_whitespace()
        .next_back()
        .expect("empty `identifier` line in NETWORK.md");

    assert_eq!(
        published, expected,
        "NETWORK.md publishes a stale genesis.\n  published: {published}\n  computed:  {expected}\n\
         Consensus changed: update NETWORK.md in the same commit."
    );
}

#[test]
fn no_document_quotes_a_stale_genesis() {
    let expected = testnet_genesis();

    // The sample outputs of the installation guides quote a prefix of the
    // genesis. A wrong prefix is as misleading as a wrong hash: the reader
    // compares what they see with what is written.
    let documents = ["NETWORK.md", "SERVER.md", "SERVER-WINDOWS.md", "JOIN.md"];

    for name in documents {
        if !Path::new(&root().join(name)).exists() {
            continue;
        }
        let text = read(name);
        for (number, line) in text.lines().enumerate() {
            let relevant = line.contains("genesis written") || line.contains("identifier");
            if !relevant {
                continue;
            }
            for token in line.split_whitespace() {
                let Some(hex) = hex_prefix(token) else {
                    continue;
                };
                assert!(
                    expected.starts_with(hex),
                    "{name}:{} quotes a genesis that is not the code's.\n  \
                     quoted:   {hex}\n  computed: {expected}",
                    number + 1
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The memory sizes announced to participants
// ---------------------------------------------------------------------------
//
// JOIN.md used to ask for 8 GB of RAM to mine, and announced a 2 GB table: the
// mainnet figures, in the guide that leads to the testnet. The testnet asks
// for sixty-four times less. A guide that overstates its requirements only
// turns participants away — and a testnet without participants measures
// nothing.
//
// These sizes are computed from the consensus constants. They are tied to
// them, like the genesis.

fn mib(elements: u32) -> u64 {
    (elements as u64) * (q21_core::consensus::POW_ELEMENT_SIZE as u64) / (1024 * 1024)
}

#[test]
fn join_md_states_the_testnet_memory_sizes() {
    use q21_core::memhard::{cache_size, table_size, TableParams};

    let p = TableParams::for_network(Network::Testnet);
    let initial_table = mib(table_size(p, 0));
    let table_cap = mib(p.nmax);
    let initial_cache = mib(cache_size(p, 0)).max(1);

    let text = read("JOIN.md");

    for (value, what) in [
        (initial_table, "the miner's table at epoch 0"),
        (table_cap, "the table cap"),
        (initial_cache, "the cache of a verifying node"),
    ] {
        let expected = format!("{value} MiB");
        assert!(
            text.contains(&expected),
            "JOIN.md no longer states `{expected}` for {what}.\n\
             The consensus constants changed: update the guide in the same\n\
             commit, otherwise it describes a network that does not exist."
        );
    }

    // The original trap: the mainnet figures presented as those of the
    // network the guide makes you join.
    assert!(
        !text.contains("You need **8 GB of RAM**"),
        "JOIN.md again asks for the mainnet memory to mine on the testnet."
    );
}

// ---------------------------------------------------------------------------
// The entry point shipped with the program
// ---------------------------------------------------------------------------
//
// The binary contains no server address, and that does not change: an address
// hard-coded into distributed software would be a permanent dependency on
// whoever holds it. But the file that carries it now travels filled in, in the
// archive. Without it, every freshly unpacked archive is blind, and its owner
// reads "no computer reachable" without knowing that nothing is broken.
//
// Two drifts then become possible, and these tests close them: shipping an
// address the project has not published — so that no one has checked — and
// ceasing to ship the file without noticing.

/// The shipped addresses are the ones the project publishes.
///
/// `NETWORK.md` sets the rule: "only what really answers is written here,
/// checked from an outside machine". An address shipped to thousands of
/// machines must at least have gone through that door.
#[test]
fn shipped_bootstrap_addresses_are_those_network_md_publishes() {
    let file = read("default-bootstrap.txt");
    let network_md = read("NETWORK.md");

    let addresses: Vec<&str> = file
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    assert!(
        !addresses.is_empty(),
        "default-bootstrap.txt contains no address: the archive would start out \
         blind again, and the first launch would lead nowhere."
    );

    for a in &addresses {
        assert!(
            network_md.contains(a),
            "default-bootstrap.txt ships `{a}`, which NETWORK.md does not publish.\n\
             Publish first, ship second: we do not send strangers an address \
             that the project has not checked."
        );
    }
}

/// The **produced** archive is opened and checked before it goes out.
///
/// Putting a file in the assembly folder does not guarantee that it ends up in
/// the archive: the packaging tool differs from one platform to another, and a
/// lost subfolder makes nothing fail. It happened — `q21-data/` present in the
/// tar archives, absent from the Windows archive — and the defect was only
/// seen by a user, several versions later. Assembling and packing are two
/// steps: the second one must be checked.
#[test]
fn release_checks_the_contents_of_the_produced_archive() {
    let workflow = read(".github/workflows/release.yml");
    assert!(
        workflow.contains("The archive carries everything it should"),
        "the step that opens the produced archive and checks its listing is gone: \
         an incomplete archive would ship again with nothing to signal it."
    );
    for expected in ["q21-data", "bootstrap.txt", "JOIN.md"] {
        assert!(
            workflow.contains(&format!("\"{expected}\"")),
            "`{expected}` is no longer required by the archive check"
        );
    }
    // 7z must recurse explicitly: that is what was missing.
    assert!(
        workflow.contains("7z a -r "),
        "the Windows archive is no longer built in recursive mode: the \
         q21-data subfolder may disappear again."
    );
}

/// The bootstrap file travels in two copies, one of them flat.
///
/// A subfolder gets lost during packaging depending on the tool: `tar` goes
/// down into it, `7z` not always. The Mac and Linux archives carried
/// `q21-data/`, the Windows archive shipped without it — and its owner read
/// "no bootstrap". A file placed flat next to the binary goes through every
/// tool; the node reads it when the data directory has none. Losing one of
/// them no longer leaves anyone blind.
#[test]
fn bootstrap_file_also_ships_flat() {
    let workflow = read(".github/workflows/release.yml");
    assert!(
        workflow.contains("cp default-bootstrap.txt dist/bootstrap.txt"),
        "the flat copy is no longer shipped: an archive that lost \
         q21-data would start out blind again."
    );
    let bootstrap_rs = read("src/bootstrap.rs");
    assert!(
        bootstrap_rs.contains("pub fn bootstrap_next_to_program"),
        "the node no longer looks for bootstrap addresses next to the binary"
    );
    let bin = read("src/bin/q21.rs");
    let (i_datadir, i_next_to) = (
        bin.find("bootstrap_from_datadir(datadir)")
            .expect("datadir source"),
        bin.find("bootstrap_next_to_program()")
            .expect("flat source"),
    );
    assert!(
        i_datadir < i_next_to,
        "the shipped file would come before the user's: what they write at \
         home must win"
    );
}

/// The release pipeline does put this file in the archive.
///
/// The file can be perfect in the repository and arrive nowhere. It is the
/// assembly step that makes it travel, and nothing else guards it.
#[test]
fn release_puts_the_bootstrap_file_in_the_archive() {
    let workflow = read(".github/workflows/release.yml");
    assert!(
        workflow.contains("cp default-bootstrap.txt dist/q21-data/bootstrap.txt"),
        "the release pipeline no longer puts bootstrap.txt in the archive: \
         every archive would start out blind again."
    );
    assert!(
        workflow.contains("mkdir -p dist/q21-data"),
        "the q21-data folder is no longer created in the archive: the bootstrap \
         file would not land where the node looks for it."
    );
}

/// The macOS launcher removes the quarantine before starting.
///
/// Without this line, every browser download ends in "is damaged and can't be
/// opened" on `q21` — a message that blames the file and sends the newcomer to
/// the Trash. The step it performs is the one NETWORK.md used to ask for by
/// hand; there was no reason to leave it to the user.
#[test]
fn macos_launcher_removes_the_quarantine() {
    let launcher = read("Q21 Wallet.command");
    assert!(
        launcher.contains("xattr -dr com.apple.quarantine ."),
        "the macOS launcher no longer removes the quarantine: q21 will be \
         \"damaged\" at every first launch."
    );
    assert!(
        launcher.contains("2>/dev/null || true"),
        "removing the quarantine must stay silent where there is nothing to \
         remove, otherwise the launcher stops on Linux or after an archive \
         opened from the Terminal."
    );
    // And the useful step comes BEFORE the launch, not after.
    let (i_xattr, i_wallet) = (
        launcher.find("xattr -dr").expect("xattr present"),
        launcher.find("./q21 wallet").expect("launch present"),
    );
    assert!(
        i_xattr < i_wallet,
        "the quarantine must be removed before launching q21, not after"
    );
}

/// The monitoring unit keeps its state between runs.
///
/// `RuntimeDirectory=` alone makes systemd delete the directory each time the
/// one-shot script exits: every run then takes its first measurement again,
/// and a stuck node is never noticed. This was the published configuration up
/// to 0.4.0, and it looked healthy: the timer ran, the script succeeded.
#[test]
fn monitoring_unit_preserves_its_state() {
    let docs: Vec<String> = std::fs::read_dir(root())
        .expect("repository root")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".md"))
        .collect();
    // Unit lines only: a line of its own, not a command that edits it.
    const UNIT: &str = "\nRuntimeDirectory=q21-monitor\n";
    const PRESERVED: &str = "\nRuntimeDirectory=q21-monitor\nRuntimeDirectoryPreserve=yes\n";
    assert!(
        docs.iter().any(|d| read(d).contains(UNIT)),
        "no document shows the monitoring unit any more"
    );
    for doc in &docs {
        let text = read(doc);
        let units = text.matches(UNIT).count();
        assert_eq!(
            text.matches(PRESERVED).count(),
            units,
            "{doc}: a monitoring unit without RuntimeDirectoryPreserve=yes forgets \
             its measurement after every run"
        );
    }
}

/// A release page lists what a user downloads and what proves it, nothing
/// else: the archives, `SHA256SUMS` and its signature. The per-file `.sha256`
/// that the build jobs produce are already inside `SHA256SUMS`, which is the
/// signed one; publishing them separately invited checking an unsigned file.
#[test]
fn the_release_publishes_archives_and_signed_sums_only() {
    let workflow = read(".github/workflows/release.yml");
    let publish = &workflow[workflow
        .find("- name: Publish the release")
        .expect("publish step")..];
    let files =
        &publish[publish.find("files:").expect("files list")..publish.find("body:").expect("body")];
    for wanted in [
        "artifacts/q21-*.tar.gz",
        "artifacts/q21-*.zip",
        "artifacts/SHA256SUMS",
        "artifacts/SHA256SUMS.minisig",
    ] {
        assert!(
            files.contains(wanted),
            "the release no longer publishes {wanted}"
        );
    }
    assert!(
        !files.contains("artifacts/*\n") && !files.contains(".sha256"),
        "the release publishes the unsigned per-file hashes again"
    );
}
