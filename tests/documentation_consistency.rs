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
///
/// Since 0.4.9, from the files of the archive only, by name: removing it from
/// the whole folder released every other download sitting next to it when the
/// archive was unpacked straight into Downloads.
#[test]
fn macos_launcher_removes_the_quarantine() {
    let launcher = read("Q21 Wallet.command");
    assert!(
        launcher.contains("for f in q21 ")
            && launcher.contains("xattr -dr com.apple.quarantine \"$f\""),
        "the macOS launcher no longer removes the quarantine from q21: it will be \
         \"damaged\" at every first launch."
    );
    assert!(
        !launcher.contains("xattr -dr com.apple.quarantine ."),
        "the quarantine must be removed from the archive's files, not from the \
         whole folder and whatever else was downloaded into it."
    );
    assert!(
        launcher.contains("\"$f\" 2>/dev/null"),
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

/// The public explorer survives a crash of its reverse proxy, and someone is
/// told when it does not.
///
/// In October 2026 Caddy crashed and stayed stopped for more than a day: the
/// package's service does not restart, and the monitoring only watched the
/// node's height, which kept moving. Three things close it, and each must stay
/// written where an operator copies it from.
#[test]
fn the_public_explorer_is_watched_and_restarted() {
    let explorer = read("PUBLIC-EXPLORER.md");
    assert!(
        explorer.contains("/etc/systemd/system/caddy.service.d/restart.conf")
            && explorer.contains("\nRestart=on-failure\n"),
        "PUBLIC-EXPLORER.md no longer makes Caddy restart after a crash"
    );
    let script = read("tools/monitor.sh");
    assert!(script.contains("PUBLIC_URL=\"${Q21_PUBLIC_URL:-}\""));
    assert!(
        script.contains("000|\"\")") && script.contains("systemctl restart \"$PROXY\""),
        "monitor.sh no longer restarts the proxy when the explorer is unreachable"
    );
    // A 502 is the node, not the proxy: restarting the proxy would hide it.
    let bad_gateway = &script[script.find("502|503|504)").expect("502 case")..];
    let end = bad_gateway.find(";;").expect("end of the 502 case");
    assert!(
        !bad_gateway[..end].contains("restart"),
        "a 502 must not restart the proxy"
    );
    assert!(
        read("SERVER.md").contains("\nQ21_PUBLIC_URL=\n"),
        "the monitoring environment file no longer shows Q21_PUBLIC_URL"
    );
}

/// A network where nobody mines is not a stuck node: the monitoring asks
/// whether any peer knows a longer chain before restarting anything.
#[test]
fn the_monitoring_does_not_restart_an_idle_network() {
    let script = read("tools/monitor.sh");
    let frozen = script
        .find("minutes=$(( (now - since) / 60 ))")
        .expect("frozen branch");
    let tail = &script[frozen..];
    let idle = tail
        .find("getsyncstatus")
        .expect("the frozen branch asks for the sync status");
    let restart = tail
        .find("systemctl restart \"$SERVICE\"")
        .expect("restart of the service");
    assert!(
        idle < restart,
        "the idle-network check must come before the restart"
    );
}

/// A refusal is a configuration error, never a stuck node: the monitoring
/// must not restart a node that answered "no". Both refusals the RPC can
/// give are handled before the restart.
#[test]
fn the_monitoring_does_not_restart_a_node_that_refuses_it() {
    let script = read("tools/monitor.sh");
    let restart = script
        .find("systemctl restart \"$SERVICE\"")
        .expect("restart of the service");
    for refusal in ["'access token'", "'another account'"] {
        let at = script
            .find(refusal)
            .unwrap_or_else(|| panic!("monitor.sh does not recognize {refusal}"));
        assert!(
            at < restart,
            "monitor.sh checks {refusal} only after restarting the node"
        );
    }
}

/// A release page lists what a user downloads and what proves it, nothing
/// else: the archives and `SHA256SUMS`, to which the offline signature is
/// added by hand. The per-file `.sha256` that the build jobs produce are
/// already inside `SHA256SUMS`, which is the signed one; publishing them
/// separately invited checking an unsigned file.
#[test]
fn the_release_drafts_archives_and_sums_only() {
    let workflow = read(".github/workflows/release.yml");
    let publish = &workflow[workflow
        .find("- name: Create the draft release")
        .expect("draft release step")..];
    let files = &publish
        [publish.find("files: |").expect("files list")..publish.find("body:").expect("body")];
    for wanted in [
        "artifacts/q21-*.tar.gz",
        "artifacts/q21-*.zip",
        "artifacts/SHA256SUMS",
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
    assert!(
        publish.contains("draft: true"),
        "the release is no longer created as a draft: it would be public \
         before its offline signature exists"
    );
}

/// The signing key never comes to GitHub: no workflow reads a signing secret
/// or signs, and a published release is checked — signature, trusted comment,
/// attestations, archives — and sent back to draft if anything fails.
#[test]
fn the_release_is_signed_offline_and_checked_when_published() {
    for w in [".github/workflows/release.yml", ".github/workflows/ci.yml"] {
        let text = read(w);
        assert!(
            !text.contains("secrets.MINISIGN")
                && !text
                    .lines()
                    .any(|l| l.contains("minisign -S") && !l.trim_start().starts_with("echo")),
            "{w} signs, or reads a signing key: the key must stay offline (SIGNING.md)"
        );
    }
    let workflow = read(".github/workflows/release.yml");
    let verify = &workflow[workflow.find("  verify:").expect("verify job")..];
    for wanted in [
        "SHA256SUMS.minisig",
        "q21-release.pub",
        "attestations/threshold",
        "--draft=true",
    ] {
        assert!(
            verify.contains(wanted),
            "the verification of a published release no longer handles {wanted}"
        );
    }
}

/// Nothing is released before the whole CI has passed on the released commit,
/// from `main`, without cache; and every third-party action is pinned to a
/// commit hash, which nobody can move.
#[test]
fn the_release_is_gated_and_its_actions_pinned() {
    let workflow = read(".github/workflows/release.yml");
    assert!(
        workflow.contains("uses: ./.github/workflows/ci.yml"),
        "the release no longer runs the CI on the commit it publishes"
    );
    assert!(
        workflow.contains("git merge-base --is-ancestor \"$GITHUB_SHA\" origin/main"),
        "a tag outside main could be released"
    );
    let build = &workflow[workflow.find("  build:").expect("build job")
        ..workflow.find("  sums:").expect("sums job")];
    assert!(
        !build.contains("rust-cache"),
        "the release builds from a cache again"
    );
    for w in [".github/workflows/release.yml", ".github/workflows/ci.yml"] {
        for line in read(w).lines() {
            let Some(rest) = line
                .trim_start()
                .trim_start_matches("- ")
                .strip_prefix("uses:")
            else {
                continue;
            };
            let target = rest.trim();
            if target.starts_with("./") {
                continue;
            }
            let reference = target
                .split('@')
                .nth(1)
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            assert!(
                reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()),
                "{w}: `{}` is not pinned to a commit hash (tools/pin-actions.sh)",
                line.trim()
            );
        }
    }
}

/// The public key printed in the documents is the one in `q21-release.pub`:
/// a copy left behind after a key change would send people to check against
/// a key that signs nothing any more.
#[test]
fn every_printed_release_key_is_the_current_one() {
    let file = read("q21-release.pub");
    let key = file
        .lines()
        .nth(1)
        .expect("second line: the key")
        .trim()
        .to_string();
    assert_eq!(
        key.len(),
        56,
        "q21-release.pub does not hold a minisign key"
    );
    for doc in ["README.md", "JOIN.md"] {
        let text = read(doc);
        assert!(
            text.contains(&key),
            "{doc} does not print the current release key"
        );
        for word in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '/') {
            if word.len() == 56 && word.starts_with("RW") {
                assert_eq!(word, key, "{doc} prints an old release key");
            }
        }
    }
}

/// A flaw is reported privately, and the way to do it is written down.
#[test]
fn security_reports_have_a_private_channel() {
    let policy = read("SECURITY.md");
    assert!(
        policy.contains("security/advisories/new"),
        "SECURITY.md no longer says where to report privately"
    );
    let readme = read("README.md");
    assert!(
        readme.contains("SECURITY.md"),
        "the README no longer points to SECURITY.md"
    );
}

/// The audit feature carries the hooks the tests and the lab use to make
/// inconsistent or early state — among them a policy activation height other
/// than the scheduled one. A released binary must not have them: it is built
/// with `mldsa` alone, and every `cargo build --release` of the workflow says
/// so.
#[test]
fn the_released_binary_is_built_without_the_audit_hooks() {
    let workflow = read(".github/workflows/release.yml");
    let builds: Vec<&str> = workflow
        .lines()
        .filter(|l| l.contains("cargo build") && l.contains("--release"))
        .collect();
    assert!(!builds.is_empty(), "no release build in the workflow");
    for b in builds {
        assert!(
            b.contains("--features mldsa") && !b.contains("audit") && !b.contains("--all-features"),
            "a release build that may carry the audit hooks: {b}"
        );
    }
}

/// The upgrade notes announce the testnet activation height. The height is
/// set at release: the notes must follow it, or operators would upgrade by
/// the wrong date.
#[test]
fn upgrading_md_announces_the_compiled_testnet_activation() {
    let h = q21_core::consensus::POLICY_ACTIVATION_TESTNET;
    let digits = h.to_string();
    let mut grouped = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    let text = read("UPGRADING.md");
    // The newest section is the one operators follow.
    let start = text
        .find("# Upgrading from ")
        .expect("UPGRADING.md has no upgrade section");
    let section = &text[start..];
    let section = &section[..section[1..].find("\n# ").map_or(section.len(), |e| e + 1)];
    assert!(
        section.contains(&format!("block {grouped}")),
        "the newest upgrade notes do not announce block {grouped}, the compiled testnet activation"
    );
    // And the names, from 0.5.0 on.
    let names = q21_core::consensus::NAME_ACTIVATION_TESTNET;
    let names = format!("block {},{:03}", names / 1000, names % 1000);
    assert!(
        section.contains(&names),
        "the newest upgrade notes do not announce {names}, the compiled name activation"
    );
}
