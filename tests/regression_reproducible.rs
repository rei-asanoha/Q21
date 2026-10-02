//! Reproducible build: the tests that guard the setup.
//!
//! # What is guarded here, and why it is not in the code
//!
//! Q21's reproducibility does not rest on a line of Rust but on an agreement
//! between five files that do not talk to each other:
//!
//! - `rust-toolchain.toml` pins the compiler;
//! - `tools/build-reproducible.sh` sets `--remap-path-prefix` on Unix;
//! - `tools/build-reproducible.ps1` does the same on Windows;
//! - `.github/workflows/release.yml` repeats the step for the release;
//! - `REPRODUCING.md` publicly announces the resulting prefix.
//!
//! If one drifts — a prefix changed in the script but not in the release, a
//! compiler version bumped in one file only — two builds of the same commit
//! stop being identical, **silently**. The published hash then no longer proves
//! anything, and nobody notices until a third party tries to reproduce and
//! cannot.
//!
//! These tests therefore read the files of the repository. It is unusual for a
//! unit test, and it is deliberately the only place in the project where this
//! is done: the guarded invariant is a property of the repository, not of the
//! program.
//!
//! What they do not do: check that two builds give the same binary. That takes
//! two full builds, hence a separate CI job (`reproducible` in `ci.yml`, which
//! runs `tools/verify-reproducible.sh`).

use std::fs;
use std::path::PathBuf;

/// The root of the repository, deduced from the location of the manifest.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let p = root().join(path);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The target prefix of the remapping, the one that ends up in the binary.
///
/// It is arbitrary, but it must be the **same everywhere**: it is what a third
/// party will find in the binary they rebuild, and REPRODUCING.md announces it.
/// Changing it on one side only breaks reproducibility without any error
/// message.
const PREFIX: &str = "=/q21";

#[test]
fn the_remapping_prefix_is_the_same_everywhere() {
    let places = [
        "tools/build-reproducible.sh",
        "tools/build-reproducible.ps1",
        ".github/workflows/release.yml",
    ];
    for e in places {
        let text = read(e);
        assert!(
            text.contains("--remap-path-prefix"),
            "{e} no longer sets --remap-path-prefix: the build is no longer \
             reproducible, and nothing else will flag it"
        );
        assert!(
            text.contains(PREFIX),
            "{e} no longer uses the target prefix \"{PREFIX}\"; two \
             builds of the same commit will diverge silently"
        );
    }
    // The public document must announce the same prefix, without the "=" that
    // only belongs to the flag syntax.
    let doc = read("REPRODUCING.md");
    assert!(
        doc.contains("/q21/vendor/"),
        "REPRODUCING.md no longer announces the remapped paths that the reader \
         must find in their own binary"
    );
}

#[test]
fn the_compiler_version_is_the_same_in_every_file() {
    let pinned = read("rust-toolchain.toml");
    // `channel = "1.95.0"` — the value is extracted rather than hard-coded
    // here, so that bumping the toolchain stays a single change.
    let version = pinned
        .lines()
        .find_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("channel")?.trim_start().strip_prefix('=')?;
            Some(rest.trim().trim_matches('"').to_string())
        })
        .expect("rust-toolchain.toml no longer declares a `channel`");

    assert!(
        version.split('.').count() == 3,
        "the toolchain must be an exact version (1.95.0), not a moving \
         channel like \"stable\": otherwise \"the same commit\" designates a \
         different compiler every six weeks. Found: {version}"
    );

    for w in [".github/workflows/ci.yml", ".github/workflows/release.yml"] {
        let text = read(w);
        assert!(
            text.contains(&version),
            "{w} does not install {version}, the version pinned by \
             rust-toolchain.toml: the release would not be reproducible \
             from the repository"
        );
    }
}

#[test]
fn the_reproducibility_check_is_wired_into_ci() {
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("tools/verify-reproducible.sh"),
        "no CI job builds twice to compare: a dependency that wrote a date or \
         a path would break reproducibility without the merge being stopped"
    );

    let release = read(".github/workflows/release.yml");
    assert!(
        release.contains("No build path in the binary"),
        "the release no longer checks that the published binary is free of the \
         path of the machine that built it"
    );
}

/// The attestations folder must exist and carry its instructions.
///
/// Empty, it attests nothing — and that is the honest state as long as a
/// single person builds. Missing, it prevents the first attestation from
/// arriving: a third party who rebuilds would have nowhere to drop what they
/// get.
#[test]
fn the_repository_can_receive_attestations() {
    for f in [
        "attestations/README.md",
        "attestations/builder-keys/README.md",
    ] {
        assert!(
            root().join(f).is_file(),
            "{f} is missing: the attestation setup is no longer documented"
        );
    }
    // The rule that matters, declared in advance: a key dropped there
    // authorizes nothing. If this sentence disappears, the folder becomes a
    // list of trusted people, that is the opposite of its purpose.
    //
    // The phrase is quoted from the text of the document: if the document is
    // reworded, this quote must follow.
    let doc = read("attestations/builder-keys/README.md");
    assert!(
        doc.contains("No rights."),
        "the rule \"a key dropped here authorizes nothing\" has disappeared from \
         attestations/builder-keys/README.md"
    );
}

/// The absence of a master key is a decision, and it must stay written down.
///
/// Bitcoin had an alert key, retired in 2016 after it was found to be a single
/// point of compromise and a power without a mandate. Q21 has none. Such a key
/// never gets added by accident, but the **declaration** that there will be
/// none can get lost in a documentation rewrite — and it is the declaration
/// that commits.
#[test]
fn the_absence_of_a_master_key_stays_declared() {
    let doc = read("SUCCESSION.md");
    // The phrases are quoted from the text of the document: if the document
    // is reworded, these quotes must follow.
    for phrase in ["There is no master key", "alert key", "2016"] {
        assert!(
            doc.contains(phrase),
            "SUCCESSION.md no longer declares \"{phrase}\": the rule that \
             forbids any key able to impose something on the network \
             is no longer written anywhere"
        );
    }
}
