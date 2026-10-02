//! Upgrade of a data directory written by q21 0.3.x or earlier.
//!
//! Up to 0.3.x the program wrote other file names, settings keys and values
//! into its data directory. From 0.4 on, every name is English. This module
//! holds the **only** copies of the old names — frozen values that must never
//! change, since they describe files that already exist on users' disks — and
//! the one function that renames them, [`migrate_data_dir`]. The binary runs
//! it at startup, right after taking the directory lock and before anything
//! else reads the directory.
//!
//! # What it does
//!
//! | 0.3.x                         | 0.4                              |
//! |-------------------------------|----------------------------------|
//! | `reglages.txt`, `joignable=oui/non` | `settings.txt`, `reachable=yes/no` |
//! | `wallet.ancre`, `scelle=`, `graine=` | `wallet.anchor`, `sealed=`, `seed=` |
//! | `amorces.txt`                 | `bootstrap.txt`                  |
//! | `entetes.dat`                 | `headers.dat`                    |
//! | `adoption.txt`: `hauteur=`, `tete=`, `empreinte=`, `revalide=oui/non` | `height=`, `tip=`, `legacy_commitment=`, `revalidated=yes/no` |
//! | `ancienne-chaine-<id>/`       | `old-chain-<id>/`                |
//! | `blocks.dat.coupe`, `entetes.dat.abime` | `blocks.dat.cut`, `headers.dat.damaged` |
//! | `blocks.elagage` (pruning temp file) | removed                    |
//! | `.verrou` (lock file)         | `.lock`                          |
//! | `state.dat` MuHash label `Q21/muhash/empreinte` | `Q21/muhash/commitment` |
//!
//! Some old names cannot be renamed at startup, because they live inside the
//! sealed `wallet.dat` or are keyed by the seed. They are read under either
//! name and written under the new one at the next wallet write:
//!
//! | 0.3.x                         | 0.4                              |
//! |-------------------------------|----------------------------------|
//! | sealed format `Q21SCEL1`/`Q21SCEL2`, keystream label `Q21/flot` | `Q21SEAL3`, `Q21/keystream` |
//! | `wallet.dat` keys `serie=`, `verifie_jusqu_a=`, `consommes=`, `reserves=`, `etiquettes=`, `demandees=` | `serial=`, `verified_up_to=`, `consumed=`, `reserved=`, `labels=`, `requested=` |
//! | anchor fingerprint label `Q21-DOSSIER-v1` | `Q21-DATADIR-v1` |
//! | address cache key label `Q21-CACHE-ADRESSES-v1` | `Q21-ADDRESS-CACHE-v1` |
//!
//! Sync snapshots exported by 0.3.x (magic `Q21AMORC`, now `Q21SNAPS`) are not
//! converted: their state commitment changed, and they must be exported again.
//!
//! A legacy file is renamed only when the new one does not exist yet. When
//! both exist, the two text files that carry a user's choices are merged
//! (see below) and the binary files are left alone: the new file wins, and
//! the old one stays where it is.
//!
//! # Security-critical: the reachability setting
//!
//! `reglages.txt` said `joignable=non` when the user chose not to accept
//! incoming connections — typically to keep a home IP address out of other
//! nodes' address books. An absent setting means *reachable*. Losing this
//! line during an upgrade would silently open the router port and publish
//! the address. So:
//!
//! - it is translated before anything reads the settings;
//! - any value other than `oui` becomes `reachable=no` (the more private
//!   choice);
//! - when both files exist, a `no` in either one wins;
//! - if the translation cannot be written, [`migrate_data_dir`] fails and the
//!   binary stops, instead of starting with the default.
//!
//! The same care applies to `wallet.ancre`: its `scelle=1` line records that
//! this directory has held a passphrase-sealed wallet, which is what makes a
//! plaintext `wallet.dat` dropped into the directory refused. Losing it would
//! reopen that substitution.
//!
//! # The state commitment labels
//!
//! 0.4 also renamed two hash labels that are not part of consensus: the final
//! label of the MuHash commitment of the UTXO set, and the label of the state
//! commitment that binds it to the issued total. The state snapshot
//! `state.dat` records the MuHash: it is rewritten under the new label after
//! the file has passed every check of a normal load and reproduced its MuHash
//! under the old label. An adoption record written by 0.3.x keeps its trusted
//! commitment as `legacy_commitment=`, and `revalidate` compares it with
//! [`legacy_state_commitment`].

use crate::chain::Chain;
use crate::hash::Hash256;
use std::path::Path;

/// MuHash final label used up to 0.3.x. Frozen: it is what `state.dat` files
/// written by 0.3.x commit to.
pub const LEGACY_MUHASH_TAG: &str = "Q21/muhash/empreinte";

/// State commitment label used up to 0.3.x. Frozen: it is what adoption
/// records written by 0.3.x commit to.
pub const LEGACY_STATE_TAG: &str = "Q21/etat/empreinte";

/// Magic of sealed files in the first format (PBKDF2). Frozen: still read,
/// never written.
pub const LEGACY_SEAL_V1_MAGIC: &[u8; 8] = b"Q21SCEL1";

/// Magic of sealed files in the Argon2id format written up to 0.3.x. Frozen:
/// still read, never written.
pub const LEGACY_SEAL_V2_MAGIC: &[u8; 8] = b"Q21SCEL2";

/// Keystream label of the two sealed formats above. Frozen: without it, a
/// wallet sealed by 0.3.x could not be decrypted.
pub const LEGACY_KEYSTREAM_LABEL: &[u8] = b"Q21/flot";

/// Magic of the sync snapshots exported by 0.3.x. Frozen. They no longer
/// load — their state commitment changed — and this magic is only used to
/// say so instead of "not a snapshot".
pub const LEGACY_SNAPSHOT_MAGIC: &[u8; 8] = b"Q21AMORC";

/// Label of the seed fingerprint recorded in `wallet.anchor` up to 0.3.x.
/// Frozen: an anchor written by 0.3.x is still recognized, then rewritten
/// under the new label at the next wallet write.
pub const LEGACY_DATADIR_LABEL: &[u8] = b"Q21-DOSSIER-v1";

/// Label of the key that authenticates the `addresses.dat` cache, up to
/// 0.3.x. Frozen: a cache written by 0.3.x is still accepted, then rewritten
/// under the new key.
pub const LEGACY_ADDRESS_CACHE_LABEL: &[u8] = b"Q21-CACHE-ADRESSES-v1";

/// Keys of the (sealed) `wallet.dat` up to 0.3.x, with their 0.4 names.
/// Frozen. The file is sealed by the passphrase, so it cannot be rewritten at
/// startup: it is read under either name and written under the new one at
/// its next write.
pub const LEGACY_WALLET_KEYS: &[(&str, &str)] = &[
    ("serie", "serial"),
    ("verifie_jusqu_a", "verified_up_to"),
    ("consommes", "consumed"),
    ("reserves", "reserved"),
    ("etiquettes", "labels"),
    ("demandees", "requested"),
];

/// The 0.4 name of a `wallet.dat` key, whichever name the file used.
pub fn wallet_key(key: &str) -> &str {
    LEGACY_WALLET_KEYS
        .iter()
        .find(|(old, _)| *old == key)
        .map_or(key, |(_, new)| new)
}

/// Lock file used up to 0.3.x. Frozen.
pub const LEGACY_LOCK_FILE: &str = ".verrou";

/// Settings file used up to 0.3.x. Frozen.
pub const LEGACY_SETTINGS_FILE: &str = "reglages.txt";

/// Wallet anchor file used up to 0.3.x. Frozen.
pub const LEGACY_ANCHOR_FILE: &str = "wallet.ancre";

/// Bootstrap list used up to 0.3.x. Frozen.
pub const LEGACY_BOOTSTRAP_FILE: &str = "amorces.txt";

/// Header store used up to 0.3.x. Frozen.
pub const LEGACY_HEADERS_FILE: &str = "entetes.dat";

/// Tail cut from a damaged block file, kept aside, up to 0.3.x. Frozen.
pub const LEGACY_CUT_TAIL_FILE: &str = "blocks.dat.coupe";

/// Unusable header store set aside, up to 0.3.x. Frozen.
pub const LEGACY_DAMAGED_HEADERS_FILE: &str = "entetes.dat.abime";

/// Temporary file of an interrupted pruning, up to 0.3.x. Frozen. Never
/// read: the block file is replaced only once the copy is complete.
pub const LEGACY_PRUNING_TEMP_FILE: &str = "blocks.elagage";

/// Prefix of the folder where files of a chain with another genesis were
/// put aside, up to 0.3.x. Frozen.
pub const LEGACY_OLD_CHAIN_PREFIX: &str = "ancienne-chaine-";

/// Reachability key of `reglages.txt`, up to 0.3.x. Frozen.
const LEGACY_REACHABLE_KEY: &str = "joignable";

/// The "yes" value of the 0.3.x settings and adoption record (`oui`). Frozen.
/// Any other value, `non` included, is read as "no".
const LEGACY_YES: &str = "oui";

/// Key of `wallet.ancre` saying that the directory has held a sealed wallet,
/// up to 0.3.x. Frozen.
const LEGACY_ANCHOR_SEALED_KEY: &str = "scelle";

/// Key of `wallet.ancre` holding the public fingerprint of the seed, up to
/// 0.3.x. Frozen.
const LEGACY_ANCHOR_SEED_KEY: &str = "graine";

/// Keys of `adoption.txt` up to 0.3.x: height, tip, commitment, and the
/// "revalidated" flag. Frozen.
const LEGACY_ADOPTION_HEIGHT_KEY: &str = "hauteur";
const LEGACY_ADOPTION_TIP_KEY: &str = "tete";
const LEGACY_ADOPTION_COMMITMENT_KEY: &str = "empreinte";
const LEGACY_ADOPTION_REVALIDATED_KEY: &str = "revalide";

/// New names, as the rest of the program spells them.
pub const ANCHOR_FILE: &str = "wallet.anchor";
/// Header store of an adopted or pruned directory.
pub const HEADERS_FILE: &str = "headers.dat";
/// Adoption record. Same name as in 0.3.x; only its keys changed.
pub const ADOPTION_FILE: &str = "adoption.txt";
/// Prefix of the folder where files of a chain with another genesis are put
/// aside.
pub const OLD_CHAIN_PREFIX: &str = "old-chain-";
/// Tail cut from a damaged block file, kept aside.
pub const CUT_TAIL_FILE: &str = "blocks.dat.cut";
/// Unusable header store set aside.
pub const DAMAGED_HEADERS_FILE: &str = "headers.dat.damaged";

/// The state commitment of `chain` as 0.3.x computed it.
///
/// Only used to check an adoption record written by 0.3.x, which holds the
/// trusted commitment under the old labels (`legacy_commitment=`).
pub fn legacy_state_commitment(chain: &Chain) -> Hash256 {
    crate::state::state_commitment_with_tag(
        LEGACY_STATE_TAG,
        chain.utxo.commitment_with_tag(LEGACY_MUHASH_TAG),
        chain.total_issued().units(),
    )
}

/// Upgrades a 0.3.x data directory in place. Returns one line per action
/// taken (empty when there was nothing to do).
///
/// Must run while holding the 0.4 directory lock ([`crate::lock::acquire`])
/// and before anything else reads the directory. An error means a file that
/// carries a user's security choice could not be carried over: the caller
/// must stop rather than run with defaults.
pub fn migrate_data_dir(datadir: &Path) -> Result<Vec<String>, String> {
    let mut done = Vec::new();
    if !datadir.is_dir() {
        return Ok(done);
    }

    // --- 0. No 0.3.x process may still be running on this directory: it
    // takes `.verrou`, not `.lock`, so the 0.4 lock does not stop it.
    let legacy_lock = datadir.join(LEGACY_LOCK_FILE);
    if legacy_lock.exists() {
        match crate::lock::try_lock_file(&legacy_lock) {
            Ok(Some(held)) => {
                drop(held);
                let _ = std::fs::remove_file(&legacy_lock);
                done.push(format!("removed the 0.3.x lock file {LEGACY_LOCK_FILE}"));
            }
            Ok(None) => {
                return Err(format!(
                    "an older q21 (0.3.x) is still running on {}. Close it, then start \
                     this version again.",
                    datadir.display()
                ))
            }
            Err(e) => {
                return Err(format!(
                    "cannot check the 0.3.x lock file {}: {e}",
                    legacy_lock.display()
                ))
            }
        }
    }

    // --- 1. Settings: security-critical, see the module documentation.
    migrate_settings(datadir, &mut done)?;

    // --- 2. Wallet anchor: security-critical as well.
    migrate_anchor(datadir, &mut done)?;

    // --- 3. Bootstrap list: merged, so that a user's own entries survive an
    // archive extracted over the old folder.
    migrate_bootstrap(datadir, &mut done)?;

    // --- 4. Plain renames of binary files.
    rename_if_free(datadir, LEGACY_HEADERS_FILE, HEADERS_FILE, &mut done)?;
    rename_if_free(datadir, LEGACY_CUT_TAIL_FILE, CUT_TAIL_FILE, &mut done)?;
    rename_if_free(
        datadir,
        LEGACY_DAMAGED_HEADERS_FILE,
        DAMAGED_HEADERS_FILE,
        &mut done,
    )?;
    let stale = datadir.join(LEGACY_PRUNING_TEMP_FILE);
    if stale.exists() && std::fs::remove_file(&stale).is_ok() {
        done.push(format!(
            "removed {LEGACY_PRUNING_TEMP_FILE}, left by an interrupted pruning"
        ));
    }

    // --- 5. Adoption record keys.
    migrate_adoption(datadir, &mut done)?;

    // --- 6. Folders of an old chain put aside.
    migrate_old_chain_dirs(datadir, &mut done)?;

    // --- 7. State snapshot under the new MuHash label. Never fatal: a
    // snapshot that cannot be carried over is rebuilt from the block file,
    // as for any unusable snapshot.
    migrate_state_snapshot(datadir, &mut done);

    Ok(done)
}

/// Translates one 0.3.x settings line.
fn translate_settings_line(line: &str) -> String {
    match line.trim().split_once('=') {
        Some((key, value)) if key.trim() == LEGACY_REACHABLE_KEY => {
            // Only `oui` ever meant reachable in a file 0.3.x wrote itself;
            // anything else becomes the more private choice.
            let reachable = value.trim() == LEGACY_YES;
            format!(
                "{}={}",
                crate::settings::REACHABLE_KEY,
                if reachable { "yes" } else { "no" }
            )
        }
        _ => line.to_string(),
    }
}

fn migrate_settings(datadir: &Path, done: &mut Vec<String>) -> Result<(), String> {
    let legacy = datadir.join(LEGACY_SETTINGS_FILE);
    if !legacy.exists() {
        return Ok(());
    }
    let legacy_text = std::fs::read_to_string(&legacy).map_err(|e| {
        format!(
            "cannot read {} to carry over the reachability setting: {e}",
            legacy.display()
        )
    })?;
    let translated: Vec<String> = legacy_text.lines().map(translate_settings_line).collect();
    let target = datadir.join(crate::settings::FILE_NAME);

    let key_of = |line: &str| {
        line.trim()
            .split_once('=')
            .map(|(k, _)| k.trim().to_string())
    };
    let legacy_closed = !crate::settings::reachable_from_text(&translated.join("\n"));
    let current = if target.exists() {
        std::fs::read_to_string(&target).map_err(|e| {
            format!(
                "cannot read {} to merge the reachability setting: {e}",
                target.display()
            )
        })?
    } else {
        String::new()
    };
    let mut text = String::new();
    for line in current.lines() {
        // A closed legacy setting replaces whatever the new file says: when
        // the two disagree, the more private choice wins.
        if legacy_closed && key_of(line).as_deref() == Some(crate::settings::REACHABLE_KEY) {
            continue;
        }
        text.push_str(line);
        text.push('\n');
    }
    for line in &translated {
        let known = match key_of(line) {
            Some(k) => text
                .lines()
                .any(|l| key_of(l).as_deref() == Some(k.as_str())),
            None => current.lines().any(|l| l == line.as_str()),
        };
        if !known {
            text.push_str(line);
            text.push('\n');
        }
    }

    crate::settings::write_atomic(&target, &text).map_err(|e| {
        format!(
            "cannot write {} to carry over the reachability setting: {e}",
            target.display()
        )
    })?;
    // Read back before removing the old file: the setting must have landed.
    let written = std::fs::read_to_string(&target).map_err(|e| e.to_string())?;
    if !crate::settings::reachable_from_text(&translated.join("\n"))
        && crate::settings::reachable_from_text(&written)
    {
        return Err(format!(
            "{} did not keep `reachable=no`; {} is left in place",
            target.display(),
            legacy.display()
        ));
    }
    std::fs::remove_file(&legacy).map_err(|e| e.to_string())?;
    done.push(format!(
        "{LEGACY_SETTINGS_FILE} -> {} (reachable={})",
        crate::settings::FILE_NAME,
        if crate::settings::reachable_from_text(&written) {
            "yes"
        } else {
            "no"
        }
    ));
    Ok(())
}

/// The two facts of a wallet anchor: "this directory has held a sealed
/// wallet", and the public fingerprint of its seed.
fn parse_anchor(text: &str, sealed_key: &str, seed_key: &str) -> (bool, Option<String>) {
    let mut sealed = false;
    let mut seed = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some((k, v)) if k.trim() == sealed_key => sealed = v.trim() == "1",
            Some((k, v)) if k.trim() == seed_key && !v.trim().is_empty() => {
                seed = Some(v.trim().to_string())
            }
            _ => {}
        }
    }
    (sealed, seed)
}

fn migrate_anchor(datadir: &Path, done: &mut Vec<String>) -> Result<(), String> {
    let legacy = datadir.join(LEGACY_ANCHOR_FILE);
    if !legacy.exists() {
        return Ok(());
    }
    let legacy_text = std::fs::read_to_string(&legacy)
        .map_err(|e| format!("cannot read {} to carry it over: {e}", legacy.display()))?;
    let (mut sealed, mut seed) = parse_anchor(
        &legacy_text,
        LEGACY_ANCHOR_SEALED_KEY,
        LEGACY_ANCHOR_SEED_KEY,
    );
    let target = datadir.join(ANCHOR_FILE);
    if target.exists() {
        let current = std::fs::read_to_string(&target)
            .map_err(|e| format!("cannot read {} to merge it: {e}", target.display()))?;
        let (s2, g2) = parse_anchor(&current, "sealed", "seed");
        // "Has held a sealed wallet" is never forgotten; the newer seed wins.
        sealed |= s2;
        if g2.is_some() {
            seed = g2;
        }
    }
    let text = format!(
        "sealed={}\nseed={}\n",
        u8::from(sealed),
        seed.unwrap_or_default()
    );
    write_private_atomic(&target, &text)
        .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    std::fs::remove_file(&legacy).map_err(|e| e.to_string())?;
    done.push(format!("{LEGACY_ANCHOR_FILE} -> {ANCHOR_FILE}"));
    Ok(())
}

fn migrate_bootstrap(datadir: &Path, done: &mut Vec<String>) -> Result<(), String> {
    let legacy = datadir.join(LEGACY_BOOTSTRAP_FILE);
    if !legacy.exists() {
        return Ok(());
    }
    let target = datadir.join(crate::bootstrap::FILE_NAME);
    if !target.exists() {
        std::fs::rename(&legacy, &target).map_err(|e| {
            format!(
                "cannot rename {} to {}: {e}",
                legacy.display(),
                target.display()
            )
        })?;
        done.push(format!(
            "{LEGACY_BOOTSTRAP_FILE} -> {}",
            crate::bootstrap::FILE_NAME
        ));
        return Ok(());
    }
    // Both exist: typically a new archive extracted over the old folder. Add
    // the user's entries that the new file does not have yet.
    let legacy_text = std::fs::read_to_string(&legacy).map_err(|e| e.to_string())?;
    let current = std::fs::read_to_string(&target).map_err(|e| e.to_string())?;
    let have = crate::bootstrap::read_bootstrap(&current);
    let missing: Vec<String> = crate::bootstrap::read_bootstrap(&legacy_text)
        .into_iter()
        .filter(|a| !have.contains(a))
        .collect();
    if !missing.is_empty() {
        let mut text = current;
        if !text.ends_with('\n') && !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!("# Carried over from {LEGACY_BOOTSTRAP_FILE}\n"));
        for a in &missing {
            text.push_str(a);
            text.push('\n');
        }
        crate::settings::write_atomic(&target, &text)?;
    }
    std::fs::remove_file(&legacy).map_err(|e| e.to_string())?;
    done.push(format!(
        "{LEGACY_BOOTSTRAP_FILE} merged into {} ({} entr{} added)",
        crate::bootstrap::FILE_NAME,
        missing.len(),
        if missing.len() == 1 { "y" } else { "ies" }
    ));
    Ok(())
}

fn rename_if_free(
    datadir: &Path,
    old: &str,
    new: &str,
    done: &mut Vec<String>,
) -> Result<(), String> {
    let from = datadir.join(old);
    let to = datadir.join(new);
    if !from.exists() {
        return Ok(());
    }
    if to.exists() {
        done.push(format!("{old} left in place: {new} already exists"));
        return Ok(());
    }
    std::fs::rename(&from, &to)
        .map_err(|e| format!("cannot rename {} to {}: {e}", from.display(), to.display()))?;
    done.push(format!("{old} -> {new}"));
    Ok(())
}

fn migrate_adoption(datadir: &Path, done: &mut Vec<String>) -> Result<(), String> {
    let path = datadir.join(ADOPTION_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let is_legacy = text.lines().any(|l| {
        l.split_once('=').is_some_and(|(k, _)| {
            k == LEGACY_ADOPTION_HEIGHT_KEY || k == LEGACY_ADOPTION_REVALIDATED_KEY
        })
    });
    if !is_legacy {
        return Ok(());
    }
    let mut out = String::new();
    for line in text.lines() {
        let translated = match line.split_once('=') {
            Some((LEGACY_ADOPTION_HEIGHT_KEY, v)) => format!("height={v}"),
            Some((LEGACY_ADOPTION_TIP_KEY, v)) => format!("tip={v}"),
            // Computed under the 0.3.x labels: kept apart, never compared
            // with a commitment under the current ones.
            Some((LEGACY_ADOPTION_COMMITMENT_KEY, v)) => format!("legacy_commitment={v}"),
            Some((LEGACY_ADOPTION_REVALIDATED_KEY, v)) => {
                format!(
                    "revalidated={}",
                    if v.trim() == LEGACY_YES { "yes" } else { "no" }
                )
            }
            _ => line.to_string(),
        };
        out.push_str(&translated);
        out.push('\n');
    }
    crate::settings::write_atomic(&path, &out)
        .map_err(|e| format!("cannot rewrite {}: {e}", path.display()))?;
    done.push(format!("{ADOPTION_FILE}: keys translated"));
    Ok(())
}

fn migrate_old_chain_dirs(datadir: &Path, done: &mut Vec<String>) -> Result<(), String> {
    let Ok(entries) = std::fs::read_dir(datadir) else {
        return Ok(());
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(id) = name.strip_prefix(LEGACY_OLD_CHAIN_PREFIX) {
            if e.path().is_dir() {
                let new = format!("{OLD_CHAIN_PREFIX}{id}");
                rename_if_free(datadir, &name, &new, done)?;
                // The folder holds a header store under its old name too.
                let moved = datadir.join(&new);
                if moved.is_dir() {
                    let mut inner = Vec::new();
                    rename_if_free(&moved, LEGACY_HEADERS_FILE, HEADERS_FILE, &mut inner)?;
                }
            }
        }
    }
    Ok(())
}

fn migrate_state_snapshot(datadir: &Path, done: &mut Vec<String>) {
    let path = datadir.join("state.dat");
    if !path.exists() {
        return;
    }
    let Ok(key) = crate::state::datadir_key(datadir) else {
        return;
    };
    let store = crate::state::StateStore::new_sealed(&path, key);
    match store.migrate_commitment_label(LEGACY_MUHASH_TAG) {
        Ok(true) => done.push("state.dat: commitment relabeled".to_string()),
        Ok(false) => {}
        Err(e) => done.push(format!(
            "state.dat not carried over ({e}); it will be rebuilt from the block file"
        )),
    }
}

/// Like [`crate::settings::write_atomic`], but the temporary file is created
/// readable by its owner only, as the binary does for the wallet anchor.
fn write_private_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = crate::state::create_private_temp(&tmp).map_err(|e| e.to_string())?;
        f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("q21-legacy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // The test inputs below are written in the frozen 0.3.x format on
    // purpose: `joignable=oui/non`, `scelle=`, `graine=`, the old adoption
    // keys and folder names.

    /// Regression test, security-critical: a 0.3.x wallet that was told not
    /// to be reachable must stay closed after the upgrade.
    #[test]
    fn legacy_unreachable_setting_stays_not_reachable() {
        let d = dir("closed");
        std::fs::write(d.join(LEGACY_SETTINGS_FILE), "joignable=non\n").unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(!d.join(LEGACY_SETTINGS_FILE).exists());
        assert!(!crate::settings::reachable(&d), "the node became reachable");
        assert_eq!(
            std::fs::read_to_string(d.join(crate::settings::FILE_NAME)).unwrap(),
            "reachable=no\n"
        );
        // Running it again changes nothing.
        assert!(migrate_data_dir(&d).unwrap().is_empty());
        assert!(!crate::settings::reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_reachable_setting_stays_reachable() {
        let d = dir("open");
        std::fs::write(d.join(LEGACY_SETTINGS_FILE), "joignable=oui\n").unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(crate::settings::reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unknown_legacy_value_becomes_not_reachable() {
        let d = dir("odd");
        // An unknown 0.3.x value ("maybe").
        std::fs::write(d.join(LEGACY_SETTINGS_FILE), "joignable=peut-etre\n").unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(!crate::settings::reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Both files present (an archive extracted over the old folder, or a
    /// downgrade then upgrade): a `no` in either one wins.
    #[test]
    fn closed_legacy_setting_wins_over_open_new_file() {
        let d = dir("both");
        std::fs::write(d.join(LEGACY_SETTINGS_FILE), "joignable=non\n").unwrap();
        std::fs::write(d.join(crate::settings::FILE_NAME), "reachable=yes\n").unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(!crate::settings::reachable(&d));
        let _ = std::fs::remove_dir_all(&d);

        let d = dir("both2");
        std::fs::write(d.join(LEGACY_SETTINGS_FILE), "joignable=oui\n").unwrap();
        std::fs::write(d.join(crate::settings::FILE_NAME), "reachable=no\n").unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(!crate::settings::reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn anchor_keeps_sealed_flag_and_seed() {
        let d = dir("anchor");
        std::fs::write(d.join(LEGACY_ANCHOR_FILE), "scelle=1\ngraine=abcd\n").unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(!d.join(LEGACY_ANCHOR_FILE).exists());
        assert_eq!(
            std::fs::read_to_string(d.join(ANCHOR_FILE)).unwrap(),
            "sealed=1\nseed=abcd\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join(ANCHOR_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the anchor must stay private");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bootstrap_list_is_renamed_or_merged() {
        let d = dir("boot");
        std::fs::write(
            d.join(LEGACY_BOOTSTRAP_FILE),
            "# mine\nnode.example:21121\n",
        )
        .unwrap();
        migrate_data_dir(&d).unwrap();
        assert_eq!(
            crate::bootstrap::bootstrap_from_datadir(&d),
            vec!["node.example:21121".to_string()]
        );
        let _ = std::fs::remove_dir_all(&d);

        let d = dir("boot2");
        std::fs::write(
            d.join(LEGACY_BOOTSTRAP_FILE),
            "node.example:21121\n198.51.100.7:21121\n",
        )
        .unwrap();
        std::fs::write(d.join(crate::bootstrap::FILE_NAME), "198.51.100.7:21121\n").unwrap();
        migrate_data_dir(&d).unwrap();
        let list = crate::bootstrap::bootstrap_from_datadir(&d);
        assert_eq!(list.len(), 2, "{list:?}");
        assert!(list.contains(&"node.example:21121".to_string()));
        assert!(!d.join(LEGACY_BOOTSTRAP_FILE).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn adoption_record_keys_are_translated() {
        let d = dir("adoption");
        std::fs::write(
            d.join(ADOPTION_FILE),
            "hauteur=12\ntete=aa\nempreinte=bb\nrevalide=non\n",
        )
        .unwrap();
        migrate_data_dir(&d).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join(ADOPTION_FILE)).unwrap(),
            "height=12\ntip=aa\nlegacy_commitment=bb\nrevalidated=no\n"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn headers_and_old_chain_folders_are_renamed() {
        let d = dir("files");
        std::fs::write(d.join(LEGACY_HEADERS_FILE), b"x").unwrap();
        std::fs::create_dir_all(d.join("ancienne-chaine-0123456789ab")).unwrap();
        std::fs::write(
            d.join("ancienne-chaine-0123456789ab")
                .join(LEGACY_HEADERS_FILE),
            b"y",
        )
        .unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(d.join(HEADERS_FILE).exists());
        assert!(d.join("old-chain-0123456789ab").join(HEADERS_FILE).exists());
        assert!(!d.join("ancienne-chaine-0123456789ab").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_free_legacy_lock_is_removed() {
        let d = dir("lock");
        std::fs::write(d.join(LEGACY_LOCK_FILE), b"").unwrap();
        migrate_data_dir(&d).unwrap();
        assert!(!d.join(LEGACY_LOCK_FILE).exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
