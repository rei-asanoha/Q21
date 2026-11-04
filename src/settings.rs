//! Node settings kept in the data directory: `settings.txt`.
//!
//! One `key=value` per line, readable and not secret. An unknown key is
//! ignored, so that a later version can add one without an older version
//! getting lost in it.
//!
//! Two keys today. `reachable`: does this node accept incoming connections
//! and ask the router to open its port? `tor` (0.4.7): does every outgoing
//! connection go through Tor? Both are **off** unless the user turns them on,
//! for every node; the wallet alone (0.5.9) turns them on when the user never
//! chose, see [`wallet_defaults`].
//! Up to 0.3.x the file
//! had another name and other keys; [`crate::legacy::migrate_data_dir`]
//! translates it before anything reads it.

use std::path::Path;

/// Name of the settings file in the data directory.
pub const FILE_NAME: &str = "settings.txt";

/// Key of the reachability setting.
pub const REACHABLE_KEY: &str = "reachable";

/// Key of the Tor setting.
pub const TOR_KEY: &str = "tor";

/// Reads the "is this node reachable from outside" setting.
///
/// Only an explicit `reachable=yes` makes a wallet reachable. An absent file,
/// an absent key, an unreadable file, any other value or a typo: the node
/// stays a client.
///
/// # Why off by default
///
/// A reachable wallet asks the home router to open a port and announces its
/// public address to its peers, which pass it on: the owner's home IP address
/// ends up in the address book of every node of the network, and an address
/// once gossiped cannot be called back. Up to 0.4.0 this was the default.
/// Turning it on must be a choice made knowing that, never a side effect of
/// installing a wallet.
pub fn reachable(datadir: &Path) -> bool {
    let text = match std::fs::read_to_string(datadir.join(FILE_NAME)) {
        Ok(t) => t,
        Err(_) => return false,
    };
    reachable_from_text(&text)
}

/// The parsing half of [`reachable`], on the file's text.
pub fn reachable_from_text(text: &str) -> bool {
    matches!(
        value_in_text(text, REACHABLE_KEY).as_deref(),
        Some("yes" | ONION_ONLY)
    )
}

/// The value the wallet writes when it makes itself reachable on its own
/// (0.5.9): reachable through Tor only. If Tor is turned off later, the
/// wallet does not become reachable in the clear: that, with its router port
/// and its address announced, needs an explicit `reachable=yes` (red-team
/// campaign 8).
pub const ONION_ONLY: &str = "onion";

/// Reachable in the clear: only an explicit `reachable=yes`, never the
/// default [`ONION_ONLY`].
pub fn reachable_in_clear(datadir: &Path) -> bool {
    std::fs::read_to_string(datadir.join(FILE_NAME))
        .map(|t| value_in_text(&t, REACHABLE_KEY).as_deref() == Some("yes"))
        .unwrap_or(false)
}

/// The value of `key` in this text, trimmed; `None` when the key is absent.
/// A byte-order mark before the first key is not part of it.
pub fn value_in_text(text: &str, wanted: &str) -> Option<String> {
    for line in text.trim_start_matches('\u{feff}').lines() {
        if let Some((key, value)) = line.trim().split_once('=') {
            if key.trim() == wanted {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Reads the Tor setting: only an explicit `tor=yes` turns it on, as for
/// [`reachable`].
pub fn tor(datadir: &Path) -> bool {
    std::fs::read_to_string(datadir.join(FILE_NAME))
        .map(|t| yes_in_text(&t, TOR_KEY))
        .unwrap_or(false)
}

/// What `key` says in this text: `Some(true)` for `yes`, `Some(false)` for
/// any other value, `None` when the key is absent. An unreadable file reads
/// as absent.
pub fn choice_in_text(text: &str, wanted: &str) -> Option<bool> {
    value_in_text(text, wanted).map(|v| v == "yes")
}

/// The wallet's defaults (0.5.9): a contact found in the directory must be
/// able to call this wallet, without anyone setting anything.
///
/// - No `tor` key, and a Tor this computer can use (`tor_available`):
///   `tor=yes` is written. Without a Tor, nothing is written: the wallet
///   runs as before, and the next start looks again.
/// - No `reachable` key, and Tor on: `reachable=onion` is written: reachable
///   through Tor only, an onion service. The wallet listens on the computer
///   itself only, never asks the router for anything, and its internet
///   address is never announced, even if Tor is later turned off. Without
///   Tor, nothing is written: a wallet reachable in the clear would announce
///   its owner's address, which stays a choice (`reachable=yes`, see
///   [`reachable_in_clear`]).
///
/// A key the user wrote, `no` included, is never changed. Returns what was
/// written, for the log.
pub fn wallet_defaults(datadir: &Path, tor_available: bool) -> Result<Vec<&'static str>, String> {
    // A file that cannot be read (not UTF-8, a folder in its place) is not
    // an absent one: nothing is written over the user's own words.
    let text = match std::fs::read_to_string(datadir.join(FILE_NAME)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("{FILE_NAME} unreadable, left as it is: {e}")),
    };
    let mut written = Vec::new();
    let tor_on = match choice_in_text(&text, TOR_KEY) {
        Some(on) => on,
        None if tor_available => {
            set_tor(datadir, true)?;
            written.push(TOR_KEY);
            true
        }
        None => false,
    };
    if tor_on && choice_in_text(&text, REACHABLE_KEY).is_none() {
        set_value(datadir, REACHABLE_KEY, ONION_ONLY)?;
        written.push(REACHABLE_KEY);
    }
    Ok(written)
}

/// Key of this node's own onion service, written by hand once Tor has
/// created it: `onion=….onion`.
pub const ONION_KEY: &str = "onion";

/// Reads the onion service name, if any.
pub fn onion(datadir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(datadir.join(FILE_NAME)).ok()?;
    value_in_text(&text, ONION_KEY).filter(|v| !v.is_empty())
}

/// Is `key` set to exactly `yes` in this text?
pub fn yes_in_text(text: &str, wanted: &str) -> bool {
    value_in_text(text, wanted).as_deref() == Some("yes")
}

/// Writes the reachability setting. Atomic write (temporary file then
/// rename), like `wallet.anchor`: a power cut leaves the old file whole,
/// never a half-written one. Other keys already in the file are kept.
///
/// Turned on while Tor is on, it is `onion`: reachable through Tor only, as
/// the card says. Turning Tor off later then makes the wallet unreachable,
/// never reachable in the clear: that is a choice made with Tor off
/// (red-team campaign 8, third round).
pub fn set_reachable(datadir: &Path, reachable: bool) -> Result<(), String> {
    if reachable && tor(datadir) {
        return set_value(datadir, REACHABLE_KEY, ONION_ONLY);
    }
    set_yes_no(datadir, REACHABLE_KEY, reachable)
}

/// Writes the Tor setting, like [`set_reachable`].
pub fn set_tor(datadir: &Path, on: bool) -> Result<(), String> {
    set_yes_no(datadir, TOR_KEY, on)
}

fn set_yes_no(datadir: &Path, wanted: &str, on: bool) -> Result<(), String> {
    set_value(datadir, wanted, if on { "yes" } else { "no" })
}

fn set_value(datadir: &Path, wanted: &str, value: &str) -> Result<(), String> {
    let path = datadir.join(FILE_NAME);
    // Never rewrite from nothing a file that exists but cannot be read.
    let old = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("{FILE_NAME} unreadable, left as it is: {e}")),
    };
    let mut text = String::new();
    for line in old.trim_start_matches('\u{feff}').lines() {
        let key = line.trim().split_once('=').map(|(c, _)| c.trim());
        if key == Some(wanted) {
            continue;
        }
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&format!("{wanted}={value}\n"));
    write_atomic(&path, &text)
}

/// Writes `text` to `path` through a synced temporary file and a rename.
pub(crate) fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("q21-settings-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Security regression: a new wallet, with no setting at all, must not
    /// open the router port nor announce its owner's address.
    #[test]
    fn absent_file_means_not_reachable() {
        let d = dir("absent");
        assert!(!reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unreadable_file_means_not_reachable() {
        let d = dir("unreadable");
        // A directory where the file should be: present but unreadable.
        std::fs::create_dir_all(d.join(FILE_NAME)).unwrap();
        assert!(!reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_yes_means_reachable() {
        assert!(reachable_from_text("reachable=yes\n"));
        assert!(!reachable_from_text("reachable=no\n"));
        // A 0.3.x-style value ("non") is not `yes`.
        assert!(!reachable_from_text("reachable=non\n"));
        assert!(!reachable_from_text("reachable=\n"));
        assert!(!reachable_from_text("reachable=YES\n"));
        // Another key only: the setting is absent, so off.
        assert!(!reachable_from_text("other=1\n"));
        assert!(!reachable_from_text(""));
    }

    #[test]
    fn set_reachable_round_trips_and_keeps_other_keys() {
        let d = dir("roundtrip");
        std::fs::write(d.join(FILE_NAME), "future=42\nreachable=yes\n").unwrap();
        set_reachable(&d, false).unwrap();
        assert!(!reachable(&d));
        let text = std::fs::read_to_string(d.join(FILE_NAME)).unwrap();
        assert!(text.contains("future=42"));
        set_reachable(&d, true).unwrap();
        assert!(reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The Tor key lives next to the other one, off unless `yes`, and
    /// writing one keeps the other.
    #[test]
    fn tor_is_off_unless_yes_and_keeps_the_other_keys() {
        let d = dir("tor");
        assert!(!tor(&d));
        set_reachable(&d, true).unwrap();
        set_tor(&d, true).unwrap();
        assert!(tor(&d) && reachable(&d));
        set_tor(&d, false).unwrap();
        assert!(!tor(&d) && reachable(&d));
        assert!(!yes_in_text("tor=YES\n", TOR_KEY));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The wallet's defaults (0.5.9): Tor on when a Tor is there, and
    /// reachable through it; what the user chose is kept, `no` included;
    /// never reachable in the clear by default.
    /// Red-team campaign 8: the reachability the wallet gives itself holds
    /// through Tor only; Tor turned off later does not make it reachable in
    /// the clear. A byte-order mark does not hide a key, and a file that
    /// cannot be read is never rewritten from nothing.
    #[test]
    fn the_default_reachability_never_becomes_reachable_in_the_clear() {
        let d = dir("defaults-onion-only");
        wallet_defaults(&d, true).unwrap();
        assert!(reachable(&d), "reachable through Tor");
        assert!(!reachable_in_clear(&d), "never in the clear by default");
        set_tor(&d, false).unwrap();
        assert!(!reachable_in_clear(&d), "Tor off: still not in the clear");
        set_reachable(&d, true).unwrap();
        assert!(reachable_in_clear(&d), "an explicit yes is");
        // The switch, turned on while Tor is on, is Tor-only too (third
        // round: one click wrote `yes`, and Tor off then listened in the
        // clear).
        set_tor(&d, true).unwrap();
        set_reachable(&d, false).unwrap();
        set_reachable(&d, true).unwrap();
        assert!(reachable(&d) && !reachable_in_clear(&d));
        set_tor(&d, false).unwrap();
        assert!(!reachable_in_clear(&d));
        let _ = std::fs::remove_dir_all(&d);

        let d = dir("defaults-bom");
        std::fs::write(d.join(FILE_NAME), "\u{feff}tor=no\nreachable=no\n").unwrap();
        assert!(wallet_defaults(&d, true).unwrap().is_empty());
        assert!(!tor(&d) && !reachable(&d));
        let _ = std::fs::remove_dir_all(&d);

        let d = dir("defaults-latin1");
        std::fs::write(d.join(FILE_NAME), b"# caf\xe9\ntor=no\n").unwrap();
        assert!(wallet_defaults(&d, true).is_err());
        assert_eq!(
            std::fs::read(d.join(FILE_NAME)).unwrap(),
            b"# caf\xe9\ntor=no\n".to_vec(),
            "left as it is"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_wallet_defaults_to_tor_and_reachable_through_it() {
        // A new wallet, with a Tor: both on.
        let d = dir("defaults-new");
        assert_eq!(
            wallet_defaults(&d, true).unwrap(),
            vec![TOR_KEY, REACHABLE_KEY]
        );
        assert!(tor(&d) && reachable(&d));
        // A second start writes nothing more.
        assert!(wallet_defaults(&d, true).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);

        // No Tor on this computer: nothing written, not reachable in the clear.
        let d = dir("defaults-no-tor");
        assert!(wallet_defaults(&d, false).unwrap().is_empty());
        assert!(!tor(&d) && !reachable(&d));
        assert!(!d.join(FILE_NAME).exists());
        let _ = std::fs::remove_dir_all(&d);

        // The user's choices are kept.
        for (text, tor_after, reachable_after) in [
            ("tor=no\n", false, false),
            ("tor=no\nreachable=yes\n", false, true),
            ("tor=yes\nreachable=no\n", true, false),
            ("reachable=no\n", true, false),
            ("tor=yes\n", true, true),
            ("reachable=yes\n", true, true),
            ("tor=YES\n", false, false),
        ] {
            let d = dir("defaults-kept");
            std::fs::write(d.join(FILE_NAME), text).unwrap();
            wallet_defaults(&d, true).unwrap();
            assert_eq!(
                (tor(&d), reachable(&d)),
                (tor_after, reachable_after),
                "{text}"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
        assert_eq!(choice_in_text("a=1\n", TOR_KEY), None);
        assert_eq!(choice_in_text("tor=no\n", TOR_KEY), Some(false));
        assert_eq!(choice_in_text(" tor = yes \n", TOR_KEY), Some(true));
    }
}
