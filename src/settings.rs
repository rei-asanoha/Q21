//! Node settings kept in the data directory: `settings.txt`.
//!
//! One `key=value` per line, readable and not secret. An unknown key is
//! ignored, so that a later version can add one without an older version
//! getting lost in it.
//!
//! The only key today is `reachable`: does this node accept incoming
//! connections and ask the router to open its port? Up to 0.3.x the file
//! had another name and other keys; [`crate::legacy::migrate_data_dir`]
//! translates it before anything reads it.

use std::path::Path;

/// Name of the settings file in the data directory.
pub const FILE_NAME: &str = "settings.txt";

/// Key of the reachability setting.
pub const REACHABLE_KEY: &str = "reachable";

/// Reads the "is this node reachable from outside" setting.
///
/// Absent file or absent key = **yes**: by default, a wallet contributes to
/// the network by accepting connections. An unreadable file also falls back
/// to yes, so the default does not depend on the state of the disk.
///
/// A key that is present is read strictly: only `yes` means reachable. Any
/// other value, including a typo, keeps the node closed. The user who wrote
/// something there did not ask to be exposed.
pub fn reachable(datadir: &Path) -> bool {
    let text = match std::fs::read_to_string(datadir.join(FILE_NAME)) {
        Ok(t) => t,
        Err(_) => return true,
    };
    reachable_from_text(&text)
}

/// The parsing half of [`reachable`], on the file's text.
pub fn reachable_from_text(text: &str) -> bool {
    for line in text.lines() {
        if let Some((key, value)) = line.trim().split_once('=') {
            if key.trim() == REACHABLE_KEY {
                return value.trim() == "yes";
            }
        }
    }
    true
}

/// Writes the reachability setting. Atomic write (temporary file then
/// rename), like `wallet.anchor`: a power cut leaves the old file whole,
/// never a half-written one. Other keys already in the file are kept.
pub fn set_reachable(datadir: &Path, reachable: bool) -> Result<(), String> {
    let path = datadir.join(FILE_NAME);
    let old = std::fs::read_to_string(&path).unwrap_or_default();
    let mut text = String::new();
    for line in old.lines() {
        let key = line.trim().split_once('=').map(|(c, _)| c.trim());
        if key == Some(REACHABLE_KEY) {
            continue;
        }
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&format!(
        "{REACHABLE_KEY}={}\n",
        if reachable { "yes" } else { "no" }
    ));
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

    #[test]
    fn absent_file_means_reachable() {
        let d = dir("absent");
        assert!(reachable(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_yes_means_reachable() {
        assert!(reachable_from_text("reachable=yes\n"));
        assert!(!reachable_from_text("reachable=no\n"));
        // A 0.3.x-style value ("non") is not `yes`.
        assert!(!reachable_from_text("reachable=non\n"));
        assert!(!reachable_from_text("reachable=\n"));
        assert!(reachable_from_text("other=1\n"));
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
}
