//! The wallet launcher without a window: `Q21 Wallet.exe` on Windows, the
//! program inside `Q21 Wallet.app` on macOS.
//!
//! # Why
//!
//! The launchers used to be a `.bat` file and a `.command` file. Both open a
//! console window next to the wallet — PowerShell's blue window, the macOS
//! Terminal — that the user did not ask for, cannot use, and is afraid to
//! close. The wallet is a page in the browser; nothing else should show.
//!
//! # What it does
//!
//! It starts `q21 wallet` next to it with no window (on Windows,
//! `CREATE_NO_WINDOW`; on macOS, from an application bundle, which macOS
//! opens without a Terminal), appends what the wallet prints to
//! `q21-data/wallet.log`, and watches it for [`GRACE`]. If the wallet stops
//! with an error in that time — the moment errors happen — the end of the log
//! is shown in a dialog box. After that, the launcher leaves: the wallet runs
//! on its own, and a later double-click starts a new launcher. That matters
//! on macOS, where double-clicking an application that is still running
//! starts nothing.
//!
//! A second launch while the wallet runs does not start a second one:
//! `q21 wallet` finds the folder in use, asks the running wallet to open its
//! page again, and exits without error.
//!
//! The `.bat` and `.command` files stay in the archive, renamed, for whoever
//! wants to see what the wallet prints.
#![cfg_attr(windows, windows_subsystem = "windows")]

use q21_core::dialog::alert;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LOG_NAME: &str = "wallet.log";

/// What the release archive ships next to the launcher, by name: the files
/// whose quarantine mark the launcher removes on macOS, and nothing else.
/// Keep in step with the "Assemble" step of `.github/workflows/release.yml`.
#[cfg(any(target_os = "macos", test))]
const ARCHIVE_ENTRIES: &[&str] = &[
    "q21",
    "Q21 Wallet.app",
    "Troubleshooting",
    "tor",
    "bootstrap.txt",
    "q21-data/bootstrap.txt",
    "README.md",
    "JOIN.md",
    "WHITEPAPER.md",
    "AUDIT.md",
    "WALLET.md",
    "REPRODUCING.md",
    "SUCCESSION.md",
    "TOR.md",
];

/// How long the launcher watches the wallet before leaving it: long enough
/// for the wallet to fail to start (a program that cannot run, a folder in
/// use: within a second or two), short enough not to stand in the way of the
/// next launch — on macOS, a double-click on an application still running
/// starts nothing. A later error is shown by the wallet itself, in a dialog
/// box (`Q21_NO_WINDOW`).
const GRACE: Duration = Duration::from_secs(8);

/// Beyond this size, the log is set aside as `wallet.log.old` at the next
/// launch: each launch appends to it, and a wallet left running for months
/// prints a status line now and then.
const LOG_LIMIT: u64 = 2 * 1024 * 1024;

fn main() {
    let folder = match program_folder() {
        Ok(f) => f,
        Err(e) => {
            alert(&e);
            std::process::exit(1);
        }
    };
    let program = folder.join(if cfg!(windows) { "q21.exe" } else { "q21" });
    if !program.is_file() {
        alert(&format!(
            "The wallet program was not found next to this launcher:\n{}\n\n\
             Unzip the whole archive into one folder, and open the wallet from there.",
            program.display()
        ));
        std::process::exit(1);
    }

    #[cfg(target_os = "macos")]
    {
        // Every file a browser downloads carries a quarantine mark, and macOS
        // refuses to run a program that carries it without asking. The
        // launcher was allowed by the user; the files of the archive are
        // released here, once, as `Troubleshooting/Q21 Wallet - Terminal.command`
        // does — by name. Up to 0.4.8 the whole folder was: unpacked straight
        // into Downloads, that released every other file downloaded there.
        let shipped: Vec<PathBuf> = ARCHIVE_ENTRIES
            .iter()
            .map(|name| folder.join(name))
            .filter(|p| p.exists())
            .collect();
        if !shipped.is_empty() {
            let _ = Command::new("/usr/bin/xattr")
                .arg("-dr")
                .arg("com.apple.quarantine")
                .args(&shipped)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    let data = folder.join("q21-data");
    let _ = std::fs::create_dir_all(&data);
    let log_path = data.join(LOG_NAME);
    let log = open_log(&log_path);

    let mut cmd = Command::new(&program);
    cmd.arg("wallet")
        .current_dir(&folder)
        .env("Q21_NO_WINDOW", "1")
        .stdin(Stdio::null());
    match log.and_then(|f| Ok((f.try_clone()?, f))) {
        Ok((out, err)) => {
            cmd.stdout(out).stderr(err);
        }
        Err(_) => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            alert(&format!(
                "The wallet could not be started: {e}\n{}",
                program.display()
            ));
            std::process::exit(1);
        }
    };
    let started = Instant::now();
    while started.elapsed() < GRACE {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return,
            Ok(Some(_)) => {
                let tail = log_tail(&log_path, 12);
                alert(&format!(
                    "The wallet stopped with an error.\n\n{tail}\n\nThe whole message is in {}",
                    log_path.display()
                ));
                std::process::exit(1);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(_) => return,
        }
    }
    // Still running: it goes on without the launcher.
}

/// Opens the log for appending, after setting a log grown too large aside.
fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    use std::io::Write;
    if std::fs::metadata(path)
        .map(|m| m.len() > LOG_LIMIT)
        .unwrap_or(false)
    {
        let _ = std::fs::rename(path, path.with_extension("log.old"));
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(f, "\n=== launch (unix time {now}) ===");
    Ok(f)
}

/// The folder that holds `q21`: the launcher's own, or, inside a macOS
/// application bundle (`Q21 Wallet.app/Contents/MacOS/`), the one that holds
/// the bundle.
fn program_folder() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("launcher not found: {e}"))?;
    let exe = original_location(&exe);
    let dir = exe
        .parent()
        .ok_or_else(|| "launcher folder not found".to_string())?;
    Ok(bundle_folder(dir).unwrap_or_else(|| dir.to_path_buf()))
}

/// `…/Q21 Wallet.app/Contents/MacOS` → `…`, the folder the bundle sits in.
fn bundle_folder(dir: &Path) -> Option<PathBuf> {
    let macos = dir.file_name()?.to_str()?;
    let contents = dir.parent()?;
    let app = contents.parent()?;
    let is_bundle = macos == "MacOS"
        && contents.file_name()?.to_str()? == "Contents"
        && app.extension()?.to_str()? == "app";
    if is_bundle {
        app.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

/// On macOS, an application that still carries the quarantine mark is run
/// from a random read-only copy ("App Translocation"), away from the folder
/// it was unzipped in: `q21` would not be found next to it. The system
/// tells where the real one is.
#[cfg(target_os = "macos")]
fn original_location(exe: &Path) -> PathBuf {
    macos::original_path(exe).unwrap_or_else(|| exe.to_path_buf())
}

#[cfg(not(target_os = "macos"))]
fn original_location(exe: &Path) -> PathBuf {
    exe.to_path_buf()
}

/// The last `n` lines of the wallet's log, after the last launch marker.
fn log_tail(path: &Path, n: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let session = text.rsplit("=== launch").next().unwrap_or("");
    let lines: Vec<&str> = session
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .collect();
    let start = lines.len().saturating_sub(n);
    let tail = lines[start..].join("\n");
    if tail.is_empty() {
        "(the wallet printed nothing)".to_string()
    } else {
        tail
    }
}

#[cfg(target_os = "macos")]
mod macos {
    //! `SecTranslocateIsTranslocatedURL` and
    //! `SecTranslocateCreateOriginalPathForURL` (Security framework, macOS
    //! 10.12 and later), looked up when needed rather than linked: if a
    //! system does not offer them, the launcher simply does without.
    use std::ffi::{c_void, CStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    type CFTypeRef = *const c_void;
    type CFURLRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFErrorRef = *mut c_void;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFURLCreateFromFileSystemRepresentation(
            allocator: CFAllocatorRef,
            buffer: *const u8,
            length: isize,
            is_directory: u8,
        ) -> CFURLRef;
        fn CFURLGetFileSystemRepresentation(
            url: CFURLRef,
            resolve_against_base: u8,
            buffer: *mut u8,
            max_length: isize,
        ) -> u8;
        fn CFRelease(cf: CFTypeRef);
    }

    type IsTranslocated = unsafe extern "C" fn(CFURLRef, *mut u8, *mut CFErrorRef) -> u8;
    type OriginalPath = unsafe extern "C" fn(CFURLRef, *mut CFErrorRef) -> CFURLRef;

    fn symbol(handle: *mut c_void, name: &[u8]) -> Option<*mut c_void> {
        let name = CStr::from_bytes_with_nul(name).ok()?;
        // SAFETY: `handle` comes from `dlopen`, `name` is NUL-terminated.
        let p = unsafe { libc::dlsym(handle, name.as_ptr()) };
        (!p.is_null()).then_some(p)
    }

    /// The original location of a translocated program, or `None` when it is
    /// not translocated (or the system cannot say).
    pub fn original_path(exe: &Path) -> Option<PathBuf> {
        let lib =
            CStr::from_bytes_with_nul(b"/System/Library/Frameworks/Security.framework/Security\0")
                .ok()?;
        // SAFETY: plain dynamic loading of a system framework.
        let handle = unsafe { libc::dlopen(lib.as_ptr(), libc::RTLD_LAZY) };
        if handle.is_null() {
            return None;
        }
        let is_translocated = symbol(handle, b"SecTranslocateIsTranslocatedURL\0")?;
        let original_for = symbol(handle, b"SecTranslocateCreateOriginalPathForURL\0")?;
        // SAFETY: the two symbols have these signatures (SecTranslocate.h).
        let is_translocated =
            unsafe { std::mem::transmute::<*mut c_void, IsTranslocated>(is_translocated) };
        let original_for =
            unsafe { std::mem::transmute::<*mut c_void, OriginalPath>(original_for) };

        let bytes = exe.as_os_str().as_bytes();
        // SAFETY: CoreFoundation objects created here are released before
        // returning; buffers are sized and owned.
        unsafe {
            let url = CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as isize,
                0,
            );
            if url.is_null() {
                return None;
            }
            let mut translocated: u8 = 0;
            let mut err: CFErrorRef = std::ptr::null_mut();
            let ok = is_translocated(url, &mut translocated, &mut err);
            if !err.is_null() {
                CFRelease(err as CFTypeRef);
            }
            if ok == 0 || translocated == 0 {
                CFRelease(url);
                return None;
            }
            let mut err: CFErrorRef = std::ptr::null_mut();
            let original = original_for(url, &mut err);
            CFRelease(url);
            if !err.is_null() {
                CFRelease(err as CFTypeRef);
            }
            if original.is_null() {
                return None;
            }
            let mut buf = vec![0u8; 4096];
            let got =
                CFURLGetFileSystemRepresentation(original, 1, buf.as_mut_ptr(), buf.len() as isize);
            CFRelease(original);
            if got == 0 {
                return None;
            }
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..end])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inside_an_application_bundle_the_folder_is_the_one_that_holds_it() {
        let d = Path::new("/Users/someone/q21/Q21 Wallet.app/Contents/MacOS");
        assert_eq!(bundle_folder(d), Some(PathBuf::from("/Users/someone/q21")));
        assert_eq!(bundle_folder(Path::new("/Users/someone/q21")), None);
        assert_eq!(
            bundle_folder(Path::new("/x/NotAnApp/Contents/MacOS")),
            None,
            "only a .app bundle"
        );
    }

    #[test]
    fn the_dialog_shows_the_end_of_the_last_launch_only() {
        use std::io::Write;
        let d = std::env::temp_dir().join(format!("q21-launcher-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let p = d.join("wallet.log");
        let _ = std::fs::remove_file(&p);
        {
            let mut f = open_log(&p).unwrap();
            writeln!(f, "old error of an earlier launch").unwrap();
        }
        {
            let mut f = open_log(&p).unwrap();
            for i in 1..=20 {
                writeln!(f, "line {i}\n").unwrap();
            }
        }
        assert_eq!(log_tail(&p, 3), "line 18\nline 19\nline 20");
        assert!(!log_tail(&p, 50).contains("old error"));
        assert_eq!(
            log_tail(&d.join("absent.log"), 3),
            "(the wallet printed nothing)"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod tests_archive {
    use super::ARCHIVE_ENTRIES;

    /// The launcher releases from quarantine what the release ships, and
    /// nothing else: each name it knows is put in the archive by the
    /// release pipeline.
    #[test]
    fn the_archive_entries_are_those_the_release_ships() {
        let workflow = include_str!("../../.github/workflows/release.yml");
        for entry in ARCHIVE_ENTRIES {
            let name = entry.rsplit('/').next().unwrap();
            assert!(
                workflow.contains(name),
                "{entry} is not put in the archive by release.yml"
            );
        }
        assert!(!ARCHIVE_ENTRIES.contains(&"."), "never the whole folder");
    }
}
