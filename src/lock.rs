//! Directory lock: only one q21 at a time on a data directory.
//!
//! # The defect this module fixes
//!
//! Nothing stopped two processes from opening the same directory. It is the
//! most ordinary case there is: the wallet runs in its window, and one starts
//! `q21 mine` in another because one wants to confirm a transaction. Or the
//! double-click file gets double-clicked twice.
//!
//! Three files lose their consistency:
//!
//! - **`wallet.dat` and `wallet.seq`.** Writing the wallet reads the serial
//!   number, seals the content — six hundred thousand iterations of PBKDF2,
//!   that is several hundred milliseconds — then writes both files. Two
//!   interleaved processes leave a `wallet.seq` newer than the `wallet.dat` it
//!   goes with. At the next startup, the anti-replay protection does what it
//!   is asked to do: it refuses to open the wallet, announcing a restore from
//!   an old backup. The wallet is intact, but the user reads that they may
//!   have revealed their keys.
//! - **`blocks.dat` and its index.** Two processes that append blocks to the
//!   same file each write at the position they believe is free.
//! - **`mempool.dat` and the state snapshot**, which are written at shutdown.
//!
//! This is not a hypothesis: the defect was hit while reproducing an ordinary
//! scenario, on a directory that a second process had opened while the first
//! one was finishing its writes.
//!
//! # How
//!
//! An advisory lock placed by the operating system on a file in the
//! directory. `flock` on POSIX systems, `LockFileEx` on Windows — the same two
//! calls the library we could have imported would make.
//!
//! The important point is that **the system releases it by itself** when the
//! process dies, however it dies: clean exit, panic, `kill -9`, power cut. A
//! hand-made lock — a `.lock` file holding a process number — would leave a
//! ghost lock after every abrupt stop, and the user would then have to be
//! taught to delete it. That would trade a rare failure for a frequent one.
//!
//! # What remains true
//!
//! The lock is **advisory**: it does not stop a program that ignores it from
//! writing to these files. It stops q21 from stepping on its own toes, which
//! is the real case.
//!
//! On a network file system, `flock` can lie. A data directory on a network
//! share is already a bad idea for other reasons; we do not claim to make up
//! for it here.

use std::fs::File;
use std::path::Path;

/// Lock held on a data directory.
///
/// As long as this value exists, no other q21 process will open the same
/// directory. Dropping it — or the death of the process — releases it.
pub struct DataDirLock {
    // The descriptor carries the lock: closing it is what releases it. It is
    // never read or written.
    _file: File,
}

/// Name of the marker file. It stays empty: only its descriptor matters.
pub const FILE_NAME: &str = ".lock";

/// Takes an exclusive advisory lock on an existing file, without waiting.
///
/// `Ok(None)` when another process holds it. Used by the upgrade of a 0.3.x
/// data directory to make sure no older q21 still runs on it: see
/// [`crate::legacy`].
pub fn try_lock_file(path: &Path) -> std::io::Result<Option<DataDirLock>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    if try_lock(&file) {
        Ok(Some(DataDirLock { _file: file }))
    } else {
        Ok(None)
    }
}

/// Takes the directory lock.
///
/// Returns a readable error if another process already holds it. The caller
/// must keep the returned value alive for as long as it touches the
/// directory.
pub fn acquire(datadir: &Path) -> Result<DataDirLock, String> {
    if let Err(e) = std::fs::create_dir_all(datadir) {
        return Err(format!(
            "data directory not accessible ({}): {e}",
            datadir.display()
        ));
    }
    let path = datadir.join(FILE_NAME);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("cannot open the lock file ({}): {e}", path.display()))?;

    if try_lock(&file) {
        Ok(DataDirLock { _file: file })
    } else {
        Err(format!(
            "another q21 is already using this data directory.\n\n  \
             Directory: {}\n\n  \
             Two programs that write the same wallet and the same block file\n  \
             damage both. Close the other window — the \"Close the wallet\"\n  \
             button on the Info tab, or the window's close button — then start\n  \
             this one again.\n\n  \
             To run a second node at the same time, give it another\n  \
             directory:\n\n      \
             q21 --datadir q21-data-2 wallet",
            datadir.display()
        ))
    }
}

#[cfg(unix)]
fn try_lock(file: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    // SAFETY: the descriptor is valid for the duration of the call, and
    // `flock` does nothing other than place the lock.
    unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
}

#[cfg(windows)]
fn try_lock(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut core::ffi::c_void,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LockFileEx(
            file: *mut core::ffi::c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;

    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: core::ptr::null_mut(),
    };
    // SAFETY: the handle is valid for the duration of the call, and the
    // overlapped structure lives until it returns. The lock covers the whole
    // file, and `LOCKFILE_FAIL_IMMEDIATELY` forbids any waiting.
    unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        ) != 0
    }
}

#[cfg(not(any(unix, windows)))]
fn try_lock(_file: &File) -> bool {
    // No known mechanism: we do not invent a lock that locks nothing. The
    // program stays usable, without this protection.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("q21-lock-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The lock can be taken on a free directory.
    #[test]
    fn a_free_directory_can_be_locked() {
        let d = test_dir("free");
        let v = acquire(&d).expect("lock refused on a free directory");
        drop(v);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// It can be taken again after being released.
    ///
    /// This is what makes a clean shutdown leave nothing behind.
    #[test]
    fn a_released_lock_can_be_taken_again() {
        let d = test_dir("released");
        {
            let _v = acquire(&d).expect("first lock");
        }
        let _v = acquire(&d).expect("the lock was not released");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The directory is created if it does not exist.
    ///
    /// The lock is taken before everything else: it cannot require a
    /// directory that the command has not yet had a chance to create.
    #[test]
    fn a_missing_directory_is_created() {
        let d = std::env::temp_dir().join("q21-lock-missing/sub/dir");
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("q21-lock-missing"));
        let _v = acquire(&d).expect("lock refused on a directory to be created");
        assert!(d.join(FILE_NAME).exists());
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("q21-lock-missing"));
    }

    /// A second process is refused.
    ///
    /// This cannot be tested within the same process: `flock` is granted per
    /// open descriptor, but most systems grant it again to the same process.
    /// So we start a real second process — the test itself, with a variable
    /// that tells it what to do.
    #[test]
    fn a_second_process_is_refused() {
        const MARKER: &str = "Q21_LOCK_TEST";
        if let Ok(path) = std::env::var(MARKER) {
            // We are the second process.
            let code = if acquire(std::path::Path::new(&path)).is_ok() {
                0 // the lock was granted: that is the failure
            } else {
                42 // refused, as it should be
            };
            std::process::exit(code);
        }

        let d = test_dir("concurrent");
        let _v = acquire(&d).expect("first lock");

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("lock::tests::a_second_process_is_refused")
            .arg("--exact")
            .arg("--nocapture")
            .env(MARKER, &d)
            .output()
            .expect("second process");

        assert_eq!(
            output.status.code(),
            Some(42),
            "the second process obtained the lock: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
