//! Clean shutdown on Ctrl-C.
//!
//! # The defect this module fixes
//!
//! A Q21 node writes several things when it stops: the state snapshot of the
//! monetary state, the peer address book, the wallet, and, recently, the
//! mempool of pending transactions.
//!
//! None of this was happening. The only planned exit was the expiry of
//! `--seconds`, used by the tests; **a Ctrl-C killed the process on the
//! spot**, and everything that should have been written was not.
//!
//! In other words, the tested path was not the path taken. An early user sent
//! a transaction and then stopped the wallet with Ctrl-C to start mining: the
//! transaction was gone. At first this was blamed on the mempool not being
//! persisted — it indeed was not — then it turned out that even once that
//! persistence was written, the mempool would never have been saved, since
//! the shutdown code was never reached.
//!
//! # How
//!
//! The handler does only one thing: raise a flag. It is the only operation a
//! signal handler is allowed to perform — allocating, writing a file or taking
//! a lock from a handler is a sure way to block a process forever. The main
//! loop sees the flag on its next turn, exits, and does the work in a normal
//! context.
//!
//! Two systems, two mechanisms, no dependency: `signal` on POSIX systems,
//! `SetConsoleCtrlHandler` on Windows. These are exactly the functions the
//! library we could have imported would call.
//!
//! # What remains true
//!
//! A second Ctrl-C, a power cut or a `kill -9` leaves no chance: that is why
//! nothing vital depends on this write. The block file is written **as blocks
//! come in**, and the state snapshot and the mempool are only time-savers —
//! losing them costs a slower startup and transactions to resend, never
//! funds.

use std::sync::atomic::{AtomicBool, Ordering};

static REQUESTED: AtomicBool = AtomicBool::new(false);

/// Has the user asked for a shutdown?
pub fn requested() -> bool {
    REQUESTED.load(Ordering::Relaxed)
}

/// Raises the flag. Exposed for the tests and for a deliberate shutdown.
pub fn request_shutdown() {
    REQUESTED.store(true, Ordering::Relaxed);
}

/// Installs the handler. To be called once, at startup.
///
/// Returns `false` if the system refused: the program stays usable, it will
/// simply lose what it had to write in case of Ctrl-C. We do not stop because
/// of it — a node that refuses to start because it does not know how to die
/// well would be a bad trade.
pub fn install() -> bool {
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn signal(sig: i32, handler: usize) -> usize;
        }
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        const SIG_ERR: usize = usize::MAX;

        extern "C" fn handler(_sig: i32) {
            // One atomic write, and nothing else. Everything else happens in
            // the main loop, where allocating and blocking are allowed.
            REQUESTED.store(true, Ordering::Relaxed);
        }

        // SAFETY: we install a handler that calls nothing but an atomic
        // store. `signal` returns the previous handler, or SIG_ERR.
        unsafe {
            let h = handler as *const () as usize;
            signal(SIGINT, h) != SIG_ERR && signal(SIGTERM, h) != SIG_ERR
        }
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn SetConsoleCtrlHandler(handler: Option<ConsoleHandler>, add: i32) -> i32;
        }
        type ConsoleHandler = unsafe extern "system" fn(u32) -> i32;

        // Ctrl-C, Ctrl-Break, window close, logoff, shutdown. The last three
        // leave a short delay — a few seconds — before the system settles
        // the matter.
        const CTRL_C_EVENT: u32 = 0;
        const CTRL_BREAK_EVENT: u32 = 1;
        const CTRL_CLOSE_EVENT: u32 = 2;
        const CTRL_LOGOFF_EVENT: u32 = 5;
        const CTRL_SHUTDOWN_EVENT: u32 = 6;

        unsafe extern "system" fn handler(event: u32) -> i32 {
            match event {
                CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
                | CTRL_SHUTDOWN_EVENT => {
                    REQUESTED.store(true, Ordering::Relaxed);
                    // Windows calls this handler on a thread of its own and
                    // kills the process as soon as it returns on a window
                    // close. So we wait until the main loop has finished
                    // writing — a few seconds at most, which the system
                    // tolerates.
                    for _ in 0..100 {
                        if !REQUESTED.load(Ordering::Relaxed) {
                            break; // the loop has finished and lowered the flag
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    1 // event handled
                }
                _ => 0,
            }
        }

        // SAFETY: we register a handler that is valid for the lifetime of the
        // process.
        unsafe { SetConsoleCtrlHandler(Some(handler), 1) != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Signals that the shutdown is complete.
///
/// On Windows, this releases the console handler, which waits for the
/// writing work to be finished before letting the system kill the process.
/// Elsewhere, it has no effect.
pub fn shutdown_done() {
    REQUESTED.store(false, Ordering::Relaxed);
}

/// Mutual exclusion lock between the tests that touch the flag.
///
/// The flag is global to the process, and the test runner runs tests in
/// parallel: two tests that handle it at the same time would steal each
/// other's state. Any test that calls `request_shutdown` or `shutdown_done`
/// must take this lock first.
#[cfg(test)]
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    /// The flag goes up and comes back down.
    ///
    /// We cannot send a real signal to ourselves in a test without risking
    /// interrupting the test runner: so we check the mechanism, not the
    /// system.
    #[test]
    fn the_flag_goes_up_and_down() {
        let _v = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        shutdown_done();
        assert!(!requested());
        request_shutdown();
        assert!(requested());
        shutdown_done();
        assert!(!requested());
    }

    /// Installing must never make a startup fail.
    #[test]
    fn install_does_not_panic() {
        let _v = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The result depends on the system and on how the tests are run; what
        // matters is that no path panics.
        let _ = install();
        shutdown_done();
    }
}
