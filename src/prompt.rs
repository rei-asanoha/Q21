//! Passphrase entry without echo.
//!
//! # Why this module exists
//!
//! A passphrase typed in the clear ends up in the terminal history, in session
//! logs, on screenshots and in the memory of whoever walks by. Wallet software
//! that displays what is typed has failed before it has even encrypted
//! anything.
//!
//! # What it does, and what it refuses to do
//!
//! It turns off terminal echo for the duration of the entry, then restores it
//! — including when reading fails. On Windows it goes through the console API;
//! on POSIX systems it goes through `stty`, the standard tool, rather than a
//! hand-written declaration of the `termios` structures, whose layout varies
//! from one system to another and where a mistake would leave the terminal
//! unusable.
//!
//! If it cannot turn off echo, it **says so** and lets the user decide.
//! Pretending would be worse than doing nothing.

use std::io::{self, BufRead, Write};

/// Is there a human at the keyboard?
///
/// # Why the question matters
///
/// An application started by double-clicking has no terminal. `read_line`
/// returns an empty line there immediately, and the program understands "the
/// user does not want a passphrase" — when nobody chose anything. A wallet was
/// therefore created **without protection, silently**, with its seed in the
/// clear on disk.
///
/// A choice that was not made is not a choice. Better to refuse and say so.
pub fn is_interactive() -> bool {
    #[cfg(unix)]
    {
        // `isatty(0)`. A single function, declared by hand rather than
        // importing a whole library for one integer.
        unsafe extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        unsafe { isatty(0) == 1 }
    }
    #[cfg(windows)]
    {
        // On Windows, an input handle that is not a console has no console
        // mode: `GetConsoleMode` fails.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
            fn GetConsoleMode(h: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        }
        const STD_INPUT_HANDLE: u32 = -10i32 as u32;
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            GetConsoleMode(h, &mut mode) != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Reads a passphrase from standard input, without displaying it.
///
/// Also returns `false` as the second member if echo could **not** be turned
/// off: the caller must then warn the user.
pub fn read_passphrase(prompt: &str) -> io::Result<(String, bool)> {
    print!("{prompt}");
    io::stdout().flush()?;

    let masked = echo(false);
    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line);
    if masked {
        echo(true);
    }
    println!();
    read?;

    // Only the line ending is removed: a passphrase is perfectly entitled to
    // start or end with a space, and trimming it silently would make the
    // wallet impossible to reopen.
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok((line, masked))
}

/// Asks for the passphrase twice and checks that both entries match.
///
/// A passphrase mistyped at creation makes the wallet permanently
/// unreadable, and the mistake only shows at the first reopening — often
/// months later.
///
/// # A failed confirmation is not an absent passphrase
///
/// The first version returned `None` when the two entries differed —
/// exactly what it returned for an empty passphrase. The caller then created
/// a wallet **without protection**, the seed in the clear on disk, with an
/// on-screen warning that a beginner does not read twice. A typo at the most
/// important moment exposed everything.
///
/// An entry that differs is now reported, then asked again, three times at
/// most; beyond that, we give up with an explicit error. Only an **empty**
/// first entry means "no passphrase".
pub fn read_passphrase_confirmed(prompt: &str) -> io::Result<Option<String>> {
    confirm_with(prompt, read_passphrase)
}

/// The confirmation logic, separated from terminal reading so that it can be
/// tested with scripted entries.
fn confirm_with<L>(prompt: &str, mut read: L) -> io::Result<Option<String>>
where
    L: FnMut(&str) -> io::Result<(String, bool)>,
{
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        let (a, masked) = read(prompt)?;
        if !masked {
            eprintln!("  warning: terminal echo could not be turned off.");
            eprintln!("  What was typed remains visible on screen and in the history.");
        }
        if a.is_empty() {
            return Ok(None);
        }
        let (b, _) = read("Confirm the passphrase: ")?;
        if a == b {
            return Ok(Some(a));
        }
        if attempt < ATTEMPTS {
            eprintln!("  The two entries differ. Try again.");
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "the two passphrase entries never matched: no wallet created",
    ))
}

#[cfg(unix)]
fn echo(on: bool) -> bool {
    // `stty` is the standard POSIX tool. We call it rather than declare
    // `termios` by hand: its memory layout differs between Linux, macOS and
    // the BSDs, and a mistake there would leave the terminal mute after the
    // program exits.
    let arg = if on { "echo" } else { "-echo" };
    std::process::Command::new("stty")
        .arg(arg)
        // `stty` acts on its controlling terminal: it must be given ours.
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn echo(on: bool) -> bool {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
        fn GetConsoleMode(h: *mut core::ffi::c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(h: *mut core::ffi::c_void, mode: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    // SAFETY: we read then rewrite the mode of a valid console handle; no
    // memory is allocated or transferred.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        let new_mode = if on {
            mode | ENABLE_ECHO_INPUT
        } else {
            mode & !ENABLE_ECHO_INPUT
        };
        SetConsoleMode(h, new_mode) != 0
    }
}

#[cfg(not(any(unix, windows)))]
fn echo(_on: bool) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sequence of scripted answers, in the order the terminal would give
    /// them.
    fn scenario(answers: &[&str]) -> impl FnMut(&str) -> io::Result<(String, bool)> {
        let queue: Vec<String> = answers.iter().map(|s| s.to_string()).collect();
        let mut i = 0;
        move |_prompt| {
            let r = queue.get(i).cloned().unwrap_or_default();
            i += 1;
            Ok((r, true))
        }
    }

    #[test]
    fn two_identical_entries_give_the_passphrase() {
        let r = confirm_with("? ", scenario(&["abc", "abc"])).unwrap();
        assert_eq!(r, Some("abc".to_string()));
    }

    #[test]
    fn an_empty_first_entry_means_no_passphrase() {
        let r = confirm_with("? ", scenario(&[""])).unwrap();
        assert_eq!(r, None);
    }

    /// The defect this test pins down: a confirmation that differs must
    /// **never** be mistaken for "no passphrase".
    #[test]
    fn a_differing_confirmation_never_counts_as_no_passphrase() {
        // Three failures in a row: an error, not `Ok(None)`.
        let r = confirm_with("? ", scenario(&["a", "b", "a", "b", "a", "b"]));
        assert!(r.is_err(), "three mismatches must be an error");

        // One failure then a success: the confirmed passphrase is returned.
        let r = confirm_with("? ", scenario(&["a", "b", "good", "good"])).unwrap();
        assert_eq!(r, Some("good".to_string()));
    }

    /// An empty passphrase as confirmation of a non-empty one is a mismatch,
    /// not a withdrawal.
    #[test]
    fn an_empty_confirmation_is_a_mismatch() {
        let r = confirm_with("? ", scenario(&["a", "", "a", "", "a", ""]));
        assert!(r.is_err());
    }
}
