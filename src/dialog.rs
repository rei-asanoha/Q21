//! A dialog box, for a program that runs without a window.
//!
//! The wallet started by `Q21 Wallet.exe` or `Q21 Wallet.app` has no console:
//! what it prints goes to `q21-data/wallet.log`, which nobody reads unless
//! told to. The few messages a person must see — the wallet could not start,
//! the browser could not be opened — are shown here instead: a message box
//! on Windows, an AppleScript dialog on macOS. Elsewhere there is always a
//! terminal, and the text goes to the error output.

/// Shows `text` in a dialog box titled "Q21 Wallet", and waits for the
/// person to close it.
#[cfg(windows)]
pub fn alert(text: &str) {
    use std::ffi::c_void;
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    // Warning icon, and in front of the browser: the program that shows it
    // has no window of its own to be in front of.
    const MB_ICONWARNING_SETFOREGROUND_TOPMOST: u32 = 0x0000_0030 | 0x0001_0000 | 0x0004_0000;
    let body = wide(text);
    let title = wide("Q21 Wallet");
    // SAFETY: both strings are NUL-terminated UTF-16 buffers that outlive the
    // call; a null owner window is allowed.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            body.as_ptr(),
            title.as_ptr(),
            MB_ICONWARNING_SETFOREGROUND_TOPMOST,
        );
    }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Shows `text` in a dialog box titled "Q21 Wallet", and waits for the
/// person to close it.
#[cfg(target_os = "macos")]
pub fn alert(text: &str) {
    let _ = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(applescript(text))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Shows `text` on the error output: outside Windows and macOS, the wallet
/// always runs in a terminal.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn alert(text: &str) {
    eprintln!("{text}");
}

/// The AppleScript that displays `text`: backslashes and quotes escaped, so
/// that no text — an error message, a path — can end the string early.
pub fn applescript(text: &str) -> String {
    let quoted = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "display dialog \"{quoted}\" with title \"Q21 Wallet\" buttons {{\"OK\"}} \
         default button \"OK\" with icon caution"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_cannot_end_the_applescript_string() {
        let s = applescript("a \"quoted\" path C:\\x\nnext");
        assert!(s.starts_with("display dialog \"a \\\"quoted\\\" path C:\\\\x\nnext\""));
        assert_eq!(s.matches("\" with title").count(), 1);
    }
}
