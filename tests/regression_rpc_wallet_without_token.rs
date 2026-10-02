//! REGRESSION — the wallet methods do not open without a token.
//!
//! `q21 node --rpc 127.0.0.1:PORT --rpc-wallet` started without a token: the
//! methods that move funds answered without authentication to any program on
//! the machine. The refusal must come at startup, before the folder is even
//! read — and the message must say what to do.

use std::process::Command;

fn q21() -> &'static str {
    env!("CARGO_BIN_EXE_q21")
}

fn folder(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("q21-rpcw-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn rpc_wallet_without_token_is_refused_at_startup() {
    let d = folder("without");
    let output = Command::new(q21())
        .args([
            "--datadir",
            d.to_str().unwrap(),
            "node",
            "--rpc",
            "127.0.0.1:0",
            "--rpc-wallet",
            "--seconds",
            "1",
        ])
        .output()
        .expect("launch");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the node started without a token");
    assert!(error.contains("--rpc-wallet without a token"), "{error}");
    assert!(error.contains("--rpc-token-file"), "{error}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn rpc_wallet_with_a_token_too_short_is_refused() {
    let d = folder("short");
    let output = Command::new(q21())
        .args([
            "--datadir",
            d.to_str().unwrap(),
            "node",
            "--rpc",
            "127.0.0.1:0",
            "--rpc-wallet",
            "--rpc-token",
            "secret",
            "--seconds",
            "1",
        ])
        .output()
        .expect("launch");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least 16"));
    let _ = std::fs::remove_dir_all(&d);
}
