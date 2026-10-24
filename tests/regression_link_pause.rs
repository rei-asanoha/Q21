//! A paused process keeps its links (D14).
//!
//! On Linux, a socket read blocked under a receive timeout fails with EINTR
//! when the process resumes from a stop signal, whether or not a handler is
//! installed. The read loop took that error for a dead peer: a wallet paused
//! for a few seconds (Ctrl-Z then `fg`, a debugger, a frozen container) came
//! back with every link cut at once, its payment channels unreachable until
//! the next reconnection.
//!
//! The test stops its own process, so it lives alone in this binary: no other
//! test is paused with it.

#![cfg(unix)]

use q21_core::chain::{genesis_block, Chain};
use q21_core::net::Node;
use q21_core::Network;
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

fn node() -> Node {
    Node::new(NETWORK, Chain::new(NETWORK, genesis_block(NETWORK)))
}

fn wait(cond: impl Fn() -> bool, secs: u64) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}

#[test]
fn a_stop_and_continue_does_not_cut_live_links() {
    let a = node();
    let b = node();
    let addr = b.listen("127.0.0.1:0").expect("listen");
    a.connect(addr).expect("connect");
    assert!(
        wait(
            || a.peer_count_established() == 1 && b.peer_count_established() == 1,
            10
        ),
        "handshake did not complete"
    );
    let before: Vec<u64> = a.peer_list().iter().map(|p| p.id).collect();
    // Let both read loops settle into a blocking read.
    std::thread::sleep(Duration::from_millis(300));

    // Stop this whole process for a second, then resume it, from a helper
    // that outlives the stop.
    let pid = std::process::id();
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("kill -STOP {pid}; sleep 1; kill -CONT {pid}"))
        .status()
        .expect("run the stop/continue helper");
    assert!(status.success());

    // Give a cut link time to show.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(a.peer_count(), 1, "the dialing side lost its link");
    assert_eq!(b.peer_count(), 1, "the listening side lost its link");
    let after: Vec<u64> = a.peer_list().iter().map(|p| p.id).collect();
    assert_eq!(before, after, "the link was replaced, not kept");
}
