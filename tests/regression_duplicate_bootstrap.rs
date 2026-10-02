//! REGRESSION — the same bootstrap node written twice is dialed only once.
//!
//! The shipped bootstrap file gives the bootstrap node under its name AND
//! under its numeric address, on purpose: a domain name can expire. At
//! startup, duplicates were removed by comparing the text of the lines, not
//! the address they designate. Both lines survived, and each node opened
//! **two** connections to the same bootstrap node.
//!
//! The bootstrap node, for its part, only gives four slots per address group
//! — and a whole household goes out to the internet through the same address.
//! Two devices in the house therefore filled the four slots; the third was
//! refused without a word, and its wallet stayed "Waiting for a computer to
//! ask for the chain" forever. Observed at a user's home: four connections,
//! all from the same address, in pairs of consecutive ports.
//!
//! The test starts two real nodes: a bootstrap node, and a node that gets it
//! under two different spellings. The bootstrap node must count a single
//! peer.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn q21() -> &'static str {
    env!("CARGO_BIN_EXE_q21")
}

/// A node process, stopped whatever happens to the test.
struct NodeProcess(Child);

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "q21-duplicate-bootstrap-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The number of peers the node reports, or `None` if it does not answer.
fn peers(rpc: u16) -> Option<u64> {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", rpc)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    write!(
        s,
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{rpc}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok()?;
    let i = resp.find("\"peers\"")? + "\"peers\"".len();
    let rest = resp[i..].trim_start_matches(|c: char| c == ':' || c.is_whitespace());
    let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    n.parse().ok()
}

fn launch(args: &[&str]) -> NodeProcess {
    NodeProcess(
        Command::new(q21())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("launching the node"),
    )
}

#[test]
fn the_same_bootstrap_node_written_twice_is_dialed_only_once() {
    let dir_a = dir("bootstrap");
    let dir_b = dir("client");
    let p2p = free_port();
    let rpc_a = free_port();
    let rpc_b = free_port();

    let _a = launch(&[
        "--datadir",
        dir_a.to_str().unwrap(),
        "node",
        "--network",
        "regtest",
        "--listen",
        &format!("127.0.0.1:{p2p}"),
        "--no-bootstrap",
        "--rpc",
        &format!("127.0.0.1:{rpc_a}"),
        "--seconds",
        "60",
    ]);
    let start = Instant::now();
    while peers(rpc_a).is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the bootstrap node does not start"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // The same bootstrap node, under its name and under its address: exactly
    // the shape of the bootstrap file shipped with the program.
    let _b = launch(&[
        "--datadir",
        dir_b.to_str().unwrap(),
        "node",
        "--network",
        "regtest",
        "--bootstrap",
        &format!("localhost:{p2p}"),
        "--bootstrap",
        &format!("127.0.0.1:{p2p}"),
        "--rpc",
        &format!("127.0.0.1:{rpc_b}"),
        "--seconds",
        "60",
    ]);

    // We wait for the first connection, then keep watching: the second, when
    // the defect is present, arrives right after the first.
    let start = Instant::now();
    let mut seen = 0u64;
    while seen == 0 && start.elapsed() < Duration::from_secs(30) {
        seen = peers(rpc_a).unwrap_or(0);
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        seen >= 1,
        "the client never connected to the bootstrap node"
    );
    let observation = Instant::now();
    while observation.elapsed() < Duration::from_secs(5) {
        seen = seen.max(peers(rpc_a).unwrap_or(0));
        std::thread::sleep(Duration::from_millis(200));
    }

    assert_eq!(
        seen, 1,
        "the bootstrap node counts {seen} connections from a single client that knows it \
         under two spellings: each duplicate takes a slot from a whole household"
    );

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
