//! REGRESSION (D11) — a restarted node announces the channel capability to the
//! peers it dials at startup.
//!
//! The channel manager was installed only after the node had started listening
//! and dialing. The `Version` of every startup connection therefore went out
//! without the capability or the stable channel node id: the peer filed the
//! restarted node as not speaking channels and never sent it a channel message,
//! and the restarted node, its handshake already complete, never offered the
//! reestablish of its reloaded channels. Every reloaded channel stayed unbound —
//! "peer is not connected" — until a later reconnection, if any.
//!
//! The test starts two real wallet nodes on regtest. The second dials the first
//! at startup; the first must see it as channel-capable, with a node id.

#![cfg(feature = "mldsa")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
    let p = std::env::temp_dir().join(format!("q21-chan-startup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn private_file(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

const TOKEN: &str = "channel-startup-test-token";

/// Calls one RPC method and returns the raw response body, or `None` if the
/// node does not answer yet.
fn rpc(port: u16, method: &str) -> Option<String> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        s,
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Authorization: Bearer {TOKEN}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .ok()?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok()?;
    let at = resp.find("\r\n\r\n")?;
    Some(resp[at + 4..].to_string())
}

/// Creates a regtest wallet in `d`, protected by `passphrase`.
fn init(d: &Path, passphrase: &Path) {
    let out = Command::new(q21())
        .arg("--datadir")
        .arg(d)
        .arg("--passphrase-file")
        .arg(passphrase)
        .args(["init", "regtest"])
        .stdin(Stdio::null())
        .output()
        .expect("starting q21 init");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn launch(d: &Path, passphrase: &Path, token: &Path, args: &[String]) -> NodeProcess {
    NodeProcess(
        Command::new(q21())
            .arg("--datadir")
            .arg(d)
            .arg("--passphrase-file")
            .arg(passphrase)
            .args([
                "node",
                "--network",
                "regtest",
                "--no-bootstrap",
                "--rpc-wallet",
            ])
            .arg("--rpc-token-file")
            .arg(token)
            .args(args)
            .args(["--seconds", "90"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("launching the node"),
    )
}

/// The `getpeers` entries of a node, one JSON object text per peer.
fn peer_entries(port: u16) -> Vec<String> {
    let Some(body) = rpc(port, "getpeers") else {
        return Vec::new();
    };
    // Each peer is a flat object: split at its closing brace.
    body.split('}')
        .filter(|s| s.contains("\"address\""))
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn a_node_dialing_at_startup_announces_the_channel_capability() {
    let base = dir("pair");
    let (dx, dy) = (base.join("x"), base.join("y"));
    std::fs::create_dir_all(&dx).unwrap();
    std::fs::create_dir_all(&dy).unwrap();
    let passphrase = base.join("passphrase.txt");
    private_file(&passphrase, "channel startup passphrase\n");
    let token = base.join("token.txt");
    private_file(&token, TOKEN);
    init(&dx, &passphrase);
    init(&dy, &passphrase);

    let (p2p_x, rpc_x, rpc_y) = (free_port(), free_port(), free_port());
    let _x = launch(
        &dx,
        &passphrase,
        &token,
        &[
            "--listen".into(),
            format!("127.0.0.1:{p2p_x}"),
            "--rpc".into(),
            format!("127.0.0.1:{rpc_x}"),
        ],
    );
    let start = Instant::now();
    while rpc(rpc_x, "getinfo").is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the first node does not start"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The second node dials the first from its startup path, exactly as a
    // restarted wallet redials its channel peer.
    let _y = launch(
        &dy,
        &passphrase,
        &token,
        &[
            "--connect".into(),
            format!("127.0.0.1:{p2p_x}"),
            "--rpc".into(),
            format!("127.0.0.1:{rpc_y}"),
        ],
    );
    let start = Instant::now();
    let mut seen = Vec::new();
    while start.elapsed() < Duration::from_secs(60) {
        seen = peer_entries(rpc_x);
        if seen
            .iter()
            .any(|p| p.contains("\"handshake_complete\":true"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let inbound: Vec<&String> = seen
        .iter()
        .filter(|p| p.contains("\"handshake_complete\":true"))
        .collect();
    assert!(
        !inbound.is_empty(),
        "the second node never connected: {seen:?}"
    );
    assert!(
        inbound
            .iter()
            .any(|p| p.contains("\"supports_channels\":true")),
        "the dialing node did not announce the channel capability: {inbound:?}"
    );
    assert!(
        inbound
            .iter()
            .any(|p| !p.contains("\"channel_id\":\"\"") && p.contains("\"channel_id\":\"")),
        "the dialing node did not announce its channel node id: {inbound:?}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// A testnet wallet node runs the channel manager from its start, before the
/// activation height of policy outputs: it lists its channels, and refuses
/// to open one until the tip reaches that height.
#[test]
fn a_testnet_wallet_node_runs_channels_and_waits_for_the_activation() {
    let base = dir("testnet");
    let d = base.join("t");
    std::fs::create_dir_all(&d).unwrap();
    let passphrase = base.join("passphrase.txt");
    private_file(&passphrase, "channel startup passphrase\n");
    let token = base.join("token.txt");
    private_file(&token, TOKEN);
    let out = Command::new(q21())
        .arg("--datadir")
        .arg(&d)
        .arg("--passphrase-file")
        .arg(&passphrase)
        .args(["init", "testnet"])
        .stdin(Stdio::null())
        .output()
        .expect("starting q21 init");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let port = free_port();
    let _n = NodeProcess(
        Command::new(q21())
            .arg("--datadir")
            .arg(&d)
            .arg("--passphrase-file")
            .arg(&passphrase)
            .args([
                "node",
                "--network",
                "testnet",
                "--no-bootstrap",
                "--rpc-wallet",
            ])
            .arg("--rpc-token-file")
            .arg(&token)
            .args(["--rpc", &format!("127.0.0.1:{port}"), "--seconds", "90"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("launching the node"),
    );
    let start = Instant::now();
    while rpc(port, "getinfo").is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the node does not start"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let list = rpc(port, "channellist").unwrap();
    assert!(list.contains("\"result\":[]"), "channellist: {list}");
    let status = rpc(port, "channelstatus").unwrap();
    assert!(status.contains("\"active\":false"), "{status}");
    assert!(
        status.contains(&format!(
            "\"activation_height\":{}",
            q21_core::consensus::POLICY_ACTIVATION_TESTNET
        )),
        "{status}"
    );
    let open = rpc(port, "channelopen").unwrap();
    assert!(
        open.contains("payment channels are not active on this network yet: they open at block"),
        "channelopen before the activation: {open}"
    );
}
