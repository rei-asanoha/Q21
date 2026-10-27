//! Two real wallet nodes verify each other by words, end to end.
//!
//! The second node dials the first; their channel session proves each one's
//! identity key. The first adds the second as a contact by its connection,
//! starts a verification, and both screens — the `verifications` call of each
//! node — must show the same four words. Both holders confirm, and each
//! contact book holds the other, verified. A mismatch then refuses any new
//! verification on that connection.

#![cfg(feature = "mldsa")]

use q21_core::json::{parse, Json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn q21() -> &'static str {
    env!("CARGO_BIN_EXE_q21")
}

struct NodeProcess(Child);

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("q21-contacts-{name}-{}", std::process::id()));
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

const TOKEN: &str = "contact-verification-test-token";

/// Calls `method` with `params` (a JSON object text); the parsed response,
/// or `None` while the node does not answer.
fn rpc(port: u16, method: &str, params: &str) -> Option<Json> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
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
    parse(&resp[at + 4..]).ok()
}

fn result(port: u16, method: &str, params: &str) -> Json {
    let r = rpc(port, method, params).expect("the node answers");
    assert!(r.get("error").is_none(), "{method}: {}", r.encode());
    r.get("result").cloned().expect("result")
}

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
        "{}",
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
            .args(["--seconds", "120"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("launching the node"),
    )
}

fn wait<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn list(j: &Json) -> Vec<Json> {
    match j {
        Json::Array(v) => v.clone(),
        other => panic!("not a list: {other:?}"),
    }
}

fn str_of(j: &Json, k: &str) -> String {
    j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// The connection id, on `port`'s node, of the peer holding a channel session.
fn session_peer(port: u16) -> u64 {
    wait("a channel session", 60, || {
        let peers = rpc(port, "getpeers", "{}")?
            .get("result")?
            .get("peers")?
            .clone();
        list(&peers)
            .into_iter()
            .find(|p| !str_of(p, "channel_session").is_empty())
            .and_then(|p| p.get("id").and_then(|v| v.as_u64()))
    })
}

/// The ready words of the only verification of `port`'s node, in `lang`.
fn ready_words(port: u16, lang: &str) -> (u64, Vec<String>) {
    wait("ready words", 30, || {
        let v = list(
            &rpc(port, "verifications", &format!(r#"{{"lang":"{lang}"}}"#))?
                .get("result")?
                .clone(),
        );
        let r = v.into_iter().find(|x| str_of(x, "status") == "ready")?;
        let words = list(r.get("words")?)
            .iter()
            .filter_map(|w| w.as_str().map(String::from))
            .collect();
        Some((r.get("connection")?.as_u64()?, words))
    })
}

#[test]
fn two_wallets_read_the_same_words_and_verify_each_other() {
    let base = dir("pair");
    let (dx, dy) = (base.join("x"), base.join("y"));
    std::fs::create_dir_all(&dx).unwrap();
    std::fs::create_dir_all(&dy).unwrap();
    let passphrase = base.join("passphrase.txt");
    private_file(&passphrase, "contact verification passphrase\n");
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
    wait("the first node", 60, || rpc(rpc_x, "getinfo", "{}"));
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
    let peer_on_x = session_peer(rpc_x);
    let peer_on_y = session_peer(rpc_y);

    // X adds Y by the key its session proved, then asks for six words.
    let y_id = result(rpc_y, "channelidentity", "{}");
    let added = result(
        rpc_x,
        "contactadd",
        &format!(r#"{{"label":"Yann","peer":{peer_on_x}}}"#),
    );
    assert_eq!(
        str_of(&added, "owner_address"),
        str_of(&y_id, "identity_address")
    );
    assert_eq!(added.get("verified"), Some(&Json::Bool(false)));
    assert_eq!(added.get("connected"), Some(&Json::Bool(true)));
    let owner = str_of(&added, "owner");
    // The peer list names the same identity, for the page to show the
    // contact behind the peer.
    let peers = result(rpc_x, "getpeers", "{}");
    let p = list(peers.get("peers").unwrap())
        .into_iter()
        .find(|p| p.get("id").and_then(|v| v.as_u64()) == Some(peer_on_x))
        .expect("the peer");
    assert_eq!(str_of(&p, "channel_owner"), owner);
    result(
        rpc_x,
        "contactverify",
        &format!(r#"{{"owner":"{owner}","words":6}}"#),
    );

    // Both screens, the same six words: in French on both, and the same
    // indices read in English on one side give the English list's words.
    let (cx, wx) = ready_words(rpc_x, "fr");
    let (cy, wy) = ready_words(rpc_y, "fr");
    assert_eq!(cx, peer_on_x);
    assert_eq!(cy, peer_on_y);
    assert_eq!(wx.len(), 6);
    assert_eq!(wx, wy, "the two screens differ");
    let (_, wy_en) = ready_words(rpc_y, "en");
    assert_ne!(wy_en, wy);

    // Both holders confirm. Y did not know X yet: it names it.
    result(
        rpc_x,
        "contactconfirm",
        &format!(r#"{{"connection":{cx},"matched":true}}"#),
    );
    let on_y = result(
        rpc_y,
        "contactconfirm",
        &format!(r#"{{"connection":{cy},"matched":true,"label":"Xavier"}}"#),
    );
    assert_eq!(on_y.get("verified"), Some(&Json::Bool(true)));
    let book_x = list(&result(rpc_x, "contactlist", "{}"));
    assert_eq!(book_x.len(), 1);
    assert_eq!(
        book_x[0].get("verified_words").and_then(|v| v.as_u64()),
        Some(6)
    );
    let book_y = list(&result(rpc_y, "contactlist", "{}"));
    assert_eq!(str_of(&book_y[0], "label"), "Xavier");
    let x_id = result(rpc_x, "channelidentity", "{}");
    assert_eq!(
        str_of(&book_y[0], "owner_address"),
        str_of(&x_id, "identity_address")
    );

    // A second round, which X's holder declares different: no third one on
    // this connection.
    result(rpc_x, "contactverify", &format!(r#"{{"owner":"{owner}"}}"#));
    let (cx, w4) = ready_words(rpc_x, "en");
    assert_eq!(w4.len(), 4);
    result(
        rpc_x,
        "contactconfirm",
        &format!(r#"{{"connection":{cx},"matched":false}}"#),
    );
    let refused = rpc(rpc_x, "contactverify", &format!(r#"{{"owner":"{owner}"}}"#)).unwrap();
    assert!(
        str_of(refused.get("error").unwrap(), "message").contains("did not match"),
        "{}",
        refused.encode()
    );
    let _ = std::fs::remove_dir_all(&base);
}
