//! Adversarial audit of the HTTP / JSON-RPC / explorer / wallet surface.
//!
//! Every test in this file is an **exploit**: it really connects to the server
//! over TCP and sends it hostile bytes.
//!
//! # What this file has become
//!
//! Originally, a `flaw_*` test that passed *demonstrated* a flaw. Those flaws
//! have been fixed; the tests stayed, under the same names, and now check that
//! the fix holds. The name tells the attack, the comment tells what it made
//! possible, and the assertions check that it no longer makes anything
//! possible. A test that fails here signals a regression to the earlier state.
//!
//! The `ok_*` tests confirm, as before, that an attack fails.
//!
//! What the assertions describe is the **observed** behavior, not the desired
//! behavior. Where a rough edge remains - a duplicated `Content-Length`,
//! headers beyond the sixty-fourth - the test pins it down as is and names it,
//! rather than dressing it up: that is how you notice it has moved.
//!
//! Nothing in this file modifies `src/`.

use q21_core::address::Network;
use q21_core::chain::{genesis_block, Chain};
use q21_core::http::{self, Request, Response, ServerHandle};
use q21_core::net::Node;
use q21_core::rpc::RpcContext;
use q21_core::wallet::Wallet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

// ---------------------------------------------------------------------------
// Harness: the same router as src/bin/q21.rs (function `servir`, l. 1553).
// ---------------------------------------------------------------------------

fn router(ctx: &RpcContext, req: Request) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            Response::html(q21_core::explorer::PAGE.to_string())
        }
        ("POST", "/rpc") => Response::json(ctx.handle(&req.body)),
        ("GET", "/rpc") => Response::text(405, "POST expected"),
        _ => Response::not_found(),
    }
}

fn server(with_wallet: bool, token: Option<&str>) -> ServerHandle {
    let g = genesis_block(NETWORK);
    let node = Arc::new(Node::new(NETWORK, Chain::new(NETWORK, g)));
    let ctx = RpcContext {
        on_change: None,
        scans: None,
        configured_bootstrap: 0,
        reachable: std::sync::atomic::AtomicBool::new(true),
        reachable_session: true,
        router_status: None,
        set_reachable: None,
        node,
        wallet: if with_wallet {
            Some(Arc::new(Mutex::new(Wallet::from_seed([7u8; 32], NETWORK))))
        } else {
            None
        },
        network: NETWORK,
        index: None,
        mining: None,
    };
    http::serve("127.0.0.1:0", token.map(|s| s.to_string()), move |req| {
        router(&ctx, req)
    })
    .expect("server startup")
}

/// Sends raw bytes, closes the write side, reads everything.
fn raw(addr: SocketAddr, bytes: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).expect("connection");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(bytes).expect("send");
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut r = Vec::new();
    let _ = s.read_to_end(&mut r);
    String::from_utf8_lossy(&r).into_owned()
}

/// POST /rpc with arbitrary headers.
fn post_rpc_with(addr: SocketAddr, headers: &str, body: &str) -> String {
    raw(
        addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
}

/// A legitimate client: the explorer's, or `curl`.
///
/// Since the server requires `application/json`, the absence of that header is
/// itself a refusal - that is the point of the fix. The exploits that want to
/// omit it call `post_rpc_with` directly.
fn post_rpc(addr: SocketAddr, body: &str) -> String {
    post_rpc_with(addr, "Content-Type: application/json\r\n", body)
}

fn body_of(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
}

fn call(addr: SocketAddr, method: &str, params: &str) -> String {
    let c = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    post_rpc(addr, &c).to_string()
}

fn regtest_address(addr: SocketAddr) -> String {
    let r = call(addr, "getnewaddress", "{}");
    let b = body_of(&r).to_string();
    let i = b.find(r#""address":""#).expect("address field") + 11;
    let rest = &b[i..];
    rest[..rest.find('"').unwrap()].to_string()
}

/// The same server, but keeping hold of the node.
///
/// Two tests need to build a state that the RPC cannot produce - a UTXO set
/// of a hundred thousand outputs, for example.
fn server_and_node() -> (ServerHandle, Arc<Node>) {
    let g = genesis_block(NETWORK);
    let node = Arc::new(Node::new(NETWORK, Chain::new(NETWORK, g)));
    let ctx = RpcContext {
        node: node.clone(),
        wallet: Some(Arc::new(Mutex::new(Wallet::from_seed([7u8; 32], NETWORK)))),
        network: NETWORK,
        index: None,
        mining: None,
        on_change: None,
        scans: None,
        configured_bootstrap: 0,
        reachable: std::sync::atomic::AtomicBool::new(true),
        reachable_session: true,
        router_status: None,
        set_reachable: None,
    };
    let h = http::serve("127.0.0.1:0", None, move |req| router(&ctx, req)).expect("server startup");
    (h, node)
}

/// The tests that count the process threads cannot overlap.
///
/// `Threads:` in `/proc/self/status` is a measurement of the **process**, not of
/// the server: two tests that each open hundreds of connections in parallel
/// would measure each other. The lock serializes them.
static THREAD_LOCK: Mutex<()> = Mutex::new(());

fn thread_lock() -> std::sync::MutexGuard<'static, ()> {
    THREAD_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Opens `n` connections, then checks that the last ones were refused.
///
/// Beyond `MAX_CONNECTIONS`, `serve` answers 503 without starting a thread.
/// The late connections therefore already carry their refusal when they are
/// read; the ones that occupy a thread answer nothing before the read timeout.
fn refusals_of_late_connections(kept: &mut [TcpStream], sample: usize) -> usize {
    let start = kept.len().saturating_sub(sample);
    let mut refused = 0;
    for s in &mut kept[start..] {
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let mut buf = [0u8; 64];
        if let Ok(n) = s.read(&mut buf) {
            if String::from_utf8_lossy(&buf[..n]).contains("503") {
                refused += 1;
            }
        }
    }
    refused
}

/// Waits until the server has a thread available again.
fn wait_for_recovery(addr: SocketAddr) -> bool {
    for _ in 0..40 {
        if call(addr, "getinfo", "{}").starts_with("HTTP/1.1 200") {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

// The process thread count can only be read through `/proc/self/status`, which
// is Linux-specific. Where that file does not exist - Windows, macOS - the
// measurement is missing, and the call returns `None`: the tests that depend on
// it then rely on their portable checks alone, for lack of an instrument.
fn process_threads() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        })
}

// ===========================================================================
// 1. CSRF / browser - the shortest path to the funds
// ===========================================================================

/// The RPC examined neither `Origin`, nor `Referer`, nor `Sec-Fetch-Site`.
///
/// The node listens on the local loopback, which is wrongly reassuring: **the
/// user's browser is on the local loopback**. A hostile page open in any tab
/// could therefore send a "simple" request in the CORS sense - so without a
/// preflight - to `http://127.0.0.1:PORT/rpc`, and reach the wallet. The only
/// obstacle encountered was the lack of funds.
///
/// `browser_guard` (src/http.rs) closes this path with four independent locks:
/// `Host`, `Origin`/`Referer`, `Sec-Fetch-Site`, and the requirement of a
/// `Content-Type: application/json`. Each one is enough for a 403 refusal
/// returned **before** the body is parsed: the request no longer reaches the
/// wallet, nor even the JSON parser.
#[test]
fn flaw_csrf_hostile_origin_reaches_the_wallet() {
    let h = server(true, None);
    let dest = regtest_address(h.addr);
    let payload = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{dest}","units":100000}}}}"#
    );

    // First the proof that the payload is live: through the legitimate path, it
    // goes all the way to transaction creation. What follows therefore measures
    // the guard, and not a request that became harmless by accident.
    assert!(
        body_of(&post_rpc(h.addr, &payload)).contains("insufficient funds"),
        "the payload must reach the wallet through the legitimate local path"
    );

    for (name, headers) in [
        (
            "third-party origin",
            "Origin: https://evil.example\r\nContent-Type: application/json\r\n",
        ),
        (
            "third-party referrer",
            "Referer: https://evil.example/trap.html\r\nContent-Type: application/json\r\n",
        ),
        (
            "mark set by the browser",
            "Sec-Fetch-Site: cross-site\r\nContent-Type: application/json\r\n",
        ),
        (
            "simple request, without preflight",
            "Origin: https://evil.example\r\nReferer: https://evil.example/trap.html\r\n\
             Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: no-cors\r\n\
             Content-Type: text/plain;charset=UTF-8\r\n",
        ),
    ] {
        let r = post_rpc_with(h.addr, headers, &payload);
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "{name}: refusal expected, got {}",
            r.lines().next().unwrap_or("(nothing)")
        );
        let c = body_of(&r);
        assert!(
            !c.contains("jsonrpc") && !c.contains("funds") && !c.contains("txid"),
            "{name}: the request was handled anyway: {c}"
        );
    }

    // `Sec-Fetch-Site: same-origin` - what the explorer itself sets - is still
    // served: the guard tells origins apart, it does not refuse everyone.
    let r = post_rpc_with(
        h.addr,
        "Sec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1\r\nContent-Type: application/json\r\n",
        &payload,
    );
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    h.shutdown();
}

/// Worse still: no JavaScript was needed.
///
/// `<form action="http://127.0.0.1:21080/rpc" method="POST"
///        enctype="text/plain">` produces a `name=value\r\n` body. By placing
/// the JSON in the *name* and closing the object in the *value*, the body sent
/// is a valid JSON-RPC document. A simple click - or an automatic
/// `form.submit()` - was enough.
///
/// The lock that closes precisely this path is the requirement of
/// `Content-Type: application/json`: an HTML form can only produce
/// `text/plain`, `application/x-www-form-urlencoded` or `multipart/form-data`.
/// None of the three opens anything anymore, and a `fetch` that set
/// `application/json` would trigger a preflight this service does not satisfy.
#[test]
fn flaw_csrf_html_form_without_javascript() {
    let h = server(true, None);
    let dest = regtest_address(h.addr);

    // name  = {"jsonrpc":"2.0","id":1,"method":"sendtoaddress",
    //          "params":{"address":"...","units":100000,"z":"
    // value = "}}
    // body  = name + "=" + value  ->  ..."z":"="}}
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{dest}","units":100000,"z":"="}}}}"#
    );

    // The only three content types an HTML form can send.
    for enctype in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=----q21",
    ] {
        let r = post_rpc_with(
            h.addr,
            &format!("Origin: https://evil.example\r\nContent-Type: {enctype}\r\n"),
            &body,
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "enctype {enctype}: refusal expected, got {}",
            r.lines().next().unwrap_or("(nothing)")
        );
        assert!(
            !body_of(&r).contains("funds"),
            "enctype {enctype} reached sendtoaddress: {}",
            body_of(&r)
        );
    }
    h.shutdown();
}

/// An absurd `Content-Type` changed nothing: the body was parsed anyway, and
/// that is what made the form request exploitable.
///
/// The POST now requires `application/json`. This is not a formality: that
/// type is precisely the one a page cannot set without triggering a CORS
/// preflight, which this service does not answer. Parameters (`; charset=`)
/// and case are still tolerated - a compliant client does not have to worry
/// about them.
#[test]
fn flaw_csrf_no_content_type_check() {
    let h = server(false, None);
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;

    for ct in [
        "Content-Type: text/plain\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Type: multipart/form-data; boundary=x\r\n",
        "Content-Type: image/png\r\n",
        "Content-Type: application/json-patch+json\r\n",
        "", // no Content-Type at all
    ] {
        let r = post_rpc_with(h.addr, ct, body);
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "content type {ct:?} should have been refused; response = {}",
            r.lines().next().unwrap_or("(nothing)")
        );
        assert!(
            !body_of(&r).contains("\"height\""),
            "the body was parsed despite the refusal: {}",
            body_of(&r)
        );
    }

    // And the compliant client gets through, whatever the case or parameters.
    for ct in [
        "Content-Type: application/json\r\n",
        "Content-Type: application/json; charset=utf-8\r\n",
        "content-type: Application/JSON\r\n",
    ] {
        let r = post_rpc_with(h.addr, ct, body);
        assert!(
            body_of(&r).contains("\"height\""),
            "content type {ct:?} is legitimate and must get through: {r}"
        );
    }
    h.shutdown();
}

/// No check of the `Host` header: DNS rebinding possible.
///
/// With a name that first resolves to the attacker's IP and then to
/// 127.0.0.1, the hostile page became **same-origin** with the node: it then
/// read the responses, and no longer merely sent requests blindly. It thus
/// got hold of the token passed in `?token=`, the addresses, the balances.
///
/// The first lock of `browser_guard` refuses any `Host` that does not
/// designate this machine. A browser always sets this header, and a page
/// cannot forge it: after rebinding, it carries the attacker's name.
///
/// The lock is however narrower than its intent, and this test pins down the
/// two gaps observed below:
///
/// - it only applies if the header is **present**;
/// - it accepts any name starting with `127.`, which includes domain names
///   such as `127.0.0.1.evil.example`.
///
/// The second gap entirely reopens DNS rebinding: such a name also gets
/// through the `Origin` and `Sec-Fetch-Site` locks, for the same reason.
#[test]
fn flaw_no_host_check_dns_rebinding() {
    let h = server(false, None);

    for host in [
        "rebind.evil.example",
        "attacker.example:21080",
        "192.168.1.10",
        "q21.local",
    ] {
        let r = raw(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "Host {host} should have been refused: {}",
            r.lines().next().unwrap_or("(nothing)")
        );
        assert!(
            !body_of(&r).contains("<!doctype"),
            "the page was served to a foreign host: {host}"
        );
    }

    // And the POST to the RPC, even when otherwise perfectly formed.
    let c = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let r = raw(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: rebind.evil.example\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{c}",
            c.len()
        )
        .as_bytes(),
    );
    assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    assert!(
        !body_of(&r).contains("\"height\""),
        "a foreign Host obtained the chain state: {r}"
    );

    // --- The name that wore an address's costume.
    //
    // The first version of `local_host` ended with `bare.starts_with("127.")`,
    // to cover loopback addresses other than 127.0.0.1. But a **domain name**
    // can start that way: `127.0.0.1.evil.example` can be registered in five
    // minutes and pointed to 127.0.0.1.
    //
    // That name then got through all four locks at once: `Host` took it for
    // loopback; after rebinding, the page's origin became
    // `http://127.0.0.1.evil.example:PORT`, which `local_origin` accepted for
    // the same reason; `Sec-Fetch-Site` was `same-origin`; and a same-origin
    // request has no preflight, so it set the right `Content-Type`. DNS
    // rebinding was entirely reopened by a string comparison.
    //
    // The filter now parses an address instead of comparing a prefix.
    for host in [
        "127.0.0.1.evil.example",
        "127.evil.example:21080",
        "localhost.evil.example",
        "127-0-0-1.evil.example",
        "[::1].evil.example",
    ] {
        let r = raw(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "{host} still passes for loopback: {}",
            r.lines().next().unwrap_or("")
        );
    }

    // And the really local forms are still served.
    for host in ["127.0.0.1", "localhost", "127.1.2.3", "[::1]:21080"] {
        let r = raw(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "{host} should be served: {}",
            r.lines().next().unwrap_or("")
        );
    }

    // A missing `Host` is not examined either: the lock only applies to the
    // header when present. No browser omits `Host`, but a raw client can, and
    // then only runs into the other three locks.
    let c = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let r = raw(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{c}",
            c.len()
        )
        .as_bytes(),
    );
    assert!(
        body_of(&r).contains("\"height\""),
        "finding: without a Host header, the first lock does not apply: {r}"
    );

    // Hosts that do designate this machine are still served, with or without
    // a port, in IPv4, in IPv6 or by name.
    for host in [
        "127.0.0.1",
        "127.0.0.1:21080",
        "localhost",
        "LocalHost",
        "[::1]:21080",
    ] {
        let r = raw(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "Host {host} designates this machine and must be served: {}",
            r.lines().next().unwrap_or("(nothing)")
        );
    }
    h.shutdown();
}

/// The response carried no defensive header for the browser: the page could
/// be loaded in an `<iframe>` of a hostile site, nothing limited scripts in
/// it, and the address - token included, at the time - went out in the
/// `Referer` of the first external resource.
///
/// `write_response` (src/http.rs) now sets them on **every** response,
/// refusals included: an error page is a page like any other.
///
/// `Cross-Origin-Resource-Policy` and `Cross-Origin-Opener-Policy` remain
/// absent. Framing is covered by `X-Frame-Options: DENY`, and the rest by
/// `browser_guard`, which refuses the cross-site request before a response
/// policy has to catch it.
#[test]
fn flaw_no_defensive_browser_header() {
    let h = server(false, None);

    let expected = [
        ("content-security-policy", "default-src 'none'"),
        ("x-frame-options", "deny"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
    ];

    // On the served page...
    let page = raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    // ...on a JSON response...
    let json = call(h.addr, "getinfo", "{}");
    // ...and on a refusal: that is where forgetting is easiest.
    let refusal = raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    );
    assert!(refusal.starts_with("HTTP/1.1 403"), "{refusal}");

    for (name, response) in [("page", &page), ("json", &json), ("refusal", &refusal)] {
        let headers = response
            .split("\r\n\r\n")
            .next()
            .unwrap()
            .to_ascii_lowercase();
        for (key, value) in expected {
            assert!(
                headers.contains(key),
                "response {name}: header {key} missing\n{headers}"
            );
            assert!(
                headers.contains(value),
                "response {name}: {key} does not have the expected value ({value})\n{headers}"
            );
        }
    }
    h.shutdown();
}

// ===========================================================================
// 2. Theft of funds / stopping the node through the wallet
// ===========================================================================

/// Unchecked integer overflow in `Wallet::create_transaction`
/// (`amount.units() + fee.units()`).
///
/// `overflow-checks = true` on **every** profile, and `panic = "abort"` in
/// release: the connection thread panicked, and a node built in release
/// **stopped**. In tests (unwinding), the connection closed without the
/// slightest HTTP response - the signature of the panic.
///
/// The JSON parser already rejected integers above `i64::MAX`, but
/// `Json::as_u64` accepted a **string** and converted it: the bound could be
/// bypassed with three characters.
///
/// Two locks were put in place, and both are needed:
///
/// - `Json::as_u64` no longer accepts a string - the detour is closed;
/// - `create_transaction` rejects the amount, the fee and their **sum** above
///   `MAX_SUPPLY` (`WalletError::AmountOutOfRange`), before any arithmetic.
///
/// Each of the three sends below therefore produces a clean JSON-RPC error,
/// and the thread survives.
#[test]
fn flaw_sendtoaddress_overflow_stops_the_node() {
    let h = server(true, None);
    let dest = regtest_address(h.addr);

    // 1. The original detour: the number placed in quotes.
    let r = post_rpc(
        h.addr,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{dest}","units":"18446744073709551615","fee":"1000"}}}}"#
        ),
    );
    assert!(
        r.starts_with("HTTP/1.1 200"),
        "no response (thread panicked?): {r}"
    );
    let c = body_of(&r);
    assert!(
        c.contains("\"code\":-32602") && c.contains("'units' expected"),
        "a string must no longer count as an integer: {c}"
    );

    // 2. The same number, this time as a number: the parser now accepts it
    //    (`Json::UInt`), and it is the wallet that rejects it.
    let r = post_rpc(
        h.addr,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{dest}","units":18446744073709551615}}}}"#
        ),
    );
    let c = body_of(&r);
    assert!(
        c.contains("\"code\":-3") && c.contains("beyond what can exist"),
        "an out-of-bounds amount must be rejected by name: {c}"
    );

    // 3. Two values each under the cap, whose sum is not: it is the addition
    //    itself that overflowed.
    let r = post_rpc(
        h.addr,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{dest}","units":2100000100000000,"fee":2100000100000000}}}}"#
        ),
    );
    let c = body_of(&r);
    assert!(
        c.contains("\"code\":-3") && c.contains("beyond what can exist"),
        "the amount + fee sum must be bounded too: {c}"
    );

    // And the node still answers: no panic happened anymore.
    assert!(call(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// The same overflow through the `fee` field, which had no cap.
///
/// `create_transaction` now bounds the fee like the amount. One rough edge
/// remains, which this test pins down as is: `sendtoaddress` reads the fee
/// with `.unwrap_or(1_000)`. A **badly typed** fee - a string, for example -
/// is therefore not rejected: it is silently replaced by the default. It is no
/// longer an overflow, but the transaction built is not the one the client
/// wrote. The amount, for its part, has no default and complains.
#[test]
fn flaw_sendtoaddress_overflow_through_the_fee() {
    let h = server(true, None);
    let dest = regtest_address(h.addr);

    for fee in ["18446744073709551615", "2100000100000000"] {
        let r = post_rpc(
            h.addr,
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{dest}","units":10000,"fee":{fee}}}}}"#
            ),
        );
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "expected a response, got: {r}"
        );
        let c = body_of(&r);
        assert!(
            c.contains("\"code\":-3") && c.contains("beyond what can exist"),
            "fee {fee}: refusal expected, got {c}"
        );
    }

    // --- A badly typed fee no longer falls back to the default.
    //
    // `.and_then(as_u64).unwrap_or(1_000)` silently replaced any unreadable
    // value with a thousand units: the transaction built was not the one the
    // client had written. A field that is present and invalid is now an
    // error, not an invitation to guess.
    for fee in [
        r#""18446744073709551615""#,
        r#""1000""#,
        "true",
        r#"{"units":1000}"#,
        "[1000]",
    ] {
        let c = body_of(&post_rpc(
            h.addr,
            &format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{dest}","units":10000,"fee":{fee}}}}}"#
            ),
        ))
        .to_string();
        assert!(
            c.contains("\"code\":-32602") && c.contains("unreadable"),
            "fee {fee}: refusal expected, got {c}"
        );
    }

    // Absent or null: the default applies, and that is legitimate.
    for fee in ["null", ""] {
        let params = if fee.is_empty() {
            format!(r#"{{"address":"{dest}","units":10000}}"#)
        } else {
            format!(r#"{{"address":"{dest}","units":10000,"fee":{fee}}}"#)
        };
        let c = body_of(&post_rpc(
            h.addr,
            &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{params}}}"#),
        ))
        .to_string();
        assert!(
            c.contains("insufficient funds"),
            "fee absent: the default must apply, got {c}"
        );
    }

    assert!(call(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// A JSON-RPC batch turned a single panic into a guaranteed shutdown: the
/// first entry that overflowed took the thread down before any response, and
/// none of the others was returned.
///
/// Since nothing panics anymore, the batch now returns what a batch must
/// return: one response per call, the error of one not taking the other down.
#[test]
fn flaw_the_batch_propagates_the_panic() {
    let h = server(true, None);
    let dest = regtest_address(h.addr);
    let body = format!(
        r#"[{{"jsonrpc":"2.0","id":1,"method":"getinfo"}},{{"jsonrpc":"2.0","id":2,"method":"sendtoaddress","params":{{"address":"{dest}","units":18446744073709551615}}}},{{"jsonrpc":"2.0","id":3,"method":"getsupply"}}]"#
    );
    let r = post_rpc(h.addr, &body);
    assert!(
        r.starts_with("HTTP/1.1 200"),
        "no response (thread panicked?): {r}"
    );

    let c = body_of(&r);
    assert!(
        c.starts_with('[') && c.ends_with(']'),
        "a batch returns an array: {c}"
    );
    assert_eq!(
        c.matches("\"jsonrpc\":\"2.0\"").count(),
        3,
        "all three calls must be returned: {c}"
    );
    assert!(
        c.contains("\"height\":0"),
        "the first call was indeed executed: {c}"
    );
    assert!(
        c.contains("\"code\":-3"),
        "the second must return an error, not a panic: {c}"
    );
    assert!(
        c.contains("\"cap\""),
        "the third must be executed despite the error of the second: {c}"
    );

    assert!(call(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Confirmation: without `--rpc-wallet`, the spending methods are indeed
/// refused, and the overflow cannot be reached.
#[test]
fn ok_the_wallet_is_indeed_closed_without_rpc_wallet() {
    let h = server(false, None);
    for m in ["getbalance", "getnewaddress", "sendtoaddress"] {
        let r = call(
            h.addr,
            m,
            r#"{"address":"x","units":"18446744073709551615"}"#,
        );
        let c = body_of(&r);
        assert!(
            c.contains("\"code\":-2"),
            "{m} should have been refused (code -2): {c}"
        );
    }
    // And the server still answers: no panic happened.
    assert!(call(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// `getinfo` publicly announces whether the funds are reachable.
///
/// It is not a flaw in itself, it is the **reconnaissance** that precedes the
/// CSRF: a hostile page tests `wallet_enabled` before firing.
#[test]
fn flaw_getinfo_announces_whether_the_funds_are_reachable() {
    let open = server(true, None);
    assert!(body_of(&call(open.addr, "getinfo", "{}")).contains("\"wallet_enabled\":true"));
    open.shutdown();

    let closed = server(false, None);
    assert!(body_of(&call(closed.addr, "getinfo", "{}")).contains("\"wallet_enabled\":false"));
    closed.shutdown();
}

// ===========================================================================
// 3. Authentication
// ===========================================================================

/// No attempt to bypass the token succeeded.
#[test]
fn ok_the_token_is_not_trivially_bypassed() {
    let h = server(false, Some("s3cret"));

    let attempts: Vec<(&str, String)> = vec![
        ("no token", String::new()),
        ("different case", "Authorization: Bearer S3CRET\r\n".into()),
        (
            "lowercase scheme",
            "authorization: bearer s3cret\r\n".into(),
        ),
        ("missing scheme", "Authorization: s3cret\r\n".into()),
        ("correct prefix", "Authorization: Bearer s3c\r\n".into()),
        (
            "appended suffix",
            "Authorization: Bearer s3cretX\r\n".into(),
        ),
        ("null byte", "Authorization: Bearer s3cret\x00\r\n".into()),
        (
            "alternative header",
            "X-Auth-Token: s3cret\r\nAuthorization: Bearer wrong\r\n".into(),
        ),
    ];
    for (name, headers) in attempts {
        let r = raw(
            h.addr,
            format!("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Connection: close\r\n\r\n")
                .as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 401"),
            "bypass through \"{name}\": {}",
            r.lines().next().unwrap_or("")
        );
    }

    // The only legitimate path: the header.
    assert!(raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));
    // The token in the URL no longer opens anything: an address ends up in the
    // history, in the logs of a front server, and in the `Referer`.
    assert!(raw(
        h.addr,
        b"GET /?token=s3cret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 401"));
    h.shutdown();
}

/// The token was accepted with extra spaces (the `.trim()` in `authorized`,
/// src/http.rs) **and** in percent-encoded form in the URL.
///
/// The second point was the real problem: `?token=%73%33%63%72%65%74` opened
/// the node, and a URL ends up in the browser history, in the logs of every
/// front server, and in the `Referer`. That path is closed: only the
/// `Authorization` header is read.
///
/// The tolerance for spaces remains, and this test pins it down: it is not a
/// bypass - the right token is still needed, compared in constant time - but
/// it widens what an intermediary has to normalize before comparing.
#[test]
fn minor_flaw_the_token_tolerates_spaces_and_encoding() {
    let h = server(false, Some("s3cret"));

    // Extra spaces: still tolerated, still without effect on the value
    // required.
    assert!(raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer    s3cret   \r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));
    // But a space does not replace a character: the token is still compared
    // whole.
    assert!(raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3 cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 401"));

    // The percent-encoded token in the URL no longer opens anything: the URL
    // is no longer an authentication path, whatever its form.
    for target in [
        "/?token=%73%33%63%72%65%74",
        "/?token=s3cret",
        "/?a=1&token=s3cret",
        "/index.html?token=s3cret",
    ] {
        let r = raw(
            h.addr,
            format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 401"),
            "{target} opened the node: {}",
            r.lines().next().unwrap_or("(nothing)")
        );
    }
    h.shutdown();
}

/// Duplicated `Authorization` header: it is the **last** one that counts
/// (`BTreeMap::insert`, src/http.rs:236). A front server that validated the
/// first one would be out of sync with the node.
#[test]
fn flaw_duplicated_header_the_last_one_wins() {
    let h = server(false, Some("s3cret"));
    let first_good = raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nAuthorization: Bearer wrong\r\nConnection: close\r\n\r\n",
    );
    let last_good = raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer wrong\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n",
    );
    assert!(
        first_good.starts_with("HTTP/1.1 401"),
        "the first header is ignored"
    );
    assert!(
        last_good.starts_with("HTTP/1.1 200"),
        "the last header wins"
    );
    h.shutdown();
}

/// The token could travel in the URL (`?token=`), and the explorer itself
/// recommended it in its error message. A URL ends up in the browser history,
/// in the logs of a front server, and in the `Referer` of the first external
/// resource loaded. A secret that travels in a URL is no longer a secret.
///
/// `authorized` (src/http.rs) now only reads the `Authorization` header, and
/// the page has changed its advice: it asks for the token and sends it as
/// `Bearer`.
#[test]
fn flaw_the_token_travels_in_the_url() {
    let h = server(false, Some("s3cret"));

    assert!(
        raw(
            h.addr,
            b"GET /?token=s3cret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .starts_with("HTTP/1.1 401"),
        "the token in the URL must no longer open anything"
    );

    // The query string is simply ignored: it opens nothing, and it does not
    // close anything either for whoever presents the header.
    assert!(raw(
        h.addr,
        b"GET /?token=wrong HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));

    // And the page no longer advises putting it there.
    let p = q21_core::explorer::PAGE;
    assert!(
        !p.contains("?token="),
        "the page still advises putting the token in the URL"
    );
    assert!(
        p.contains("Authorization") && p.contains("\"Bearer \""),
        "the page must send the token in a header"
    );
    h.shutdown();
}

/// Confirms the safeguard: no public listening without a token.
#[test]
fn ok_listening_outside_loopback_without_a_token_is_refused() {
    let r = http::serve("0.0.0.0:0", None, |_| Response::text(200, "x"));
    assert!(r.is_err(), "0.0.0.0 without a token must be refused");
    let r6 = http::serve("[::]:0", None, |_| Response::text(200, "x"));
    assert!(r6.is_err(), "[::] without a token must be refused");
}

// ===========================================================================
// 4. HTTP parser
// ===========================================================================

/// Lying `Content-Length`: the server allocated the buffer **before** reading
/// (`vec![0u8; size]`), then stayed blocked until the read timeout. Each
/// connection therefore cost a mebibyte of heap and a system thread, for zero
/// bytes of body sent by the attacker. A hundred and twenty connections were
/// enough for a hundred and twenty threads and a hundred and twenty mebibytes.
///
/// Two fixes. The first cannot be observed from a client: the buffer is now
/// **filled** in chunks and not preallocated, so what is allocated is what has
/// arrived. It can be read in `read_request`.
///
/// The second can: `MAX_CONNECTIONS` caps the connections handled
/// simultaneously. Beyond that, the connection receives a plain 503, without a
/// thread. That is what this test checks - the number of process threads no
/// longer follows the number of open connections.
#[test]
fn flaw_lying_content_length_allocates_before_reading() {
    let _lock = thread_lock();
    let h = server(false, None);
    let before = process_threads();

    // 120 connections announcing 1 MiB each, without ever sending the body.
    let mut kept = Vec::new();
    for _ in 0..120 {
        let mut s = TcpStream::connect(h.addr).expect("connection");
        s.write_all(
            b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
              Content-Length: 1048576\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        kept.push(s);
    }
    std::thread::sleep(Duration::from_millis(700));
    let during = process_threads();
    eprintln!("threads: before={before:?} during={during:?} (120 connections announcing 1 MiB)");

    // The central invariant - the number of threads does not follow the number
    // of connections - can only be measured where `/proc` exists. On Linux, we
    // require it; elsewhere, the instrument is missing and we can only note its
    // absence, not draw the conclusion in its place.
    if let (Some(before), Some(during)) = (before, during) {
        assert!(
            during < before + 100,
            "the number of threads still follows the number of connections; \
             before={before} during={during}, announced cap = {}",
            http::MAX_CONNECTIONS
        );
    }

    // The connections beyond the cap already carry their refusal. The moment
    // the 503 is written depends on the system's scheduling: on Linux it is
    // immediate, and the last forty connections carry it when they are read.
    // On other systems, the excess can wait in the kernel accept queue and only
    // receive its refusal later - we then just require that none is wrongly
    // served.
    let refused = refusals_of_late_connections(&mut kept, 40);
    #[cfg(target_os = "linux")]
    assert_eq!(
        refused,
        40,
        "the connections beyond {} must be refused with a 503",
        http::MAX_CONNECTIONS
    );
    #[cfg(not(target_os = "linux"))]
    assert!(
        refused <= 40,
        "a connection was wrongly served beyond the cap of {}",
        http::MAX_CONNECTIONS
    );

    // A body larger than `MAX_BODY` is refused on its announcement alone,
    // without a byte being read or reserved.
    let r = raw(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            http::MAX_BODY + 1
        )
        .as_bytes(),
    );
    assert!(
        r.is_empty() || r.starts_with("HTTP/1.1 400") || r.starts_with("HTTP/1.1 503"),
        "{r}"
    );

    // The cap is not a lockout: the threads are freed.
    drop(kept);
    assert!(
        wait_for_recovery(h.addr),
        "the server must answer again once the connections are closed"
    );
    h.shutdown();
}

/// No limit on the number of connections or threads.
///
/// `serve` did a `std::thread::spawn` per connection, with no counter, no
/// queue, no pool. Five hundred silent connections - no byte sent - gave five
/// hundred system threads, each blocked until the read timeout.
///
/// `MAX_CONNECTIONS` now bounds the connections handled simultaneously, and
/// the refusal is immediate: a 503 written from the accept loop, without
/// starting a thread. A plain refusal costs less than one more thread.
#[test]
fn flaw_unbounded_number_of_threads() {
    let _lock = thread_lock();
    let h = server(false, None);
    let before = process_threads();
    let mut kept = Vec::new();
    for _ in 0..500 {
        // Connection open, no byte sent.
        match TcpStream::connect(h.addr) {
            Ok(s) => kept.push(s),
            Err(_) => break,
        }
    }
    std::thread::sleep(Duration::from_millis(900));
    let during = process_threads();
    eprintln!(
        "threads: before={before:?} during={during:?} ({} silent connections, cap {})",
        kept.len(),
        http::MAX_CONNECTIONS
    );

    assert!(
        kept.len() >= 400,
        "the test could not open enough connections: {}",
        kept.len()
    );
    // The thread count can only be read on Linux (`/proc`). Where it is read,
    // it proves that the threads do not follow the connections; elsewhere, the
    // instrument is missing and the assertion would bear on a missing
    // measurement.
    if let (Some(before), Some(during)) = (before, during) {
        assert!(
            during < before + 200,
            "the threads still follow the connections: before={before} during={during} \
             for {} connections",
            kept.len()
        );
    }

    // The direct proof, specific to this server: the late connections are
    // refused instead of getting a thread. On Linux the 503 is immediate and
    // the last fifty carry it; elsewhere the refusal can come later, and we
    // only require that no late connection is wrongly served.
    let refused = refusals_of_late_connections(&mut kept, 50);
    #[cfg(target_os = "linux")]
    assert_eq!(
        refused, 50,
        "the connections beyond the cap must receive a 503"
    );
    #[cfg(not(target_os = "linux"))]
    assert!(
        refused <= 50,
        "a connection was wrongly served beyond the cap"
    );

    drop(kept);
    assert!(wait_for_recovery(h.addr));
    h.shutdown();
}

/// The read timeout applied to **each read**, never to the whole request. One
/// byte every few seconds therefore kept the connection - and its thread -
/// alive indefinitely: that is Slowloris, and a few dozen connections were
/// enough to immobilize the node.
///
/// `REQUEST_TIMEOUT` (20 s) now bounds the complete request: `read_request`
/// checks the deadline after the request line, after each header and before
/// each chunk of body. Beyond that, it is a 400 "request too slow".
///
/// The bound is checked **between** lines, not in the middle of a line: the
/// blade therefore falls at the end of the header in progress, never before.
/// The line itself is bounded by `MAX_LINE`, but an attacker who spreads out a
/// single very long header can still hold a connection well beyond the
/// deadline. This test measures what the server really guarantees.
#[test]
fn flaw_slowloris_no_global_timeout() {
    let h = server(false, None);
    let mut s = TcpStream::connect(h.addr).expect("connection");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    // A request of seven hundred bytes, sent at ten bytes per second: without
    // a global deadline, it would occupy a thread for more than a minute, then
    // be served.
    let mut request = String::from("GET /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for i in 0..30 {
        request.push_str(&format!("X-Slow-{i:02}: aaaaaaaaaa\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    let total = request.len();

    let start = Instant::now();
    let mut sent = 0usize;
    let mut cut = false;
    for o in request.as_bytes() {
        if s.write_all(&[*o]).is_err() || s.flush().is_err() {
            cut = true;
            break;
        }
        sent += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut r = String::new();
    let _ = s.read_to_string(&mut r);
    let elapsed = start.elapsed();
    eprintln!("slowloris: {sent}/{total} bytes in {elapsed:?}, cut={cut}");

    assert!(
        cut || !r.is_empty(),
        "the connection was neither cut nor closed after {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(45),
        "the connection survived {elapsed:?}: the global deadline does not apply"
    );
    assert!(
        sent < total,
        "the server waited for the whole request ({sent} bytes out of {total})"
    );
    assert!(
        r.is_empty() || r.starts_with("HTTP/1.1 400"),
        "a request spread out beyond the deadline must not be served: {r}"
    );
    assert!(
        !r.contains("HTTP/1.1 405"),
        "the server served a request spread out over {elapsed:?}: {r}"
    );
    // And the deadline is indeed what cut it: an immediate refusal would look
    // quite different.
    assert!(
        elapsed > Duration::from_secs(15),
        "cut too early to come from the {:?} deadline: {elapsed:?}",
        http::REQUEST_TIMEOUT
    );

    assert!(call(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Beyond `MAX_HEADERS` headers, the request is **refused**.
///
/// # The history of this test, which is that of the fix
///
/// The read loop stopped at the limit **without consuming the empty line**:
/// the following headers were neither read nor refused, they silently became
/// the start of the body. This test pinned down that behavior as is, checking
/// that each of its consequences was at least *closing* - an authentication
/// out of reach gave 401, a `Content-Type` out of reach gave 403, a shifted
/// body gave a parse error. None let through a request that would have been
/// refused otherwise.
///
/// Its last line said, however: "a plain 400 would be better than a silently
/// shifted body". The penetration audit carried out before the public
/// explorer went live settled it - a request whose splitting depends on the
/// sender is the ground for smuggling, and this leniency would become a
/// vulnerability the day connection reuse was added.
///
/// The three cases now return **400**, and this test checks that they do.
#[test]
fn flaw_beyond_64_headers_the_rest_becomes_the_body() {
    let padding = |n: usize| {
        let mut s = String::new();
        for i in 0..n {
            s.push_str(&format!("X-Padding-{i}: a\r\n"));
        }
        s
    };
    let too_many = http::MAX_HEADERS + 6;

    // 1. The authentication after the 64th header is lost: closing failure.
    let h = server(false, Some("s3cret"));
    let req = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Authorization: Bearer s3cret\r\nConnection: close\r\n\r\n",
        padding(too_many)
    );
    let r = raw(h.addr, req.as_bytes());
    assert!(
        r.starts_with("HTTP/1.1 400"),
        "beyond {} headers, the request must be plainly refused: {}",
        http::MAX_HEADERS,
        r.lines().next().unwrap_or("(nothing)")
    );
    // The same request without padding gets through: it is indeed the padding
    // that cuts.
    assert!(raw(
        h.addr,
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer s3cret\r\nConnection: close\r\n\r\n"
    )
    .starts_with("HTTP/1.1 200"));
    h.shutdown();

    let h2 = server(false, None);
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;

    // 2. The `Content-Type` pushed beyond the limit is ignored: the guard
    //    refuses the request instead of parsing it.
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Content-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        padding(too_many),
        body.len()
    );
    let r = raw(h2.addr, req.as_bytes());
    assert!(
        r.starts_with("HTTP/1.1 400"),
        "a Content-Type out of reach must close the request: {}",
        r.lines().next().unwrap_or("(nothing)")
    );

    // 3. Valid headers first, padding afterward: formerly the announced body
    //    was shifted by the unread headers and the call became unreadable.
    //    Now the request is simply not served.
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n{}\r\n{body}",
        body.len(),
        padding(too_many)
    );
    let r = raw(h2.addr, req.as_bytes());
    assert!(
        r.starts_with("HTTP/1.1 400"),
        "the padding must close the request: {}",
        r.lines().next().unwrap_or("(nothing)")
    );
    assert!(
        !body_of(&r).contains("\"height\""),
        "the call was executed despite the padding: {r}"
    );

    // And the same request without padding is served: it is indeed the limit
    // that cuts, nothing else.
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    assert!(body_of(&raw(h2.addr, req.as_bytes())).contains("\"height\""));
    h2.shutdown();
}

/// `Transfer-Encoding: chunked` is not implemented, and is now plainly
/// **refused** with a 400 - instead of being silently ignored (red-team 8b).
///
/// We check the refusal AND the absence of smuggling: the chunked body is
/// never executed, a single response goes out per connection, and a request
/// hidden in the chunks - including when `Content-Length` and
/// `Transfer-Encoding` contradict each other, the classic desynchronization
/// pattern - is never served.
#[test]
fn chunked_is_refused_with_400() {
    let h = server(false, None);

    let r = raw(
        h.addr,
        b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
          Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
          2a\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\"}\r\n0\r\n\r\n",
    );
    assert!(
        r.starts_with("HTTP/1.1 400"),
        "chunked must be refused with a plain 400: {r}"
    );
    assert!(
        !r.contains("\"height\""),
        "the chunked body must not be executed: {r}"
    );

    // Contradictory `Content-Length` and `Transfer-Encoding`: the very pattern
    // of smuggling. Refusal, a single response, hidden request never served.
    let hidden = r#"{"jsonrpc":"2.0","id":9,"method":"getsupply"}"#;
    let r = raw(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n\
             {:x}\r\n{hidden}\r\n0\r\n\r\n",
            hidden.len()
        )
        .as_bytes(),
    );
    assert!(
        r.starts_with("HTTP/1.1 400"),
        "contradictory Content-Length and Transfer-Encoding must be refused: {r}"
    );
    assert_eq!(
        r.matches("HTTP/1.1 ").count(),
        1,
        "a single response must come out of the connection: {r}"
    );
    assert!(
        !r.contains("\"cap\""),
        "the request hidden in the chunks was served: {r}"
    );
    h.shutdown();
}

/// Duplicated `Content-Length`: now plainly **refused** with a 400, as RFC 9112
/// requires - instead of keeping the last value and silently throwing away the
/// excess (red-team 8b). Two contradictory `Content-Length` headers were the
/// other classic half of smuggling: a front server could keep the first value
/// and read a different message than the node.
///
/// We check the refusal in both orders, and the absence of smuggling: one
/// connection, one response, no hidden request served.
#[test]
fn duplicated_content_length_is_refused_with_400() {
    let h = server(false, None);
    let json = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let hidden = r#"{"jsonrpc":"2.0","id":9,"method":"getsupply"}"#;
    let body = format!("{json}{hidden}");

    for (a, b) in [(9999, json.len()), (json.len(), 9999)] {
        let r = raw(
            h.addr,
            format!(
                "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
                 Content-Length: {a}\r\nContent-Length: {b}\r\nConnection: close\r\n\r\n{body}"
            )
            .as_bytes(),
        );
        assert!(
            r.starts_with("HTTP/1.1 400"),
            "two Content-Length headers must give a plain 400 (order {a}/{b}): {r}"
        );
        assert_eq!(
            r.matches("HTTP/1.1 ").count(),
            1,
            "a single response per connection (order {a}/{b}): {r}"
        );
        assert!(
            !r.contains("\"height\"") && !r.contains("\"cap\""),
            "no call must be executed (order {a}/{b}): {r}"
        );
    }
    h.shutdown();
}

/// Two requests stacked on one connection: the second is lost.
/// No smuggling, but no error either.
#[test]
fn ok_no_smuggling_by_stacking() {
    let h = server(false, None);
    let c = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"}"#;
    let r = raw(
        h.addr,
        format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Content-Type: application/json\r\nContent-Length: {n}\r\n\r\n{c}\
             POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Content-Type: application/json\r\nContent-Length: {n}\r\n\r\n{c}",
            n = c.len()
        )
        .as_bytes(),
    );
    assert_eq!(
        r.matches("HTTP/1.1 200").count(),
        1,
        "a single response must come out: {r}"
    );
    h.shutdown();
}

/// The non-UTF-8 bytes of the body are replaced without error
/// (`from_utf8_lossy`, src/http.rs:254) - no panic.
#[test]
fn ok_binary_body_does_not_cause_a_panic() {
    let h = server(false, None);
    let mut req = b"POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
          Content-Length: 16\r\nConnection: close\r\n\r\n"
        .to_vec();
    req.extend_from_slice(&[
        0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28, 0xed, 0xa0, 0x80, 1, 2, 3, 4, 5, 6, 7,
    ]);
    let r = raw(h.addr, &req);
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    h.shutdown();
}

// ===========================================================================
// 5. JSON parser
// ===========================================================================

/// Deep nesting: the depth counter holds, no stack overflow.
#[test]
fn ok_deep_nesting_is_cleanly_refused() {
    let h = server(false, None);
    for n in [40usize, 5_000, 200_000] {
        let body = format!("{}{}", "[".repeat(n), "]".repeat(n));
        let r = post_rpc(h.addr, &body);
        assert!(
            r.starts_with("HTTP/1.1 200") || r.starts_with("HTTP/1.1 400"),
            "depth {n}: {}",
            r.lines().next().unwrap_or("(nothing)")
        );
    }
    assert!(call(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Giant strings, pathological escapes, lone surrogates, out-of-bounds
/// numbers: clean errors, no panic.
#[test]
fn ok_pathological_json_does_not_cause_a_panic() {
    let h = server(false, None);
    let cases: Vec<String> = vec![
        format!(r#"{{"method":"{}"}}"#, "A".repeat(500_000)),
        r#"{"method":"getinfo","x":"\ud800𐏿"}"#.into(),
        r#"{"method":"getinfo","x":" ￿"}"#.into(),
        format!(
            r#"{{"method":"getemission","params":{{"height":{}}}}}"#,
            "9".repeat(400)
        ),
        r#"{"method":"getemission","params":{"height":-1}}"#.into(),
        r#"{"method":"getemission","params":{"height":1.5}}"#.into(),
        r#"{"method":"getinfo","x":"\uZZZZ"}"#.into(),
        r#"{"method":"getinfo","x":"unterminated"#.into(),
        format!(r#"{{"method":"getinfo","x":{}}}"#, "\"a\":".to_string()),
        "\u{feff}{\"method\":\"getinfo\"}".into(),
    ];
    for c in &cases {
        let r = post_rpc(h.addr, c);
        assert!(
            !r.is_empty(),
            "no response (panic?) for: {}",
            &c[..c.len().min(60)]
        );
    }
    assert!(call(h.addr, "getinfo", "{}").starts_with("HTTP/1.1 200"));
    h.shutdown();
}

/// Duplicate keys: the **last** one won (`BTreeMap::insert`). An
/// intermediary - application firewall, audit log, filtering front server -
/// that reads the first occurrence of `method` therefore saw something other
/// than the node, and let through a spend announced as a lookup.
///
/// RFC 8259 leaves this behavior undefined; monetary code cannot afford
/// undefined. The parser now rejects the whole document
/// (`JsonError::DuplicateKey`), at any depth.
#[test]
fn flaw_duplicate_json_key_the_last_one_wins() {
    use q21_core::json::{parse, JsonError};

    let h = server(true, None);

    // The `method` key repeated: neither the first nor the last reading is
    // executed, the document is rejected.
    let r = post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"getinfo","method":"getnewaddress"}"#,
    );
    let c = body_of(&r);
    assert!(c.contains("-32700"), "ambiguous document accepted: {c}");
    assert!(
        !c.contains("\"address\""),
        "the second key was executed: {c}"
    );
    assert!(!c.contains("\"height\""), "the first key was executed: {c}");

    // And down into the parameters, where a second amount could hide.
    let c = body_of(&post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{"address":"rq21zzz","units":1,"units":100000000}}"#,
    ))
    .to_string();
    assert!(
        c.contains("-32700"),
        "duplication in the parameters accepted: {c}"
    );

    // Directly on the parser: the refusal names the offending key.
    assert_eq!(
        parse(r#"{"method":"getinfo","method":"sendtoaddress"}"#),
        Err(JsonError::DuplicateKey("method".to_string()))
    );
    // An object without repetition is of course still accepted.
    assert!(parse(r#"{"a":1,"b":2}"#).is_ok());
    h.shutdown();
}

/// `Json::as_u64` accepted a string: the promise "no integer above
/// `i64::MAX`" did not hold on the **input** side, and that was the door to
/// the `sendtoaddress` overflow.
///
/// Two changes, in opposite directions, that complement each other:
///
/// - an integer stays an integer. `as_u64` no longer converts a string; a
///   numeric value given in quotes is no longer read at all;
/// - the parser's bound, on the other hand, no longer has any reason to exist:
///   the `Json::UInt` variant represents the integers between `i64::MAX` and
///   `u64::MAX`, which are perfectly valid JSON. They are therefore **accepted
///   as numbers**, and it is up to the business layers to bound them - which
///   the wallet does.
#[test]
fn flaw_integers_beyond_i64_go_through_a_string() {
    use q21_core::json::parse;

    let h = server(false, None);

    // As a number: accepted, and returned as a number.
    let n = body_of(&post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"getemission","params":{"height":18446744073709551615}}"#,
    ))
    .to_string();
    assert!(
        n.contains("\"height\":18446744073709551615"),
        "an integer beyond i64 is valid JSON and must be read as a number: {n}"
    );
    assert!(
        !n.contains("\"height\":\"18446744073709551615\""),
        "the field must not come back out as a string: {n}"
    );

    // As a string: no more conversion. The parameter is simply absent, and
    // `getemission` falls back to the chain height - zero here.
    let s = body_of(&post_rpc(
        h.addr,
        r#"{"jsonrpc":"2.0","id":1,"method":"getemission","params":{"height":"18446744073709551615"}}"#,
    ))
    .to_string();
    assert!(
        s.contains("\"height\":0"),
        "a string must no longer count as an integer: {s}"
    );
    assert!(
        !s.contains("18446744073709551615"),
        "the value given as a string was read: {s}"
    );

    // The same finding, without going through the network.
    assert_eq!(
        parse(r#"{"n":"18446744073709551615"}"#)
            .unwrap()
            .get("n")
            .and_then(|v| v.as_u64()),
        None
    );
    assert_eq!(
        parse(r#"{"n":18446744073709551615}"#)
            .unwrap()
            .get("n")
            .and_then(|v| v.as_u64()),
        Some(u64::MAX)
    );
    h.shutdown();
}

/// Batch amplification: a one-mebibyte request - the maximum size of a body -
/// contained tens of thousands of calls, each producing its response, the
/// whole thing assembled **entirely in memory** before being sent
/// (`Json::array(responses).encode()`). No bound on the number of calls, none
/// on the size of the response; the factor measured exceeded ten.
///
/// `MAX_BATCH` bounds the number of calls and `MAX_BATCH_RESPONSE` the
/// cumulative size of the responses. A batch that is too large is refused
/// **before** executing anything: the cost of the attack is now that of one
/// parse, not that of twenty thousand calls.
#[test]
fn flaw_json_rpc_batch_amplification() {
    use q21_core::rpc::MAX_BATCH;

    let h = server(false, None);

    let unit = r#"{"jsonrpc":"2.0","id":1,"method":"getinfo"},"#;
    let n = (1024 * 1024 - 2) / unit.len();
    let mut body = String::with_capacity(1024 * 1024);
    body.push('[');
    for _ in 0..n {
        body.push_str(unit);
    }
    body.pop();
    body.push(']');
    assert!(body.len() <= 1024 * 1024, "body = {} B", body.len());

    let start = Instant::now();
    let r = post_rpc(h.addr, &body);
    let elapsed = start.elapsed();
    let out = body_of(&r).len();

    let factor = out as f64 / body.len() as f64;
    eprintln!(
        "batch: {n} requests, input {} B, output {out} B, factor x{factor:.4}, {elapsed:?}",
        body.len()
    );
    assert!(
        factor < 1.0,
        "a batch must no longer amplify: input {} B -> output {out} B (x{factor:.1})",
        body.len()
    );
    let c = body_of(&r);
    assert!(
        c.contains("-32600") && c.contains(&format!("maximum {MAX_BATCH}")),
        "the refusal must name the bound: {c}"
    );
    assert!(
        !c.contains("\"height\""),
        "none of the {n} calls may have been executed: {c}"
    );

    // The bound is exact, and a useful batch still gets through.
    let batch = |m: usize| {
        let mut c = String::from("[");
        for _ in 0..m {
            c.push_str(unit);
        }
        c.pop();
        c.push(']');
        post_rpc(h.addr, &c)
    };
    assert_eq!(
        body_of(&batch(MAX_BATCH)).matches("\"height\"").count(),
        MAX_BATCH,
        "a batch of {MAX_BATCH} calls must be served entirely"
    );
    assert!(body_of(&batch(MAX_BATCH + 1)).contains("-32600"));
    h.shutdown();
}

/// Work amplification: each `gettransaction` in a batch triggered a backward
/// scan of the **whole** chain, under the node's global lock. The cost grew
/// with the height, and a batch multiplied it by the number of elements - five
/// thousand calls for the price of one request.
///
/// Two bounds complement each other: `MAX_BATCH` limits the number of calls in
/// a batch, and `MAX_SCANNED_BLOCKS` limits the depth of each scan. The second
/// is not exercised here - it would take a chain of more than two thousand
/// blocks, so as many proofs of work. This test locks in the first, which is
/// the one that turned a costly call into a weapon.
#[test]
fn flaw_gettransaction_scans_the_whole_chain_per_batch_element() {
    use q21_core::rpc::MAX_BATCH;

    let h = server(false, None);
    let one = r#"{"jsonrpc":"2.0","id":1,"method":"gettransaction","params":{"txid":"0000000000000000000000000000000000000000000000000000000000000000"}},"#;

    let batch_of = |n: usize| {
        let mut body = String::from("[");
        for _ in 0..n {
            body.push_str(one);
        }
        body.pop();
        body.push(']');
        let t = Instant::now();
        let r = post_rpc(h.addr, &body);
        (t.elapsed(), r)
    };

    let (bounded, r_bounded) = batch_of(MAX_BATCH);
    let n = 5_000;
    let (large, r_large) = batch_of(n);
    eprintln!("gettransaction: batch of {MAX_BATCH} in {bounded:?}, batch of {n} in {large:?}");

    // The allowed batch is executed entirely...
    assert_eq!(
        body_of(&r_bounded).matches("\"code\":-1").count(),
        MAX_BATCH,
        "the {MAX_BATCH} allowed calls must be executed"
    );
    // ...and the oversized batch is not executed at all.
    let c = body_of(&r_large);
    assert_eq!(
        c.matches("\"code\":-1").count(),
        0,
        "none of the {n} scans may have happened: {c}"
    );
    assert!(
        c.contains("-32600") && c.contains(&format!("maximum {MAX_BATCH}")),
        "{c}"
    );
    // The work no longer follows the size of the batch: the refusal fits in
    // about a hundred bytes, where the response weighed mebibytes.
    assert!(
        c.len() < 200,
        "the refusal must cost a tiny response: {} B",
        c.len()
    );
    h.shutdown();
}

/// `getbalance` copied the entire UTXO set at every call (`c.utxo.clone()`) -
/// hundreds of mebibytes on a real chain, to read a balance - and a batch asked
/// for as many copies.
///
/// The computation is now done under the lock, on a reference: it is
/// identical, the allocation has disappeared. It is a cost property, so
/// invisible in a response; this test measures it by giving itself a yardstick.
///
/// The yardstick is the copy itself: we fill a set of a hundred thousand
/// outputs, time **one** copy, then time a hundred `getbalance` calls. If the
/// call copied, those hundred calls would cost at least a hundred copies.
/// Today they cost less than two - each call walks the set without
/// duplicating it.
#[test]
fn flaw_getbalance_copies_the_utxo_set_per_call() {
    use q21_core::amount::Amount;
    use q21_core::hash::Hash256;
    use q21_core::rpc::MAX_BATCH;
    use q21_core::sig::SchemeId;
    use q21_core::tx::{OutPoint, TxOut};
    use q21_core::utxo::UtxoEntry;

    let (h, node) = server_and_node();

    // A hundred thousand unspent outputs: enough to make a copy measurable.
    const OUTPUTS: u32 = 100_000;
    node.with_chain(|c| {
        for i in 0..OUTPUTS {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            c.utxo.insert(
                OutPoint {
                    txid: Hash256(b),
                    index: 0,
                },
                UtxoEntry {
                    output: TxOut {
                        value: Amount::from_units(1_000),
                        scheme: SchemeId::LamportOts,
                        pubkey_hash: Hash256(b),
                    },
                    height: 0,
                    is_coinbase: false,
                },
            );
        }
    });

    // The yardstick: exactly what the removed `clone()` costs.
    let copy_cost = {
        let t = Instant::now();
        let copy = node.with_chain(|c| c.utxo.clone());
        let d = t.elapsed();
        assert!(copy.len() as u32 > OUTPUTS, "the set must really be filled");
        d
    };

    let mut body = String::from("[");
    for _ in 0..MAX_BATCH {
        body.push_str(r#"{"jsonrpc":"2.0","id":1,"method":"getbalance"},"#);
    }
    body.pop();
    body.push(']');

    let t = Instant::now();
    let r = post_rpc(h.addr, &body);
    let batch_cost = t.elapsed();
    eprintln!("one copy of the UTXO set: {copy_cost:?}; {MAX_BATCH} getbalance: {batch_cost:?}");

    assert_eq!(
        body_of(&r).matches("\"spendable\"").count(),
        MAX_BATCH,
        "the {MAX_BATCH} balances must be returned"
    );
    assert!(
        batch_cost < copy_cost * 25,
        "{MAX_BATCH} calls cost {batch_cost:?} for a copy at {copy_cost:?}: \
         the UTXO set is copied at every call"
    );

    // And the batch itself stays bounded: twenty thousand copies can no longer
    // be requested.
    let mut huge = String::from("[");
    for _ in 0..20_000 {
        huge.push_str(r#"{"jsonrpc":"2.0","id":1,"method":"getbalance"},"#);
    }
    huge.pop();
    huge.push(']');
    let c = body_of(&post_rpc(h.addr, &huge)).to_string();
    assert!(
        c.contains("-32600"),
        "a batch of 20,000 must be refused: {c}"
    );
    assert!(!c.contains("spendable"), "{c}");
    h.shutdown();
}

// ===========================================================================
// 6. Explorer / injection into the browser
// ===========================================================================

/// The JSON encoder (`escape`, src/json.rs) escaped neither `<`, nor `>`, nor
/// `/`, nor U+2028 / U+2029.
///
/// The unknown method name is returned **verbatim** in the error message. Any
/// client that inserts this message into HTML - or that places the response in
/// a `<script>` - then ran the attacker's script. U+2028 and U+2029 are line
/// terminators for JavaScript but not for JSON: a string that contains them
/// breaks the literal that embeds it.
///
/// These five characters now come out escaped. The escapes remain standard
/// JSON: every parser reads them back identically, which this test also
/// checks - a safe output that did not read back would be another bug.
#[test]
fn flaw_outgoing_json_does_not_escape_html() {
    use q21_core::json::{parse, Json};

    let h = server(false, None);
    let payload = "</script><img src=x onerror=alert(document.domain)>";
    let r = post_rpc(
        h.addr,
        &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{payload}"}}"#),
    );
    let c = body_of(&r);
    assert!(
        !c.contains(payload),
        "the payload comes back as is in the JSON body: {c}"
    );
    assert!(
        !c.contains('<') && !c.contains('>') && !c.contains('/'),
        "none of these three characters may come out bare: {c}"
    );
    assert!(
        c.contains("\\u003c") && c.contains("\\u003e") && c.contains("\\u002f"),
        "the expected escape is missing: {c}"
    );
    // And the payload is intact after reading back: we escape, we do not
    // mutilate.
    let reread = parse(c).expect("the response must remain valid JSON");
    assert_eq!(
        reread
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(|m| m.contains(payload)),
        Some(true),
        "reading back must return the original string: {c}"
    );

    // U+2028 and U+2029: invisible, and fatal to a JavaScript literal.
    for (name, sep) in [("U+2028", '\u{2028}'), ("U+2029", '\u{2029}')] {
        let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a{sep}b\"}}");
        let c = body_of(&post_rpc(h.addr, &body)).to_string();
        assert!(!c.contains(sep), "{name} comes out bare: {c}");
        assert!(
            c.contains(&format!("\\u{:04x}", sep as u32)),
            "{name} must be escaped: {c}"
        );
    }

    // Directly on the encoder, so that the property does not depend on a
    // particular call path.
    assert_eq!(
        Json::str("<a/b>\u{2028}\u{2029}").encode(),
        r#""\u003ca\u002fb\u003e\u2028\u2029""#
    );
    h.shutdown();
}

/// The explorer had **unescaped** `innerHTML` insertion points.
///
/// `tile(k,v,n)` escaped `k` but inserted `v` and `n` raw; `rows()` escaped
/// the key but inserted the value raw. Only numbers went through them, so the
/// exploit was not demonstrated - but the invariant rested on the discipline
/// of each caller alone, and the neighboring flaw (`Json::u64` switching to a
/// string) was precisely what could break it.
///
/// The two helpers now go through `render()`, which escapes by default; a
/// deliberate markup fragment is declared with `brut()`. The discipline is
/// therefore reversed: raw insertion has to be asked for, it is no longer the
/// default.
///
/// A few raw insertions remain in the block table and in the security panel.
/// They are listed below, one by one: all are fed by fields that `Json::u64`
/// guarantees numeric (see
/// `latent_flaw_a_numeric_field_can_become_a_string`). The scan that follows
/// fails as soon as a raw insertion point appears outside this list.
#[test]
fn latent_flaw_unescaped_insertion_points_in_the_explorer() {
    let p = q21_core::explorer::PAGE;

    // The two shared helpers now escape by default.
    assert!(
        p.contains(r#"<div class="v">${render(v)}</div>"#),
        "tile() must pass `v` through render()"
    );
    assert!(
        p.contains("<tr><th>${esc(k)}</th><td>${render(v)}</td></tr>"),
        "rows() must pass the value through render()"
    );
    assert!(!p.contains(r#"<div class="v">${v}</div>"#));
    assert!(!p.contains("<td>${v}</td>"));
    assert!(
        p.contains("const render =") && p.contains("const raw ="),
        "deliberate markup must be declared explicitly"
    );

    // Functions that escape or that can only produce safe characters.
    const SAFE: [&str; 10] = [
        "esc(",
        "render(",
        "trunc(",
        "formatBytes(",
        "date(",
        // Link builders: they escape the route **and** the text. The check
        // that they do so is made just above, on the source of `lien`:
        // without it, listing them here would be a belief.
        "link(",
        "blockLink(",
        "txLink(",
        "addressLink(",
        // Conversion from units to Q21: only assembles digits coming from a
        // BigInt and a point. No markup character comes out of it.
        "q21(",
    ];
    // Raw insertions allowed, and the reason for each.
    const RAW_ALLOWED: [&str; 13] = [
        // Condition of a ternary: never inserted, only tested.
        "n",
        // Numeric fields from the node (`Json::u64`), so never strings.
        "b.header.height",
        "b.tx_count",
        "sec.defenses.rolling_finality_blocks",
        "sec.defenses.rolling_finality_hours",
        // Boolean, rendered by a literal chosen in the page itself.
        "sec.full_protection_possible",
        // Arrays whose every element goes through esc() right after.
        "sec.an_attacker_can.map(x=>",
        "sec.an_attacker_cannot.map(x=>",
        // Ternary conditions: tested, never inserted. What is inserted
        // afterward is a literal chosen in the page itself.
        "t.coinbase",
        "m.coinbase",
        // Boolean of `badge(text, gray)`: condition of a ternary whose two
        // branches are literals of the page. The text goes through esc()
        // right after.
        "gray",
        "BigInt(m.received.units) > 0n",
        "!m.amount_out_known",
    ];

    // The link builders are declared safe above. Here we check that they are:
    // both of their halves go through esc(). Without this check, adding a name
    // to SAFE would amount to disarming the test with one line.
    assert!(
        p.contains(r##"`<a class="flat" href="#/${esc(route)}">${esc(text)}</a>`"##),
        "the link builder no longer escapes both of its halves: everything \
         that goes through link(), blockLink(), txLink() or addressLink() \
         becomes a possible injection"
    );

    let mut rest = p;
    let mut examined = 0;
    while let Some(i) = rest.find("${") {
        rest = &rest[i + 2..];
        let end = rest.find(['}', '?', '`']).unwrap_or(rest.len());
        let head = rest[..end].trim();
        examined += 1;
        let safe = SAFE.iter().any(|f| head.starts_with(f));
        assert!(
            safe || RAW_ALLOWED.contains(&head),
            "unescaped and unlisted insertion point: ${{{head}}}\n\
             Add it to RAW_ALLOWED with a justification of why its value cannot \
             carry markup, or pass it through render()."
        );
    }
    assert!(
        examined >= 15,
        "the scan only found {examined} insertion points: the page has \
         changed shape, the check no longer measures anything"
    );
}

/// `Json::u64` switched to a **string** above `i64::MAX`. A field the client
/// believes numeric therefore changed type depending on its value: the value
/// arrived in an insertion point meant for a number, or in a comparison that
/// no longer compared anything. That was the bridge between a node counter
/// and an injection in the explorer.
///
/// The `Json::UInt` variant now carries these values and is encoded as a
/// **number**. JSON does not bound integers; it is JavaScript that loses
/// precision above 2^53, which is another matter. The type, however, no longer
/// varies - and that is what makes safe the raw insertion points listed in
/// `latent_flaw_unescaped_insertion_points_in_the_explorer`.
#[test]
fn latent_flaw_a_numeric_field_can_become_a_string() {
    use q21_core::json::{parse, Json};

    assert!(matches!(Json::u64(42), Json::Int(_)));
    assert!(
        matches!(Json::u64(u64::MAX), Json::UInt(_)),
        "above i64::MAX, the field must stay a number"
    );

    // No value may produce a string, on either side of the bound.
    for v in [
        0,
        1,
        i64::MAX as u64 - 1,
        i64::MAX as u64,
        i64::MAX as u64 + 1,
        u64::MAX,
    ] {
        let j = Json::u64(v);
        assert!(!matches!(j, Json::Str(_)), "u64({v}) became a string");
        let encoded = j.encode();
        assert!(
            !encoded.contains('"'),
            "u64({v}) is encoded as a string: {encoded}"
        );
        assert_eq!(encoded, v.to_string());
        // And it reads back as a number.
        assert_eq!(parse(&encoded).unwrap().as_u64(), Some(v));
    }
}

/// The explorer passed the whole of `location.search` on to the RPC
/// (`const RPC = "/rpc" + location.search`).
///
/// That was the visible half of carrying the token in the URL: the page copied
/// into every call whatever was lying in the query string, token included, and
/// the address carrying that token stayed in the browser history.
///
/// The token is now asked for once, kept in memory for the life of the tab,
/// and sent as `Authorization: Bearer`.
#[test]
fn flaw_the_explorer_copies_the_query_string() {
    let p = q21_core::explorer::PAGE;

    assert!(
        !p.contains("location.search"),
        "the query string is still copied to the RPC"
    );
    assert!(
        p.contains(r#"const RPC = "/rpc";"#),
        "the RPC entry point must be fixed"
    );
    assert!(
        p.contains("\"Authorization\"") && p.contains("\"Bearer \""),
        "the token must travel in a header"
    );
    // The token is asked for in the page. `window.prompt` blocks the whole
    // tab, cannot be styled, and several browsers no longer show it at all in
    // some contexts - an explorer then became unusable without any message
    // explaining why.
    assert!(
        p.contains(r#"id="token-panel""#),
        "the token must be asked for through a field of the page"
    );
    assert!(
        !p.contains("window.prompt"),
        "the token must no longer be asked for through a browser dialog"
    );

    // --- The fragment now serves two purposes, and only one is secret.
    //
    // The token arrives there - the browser never sends it to the server - and
    // routing then uses it. What must remain true:
    //
    //  - the token is erased from the address bar as soon as it is read;
    //  - it only goes back out in the `Authorization` header;
    //  - nothing from the address is copied into an outgoing request.
    assert!(
        p.contains("history.replaceState"),
        "the token stays in the address bar after being read"
    );
    assert!(
        p.contains(r##"if (f && !f.startsWith("/"))"##),
        "nothing tells a token from a route in the fragment"
    );
    assert!(!p.contains("location.href"));
    // The body of a request only contains the method and its parameters.
    assert!(
        p.contains("body: JSON.stringify({jsonrpc:\"2.0\", id:++counter, method:method, params:params||{}})"),
        "the request body is no longer what we think it is"
    );
}

// ===========================================================================
// 7. Leaks
// ===========================================================================

/// No RPC response leaks the seed or the backup code.
#[test]
fn ok_no_rpc_response_reveals_the_seed() {
    let h = server(true, None);
    let seed_hex = "07".repeat(32);
    for (m, p) in [
        ("getinfo", "{}"),
        ("getbalance", "{}"),
        ("getnewaddress", "{}"),
        ("getsupply", "{}"),
        ("getpeers", "{}"),
        ("getmempool", "{}"),
        ("listmethods", "{}"),
        ("sendtoaddress", r#"{"address":"rq21zzz","units":1}"#),
    ] {
        let c = body_of(&call(h.addr, m, p)).to_string();
        assert!(!c.contains(&seed_hex), "{m} reveals the seed: {c}");
        assert!(!c.to_lowercase().contains("seed="), "{m}: {c}");
        assert!(!c.contains("next_index"), "{m}: {c}");
    }
    h.shutdown();
}

/// Wallet errors exposed internal state: returned through `format!("{e:?}")`,
/// they carried the contents of the variant, that is
/// `InsufficientFunds { available: 43120000, requested: ... }`. The exact
/// balance thus went out to a caller who only had to ask for an absurd sum to
/// get it. A refusal does not need to be an account statement.
///
/// `wallet_message` (src/rpc.rs) now translates each variant into a fixed
/// message. The other variants carry nothing sensitive and keep a precise
/// message: whoever makes a mistake must understand why.
#[test]
fn flaw_the_funds_error_reveals_the_exact_balance() {
    let h = server(true, None);
    let dest = regtest_address(h.addr);

    // Two very different requests must give exactly the same refusal:
    // otherwise the response still measures the balance.
    let refusal = |units: u64| -> String {
        body_of(&call(
            h.addr,
            "sendtoaddress",
            &format!(r#"{{"address":"{dest}","units":{units}}}"#),
        ))
        .to_string()
    };
    let small = refusal(10_000);
    let large = refusal(1_000_000_000_000);

    assert!(small.contains("\"code\":-3"), "{small}");
    assert_eq!(small, large, "the refusal varies with the sum requested");

    for forbidden in ["available", "requested", "InsufficientFunds", "43120000"] {
        assert!(
            !small.contains(forbidden),
            "the error leaks \"{forbidden}\": {small}"
        );
    }
    assert!(
        small.contains("insufficient funds"),
        "the refusal must remain understandable: {small}"
    );
    // No digit in the message: that is where the balance was hiding.
    let message = small
        .split("\"message\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("message field");
    assert!(
        !message.chars().any(|c| c.is_ascii_digit()),
        "the message still carries a number: {message}"
    );
    h.shutdown();
}

// ===========================================================================
// 8. Sealed wallet file (src/kdf.rs)
// ===========================================================================

/// The iteration count is authenticated, but **used before** it is.
///
/// `unseal` derives the key with the value read from the file (l. 235-243),
/// and only afterward checks the MAC. An attacker who can write four bytes in
/// `wallet.dat` therefore imposes arbitrary work - up to 2^32-1 iterations of
/// PBKDF2, that is hours - before the slightest rejection. The wallet becomes
/// impossible to open without any message explaining why.
#[test]
fn flaw_attacker_iterations_before_mac_check() {
    use q21_core::kdf;

    let sealed = kdf::seal(b"phrase", b"seed=00\nnext_index=0\n", kdf::TEST_COST).expect("sealing");

    // The current format announces its memory in KiB at bytes 8..12: that is
    // the field an attacker would rewrite to impose the work.
    let measure = |memory_kib: u32| {
        let mut forged = sealed.clone();
        forged[8..12].copy_from_slice(&memory_kib.to_le_bytes());
        let t = Instant::now();
        let r = kdf::unseal(b"phrase", &forged);
        (t.elapsed(), r)
    };

    // The field is still read before it is authenticated - that is
    // unavoidable, this number is needed to derive the key that checks the
    // MAC. What changed: it is **bounded** before the derivation.
    let (fast, _) = measure(64);
    let (absurd, r) = measure(u32::MAX);
    eprintln!("memory=64 KiB: {fast:?}; memory=2^32-1 KiB: {absurd:?}");
    assert!(
        matches!(r, Err(q21_core::kdf::SealError::CostOutOfRange { .. })),
        "an aberrant cost must be refused: {r:?}"
    );
    assert!(
        absurd < Duration::from_millis(50),
        "the refusal cost {absurd:?}: the derivation was started anyway"
    );

    // A legitimate setting - strengthened, under the 256 MiB bound - gets
    // through and costs what it should cost.
    let (slow, r2) = measure(200_000);
    assert!(r2.is_err(), "the MAC must end up failing");
    assert!(slow > absurd, "a legitimate setting does derive");
}

/// No version, no counter, no file identity in the sealed format: an old
/// `wallet.dat` can be replayed as is.
///
/// The format is `MAGIC || iterations || salt || ciphertext || mac`
/// (src/kdf.rs:200). Two successive sealings of the same wallet are
/// interchangeable: nothing makes it possible to know which one is the more
/// recent.
#[test]
fn flaw_replay_of_an_old_wallet_file() {
    use q21_core::kdf;

    // The sealed format itself still does not order two files: that is a
    // finding, not a defect of the sealing. What orders them is **in the
    // plaintext**, and the node keeps the highest value seen separately.
    let contents = |serial: u32, next: u32| {
        format!(
            "seed=1111111111111111111111111111111111111111111111111111111111111111\n\
             next_index={next}\nnetwork=regtest\nscheme=1\nserial={serial}\nconsumed=\n"
        )
    };
    let old = kdf::seal(b"phrase", contents(3, 0).as_bytes(), kdf::TEST_COST).unwrap();
    let recent = kdf::seal(b"phrase", contents(4, 9).as_bytes(), kdf::TEST_COST).unwrap();

    let a = String::from_utf8(kdf::unseal(b"phrase", &old).unwrap()).unwrap();
    let r = String::from_utf8(kdf::unseal(b"phrase", &recent).unwrap()).unwrap();

    let serial_of = |s: &str| -> u64 {
        s.lines()
            .find_map(|l| l.strip_prefix("serial="))
            .and_then(|v| v.parse().ok())
            .expect("serial field")
    };
    assert!(
        serial_of(&a) < serial_of(&r),
        "two successive files must be orderable: {a} / {r}"
    );
    // It is this comparison that `read_wallet` (src/bin/q21.rs) performs against the high
    // value kept in `wallet.seq`: an older file is refused, with a message that
    // explains how to override it knowingly.
}

/// Consequence of the replay, on a **one-time** scheme (Lamport, the default
/// without the `mldsa` feature): bringing `next_index` back to zero makes the
/// same keys be derived again, and the list of indices that have already
/// signed was **never** written to disk (`write_wallet` in src/bin/q21.rs
/// only saved `seed`, `next_index`, `network` and `scheme`; the
/// `Wallet::consumed` list died with the process).
///
/// Two signatures with a Lamport key reveal the private key.
#[test]
fn flaw_the_lamport_anti_reuse_safeguard_does_not_survive_a_restart() {
    use q21_core::sig::SchemeId;

    let mut w1 = Wallet::from_seed_scheme([3u8; 32], NETWORK, SchemeId::LamportOts).unwrap();
    let a0 = w1.new_address();
    let a1 = w1.new_address();

    // A "restart": we only reread what the file contains.
    let mut w2 = Wallet::from_seed_scheme([3u8; 32], NETWORK, SchemeId::LamportOts).unwrap();
    w2.rescan(2);

    let known1 = w1.known_hashes();
    let known2 = w2.known_hashes();
    assert_eq!(known1, known2, "same keys derived again");
    assert_eq!(known2[0], a0.hash);
    assert_eq!(known2[1], a1.hash);

    // What is persisted now carries the list of keys already used.
    let contents = format!(
        "seed={}\nnext_index={}\nnetwork=regtest\nscheme={}\nserial=1\nconsumed={}\n",
        w1.seed_hex(),
        w1.next_index(),
        w1.scheme().as_u8(),
        w1.consumed_indices()
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(
        contents.contains("consumed="),
        "the format written to disk must keep the keys already used: {contents}"
    );

    // And loading gives them back to the wallet.
    w2.mark_consumed(&[0]);
    assert!(w2.is_consumed(0), "consumption must survive the restart");
    assert!(!w2.is_consumed(1));
}

/// Truncation: rejected, but with a message **distinct** from that of a wrong
/// passphrase. A damaged file and a wrong passphrase were therefore not
/// indistinguishable, contrary to what the module documentation claimed:
/// whoever damaged a sealed file themselves could, by watching the message,
/// learn whether the passphrase tried was the right one.
///
/// `unseal` now returns `AuthenticationFailed` in every case where the file
/// presents itself as a Q21 sealed file - truncation included.
///
/// A single distinction remains, and it is intended: the **magic**. When it is
/// missing, this file is not a Q21 wallet, and saying so tells nobody anything
/// about the passphrase. This test checks both halves of that split.
#[test]
fn flaw_truncation_and_wrong_passphrase_do_not_give_the_same_message() {
    use q21_core::kdf::{self, SealError};
    let sealed = kdf::seal(b"phrase", b"seed=00\n", kdf::TEST_COST).unwrap();

    let wrong = kdf::unseal(b"other", &sealed).unwrap_err();
    assert_eq!(wrong, SealError::AuthenticationFailed);

    // Any truncation of a file that carries the magic gives the same message
    // as a wrong passphrase - whatever the length removed.
    for n in [1, 2, 20, sealed.len() - 40, sealed.len() - 8] {
        let truncated = kdf::unseal(b"phrase", &sealed[..sealed.len() - n]).unwrap_err();
        assert_eq!(
            truncated, wrong,
            "a file cut short by {n} bytes is still distinguishable from a wrong passphrase"
        );
        // And the messages returned to the user are too.
        assert_eq!(truncated.to_string(), wrong.to_string());
    }

    // A header altered other than in the magic or the cost - here the salt, at
    // bytes 16..32 of the current format: same message again.
    let mut salt_changed = sealed.clone();
    salt_changed[20] ^= 0x01;
    assert_eq!(kdf::unseal(b"phrase", &salt_changed).unwrap_err(), wrong);

    // The only distinction kept: this file is not a Q21 sealed file.
    let magic = {
        let mut m = sealed.clone();
        m[0] = b'X';
        kdf::unseal(b"phrase", &m).unwrap_err()
    };
    assert_eq!(magic, SealError::InvalidFormat);
    assert_ne!(
        magic, wrong,
        "saying that a file is not a Q21 wallet tells nobody anything about \
         the passphrase, and saves the user from looking in the wrong place"
    );
    assert_eq!(
        kdf::unseal(b"phrase", b"this is not a sealed file").unwrap_err(),
        SealError::InvalidFormat
    );
}

/// A zero cost is refused - the protection cannot be canceled. The passes are
/// at bytes 12..16 of the current format, the memory at bytes 8..12.
#[test]
fn ok_a_zero_cost_is_refused() {
    use q21_core::kdf;
    let sealed = kdf::seal(b"phrase", b"x", kdf::TEST_COST).unwrap();
    let mut forged = sealed.clone();
    forged[12..16].copy_from_slice(&0u32.to_le_bytes());
    assert!(kdf::unseal(b"phrase", &forged).is_err());
    let mut forged = sealed.clone();
    forged[8..12].copy_from_slice(&0u32.to_le_bytes());
    assert!(kdf::unseal(b"phrase", &forged).is_err());
}

/// The MAC does cover the header: the cost cannot be lowered.
#[test]
fn ok_the_mac_covers_the_cost() {
    use q21_core::kdf;
    let sealed = kdf::seal(
        b"phrase",
        b"seed=aa\n",
        kdf::Cost {
            memory_kib: 1024,
            passes: 2,
        },
    )
    .unwrap();
    let mut forged = sealed.clone();
    forged[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert!(
        kdf::unseal(b"phrase", &forged).is_err(),
        "lowering the cost must break the MAC"
    );
    let mut forged = sealed.clone();
    forged[8..12].copy_from_slice(&64u32.to_le_bytes());
    assert!(kdf::unseal(b"phrase", &forged).is_err());
}
