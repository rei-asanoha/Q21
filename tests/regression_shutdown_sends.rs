//! A send answered "accepted" is never lost by a shutdown.
//!
//! The RPC kept serving while the node wrote its state on the way out: a send
//! answered after the pool had been written went into a pool about to vanish,
//! and was gone at the next start, though the wallet had been told it was
//! sent. In the load test of 25 October 2026, five payments were lost this
//! way, all in the half-second after `stop`.
//!
//! These tests raise the process-wide shutdown flag, so they live alone in
//! this binary and run one at a time.

use q21_core::address::Network;
use q21_core::chain::{genesis_block, Chain, GENESIS_TIME};
use q21_core::consensus::{COINBASE_MATURITY, TARGET_BLOCK_SECS};
use q21_core::json::{parse, Json};
use q21_core::net::Node;
use q21_core::rpc::RpcContext;
use q21_core::shutdown;
use q21_core::wallet::Wallet;
use std::sync::{Arc, Mutex};

const NETWORK: Network = Network::Regtest;

static SERIAL: Mutex<()> = Mutex::new(());

/// An RPC context whose wallet holds many mature coins.
fn funded() -> Arc<RpcContext> {
    let mut w = Wallet::from_seed([0x3c; 32], NETWORK);
    let mut c = Chain::new(NETWORK, genesis_block(NETWORK));
    for i in 1..=(COINBASE_MATURITY + 40) {
        let a = w.new_address();
        let t = GENESIS_TIME + i * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(a.hash, a.scheme, &[], t, 5_000_000)
            .expect("mining");
        c.connect(&b, t + 1).expect("connect");
    }
    Arc::new(RpcContext {
        on_change: None,
        scans: None,
        configured_bootstrap: 0,
        reachable: std::sync::atomic::AtomicBool::new(true),
        reachable_session: true,
        router_status: None,
        set_reachable: None,
        tor: None,
        #[cfg(feature = "mldsa")]
        channels: None,
        index: None,
        mining: None,
        node: Arc::new(Node::new(NETWORK, c)),
        wallet: Some(Arc::new(Mutex::new(w))),
        network: NETWORK,
    })
}

/// Sends a small payment to the wallet's own new address; the txid if it was
/// accepted, the error message otherwise.
fn send(c: &RpcContext, to: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{{"address":"{to}","units":10000}}}}"#
    );
    let r = parse(&c.handle(&body)).expect("valid JSON response");
    if let Some(e) = r.get("error") {
        return Err(e
            .get("message")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string());
    }
    Ok(r.get("result")
        .and_then(|x| x.get("txid"))
        .and_then(Json::as_str)
        .expect("txid")
        .to_string())
}

fn address(c: &RpcContext) -> String {
    let r = parse(&c.handle(r#"{"jsonrpc":"2.0","id":1,"method":"getnewaddress","params":{}}"#))
        .unwrap();
    r.get("result")
        .and_then(|x| x.get("address"))
        .and_then(Json::as_str)
        .unwrap()
        .to_string()
}

/// Once a shutdown is asked for, a send is refused, with a message that says
/// why — not accepted into a pool that is about to vanish.
#[test]
fn a_send_after_a_shutdown_request_is_refused() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = funded();
    let to = address(&c);
    shutdown::shutdown_done();
    assert!(
        send(&c, &to).is_ok(),
        "a send before the shutdown goes through"
    );

    shutdown::request_shutdown();
    let refused = send(&c, &to);
    shutdown::shutdown_done();
    match refused {
        Ok(txid) => panic!("a send was accepted after the shutdown request: {txid}"),
        Err(e) => assert!(e.contains("shutting down"), "unclear refusal: {e}"),
    }
    assert_eq!(
        c.node.mempool_len(),
        1,
        "only the first send is in the pool"
    );
}

/// Every send answered "accepted" while the shutdown starts is in the pool the
/// shutdown writes: sends in progress finish before it, later ones are
/// refused.
#[test]
fn every_send_answered_before_the_shutdown_is_in_the_pool_it_writes() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    shutdown::shutdown_done();
    let c = funded();
    let to = address(&c);
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let senders: Vec<_> = (0..4)
        .map(|_| {
            let (c, to, done) = (c.clone(), to.clone(), done.clone());
            std::thread::spawn(move || {
                let mut accepted = Vec::new();
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    match send(&c, &to) {
                        Ok(txid) => accepted.push(txid),
                        Err(e) if e.contains("shutting down") => return accepted,
                        Err(_) => {}
                    }
                }
                accepted
            })
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // What the node does on the way out: drain, then write the pool.
    shutdown::drain_sends();
    let written: std::collections::HashSet<String> = c
        .node
        .with_mempool(|m| m.ordered_transactions())
        .iter()
        .map(|t| t.txid().to_hex())
        .collect();
    // Senders that kept going past the shutdown stop here.
    std::thread::sleep(std::time::Duration::from_millis(1000));
    done.store(true, std::sync::atomic::Ordering::Relaxed);

    let accepted: Vec<String> = senders
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    shutdown::shutdown_done();
    assert!(accepted.len() > 4, "too few sends to exercise the race");
    let missing: Vec<&String> = accepted.iter().filter(|t| !written.contains(*t)).collect();
    assert!(
        missing.is_empty(),
        "{} of {} accepted sends are missing from the pool the shutdown wrote",
        missing.len(),
        accepted.len()
    );
}
