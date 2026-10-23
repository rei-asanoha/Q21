//! The payment-channel engine, driven end to end over its own messages.
//!
//! Unlike `channel_sim.rs`, which moves balances directly, this runs the real
//! [`q21_core::channel::machine::Machine`] on both sides and passes the real
//! [`q21_core::channel::messages::Message`] bytes between them through an
//! in-memory duplex with an optional one-way latency. It does the opening
//! handshake, N payments in both directions, a cooperative close, and a
//! penalty case where one side broadcasts a revoked state — asserting the
//! on-chain outcomes to the unit and that the penalty is valid before the
//! delay elapses.
//!
//! Run: `cargo run --release --offline --locked --features mldsa --example
//! channel_protocol -- [payments]` (default 24).

#[cfg(feature = "mldsa")]
fn main() {
    sim::main();
}

#[cfg(not(feature = "mldsa"))]
fn main() {
    eprintln!("Needs real signatures: run with --features mldsa.");
}

#[cfg(feature = "mldsa")]
mod sim {
    use q21_core::address::Network;
    use q21_core::channel::keys::ChannelKey;
    use q21_core::channel::machine::Machine;
    use q21_core::channel::messages::Message;
    use q21_core::channel::txbuild::{FeeTier, ACCEPTOR, FUNDER};
    use q21_core::channel::watcher::{classify, OutputRef, Watch, WatchContext};
    use q21_core::channel::Signer;
    use q21_core::consensus::UNITS_PER_COIN;
    use q21_core::hash::Hash256;
    use q21_core::sig::SchemeId;
    use q21_core::tx::{OutPoint, Transaction};
    use q21_core::utxo::{UtxoEntry, UtxoSet};
    use q21_core::validate::check_transaction;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    const NET: Network = Network::Regtest;
    const CAP: u64 = 50 * UNITS_PER_COIN;
    const DELAY: u16 = 12;
    const DEPTH: u16 = 2;
    const RATE: u64 = 10;
    const CLOSE_FEE: u64 = 20_000;
    const PENALTY_FEE: u64 = 20_000;

    fn q21(u: u64) -> String {
        format!("{}.{:08}", u / UNITS_PER_COIN, u % UNITS_PER_COIN)
    }

    /// A fresh per-run journal directory under the system temp dir.
    fn dir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "q21chan-proto-{}-{}-{:?}",
            std::process::id(),
            tag,
            Instant::now()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// One hop across the link: encode, wait the latency, decode. Returns the
    /// decoded message and the bytes on the wire.
    fn hop(msg: &Message, latency: Duration) -> (Message, usize) {
        let bytes = msg.encode();
        let n = bytes.len();
        if !latency.is_zero() {
            std::thread::sleep(latency);
        }
        (Message::decode(&bytes).unwrap(), n)
    }

    fn open_pair(d: &std::path::Path) -> (Machine, Machine, usize) {
        let a_signer = ChannelKey::from_seed(&[2u8; 32]);
        let a_pub = a_signer.pubkey().to_vec();
        let (mut f, open) = Machine::new_funder(
            d.join("f.jrnl"),
            NET,
            Box::new(ChannelKey::from_seed(&[1u8; 32])),
            a_pub,
            CAP,
            DELAY,
            DEPTH,
            RATE,
        )
        .unwrap();
        let (mut a, accept) =
            Machine::accept(d.join("a.jrnl"), NET, Box::new(a_signer), RATE, &open).unwrap();
        let mut handshake_bytes = open.encode().len();
        f.on_accept(&accept).unwrap();
        handshake_bytes += accept.encode().len();
        let outpoint = OutPoint {
            txid: Hash256([9u8; 32]),
            index: 0,
        };
        let funding = f.funding_created(outpoint).unwrap();
        handshake_bytes += funding.encode().len();
        let funding_signed = a.on_funding(&funding).unwrap();
        handshake_bytes += funding_signed.encode().len();
        f.on_funding_signed(&funding_signed).unwrap();
        let r1 = f.funding_confirmed().unwrap();
        let r2 = a.funding_confirmed().unwrap();
        handshake_bytes += r1.encode().len() + r2.encode().len();
        (f, a, handshake_bytes)
    }

    /// Runs one payment update over the link and returns the bytes exchanged.
    fn one_payment(
        initiator: &mut Machine,
        responder: &mut Machine,
        bal: [u64; 2],
        latency: Duration,
    ) -> usize {
        let mut bytes = 0;
        let upd = initiator.propose(bal).unwrap();
        let (upd, n) = hop(&upd, latency);
        bytes += n;
        let ack = responder.on_update(&upd).unwrap();
        let (ack, n) = hop(&ack, latency);
        bytes += n;
        let rev = initiator.on_ack(&ack).unwrap();
        let (rev, n) = hop(&rev, latency);
        bytes += n;
        responder.on_revoke(&rev).unwrap();
        bytes
    }

    /// A deterministic script of `n` payments, alternating directions, moving a
    /// pseudo-random amount while keeping each side above one coin.
    fn script(n: usize) -> Vec<(usize, [u64; 2])> {
        let mut out = Vec::with_capacity(n);
        let mut bal = [CAP, 0u64];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for i in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let amt = 100_000 + x % 3_000_000;
            let payer = i % 2;
            let payer = if bal[payer] >= amt + UNITS_PER_COIN {
                payer
            } else {
                1 - payer
            };
            if bal[payer] < amt + UNITS_PER_COIN {
                continue;
            }
            bal[payer] -= amt;
            bal[1 - payer] += amt;
            out.push((payer, bal));
        }
        out
    }

    pub fn main() {
        let n: usize = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);

        // --- Open, once, and report its cost.
        let d = dir("open");
        let (_f0, _a0, handshake_bytes) = open_pair(&d);
        println!(
            "OPEN  capacity {} Q21, funded by F; handshake {} bytes over 6 messages",
            q21(CAP),
            handshake_bytes
        );
        println!(
            "  usable after 1 + {DEPTH} confirmations; to-self delay {DELAY} blocks"
        );

        let sc = script(n);
        println!(
            "\nBURST {} payments, alternating direction, over the real engine messages",
            sc.len()
        );
        println!(
            "  {:>14} {:>12} {:>14} {:>14}",
            "link one-way", "payments", "payments/s", "bytes/update"
        );
        for latency_ms in [0u64, 50, 250] {
            let latency = Duration::from_millis(latency_ms);
            let d = dir(&format!("burst-{latency_ms}"));
            let (mut f, mut a, _) = open_pair(&d);
            let start = Instant::now();
            let mut bytes = 0usize;
            for &(payer, bal) in &sc {
                bytes += if payer == FUNDER {
                    one_payment(&mut f, &mut a, bal, latency)
                } else {
                    one_payment(&mut a, &mut f, bal, latency)
                };
            }
            let wall = start.elapsed();
            assert_eq!(f.balances(), a.balances(), "both sides agree");
            println!(
                "  {:>14} {:>12} {:>14.1} {:>14}",
                format!("{latency_ms} ms"),
                sc.len(),
                sc.len() as f64 / wall.as_secs_f64(),
                bytes / sc.len().max(1),
            );
        }

        // --- Cooperative close, outcomes exact to the unit.
        {
            let d = dir("close");
            let (mut f, mut a, _) = open_pair(&d);
            for &(payer, bal) in &sc {
                if payer == FUNDER {
                    one_payment(&mut f, &mut a, bal, Duration::ZERO);
                } else {
                    one_payment(&mut a, &mut f, bal, Duration::ZERO);
                }
            }
            let bal = f.balances();
            let close_msg = f.propose_close(CLOSE_FEE).unwrap();
            let signed = a.on_close(&close_msg).unwrap();
            let close_tx = f.on_close_signed(&signed).unwrap();
            let got = |hash: Hash256| -> u64 {
                close_tx
                    .outputs
                    .iter()
                    .filter(|o| o.scheme == SchemeId::MlDsa87 && o.pubkey_hash == hash)
                    .map(|o| o.value.units())
                    .sum()
            };
            let gf = got(f.params().funding[FUNDER]);
            let ga = got(a.params().funding[ACCEPTOR]);
            println!(
                "\nCLOSE cooperative: channel F {} A {}  on chain F {} (fee {}) A {}",
                q21(bal[FUNDER]),
                q21(bal[ACCEPTOR]),
                q21(gf),
                q21(CLOSE_FEE),
                q21(ga),
            );
            assert_eq!(gf + ga + CLOSE_FEE, CAP, "exact to the unit");
            println!("  conserved to the unit: yes (weight {})", close_tx.weight(q21_core::consensus::WITNESS_DISCOUNT));
        }

        // --- Penalty: F broadcasts a revoked state; A punishes before D.
        {
            let d = dir("penalty");
            let (mut f, mut a, _) = open_pair(&d);
            // A few payments so an old state is genuinely revoked.
            let mut states = vec![[CAP, 0u64]];
            for (i, &(payer, bal)) in sc.iter().take(4).enumerate() {
                let _ = i;
                if payer == FUNDER {
                    one_payment(&mut f, &mut a, bal, Duration::ZERO);
                } else {
                    one_payment(&mut a, &mut f, bal, Duration::ZERO);
                }
                states.push(bal);
            }
            let k = f.local_commit_number().unwrap();
            let revoked_state = k - 1;
            let cheat = f.signed_commitment_at(revoked_state, FeeTier::Low).unwrap();

            // A watches the chain: a UTXO view holding the broadcast outputs.
            let born = 1_000u64;
            let mut utxo = UtxoSet::new();
            for (idx, out) in cheat.outputs.iter().enumerate() {
                utxo.insert(
                    OutPoint { txid: cheat.txid(), index: idx as u32 },
                    UtxoEntry { output: *out, height: born, is_coinbase: false },
                );
            }
            let decision = {
                let ctx = WatchContext {
                    params: a.params(),
                    our_index: a.our_index(),
                    store: a.revocation_store(),
                    latest_state: k,
                };
                classify(&ctx, a.funding_outpoint().unwrap(), &cheat)
            };
            let Watch::RevokedByPeer { state, to_local, .. } = &decision else {
                panic!("expected a revoked broadcast, got {decision:?}");
            };
            assert_eq!(*state, revoked_state);
            let to_local = *to_local;

            let penalty = a
                .build_penalty(&decision, a.params().funding[ACCEPTOR], PENALTY_FEE)
                .unwrap();
            // The penalty is valid in the very next block — before F's delay.
            check_transaction(&penalty, &utxo, NET, born + 1, &mut HashSet::new())
                .expect("penalty valid immediately");
            // F's own sweep of the same output is refused until block born+DELAY.
            let cheater_sweep = f
                .build_local_sweep(
                    &Watch::OurCommitment { state: *state, to_local: Some(to_local), delay: DELAY },
                    f.params().funding[FUNDER],
                    PENALTY_FEE,
                )
                .unwrap();
            assert!(
                check_transaction(&cheater_sweep, &utxo, NET, born + 1, &mut HashSet::new()).is_err(),
                "cheater must not sweep before its delay"
            );
            assert!(
                check_transaction(&cheater_sweep, &utxo, NET, born + DELAY as u64, &mut HashSet::new())
                    .is_ok(),
                "cheater could sweep only at born+DELAY — too late"
            );

            // A also claims its to_remote on the same commitment.
            let mut a_recovered = penalty.outputs[0].value.units();
            if let Some((idx, out)) = cheat.outputs.iter().enumerate().find(|(_, o)| {
                o.scheme == SchemeId::MlDsa87 && o.pubkey_hash == a.params().funding[ACCEPTOR]
            }) {
                let claim = a.build_to_remote_claim(
                    &OutputRef {
                        outpoint: OutPoint { txid: cheat.txid(), index: idx as u32 },
                        output: *out,
                    },
                    a.params().funding[ACCEPTOR],
                    PENALTY_FEE,
                );
                check_transaction(&claim, &utxo, NET, born + 1, &mut HashSet::new()).unwrap();
                a_recovered += claim.outputs[0].value.units();
            }
            let fair = f.balances()[ACCEPTOR];
            println!(
                "\nPENALTY F broadcast revoked state {revoked_state} (current {k})"
            );
            println!(
                "  A sweeps F's to_local in the next block (penalty weight {}), {} blocks before F's delay",
                penalty.weight(q21_core::consensus::WITNESS_DISCOUNT),
                DELAY - 1
            );
            println!(
                "  A recovers {} Q21 (its fair balance is {}); the cheater keeps nothing",
                q21(a_recovered),
                q21(fair)
            );
            assert!(a_recovered >= fair, "the honest party never loses");
            let _ = Transaction::txid;
        }

        println!("\nAll protocol assertions held.");
    }
}
