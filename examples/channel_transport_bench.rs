//! What the channel transport costs: the handshake, in CPU and over a link
//! with a one-way latency, and the record layer per frame.
//!
//! Each handshake frame is handed to the other side after the link's
//! latency, as a P2P connection would; the session is up at the initiator
//! after one round trip (it may send at once, its `Fin` ahead of its
//! records) and at the responder half a round trip later.
//!
//! Run: `cargo run --release --offline --locked --features mldsa --example
//! channel_transport_bench -- [rounds]` (default 20).

#[cfg(feature = "mldsa")]
fn main() {
    bench::main();
}

#[cfg(not(feature = "mldsa"))]
fn main() {
    eprintln!("Needs real signatures: run with --features mldsa.");
}

#[cfg(feature = "mldsa")]
mod bench {
    use q21_core::address::Network;
    use q21_core::channel::keys::NodeIdentity;
    use q21_core::channel::transport::{Context, Initiator, Responder, MAX_RECORD};
    use std::time::{Duration, Instant};

    fn ms(d: Duration) -> f64 {
        d.as_secs_f64() * 1000.0
    }

    fn median(mut v: Vec<f64>) -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    }

    pub fn main() {
        let rounds: usize = std::env::args()
            .nth(1)
            .and_then(|a| a.parse().ok())
            .unwrap_or(20);
        let a = NodeIdentity::derive(&[1; 32]);
        let b = NodeIdentity::derive(&[2; 32]);
        let ctx = Context {
            network: Network::Regtest,
            initiator_nonce: 1,
            responder_nonce: 2,
        };

        // CPU of each step.
        let (mut init, mut resp, mut fin_i, mut fin_r) = (vec![], vec![], vec![], vec![]);
        for _ in 0..rounds {
            let t = Instant::now();
            let (i, m1) = Initiator::start(&a, ctx).unwrap();
            init.push(ms(t.elapsed()));
            let t = Instant::now();
            let (r, m2) = Responder::accept(&b, ctx, &m1).unwrap();
            resp.push(ms(t.elapsed()));
            let t = Instant::now();
            let (_, _, m3) = i.finish(&a, &m2).unwrap();
            fin_i.push(ms(t.elapsed()));
            let t = Instant::now();
            r.finish(&m3).unwrap();
            fin_r.push(ms(t.elapsed()));
        }
        let (i0, r0, i1, r1) = (median(init), median(resp), median(fin_i), median(fin_r));
        println!("handshake CPU, median of {rounds} (ms):");
        println!(
            "  initiator: Init {i0:.2}, Resp -> Fin {i1:.2}  (total {:.2})",
            i0 + i1
        );
        println!(
            "  responder: Init -> Resp {r0:.2}, Fin {r1:.2}  (total {:.2})",
            r0 + r1
        );

        // Over a link: each frame is delivered after the one-way latency.
        for latency in [0u64, 250] {
            let link = Duration::from_millis(latency);
            let (mut up_i, mut up_r) = (vec![], vec![]);
            for _ in 0..rounds.min(5) {
                let t = Instant::now();
                let (i, m1) = Initiator::start(&a, ctx).unwrap();
                std::thread::sleep(link);
                let (r, m2) = Responder::accept(&b, ctx, &m1).unwrap();
                std::thread::sleep(link);
                let (_, _, m3) = i.finish(&a, &m2).unwrap();
                up_i.push(ms(t.elapsed()));
                std::thread::sleep(link);
                r.finish(&m3).unwrap();
                up_r.push(ms(t.elapsed()));
            }
            println!(
                "handshake over a {latency} ms one-way link: session up at the initiator in {:.1} ms, at the responder in {:.1} ms",
                median(up_i),
                median(up_r)
            );
        }

        // Records.
        let (i, m1) = Initiator::start(&a, ctx).unwrap();
        let (r, m2) = Responder::accept(&b, ctx, &m1).unwrap();
        let (mut si, _, m3) = i.finish(&a, &m2).unwrap();
        let (mut sr, _) = r.finish(&m3).unwrap();
        for size in [100usize, 14_000, MAX_RECORD] {
            let frame = vec![0x5a; size];
            let n = 200;
            let t = Instant::now();
            for _ in 0..n {
                let rec = si.seal(&frame).unwrap();
                sr.open(&rec).unwrap();
            }
            println!(
                "record of {size} bytes: seal + open {:.1} us",
                t.elapsed().as_secs_f64() * 1e6 / n as f64
            );
        }
    }
}
