//! What paying through a payment channel feels like, measured.
//!
//! Two parties, A and B, run a channel over TCP on 127.0.0.1, through a
//! proxy that adds a one-way latency and, optionally, a bandwidth limit. The
//! chain is a regtest [`Chain`] in this process, used for what touches it:
//! the funding, the cooperative close, and a revoked commitment punished.
//!
//! Every signature is a real ML-DSA-87 signature over the real policy
//! sighash, and every commitment a party accepts goes through
//! `validate::check_transaction` against the funding output, as if it were
//! about to be broadcast.
//!
//! # One payment, from payer P to payee Q
//!
//! ```text
//! P -> Q  Propose { amount, P's signature of Q's new commitment }
//!         Q co-signs its commitment, validates it: Q can enforce the new
//!         balance ("received")
//! Q -> P  Accept  { Q's signature of P's new commitment,
//!                   Q's secret revoking its previous state, next hash }
//!         P validates its commitment, checks the secret: the payment can
//!         no longer be undone ("paid")
//! P -> Q  Revoke  { P's secret revoking its previous state, next hash }
//!         Q checks it: P can no longer broadcast the old state ("settled")
//! ```
//!
//! Run: `cargo run --release --offline --locked --features mldsa --example
//! channel_sim -- [burst_seconds] [batch]` (defaults 30 and 25: the burst
//! of 1,000 payments stops early on slow links, and its rate is reported as
//! such; `batch` is how many queued payments one state update may carry, 1
//! for one update per payment).

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
    use ml_dsa::{signature::Keypair, MlDsa87, Signer, SigningKey, B32};
    use q21_core::address::Network;
    use q21_core::amount::Amount;
    use q21_core::block::Block;
    use q21_core::chain::{genesis_block, Chain};
    use q21_core::consensus::{
        COINBASE_MATURITY, MIN_OUTPUT_VALUE, TARGET_BLOCK_SECS, UNITS_PER_COIN, WITNESS_DISCOUNT,
    };
    use q21_core::hash::Hash256;
    use q21_core::policy::{self, Policy, Satisfaction};
    use q21_core::sha256::sha256;
    use q21_core::shachain;
    use q21_core::sig::{self, SchemeId};
    use q21_core::tx::{OutPoint, Transaction, TxIn, TxOut, Witness};
    use q21_core::utxo::{UtxoEntry, UtxoSet};
    use q21_core::validate::check_transaction;
    use std::collections::{HashMap, HashSet};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    const NET: Network = Network::Regtest;
    const CAPACITY: u64 = 50 * UNITS_PER_COIN;
    /// Fee of a commitment, paid by the funder A, as in Lightning.
    const COMMIT_FEE: u64 = 20_000;
    const CLOSE_FEE: u64 = 20_000;
    const PENALTY_FEE: u64 = 20_000;
    /// to_self delay of the commitments, in blocks.
    const DELAY: u16 = 144;
    /// Confirmations before the channel is used.
    const DEPTH: u64 = 3;
    const SINGLES: [u64; 10] = [
        10_000,
        50_000,
        100_000,
        500_000,
        1_000_000,
        5_000_000,
        10_000_000,
        50_000_000,
        100_000_000,
        500_000_000,
    ];
    const BURST: usize = 1_000;

    // --- Keys --------------------------------------------------------------

    struct Key {
        sk: SigningKey<MlDsa87>,
        pk: Vec<u8>,
    }

    impl Key {
        fn new(n: u8) -> Key {
            let sk = SigningKey::<MlDsa87>::from_seed(&B32::from([n; 32]));
            let pk = sk.verifying_key().encode()[..].to_vec();
            Key { sk, pk }
        }
        fn hash(&self) -> Hash256 {
            sig::pubkey_hash(SchemeId::MlDsa87, &self.pk)
        }
        fn sign(&self, m: &Hash256) -> Vec<u8> {
            self.sk.sign(m.as_bytes()).encode()[..].to_vec()
        }
    }

    fn key_out(hash: Hash256, v: u64) -> TxOut {
        TxOut {
            value: Amount::from_units(v),
            scheme: SchemeId::MlDsa87,
            pubkey_hash: hash,
        }
    }

    fn leaf(hash: Hash256) -> Policy {
        Policy::Key {
            scheme: SchemeId::MlDsa87,
            pubkey_hash: hash,
        }
    }

    fn one_input(op: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: op,
                witness: Witness::default(),
                sequence: u32::MAX,
            }],
            outputs,
            lock_time: 0,
        }
    }

    // --- The channel's transactions ---------------------------------------

    /// Index 0 is A, 1 is B: also their leaf positions in the funding policy.
    #[derive(Clone)]
    struct Channel {
        hashes: [Hash256; 2],
        fund_p: Policy,
        fund_op: OutPoint,
        fund_out: TxOut,
    }

    impl Channel {
        /// `holder`'s commitment for balances `bal`, with `rev` the hash of
        /// the holder's secret for this state. Outputs below the dust floor
        /// are left out (they go to the fee).
        fn commitment(
            &self,
            holder: usize,
            n: usize,
            bal: [u64; 2],
            rev: Hash256,
        ) -> (Transaction, Policy) {
            let other = 1 - holder;
            let mut side = bal;
            side[0] -= COMMIT_FEE;
            let to_local = self.to_local(holder, rev);
            let mut outs = Vec::new();
            if side[holder] >= MIN_OUTPUT_VALUE {
                outs.push(to_local.output(Amount::from_units(side[holder])));
            } else {
                trim(side[holder]);
            }
            if side[other] >= MIN_OUTPUT_VALUE {
                outs.push(key_out(self.hashes[other], side[other]));
            } else {
                trim(side[other]);
            }
            let mut tx = one_input(self.fund_op, outs);
            // The state number, obscured, where the chain will show it: a
            // watcher reads it back from a broadcast commitment and needs no
            // record per state. `lock_time` is committed in the txid and the
            // sighash, and is not enforced.
            tx.lock_time = n as u64 ^ self.obscurer();
            (tx, to_local)
        }

        fn to_local(&self, holder: usize, rev: Hash256) -> Policy {
            Policy::Any(vec![
                Policy::All(vec![leaf(self.hashes[1 - holder]), Policy::Preimage(rev)]),
                Policy::All(vec![leaf(self.hashes[holder]), Policy::Older(DELAY)]),
            ])
        }

        /// 48 bits derived from both keys, as BOLT 3 obscures the
        /// commitment number from third parties.
        fn obscurer(&self) -> u64 {
            let mut b = self.hashes[0].0.to_vec();
            b.extend_from_slice(self.hashes[1].as_bytes());
            let h = sha256(&b);
            u64::from_le_bytes(h[..8].try_into().unwrap()) & shachain::MAX_INDEX
        }

        /// The state of a commitment found on the chain.
        fn state_of(&self, tx: &Transaction) -> usize {
            (tx.lock_time ^ self.obscurer()) as usize
        }

        fn sighash(&self, tx: &Transaction, signer: usize) -> Hash256 {
            // The funding policy has no `Any`: no choices to sign.
            policy::sighash(tx, 0, NET, &self.fund_out, &self.fund_p, signer as u8, &[])
        }

        fn complete(&self, tx: &mut Transaction, sigs: [Vec<u8>; 2], pks: [&[u8]; 2]) {
            let s = Satisfaction::All(
                (0..2)
                    .map(|i| Satisfaction::Key {
                        pubkey: pks[i].to_vec(),
                        signature: sigs[i].clone(),
                    })
                    .collect(),
            );
            tx.inputs[0].witness = policy::witness(&self.fund_p, &s);
        }
    }

    /// Outputs below the dust floor are never created: their value goes to
    /// the fee, and every such trim is counted here and reported.
    static TRIMMED: AtomicU64 = AtomicU64::new(0);
    static TRIMMED_UNITS: AtomicU64 = AtomicU64::new(0);

    fn trim(v: u64) {
        if v > 0 {
            TRIMMED.fetch_add(1, Ordering::Relaxed);
            TRIMMED_UNITS.fetch_add(v, Ordering::Relaxed);
        }
    }

    // --- Wire: length-prefixed frames ---------------------------------------

    fn send(s: &mut TcpStream, kind: u8, body: &[u8]) -> usize {
        let mut f = Vec::with_capacity(body.len() + 5);
        f.extend_from_slice(&(body.len() as u32 + 1).to_le_bytes());
        f.push(kind);
        f.extend_from_slice(body);
        s.write_all(&f).expect("send");
        f.len()
    }

    fn recv_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
        let mut len = [0u8; 4];
        s.read_exact(&mut len).ok()?;
        let mut f = vec![0u8; u32::from_le_bytes(len) as usize];
        s.read_exact(&mut f).ok()?;
        Some(f)
    }

    fn recv(s: &mut TcpStream, kind: u8) -> (Vec<u8>, usize) {
        let f = recv_frame(s).expect("peer closed");
        assert_eq!(f[0], kind, "unexpected message");
        let n = f.len() + 4;
        (f[1..].to_vec(), n)
    }

    const HELLO: u8 = 1;
    const SIG0: u8 = 2;
    const PROPOSE: u8 = 3;
    const ACCEPT: u8 = 4;
    const REVOKE: u8 = 5;

    // --- The delay proxy -----------------------------------------------------

    #[derive(Clone, Copy)]
    struct Link {
        name: &'static str,
        latency_ms: u64,
        /// Bytes per second; zero for unlimited.
        bandwidth: u64,
    }

    /// One direction: frames are timestamped on arrival, then delivered after
    /// the time to serialize them on the link plus the latency.
    fn pipe(mut from: TcpStream, mut to: TcpStream, link: Link) {
        let (tx, rx) = mpsc::channel::<(Instant, Vec<u8>)>();
        thread::spawn(move || {
            while let Some(f) = recv_frame(&mut from) {
                if tx.send((Instant::now(), f)).is_err() {
                    break;
                }
            }
        });
        thread::spawn(move || {
            let mut free = Instant::now();
            for (arrived, f) in rx {
                let start = free.max(arrived);
                let on_wire = if link.bandwidth == 0 {
                    Duration::ZERO
                } else {
                    Duration::from_secs_f64((f.len() + 4) as f64 / link.bandwidth as f64)
                };
                free = start + on_wire;
                let deliver = free + Duration::from_millis(link.latency_ms);
                if let Some(wait) = deliver.checked_duration_since(Instant::now()) {
                    thread::sleep(wait);
                }
                let mut out = (f.len() as u32).to_le_bytes().to_vec();
                out.extend_from_slice(&f);
                if to.write_all(&out).is_err() {
                    break;
                }
            }
        });
    }

    /// A <-> proxy <-> B. Returns A's and B's ends.
    fn connect(link: Link) -> (TcpStream, TcpStream) {
        let lb = TcpListener::bind("127.0.0.1:0").unwrap();
        let lp = TcpListener::bind("127.0.0.1:0").unwrap();
        let (pb, pp) = (lb.local_addr().unwrap(), lp.local_addr().unwrap());
        let a = TcpStream::connect(pp).unwrap();
        let (proxy_a, _) = lp.accept().unwrap();
        let proxy_b = TcpStream::connect(pb).unwrap();
        let (b, _) = lb.accept().unwrap();
        for s in [&a, &b, &proxy_a, &proxy_b] {
            s.set_nodelay(true).unwrap();
        }
        pipe(
            proxy_a.try_clone().unwrap(),
            proxy_b.try_clone().unwrap(),
            link,
        );
        pipe(proxy_b, proxy_a, link);
        (a, b)
    }

    // --- A party -------------------------------------------------------------

    #[derive(Default, Clone, Copy)]
    struct Stamp {
        t0: Duration,
        received: Duration,
        paid: Duration,
        settled: Duration,
        bytes: usize,
    }

    #[derive(Default)]
    struct Cpu {
        sign: Duration,
        verify: Duration,
        signs: u32,
        verifies: u32,
    }

    struct Party {
        me: usize,
        key: Key,
        their_pk: Vec<u8>,
        ch: Channel,
        utxo: UtxoSet,
        height: u64,
        bal: [u64; 2],
        /// Every secret of mine derives from it (BOLT 3 shachain).
        seed: [u8; 32],
        /// The other side's announced hashes not yet revoked: two at most.
        their_hashes: HashMap<usize, Hash256>,
        /// The other side's revealed secrets, compact: at most 49 entries.
        store: shachain::Store,
        /// Every commitment of mine with the counterparty's signature (the
        /// last one is current; the others are there to cheat with, for A).
        history: Vec<(Transaction, Vec<u8>)>,
        cpu: Cpu,
    }

    impl Party {
        fn my_secret(&self, n: usize) -> [u8; 32] {
            shachain::derive(&self.seed, shachain::MAX_INDEX - n as u64)
        }

        fn secret(&mut self, n: usize) -> Hash256 {
            Hash256(sha256(&self.my_secret(n)))
        }

        fn sign(&mut self, m: &Hash256) -> Vec<u8> {
            let t = Instant::now();
            let s = self.key.sign(m);
            self.cpu.sign += t.elapsed();
            self.cpu.signs += 1;
            s
        }

        /// The other's commitment for state `n`, signed by me.
        fn sign_theirs(&mut self, n: usize, bal: [u64; 2]) -> Vec<u8> {
            let (tx, _) = self
                .ch
                .commitment(1 - self.me, n, bal, self.their_hashes[&n]);
            let m = self.ch.sighash(&tx, self.me);
            self.sign(&m)
        }

        /// My commitment for state `n` with their signature: co-signed and
        /// validated as for a broadcast. Panics if it is not valid.
        fn accept_mine(&mut self, n: usize, bal: [u64; 2], theirs: Vec<u8>) {
            let rev = self.secret(n);
            let (tx, _) = self.ch.commitment(self.me, n, bal, rev);
            // Only the counterparty's half is checked: the holder signs its
            // own half when, and if, it broadcasts.
            let t = Instant::now();
            policy::check_signature(
                &tx,
                0,
                NET,
                &self.ch.fund_out,
                &self.ch.fund_p.encode(),
                (1 - self.me) as u8,
                &[],
                &self.their_pk,
                &theirs,
            )
            .expect("the counterparty's signature must be valid");
            self.cpu.verify += t.elapsed();
            self.cpu.verifies += 1;
            self.history.push((tx, theirs));
        }

        /// My commitment of state `n`, completed with my own signature and
        /// validated in full, ready to broadcast.
        fn broadcastable(&self, n: usize) -> Transaction {
            let (mut tx, theirs) = self.history[n].clone();
            let mut sigs = [Vec::new(), Vec::new()];
            sigs[self.me] = self.key.sign(&self.ch.sighash(&tx, self.me));
            sigs[1 - self.me] = theirs;
            let mut pks: [&[u8]; 2] = [&[], &[]];
            pks[self.me] = &self.key.pk;
            pks[1 - self.me] = &self.their_pk;
            self.ch.complete(&mut tx, sigs, pks);
            check_transaction(&tx, &self.utxo, NET, self.height, &mut HashSet::new())
                .expect("the commitment must be valid");
            tx
        }

        /// Checks the other's revocation of its state `n`.
        fn take_revocation(&mut self, n: usize, secret: [u8; 32]) {
            let announced = self.their_hashes.remove(&n).expect("announced hash");
            assert_eq!(Hash256(sha256(&secret)), announced, "bad revocation");
            self.store
                .insert(secret, shachain::MAX_INDEX - n as u64)
                .expect("a secret consistent with the earlier ones");
        }

        fn revocation(&mut self, n: usize) -> Vec<u8> {
            let next = self.secret(n + 2);
            let mut b = self.my_secret(n).to_vec();
            b.extend_from_slice(next.as_bytes());
            b
        }

        fn note_next(&mut self, b: &[u8]) -> [u8; 32] {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b[..32]);
            let next = self.their_hashes.keys().max().map_or(0, |k| k + 1);
            self.their_hashes
                .insert(next, Hash256(b[32..64].try_into().unwrap()));
            s
        }

        /// Runs the script: one state update per entry, `(payer, amount)`.
        fn run(
            &mut self,
            s: &mut TcpStream,
            script: &[(usize, u64)],
            epoch: Instant,
        ) -> Vec<Stamp> {
            let now = || epoch.elapsed();
            // Opening: next hashes, then signatures of commitment 0.
            let mut hello = self.secret(0).0.to_vec();
            hello.extend_from_slice(self.secret(1).as_bytes());
            send(s, HELLO, &hello);
            let (h, _) = recv(s, HELLO);
            self.their_hashes = HashMap::from([
                (0, Hash256(h[..32].try_into().unwrap())),
                (1, Hash256(h[32..].try_into().unwrap())),
            ]);
            let mut bal = self.bal;
            let sig0 = self.sign_theirs(0, bal);
            send(s, SIG0, &sig0);
            let (theirs, _) = recv(s, SIG0);
            self.accept_mine(0, bal, theirs);

            let mut stamps = Vec::with_capacity(script.len());
            for (i, &(payer, amount)) in script.iter().enumerate() {
                let n = i + 1;
                let mut st = Stamp::default();
                let mut next = bal;
                next[payer] -= amount;
                next[1 - payer] += amount;
                if self.me == payer {
                    st.t0 = now();
                    let sig = self.sign_theirs(n, next);
                    let mut body = amount.to_le_bytes().to_vec();
                    body.extend_from_slice(&sig);
                    st.bytes += send(s, PROPOSE, &body);
                    let (acc, k) = recv(s, ACCEPT);
                    st.bytes += k;
                    let ss = sig::SchemeId::MlDsa87.sig_len();
                    self.accept_mine(n, next, acc[..ss].to_vec());
                    let secret = self.note_next(&acc[ss..]);
                    self.take_revocation(n - 1, secret);
                    st.paid = now();
                    let rev = self.revocation(n - 1);
                    st.bytes += send(s, REVOKE, &rev);
                } else {
                    let (prop, k) = recv(s, PROPOSE);
                    st.bytes += k;
                    assert_eq!(u64::from_le_bytes(prop[..8].try_into().unwrap()), amount);
                    self.accept_mine(n, next, prop[8..].to_vec());
                    st.received = now();
                    let mut body = self.sign_theirs(n, next);
                    body.extend_from_slice(&self.revocation(n - 1));
                    st.bytes += send(s, ACCEPT, &body);
                    let (rev, k) = recv(s, REVOKE);
                    st.bytes += k;
                    let secret = self.note_next(&rev);
                    self.take_revocation(n - 1, secret);
                    st.settled = now();
                }
                bal = next;
                stamps.push(st);
            }
            self.bal = bal;
            stamps
        }
    }

    // --- The chain -------------------------------------------------------------

    struct Regtest {
        c: Chain,
        miner: Hash256,
        blocks: Vec<Block>,
    }

    impl Regtest {
        fn mine(&mut self, txs: &[Transaction]) {
            let t = self.c.tip().time + TARGET_BLOCK_SECS;
            let b = self
                .c
                .mine_block(self.miner, SchemeId::MlDsa87, txs, t, 50_000_000)
                .expect("mining");
            self.c.connect(&b, t + 1).expect("block refused");
            self.blocks.push(b);
        }
        fn height(&self) -> u64 {
            self.c.height()
        }
    }

    /// A chain where A has mined enough mature coinbases for the capacity.
    /// The slow start keeps early rewards small: about 1.2 Q21 per block
    /// near height 1,800, so the funding gathers some forty coinbases.
    fn chain_and_funding(a: &Key, b: &Key) -> (Regtest, Channel, Transaction) {
        let mut r = Regtest {
            c: Chain::new(NET, genesis_block(NET)),
            miner: a.hash(),
            blocks: Vec::new(),
        };
        while r.height() < 1_800 + COINBASE_MATURITY {
            r.mine(&[]);
        }
        let mut coins = Vec::new();
        let mut total = 0;
        let mut h = 1_800;
        while total < CAPACITY + COMMIT_FEE {
            let cb = &r.blocks[h - 1].transactions[0];
            coins.push((
                OutPoint {
                    txid: cb.txid(),
                    index: 0,
                },
                cb.outputs[0],
            ));
            total += cb.outputs[0].value.units();
            h -= 1;
        }
        let fund_p = Policy::All(vec![leaf(a.hash()), leaf(b.hash())]);
        let mut funding = Transaction {
            version: 1,
            inputs: coins
                .iter()
                .map(|(op, _)| TxIn {
                    prev_out: *op,
                    witness: Witness::default(),
                    sequence: u32::MAX,
                })
                .collect(),
            outputs: vec![fund_p.output(Amount::from_units(CAPACITY))],
            lock_time: 0,
        };
        let change = total - CAPACITY - COMMIT_FEE;
        if change >= MIN_OUTPUT_VALUE {
            funding.outputs.push(key_out(a.hash(), change));
        }
        for (i, (_, o)) in coins.iter().enumerate() {
            let m = funding.sighash(i as u32, NET, o);
            funding.inputs[i].witness = Witness {
                pubkey: a.pk.clone(),
                signature: a.sign(&m),
            };
        }
        let ch = Channel {
            hashes: [a.hash(), b.hash()],
            fund_p,
            fund_op: OutPoint {
                txid: funding.txid(),
                index: 0,
            },
            fund_out: funding.outputs[0],
        };
        (r, ch, funding)
    }

    /// Payments of the script: the ten fixed amounts from A, then a burst of
    /// random amounts, log-uniform over the same range. The burst pays from
    /// whichever side can afford it while keeping one coin, so that a
    /// thousand payments fit in a 50 Q21 channel.
    fn script(seed: u64) -> Vec<(usize, u64)> {
        let mut s: Vec<(usize, u64)> = SINGLES.iter().map(|&v| (0, v)).collect();
        let mut bal = [CAPACITY, 0];
        for &(_, v) in &s {
            bal[0] -= v;
            bal[1] += v;
        }
        let mut x = seed;
        let (lo, hi) = ((SINGLES[0] as f64).ln(), (SINGLES[9] as f64).ln());
        for _ in 0..BURST {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let u = (x >> 11) as f64 / (1u64 << 53) as f64;
            let v = (lo + u * (hi - lo)).exp() as u64;
            let payer = if bal[0] >= v + UNITS_PER_COIN { 0 } else { 1 };
            bal[payer] -= v;
            bal[1 - payer] += v;
            s.push((payer, v));
        }
        s
    }

    /// Groups the burst into state updates of up to `max` consecutive
    /// payments in the same direction, each update moving their sum: what a
    /// wallet does with the payments that queue up while an update is in
    /// flight. The ten single payments stay one per update. Returns the
    /// updates and the number of payments each carries.
    fn batched(script: &[(usize, u64)], max: usize) -> (Vec<(usize, u64)>, Vec<usize>) {
        let mut updates: Vec<(usize, u64)> = script[..SINGLES.len()].to_vec();
        let mut counts = vec![1; SINGLES.len()];
        for &(payer, v) in &script[SINGLES.len()..] {
            let last = updates.len() - 1;
            let joins =
                updates.len() > SINGLES.len() && updates[last].0 == payer && counts[last] < max;
            if joins {
                updates[last].1 += v;
                counts[last] += 1;
            } else {
                updates.push((payer, v));
                counts.push(1);
            }
        }
        (updates, counts)
    }

    struct Run {
        stamps: Vec<Stamp>,
        a: Party,
        b: Party,
        wall: Duration,
    }

    fn party(me: usize, key: Key, their_pk: Vec<u8>, ch: &Channel, r: &Regtest) -> Party {
        let mut utxo = UtxoSet::new();
        utxo.insert(
            ch.fund_op,
            UtxoEntry {
                output: ch.fund_out,
                height: r.height() - DEPTH,
                is_coinbase: false,
            },
        );
        Party {
            me,
            key,
            their_pk,
            ch: ch.clone(),
            utxo,
            height: r.height() + 1,
            bal: [CAPACITY, 0],
            seed: q21_core::rng::bytes().expect("system randomness"),
            their_hashes: HashMap::new(),
            store: shachain::Store::new(),
            history: Vec::new(),
            cpu: Cpu::default(),
        }
    }

    /// Runs `script` over `link`, with the burst cut at `budget`.
    fn run_channel(
        ch: &Channel,
        r: &Regtest,
        link: Link,
        script: &[(usize, u64)],
        budget: Duration,
    ) -> Run {
        // The burst is cut by time, but both sides must agree on where: the
        // cut is estimated from the latency (three one-way trips per
        // payment) before the run, and is the same script for both.
        let (sa, sb) = connect(link);
        let mut pa = party(0, Key::new(1), Key::new(2).pk, ch, r);
        let mut pb = party(1, Key::new(2), Key::new(1).pk, ch, r);
        let per_payment = 3.0 * link.latency_ms as f64 / 1000.0 + 0.01;
        let n = SINGLES.len()
            + ((budget.as_secs_f64() / per_payment) as usize).min(script.len() - SINGLES.len());
        let script = script[..n].to_vec();
        let epoch = Instant::now();
        let sc = script.clone();
        let tb = thread::spawn(move || {
            let mut sb = sb;
            let st = pb.run(&mut sb, &sc, epoch);
            (pb, st)
        });
        let mut sa = sa;
        let st_a = pa.run(&mut sa, &script, epoch);
        let (pb, st_b) = tb.join().unwrap();
        let wall = epoch.elapsed();
        let stamps = st_a
            .iter()
            .zip(&st_b)
            .zip(&script)
            .map(|((x, y), &(payer, _))| {
                let (p, q) = if payer == 0 { (x, y) } else { (y, x) };
                Stamp {
                    t0: p.t0,
                    paid: p.paid,
                    received: q.received,
                    settled: q.settled,
                    bytes: p.bytes,
                }
            })
            .collect();
        Run {
            stamps,
            a: pa,
            b: pb,
            wall,
        }
    }

    fn ms(d: Duration) -> f64 {
        d.as_secs_f64() * 1000.0
    }

    fn q21(units: u64) -> String {
        format!("{}.{:08}", units / UNITS_PER_COIN, units % UNITS_PER_COIN)
    }

    fn weight(tx: &Transaction) -> u64 {
        tx.weight(WITNESS_DISCOUNT)
    }

    pub fn main() {
        let budget = Duration::from_secs(
            std::env::args()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        );
        // Payments per state update in the burst; 1 runs it one by one.
        let batch: usize = std::env::args()
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(25)
            .max(1);
        let (a, b) = (Key::new(1), Key::new(2));
        let t = Instant::now();
        let (mut r, ch, funding) = chain_and_funding(&a, &b);
        println!(
            "regtest chain mined to {} in {:.1} s; funding gathers {} coinbases",
            r.height(),
            t.elapsed().as_secs_f64(),
            funding.inputs.len()
        );

        // --- Open.
        let opened_at = r.height() + 1;
        r.mine(std::slice::from_ref(&funding));
        for _ in 0..DEPTH {
            r.mine(&[]);
        }
        let blocks = r.height() + 1 - opened_at;
        println!("\nOPEN  capacity {} Q21, funded by A", q21(CAPACITY));
        println!(
            "  funding weight {} ({} inputs here; a one-input funding weighs 8,563)",
            weight(&funding),
            funding.inputs.len()
        );
        println!(
            "  usable after {blocks} blocks (1 + {DEPTH} confirmations): about {} min at {} s blocks",
            blocks * TARGET_BLOCK_SECS / 60,
            TARGET_BLOCK_SECS
        );

        let links = [
            Link {
                name: "0 ms",
                latency_ms: 0,
                bandwidth: 0,
            },
            Link {
                name: "50 ms",
                latency_ms: 50,
                bandwidth: 0,
            },
            Link {
                name: "250 ms, 80 KB/s",
                latency_ms: 250,
                bandwidth: 80_000,
            },
            Link {
                name: "500 ms",
                latency_ms: 500,
                bandwidth: 0,
            },
        ];
        let (script, counts) = batched(&script(0x9e37_79b9_7f4a_7c15), batch);
        println!(
            "\nBURST {BURST} payments in {} state updates (up to {batch} per update)",
            script.len() - SINGLES.len()
        );
        let mut last = None;
        for link in links {
            let run = run_channel(&ch, &r, link, &script, budget);
            println!("\nLINK  one way {}", link.name);
            println!(
                "  {:>12} {:>12} {:>12} {:>12} {:>8}",
                "amount Q21", "received ms", "paid ms", "settled ms", "bytes"
            );
            for (i, st) in run.stamps.iter().take(SINGLES.len()).enumerate() {
                println!(
                    "  {:>12} {:>12.1} {:>12.1} {:>12.1} {:>8}",
                    q21(SINGLES[i]),
                    ms(st.received - st.t0),
                    ms(st.paid - st.t0),
                    ms(st.settled - st.t0),
                    st.bytes
                );
            }
            let burst = &run.stamps[SINGLES.len()..];
            let paid_count: usize = counts[SINGLES.len()..SINGLES.len() + burst.len()]
                .iter()
                .sum();
            if let (Some(first), Some(end)) = (burst.first(), burst.last()) {
                let span = end.settled.max(end.paid) - first.t0;
                let mut paid: Vec<f64> = burst.iter().map(|s| ms(s.paid - s.t0)).collect();
                paid.sort_by(|x, y| x.partial_cmp(y).unwrap());
                println!(
                    "  burst: {} payments in {} updates, {:.2} s = {:.1} payments/s; update paid median {:.1} ms, p99 {:.1} ms{}",
                    paid_count,
                    burst.len(),
                    span.as_secs_f64(),
                    paid_count as f64 / span.as_secs_f64(),
                    paid[paid.len() / 2],
                    paid[paid.len() * 99 / 100],
                    if paid_count < BURST { " (cut by the time budget)" } else { "" }
                );
            }
            for (name, p) in [("A", &run.a), ("B", &run.b)] {
                println!(
                    "  cpu {name}: {} signatures {:.1} ms, {} verifications {:.1} ms (wall {:.1} s)",
                    p.cpu.signs,
                    ms(p.cpu.sign),
                    p.cpu.verifies,
                    ms(p.cpu.verify),
                    run.wall.as_secs_f64()
                );
            }
            println!(
                "  revocation stores after {} states: A {} secrets / {} bytes, B {} secrets / {} bytes",
                run.a.history.len(),
                run.a.store.len(),
                run.a.store.bytes(),
                run.b.store.len(),
                run.b.store.bytes()
            );
            println!(
                "  dust trimmed into fees: {} outputs, {} units",
                TRIMMED.swap(0, Ordering::Relaxed),
                TRIMMED_UNITS.swap(0, Ordering::Relaxed)
            );
            last = Some(run);
        }
        let run = last.expect("at least one link");
        let latest = run.a.broadcastable(run.a.history.len() - 1);
        println!("\ncommitment weight (2 outputs): {}", weight(&latest));

        // --- Cooperative close of the last run, on the chain.
        let bal = run.a.bal;
        assert_eq!(bal, run.b.bal, "both sides agree on the balance");
        let owed = [bal[0] - CLOSE_FEE, bal[1]];
        let mut outs = Vec::new();
        for (i, h) in [a.hash(), b.hash()].into_iter().enumerate() {
            if owed[i] >= MIN_OUTPUT_VALUE {
                outs.push(key_out(h, owed[i]));
            } else {
                trim(owed[i]);
                println!(
                    "  close: {}'s {} units are dust, trimmed into the fee",
                    ["A", "B"][i],
                    owed[i]
                );
            }
        }
        let trimmed = TRIMMED_UNITS.swap(0, Ordering::Relaxed);
        let mut close = one_input(ch.fund_op, outs);
        let sigs = [
            a.sign(&ch.sighash(&close, 0)),
            b.sign(&ch.sighash(&close, 1)),
        ];
        ch.complete(&mut close, sigs, [&a.pk, &b.pk]);
        r.mine(std::slice::from_ref(&close));
        // What each side holds on chain from the close, found by its key.
        let got = |i: usize| {
            let h = [a.hash(), b.hash()][i];
            (0..close.outputs.len() as u32)
                .filter_map(|index| {
                    r.c.utxo.get(&OutPoint {
                        txid: close.txid(),
                        index,
                    })
                })
                .filter(|e| e.output.pubkey_hash == h)
                .map(|e| e.output.value.units())
                .sum::<u64>()
        };
        println!(
            "\nCLOSE cooperative, confirmed at height {} (1 block, weight {})",
            r.height(),
            weight(&close)
        );
        println!(
            "  channel: A {} B {}  on chain: A {} (close fee {}) B {}",
            q21(bal[0]),
            q21(bal[1]),
            q21(got(0)),
            q21(CLOSE_FEE),
            q21(got(1))
        );
        for (i, &o) in owed.iter().enumerate() {
            let expected = if o >= MIN_OUTPUT_VALUE { o } else { 0 };
            assert_eq!(got(i), expected);
        }
        assert_eq!(got(0) + got(1) + CLOSE_FEE + trimmed, CAPACITY);
        println!("  exact to the unit: yes");

        // --- The second run: A broadcasts its old state 1 instead.
        //
        // The same channel replayed on the chain as it stood before the
        // close: A's commitment of state 1 (A still had almost everything).
        let mut r2 = Regtest {
            c: Chain::new(NET, genesis_block(NET)),
            miner: a.hash(),
            blocks: Vec::new(),
        };
        for blk in &r.blocks[..r.blocks.len() - 1] {
            r2.c.connect(blk, blk.header.time + 1).expect("replay");
            r2.blocks.push(blk.clone());
        }
        let old = run.a.broadcastable(1);
        r2.mine(std::slice::from_ref(&old));
        let hc = r2.height();
        // B watches the chain: the funding output was spent by a commitment
        // of A's whose state number, read from its lock_time, is older than
        // the current one. Its secret comes from B's compact store, and the
        // to_local policy is rebuilt from it: nothing was kept per state.
        let spender = r2.blocks.last().unwrap().transactions[1].clone();
        let n = ch.state_of(&spender);
        let current = run.a.history.len() - 1;
        assert!(n < current, "a revoked state");
        let secret = run
            .b
            .store
            .get(shachain::MAX_INDEX - n as u64)
            .expect("B holds the secret of every revoked state");
        let to_local = ch.to_local(0, Hash256(sha256(&secret)));
        println!(
            "\nWATCH B's store after {current} states: {} secrets, {} bytes (at most {} entries)",
            run.b.store.len(),
            run.b.store.bytes(),
            shachain::MAX_ENTRIES
        );
        let lout = spender.outputs[0];
        let mut penalty = one_input(
            OutPoint {
                txid: spender.txid(),
                index: 0,
            },
            vec![key_out(b.hash(), lout.value.units() - PENALTY_FEE)],
        );
        // The revocation branch: choice 0 of the to_local `Any`.
        let m = policy::sighash(&penalty, 0, NET, &lout, &to_local, 0, &[0]);
        let s = Satisfaction::Any {
            index: 0,
            branch: Box::new(Satisfaction::All(vec![
                Satisfaction::Key {
                    pubkey: b.pk.clone(),
                    signature: b.sign(&m),
                },
                Satisfaction::Preimage(secret),
            ])),
        };
        penalty.inputs[0].witness = policy::witness(&to_local, &s);
        r2.mine(std::slice::from_ref(&penalty));
        let to_remote = spender.outputs.get(1).map(|o| o.value.units()).unwrap_or(0);
        let b_total = lout.value.units() - PENALTY_FEE + to_remote;
        println!("\nPENALTY A broadcast its revoked state {n} at height {hc}");
        println!(
            "  A's to_local {} Q21 taken by B in the next block (weight {}), {} blocks before A's delay of {DELAY}",
            q21(lout.value.units()),
            weight(&penalty),
            DELAY - 1
        );
        println!(
            "  B ends with {} Q21 of the {} capacity; A with 0 (fees: commitment {}, penalty {})",
            q21(b_total),
            q21(CAPACITY),
            q21(COMMIT_FEE),
            q21(PENALTY_FEE)
        );
        assert_eq!(b_total + COMMIT_FEE + PENALTY_FEE, CAPACITY);
    }
}
