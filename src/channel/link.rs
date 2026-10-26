//! The node side of the channel transport: one session per channel-capable
//! P2P connection, between the network ([`crate::net::ChannelSink`]) and the
//! [`ChannelManager`].
//!
//! Every channel payload is a transport frame ([`crate::channel::transport`]).
//! Handshake frames build the connection's session; a record is opened in it
//! and its plaintext handed to the manager, tagged with the node id the
//! session authenticated. Nothing reaches the manager any other way. What the
//! manager sends is sealed here and queued at once, under the connection's
//! lock, so records leave in the order they are numbered.
//!
//! # Roles and recovery
//!
//! The side that dialed starts the handshake as soon as the P2P handshake
//! completes. A session ends on any record that does not open — tampered,
//! replayed, or after a gap left by a dropped one — and the channels on it
//! wait, unsynchronized. The initiator then starts a new handshake; a
//! responder that lost its session tells it so with a `Reset`. A new session
//! resynchronizes every channel through the manager's reestablish, as a
//! reconnection does.
//!
//! # Work a stranger can cause
//!
//! A responder signs before its peer has proven anything, and either side
//! verifies, decapsulates and encapsulates once per handshake. So:
//!
//! - each connection gets [`HANDSHAKE_BURST`] handshakes, then one per
//!   [`HANDSHAKE_REFILL`] — as responder (an `Init` answered) and as initiator
//!   (one started, a `Reset` answered or sent) alike;
//! - all connections together get [`GLOBAL_HANDSHAKE_BURST`] answered `Init`s,
//!   then [`GLOBAL_HANDSHAKES_PER_SEC`] a second — strangers, first come first
//!   served. An `Init` whose identity key is that of a peer we hold a channel
//!   with draws first on a pool of its own, [`KNOWN_HANDSHAKE_BURST`] then
//!   [`KNOWN_HANDSHAKES_PER_SEC`] a second, within a share of
//!   [`KNOWN_PER_PEER_BURST`] for that key on that connection, refilled one per
//!   [`HANDSHAKE_REFILL`]: a flood of strangers cannot keep our channel peers
//!   out. Identity keys travel in clear, so the key an `Init` claims proves
//!   nothing yet. A connection that claimed one and then sent no valid `Fin`
//!   draws on that pool no more, and a `Fin` that does not verify is
//!   misconduct: a party claiming our peers' keys spends a connection for each
//!   few answers, and the real peer, on its own connection, keeps its share.
//!   Our own outbound handshakes draw on no shared pool at all: only on
//!   their connection's budget;
//! - a dialer whose `Init`s go unanswered — a node that follows the activation
//!   but runs no channels ignores them — backs off: after
//!   [`UNANSWERED_BEFORE_BACKOFF`] of them, each retry waits twice as long as
//!   the last, up to [`MAX_BACKOFF`]. Any frame of the transport from the peer
//!   ends the backoff;
//! - at most [`MAX_PENDING_HANDSHAKES`] responders wait for a `Fin` at once,
//!   one per connection, each for [`HANDSHAKE_TIMEOUT`];
//! - a handshake frame nobody asked for (`Resp` or `Fin` with no handshake
//!   pending) is dropped unread, and an initiator verifies at most
//!   [`RESP_TRIES`] `Resp`s per handshake.
//!
//! Before channels open on the network ([`crate::policy::reached`]: on
//! testnet, below the activation height) no handshake is started, answered
//! or retried: nothing could be sent anyway. When the tip reaches it, the
//! dialer starts at once, and a responder with no session tells its peer
//! with a `Reset`, for the dialer that got there first and whose `Init` was
//! dropped.
//!
//! Beyond a budget a frame is dropped, not answered. The P2P layer's own
//! per-peer rate on channel messages ([`crate::net::CHAN_RATE_PER_SEC`]) and
//! frame bound come first.

use crate::channel::manager::ChannelManager;
use crate::channel::transport::{
    self, Context, Initiator, Limits, Responder, Session, TransportError,
};
use crate::net::{ChannelLink, ChannelOutcome, ChannelSender, ChannelSink, MISCONDUCT_CHANNEL};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Handshakes a connection may cause at once.
pub const HANDSHAKE_BURST: u32 = 4;
/// Then one per this period, per connection.
pub const HANDSHAKE_REFILL: Duration = Duration::from_secs(15);
/// `Init`s answered at once, across all connections.
pub const GLOBAL_HANDSHAKE_BURST: u32 = 32;
/// Then this many a second, across all connections.
pub const GLOBAL_HANDSHAKES_PER_SEC: u32 = 4;
/// `Init`s answered at once, across all connections, for identity keys of
/// peers we hold a channel with.
pub const KNOWN_HANDSHAKE_BURST: u32 = 16;
/// Then this many a second, for them.
pub const KNOWN_HANDSHAKES_PER_SEC: u32 = 2;
/// Of which any one such key gets at once; then one per [`HANDSHAKE_REFILL`].
pub const KNOWN_PER_PEER_BURST: u32 = 2;
/// `Resp`s an initiator verifies in one handshake. Two: when both ends reach
/// the activation at once, the responder's `Reset` and our `Init` cross, we
/// start again, and the answer to the first `Init` comes before the one to
/// the second.
pub const RESP_TRIES: u32 = 2;
/// `Init`s gone unanswered on a connection before its retries back off.
pub const UNANSWERED_BEFORE_BACKOFF: u32 = 3;
/// Longest wait between two `Init`s on one connection.
pub const MAX_BACKOFF: Duration = Duration::from_secs(3600);
/// Responders waiting for their `Fin`, across all connections.
pub const MAX_PENDING_HANDSHAKES: usize = 64;
/// How long a handshake may wait for its next frame.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections tracked at once. The P2P layer bounds its peers well below.
const MAX_CONNECTIONS: usize = 1024;

/// The bounds above, as one value a test may change.
#[derive(Clone, Copy, Debug)]
pub struct DosLimits {
    pub burst: u32,
    pub refill: Duration,
    pub global_burst: u32,
    pub global_refill: Duration,
    pub max_pending: usize,
    pub timeout: Duration,
    pub known_burst: u32,
    pub known_refill: Duration,
}

impl Default for DosLimits {
    fn default() -> DosLimits {
        DosLimits {
            burst: HANDSHAKE_BURST,
            refill: HANDSHAKE_REFILL,
            global_burst: GLOBAL_HANDSHAKE_BURST,
            global_refill: Duration::from_millis(1000 / u64::from(GLOBAL_HANDSHAKES_PER_SEC)),
            max_pending: MAX_PENDING_HANDSHAKES,
            timeout: HANDSHAKE_TIMEOUT,
            known_burst: KNOWN_HANDSHAKE_BURST,
            known_refill: Duration::from_millis(1000 / u64::from(KNOWN_HANDSHAKES_PER_SEC)),
        }
    }
}

fn known_pool(dos: &DosLimits) -> Budget {
    Budget::new(dos.known_burst, dos.known_refill)
}

/// A token bucket: `max` tokens, one more every `every`.
struct Budget {
    tokens: u32,
    max: u32,
    every: Duration,
    last: Instant,
}

impl Budget {
    fn new(max: u32, every: Duration) -> Budget {
        Budget {
            tokens: max,
            max,
            every,
            last: Instant::now(),
        }
    }

    /// Whether a token is there, once what time earned is counted.
    fn available(&mut self) -> bool {
        self.refill();
        self.tokens > 0
    }

    fn refill(&mut self) {
        let now = Instant::now();
        if !self.every.is_zero() {
            let earned = now.duration_since(self.last).as_nanos() / self.every.as_nanos();
            if earned > 0 {
                self.tokens = self
                    .tokens
                    .saturating_add(u32::try_from(earned).unwrap_or(u32::MAX))
                    .min(self.max);
                self.last = now;
            }
        }
    }

    fn take(&mut self) -> bool {
        self.refill();
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

enum Handshake {
    Idle,
    Initiating(Initiator, Instant),
    Responding(Responder, Instant),
}

struct Established {
    session: Session,
}

/// One channel-capable connection.
struct Conn {
    link: ChannelLink,
    handshake: Handshake,
    session: Option<Established>,
    budget: Budget,
    /// Initiator: a handshake is due, and waits for the budget.
    wanted: bool,
    /// Responder: when a `Reset` last went out since the last session ended.
    reset_sent: Option<Instant>,
    /// Responder: the handshake under way was answered from the channel
    /// peers' pool, on the strength of the key its `Init` claimed.
    claimed_known: bool,
    /// Responder: this connection claimed a channel peer's key and never
    /// proved it. It draws on the strangers' pool only.
    demoted: bool,
    /// Initiator: `Resp`s refused in the handshake under way. Each costs a
    /// verification; past [`RESP_TRIES`], the handshake is given up.
    resp_failures: u32,
    /// Initiator: `Init`s that timed out unanswered in a row.
    unanswered: u32,
    /// Initiator: no retry before then (see [`UNANSWERED_BEFORE_BACKOFF`]).
    next_try: Option<Instant>,
}

/// What a handshake frame left to do once the connection's lock is released.
#[derive(Default)]
struct After {
    /// The previous session ended: the manager forgets it.
    closed: bool,
    /// A session was established, with this node id, legacy id and binding.
    established: Option<(String, String, [u8; 32])>,
    /// How long its handshake took from this side, and in which role.
    took: Option<(Duration, &'static str)>,
    penalize: u32,
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The node id of a session's peer, as the manager names it: [`is_node_id`].
///
/// [`is_node_id`]: crate::channel::manager::is_node_id
fn identity_of(peer: &transport::Peer) -> (String, String, [u8; 32]) {
    (hex(&peer.id.0), hex(&peer.legacy_id), peer.binding)
}

/// The transport context of a connection, by role.
fn context(network: crate::address::Network, link: &ChannelLink) -> Context {
    if link.outbound {
        Context {
            network,
            initiator_nonce: link.local_nonce,
            responder_nonce: link.remote_nonce,
        }
    } else {
        Context {
            network,
            initiator_nonce: link.remote_nonce,
            responder_nonce: link.local_nonce,
        }
    }
}

/// Misconduct for a handshake frame that failed: a malformed one, or a key
/// that is not one, is misconduct of the sender. A signature that does not
/// verify may be an honest answer to a handshake already replaced.
fn handshake_penalty(e: TransportError) -> u32 {
    match e {
        TransportError::Malformed | TransportError::BadKey | TransportError::Reflected => {
            MISCONDUCT_CHANNEL
        }
        _ => 0,
    }
}

type SendFrame = dyn Fn(u64, Vec<u8>) -> bool + Send + Sync;
type Gate = dyn Fn() -> bool + Send + Sync;
type Alive = dyn Fn(u64) -> bool + Send + Sync;
/// Each channel peer key's share of the reserved pool, per connection.
type Shares = HashMap<(String, u64), Budget>;

/// The channel component a node installs: sessions over its connections,
/// in front of the manager.
pub struct ChannelTransport {
    mgr: Arc<ChannelManager>,
    sender: RwLock<Option<Box<SendFrame>>>,
    conns: Mutex<HashMap<u64, Arc<Mutex<Conn>>>>,
    /// Responders waiting for a `Fin`, by connection.
    pending: Mutex<HashMap<u64, Instant>>,
    global: Mutex<Budget>,
    /// The pool for channel peers' keys, and each key's share of it, per
    /// connection.
    known: Mutex<(Budget, Shares)>,
    /// Whether a connection is still there; absent, every one is.
    alive: RwLock<Option<Box<Alive>>>,
    dos: RwLock<DosLimits>,
    rekey: RwLock<Limits>,
    /// Whether channels are open; absent, they always are.
    gate: RwLock<Option<Box<Gate>>>,
    /// The gate's value at the last look, to act once when it opens.
    was_open: AtomicBool,
    /// Handshakes started or answered: each an ephemeral key and a signature.
    attempts: AtomicU64,
}

impl ChannelTransport {
    /// The transport in front of `mgr`; the manager's own sends go through it.
    pub fn new(mgr: Arc<ChannelManager>) -> Arc<ChannelTransport> {
        let dos = DosLimits::default();
        let t = Arc::new(ChannelTransport {
            mgr,
            sender: RwLock::new(None),
            conns: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            global: Mutex::new(Budget::new(dos.global_burst, dos.global_refill)),
            known: Mutex::new((known_pool(&dos), HashMap::new())),
            alive: RwLock::new(None),
            dos: RwLock::new(dos),
            rekey: RwLock::new(Limits::default()),
            gate: RwLock::new(None),
            was_open: AtomicBool::new(true),
            attempts: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&t);
        t.mgr.set_outbound(Box::new(move |peer, frame| {
            weak.upgrade().is_some_and(|t| t.send(peer, frame))
        }));
        t
    }

    pub fn manager(&self) -> &Arc<ChannelManager> {
        &self.mgr
    }

    /// Where transport frames go: the node's [`ChannelSender`] once attached,
    /// or anything a test wires in.
    pub fn set_sender(&self, send: Box<SendFrame>) {
        if let Ok(mut g) = self.sender.write() {
            *g = Some(send);
        }
    }

    /// Installs the check of whether channels are open on the network (see
    /// the module documentation): the node's [`ChannelSender::channels_open`]
    /// once attached.
    pub fn set_gate(&self, gate: Box<Gate>) {
        let open = gate();
        if let Ok(mut g) = self.gate.write() {
            *g = Some(gate);
        }
        self.was_open.store(open, Ordering::SeqCst);
    }

    /// Whether channels are open, so that a handshake is worth its work.
    fn open(&self) -> bool {
        match self.gate.read() {
            Ok(g) => match g.as_ref() {
                Some(f) => f(),
                None => true,
            },
            Err(_) => false,
        }
    }

    /// Installs the check of whether a connection is still there: the node's
    /// [`ChannelSender::is_connected`] once attached. An entry for one that
    /// is gone is never made, and is pruned at the next [`Self::tick`].
    pub fn set_alive(&self, alive: Box<Alive>) {
        if let Ok(mut g) = self.alive.write() {
            *g = Some(alive);
        }
    }

    fn is_alive(&self, peer: u64) -> bool {
        match self.alive.read() {
            Ok(g) => match g.as_ref() {
                Some(f) => f(peer),
                None => true,
            },
            Err(_) => true,
        }
    }

    /// Handshakes this transport started or answered.
    pub fn handshake_attempts(&self) -> u64 {
        self.attempts.load(Ordering::SeqCst)
    }

    /// Changes the handshake bounds, for tests.
    #[doc(hidden)]
    pub fn set_dos_limits(&self, dos: DosLimits) {
        *self.global.lock().unwrap() = Budget::new(dos.global_burst, dos.global_refill);
        *self.known.lock().unwrap() = (known_pool(&dos), HashMap::new());
        *self.dos.write().unwrap() = dos;
    }

    /// Changes when new sessions rekey, for tests; both ends must agree.
    #[doc(hidden)]
    pub fn set_rekey_limits(&self, limits: Limits) {
        *self.rekey.write().unwrap() = limits;
    }

    fn dos(&self) -> DosLimits {
        *self.dos.read().unwrap()
    }

    fn raw_send(&self, peer: u64, bytes: Vec<u8>) -> bool {
        match self.sender.read() {
            Ok(g) => g.as_ref().is_some_and(|f| f(peer, bytes)),
            Err(_) => false,
        }
    }

    fn conn(&self, peer: u64) -> Option<Arc<Mutex<Conn>>> {
        self.conns.lock().unwrap().get(&peer).cloned()
    }

    /// The connection's entry, made on first sight; `None` past the bound.
    fn conn_or_insert(&self, peer: u64, link: &ChannelLink) -> Option<Arc<Mutex<Conn>>> {
        let mut g = self.conns.lock().unwrap();
        if let Some(c) = g.get(&peer) {
            return Some(c.clone());
        }
        if g.len() >= MAX_CONNECTIONS || !self.is_alive(peer) {
            return None;
        }
        let dos = self.dos();
        let c = Arc::new(Mutex::new(Conn {
            link: *link,
            handshake: Handshake::Idle,
            session: None,
            budget: Budget::new(dos.burst, dos.refill),
            wanted: false,
            reset_sent: None,
            claimed_known: false,
            demoted: false,
            resp_failures: 0,
            unanswered: 0,
            next_try: None,
        }));
        g.insert(peer, c.clone());
        Some(c)
    }

    /// Whether connection `peer` has an established session.
    pub fn has_session(&self, peer: u64) -> bool {
        self.conn(peer)
            .is_some_and(|c| c.lock().unwrap().session.is_some())
    }

    /// Seals `frame` into `peer`'s session and queues it. False without a
    /// session.
    pub fn send(&self, peer: u64, frame: Vec<u8>) -> bool {
        let Some(conn) = self.conn(peer) else {
            return false;
        };
        let mut c = conn.lock().unwrap();
        let Some(est) = c.session.as_mut() else {
            return false;
        };
        match est.session.seal(&frame) {
            // Queued under the lock: the record numbered next leaves next.
            Ok(record) => self.raw_send(peer, record),
            Err(e) => {
                eprintln!("channel frame to peer {peer} not sent: {e:?}");
                false
            }
        }
    }

    /// A channel-capable connection completed its P2P handshake.
    pub fn connect(&self, peer: u64, link: &ChannelLink) {
        let Some(conn) = self.conn_or_insert(peer, link) else {
            return;
        };
        let mut c = conn.lock().unwrap();
        c.link = *link;
        if link.outbound {
            self.start_handshake(peer, &mut c);
        }
    }

    /// The connection is gone.
    pub fn disconnect(&self, peer: u64) {
        let removed = self.conns.lock().unwrap().remove(&peer);
        self.pending.lock().unwrap().remove(&peer);
        self.known
            .lock()
            .unwrap()
            .1
            .retain(|(_, conn), _| *conn != peer);
        if removed.is_some() {
            self.mgr.on_session_closed(peer);
        }
    }

    /// Starts a handshake as initiator, within the connection's budget, or
    /// marks one due.
    fn start_handshake(&self, peer: u64, c: &mut Conn) {
        if !self.open() {
            // Due once channels open: `tick` starts it then.
            c.wanted = true;
            return;
        }
        if let Handshake::Initiating(_, since) = &c.handshake {
            if since.elapsed() < self.dos().timeout {
                return;
            }
        }
        if !c.budget.take() {
            c.wanted = true;
            return;
        }
        c.wanted = false;
        let ctx = context(self.mgr.network(), &c.link);
        self.attempts.fetch_add(1, Ordering::SeqCst);
        match Initiator::start(self.mgr.identity(), ctx) {
            Ok((ini, init)) => {
                c.handshake = Handshake::Initiating(ini, Instant::now());
                c.resp_failures = 0;
                self.raw_send(peer, init);
            }
            Err(_) => c.wanted = true,
        }
    }

    /// Ends the connection's session after a failure, and asks for or starts
    /// the next. Returns whether there was one.
    fn fail_session(&self, peer: u64, c: &mut Conn) -> bool {
        let had = c.session.take().is_some();
        if c.link.outbound {
            self.start_handshake(peer, c);
        } else {
            self.send_reset(peer, c);
        }
        had
    }

    /// Responder: tells the initiator to start a session — once per ended
    /// session, again only if no handshake came of it in time, and within
    /// the budget.
    fn send_reset(&self, peer: u64, c: &mut Conn) {
        let timeout = self.dos().timeout;
        if !self.open() || c.reset_sent.is_some_and(|at| at.elapsed() < timeout) || !c.budget.take()
        {
            return;
        }
        c.reset_sent = Some(Instant::now());
        self.raw_send(peer, vec![transport::VERSION, transport::T_RESET]);
    }

    /// Handles one channel payload from `peer`.
    pub fn deliver(&self, peer: u64, link: &ChannelLink, bytes: &[u8]) -> ChannelOutcome {
        let outcome = |penalize| ChannelOutcome {
            replies: Vec::new(),
            penalize,
        };
        // Not a frame of this transport: a node that advertised it sends
        // nothing else.
        let Some(kind) = transport::frame_type(bytes) else {
            return outcome(MISCONDUCT_CHANNEL);
        };
        let Some(conn) = self.conn_or_insert(peer, link) else {
            return outcome(0);
        };
        if kind == transport::T_RECORD {
            return outcome(self.on_record(peer, &conn, bytes));
        }
        // Whose key an `Init` claims, looked up before the connection's lock:
        // the manager has a lock of its own.
        let known = (kind == transport::T_INIT && bytes.len() == transport::INIT_LEN)
            .then(|| {
                let at = 2 + transport::EK_LEN;
                let id = crate::channel::keys::node_id(&bytes[at..at + transport::PK_LEN]);
                hex(&id.0)
            })
            .filter(|id| self.mgr.holds_channel_with(id));
        let after = {
            let mut c = conn.lock().unwrap();
            match kind {
                transport::T_INIT => self.on_init(peer, &mut c, bytes, known),
                transport::T_RESP => self.on_resp(peer, &mut c, bytes),
                transport::T_FIN => self.on_fin(peer, &mut c, bytes),
                transport::T_RESET => self.on_reset(peer, &mut c, bytes),
                _ => After {
                    penalize: MISCONDUCT_CHANNEL,
                    ..After::default()
                },
            }
        };
        if after.closed {
            self.mgr.on_session_closed(peer);
        }
        if let Some((identity, legacy, binding)) = after.established {
            if let Some((took, role)) = after.took {
                eprintln!(
                    "channel session with node {} on peer {peer}: up as {role}, handshake {} ms",
                    &identity[..16],
                    took.as_millis()
                );
            }
            for frame in self.mgr.on_session(peer, &identity, &legacy, binding) {
                self.send(peer, frame);
            }
        }
        outcome(after.penalize)
    }

    fn on_record(&self, peer: u64, conn: &Arc<Mutex<Conn>>, bytes: &[u8]) -> u32 {
        let opened = {
            let mut c = conn.lock().unwrap();
            let Some(est) = c.session.as_mut() else {
                // The peer still holds a session we no longer do: ours
                // failed, or a handshake to replace it is under way.
                if c.link.outbound {
                    if matches!(c.handshake, Handshake::Idle) {
                        self.start_handshake(peer, &mut c);
                    }
                } else {
                    self.send_reset(peer, &mut c);
                }
                return 0;
            };
            match est.session.open(bytes) {
                Ok(plaintext) => Ok(plaintext),
                Err(e) => {
                    let had = self.fail_session(peer, &mut c);
                    Err((e, had))
                }
            }
        };
        match opened {
            Ok(plaintext) => {
                let r = self.mgr.deliver(peer, &plaintext);
                for frame in r.frames {
                    self.send(peer, frame);
                }
                r.penalize
            }
            Err((e, had)) => {
                if had {
                    eprintln!("channel session on peer {peer} ended ({e:?}); negotiating another");
                    self.mgr.on_session_closed(peer);
                }
                match e {
                    // A record lost on the way, most likely dropped by a rate
                    // limit on this side: nothing the peer did.
                    TransportError::Gap | TransportError::Exhausted => 0,
                    _ => MISCONDUCT_CHANNEL,
                }
            }
        }
    }

    /// Whether an `Init` on connection `peer` gets an answer from the shared
    /// budgets, and whether from the channel peers' pool: for a `known` key,
    /// within that key's share on this connection; else from the strangers'.
    fn take_shared_budget(&self, peer: u64, known: Option<String>) -> (bool, bool) {
        if let Some(id) = known {
            let refill = self.dos().refill;
            let mut g = self.known.lock().unwrap();
            let (pool, shares) = &mut *g;
            if shares.len() > 2 * MAX_CONNECTIONS {
                shares.clear();
            }
            let share = shares
                .entry((id, peer))
                .or_insert_with(|| Budget::new(KNOWN_PER_PEER_BURST, refill));
            if share.available() && pool.take() {
                share.take();
                return (true, true);
            }
        }
        (self.global.lock().unwrap().take(), false)
    }

    fn on_init(&self, peer: u64, c: &mut Conn, bytes: &[u8], known: Option<String>) -> After {
        // Only the side that was dialed answers: both ends of a link agree on
        // who that is, a relay that dialed both does not get a session.
        if c.link.outbound || !self.open() {
            return After::default();
        }
        if bytes.len() != transport::INIT_LEN {
            return After {
                penalize: MISCONDUCT_CHANNEL,
                ..After::default()
            };
        }
        let dos = self.dos();
        {
            let mut pending = self.pending.lock().unwrap();
            pending.retain(|_, since| since.elapsed() < dos.timeout);
            if pending.len() >= dos.max_pending && !pending.contains_key(&peer) {
                return After::default();
            }
        }
        // An `Init` that replaces one answered on a claimed key, with no
        // `Fin` in between: the claim was never proved.
        if c.claimed_known && matches!(c.handshake, Handshake::Responding(..)) {
            c.demoted = true;
        }
        c.claimed_known = false;
        let known = known.filter(|_| !c.demoted);
        if !c.budget.take() {
            return After::default();
        }
        let (answered, from_known) = self.take_shared_budget(peer, known);
        if !answered {
            return After::default();
        }
        // A new handshake replaces the session: the initiator starts one only
        // once it holds none.
        let closed = c.session.take().is_some();
        c.reset_sent = None;
        let ctx = context(self.mgr.network(), &c.link);
        self.attempts.fetch_add(1, Ordering::SeqCst);
        match Responder::accept(self.mgr.identity(), ctx, bytes) {
            Ok((r, resp)) => {
                let now = Instant::now();
                c.handshake = Handshake::Responding(r, now);
                c.claimed_known = from_known;
                self.pending.lock().unwrap().insert(peer, now);
                self.raw_send(peer, resp);
                After {
                    closed,
                    ..After::default()
                }
            }
            Err(e) => {
                c.handshake = Handshake::Idle;
                self.pending.lock().unwrap().remove(&peer);
                After {
                    closed,
                    penalize: handshake_penalty(e),
                    ..After::default()
                }
            }
        }
    }

    fn on_resp(&self, peer: u64, c: &mut Conn, bytes: &[u8]) -> After {
        let Handshake::Initiating(ini, since) = &c.handshake else {
            return After::default();
        };
        let since = *since;
        // The peer runs the transport: no more backing off.
        c.unanswered = 0;
        c.next_try = None;
        match ini.try_finish(self.mgr.identity(), bytes) {
            Ok((mut session, peer_info, fin)) => {
                c.handshake = Handshake::Idle;
                session.set_limits(*self.rekey.read().unwrap());
                // The Fin leaves before any record of the new session.
                self.raw_send(peer, fin);
                let closed = c.session.replace(Established { session }).is_some();
                After {
                    closed,
                    established: Some(identity_of(&peer_info)),
                    took: Some((since.elapsed(), "initiator")),
                    penalize: 0,
                }
            }
            Err(e) => {
                // Kept for the answer to the `Init` under way, a few tries.
                c.resp_failures += 1;
                if c.resp_failures >= RESP_TRIES {
                    c.handshake = Handshake::Idle;
                    c.wanted = true;
                }
                After {
                    penalize: handshake_penalty(e),
                    ..After::default()
                }
            }
        }
    }

    fn on_fin(&self, peer: u64, c: &mut Conn, bytes: &[u8]) -> After {
        let Handshake::Responding(r, since) = std::mem::replace(&mut c.handshake, Handshake::Idle)
        else {
            return After::default();
        };
        self.pending.lock().unwrap().remove(&peer);
        let claimed = std::mem::take(&mut c.claimed_known);
        match r.finish(bytes) {
            Ok((mut session, peer_info)) => {
                session.set_limits(*self.rekey.read().unwrap());
                let closed = c.session.replace(Established { session }).is_some();
                After {
                    closed,
                    established: Some(identity_of(&peer_info)),
                    took: Some((since.elapsed(), "responder")),
                    penalize: 0,
                }
            }
            // A `Fin` that does not prove the channel peer's key its `Init`
            // claimed, to be answered from that peer's pool: misconduct.
            Err(_) if claimed => {
                c.demoted = true;
                After {
                    penalize: MISCONDUCT_CHANNEL,
                    ..After::default()
                }
            }
            Err(e) => After {
                penalize: handshake_penalty(e),
                ..After::default()
            },
        }
    }

    fn on_reset(&self, peer: u64, c: &mut Conn, bytes: &[u8]) -> After {
        if !c.link.outbound {
            return After::default();
        }
        if bytes.len() != 2 {
            return After {
                penalize: MISCONDUCT_CHANNEL,
                ..After::default()
            };
        }
        c.unanswered = 0;
        c.next_try = None;
        // Initiating already: the responder never saw that `Init`, dropped
        // while it had not reached the activation yet. Started again.
        if matches!(c.handshake, Handshake::Initiating(..)) {
            c.handshake = Handshake::Idle;
        }
        let closed = c.session.take().is_some();
        self.start_handshake(peer, c);
        After {
            closed,
            ..After::default()
        }
    }

    /// Drops what is held for connections that are gone.
    fn prune_gone(&self) {
        // Entries of connections gone without a word: one that closed while
        // its handshake completed, or before the manager heard of it.
        let gone: Vec<u64> = {
            let mut g = self.conns.lock().unwrap();
            let gone: Vec<u64> = g.keys().copied().filter(|p| !self.is_alive(*p)).collect();
            for p in &gone {
                g.remove(p);
            }
            gone
        };
        if !gone.is_empty() {
            let mut pending = self.pending.lock().unwrap();
            for p in &gone {
                pending.remove(p);
            }
        }
        if !gone.is_empty() {
            self.known
                .lock()
                .unwrap()
                .1
                .retain(|(_, conn), _| !gone.contains(conn));
        }
        for p in gone {
            self.mgr.on_session_closed(p);
        }
        self.mgr.retain_sessions(&|p| self.is_alive(p));
    }

    /// Timed work: forgets handshakes that waited too long, and starts the
    /// ones due once the budget allows.
    pub fn tick(&self) {
        self.prune_gone();
        // Nothing is due, and no timer runs, before channels open.
        let open = self.open();
        let opened = open && !self.was_open.swap(open, Ordering::SeqCst);
        if !open {
            self.was_open.store(false, Ordering::SeqCst);
            return;
        }
        let timeout = self.dos().timeout;
        self.pending
            .lock()
            .unwrap()
            .retain(|_, since| since.elapsed() < timeout);
        let conns: Vec<(u64, Arc<Mutex<Conn>>)> = self
            .conns
            .lock()
            .unwrap()
            .iter()
            .map(|(p, c)| (*p, c.clone()))
            .collect();
        for (peer, conn) in conns {
            let mut c = conn.lock().unwrap();
            let expired = match &c.handshake {
                Handshake::Initiating(_, since) | Handshake::Responding(_, since) => {
                    since.elapsed() >= timeout
                }
                Handshake::Idle => false,
            };
            if expired {
                match c.handshake {
                    // Unanswered: past a few, the next waits longer each time.
                    Handshake::Initiating(..) => {
                        c.unanswered = c.unanswered.saturating_add(1);
                        if c.unanswered >= UNANSWERED_BEFORE_BACKOFF {
                            let doublings = (c.unanswered - UNANSWERED_BEFORE_BACKOFF + 1).min(20);
                            let wait = timeout.saturating_mul(1 << doublings).min(MAX_BACKOFF);
                            c.next_try = Some(Instant::now() + wait);
                        }
                    }
                    // A key claimed, never proved.
                    Handshake::Responding(..) if c.claimed_known => {
                        c.claimed_known = false;
                        c.demoted = true;
                    }
                    _ => {}
                }
                c.handshake = Handshake::Idle;
            }
            if c.link.outbound && c.session.is_none() && matches!(c.handshake, Handshake::Idle) {
                c.wanted = true;
            }
            // Just opened: a dialer that got there first sent its `Init`
            // while we dropped every channel frame.
            if opened && !c.link.outbound && c.session.is_none() {
                c.reset_sent = None;
                self.send_reset(peer, &mut c);
            }
            let backed_off = c.next_try.is_some_and(|t| Instant::now() < t);
            if c.wanted && !backed_off {
                self.start_handshake(peer, &mut c);
            }
        }
    }
}

impl ChannelSink for ChannelTransport {
    fn deliver(&self, peer: u64, link: &ChannelLink, bytes: &[u8]) -> ChannelOutcome {
        ChannelTransport::deliver(self, peer, link, bytes)
    }

    fn attach(&self, sender: ChannelSender) {
        let gate = sender.clone();
        self.set_gate(Box::new(move || gate.channels_open()));
        let alive = sender.clone();
        self.set_alive(Box::new(move |peer| alive.is_connected(peer)));
        self.set_sender(Box::new(move |peer, bytes| sender.send(peer, bytes)));
    }

    fn on_connected_block(
        &self,
        txs: &[crate::tx::Transaction],
        height: u64,
        depth_of: &crate::channel::manager::DepthOf,
    ) -> Vec<(u64, Vec<u8>)> {
        for (peer, frame) in self.mgr.on_connected_block(txs, height, depth_of) {
            self.send(peer, frame);
        }
        // The block that opens channels starts their sessions at once, not
        // at the next maintenance round.
        self.tick();
        Vec::new()
    }

    fn on_peer_connected(&self, peer: u64, link: &ChannelLink) -> Vec<Vec<u8>> {
        self.connect(peer, link);
        Vec::new()
    }

    fn on_peer_disconnected(&self, peer: u64) {
        self.disconnect(peer);
    }

    fn tick(&self) {
        ChannelTransport::tick(self);
    }

    fn on_disconnected_txids(&self, txids: &[crate::hash::Hash256]) {
        self.mgr.on_disconnected_txids(txids);
    }

    fn rescan(
        &self,
        tip: u64,
        txs_at: &dyn Fn(u64) -> Option<Vec<crate::tx::Transaction>>,
        depth_of: &crate::channel::manager::DepthOf,
    ) {
        self.mgr.rescan(tip, txs_at, depth_of);
    }
}
