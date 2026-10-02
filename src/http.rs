//! Minimal HTTP/1.1 server.
//!
//! Just enough to serve a JSON-RPC API and an explorer page. Written here,
//! without dependencies, for the same reason as everything else.
//!
//! # The security decision that matters
//!
//! An open RPC port is access to the node. An open RPC port **on a public
//! interface** is a loss of funds: a single scan is enough to find it. This
//! story has already played out - thousands of Ethereum and Docker nodes were
//! emptied because an administration port listened on `0.0.0.0` by default.
//!
//! Two safeguards, applied at bind time and not at the first call:
//!
//! - **local loopback is the default.** `127.0.0.1` serves the node to the
//!   machine that hosts it, and to no one else;
//! - **listening anywhere else requires a token.** Without a token, [`serve`]
//!   refuses to bind to a non-local address, and the refusal comes at startup,
//!   not in the middle of the night once the port has already been found.
//!
//! The token is compared in **constant time**: a naive comparison leaks its
//! length and its prefix through the response time.

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Maximum size of a request body.
pub const MAX_BODY: usize = 1024 * 1024;
/// Maximum length of a header line.
pub const MAX_LINE: usize = 8 * 1024;
/// Maximum number of headers.
pub const MAX_HEADERS: usize = 64;

pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum duration of a complete request, reading included.
///
/// `READ_TIMEOUT` applies to **each** read: one byte every twenty seconds
/// therefore kept a connection - and its thread - alive indefinitely. That is
/// the Slowloris attack, fifteen years old and still effective against anyone
/// who only bounds individual reads.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Connections handled simultaneously.
///
/// `serve` used to start one system thread per connection, with no counter and
/// no queue. A few thousand open connections were enough to exhaust the
/// process memory. Beyond this cap, the connection is refused immediately: a
/// plain refusal is better than one more thread.
pub const MAX_CONNECTIONS: usize = 64;

/// Validity period of a launch token that has not been used yet.
///
/// It only lives for as long as it takes to open a page. Ten minutes cover the
/// case of someone copying the address by hand from the terminal; beyond that,
/// whatever lingers in a browser's command line no longer opens anything.
pub const LAUNCH_TOKEN_VALIDITY: Duration = Duration::from_secs(10 * 60);

/// Path where the launch token is exchanged for the session token.
pub const SESSION_PATH: &str = "/session";

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    /// The client address, as far as the server can know it.
    ///
    /// The one of the TCP connection - except behind the local front server,
    /// where it is the **last** address of `X-Forwarded-For`. See
    /// [`client_address`]. It is used so that one client's budget is not
    /// everyone's.
    pub client: Option<IpAddr>,
}

/// The client address of a request.
///
/// # Why the header is only trusted from the local loopback
///
/// In public mode, the node only listens on the local loopback and it is the
/// front server that talks to it: every connection comes from `127.0.0.1`,
/// and without the `X-Forwarded-For` header the front server sets, every
/// visitor would be one and the same client. So we read the **last** address
/// of that header - the one the front server appended itself, the only one
/// the client could not choose.
///
/// An `X-Forwarded-For` that arrives from anywhere other than the local
/// loopback is not the front server's: it is a client writing it itself.
/// Trusting it would let that client choose its identity, hence its budget,
/// and change it at every request. We then keep the connection address, and
/// nothing else.
///
/// # A single trusted hop
///
/// This choice assumes **one** front server between the visitor and the node:
/// the one the operator installs in front of the explorer (`--public` behind
/// Caddy or nginx). If a second trusted intermediary is stacked - a CDN
/// placed before that front server -, the last address is the CDN's, and all
/// visitors then share a single client's budget: the accounting degrades, it
/// does not become forgeable. To get per-visitor accounting back in that
/// setup, it is up to the local front server to rewrite the header with the
/// address the CDN passes to it (`CF-Connecting-IP`, `True-Client-IP` or the
/// equivalent), and not up to this node to guess how many hops are trusted:
/// every hop taken at its word is a hop the visitor can imitate. Trust is
/// configured where it exists, not one step further.
///
/// An unreadable value does not make the request fail: we fall back to the
/// connection address, and the client is treated together with the front
/// server.
pub fn client_address(peer: Option<IpAddr>, headers: &BTreeMap<String, String>) -> Option<IpAddr> {
    let peer = peer?;
    if !peer.is_loopback() {
        return Some(peer);
    }
    let Some(forwarded) = headers.get("x-forwarded-for") else {
        return Some(peer);
    };
    // Take the LAST value, not the first.
    //
    // A front server appends to the end of `X-Forwarded-For` the address IT
    // received the connection from - the real client. The first value, on the
    // other hand, is whatever the client chose to write: a front server that
    // *appends* (instead of *replacing*, a common default setting) leaves it
    // intact, and trusting it made the budget forgeable at every request - a
    // different IP per call was enough to get around the per-client quota
    // (red-team 8b). The last entry is the one of the immediate trusted hop,
    // the only one we did not let the attacker choose.
    let last = forwarded.split(',').next_back().unwrap_or("").trim();
    match last.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) => Some(peer),
    }
}

/// A launch token: exchanged **only once** for the session token.
///
/// # What this closes
///
/// The launcher opens the browser on an address whose fragment carries a
/// secret. That address is passed to the launcher as a **command-line
/// argument** - readable by every account on the machine in
/// `/proc/<pid>/cmdline` on Linux, through `ps` on macOS - and it stays there
/// for as long as the browser process lives. On Linux, the `/proc/net/tcp`
/// guard refuses other accounts; elsewhere, this secret was the only barrier,
/// and it was valid for the whole session.
///
/// So the fragment no longer carries the session token. It carries this
/// short-lived token, which the page exchanges on first load for the real
/// token through a `POST` - and then it is destroyed. Whatever lingers in
/// `argv` afterward is worth nothing. Another account that read it before the
/// page only wins a one-second race; if it wins, the legitimate page fails to
/// open and says so, instead of working alongside a silent intruder.
struct LaunchToken {
    secret: String,
    created: std::time::Instant,
}

/// A configured launch token, consumed or not. `None` inside: already used.
type SharedLaunchToken = Arc<std::sync::Mutex<Option<LaunchToken>>>;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    /// One-time token for this page's inline script.
    ///
    /// See [`Response::html`]: it replaces `'unsafe-inline'` in the content
    /// security policy.
    pub nonce: Option<String>,
}

impl Response {
    pub fn json(body: String) -> Response {
        Response {
            status: 200,
            content_type: "application/json; charset=utf-8".into(),
            body,
            nonce: None,
        }
    }

    /// A page, and the token that authorizes its only script.
    ///
    /// # What this closes
    ///
    /// The content security policy said `script-src 'unsafe-inline'`. It
    /// therefore authorized **any** inline script - including a script an
    /// attacker had managed to get written into the page. As long as no free
    /// text passes through the node, this hole stays theoretical; an audit
    /// checked it field by field. But a policy is only worth anything if it
    /// still holds on the day a field is added without thinking about it.
    ///
    /// So each response carries a randomly drawn token, written on the
    /// `<script>` tag **and** in the header. The browser then only runs that
    /// script: an injected script does not have the token, and does not run.
    /// Two pages served back to back do not have the same token, so it cannot
    /// be guessed.
    ///
    /// # Why it fails closed
    ///
    /// Without secure randomness, we do not make up a predictable token: the
    /// page then goes out with a policy that forbids **every** script, and it
    /// does not work. That is the right failure - a broken random generator is
    /// a much more serious problem than an inert page, and this node should
    /// not be handling keys in that state anyway.
    pub fn html(body: String) -> Response {
        let mut raw = [0u8; 16];
        let nonce = match crate::rng::fill(&mut raw) {
            Ok(()) => Some(raw.iter().map(|o| format!("{o:02x}")).collect::<String>()),
            Err(_) => None,
        };
        let body = match &nonce {
            Some(n) => body.replacen("<script>", &format!("<script nonce=\"{n}\">"), 1),
            None => body,
        };
        Response {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            body,
            nonce,
        }
    }
    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8".into(),
            body: body.into(),
            nonce: None,
        }
    }
    pub fn not_found() -> Response {
        Response::text(404, "not found")
    }
}

#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    /// Binding to a non-local interface without an access token.
    ExposedWithoutToken(SocketAddr),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Io(e) => write!(f, "network error: {e}"),
            HttpError::ExposedWithoutToken(a) => write!(
                f,
                "refusing to listen on {a} without a token: an RPC port reachable from \
                 outside gives access to the node. Use 127.0.0.1, or provide \
                 an access token."
            ),
        }
    }
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::Io(e)
    }
}

/// Constant-time comparison.
///
/// A naive comparison stops at the first differing byte: the response time
/// then reveals the correct prefix, and a token can be guessed byte by byte.
/// Here the time depends only on the lengths.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl ServerHandle {
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Starts the server in the background.
///
/// `token` protects access. It is **mandatory** for any listening address
/// that is not a loopback address.
pub fn serve<F>(address: &str, token: Option<String>, handler: F) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_with_public(address, token, &[], handler)
}

/// Like [`serve`], but with a list of paths served **without a token**.
///
/// # Why this list exists, and why it is explicit
///
/// The explorer asks the user for its token and then sends it in
/// `Authorization`. The page still has to be able to load first: requiring the
/// token for the page itself gave a plain-text `401`, with no way to enter it.
/// The node was protected and unusable.
///
/// This list must only contain **static** resources, which carry no data: the
/// explorer's HTML shell, nothing else. It is passed by the caller, named path
/// by path, and empty by default - the safe value is the one you get by doing
/// nothing.
pub fn serve_with_public<F>(
    address: &str,
    token: Option<String>,
    public_paths: &'static [&'static str],
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_full(address, token, public_paths, None, None, handler)
}

/// Like [`serve_with_public`], with a one-time launch token.
///
/// `launch_token` is what the launcher puts in the address the browser opens.
/// The page exchanges it for `token` through a `POST` on [`SESSION_PATH`],
/// only once and within [`LAUNCH_TOKEN_VALIDITY`]; see [`LaunchToken`] for
/// what this closes. `token` remains the only token that opens anything else.
pub fn serve_with_launch_token<F>(
    address: &str,
    token: String,
    launch_token: String,
    public_paths: &'static [&'static str],
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_full(
        address,
        Some(token),
        public_paths,
        None,
        Some(launch_token),
        handler,
    )
}

/// Like [`serve_with_public`], but for a service **meant to be public**.
///
/// # Why this mode exists, and why it is separate
///
/// This server's guard refuses any request whose `Host` header is not local.
/// That is the right rule for a wallet: the RPC listens on the local loopback,
/// and the user's browser is there too - without this guard, a hostile page
/// open in any tab would reach the funds through DNS rebinding.
///
/// A public explorer is the exact opposite: it is exposed **on purpose**,
/// behind a domain name, and the browsers that reach it will send that name in
/// `Host` and in `Origin`. The guard would refuse them all.
///
/// We could have rewritten those headers in the front server. That would
/// disable a security check through a configuration trick, without the
/// program knowing it is exposed. So the name is declared to the server, which
/// accepts it for itself alone and keeps all its other rules.
///
/// **The caller must guarantee that no wallet method is served on this
/// port.** This is checked at the call site, in the binary.
pub fn serve_public_web<F>(
    address: &str,
    public_host: String,
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    serve_full(address, None, &[], Some(public_host), None, handler)
}

fn serve_full<F>(
    address: &str,
    token: Option<String>,
    public_paths: &'static [&'static str],
    public_host: Option<String>,
    launch_token: Option<String>,
    handler: F,
) -> Result<ServerHandle, HttpError>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(address)?;
    let local = listener.local_addr()?;

    let loopback = match local.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    // --- Public mode goes behind a front server, never in front of one.
    //
    // It has no token: it is an explorer, made to be read by anyone. But this
    // server handles one connection per thread, sixty-four at most: exposed
    // directly, it falls to a handful of connections opened and never
    // finished - the Slowloris attack, which a penetration audit reproduced
    // here in two lines.
    //
    // The front server, on the other hand, is built for that. So we require
    // this mode to listen on the local loopback, and the refusal lives here
    // rather than in a documentation note nobody rereads.
    if !loopback && public_host.is_some() {
        return Err(HttpError::ExposedWithoutToken(local));
    }
    if !loopback && token.is_none() {
        return Err(HttpError::ExposedWithoutToken(local));
    }

    let host = Arc::new(public_host);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handler = Arc::new(handler);
    let token = Arc::new(token);
    let launch_token: Option<SharedLaunchToken> = launch_token.map(|secret| {
        Arc::new(std::sync::Mutex::new(Some(LaunchToken {
            secret,
            created: std::time::Instant::now(),
        })))
    });
    // Counter of connections in progress: without it, a connection cost one
    // system thread, with no cap.
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stop_thread.load(Ordering::Relaxed) {
                break;
            }
            let mut stream = match stream {
                Ok(f) => f,
                Err(_) => break,
            };
            // --- Defense: another account on the same machine.
            //
            // The address the browser opens is passed to the launcher as a
            // command-line argument, which every account on the machine can
            // read in `/proc/<pid>/cmdline`. The one-time launch token (see
            // `LaunchToken`) makes that read useless after the first opening;
            // this guard also closes the race before it. On Linux, we ask the
            // kernel **who** holds the other end of the local connection, and
            // refuse every account other than ours. Public mode, served by a
            // front server under another account, is not concerned: it has no
            // wallet.
            if host.is_none() {
                if let Err(reason) = local_account_allowed(&stream) {
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let _ = write_response(&mut stream, &Response::text(403, reason));
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }
            }
            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                // Plain refusal, without a thread: the client knows where it
                // stands and the node pays nothing.
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let _ = write_response(
                    &mut stream,
                    &Response::text(503, "too many simultaneous connections"),
                );
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let h = handler.clone();
            let t = token.clone();
            let c = active.clone();
            let pubs = public_paths;
            let hp = host.clone();
            let lt = launch_token.clone();
            c.fetch_add(1, Ordering::Relaxed);
            let spawned = std::thread::Builder::new().spawn(move || {
                // The read timeout must not be able to outlive the global
                // deadline: otherwise a single blocked read would overrun it
                // before it is even checked.
                let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
                let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
                handle_connection(
                    stream,
                    &*h,
                    t.as_ref().as_deref(),
                    pubs,
                    hp.as_deref(),
                    lt.as_ref(),
                );
                c.fetch_sub(1, Ordering::Relaxed);
            });
            if spawned.is_err() {
                active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    });

    Ok(ServerHandle { addr: local, stop })
}

/// What the kernel knows about the account holding the other end of a
/// connection.
///
/// `Account` and `Absent` are only constructed by reading `/proc/net/tcp`,
/// which only exists on Linux; elsewhere, `connection_owner` always returns
/// `Unknown`. These two variants are therefore dead code outside Linux - not
/// by oversight, but because the only machinery able to produce them is
/// missing. `verdict` reads them on every platform; it is their construction,
/// not their use, that is Linux-specific. We silence the warning where it is
/// expected, rather than everywhere.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "only constructed by reading /proc, which is Linux-specific"
    )
)]
#[derive(Debug, PartialEq, Eq)]
enum Owner {
    /// The account named by the socket table.
    Account(u32),
    /// The table was read, and the connection is not in it.
    Absent,
    /// No readable table: another system, or `/proc` inaccessible.
    Unknown,
}

/// Does the local connection come from our own account?
///
/// # Closed when we know, open only when we cannot know
///
/// Three answers, and three distinct verdicts:
///
/// - the kernel names an account: we admit it if it is ours, and only ours;
/// - the socket table can be read but **does not contain** this connection:
///   we refuse. The first version admitted this case, for fear of shutting the
///   door by mistake. But a loopback connection that the kernel table does not
///   list has no legitimate explanation - both ends are in the same network
///   namespace as we are -, and an "I can't find it" that means "come in" is a
///   guard that a parsing defect is enough to disarm without any test noticing;
/// - no table is readable - macOS, Windows, a masked `/proc`: we admit,
///   because there is nothing to read and refusing would make the wallet
///   unusable. On these systems, the one-time launch token is the barrier,
///   and the launcher says so.
///
/// A connection that does not come from the local loopback is not concerned:
/// it is not another account on this machine, and the token guards it.
fn local_account_allowed(stream: &TcpStream) -> Result<(), &'static str> {
    let (Ok(local), Ok(remote)) = (stream.local_addr(), stream.peer_addr()) else {
        return Ok(());
    };
    if !remote.ip().is_loopback() {
        return Ok(());
    }
    verdict(connection_owner(local, remote))
}

/// The guard's verdict, separate from the read so it can be tested alone.
fn verdict(p: Owner) -> Result<(), &'static str> {
    match p {
        Owner::Account(uid) if uid == current_uid() => Ok(()),
        Owner::Account(_) => Err("connection from another account on this machine: refused"),
        Owner::Absent => Err("local connection the kernel attributes to no account: refused"),
        Owner::Unknown => Ok(()),
    }
}

#[cfg(target_os = "linux")]
fn current_uid() -> u32 {
    // Safe: `geteuid` cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(not(target_os = "linux"))]
fn current_uid() -> u32 {
    0
}

/// The account that owns the client socket of a local connection, according
/// to `/proc/net/tcp` and `/proc/net/tcp6`.
///
/// Each line there describes a socket: its local address, its remote address
/// and its owner. The **client** socket of our connection has `remote` (what
/// we see as the peer) as its local address and `local` (our listening port)
/// as its remote address.
#[cfg(target_os = "linux")]
fn connection_owner(local: SocketAddr, remote: SocketAddr) -> Owner {
    let file = if remote.is_ipv4() {
        "/proc/net/tcp"
    } else {
        "/proc/net/tcp6"
    };
    match std::fs::read_to_string(file) {
        Ok(contents) => owner_in(&contents, local, remote),
        Err(_) => Owner::Unknown,
    }
}

/// Looks for the client socket in the contents of a `/proc/net/tcp*` table.
///
/// Separate from reading the file so that the test can present a table that
/// does not contain the connection - which cannot be provoked with a real
/// socket.
#[cfg(target_os = "linux")]
fn owner_in(contents: &str, local: SocketAddr, remote: SocketAddr) -> Owner {
    fn to_hex(a: &SocketAddr) -> Option<String> {
        match a {
            SocketAddr::V4(v) => {
                let o = v.ip().octets();
                // The kernel writes each 32-bit word in little-endian order.
                Some(format!(
                    "{:02X}{:02X}{:02X}{:02X}:{:04X}",
                    o[3],
                    o[2],
                    o[1],
                    o[0],
                    v.port()
                ))
            }
            SocketAddr::V6(v) => {
                let o = v.ip().octets();
                let mut s = String::with_capacity(32);
                for word in o.chunks(4) {
                    for b in word.iter().rev() {
                        s.push_str(&format!("{b:02X}"));
                    }
                }
                Some(format!("{s}:{:04X}", v.port()))
            }
        }
    }
    let (Some(want_local), Some(want_remote)) = (to_hex(&remote), to_hex(&local)) else {
        return Owner::Unknown;
    };
    for line in contents.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(_sl), Some(addr_local), Some(addr_remote)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if addr_local != want_local || addr_remote != want_remote {
            continue;
        }
        // st tx_queue:rx_queue tr:tm->when retrnsmt uid ...
        return match fields.nth(4).and_then(|u| u.parse().ok()) {
            Some(uid) => Owner::Account(uid),
            // The line is there but its account is unreadable: the table was
            // readable and attributes this connection to no one. We refuse,
            // as for a missing line - the guard does not open on a parsing
            // defect.
            None => Owner::Absent,
        };
    }
    Owner::Absent
}

#[cfg(not(target_os = "linux"))]
fn connection_owner(_local: SocketAddr, _remote: SocketAddr) -> Owner {
    Owner::Unknown
}

#[cfg(all(test, target_os = "linux"))]
mod local_account {
    use super::*;

    /// The kernel does name our account for a connection we open ourselves,
    /// over IPv4 as over IPv6.
    #[test]
    fn the_local_connection_is_attributed_to_our_account() {
        for listen in ["127.0.0.1:0", "[::1]:0"] {
            let Ok(l) = TcpListener::bind(listen) else {
                continue;
            };
            let addr = l.local_addr().unwrap();
            let client = TcpStream::connect(addr).unwrap();
            let (server, _) = l.accept().unwrap();
            let uid = connection_owner(server.local_addr().unwrap(), server.peer_addr().unwrap());
            assert_eq!(uid, Owner::Account(current_uid()), "on {listen}");
            assert!(local_account_allowed(&server).is_ok());
            drop(client);
        }
    }

    /// A local connection that the kernel table does not list is refused.
    ///
    /// The guard used to admit this case: "not found" meant "come in". A
    /// readable table that does not contain the connection has no legitimate
    /// explanation, and a guard that opens on a parsing defect is no guard.
    #[test]
    fn a_local_connection_missing_from_proc_is_refused() {
        let local: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:2".parse().unwrap();
        // The real file, with a 4-tuple that is not in it.
        assert_eq!(connection_owner(local, remote), Owner::Absent);
        assert!(verdict(Owner::Absent).is_err());

        // A made-up table: the header alone, then a line for another
        // connection, then the right line with another account, then ours.
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let other = "   0: 0100007F:0003 0100007F:0001 01 00000000:00000000 00:00000000 00000000  1000        0 0 1 0 100 0 0 10 0\n";
        let matching = |uid: u32| {
            format!(
            "   1: 0100007F:0002 0100007F:0001 01 00000000:00000000 00:00000000 00000000  {uid}        0 0 1 0 100 0 0 10 0\n"
        )
        };
        assert_eq!(owner_in(header, local, remote), Owner::Absent);
        assert_eq!(
            owner_in(&format!("{header}{other}"), local, remote),
            Owner::Absent
        );
        let foreign = current_uid().wrapping_add(1);
        assert_eq!(
            owner_in(
                &format!("{header}{other}{}", matching(foreign)),
                local,
                remote
            ),
            Owner::Account(foreign)
        );
        assert!(verdict(Owner::Account(foreign)).is_err());
        assert_eq!(
            owner_in(
                &format!("{header}{}", matching(current_uid())),
                local,
                remote
            ),
            Owner::Account(current_uid())
        );
        assert!(verdict(Owner::Account(current_uid())).is_ok());
        // With no table at all, we cannot know: it is the only open case.
        assert!(verdict(Owner::Unknown).is_ok());
    }
}

fn handle_connection<F>(
    mut stream: TcpStream,
    handler: &F,
    token: Option<&str>,
    public_paths: &[&str],
    public_host: Option<&str>,
    launch_token: Option<&SharedLaunchToken>,
) where
    F: Fn(Request) -> Response,
{
    // Global deadline: the sum of a request's reads is bounded, not only each
    // read taken separately.
    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let peer = stream.peer_addr().ok().map(|a| a.ip());
    let response = match read_request(&stream, deadline) {
        Ok(mut req) => {
            req.client = client_address(peer, &req.headers);
            let public = public_paths.contains(&req.path.as_str());
            // A static shell requested with GET is a page empty of data and
            // without effect. It alone tolerates being reached from another
            // port of the local loopback - see `browser_guard`.
            let shell = public && req.method == "GET";
            match browser_guard(&req, shell, public_host) {
                Some(reason) => Response::text(403, reason),
                // The launch token exchange is served here, before the token:
                // it is what hands the token out. It goes through the browser
                // guard like any POST, and is never a public path.
                None if req.method == "POST"
                    && req.path == SESSION_PATH
                    && launch_token.is_some() =>
                {
                    exchange_launch_token(&req, token, launch_token)
                }
                None => {
                    if let Some(expected) = token.filter(|_| !public) {
                        if !authorized(&req, expected) {
                            Response::text(401, "missing or invalid access token")
                        } else {
                            handler(req)
                        }
                    } else {
                        handler(req)
                    }
                }
            }
        }
        Err(msg) => Response::text(400, msg),
    };
    let _ = write_response(&mut stream, &response);
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Exchanges the launch token for the session token, only once.
///
/// The launch token arrives in `Authorization: Bearer`, like a token - that is
/// what the page knows how to send. It is taken out of its slot **before** the
/// response goes out: two concurrent exchanges cannot both succeed, the slot
/// is under a lock. An expired launch token is removed the same way, without
/// having been used. Every refusal has the same shape: a `401` without
/// detail, because saying "already used" to someone who should not know it
/// would amount to confirming to them that it existed.
fn exchange_launch_token(
    req: &Request,
    token: Option<&str>,
    launch_token: Option<&SharedLaunchToken>,
) -> Response {
    let deny = || Response::text(401, "launch token invalid, already used or expired");
    let (Some(token), Some(slot)) = (token, launch_token) else {
        return deny();
    };
    let Some(presented) = req
        .headers
        .get("authorization")
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
    else {
        return deny();
    };
    let Ok(mut guard) = slot.lock() else {
        return deny();
    };
    let Some(a) = guard.as_ref() else {
        return deny();
    };
    if a.created.elapsed() > LAUNCH_TOKEN_VALIDITY {
        *guard = None;
        return deny();
    }
    if !constant_time_eq(&presented, &a.secret) {
        return deny();
    }
    *guard = None;
    Response::json(
        crate::json::Json::obj()
            .set("token", crate::json::Json::str(token))
            .build()
            .encode(),
    )
}

/// Refuses what a browser should never be able to send here.
///
/// # The attack
///
/// The RPC listens on the local loopback, which gives a false sense of
/// security: **the user's browser is on the local loopback too**. A hostile
/// page open in any tab can therefore send a request to
/// `http://127.0.0.1:PORT/rpc`.
///
/// An audit demonstrated it in three ways:
///
/// - in JavaScript, a "simple" request in the CORS sense - so without a
///   preflight - reached the wallet;
/// - **without any JavaScript**: a `<form enctype="text/plain">` produces a
///   `name=value` body, and by placing the JSON in the *name* you get a valid
///   JSON-RPC document. One click was enough;
/// - through DNS rebinding: a name that first resolves to the attacker and
///   then to 127.0.0.1 makes the hostile page **same-origin**. It then reads
///   the responses, and does not merely send requests blindly.
///
/// # The four locks
///
/// Each one closes one of the paths. They are independent: none makes up for
/// the failure of another, and that is intended.
///
/// # The exception, and why it does not breach the wall
///
/// `shell` is true for a **GET on a path declared public**: the explorer page,
/// the wallet page, the setup page. These documents carry no data and trigger
/// no action; fetching them teaches nobody anything.
///
/// In that case alone, lock 3 also accepts `same-site`. The need is concrete:
/// the setup page listens on one port, the node on another, and going from
/// one to the other is a `same-site` navigation that the lock used to refuse -
/// the wallet opened on "cross-site request: refused".
///
/// What the exception does not grant:
///
/// - **`same-site` on `127.0.0.1` can only come from `127.0.0.1`.** The site
///   of an IP host is that IP itself; a remote attacker's page stays
///   `cross-site`, and is therefore refused.
/// - A domain name that would resolve to the local loopback - DNS rebinding -
///   first runs into lock 1, which reads `Host`.
/// - `/rpc` is never public, so never a shell: nothing that moves funds is
///   concerned.
/// - A POST is never a shell, even on a public path.
fn browser_guard(req: &Request, shell: bool, public_host: Option<&str>) -> Option<&'static str> {
    // 1. `Host`: only the local loopback is a legitimate host - or the name
    //    the operator has **declared** for a public service. Any other domain
    //    name signals DNS rebinding.
    match req.headers.get("host") {
        Some(host) if !local_host(host) && !declared_host(host, public_host) => return Some(
            "unexpected Host header: this service only answers to 127.0.0.1, [::1] or localhost",
        ),
        Some(_) => {}
        // Missing, it proves nothing - but a published service only answers
        // under the name it was given, and an anonymous request does not carry
        // that name. Locally we stay lenient: there the guard protects against
        // a browser, which always sends this header.
        None if public_host.is_some() => {
            return Some("missing Host header: this published service only answers under its name")
        }
        None => {}
    }

    // 2. `Origin` / `Referer`: a web page has no business here. Present and
    //    not local, they designate a third-party origin - except, once again,
    //    the declared name: the public explorer page is served from it, and
    //    its calls carry its origin.
    for key in ["origin", "referer"] {
        if let Some(v) = req.headers.get(key) {
            if !local_origin(v) && !declared_origin(v, public_host) {
                return Some("request sent from another origin: refused");
            }
        }
    }

    // 3. `Sec-Fetch-Site`: recent browsers add it automatically and a page
    //    cannot forge it - it is a header forbidden to scripts.
    if let Some(v) = req.headers.get("sec-fetch-site") {
        let allowed = v == "same-origin" || v == "none" || (shell && v == "same-site");
        if !allowed {
            return Some("cross-site request: refused");
        }
    }

    // 4. `Content-Type`: requiring `application/json` rules out the "simple"
    //    request. The browser will have to send a preflight, which this
    //    service does not satisfy - so the request will never go out.
    if req.method == "POST" {
        let ct = req
            .headers
            .get("content-type")
            .map(|s| {
                s.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        if ct != "application/json" {
            return Some("content-type: application/json required");
        }
    }
    None
}

/// The host declared by the operator for a public service, with or without a
/// port.
///
/// The comparison is case-insensitive - a domain name is - and exact on
/// everything else: `example.org.evil.example` must not pass for
/// `example.org`, and that is the kind of substring that fools a lazy
/// comparison.
fn declared_host(host: &str, declared: Option<&str>) -> bool {
    let Some(d) = declared else { return false };
    let bare = match host.rsplit_once(':') {
        // A single colon and a numeric port: it is a port.
        Some((before, after))
            if !before.contains(':') && after.chars().all(|c| c.is_ascii_digit()) =>
        {
            before
        }
        _ => host,
    };
    bare.eq_ignore_ascii_case(d)
}

/// An origin served by the declared host.
///
/// We require `https`: the public service is behind a front server that
/// terminates encryption, and a cleartext origin would signal something else.
fn declared_origin(value: &str, declared: Option<&str>) -> bool {
    let Some(d) = declared else { return false };
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    // The referrer carries a path; the origin does not. Cut at the first `/`.
    let host = rest.split('/').next().unwrap_or("");
    declared_host(host, Some(d))
}

/// A host that designates this machine, and nothing else.
fn local_host(host: &str) -> bool {
    // Separate the host from the port. Three possible forms, and only one way
    // not to get it wrong: handle the bracketed form separately, then only
    // split on `:` if there is just one - beyond that, it is a bare IPv6
    // address.
    let bare = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            // After the closing bracket, only a port is allowed.
            // `[::1].evil.example` is not a bracketed address, it is a name
            // wearing its costume.
            Some((inner, after)) if after.is_empty() || after.starts_with(':') => inner,
            _ => return false,
        }
    } else if host.matches(':').count() == 1 {
        host.split_once(':').map(|(h, _)| h).unwrap_or(host)
    } else {
        host
    };

    // --- An address, not a text prefix.
    //
    // The first version of this check tested `bare.starts_with("127.")`. It
    // was wrong, and wrong in the worst way: `127.0.0.1.evil.example` is a
    // domain name you can register in five minutes, and it satisfied the
    // test. It then got through all **four** locks at once - after rebinding,
    // the hostile page's origin becomes `http://127.0.0.1.evil.example:PORT`,
    // so `local_origin` accepts it for the same reason, `Sec-Fetch-Site` is
    // `same-origin`, and a same-origin request has no preflight, so it sets
    // the right `Content-Type`. DNS rebinding was entirely reopened.
    //
    // A host name is loopback only if it **is** a loopback address, or the
    // word `localhost`. We parse; we no longer compare prefixes.
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = bare.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = bare.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

/// An origin `http://127.0.0.1:PORT` or equivalent.
fn local_origin(v: &str) -> bool {
    let without_scheme = v
        .strip_prefix("http://")
        .or_else(|| v.strip_prefix("https://"))
        .unwrap_or(v);
    // A `Referer` carries a path: only keep the authority.
    let authority = without_scheme.split('/').next().unwrap_or("");
    local_host(authority)
}

fn authorized(req: &Request, expected: &str) -> bool {
    if let Some(a) = req.headers.get("authorization") {
        if let Some(v) = a.strip_prefix("Bearer ") {
            if constant_time_eq(v.trim(), expected) {
                return true;
            }
        }
    }
    // The token no longer travels in the URL.
    //
    // It used to be accepted there, and the explorer recommended it. A URL
    // ends up in the browser history, in the logs of every front server, and
    // in the `Referer` header of the first external resource loaded. A secret
    // that travels in a URL is no longer a secret.
    false
}

fn read_request(stream: &TcpStream, deadline: std::time::Instant) -> Result<Request, &'static str> {
    let mut reader = BufReader::new(stream);
    let check_deadline = |e: std::time::Instant| -> Result<(), &'static str> {
        if std::time::Instant::now() >= e {
            Err("request too slow")
        } else {
            Ok(())
        }
    };

    let mut line = String::new();
    read_header_line(&mut reader, &mut line, deadline)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request line")?.to_string();
    let target = parts.next().ok_or("missing target")?.to_string();

    let (path, query_string) = match target.split_once('?') {
        Some((c, q)) => (c.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    let mut query = BTreeMap::new();
    for pair in query_string.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(url_decode(k), url_decode(v));
    }

    let mut headers = BTreeMap::new();
    // --- Going over the limit is a refusal, never a silence.
    //
    // This loop used to stop at `MAX_HEADERS` **without saying anything**, and
    // reading the body picked up where it had left off: the excess headers
    // silently became the start of the body. No leak followed as long as
    // connections are closed after each response - but a request whose
    // splitting depends on the sender is exactly the ground for request
    // smuggling, and it is the kind of leniency that becomes a vulnerability
    // the day connection reuse is added.
    //
    // A penetration audit flagged it before this went live. We refuse.
    let mut end_of_headers = false;
    for _ in 0..MAX_HEADERS {
        let mut l = String::new();
        read_header_line(&mut reader, &mut l, deadline)?;
        let l = l.trim_end();
        if l.is_empty() {
            end_of_headers = true;
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            // --- A duplicate `Host` is never a clumsy mistake.
            //
            // The table keeps the last value: `Host: evil.example` followed by
            // `Host: explorer.example.org` therefore passed the guard, whereas
            // the first `Host` is the one an intermediary will have read. Two
            // machines that do not read the same value for the same field:
            // that is the definition of request smuggling.
            //
            // No browser sends two, and the standard forbids it. We refuse
            // rather than choose.
            if key == "host" && headers.contains_key("host") {
                return Err("duplicate Host header");
            }
            // --- Same reason for a duplicate `Content-Length`.
            //
            // The table kept the last value; two conflicting `Content-Length`
            // headers are the other classic half of request smuggling
            // (CL.CL). We refuse instead of choosing. Red-team 8b.
            if key == "content-length" && headers.contains_key("content-length") {
                return Err("duplicate Content-Length header");
            }
            // --- `Transfer-Encoding` is not handled, so it is not tolerated.
            //
            // The body is determined only by `Content-Length`. Silently
            // accepting a `Transfer-Encoding: chunked` we do not interpret
            // opens the TE.CL desynchronization with a front server that does
            // interpret it. We refuse any request that carries one.
            if key == "transfer-encoding" {
                return Err("Transfer-Encoding not supported");
            }
            headers.insert(key, v.trim().to_string());
        }
        check_deadline(deadline)?;
    }
    if !end_of_headers {
        return Err("too many headers");
    }

    // A `Content-Length` that is present but unreadable (multiple value
    // "5, 6", stray characters) is ambiguous: we refuse rather than silently
    // fall back to zero, which would let unread bytes be read again as a
    // second request by a front server. Red-team 8b.
    let length: usize = match headers.get("content-length") {
        None => 0,
        Some(v) => v.trim().parse().map_err(|_| "unreadable Content-Length")?,
    };
    if length > MAX_BODY {
        return Err("request body too large");
    }

    // --- The buffer is filled, not preallocated.
    //
    // `vec![0u8; length]` reserved a mebibyte on the sole strength of a
    // `Content-Length` the attacker writes, then waited for bytes that never
    // came. Each connection therefore cost a mebibyte of heap and a thread,
    // for zero bytes sent. We read in chunks: what is allocated is what has
    // arrived.
    let mut raw: Vec<u8> = Vec::new();
    if length > 0 {
        let mut buf = [0u8; 16 * 1024];
        while raw.len() < length {
            check_deadline(deadline)?;
            let wanted = (length - raw.len()).min(buf.len());
            match reader.read(&mut buf[..wanted]) {
                Ok(0) => return Err("incomplete request body"),
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                Err(_) => return Err("incomplete request body"),
            }
        }
    }
    let body = String::from_utf8_lossy(&raw).into_owned();

    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
        // Set by the caller, which alone knows the connection.
        client: None,
    })
}

/// Reads a line, without ever going past the deadline.
///
/// # Why the deadline goes all the way down here
///
/// The global deadline was only checked **between** lines. But this loop
/// reads byte by byte, and only the thirty-second read timeout applied to
/// each one. One byte every twenty-five seconds inside a **single** header -
/// up to `MAX_LINE`, that is 8 KiB - therefore held a connection, and its
/// thread, for tens of hours. With the cap of sixty-four connections, that
/// many connections of this kind were enough to shut the service down at a
/// trivial cost.
///
/// That is Slowloris, and a deadline that does not go all the way down to the
/// read is not a deadline.
fn read_header_line(
    reader: &mut BufReader<&TcpStream>,
    out: &mut String,
    deadline: std::time::Instant,
) -> Result<(), &'static str> {
    out.clear();
    let mut total = 0usize;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("request too slow");
        }
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => return Err("connection closed"),
            Ok(_) => {}
            Err(_) => return Err("read failed"),
        }
        total += 1;
        if total > MAX_LINE {
            return Err("header line too long");
        }
        if byte[0] == b'\n' {
            return Ok(());
        }
        out.push(byte[0] as char);
    }
}

fn url_decode(s: &str) -> String {
    let bytes: Vec<u8> = s.bytes().collect();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = |c: u8| (c as char).to_digit(16);
                match (h(bytes[i + 1]), h(bytes[i + 2])) {
                    (Some(a), Some(b)) => {
                        out.push((a * 16 + b) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The content security policy of this response.
///
/// `script-src` changes with the response: the page's token when there is
/// one, and an outright ban otherwise. A JSON response or an error message
/// has no script to run, and saying so costs one line.
///
/// `style-src` keeps `'unsafe-inline'`: the pages use `style` attributes,
/// which a token does not cover - that is a limitation of the standard, not a
/// choice. The risk is in no way comparable: an injected style sheet does not
/// execute.
fn csp_policy(r: &Response) -> String {
    let scripts = match &r.nonce {
        Some(n) => format!("'nonce-{n}'"),
        None => "'none'".to_string(),
    };
    format!(
        "default-src 'none'; script-src {scripts}; style-src 'unsafe-inline'; \
         connect-src 'self'; base-uri 'none'; form-action 'self'; \
         frame-ancestors 'none'"
    )
}

fn write_response(stream: &mut TcpStream, r: &Response) -> std::io::Result<()> {
    let reason_phrase = match r.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: {}\r\n\
         \r\n",
        r.status,
        reason_phrase,
        r.content_type,
        r.body.len(),
        csp_policy(r)
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(r.body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal HTTP client, for tests only.
    ///
    /// Closes the write side after sending. Without that, a truncated request
    /// leaves the server waiting for the rest until the read timeout, and the
    /// test suite takes minutes where it should take milliseconds - a defect
    /// observed on the first run.
    fn request(addr: SocketAddr, raw: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("connection");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(raw.as_bytes()).expect("send");
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut response = String::new();
        let _ = s.read_to_string(&mut response);
        response
    }

    fn get(addr: SocketAddr, path: &str) -> String {
        request(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        )
    }

    fn post(addr: SocketAddr, path: &str, body: &str) -> String {
        request(
            addr,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
    }

    fn echo() -> impl Fn(Request) -> Response + Send + Sync + 'static {
        |r: Request| {
            Response::text(
                200,
                &format!("{} {} q={:?} body={}", r.method, r.path, r.query, r.body),
            )
        }
    }

    #[test]
    fn a_get_request_is_served() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let r = get(h.addr, "/status");
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(r.contains("GET /status"), "{r}");
        h.shutdown();
    }

    #[test]
    fn query_parameters_are_decoded() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let r = get(h.addr, "/x?a=1&b=two%20words&c=a+b");
        assert!(r.contains("two words"), "{r}");
        assert!(r.contains("a b"), "{r}");
        h.shutdown();
    }

    #[test]
    fn a_post_body_is_read_entirely() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let body = r#"{"jsonrpc":"2.0","method":"getinfo","id":1}"#;
        let r = post(h.addr, "/rpc", body);
        assert!(r.contains("getinfo"), "{r}");
        h.shutdown();
    }

    #[test]
    fn a_hostile_page_does_not_reach_the_rpc() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let body = r#"{"jsonrpc":"2.0","method":"getinfo","id":1}"#;

        // 1. The form without JavaScript: `enctype="text/plain"`.
        let r = request(
            h.addr,
            &format!(
                "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Content-Type: text/plain\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");

        // 2. A third-party origin.
        let r = request(
            h.addr,
            &format!(
                "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Origin: http://attacker.example\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");

        // 3. The mark the browser sets itself.
        let r = request(
            h.addr,
            &format!(
                "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Sec-Fetch-Site: cross-site\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        h.shutdown();
    }

    /// Public mode accepts the declared name, and only that name.
    ///
    /// # What this mode disarms, and what it does not
    ///
    /// The guard refuses every non-local `Host`: that is the defense against
    /// DNS rebinding, the one that keeps a hostile page from reaching a
    /// wallet through the local loopback. A public explorer, however, is
    /// exposed **on purpose**: the browsers that reach it will send its domain
    /// name, and the guard would refuse them all.
    ///
    /// So we declare that name to the server. Everything else holds: another
    /// name is refused, a third-party origin is refused, and the
    /// `Content-Type` is still required. And the binary refuses to combine
    /// this mode with a wallet.
    #[test]
    fn public_mode_only_accepts_the_declared_name() {
        let h = serve_public_web("127.0.0.1:0", "explorer.example.org".to_string(), echo())
            .expect("startup");

        let with_headers = |headers: &str| {
            request(
                h.addr,
                &format!(
                    "POST /rpc HTTP/1.1\r\n{headers}\
                     Content-Type: application/json\r\nContent-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                ),
            )
        };

        // 1. The declared name passes, with or without a port, whatever the
        //    case.
        for host in [
            "explorer.example.org",
            "explorer.example.org:443",
            "Explorer.Example.Org",
        ] {
            let r = with_headers(&format!("Host: {host}\r\n"));
            assert!(r.starts_with("HTTP/1.1 200"), "{host} must pass: {r}");
        }

        // 2. The local loopback is still admitted: the front server talks
        //    locally.
        let r = with_headers("Host: 127.0.0.1\r\n");
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "the local front server must pass: {r}"
        );

        // 3. Another name is refused. And above all: a name that **contains**
        //    ours does not pass. `explorer.example.org.evil.example` is the
        //    kind of string that fools a lazy comparison.
        for host in [
            "evil.example",
            "explorer.example.org.evil.example",
            "example.org",
        ] {
            let r = with_headers(&format!("Host: {host}\r\n"));
            assert!(r.starts_with("HTTP/1.1 403"), "{host} must be refused: {r}");
        }

        // 4. The declared origin passes - the explorer page is served under
        //    this name - but a third-party origin is still refused.
        let r =
            with_headers("Host: explorer.example.org\r\nOrigin: https://explorer.example.org\r\n");
        assert!(
            r.starts_with("HTTP/1.1 200"),
            "the declared origin must pass: {r}"
        );
        let r = with_headers("Host: explorer.example.org\r\nOrigin: https://evil.example\r\n");
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "a third-party origin must be refused: {r}"
        );
        // Not in cleartext: the public service is behind a front server that
        // terminates encryption.
        let r =
            with_headers("Host: explorer.example.org\r\nOrigin: http://explorer.example.org\r\n");
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "a cleartext origin must be refused: {r}"
        );

        h.shutdown();
    }

    /// A duplicate `Host` is refused, in either order.
    ///
    /// The header table keeps the last value. `Host: evil.example` followed by
    /// `Host: explorer.example.org` therefore passed the guard, whereas an
    /// intermediary would have read the first one. Two machines that do not
    /// read the same value for the same field: that is the definition of
    /// request smuggling. Flagged by the penetration audit before going live.
    #[test]
    fn a_duplicate_host_is_refused_in_both_orders() {
        let h = serve_public_web("127.0.0.1:0", "explorer.example.org".to_string(), echo())
            .expect("startup");
        for (a, b) in [
            ("evil.example", "explorer.example.org"),
            ("explorer.example.org", "evil.example"),
        ] {
            let r = request(
                h.addr,
                &format!(
                    "POST /rpc HTTP/1.1\r\nHost: {a}\r\nHost: {b}\r\n\
                     Content-Type: application/json\r\nContent-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                ),
            );
            assert!(
                r.starts_with("HTTP/1.1 400"),
                "duplicate Host ({a}, {b}) must be refused: {r}"
            );
        }
        h.shutdown();
    }

    /// A published service only answers under its name: without `Host`, it
    /// refuses.
    #[test]
    fn public_mode_requires_a_host() {
        let h = serve_public_web("127.0.0.1:0", "explorer.example.org".to_string(), echo())
            .expect("startup");
        let r = request(
            h.addr,
            "POST /rpc HTTP/1.1\r\nContent-Type: application/json\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "without Host, refusal expected: {r}"
        );
        h.shutdown();
    }

    /// Public mode refuses to listen anywhere other than the local loopback.
    ///
    /// This server handles one connection per thread, sixty-four at most:
    /// exposed directly, it falls to a handful of connections opened and never
    /// finished. The audit reproduced it in two lines - two hundred silent
    /// connections, and the service answered 503 to everyone. The front server
    /// is built for that; the refusal lives here rather than in a note.
    #[test]
    fn public_mode_refuses_to_listen_outside_the_local_loopback() {
        let r = serve_public_web("0.0.0.0:0", "explorer.example.org".to_string(), echo());
        assert!(
            matches!(r, Err(HttpError::ExposedWithoutToken(_))),
            "a public mode exposed directly must be refused"
        );
    }

    /// Beyond the limit, the headers do not become the body.
    ///
    /// The loop used to stop at `MAX_HEADERS` without saying anything, and
    /// reading the body picked up where it had left off: the excess headers
    /// silently became the start of the body. A request whose splitting
    /// depends on the sender is the ground for request smuggling.
    #[test]
    fn too_many_headers_is_a_refusal_not_a_reinterpretation() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let padding: String = (0..MAX_HEADERS + 10)
            .map(|i| format!("X-{i}: v\r\n"))
            .collect();
        let r = request(
            h.addr,
            &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n{padding}Connection: close\r\n\r\n"),
        );
        assert!(
            r.starts_with("HTTP/1.1 400"),
            "the excess must be refused: {r}"
        );
        h.shutdown();
    }

    /// Public mode does not relax the `Content-Type`.
    #[test]
    fn public_mode_still_requires_json() {
        let h = serve_public_web("127.0.0.1:0", "explorer.example.org".to_string(), echo())
            .expect("startup");
        let r = request(
            h.addr,
            "POST /rpc HTTP/1.1\r\nHost: explorer.example.org\r\n\
             Content-Type: text/plain\r\nContent-Length: 2\r\n\
             Connection: close\r\n\r\n{}",
        );
        assert!(
            r.starts_with("HTTP/1.1 403"),
            "a non-JSON POST must be refused: {r}"
        );
        h.shutdown();
    }

    /// The `same-site` exception only applies to a shell requested with GET.
    ///
    /// It exists because the setup page and the node live on two ports, and
    /// going from one to the other is a `same-site` navigation. These four
    /// tests say where it stops.
    #[test]
    fn same_site_is_only_admitted_for_a_shell_being_read() {
        let h = serve_with_public("127.0.0.1:0", None, &["/wallet"], echo()).expect("startup");

        let with_site = |method: &str, path: &str, site: &str| {
            request(
                h.addr,
                &format!(
                    "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                     Sec-Fetch-Site: {site}\r\n\
                     Content-Type: application/json\r\nContent-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                ),
            )
        };

        // 1. The intended case: arriving on the wallet page from the setup
        //    page, which is on another port.
        let r = with_site("GET", "/wallet", "same-site");
        assert!(r.starts_with("HTTP/1.1 200"), "the shell must pass: {r}");

        // 2. The same relaxation does not extend to the RPC, which is not
        //    public. That is what moves funds.
        let r = with_site("POST", "/rpc", "same-site");
        assert!(r.starts_with("HTTP/1.1 403"), "the RPC must refuse: {r}");

        // 3. Nor to a POST on the public path itself: a shell is read, it is
        //    not written.
        let r = with_site("POST", "/wallet", "same-site");
        assert!(r.starts_with("HTTP/1.1 403"), "a POST is not a shell: {r}");

        // 4. And `cross-site` is still refused everywhere: it is the mark the
        //    browser sets when the page comes from somewhere other than this
        //    machine.
        let r = with_site("GET", "/wallet", "cross-site");
        assert!(r.starts_with("HTTP/1.1 403"), "cross-site must refuse: {r}");

        h.shutdown();
    }

    /// A host name is loopback only if it **is** a loopback address.
    ///
    /// The check first tested `starts_with("127.")`. An audit showed that
    /// `127.0.0.1.evil.example` - a domain name, not an address - passed, and
    /// entirely reopened DNS rebinding.
    #[test]
    fn a_name_that_looks_like_loopback_is_not_loopback() {
        for good in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.0.0.1:8080",
            "127.1.2.3",
            "[::1]",
            "[::1]:8080",
        ] {
            assert!(local_host(good), "{good} should be recognized as local");
        }
        for bad in [
            "127.0.0.1.evil.example",
            "127.0.0.1.evil.example:8080",
            "localhost.evil.example",
            "127-0-0-1.evil.example",
            "evil.example",
            "1270.0.0.1",
            "127.0.0.1x",
            "[::1].evil.example",
        ] {
            assert!(!local_host(bad), "{bad} must not pass for local");
            assert!(
                !local_origin(&format!("http://{bad}")),
                "origin http://{bad} must not pass for local"
            );
        }
    }

    /// DNS rebinding: a name that ends up pointing to 127.0.0.1 makes the
    /// hostile page same-origin. The `Host` header gives it away.
    #[test]
    fn a_foreign_host_is_refused() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let r = request(
            h.addr,
            "GET /status HTTP/1.1\r\nHost: rebind.attacker.example\r\nConnection: close\r\n\r\n",
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        h.shutdown();
    }

    /// The token must no longer open anything from the URL.
    #[test]
    fn the_token_no_longer_goes_through_the_url() {
        let h = serve("127.0.0.1:0", Some("secret".into()), echo()).expect("startup");
        let r = get(h.addr, "/status?token=secret");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        let r = request(
            h.addr,
            "GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Authorization: Bearer secret\r\nConnection: close\r\n\r\n",
        );
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        h.shutdown();
    }

    /// The most important safeguard in this file.
    #[test]
    fn listening_outside_loopback_without_a_token_is_refused() {
        let r = serve("0.0.0.0:0", None, echo());
        assert!(
            matches!(r, Err(HttpError::ExposedWithoutToken(_))),
            "a public RPC port without a token must be refused at startup"
        );
    }

    #[test]
    fn listening_outside_loopback_with_a_token_is_allowed() {
        let h = serve("0.0.0.0:0", Some("secret".into()), echo());
        assert!(h.is_ok());
        if let Ok(h) = h {
            h.shutdown();
        }
    }

    #[test]
    fn the_token_is_required_when_configured() {
        let h = serve("127.0.0.1:0", Some("s3cret".into()), echo()).expect("startup");

        assert!(get(h.addr, "/x").starts_with("HTTP/1.1 401"));
        assert!(get(h.addr, "/x?token=wrong").starts_with("HTTP/1.1 401"));
        // The token in the URL no longer opens anything, even when correct:
        // see `the_token_no_longer_goes_through_the_url`.
        assert!(get(h.addr, "/x?token=s3cret").starts_with("HTTP/1.1 401"));

        let with_header = request(
            h.addr,
            "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Authorization: Bearer s3cret\r\nConnection: close\r\n\r\n",
        );
        assert!(with_header.starts_with("HTTP/1.1 200"), "{with_header}");
        h.shutdown();
    }

    #[test]
    fn the_token_comparison_is_constant_time() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn a_body_too_large_is_refused() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let r = request(
            h.addr,
            &format!(
                "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_BODY + 1
            ),
        );
        assert!(r.starts_with("HTTP/1.1 400"), "{r}");
        h.shutdown();
    }

    #[test]
    fn an_endless_header_line_is_cut() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let mut raw = String::from("GET /x HTTP/1.1\r\nX: ");
        raw.push_str(&"a".repeat(MAX_LINE + 100));
        raw.push_str("\r\n\r\n");
        let r = request(h.addr, &raw);
        assert!(r.starts_with("HTTP/1.1 400"), "{r}");
        h.shutdown();
    }

    #[test]
    fn random_bytes_do_not_bring_the_server_down() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let mut g = 0x1234_5678u64;
        for _ in 0..20 {
            g = g.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let mut s = String::new();
            for i in 0..((g % 100) as usize) {
                s.push((((g >> (i % 40)) % 94) as u8 + 33) as char);
            }
            let _ = request(h.addr, &s);
        }
        // The server must still answer normally.
        assert!(get(h.addr, "/alive").starts_with("HTTP/1.1 200"));
        h.shutdown();
    }

    #[test]
    fn the_anti_sniffing_header_is_present() {
        let h = serve("127.0.0.1:0", None, echo()).expect("startup");
        let r = get(h.addr, "/x");
        assert!(r.contains("X-Content-Type-Options: nosniff"), "{r}");
        h.shutdown();
    }

    /// Test page: a single inline script, like the real pages.
    fn page() -> impl Fn(Request) -> Response + Send + Sync + 'static {
        |_r: Request| Response::html("<!doctype html><body><script>1;</script>".into())
    }

    /// Extracts the value of the token carried by the security policy.
    fn header_nonce(response: &str) -> Option<String> {
        let d = response.find("script-src 'nonce-")? + "script-src 'nonce-".len();
        let f = d + response[d..].find('\'')?;
        Some(response[d..f].to_string())
    }

    #[test]
    fn inline_script_is_no_longer_allowed_globally() {
        let h = serve("127.0.0.1:0", None, page()).expect("startup");
        let r = get(h.addr, "/p");
        let line = r
            .lines()
            .find(|l| l.starts_with("Content-Security-Policy:"))
            .unwrap_or("")
            .to_string();
        let scripts = line
            .split("script-src ")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap_or("")
            .to_string();
        assert!(
            !scripts.contains("unsafe-inline"),
            "the policy still allows any inline script: {line}"
        );
        assert!(line.contains("default-src 'none'"), "{line}");
        assert!(line.contains("frame-ancestors 'none'"), "{line}");
        h.shutdown();
    }

    #[test]
    fn the_header_token_is_the_page_token() {
        let h = serve("127.0.0.1:0", None, page()).expect("startup");
        let r = get(h.addr, "/p");
        let nonce = header_nonce(&r).expect("token in the header");
        assert_eq!(nonce.len(), 32, "token too short: {nonce}");
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()), "{nonce}");
        assert!(
            r.contains(&format!("<script nonce=\"{nonce}\">")),
            "the tag does not carry the header token: {r}"
        );
        h.shutdown();
    }

    #[test]
    fn two_served_pages_do_not_have_the_same_token() {
        let h = serve("127.0.0.1:0", None, page()).expect("startup");
        let a = header_nonce(&get(h.addr, "/p")).expect("token a");
        let b = header_nonce(&get(h.addr, "/p")).expect("token b");
        assert_ne!(a, b, "a predictable token is no token");
        h.shutdown();
    }

    /// An injected script does not have the token: it stays inert.
    ///
    /// The page only carries a single `<script>`, the one we wrote. A tag that
    /// arrived by another path cannot carry the token, drawn afterward and
    /// different at every response.
    #[test]
    fn a_second_script_does_not_receive_the_token() {
        let h = serve("127.0.0.1:0", None, |_r: Request| {
            Response::html("<script>good()</script><script>injected()</script>".into())
        })
        .expect("startup");
        let r = get(h.addr, "/p");
        let nonce = header_nonce(&r).expect("token");
        assert!(
            r.contains(&format!("<script nonce=\"{nonce}\">good()")),
            "{r}"
        );
        assert!(r.contains("<script>injected()"), "{r}");
        h.shutdown();
    }

    #[test]
    fn a_json_response_allows_no_script() {
        let h = serve("127.0.0.1:0", None, |_r: Request| {
            Response::json("{\"ok\":true}".into())
        })
        .expect("startup");
        let r = get(h.addr, "/j");
        assert!(r.contains("script-src 'none'"), "{r}");
        assert!(!r.contains("nonce-"), "{r}");
        h.shutdown();
    }

    /// The client address comes from the connection - except behind the
    /// local front server, where it comes from `X-Forwarded-For`. An
    /// `X-Forwarded-For` that does not arrive from the local loopback is a
    /// client in disguise: it is ignored.
    #[test]
    fn the_client_address_cannot_be_forged() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let remote: IpAddr = "203.0.113.9".parse().unwrap();
        let visitor: IpAddr = "198.51.100.7".parse().unwrap();
        let mut h = BTreeMap::new();

        // Without the header: the connection address, whatever it is.
        assert_eq!(client_address(Some(loopback), &h), Some(loopback));
        assert_eq!(client_address(Some(remote), &h), Some(remote));
        assert_eq!(client_address(None, &h), None);

        // From the local loopback, the header comes from the front server. We
        // read the LAST address: the one the front server appended at the
        // end, the real client. Here an attacker prefixed a forged address
        // (1.2.3.4), betting on a front server that APPENDS instead of
        // replacing; we take the last one, so the forgery does not choose its
        // identity. Red-team 8b.
        h.insert("x-forwarded-for".into(), "1.2.3.4, 198.51.100.7".into());
        assert_eq!(client_address(Some(loopback), &h), Some(visitor));

        // A single value: first and last coincide.
        h.insert("x-forwarded-for".into(), "198.51.100.7".into());
        assert_eq!(client_address(Some(loopback), &h), Some(visitor));

        // From elsewhere, the same header is a forgery: ignored.
        assert_eq!(client_address(Some(remote), &h), Some(remote));

        // Unreadable: we fall back to the connection, without failing.
        h.insert("x-forwarded-for".into(), "not-an-address".into());
        assert_eq!(client_address(Some(loopback), &h), Some(loopback));
    }

    /// The server sets `client` on the request it passes on, from the
    /// connection and the front server's header - and the header is only read
    /// on a local connection, which is the case for all of those here.
    #[test]
    fn the_forwarded_request_carries_the_client_address() {
        let h = serve("127.0.0.1:0", None, |r: Request| {
            Response::text(200, &format!("client={:?}", r.client))
        })
        .expect("startup");
        let r = get(h.addr, "/x");
        assert!(r.contains("client=Some(127.0.0.1)"), "{r}");
        let r = request(
            h.addr,
            "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 198.51.100.7\r\n\
             Connection: close\r\n\r\n",
        );
        assert!(r.contains("client=Some(198.51.100.7)"), "{r}");
        h.shutdown();
    }

    /// The launch token is exchanged once, and is then worth nothing.
    ///
    /// This is what closes A2 outside Linux: what lingers in the browser's
    /// command line is the launch token, not the session token, and after the
    /// first opening it no longer opens anything - neither the RPC, nor a
    /// second exchange.
    #[test]
    fn the_launch_token_is_used_only_once() {
        let h = serve_with_launch_token(
            "127.0.0.1:0",
            "session-token".into(),
            "l4unch".into(),
            &["/wallet"],
            echo(),
        )
        .expect("startup");
        let bearer = |method: &str, path: &str, secret: &str| {
            request(
                h.addr,
                &format!(
                    "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                     Content-Type: application/json\r\nContent-Length: 0\r\n\
                     Authorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
                ),
            )
        };

        // 1. The launch token opens nothing other than the exchange.
        let r = bearer("POST", "/rpc", "l4unch");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 2. A wrong launch token gets nothing.
        let r = bearer("POST", SESSION_PATH, "l4uncg");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 3. The exchange returns the session token, once.
        let r = bearer("POST", SESSION_PATH, "l4unch");
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.contains(r#"{"token":"session-token"}"#), "{r}");

        // 4. What was in argv is now worth nothing: neither a second exchange,
        //    nor the RPC.
        let r = bearer("POST", SESSION_PATH, "l4unch");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");
        let r = bearer("POST", "/rpc", "l4unch");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 5. The session token, on the other hand, opens the RPC - and is not
        //    a launch token.
        let r = bearer("POST", "/rpc", "session-token");
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        let r = bearer("POST", SESSION_PATH, "session-token");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");

        // 6. The exchange is a JSON POST like any other: the browser guard
        //    applies to it.
        let r = request(
            h.addr,
            &format!(
                "POST {SESSION_PATH} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Origin: http://attacker.example\r\nContent-Type: application/json\r\n\
                 Content-Length: 0\r\nAuthorization: Bearer l4unch\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        h.shutdown();
    }

    /// Without a configured launch token, the exchange path does not exist: it
    /// falls through to the token, then to the router, like any other path.
    #[test]
    fn without_a_launch_token_the_exchange_path_is_just_a_path() {
        let h = serve("127.0.0.1:0", Some("s".into()), echo()).expect("startup");
        let r = post(h.addr, SESSION_PATH, "{}");
        assert!(r.starts_with("HTTP/1.1 401"), "{r}");
        h.shutdown();
    }
}
