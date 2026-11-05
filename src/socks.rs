//! Outgoing connections through a SOCKS5 proxy: in practice, Tor.
//!
//! # Why
//!
//! A node that connects directly shows its IP address to every peer it
//! reaches. Through Tor, a peer sees a Tor exit, or nothing at all when the
//! peer is itself an onion service (`….onion`). That is what lets someone run
//! a node — even a mining one — without the network learning where it is.
//!
//! # What this module does, and does not do
//!
//! The client side of RFC 1928, nothing more: no authentication, a CONNECT
//! command, an IPv4 address or a **name** as the destination. Names are
//! always handed to the proxy as names (address type 3): resolving them here
//! would send a DNS query from this machine, which is exactly the leak Tor is
//! there to avoid, and an onion address cannot be resolved anyway.
//!
//! No dependency: the protocol is a handful of bytes, and this program does
//! not take on a library for that.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Where Tor listens when it runs as a service (Linux, Raspberry Pi,
/// Homebrew on macOS).
pub const TOR_SERVICE_PORT: u16 = 9050;
/// Where Tor Browser listens while it is open (Windows, macOS, Linux).
pub const TOR_BROWSER_PORT: u16 = 9150;

/// Time allowed for a whole connection through Tor. Building a circuit to an
/// onion service regularly takes several seconds, and the first visit to one
/// also fetches its descriptor: half a minute was sometimes not enough. The
/// node dials on a thread of its own, so the wait holds up nothing else.
pub const TOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Destination of a connection through the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    V4([u8; 4], u16),
    /// A host name or an onion address, resolved by the proxy.
    Name(String, u16),
}

impl Target {
    /// Reads `host:port`, `host` (with `default_port`), or an IPv4 address.
    pub fn parse(raw: &str, default_port: u16) -> Result<Target, String> {
        let raw = raw.trim();
        let (host, port) = match raw.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| format!("{raw}: unreadable port"))?;
                (h, port)
            }
            Some(_) => return Err(format!("{raw}: IPv6 is not supported through a proxy")),
            None => (raw, default_port),
        };
        if host.is_empty() || port == 0 {
            return Err(format!("{raw}: empty host or port"));
        }
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Ok(Target::V4(ip.octets(), port));
        }
        // RFC 1928: a name is at most 255 bytes. A Tor v3 onion address is 62.
        if host.len() > 255
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(format!("{raw}: unreadable host name"));
        }
        Ok(Target::Name(host.to_ascii_lowercase(), port))
    }

    pub fn port(&self) -> u16 {
        match self {
            Target::V4(_, p) | Target::Name(_, p) => *p,
        }
    }

    /// Is this an onion service address?
    pub fn is_onion(&self) -> bool {
        matches!(self, Target::Name(h, _) if h.ends_with(".onion"))
    }

    /// The address this peer is filed under in the node.
    ///
    /// An IPv4 destination is itself. A name has no address of its own (an
    /// onion service has none at all), so it gets a stable stand-in in
    /// `100::/64`, the IPv6 block reserved for discarding traffic (RFC 6666):
    /// no real peer has one, and the address book holds IPv4 only. The 64
    /// bits after the prefix are the first of the name's SHA-256. Distinct
    /// names get distinct stand-ins, which keeps two onion peers from being
    /// taken for the same machine. Until 0.5.10 the stand-in was in
    /// 240.0.0.0/4, 28 bits: a name sharing an entry point's stand-in was
    /// found in minutes, and took its place (red-team campaign 9).
    pub fn label(&self) -> SocketAddr {
        match self {
            Target::V4(ip, p) => SocketAddr::from((*ip, *p)),
            Target::Name(h, p) => {
                let d = crate::sha256::sha256(h.as_bytes());
                let mut o = [0u8; 16];
                o[0] = 0x01;
                o[8..].copy_from_slice(&d[..8]);
                SocketAddr::from((std::net::Ipv6Addr::from(o), *p))
            }
        }
    }

    /// Whether `a` is the stand-in of a name (see [`Target::label`]).
    pub fn is_label(a: SocketAddr) -> bool {
        matches!(a, SocketAddr::V6(v) if v.ip().octets()[..8] == [1, 0, 0, 0, 0, 0, 0, 0])
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::V4(ip, p) => write!(f, "{}.{}.{}.{}:{p}", ip[0], ip[1], ip[2], ip[3]),
            Target::Name(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// Opens a TCP connection to `target` through the SOCKS5 proxy at `proxy`.
pub fn connect(
    proxy: SocketAddr,
    target: &Target,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(&proxy, timeout)?;
    // A proxy on this computer must still be this account's or the
    // system's, at every connection: chosen once at startup, its port could
    // be taken later by another account (a system Tor restarting), or held
    // from the start by one, the node then waiting on it for a Tor
    // (round 2 of red-team campaign 9). Only on Linux, see
    // [`listener_owner_trusted`].
    let ours = s.local_addr().ok();
    if foreign_proxy(proxy, |port| {
        listener_owner_trusted(port) && ours.map_or(true, |o| connection_owner_trusted(proxy, o))
    }) {
        drop(s);
        note_foreign_proxy(proxy);
        return Err(failure(FOREIGN_PROXY));
    }
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;

    // Greeting: version 5, one method, "no authentication".
    s.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    if reply != [5, 0] {
        return Err(failure(
            "the proxy refused the connection (is it a SOCKS5 proxy?)",
        ));
    }

    // CONNECT request.
    let mut req = vec![5, 1, 0];
    match target {
        Target::V4(ip, port) => {
            req.push(1);
            req.extend_from_slice(ip);
            req.extend_from_slice(&port.to_be_bytes());
        }
        Target::Name(host, port) => {
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
    }
    s.write_all(&req)?;

    // Reply: VER REP RSV ATYP, then the bound address, which we read and drop.
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(failure("unreadable proxy reply"));
    }
    if head[1] != 0 {
        return Err(failure(reply_text(head[1])));
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n)?;
            n[0] as usize + 2
        }
        _ => return Err(failure("unreadable proxy reply")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)?;
    // The caller sets its own timeouts for the peer connection.
    s.set_read_timeout(None)?;
    s.set_write_timeout(None)?;
    Ok(s)
}

/// Finds a local Tor: the service port first, then Tor Browser's. Checks
/// that something listens, and on Linux that it belongs to this account or
/// to a system account (the Tor service's): a program of another person's
/// account listening on 9050 or 9150 would otherwise see, and answer, every
/// connection of this node (red-team campaign 8). Elsewhere, the first
/// connection tells the rest.
pub fn find_local_tor() -> Option<SocketAddr> {
    [TOR_SERVICE_PORT, TOR_BROWSER_PORT]
        .into_iter()
        .map(|p| SocketAddr::from(([127, 0, 0, 1], p)))
        .find(|a| {
            TcpStream::connect_timeout(a, Duration::from_millis(500)).is_ok()
                && listener_owner_trusted(a.port())
        })
}

/// Below this, a Linux account is a system one (`SYS_UID_MAX` is 999).
const FIRST_PERSON_UID: u32 = 1000;

/// Whether every program listening on `port`, on any address and in IPv4
/// or IPv6, runs as this account or a system one: a connection to
/// 127.0.0.1 also reaches a listener on all addresses (`0.0.0.0`, `::`),
/// which the check of 0.5.9 did not see (red-team campaign 9). Not known
/// (not Linux, `/proc` unreadable, no listener found): trusted, as before
/// 0.5.9.
fn listener_owner_trusted(port: u16) -> bool {
    let Some(me) = own_uid() else {
        return true;
    };
    listener_uids(port)
        .into_iter()
        .all(|owner| owner_trusted(owner, me))
}

/// This account, or a system one.
fn owner_trusted(owner: u32, me: u32) -> bool {
    owner == me || owner < FIRST_PERSON_UID
}

/// The accounts of the sockets listening on `port`, whatever their
/// address, from `/proc/net/tcp` and `/proc/net/tcp6`.
fn listener_uids(port: u16) -> Vec<u32> {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .flat_map(|text| listener_uids_in(&text, port))
        .collect()
}

/// The parsing half of [`listener_uids`]: `local_address` is the address,
/// then `:` and the port, in hexadecimal; state `0A` is listening; the
/// eighth field the account.
fn listener_uids_in(text: &str, port: u16) -> Vec<u32> {
    let wanted = format!(":{port:04X}");
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 7 && f[1].ends_with(&wanted) && f[3] == "0A")
                .then(|| f[7].parse().ok())
                .flatten()
        })
        .collect()
}

/// This process's account, from `/proc/self/status`.
fn own_uid() -> Option<u32> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

/// Whether `proxy` is on this computer and its port held by a program of
/// another account, as `trusted` tells.
fn foreign_proxy(proxy: SocketAddr, trusted: impl Fn(u16) -> bool) -> bool {
    proxy.ip().is_loopback() && !trusted(proxy.port())
}

/// Whether the socket that accepted our connection `ours` → `proxy` runs as
/// this account or a system one. The listener alone is not enough: a
/// program of another account that closes its listening socket at once after
/// each connection it accepts is no listener when we look (round 3 of
/// red-team campaign 9). Read from `/proc/net/tcp` and `/proc/net/tcp6`, an
/// IPv4 connection to a listener on every address being listed there as
/// IPv4 mapped into IPv6. Not known (not Linux, or our own end of the
/// connection not listed, as on systems where `/proc/net` says nothing):
/// trusted, as before; our end listed and not the other: not trusted.
fn connection_owner_trusted(proxy: SocketAddr, ours: SocketAddr) -> bool {
    let Some(me) = own_uid() else {
        return true;
    };
    let mut seen = false;
    let mut owners = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(f) {
            let (s, o) = connection_owners_in(&text, proxy, ours);
            seen |= s;
            owners.extend(o);
        }
    }
    if !seen {
        return true;
    }
    !owners.is_empty() && owners.into_iter().all(|o| owner_trusted(o, me))
}

/// The parsing half of [`connection_owner_trusted`]: whether our end of the
/// connection is listed, and the accounts of the other end.
fn connection_owners_in(text: &str, proxy: SocketAddr, ours: SocketAddr) -> (bool, Vec<u32>) {
    let (p, o) = (proc_forms(proxy), proc_forms(ours));
    let mut seen = false;
    let mut owners = Vec::new();
    for l in text.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() <= 7 {
            continue;
        }
        let (local, remote) = (f[1].to_ascii_uppercase(), f[2].to_ascii_uppercase());
        if o.contains(&local) && p.contains(&remote) {
            seen = true;
        }
        if p.contains(&local) && o.contains(&remote) {
            if let Ok(uid) = f[7].parse() {
                owners.push(uid);
            }
        }
    }
    (seen, owners)
}

/// How `/proc/net/tcp` and `tcp6` write `a`: each 32-bit word of the address
/// in this machine's byte order, in hexadecimal, then `:` and the port; an
/// IPv4 address also as mapped into IPv6.
fn proc_forms(a: SocketAddr) -> Vec<String> {
    let word = |b: &[u8]| format!("{:08X}", u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
    let v6 = |o: [u8; 16]| o.chunks(4).map(word).collect::<String>();
    let port = format!(":{:04X}", a.port());
    match a.ip() {
        std::net::IpAddr::V4(ip) => vec![
            word(&ip.octets()) + &port,
            v6(ip.to_ipv6_mapped().octets()) + &port,
        ],
        std::net::IpAddr::V6(ip) => vec![v6(ip.octets()) + &port],
    }
}

/// Why a connection through a local proxy was not made.
pub const FOREIGN_PROXY: &str =
    "the proxy's port on this computer is held by a program of another account: nothing is sent through it";

/// Says so on the console, at most every ten minutes.
fn note_foreign_proxy(proxy: SocketAddr) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 600
        && LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        eprintln!(
            "warning: {proxy}: {FOREIGN_PROXY}. Start Tor under your own account, or use the \
             Tor in the tor/ folder next to the program."
        );
    }
}

fn failure(msg: &str) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "the proxy failed",
        2 => "the proxy does not allow this connection",
        3 => "network unreachable through the proxy",
        4 => "host unreachable through the proxy (an onion service that is offline?)",
        5 => "connection refused by the destination",
        6 => "the proxy gave up (TTL expired)",
        7 => "the proxy does not support this command",
        8 => "the proxy does not support this address type",
        _ => "the proxy refused the connection",
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Round 2 of red-team campaign 9: a node with no Tor waited on
    /// 127.0.0.1:9050 whoever listened there, and a port chosen at startup
    /// could change hands later. Every connection through a local proxy
    /// checks its owner; a proxy elsewhere is the user's own choice.
    #[test]
    fn every_connection_through_a_local_proxy_checks_its_owner() {
        let local: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let elsewhere: SocketAddr = "192.0.2.7:9050".parse().unwrap();
        assert!(foreign_proxy(local, |_| false));
        assert!(!foreign_proxy(local, |_| true));
        assert!(!foreign_proxy(elsewhere, |_| false));
        assert!(foreign_proxy("[::1]:9150".parse().unwrap(), |p| p != 9150));
        // The real check passes for a port of this account.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        assert!(!foreign_proxy(addr, listener_owner_trusted));
    }

    /// Round 3 of red-team campaign 9: a program of another account that
    /// closes its listener right after accepting was no listener when we
    /// looked. The socket that accepted our very connection is checked.
    #[test]
    fn the_socket_that_accepted_our_connection_is_checked() {
        let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let ours: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        // 127.0.0.1:9050 is 0100007F:235A, port 41000 is A028 (little-endian
        // words, as on the machines this runs on).
        let row = |local: &str, remote: &str, uid: u32| {
            format!("   0: {local} {remote} 01 00000000:00000000 00:00000000 00000000 {uid:>5}        0 1 1\n")
        };
        let head =
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n";
        if cfg!(target_endian = "little") {
            let both = format!(
                "{head}{}{}",
                row("0100007F:A028", "0100007F:235A", 1000),
                row("0100007F:235A", "0100007F:A028", 1001)
            );
            assert_eq!(connection_owners_in(&both, proxy, ours), (true, vec![1001]));
            // Ours listed, the other end not: seen, no owner.
            let alone = format!("{head}{}", row("0100007F:A028", "0100007F:235A", 1000));
            assert_eq!(connection_owners_in(&alone, proxy, ours), (true, vec![]));
            // A listener on every address: IPv4 mapped into IPv6.
            let mapped = format!(
                "{head}{}",
                row(
                    "0000000000000000FFFF00000100007F:235A",
                    "0000000000000000FFFF00000100007F:A028",
                    0
                )
            );
            assert_eq!(connection_owners_in(&mapped, proxy, ours), (false, vec![0]));
        }
        // Live: a connection of this account to itself is trusted.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let c = TcpStream::connect(addr).unwrap();
        let _accepted = l.accept().unwrap();
        assert!(connection_owner_trusted(addr, c.local_addr().unwrap()));
        assert!(!foreign_proxy(addr, |port| listener_owner_trusted(port)
            && connection_owner_trusted(addr, c.local_addr().unwrap())));
    }

    /// The owner of a listening port is read from `/proc/net/tcp`; another
    /// person's account is not trusted, a system one is (red-team campaign
    /// 8, third round).
    #[test]
    fn a_tor_port_of_another_account_is_not_trusted() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
             0: 0100007F:235A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1 1 0000000000000000 100 0 0 10 0\n   \
             1: 0100007F:23BE 00000000:0000 0A 00000000:00000000 00:00000000 00000000   108        0 2 1 0000000000000000 100 0 0 10 0\n   \
             2: 0100007F:2382 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1001        0 3 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(listener_uids_in(text, TOR_SERVICE_PORT), vec![1001]);
        assert_eq!(listener_uids_in(text, TOR_BROWSER_PORT), vec![108]);
        assert!(listener_uids_in(text, 0x2382).is_empty(), "not listening");
        // Red-team campaign 9: on all addresses, IPv4 or IPv6, a listener of
        // another account is seen too.
        let wild = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
             0: 00000000:235A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1500        0 1 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(listener_uids_in(wild, TOR_SERVICE_PORT), vec![1500]);
        let wild6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
             0: 00000000000000000000000000000000:23BE 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1500        0 2 1 0000000000000000 100 0 0 10 0\n   \
             1: 00000000000000000000000001000000:23BE 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   108        0 3 1 0000000000000000 100 0 0 10 0\n";
        assert_eq!(listener_uids_in(wild6, TOR_BROWSER_PORT), vec![1500, 108]);
        // One foreign listener among trusted ones: not trusted.
        assert!(!listener_uids_in(wild6, TOR_BROWSER_PORT)
            .into_iter()
            .all(|o| owner_trusted(o, 1000)));
        assert!(owner_trusted(108, 1000), "the Tor service's account");
        assert!(owner_trusted(1000, 1000), "this account");
        assert!(!owner_trusted(1001, 1000), "another person's");
    }

    /// A minimal SOCKS5 server for the tests: no authentication, CONNECT
    /// only, names looked up in `names` (which stands for the Tor network),
    /// then a byte relay in both directions. Returns its address and the
    /// list of destinations it was asked for.
    pub fn fake_proxy(
        names: Vec<(String, SocketAddr)>,
    ) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = asked.clone();
        std::thread::spawn(move || {
            for c in listener.incoming() {
                let Ok(mut c) = c else { break };
                let names = names.clone();
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut g = [0u8; 3];
                    if c.read_exact(&mut g).is_err() {
                        return;
                    }
                    let _ = c.write_all(&[5, 0]);
                    let mut h = [0u8; 4];
                    if c.read_exact(&mut h).is_err() {
                        return;
                    }
                    let (dest, label) = match h[3] {
                        1 => {
                            let mut b = [0u8; 6];
                            let _ = c.read_exact(&mut b);
                            let a = SocketAddr::from((
                                [b[0], b[1], b[2], b[3]],
                                u16::from_be_bytes([b[4], b[5]]),
                            ));
                            (Some(a), a.to_string())
                        }
                        3 => {
                            let mut n = [0u8; 1];
                            let _ = c.read_exact(&mut n);
                            let mut name = vec![0u8; n[0] as usize];
                            let _ = c.read_exact(&mut name);
                            let mut p = [0u8; 2];
                            let _ = c.read_exact(&mut p);
                            let name = String::from_utf8_lossy(&name).to_string();
                            let port = u16::from_be_bytes(p);
                            let found = names.iter().find(|(k, _)| *k == name).map(|(_, a)| *a);
                            (found, format!("{name}:{port}"))
                        }
                        _ => (None, String::new()),
                    };
                    seen.lock().unwrap().push(label);
                    let Some(dest) = dest else {
                        let _ = c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
                        return;
                    };
                    let Ok(up) = TcpStream::connect_timeout(&dest, Duration::from_secs(1)) else {
                        let _ = c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
                        return;
                    };
                    let _ = c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]);
                    let (mut a, mut b) = (c.try_clone().unwrap(), up.try_clone().unwrap());
                    let (mut c2, mut up2) = (c, up);
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut a, &mut up2);
                    });
                    let _ = std::io::copy(&mut b, &mut c2);
                });
            }
        });
        (addr, asked)
    }

    #[test]
    fn targets_are_read_as_written() {
        assert_eq!(
            Target::parse("92.222.86.135:21121", 1).unwrap(),
            Target::V4([92, 222, 86, 135], 21121)
        );
        assert_eq!(
            Target::parse("bootstrap.q21.dev", 21121).unwrap(),
            Target::Name("bootstrap.q21.dev".into(), 21121)
        );
        let onion = format!("{}.onion:21121", "a".repeat(56));
        let t = Target::parse(&onion, 1).unwrap();
        assert!(t.is_onion());
        assert!(Target::parse("[::1]:21121", 1).is_err());
        assert!(Target::parse("bad host:1", 1).is_err());
        assert!(Target::parse("host:0", 1).is_err());
    }

    #[test]
    fn a_name_gets_a_stable_reserved_stand_in() {
        let a = Target::Name(format!("{}.onion", "a".repeat(56)), 21121);
        let b = Target::Name(format!("{}.onion", "b".repeat(56)), 21121);
        assert_eq!(a.label(), a.label());
        assert_ne!(a.label(), b.label());
        match a.label() {
            SocketAddr::V6(v) => {
                assert_eq!(v.ip().segments()[..4], [0x100, 0, 0, 0], "in 100::/64");
                assert_eq!(v.port(), 21121);
            }
            _ => panic!("IPv6 stand-in expected"),
        }
        assert!(Target::is_label(a.label()));
        assert!(!Target::is_label(
            Target::V4([203, 0, 113, 7], 21121).label()
        ));
        assert!(!Target::is_label("[::1]:21121".parse().unwrap()));
        // The two names of red-team campaign 9, alike in the 28 bits of the
        // former stand-in, differ now.
        let e = "sxm4dtvws3po2jlygseb5bqrnpeseulqduksvkad4hv6pdfeprxr5nsd";
        let x = "a2xkz4jamqrsypkyosizxpl6ms7yz4rku4rr4f2pp7rjaq7nyxwn66od";
        assert_ne!(
            Target::Name(format!("{e}.onion"), 21121).label(),
            Target::Name(format!("{x}.onion"), 21121).label()
        );
    }

    /// A name goes to the proxy as a name: no lookup on this machine.
    #[test]
    fn a_name_is_resolved_by_the_proxy() {
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = echo.accept() {
                let mut b = [0u8; 5];
                if s.read_exact(&mut b).is_ok() {
                    let _ = s.write_all(&b);
                }
            }
        });
        let onion = format!("{}.onion", "q".repeat(56));
        let (proxy, asked) = fake_proxy(vec![(onion.clone(), echo_addr)]);
        let mut s = connect(
            proxy,
            &Target::Name(onion.clone(), 21121),
            Duration::from_secs(5),
        )
        .expect("through the proxy");
        s.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        assert_eq!(asked.lock().unwrap()[0], format!("{onion}:21121"));

        // An unknown onion service: a clear refusal, not a hang.
        let err = connect(
            proxy,
            &Target::Name(format!("{}.onion", "z".repeat(56)), 21121),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unreachable"), "{err}");
    }
}
