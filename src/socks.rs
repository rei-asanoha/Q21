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
    /// 240.0.0.0/4, a reserved range that no real peer uses and that the node
    /// never hands out ([`crate::addr::routable`]). Distinct names get
    /// distinct stand-ins, which keeps two onion peers from being taken for
    /// the same machine.
    pub fn label(&self) -> SocketAddr {
        match self {
            Target::V4(ip, p) => SocketAddr::from((*ip, *p)),
            Target::Name(h, p) => {
                let d = crate::sha256::sha256(h.as_bytes());
                let b = &d;
                SocketAddr::from(([240 | (b[0] & 0x0f), b[1], b[2], b[3]], *p))
            }
        }
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

/// Finds a local Tor: the service port first, then Tor Browser's. Only
/// checks that something listens; the first connection tells the rest.
pub fn find_local_tor() -> Option<SocketAddr> {
    [TOR_SERVICE_PORT, TOR_BROWSER_PORT]
        .into_iter()
        .map(|p| SocketAddr::from(([127, 0, 0, 1], p)))
        .find(|a| TcpStream::connect_timeout(a, Duration::from_millis(500)).is_ok())
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
            SocketAddr::V4(v) => {
                assert!(v.ip().octets()[0] >= 240, "in 240.0.0.0/4");
                assert!(!crate::addr::routable(v.ip().octets(), true));
            }
            _ => panic!("IPv4 stand-in expected"),
        }
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
