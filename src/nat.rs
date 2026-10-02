//! Automatic port opening on the router.
//!
//! # Why this module exists
//!
//! Behind a home Internet router, a wallet goes out to the network but
//! nothing comes in: the router blocks, that is its job. The network then
//! took the shape of a star whose only public entry point was the center —
//! and whoever cuts the center cuts everyone. For the network to do without
//! a center, some of the wallets must be reachable. This module asks the
//! router to open the node's port, without requiring anything from the user.
//!
//! # Two protocols, in this order
//!
//! - **NAT-PMP** (RFC 6886): one UDP round trip to the router. Simple, fast,
//!   present on Apple routers and many others.
//! - **UPnP IGD**: a multicast discovery, then a SOAP request. Chattier, but
//!   the most widespread on consumer routers.
//!
//! No dependencies: the standard library is enough for UDP, TCP, and the
//! little HTTP and XML these protocols require. It is the project's rule, and
//! it is also one less attack surface.
//!
//! # What we do not take at face value
//!
//! The router is a device on the local network, and a local network can host
//! a hostile device impersonating it. This module therefore bounds every
//! read, sets every timeout, and only considers an external address valid if
//! it is public. A private or CGNAT address returned by the router means a
//! second router in front of it: the port is opened for nothing, and we do
//! not announce it.
//!
//! Above all, it only talks to **the** router, never to a third party that a
//! response would point it to: the SSDP response must designate the device
//! that sent it; the description must come from the default gateway when the
//! system knows it; and the control URL read from the description must
//! designate that same device. A device that won the race of responses can
//! therefore neither make us send a request to a machine of its choosing, nor
//! — when the gateway is known — dictate an external address to us.
//!
//! # What this module does not guarantee
//!
//! A successful port opening does not prove that the node is reachable from
//! the outside: an upstream firewall, or an operator that shares one address
//! among several customers, can still block it. The program therefore says
//! "port opening requested from the router: succeeded", never "reachable" —
//! that would promise what cannot be verified from here.

use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::Duration;

/// Lease requested from the router, in seconds. Two hours: renewed at
/// half-life by the caller, it survives a prolonged lack of renewal without
/// lingering forever if the program dies without removing the mapping.
pub const LEASE_SECONDS: u32 = 7200;

/// Maximum size of an HTTP response read from a device on the local network.
const MAX_HTTP_RESPONSE: usize = 64 * 1024;

/// Connect and read timeout toward the router, over HTTP.
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

/// NAT-PMP port, fixed by RFC 6886.
const NATPMP_PORT: u16 = 5351;

/// SSDP multicast address, fixed by UPnP.
const SSDP_ADDRESS: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    NatPmp,
    Upnp,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::NatPmp => write!(f, "NAT-PMP"),
            Method::Upnp => write!(f, "UPnP"),
        }
    }
}

/// A port mapping obtained from the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub method: Method,
    /// The address the router says it presents to the Internet.
    pub external_address: Ipv4Addr,
    /// The port opened on the Internet side. Equal to the requested port,
    /// unless the router assigned another one (NAT-PMP allows it).
    pub external_port: u16,
    /// The lease granted, in seconds. Zero = permanent (some UPnP routers can
    /// only do that).
    pub lease_seconds: u32,
    /// What is needed to remove the mapping (UPnP): the control URL and the
    /// service type. Empty for NAT-PMP, which removes with a zero lease.
    control: Option<(String, String)>,
    /// The gateway that answered (NAT-PMP), for the removal.
    gateway: Option<Ipv4Addr>,
}

#[derive(Debug)]
pub enum NatError {
    /// Neither method succeeded: the router does not answer, or refuses.
    NoMethod { natpmp: String, upnp: String },
    /// The address returned by the router is not public: there is a second
    /// router in front, the mapping is useless.
    NonPublicAddress(Ipv4Addr),
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatError::NoMethod { natpmp, upnp } => write!(
                f,
                "the router did not open the port (NAT-PMP: {natpmp}; UPnP: {upnp})"
            ),
            NatError::NonPublicAddress(ip) => write!(
                f,
                "the router returns the address {ip}, which is not public: a second router \
                 or an operator shares the address upstream, the opened port is useless"
            ),
        }
    }
}

impl std::error::Error for NatError {}

/// Asks the router to open `port` over TCP, toward this machine.
///
/// Tries NAT-PMP, then UPnP. Returns the mapping obtained, whose external
/// address has been verified to be public.
pub fn open_port(port: u16) -> Result<PortMapping, NatError> {
    let natpmp_error = match natpmp_open(port) {
        Ok(o) => return check_public(o),
        Err(e) => e,
    };
    let upnp_error = match upnp_open(port) {
        Ok(o) => return check_public(o),
        Err(e) => e,
    };
    Err(NatError::NoMethod {
        natpmp: natpmp_error,
        upnp: upnp_error,
    })
}

/// Renews an existing mapping. Same path as the initial opening, through the
/// same method: the router resets the lease.
pub fn renew(o: &PortMapping, port: u16) -> Result<PortMapping, NatError> {
    let r = match o.method {
        Method::NatPmp => natpmp_open(port),
        Method::Upnp => upnp_open(port),
    };
    match r {
        Ok(n) => check_public(n),
        // If the original method no longer answers, we start from scratch.
        Err(_) => open_port(port),
    }
}

/// Removes the mapping. No guarantee: the router may have restarted, or may
/// refuse. A failure here has no consequence — an unrenewed lease expires on
/// its own.
pub fn close_port(o: &PortMapping, port: u16) {
    match o.method {
        Method::NatPmp => {
            if let Some(gw) = o.gateway {
                // Zero lease = removal, per RFC 6886.
                let _ = natpmp_mapping_request(gw, port, 0, 0);
            }
        }
        Method::Upnp => {
            if let Some((url, service)) = &o.control {
                let args = format!(
                    "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort>\
                     <NewProtocol>TCP</NewProtocol>",
                    o.external_port
                );
                let _ = upnp_soap(url, service, "DeletePortMapping", &args);
            }
        }
    }
}

fn check_public(o: PortMapping) -> Result<PortMapping, NatError> {
    if !public_address(o.external_address) {
        return Err(NatError::NonPublicAddress(o.external_address));
    }
    Ok(o)
}

/// An IPv4 address that the rest of the Internet can reach.
///
/// Rejects private ranges, CGNAT (100.64/10), loopback, link-local,
/// multicast, and unspecified addresses. This is the criterion that decides
/// whether the mapping deserves to be announced to other nodes.
pub fn public_address(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let private =
        o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168);
    let cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
    let link_local = o[0] == 169 && o[1] == 254;
    !(private
        || cgnat
        || link_local
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || o[0] == 0
        || o[0] >= 240)
}

// ---------------------------------------------------------------------------
// Local address and gateway
// ---------------------------------------------------------------------------

/// This machine's IPv4 address on its local network.
///
/// Classic trick: "connecting" a UDP socket to a public address sends no
/// packet, but forces the system to choose the outgoing interface, whose
/// address we read.
pub fn local_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect((Ipv4Addr::new(1, 1, 1, 1), 53)).ok()?;
    match s.local_addr().ok()? {
        std::net::SocketAddr::V4(a) => Some(*a.ip()),
        _ => None,
    }
}

/// The addresses where the router probably is, in the order to try.
///
/// On Linux, the kernel's default route gives the exact answer, and we stick
/// to it. Elsewhere, we try the conventions of consumer routers: the `.1` and
/// the `.254` of the local network. NAT-PMP only answers at the right
/// address; a wrong one only costs a short timeout.
pub fn candidate_gateways(local_addr: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
    candidates_from(system_gateway(), local_addr)
}

/// The choice of candidates, given the system's gateway.
///
/// # The defect this closes
///
/// When the gateway was known, the `.1` and `.254` conventions were still
/// added to it. If the real router did not answer NAT-PMP, we therefore moved
/// on to these guessed addresses — where a hostile device on the local
/// network can set itself up and impersonate the router. The default gateway
/// *is* the router: when we know it, we talk only to it.
fn candidates_from(gateway: Option<Ipv4Addr>, local_addr: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
    if let Some(gw) = gateway {
        return vec![gw];
    }
    let mut v: Vec<Ipv4Addr> = Vec::new();
    if let Some(ip) = local_addr {
        let o = ip.octets();
        for last in [1u8, 254] {
            let c = Ipv4Addr::new(o[0], o[1], o[2], last);
            if c != ip && !v.contains(&c) {
                v.push(c);
            }
        }
    }
    v
}

#[cfg(target_os = "linux")]
fn system_gateway() -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    gateway_from_routing_table(&content)
}

#[cfg(not(target_os = "linux"))]
fn system_gateway() -> Option<Ipv4Addr> {
    None
}

/// Reads the default route's gateway in the `/proc/net/route` format:
/// whitespace-separated columns, destination and gateway in little-endian
/// hexadecimal.
///
/// Specific to Linux (only the Linux `system_gateway` calls it), plus the
/// tests that check it. Elsewhere, `/proc/net/route` does not exist.
#[cfg(any(target_os = "linux", test))]
fn gateway_from_routing_table(content: &str) -> Option<Ipv4Addr> {
    for line in content.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _iface = cols.next()?;
        let dest = cols.next()?;
        let gw = cols.next()?;
        if dest != "00000000" {
            continue;
        }
        let n = u32::from_str_radix(gw, 16).ok()?;
        let b = n.to_le_bytes();
        let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        if !ip.is_unspecified() {
            return Some(ip);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886)
// ---------------------------------------------------------------------------

fn natpmp_open(port: u16) -> Result<PortMapping, String> {
    let local = local_ip();
    let candidates = candidate_gateways(local);
    if candidates.is_empty() {
        return Err("no candidate gateway".into());
    }
    let mut last = String::from("no response");
    for gw in candidates {
        let external = match natpmp_address_request(gw) {
            Ok(ip) => ip,
            Err(e) => {
                last = format!("{gw}: {e}");
                continue;
            }
        };
        let (external_port, lease) = natpmp_mapping_request(gw, port, port, LEASE_SECONDS)
            .map_err(|e| format!("{gw}: {e}"))?;
        return Ok(PortMapping {
            method: Method::NatPmp,
            external_address: external,
            external_port,
            lease_seconds: lease,
            control: None,
            gateway: Some(gw),
        });
    }
    Err(last)
}

/// "External address" request: two bytes, twelve-byte response.
fn natpmp_address_request(gw: Ipv4Addr) -> Result<Ipv4Addr, String> {
    let response = natpmp_exchange(gw, &[0u8, 0u8], 12)?;
    natpmp_decode_address(&response)
}

/// TCP mapping request. Returns (granted external port, granted lease).
fn natpmp_mapping_request(
    gw: Ipv4Addr,
    internal_port: u16,
    desired_external_port: u16,
    lease: u32,
) -> Result<(u16, u32), String> {
    let mut req = [0u8; 12];
    req[1] = 2; // opcode 2 = TCP
    req[4..6].copy_from_slice(&internal_port.to_be_bytes());
    req[6..8].copy_from_slice(&desired_external_port.to_be_bytes());
    req[8..12].copy_from_slice(&lease.to_be_bytes());
    let response = natpmp_exchange(gw, &req, 16)?;
    natpmp_decode_mapping(&response, internal_port)
}

/// Sends `req` and waits for a response of at least `min` bytes, with the
/// RFC's retransmissions (250 ms, 500 ms, 1 s). Three attempts: enough for a
/// router that is present, short for a router that is absent.
fn natpmp_exchange(gw: Ipv4Addr, req: &[u8], min: usize) -> Result<Vec<u8>, String> {
    let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    s.connect(SocketAddrV4::new(gw, NATPMP_PORT))
        .map_err(|e| e.to_string())?;
    let mut wait = Duration::from_millis(250);
    for _ in 0..3 {
        s.send(req).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(wait)).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 64];
        match s.recv(&mut buf) {
            Ok(n) if n >= min => return Ok(buf[..n].to_vec()),
            Ok(_) => return Err("response too short".into()),
            Err(_) => wait *= 2,
        }
    }
    Err("no NAT-PMP response".into())
}

fn natpmp_code(code: u16) -> String {
    match code {
        0 => "success".into(),
        1 => "unsupported version".into(),
        2 => "refused by the router (NAT-PMP disabled?)".into(),
        3 => "the router has no external address (no connection?)".into(),
        4 => "the router is out of resources".into(),
        5 => "unsupported operation".into(),
        n => format!("code {n}"),
    }
}

fn natpmp_decode_address(r: &[u8]) -> Result<Ipv4Addr, String> {
    if r.len() < 12 {
        return Err("response too short".into());
    }
    if r[0] != 0 || r[1] != 128 {
        return Err("unexpected response".into());
    }
    let code = u16::from_be_bytes([r[2], r[3]]);
    if code != 0 {
        return Err(natpmp_code(code));
    }
    Ok(Ipv4Addr::new(r[8], r[9], r[10], r[11]))
}

fn natpmp_decode_mapping(r: &[u8], internal_port: u16) -> Result<(u16, u32), String> {
    if r.len() < 16 {
        return Err("response too short".into());
    }
    if r[0] != 0 || r[1] != 130 {
        return Err("unexpected response".into());
    }
    let code = u16::from_be_bytes([r[2], r[3]]);
    if code != 0 {
        return Err(natpmp_code(code));
    }
    let internal = u16::from_be_bytes([r[8], r[9]]);
    if internal != internal_port {
        return Err("the router answers for another port".into());
    }
    let external = u16::from_be_bytes([r[10], r[11]]);
    let lease = u32::from_be_bytes([r[12], r[13], r[14], r[15]]);
    Ok((external, lease))
}

// ---------------------------------------------------------------------------
// UPnP IGD: SSDP discovery, description, SOAP
// ---------------------------------------------------------------------------

fn upnp_open(port: u16) -> Result<PortMapping, String> {
    let local = local_ip().ok_or("local address not found")?;
    let location = ssdp_discover().ok_or("no UPnP router answers")?;
    // The description must come from a private address: a router is on the
    // local network. A URL pointing to a public address would be a device
    // sending us elsewhere — we refuse.
    let (host, _port, _path) = split_url(&location).ok_or("invalid description URL")?;
    let desc_ip: Ipv4Addr = host.parse().map_err(|_| "non-numeric description host")?;
    if public_address(desc_ip) {
        return Err("the UPnP description comes from a public address: refused".into());
    }
    // The router *is* the default gateway. When the system knows it, the
    // description must come from it: another device on the local network,
    // even private, even first to answer, is not the router.
    if let Some(gw) = system_gateway() {
        if desc_ip != gw {
            return Err(format!(
                "the UPnP description comes from {desc_ip}, which is not the gateway {gw}: refused"
            ));
        }
    }
    let body = http_get(&location)?;
    let (control, service) = upnp_extract_control(&body, &location)
        .ok_or("WANIPConnection service not found in the description")?;
    // The control URL comes out of the XML, hence from the device itself: it
    // must designate that same device. A description that sends us to talk to
    // a third party — loopback, another machine, a public host — is not a
    // router, and we do not send any request out to that third party.
    if !url_designates(&control, desc_ip) {
        return Err("the UPnP control URL does not designate the router: refused".into());
    }

    // Some routers only accept permanent leases (error 725): we then fall
    // back to zero.
    let mut lease = LEASE_SECONDS;
    let mut last = String::new();
    for attempt in 0..2 {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol><NewInternalPort>{port}</NewInternalPort>\
             <NewInternalClient>{local}</NewInternalClient><NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>Q21</NewPortMappingDescription>\
             <NewLeaseDuration>{lease}</NewLeaseDuration>"
        );
        match upnp_soap(&control, &service, "AddPortMapping", &args) {
            Ok(_) => break,
            Err(e) => {
                last = e;
                if attempt == 0 && last.contains("725") {
                    lease = 0;
                    continue;
                }
                return Err(format!("AddPortMapping: {last}"));
            }
        }
    }
    let _ = last;
    let rep = upnp_soap(&control, &service, "GetExternalIPAddress", "")?;
    let external = extract_tag(&rep, "NewExternalIPAddress")
        .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
        .ok_or("external address missing from the UPnP response")?;
    Ok(PortMapping {
        method: Method::Upnp,
        external_address: external,
        external_port: port,
        lease_seconds: lease,
        control: Some((control, service)),
        gateway: None,
    })
}

/// SSDP discovery: one multicast question, the first response that announces
/// a gateway. Returns the description URL (the `LOCATION` header).
fn ssdp_discover() -> Option<String> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.set_multicast_ttl_v4(2).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2500))).ok()?;
    for st in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    ] {
        let req = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDRESS}:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\n\
             MX: 2\r\nST: {st}\r\n\r\n"
        );
        let _ = s.send_to(req.as_bytes(), SocketAddrV4::new(SSDP_ADDRESS, SSDP_PORT));
    }
    let mut buf = [0u8; 2048];
    // Several devices may answer: we take the first response that carries a
    // LOCATION designating its own sender, without waiting for the others
    // beyond the timeout.
    for _ in 0..8 {
        match s.recv_from(&mut buf) {
            Ok((n, source)) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let Some(loc) = ssdp_extract_location(&text) {
                    // A response whose LOCATION points somewhere other than its
                    // sender is a redirection, not a router: we ignore it and
                    // wait for the next one.
                    if location_comes_from(&loc, &source) {
                        return Some(loc);
                    }
                }
            }
            Err(_) => break,
        }
    }
    None
}

/// Does the `LOCATION` of an SSDP response designate the device that sent it,
/// itself on the local network?
///
/// # The defect this closes
///
/// The sender of the response was not looked at: any device on the local
/// network could answer first and send us to fetch the description from a
/// third party. Tying the description to its sender removes that lever: to
/// impersonate the router, one must at least be the device being designated.
fn location_comes_from(location: &str, source: &std::net::SocketAddr) -> bool {
    let src = match source {
        std::net::SocketAddr::V4(a) => *a.ip(),
        std::net::SocketAddr::V6(_) => return false,
    };
    let ip = match split_url(location).and_then(|(h, _, _)| h.parse::<Ipv4Addr>().ok()) {
        Some(ip) => ip,
        None => return false,
    };
    ip == src && !public_address(ip)
}

/// Does the URL designate exactly this address?
fn url_designates(url: &str, ip: Ipv4Addr) -> bool {
    split_url(url)
        .and_then(|(h, _, _)| h.parse::<Ipv4Addr>().ok())
        .map(|h| h == ip)
        .unwrap_or(false)
}

/// The `LOCATION` header of an SSDP response, case-insensitive on the name.
fn ssdp_extract_location(response: &str) -> Option<String> {
    for line in response.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("location") {
                let v = value.trim();
                if v.starts_with("http://") {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// In the XML description, the WAN connection service and its control URL.
///
/// Prefers `WANIPConnection:2`, then `:1`, then `WANPPPConnection:1`. A
/// relative control URL is resolved against `URLBase` if present, otherwise
/// against the origin of the description. No XML parser: we look for the
/// tags, which is enough for a document of which we only read two fields.
fn upnp_extract_control(xml: &str, location: &str) -> Option<(String, String)> {
    let base = extract_tag(xml, "URLBase")
        .map(|b| b.trim().trim_end_matches('/').to_string())
        .filter(|b| b.starts_with("http://"))
        .or_else(|| url_origin(location))?;
    let preferred = [
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ];
    for wanted in preferred {
        let mut rest = xml;
        while let Some(start) = rest.find("<service>") {
            let after = &rest[start..];
            let end = match after.find("</service>") {
                Some(f) => f,
                None => break,
            };
            let section = &after[..end];
            if extract_tag(section, "serviceType").map(|s| s.trim() == wanted) == Some(true) {
                if let Some(url) = extract_tag(section, "controlURL") {
                    let url = url.trim();
                    let full = if url.starts_with("http://") {
                        url.to_string()
                    } else if url.starts_with('/') {
                        format!("{base}{url}")
                    } else {
                        format!("{base}/{url}")
                    };
                    return Some((full, wanted.to_string()));
                }
            }
            rest = &after[end + "</service>".len()..];
        }
    }
    None
}

/// The content of the first `<name>...</name>` tag.
fn extract_tag(text: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let d = text.find(&open)? + open.len();
    let f = text[d..].find(&close)? + d;
    Some(text[d..f].to_string())
}

/// Sends a SOAP action to the control URL. Returns the response body, or an
/// error that contains the UPnP fault code when there is one.
fn upnp_soap(url: &str, service: &str, action: &str, args: &str) -> Result<String, String> {
    let body = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>"
    );
    let (host, port, path) = split_url(url).ok_or("invalid control URL")?;
    let header = format!(
        "POST {path} HTTP/1.1\r\nHOST: {host}:{port}\r\n\
         CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
         SOAPACTION: \"{service}#{action}\"\r\nCONTENT-LENGTH: {}\r\nCONNECTION: close\r\n\r\n",
        body.len()
    );
    let mut request = header.into_bytes();
    request.extend_from_slice(body.as_bytes());
    let (status, response) = http_exchange(&host, port, &request)?;
    if status == 200 {
        return Ok(response);
    }
    // A SOAP fault carries a UPnP code in <errorCode>. We pass it up so that
    // the caller recognizes 725 "permanent leases only".
    if let Some(code) = extract_tag(&response, "errorCode") {
        return Err(format!("UPnP error {} (HTTP {status})", code.trim()));
    }
    Err(format!("HTTP {status}"))
}

/// Fetches a document by HTTP GET, bounding its size.
fn http_get(url: &str) -> Result<String, String> {
    let (host, port, path) = split_url(url).ok_or("invalid URL")?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHOST: {host}:{port}\r\nCONNECTION: close\r\n\r\n");
    let (status, body) = http_exchange(&host, port, request.as_bytes())?;
    if status != 200 {
        return Err(format!("HTTP {status}"));
    }
    Ok(body)
}

/// A raw HTTP round trip to a device on the local network. Returns (status,
/// body). Fixed timeouts, bounded body: we never trust the announced size, we
/// cap the actual read.
fn http_exchange(host: &str, port: u16, request: &[u8]) -> Result<(u16, String), String> {
    let stream = TcpStream::connect_timeout(
        &SocketAddrV4::new(host.parse().map_err(|_| "non-numeric host")?, port).into(),
        HTTP_TIMEOUT,
    )
    .map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).ok();
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).ok();
    let mut stream = stream;
    stream.write_all(request).map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buffer[..n]);
                if raw.len() > MAX_HTTP_RESPONSE {
                    raw.truncate(MAX_HTTP_RESPONSE);
                    break;
                }
            }
            Err(_) => break,
        }
    }
    split_http_response(&raw)
}

/// Separates the status and the body of an HTTP response. `\r\n\r\n` marks the
/// end of the headers; we do not interpret the headers, only the status code.
fn split_http_response(raw: &[u8]) -> Result<(u16, String), String> {
    let text = String::from_utf8_lossy(raw);
    let first = text.lines().next().ok_or("empty response")?;
    // "HTTP/1.1 200 OK": the code is the second word.
    let status = first
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("unreadable status line")?;
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => String::new(),
    };
    Ok((status, body))
}

/// Splits an `http://host:port/path` URL into its three pieces. The port
/// defaults to 80, the path to `/`.
fn split_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80u16),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

/// The `http://host:port` origin of a URL, without the path.
fn url_origin(url: &str) -> Option<String> {
    let (host, port, _) = split_url(url)?;
    Some(format!("http://{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_or_cgnat_address_is_not_public() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 4, 5),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1), // CGNAT
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            assert!(!public_address(ip), "{ip} must not be public");
        }
    }

    #[test]
    fn a_real_public_address_is_recognized() {
        for ip in [
            Ipv4Addr::new(92, 222, 86, 135), // the public bootstrap node (OVH)
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(203, 0, 113, 7),
        ] {
            assert!(public_address(ip), "{ip} must be public");
        }
    }

    #[test]
    fn the_gateway_is_read_from_the_routing_table() {
        // Default route line: destination 00000000, gateway 0101A8C0 =
        // 192.168.1.1 in little-endian.
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     eth0\t00000000\t0101A8C0\t0003\n\
                     eth0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(
            gateway_from_routing_table(table),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn no_default_route_no_gateway() {
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     eth0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(gateway_from_routing_table(table), None);
    }

    #[test]
    fn without_a_known_gateway_the_candidates_cover_1_and_254() {
        let c = candidates_from(None, Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert!(c.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(c.contains(&Ipv4Addr::new(192, 168, 1, 254)));
    }

    /// When the gateway is known, we no longer guess other addresses: a
    /// hostile device set up at `.254` would never be queried.
    #[test]
    fn with_a_known_gateway_we_talk_only_to_it() {
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        let c = candidates_from(Some(gw), Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(c, vec![gw]);
    }

    /// An SSDP response is kept only if its LOCATION designates the device
    /// that sent it, on the local network.
    #[test]
    fn the_ssdp_location_must_designate_its_sender() {
        let router = std::net::SocketAddr::from(([192, 168, 1, 1], 1900));
        assert!(location_comes_from(
            "http://192.168.1.1:5000/desc.xml",
            &router
        ));
        // Redirection to a third party on the local network: refused.
        assert!(!location_comes_from(
            "http://192.168.1.77:5000/desc.xml",
            &router
        ));
        // Redirection to loopback or to a public host: refused.
        assert!(!location_comes_from(
            "http://127.0.0.1:21080/desc.xml",
            &router
        ));
        assert!(!location_comes_from("http://203.0.113.9/desc.xml", &router));
        // A sender that designates itself but with a public address is not a
        // router on the local network.
        let public = std::net::SocketAddr::from(([203, 0, 113, 9], 1900));
        assert!(!location_comes_from("http://203.0.113.9/desc.xml", &public));
    }

    /// The control URL read from the description must designate the router,
    /// and nothing else.
    ///
    /// # The defect this test pins down
    ///
    /// An audit showed that a hostile description could point its
    /// `controlURL` at loopback or at a public host: the node then sent its
    /// SOAP requests there, and announced the external address that this
    /// third party returned to it. The address check covered only the
    /// description URL, never the control URL.
    #[test]
    fn the_control_url_must_designate_the_router() {
        let router = Ipv4Addr::new(192, 168, 1, 1);
        for target in [
            "http://127.0.0.1:21080/ctl", // toward a local service
            "http://203.0.113.9:80/ctl",  // toward a public host
            "http://192.168.1.77:80/ctl", // toward a neighbor on the local network
        ] {
            let xml = format!(
                "<root><device><serviceList><service>\
                 <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
                 <controlURL>{target}</controlURL></service></serviceList></device></root>"
            );
            let (url, _) = upnp_extract_control(&xml, "http://192.168.1.1:5000/desc.xml").unwrap();
            assert!(!url_designates(&url, router), "{target} should be refused");
        }
        // The real router, as a relative URL resolved against the origin:
        // accepted.
        let xml = "<root><device><serviceList><service>\
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
            <controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>";
        let (url, _) = upnp_extract_control(xml, "http://192.168.1.1:5000/desc.xml").unwrap();
        assert!(url_designates(&url, router));
    }

    #[test]
    fn the_natpmp_mapping_decodes() {
        // Mapping response: version 0, op 130, code 0, internal port 21121,
        // external port 21121, lease 7200.
        let mut r = [0u8; 16];
        r[1] = 130;
        r[8..10].copy_from_slice(&21121u16.to_be_bytes());
        r[10..12].copy_from_slice(&21121u16.to_be_bytes());
        r[12..16].copy_from_slice(&7200u32.to_be_bytes());
        assert_eq!(natpmp_decode_mapping(&r, 21121), Ok((21121, 7200)));
    }

    #[test]
    fn a_natpmp_error_code_is_passed_up() {
        let mut r = [0u8; 16];
        r[1] = 130;
        r[2..4].copy_from_slice(&2u16.to_be_bytes()); // refused
        assert!(natpmp_decode_mapping(&r, 21121).is_err());
    }

    #[test]
    fn the_natpmp_external_address_decodes() {
        let mut r = [0u8; 12];
        r[1] = 128;
        r[8..12].copy_from_slice(&[92, 222, 86, 135]);
        assert_eq!(
            natpmp_decode_address(&r),
            Ok(Ipv4Addr::new(92, 222, 86, 135))
        );
    }

    #[test]
    fn the_ssdp_location_is_read_regardless_of_case() {
        let rep = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n\
                   Location: http://192.168.1.1:5000/desc.xml\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(
            ssdp_extract_location(rep).as_deref(),
            Some("http://192.168.1.1:5000/desc.xml")
        );
    }

    #[test]
    fn a_url_splits() {
        assert_eq!(
            split_url("http://192.168.1.1:5000/ctl/IPConn"),
            Some(("192.168.1.1".into(), 5000, "/ctl/IPConn".into()))
        );
        assert_eq!(
            split_url("http://10.0.0.1/desc"),
            Some(("10.0.0.1".into(), 80, "/desc".into()))
        );
        assert_eq!(split_url("ftp://x/y"), None);
    }

    #[test]
    fn the_control_service_is_found_in_the_description() {
        let xml = "<root><URLBase>http://192.168.1.1:5000/</URLBase><device><serviceList>\
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
            <controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>";
        let (url, service) = upnp_extract_control(xml, "http://192.168.1.1:5000/desc.xml").unwrap();
        assert_eq!(url, "http://192.168.1.1:5000/ctl/IPConn");
        assert_eq!(service, "urn:schemas-upnp-org:service:WANIPConnection:1");
    }

    #[test]
    fn the_http_status_and_body_separate() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/xml\r\n\r\n<e>725</e>";
        let (status, body) = split_http_response(raw).unwrap();
        assert_eq!(status, 500);
        assert_eq!(body, "<e>725</e>");
    }
}
