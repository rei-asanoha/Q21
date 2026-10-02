//! Bootstrap: how a node gets into a network.
//!
//! # The problem
//!
//! A newborn node knows nobody. It has the genesis — it is deterministic, the
//! node computed it itself — but no address to knock on.
//!
//! This module gathers the three ways to get one, and the little code they
//! need: the default port of each network, the list built into the binary, the
//! operator's file, and name resolution.
//!
//! # What bootstrap does not decide
//!
//! It decides **who you talk to first**, not what you believe. A peer, whoever
//! it is, can only make you accept valid blocks that extend your own genesis
//! and carry the proof of work. It can hide things from you; it cannot make
//! things up.
//!
//! The defense against being isolated — the eclipse — is not trust in the
//! bootstrap: it is the address book, its buckets per /16 network group and its
//! salt unique to each node. See `net::addr`.

use crate::address::Network;
use std::path::Path;

/// Name of the bootstrap list, in the data directory and next to the program.
///
/// It had another name up to 0.3.x; [`crate::legacy::migrate_data_dir`]
/// renames an existing one.
pub const FILE_NAME: &str = "bootstrap.txt";

/// Default P2P port of each network.
///
/// A fixed port per network avoids having to write it in every set of
/// instructions, and makes a bootstrap address copyable as is. The three are
/// distinct: mistakenly pointing a testnet node at the mainnet port must fail
/// with "connection refused", not with a handshake that goes ahead and gets
/// banned.
pub fn default_port(n: Network) -> u16 {
    match n {
        Network::Mainnet => 21021,
        Network::Testnet => 21121,
        Network::Regtest => 21221,
    }
}

/// Bootstrap nodes built into the binary, per network.
///
/// # Why names and not addresses
///
/// An IP address changes: the server is replaced, the hosting provider
/// reassigns, the ISP renumbers. A distributed binary does not update itself
/// for all that, and a network whose entry points are dead is a network nobody
/// can join anymore.
///
/// A name can be repointed in a minute, without redistributing anything.
///
/// # What power this does not give
///
/// Whoever holds these names decides **who you talk to first**, not what you
/// believe. A peer, whoever it is, can only make you accept valid blocks that
/// extend the genesis you wrote yourself, and that carry the proof of work. It
/// can hide things from you; it cannot make things up.
///
/// The defense against being isolated — the eclipse — is not trust in the
/// bootstrap, it is the address book: see `net::addr`, its buckets per /16
/// group and its salt unique to each node.
///
/// # State of the lists
///
/// - **All lists are empty**, and that is a choice, not an oversight.
///
///   A name written here is compiled into every distributed binary: it becomes
///   the entry point every newcomer queries, hence a permanent dependency on
///   whoever holds that name. A protocol meant to outlive its author must not
///   be born with its author's address carved into it.
///
///   The entry point is therefore supplied at run time: `bootstrap.txt` in the
///   data directory, or `--bootstrap <host>`. The setup guides give the name of
///   the network to join, and it can be changed without recompiling or
///   redistributing anything.
///
///   The day the project owns a name that belongs to it alone — to the project,
///   not to a person —, this is where it gets written, after being checked
///   (resolution and handshake from an outside machine).
/// - **Regtest**: empty by nature — a regtest network is local, it has nobody
///   to join.
///
/// A single entry point is a single point of failure: if it goes down, nobody
/// can *get in* anymore (those already in the network carry on, the address
/// book is enough for them). A second one, at another hosting provider, is the
/// first thing to add here.
pub fn builtin_bootstrap(n: Network) -> &'static [&'static str] {
    match n {
        Network::Mainnet => &[],
        Network::Testnet => &[],
        Network::Regtest => &[],
    }
}

/// Bootstrap addresses read from the data directory, one per line.
///
/// This is what makes it possible to open a network without recompiling
/// anything: the operator drops in `bootstrap.txt`, and anyone adds what they
/// want to it. Empty lines and lines starting with `#` are ignored.
pub fn bootstrap_from_datadir(datadir: &Path) -> Vec<String> {
    read_bootstrap_file(&datadir.join(FILE_NAME))
}

/// Reads a bootstrap file, if it exists. Missing or unreadable: empty list.
///
/// The parsing itself is left to [`read_bootstrap`], which is tested on its
/// own: a format the operator types by hand deserves to be checked without
/// going through a file.
fn read_bootstrap_file(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => read_bootstrap(&contents),
        Err(_) => Vec::new(),
    }
}

/// Bootstrap addresses read **next to the program**, not from the data
/// directory.
///
/// # What this fixes
///
/// The shipped file used to live in `q21-data/`, a subfolder. Assembling an
/// archive and packing it are two steps: `tar` descended into that subfolder,
/// `7z` did not. The Mac and Linux archives therefore carried the file, the
/// Windows archive shipped blind, and nothing flagged it — the defect was only
/// noticed at a user's, several versions later.
///
/// A **flat file, next to the binary** goes through every archiving tool
/// unconditionally. It is the same idea as before — the address sits next to
/// the program, never inside it, and it stays readable and editable by whoever
/// receives it — but it no longer depends on a folder structure that can get
/// lost along the way.
///
/// The data directory keeps priority: what users write in their own directory
/// wins over what the release dropped in.
pub fn bootstrap_next_to_program() -> Vec<String> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    read_bootstrap_file(&dir.join(FILE_NAME))
}

/// Resolves `host:port`, or `host` alone with the network's default port.
///
/// # The defect this fixes
///
/// The node used `"1.2.3.4:5678".parse::<SocketAddr>()`, which only accepts a
/// literal address. A name — the only durable entry point of a public network
/// — gave "unreadable address" with no further explanation.
///
/// A name can return several addresses; we take them all. This is what lets a
/// bootstrap point be made redundant behind a single name.
pub fn resolve(target: &str, network: Network) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    // A literal IPv6 address carries its brackets: `[::1]:21121`. Without them,
    // the colons of the address get mixed up with the one of the port.
    let with_port = if target.contains(':') && !target.ends_with(']') {
        target.to_string()
    } else {
        format!("{target}:{}", default_port(network))
    };
    let addrs: Vec<_> = with_port
        .to_socket_addrs()
        .map_err(|e| format!("{target}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{target}: no address"));
    }
    Ok(addrs)
}

/// Interprets `--listen`: a port number alone, or a full address.
///
/// `--listen 21121` listens on every interface, which a public node wants;
/// `--listen 127.0.0.1:21121` stays local. Writing the former is much shorter
/// than `0.0.0.0:21121`, and it is what one types most often on a server.
pub fn listen_address(raw: &str, network: Network) -> String {
    // The empty case is handled first. `"".chars().all(...)` returns **true** —
    // an empty set satisfies everything — so the reverse order produced
    // `0.0.0.0:`, an address without a port that the system refuses. It was
    // this module's test that found it, not the review.
    if raw.is_empty() {
        format!("0.0.0.0:{}", default_port(network))
    } else if raw.chars().all(|c| c.is_ascii_digit()) {
        format!("0.0.0.0:{raw}")
    } else {
        raw.to_string()
    }
}

/// Reads a bootstrap list. Empty lines and comments are ignored.
///
/// Kept apart from reading the file so that it can be tested: the format is
/// what the operator types by hand, hence the place where a misplaced
/// tolerance comes at a price.
pub fn read_bootstrap(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three networks, three ports. Mixing them up must fail with "connection
    /// refused", not with a handshake that goes ahead and gets banned.
    #[test]
    fn the_three_networks_have_distinct_ports() {
        let p = [
            default_port(Network::Mainnet),
            default_port(Network::Testnet),
            default_port(Network::Regtest),
        ];
        assert_eq!(p.len(), 3);
        assert_ne!(p[0], p[1]);
        assert_ne!(p[1], p[2]);
        assert_ne!(p[0], p[2]);
        // Outside the reserved ranges and the privileged ports.
        for x in p {
            assert!(x > 1024, "privileged port: {x}");
        }
    }

    /// `--listen 21121` listens everywhere; a full address is respected.
    ///
    /// This is what one types on a server, and the short form must do what is
    /// expected of it — otherwise one writes `0.0.0.0:` by hand, and one day
    /// forgets it.
    #[test]
    fn a_port_number_alone_listens_everywhere() {
        assert_eq!(listen_address("21121", Network::Testnet), "0.0.0.0:21121");
        assert_eq!(
            listen_address("127.0.0.1:9", Network::Testnet),
            "127.0.0.1:9"
        );
        assert_eq!(
            listen_address("", Network::Testnet),
            format!("0.0.0.0:{}", default_port(Network::Testnet))
        );
    }

    /// A name without a port takes the network's.
    #[test]
    fn a_name_without_port_takes_the_network_port() {
        let a = resolve("localhost", Network::Testnet).expect("localhost must resolve");
        assert!(!a.is_empty());
        assert!(a.iter().all(|s| s.port() == default_port(Network::Testnet)));
    }

    /// An explicit port wins.
    #[test]
    fn an_explicit_port_wins() {
        let a = resolve("127.0.0.1:12345", Network::Testnet).expect("literal address");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].port(), 12345);
    }

    /// A literal IPv6 address keeps its brackets, and its port.
    ///
    /// Without special handling, the colons of the address get mixed up with
    /// the one of the port: `::1` would become a host name followed by port `1`.
    #[test]
    fn an_ipv6_address_is_not_mistaken_for_a_port() {
        let a = resolve("[::1]:12345", Network::Testnet).expect("literal IPv6");
        assert_eq!(a[0].port(), 12345);
        assert!(a[0].is_ipv6());
    }

    /// A name that does not exist returns a readable error, not a panic.
    #[test]
    fn an_unknown_name_returns_an_error() {
        let r = resolve("q21-this-name-does-not-exist.invalid", Network::Testnet);
        assert!(r.is_err());
        let m = r.unwrap_err();
        assert!(
            m.contains("q21-this-name-does-not-exist.invalid"),
            "the error must name what failed: {m}"
        );
    }

    /// The format of the bootstrap file.
    #[test]
    fn comments_and_empty_lines_are_ignored() {
        let v = read_bootstrap(
            "# the testnet bootstrap addresses\n\
             \n   \n\
             seed1.example.org\n\
             \t seed2.example.org:21121 \n\
             # a line set aside\n",
        );
        assert_eq!(v, vec!["seed1.example.org", "seed2.example.org:21121"]);
    }

    /// The testnet is open; the mainnet is not.
    ///
    /// The old version of this test required **all** lists to be empty, and it
    /// failed on the day of the opening — that was intended: it was a reminder
    /// that one then had to check that the name really answers. It was checked
    /// (handshake and `peers 1` from an outside machine) before being written
    /// in.
    ///
    /// It now guards the invariant that matters: **no domain name is compiled
    /// into the binary**.
    ///
    /// An entry point carved into the code is a permanent dependency on whoever
    /// holds that name, and it exposes its owner to every user who resolves it.
    /// The entry point is supplied at run time (`bootstrap.txt`,
    /// `--bootstrap`). This test will fail the day the project writes in a name
    /// that belongs to it alone: it will then be a deliberate choice, made with
    /// full knowledge, not a leftover.
    #[test]
    fn no_domain_is_compiled_into_the_binary() {
        for r in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert!(
                builtin_bootstrap(r).is_empty(),
                "an entry point is carved into the binary for {r:?}: {:?}",
                builtin_bootstrap(r)
            );
        }
    }

    /// Every built-in bootstrap address must be a target that `resolve` can
    /// read.
    ///
    /// We do not resolve here — a test must not depend on the network or on
    /// DNS — but a typo in a hard-coded name would only show up at a user's
    /// first startup, which is too late.
    #[test]
    fn builtin_bootstrap_addresses_are_well_formed() {
        for r in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            for a in builtin_bootstrap(r) {
                assert!(!a.is_empty(), "empty bootstrap address for {r:?}");
                assert!(!a.contains(' '), "space in a bootstrap address: {a:?}");
                assert!(
                    !a.starts_with('.') && !a.ends_with('.'),
                    "malformed name: {a:?}"
                );
                assert!(
                    a.contains('.'),
                    "a public entry point is designated by a name, not by {a:?}"
                );
            }
        }
    }
}
