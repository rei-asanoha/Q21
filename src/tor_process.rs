//! A Tor shipped with the program, started and stopped by the node.
//!
//! # Why
//!
//! Asking people to install Tor Browser, open it, and keep it open for as long
//! as the wallet runs is a step most of them will not take: the switch in the
//! Network tab then does nothing they can see, and they conclude it is broken.
//! The release archives for Windows, macOS and Linux (x86_64) therefore carry
//! the Tor Expert Bundle, in a `tor/` folder next to the program, and the node
//! runs it itself when Tor is turned on.
//!
//! # What this module does
//!
//! - finds that `tor` (or one on the `PATH`);
//! - starts it with a configuration of its own, written on the command line:
//!   a SOCKS port on the loopback chosen free, a data directory inside the
//!   node's, no system `torrc`, and `__OwningControllerProcess` so that Tor
//!   exits by itself if the node dies without stopping it;
//! - optionally asks it for an onion service that forwards to the port the
//!   node listens on, and reads the name Tor creates: a reachable node behind
//!   Tor gets its `.onion` address without anyone editing a file;
//! - reports the bootstrap progress Tor prints (`Bootstrapped 45% …`).
//!
//! It never falls back to a direct connection: if Tor cannot start, the node
//! says so and waits, exactly as when no Tor is found at all.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

/// The folder, next to the program, that holds the bundled Tor.
pub const BUNDLE_DIR: &str = "tor";

/// Name of the Tor executable on this system.
pub fn executable_name() -> &'static str {
    if cfg!(windows) {
        "tor.exe"
    } else {
        "tor"
    }
}

/// The bundled Tor of a program folder: `<folder>/tor/tor` (`tor.exe` on
/// Windows), if it is there.
pub fn find_bundled(program_dir: &Path) -> Option<PathBuf> {
    let p = program_dir.join(BUNDLE_DIR).join(executable_name());
    p.is_file().then_some(p)
}

/// The bundled Tor next to the running program.
pub fn find_bundled_next_to_program() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    find_bundled(exe.parent()?)
}

/// A `tor` on the `PATH` (installed with `apt`, Homebrew…).
pub fn find_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(executable_name()))
        .find(|p| p.is_file())
}

/// Reads the bootstrap percentage from one line of Tor's log, if it carries
/// one: `… [notice] Bootstrapped 45% (loading_descriptors): …`.
pub fn bootstrap_percent(line: &str) -> Option<u8> {
    let rest = &line[line.find("Bootstrapped ")? + "Bootstrapped ".len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if !rest[digits.len()..].starts_with('%') {
        return None;
    }
    digits.parse::<u8>().ok().filter(|p| *p <= 100)
}

/// What the node asks of its Tor.
#[derive(Clone, Debug)]
pub struct Options {
    pub executable: PathBuf,
    /// Tor's own directory, inside the node's data directory. It keeps the
    /// guard relays and, above all, the onion service key: as long as it is
    /// kept, the `.onion` address stays the same.
    pub data_dir: PathBuf,
    /// An onion service forwarding `(virtual port, local address)`: the
    /// port the network expects, and where this node listens.
    pub hidden_service: Option<(u16, SocketAddr)>,
}

/// A Tor started by this node. Stopped when dropped.
pub struct ManagedTor {
    child: Mutex<Option<Child>>,
    socks: Mutex<SocketAddr>,
    progress: Arc<AtomicU8>,
    last_problem: Arc<Mutex<String>>,
    onion_dir: Option<PathBuf>,
    options: Options,
}

impl ManagedTor {
    /// Starts Tor and returns at once: the SOCKS port is known before Tor has
    /// finished building its circuits, and the node's connections simply fail
    /// until it has (see [`ManagedTor::progress`]).
    pub fn start(options: &Options) -> std::io::Result<ManagedTor> {
        let progress = Arc::new(AtomicU8::new(0));
        let last_problem = Arc::new(Mutex::new(String::new()));
        let (child, socks, onion_dir) = spawn(options, &progress, &last_problem)?;
        Ok(ManagedTor {
            child: Mutex::new(Some(child)),
            socks: Mutex::new(socks),
            progress,
            last_problem,
            onion_dir,
            options: options.clone(),
        })
    }

    /// Starts Tor again, with the same options, after it stopped (killed by
    /// the system, a crash, an antivirus). Returns the new SOCKS port; the
    /// onion service keeps its address, its key being in the data directory.
    pub fn restart(&self) -> std::io::Result<SocketAddr> {
        self.stop();
        self.progress.store(0, Ordering::SeqCst);
        let (child, socks, _) = spawn(&self.options, &self.progress, &self.last_problem)?;
        if let Ok(mut g) = self.child.lock() {
            *g = Some(child);
        }
        if let Ok(mut g) = self.socks.lock() {
            *g = socks;
        }
        Ok(socks)
    }

    /// The SOCKS port to send the node's connections to.
    pub fn socks(&self) -> SocketAddr {
        self.socks
            .lock()
            .map(|g| *g)
            .unwrap_or_else(|e| *e.into_inner())
    }

    /// Bootstrap progress, 0 to 100.
    pub fn progress(&self) -> u8 {
        self.progress.load(Ordering::SeqCst)
    }

    /// Shared handle on the progress, for the RPC.
    pub fn progress_handle(&self) -> Arc<AtomicU8> {
        self.progress.clone()
    }

    /// Tor's last warning or error, if any.
    pub fn last_problem(&self) -> String {
        self.last_problem
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// True while the Tor process is still running.
    pub fn is_running(&self) -> bool {
        match self.child.lock() {
            Ok(mut g) => match g.as_mut() {
                Some(c) => matches!(c.try_wait(), Ok(None)),
                None => false,
            },
            Err(_) => false,
        }
    }

    /// True if this Tor was asked for an onion service.
    pub fn serves_onion(&self) -> bool {
        self.onion_dir.is_some()
    }

    /// The onion address Tor created for this node, once it has written it.
    pub fn onion_name(&self) -> Option<String> {
        let raw = std::fs::read_to_string(self.onion_dir.as_ref()?.join("hostname")).ok()?;
        let name = raw.trim().to_string();
        crate::wire::OnionAddr::parse(&name, 1).map(|_| name)
    }

    /// Stops Tor. Called on drop as well.
    pub fn stop(&self) {
        if let Ok(mut g) = self.child.lock() {
            if let Some(mut c) = g.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

impl Drop for ManagedTor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Starts the Tor process and the thread that reads its log.
fn spawn(
    options: &Options,
    progress: &Arc<AtomicU8>,
    last_problem: &Arc<Mutex<String>>,
) -> std::io::Result<(Child, SocketAddr, Option<PathBuf>)> {
    create_private_dir(&options.data_dir)?;
    // An empty configuration file of our own: without `-f`, Tor reads the
    // system one (`/etc/tor/torrc`), which may open ports or services
    // nobody asked this node for.
    let torrc = options.data_dir.join("torrc");
    if !torrc.exists() {
        std::fs::write(
            &torrc,
            "# Written by q21: the configuration is on the command line.\n",
        )?;
    }
    let socks = SocketAddr::from(([127, 0, 0, 1], free_port()?));

    let mut cmd = Command::new(&options.executable);
    cmd.arg("-f")
        .arg(&torrc)
        .arg("--defaults-torrc")
        .arg(&torrc)
        .arg("--SocksPort")
        .arg(socks.to_string())
        .arg("--DataDirectory")
        .arg(&options.data_dir)
        .arg("--ClientOnly")
        .arg("1")
        .arg("--__OwningControllerProcess")
        .arg(std::process::id().to_string())
        .arg("--Log")
        .arg("notice stdout");
    // The bundle carries its GeoIP files in `tor/data/`: without them Tor
    // works, but logs a warning at every start.
    if let Some(dir) = options.executable.parent() {
        let geoip = dir.join("data").join("geoip");
        let geoip6 = dir.join("data").join("geoip6");
        if geoip.is_file() && geoip6.is_file() {
            cmd.arg("--GeoIPFile")
                .arg(geoip)
                .arg("--GeoIPv6File")
                .arg(geoip6);
        }
        // The Linux bundle ships its libraries next to `tor`.
        if cfg!(target_os = "linux") {
            let mut paths = vec![dir.to_path_buf()];
            if let Some(old) = std::env::var_os("LD_LIBRARY_PATH") {
                paths.extend(std::env::split_paths(&old));
            }
            if let Ok(joined) = std::env::join_paths(paths) {
                cmd.env("LD_LIBRARY_PATH", joined);
            }
        }
    }
    let onion_dir = options.hidden_service.map(|(virt, local)| {
        let d = options.data_dir.join("onion");
        cmd.arg("--HiddenServiceDir")
            .arg(&d)
            .arg("--HiddenServicePort")
            .arg(format!("{virt} {local}"));
        d
    });
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        // No console window popping up next to the wallet.
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn()?;
    if let Some(out) = child.stdout.take() {
        let p = progress.clone();
        let problem = last_problem.clone();
        std::thread::Builder::new()
            .name("tor-log".to_string())
            .spawn(move || {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    if let Some(n) = bootstrap_percent(&line) {
                        p.store(n, Ordering::SeqCst);
                    }
                    if line.contains("[warn]") || line.contains("[err]") {
                        if let Ok(mut g) = problem.lock() {
                            *g = line.chars().take(300).collect();
                        }
                    }
                }
            })?;
    }
    Ok((child, socks, onion_dir))
}

/// A free TCP port on the loopback. Another program could take it between
/// this call and Tor's start; Tor then fails to start and says so, and the
/// node waits instead of connecting in the clear.
fn free_port() -> std::io::Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Tor refuses a data directory that other accounts can read.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bootstrap_progress_is_read_from_tor_lines() {
        let l = "Oct 18 10:00:01.000 [notice] Bootstrapped 45% (loading_descriptors): Loading relay descriptors";
        assert_eq!(bootstrap_percent(l), Some(45));
        assert_eq!(
            bootstrap_percent("[notice] Bootstrapped 100% (done): Done"),
            Some(100)
        );
        assert_eq!(bootstrap_percent("[notice] Opening Socks listener"), None);
        assert_eq!(bootstrap_percent("Bootstrapped 450% (x)"), None);
        assert_eq!(bootstrap_percent("Bootstrapped soon"), None);
    }

    #[test]
    fn the_bundled_tor_is_found_next_to_the_program_only() {
        let d = std::env::temp_dir().join(format!("q21-torbundle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(BUNDLE_DIR)).unwrap();
        assert_eq!(find_bundled(&d), None, "an empty folder is no Tor");
        std::fs::write(d.join(BUNDLE_DIR).join(executable_name()), b"").unwrap();
        assert_eq!(
            find_bundled(&d),
            Some(d.join(BUNDLE_DIR).join(executable_name()))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A stand-in for Tor, written as a shell script: it prints the lines the
    /// real one prints and writes an onion name where it was asked to.
    #[cfg(unix)]
    #[test]
    fn a_managed_tor_reports_progress_and_its_onion_name() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("q21-managedtor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let fake = d.join("tor");
        let name = format!("{}d.onion", "q".repeat(55));
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\n\
                 while [ $# -gt 0 ]; do\n\
                 if [ \"$1\" = --HiddenServiceDir ]; then mkdir -p \"$2\"; echo {name} > \"$2/hostname\"; fi\n\
                 shift\n\
                 done\n\
                 echo '[notice] Bootstrapped 10% (conn): Connecting'\n\
                 echo '[notice] Bootstrapped 100% (done): Done'\n\
                 sleep 30\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let t = ManagedTor::start(&Options {
            executable: fake,
            data_dir: d.join("data"),
            hidden_service: Some((21121, SocketAddr::from(([127, 0, 0, 1], 21999)))),
        })
        .expect("start");
        assert!(t.socks().ip().is_loopback());
        let mut waited = 0;
        while (t.progress() < 100 || t.onion_name().is_none()) && waited < 100 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            waited += 1;
        }
        assert_eq!(t.progress(), 100);
        assert_eq!(t.onion_name().as_deref(), Some(name.as_str()));
        assert!(t.is_running());
        let mode = std::fs::metadata(d.join("data"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "Tor's directory stays private");
        t.stop();
        assert!(!t.is_running());
        // Stopped behind the node's back: started again, same onion name.
        let before = t.socks();
        t.restart().expect("restart");
        assert!(t.is_running());
        let _ = before;
        assert_eq!(t.onion_name().as_deref(), Some(name.as_str()));
        t.stop();
        let _ = std::fs::remove_dir_all(&d);
    }
}
