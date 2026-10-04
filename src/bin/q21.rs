//! `q21` — command-line node and wallet.
//!
//! Single-machine local node: no peer-to-peer network yet, that will be
//! phase 4. You can already initialize a chain, mine, check a balance,
//! send funds and inspect blocks.

use q21_core::addr::AddrStore;
use q21_core::address::{Address, Network};
use q21_core::amount::Amount;
use q21_core::chain::{genesis_block, Chain};
use q21_core::consensus::*;
use q21_core::emission;
use q21_core::hash::Hash256;
use q21_core::pow;
use q21_core::sig::SchemeId;
use q21_core::state::{AddressCache, StateStore};
use q21_core::store::BlockArchive;
use q21_core::tx::Transaction;
use q21_core::wallet::Wallet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HELP: &str = "\
q21 — node and wallet for the Q21 protocol (phase 2)

USAGE
    q21 [--datadir <path>] [--passphrase-file <path>] [--backup-code-file <path>]
        [--accept-other-seed] <command> [arguments]

    --passphrase-file <f>   passphrase read from f (a file only you can read)
    --backup-code-file <f>  backup code read from f, for `restore`
    --accept-other-seed     opens a wallet.dat from a seed other than the one
                            this folder has known (see WALLET.md)

COMMANDS
    init [regtest|testnet] [lamport|mldsa65|mldsa87]
                            Creates a chain and a wallet
                            (default scheme: mldsa87 if compiled in, else lamport)
    restore [network] [scheme]
                            Restores a wallet from its Bech32m backup
                            code. The code is asked for at the terminal,
                            without echo, or read with --backup-code-file:
                            it is NEVER passed as an argument
    info                     Chain status
    address                  Produces a new receiving address
    balance                  Spendable balance of the wallet
    mine [n]                 Mines n blocks (default: 1)
    send <address> <amount>  Sends funds (the amount is in Q21)
    block <height>           Shows the details of a block
    utxo                     Summary of the unspent output set
    emission [year]          Theoretical emission curve
    revalidate [--blocks <f>] [--network <n>]
                             Replays the whole history from genesis and checks
                             that it reproduces the adopted state. Makes a node
                             that started from a snapshot fully self-reliant.

    snapshot <action>        Portable snapshot of the state of the currency
                             export <file> [--network <name>]
                                                  writes a portable snapshot
                                                  (the node must be stopped;
                                                  --network for a wallet-less
                                                  node)
                             verify <file> [--commitment <hex>]
                                                  checks a snapshot, and compares
                                                  it to a trusted commitment
                                                  if one is given
                             export-sync <folder> [--network <name>]
                                                  writes a fast-sync snapshot
                                                  (snapshot + headers + window
                                                  of block bodies)
                             adopt <folder> --tip <hex> --commitment <hex>
                                                  starts an empty folder from
                                                  a fast-sync snapshot, after
                                                  anchoring tip and commitment
                                                  to a trusted source: the node
                                                  resumes at the snapshot height
    wallet [options]         Opens the wallet in the browser
                             --port <n>           listening port (default: free)
                             --no-browser         does not open the browser,
                                                  prints the address
    node [options]           Starts a network node
                             --network <name>     testnet or regtest. Allows
                                                  starting WITHOUT a wallet:
                                                  only the genesis is written
                                                  and no key is kept
                             --listen <port>      accepts connections. A bare
                                                  number listens everywhere;
                                                  a full address targets one
                                                  interface
                             --bootstrap <host>   entry point. A name is enough,
                                                  the network port is used by
                                                  default. Repeatable
                             --no-bootstrap       use only what the command
                                                  line gives
                             --connect <ip:port>  synonym for --bootstrap
                             --assume-commitment <hex>
                                                  fast sync: in an empty
                                                  folder, downloads a peer's
                                                  snapshot and adopts it if
                                                  its commitment matches
                                                  (requires --network and
                                                  --assume-tip)
                             --assume-tip <hex>   the trusted tip that goes
                                                  with the commitment
                             --address-index      search index (see
                                                  EXPLORER.md)
                             --prune              keeps only recent block bodies
                                                  on disk (~8 days); the rest
                                                  is summarized in the
                                                  snapshot. Incompatible
                                                  with an explorer
                             --mine               mines continuously
                             --rpc <ip:port>      JSON-RPC API + web explorer
                             --rpc-token <token>  requires a token (mandatory
                                                  off the loopback, and with
                                                  --rpc-wallet)
                             --rpc-token-file <path>
                                                  the token, read from a file
                                                  rather than the command line
                             --rpc-wallet         enables the wallet methods
                                                  (they can move funds)
                             --rpc-public <name>  publishes the explorer under
                                                  this domain name, behind a
                                                  reverse proxy. Refused if a
                                                  wallet is served
                             --seconds <n>        stops after n seconds
                             --threads <n>        mining threads (default: all
                                                  cores)
                             --peers <n>          target outbound connections
                                                  (default: 8, all from distinct
                                                  network groups)
    pow [regtest|testnet|mainnet]
                            Proof-of-work benchmark.
                            `mainnet` builds the real 2 GiB table and
                            plots the time-memory tradeoff curve.
    explorer                 Chain explorer in the browser.
                            Search by height, block, transaction or address.
                            The address index is enabled: address search
                            is then complete, and unbounded.
                            --no-index           do without it
                            --port <n>           force the port
                            --no-browser         open nothing
    genesis [network]        Identifier of the genesis block, and the network port.
                            Check it before joining: two nodes that do not have
                            the same genesis are not on the same chain.
    security                 What is protected, and what is not
    version                  Version of this program. Also --version and -V
    diagnostic [--network n] Why this node does not connect: bootstrap, name,
                            port, handshake. Run it while the wallet
                            is running
    help                     This help

EXAMPLE
    q21 init regtest
    q21 mine 205

    # join a testnet, without a wallet
    q21 genesis testnet
    q21 --datadir n node --network testnet --bootstrap seed.example.org

    # two nodes that sync with each other, in two terminals
    q21 --datadir a node --listen 127.0.0.1:21021 --mine
    q21 --datadir b node --connect 127.0.0.1:21021

    # local explorer, in a browser: http://127.0.0.1:21080
    q21 --datadir a node --rpc 127.0.0.1:21080 --mine
    q21 balance
    q21 address
    q21 send rq21... 1.5

WARNING
    Research code, not audited. The proof of work is memory-hard but
    has received no external cryptanalysis. ML-DSA signatures rely on the
    RustCrypto `ml-dsa` crate, itself not formally audited.
    Run `q21 security` for what is protected and what is not.
";

fn main() {
    // No core dumps: a process that holds a seed must not be able to write
    // it into a `core` file at the first crash.
    disable_core_dumps();
    // The environment variable is read once, then removed: it must neither
    // pass to child processes nor stay readable in `/proc/<pid>/environ` by
    // another account on the machine.
    let _ = passphrase_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut datadir = PathBuf::from("q21-data");
    let mut rest: Vec<String> = Vec::new();

    let mut passphrase_option: Option<String> = None;
    let mut code_option: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--datadir" && i + 1 < args.len() {
            datadir = PathBuf::from(&args[i + 1]);
            i += 2;
        } else if args[i] == "--passphrase-file" && i + 1 < args.len() {
            passphrase_option = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--backup-code-file" && i + 1 < args.len() {
            code_option = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--accept-other-seed" {
            ACCEPT_OTHER_SEED.store(true, std::sync::atomic::Ordering::Relaxed);
            i += 1;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }

    // A passphrase given by file or by environment variable applies to the
    // whole command.
    //
    // The variable used to be consulted too late: the terminal check added
    // to stop creating unprotected wallets ran before it, and then refused a
    // perfectly legitimate command — precisely the one used when there is no
    // terminal.
    match get_passphrase(passphrase_option.as_deref(), false) {
        Ok(Some(p)) => remember_passphrase(Some(p)),
        Ok(None) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }

    // --- The double-click that opened nothing.
    //
    // Started without arguments, this program printed its help and returned.
    // On Windows, a double-click then opens a window that closes within half
    // a second: nothing can be read, and the user concludes — rightly — that
    // the software does not work. It happened to the first person who tried
    // it, after following the procedure to the end.
    //
    // A program started from a terminal has received a command; a program
    // that was double-clicked has none. The distinction is therefore clear,
    // and the answer obvious: without arguments, it is the wallet you want.
    //
    // The fallback remains the help, but followed by a pause: a window that
    // closes before anyone could read it never taught anybody anything.
    // --- Only one q21 at a time on a data directory.
    //
    // Nothing prevented it, and the case is common: the wallet runs in its
    // window, and you start `q21 mine` in another one to confirm a
    // transaction. Two processes then write the same `wallet.dat`, the same
    // `blocks.dat` and the same `wallet.seq`. The wallet comes out of it with
    // an inconsistent serial number, and refuses to open at the next start,
    // announcing a restore from an old backup.
    //
    // Commands that do not touch the directory — the help, the emission
    // curve, the security note — do not lock it: refusing `q21 help` because
    // a wallet is running would be absurd.
    let first_command = rest.first().map(|s| s.as_str()).unwrap_or("help");
    let no_datadir = matches!(
        first_command,
        "emission"
            | "security"
            | "genesis"
            | "version"
            | "diagnostic"
            | "--version"
            | "-V"
            | "help"
            | "--help"
            | "-h"
    );
    let _lock = if no_datadir {
        None
    } else {
        match q21_core::lock::acquire(&datadir) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("error: {e}");
                if q21_core::prompt::is_interactive() {
                    println!();
                    println!("  Press Enter to close.");
                    let mut _l = String::new();
                    let _ = std::io::stdin().read_line(&mut _l);
                }
                std::process::exit(1);
            }
        }
    };

    // --- Upgrade of a 0.3.x data directory: legacy file names, settings keys
    // and values become English. Runs under the lock, before anything else
    // reads the directory. `diagnostic` takes no lock (it runs next to a
    // live wallet): it upgrades only a directory nobody else holds.
    let _diagnostic_lock = if first_command == "diagnostic" {
        q21_core::lock::acquire(&datadir).ok()
    } else {
        None
    };
    if _lock.is_some() || _diagnostic_lock.is_some() {
        match q21_core::legacy::migrate_data_dir(&datadir) {
            Ok(done) => {
                for f in &done {
                    eprintln!("  data directory upgraded: {f}");
                }
            }
            // `diagnostic` must still run next to an older q21: it only
            // reports, and the directory was left untouched.
            Err(e) if _diagnostic_lock.is_some() => eprintln!("  warning: {e}"),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    drop(_diagnostic_lock);

    let no_argument = rest.is_empty();
    if no_argument {
        println!("Q21 — wallet");
        println!();
        println!("  Started without a command: opening the wallet.");
        println!("  For the list of commands: q21 help");
        println!();
        let r = cmd_wallet(&datadir, &[]);
        if let Err(e) = r {
            eprintln!("error: {e}");
            if q21_core::prompt::is_interactive() {
                println!();
                println!("  Press Enter to close.");
                let mut _l = String::new();
                let _ = std::io::stdin().read_line(&mut _l);
            }
            std::process::exit(1);
        }
        return;
    }

    let command = rest.first().map(|s| s.as_str()).unwrap_or("help");
    let r = match command {
        "init" => cmd_init(
            &datadir,
            rest.get(1).map(|s| s.as_str()),
            rest.get(2).map(|s| s.as_str()),
            passphrase_option.as_deref(),
        ),
        "restore" => cmd_restore(
            &datadir,
            &rest[1..],
            code_option.as_deref(),
            passphrase_option.as_deref(),
        ),
        "info" => cmd_info(&datadir),
        "address" => cmd_address(&datadir),
        "balance" => cmd_balance(&datadir),
        "mine" => cmd_mine(&datadir, rest.get(1).map(|s| s.as_str())),
        "send" => cmd_send(&datadir, rest.get(1), rest.get(2)),
        "block" => cmd_block(&datadir, rest.get(1).map(|s| s.as_str())),
        "utxo" => cmd_utxo(&datadir),
        "emission" => cmd_emission(rest.get(1).map(|s| s.as_str())),
        "snapshot" => cmd_snapshot(&datadir, &rest[1..]),
        "node" => cmd_node(&datadir, &rest[1..]),
        "wallet" => cmd_wallet(&datadir, &rest[1..]),
        "explorer" => cmd_explorer(&datadir, &rest[1..]),
        "pow" => cmd_pow(
            &datadir,
            rest.get(1).map(|s| s.as_str()),
            rest.iter().any(|a| a == "--no-table"),
        ),
        "genesis" => cmd_genesis(rest.get(1).map(|s| s.as_str())),
        "revalidate" => cmd_revalidate(&datadir, &rest[1..]),
        "security" => cmd_security(),
        "diagnostic" => cmd_diagnostic(&datadir, &rest[1..]),
        "version" | "--version" | "-V" => {
            println!("q21 {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown command: {other}\n\n{HELP}")),
    };

    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// State on disk
// ---------------------------------------------------------------------------

struct DiskState {
    chain: Chain,
    wallet: Wallet,
    /// This node runs without a wallet file.
    ///
    /// The in-memory wallet is then only a shell: it is never written, none
    /// of its addresses is handed out, and the methods that move funds are not
    /// served. This is what a bootstrap node must be — a server that restarts
    /// on its own after an outage cannot wait for a human to type a
    /// passphrase, and has no reason to keep keys.
    wallet_less: bool,
    /// The block file **and** the index of their positions. Both together,
    /// never one without the other: a block written but not indexed is a
    /// block this node will no longer be able to serve to its peers.
    archive: std::sync::Arc<BlockArchive>,
    datadir: PathBuf,
}

fn wallet_path(d: &Path) -> PathBuf {
    d.join("wallet.dat")
}
fn blocks_path(d: &Path) -> PathBuf {
    d.join("blocks.dat")
}

/// The passphrase given by `Q21_PASSPHRASE`, read only once at startup
/// then removed from the process environment.
fn passphrase_from_env() -> Option<String> {
    static ENV: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    ENV.get_or_init(|| {
        let p = std::env::var("Q21_PASSPHRASE")
            .ok()
            .filter(|p| !p.is_empty());
        // Safe: called at the very start of `main`, before any thread.
        unsafe { std::env::remove_var("Q21_PASSPHRASE") };
        p
    })
    .clone()
}

/// Forbids core dump files for this process.
///
/// On Unix, the `RLIMIT_CORE` limit is set to zero. A crash then writes
/// nothing to disk: no seed, no passphrase, no derived key. On Windows, there
/// is no simple equivalent; the protection remains the encryption of the
/// wallet file and the wiping of buffers.
fn disable_core_dumps() {
    #[cfg(unix)]
    {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // Safe: `rlimit` is a plain C structure, passed by reference, and
        // `setrlimit` does not keep the pointer.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &zero);
        }
    }
}

/// The wallet passphrase, as the user provided it.
///
/// Three sources, in this order: the explicit option, a file, the
/// environment variable. Interactive input comes only as a last resort, and
/// only if a terminal is available.
fn get_passphrase(from_file: Option<&str>, interactive: bool) -> Result<Option<String>, String> {
    if let Some(path) = from_file {
        let p = read_secret_from_file(path, "passphrase")?;
        return Ok(Some(p));
    }
    if let Some(p) = passphrase_from_env() {
        return Ok(Some(p));
    }
    if !interactive {
        return Ok(None);
    }
    let (p, masked) =
        q21_core::prompt::read_passphrase("Wallet passphrase: ").map_err(|e| e.to_string())?;
    if !masked {
        eprintln!("  warning: terminal echo could not be turned off.");
    }
    Ok(if p.is_empty() { None } else { Some(p) })
}

/// Reads a secret — passphrase or backup code — from a file.
///
/// A file readable by other accounts is as good as a displayed secret: we say
/// so, without refusing — refusing would block a service that starts with
/// nobody around to fix it, and the file does not become any more secret
/// because we did not read it. Only the line ending is removed: a passphrase
/// is allowed to start or end with a space.
fn read_secret_from_file(path: &str, what: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(path) {
            if m.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "  warning: {path} is readable by other accounts on this \
                     machine (mode {:o}). Restrict it: chmod 600 {path}",
                    m.permissions().mode() & 0o777
                );
            }
        }
    }
    let mut raw =
        std::fs::read_to_string(path).map_err(|e| format!("{what} unreadable in {path}: {e}"))?;
    let p = raw.trim_end_matches(['\n', '\r']).to_string();
    // The raw read is wiped: only the trimmed copy survives, in a type that
    // is wiped in turn (`Secret`) by the caller.
    // Safe: only zeros are written, which are valid UTF-8.
    q21_core::kdf::wipe(unsafe { raw.as_bytes_mut() });
    if p.is_empty() {
        return Err(format!("the file {path} is empty"));
    }
    Ok(p)
}

/// Minimum length of a NON-EMPTY passphrase, at creation.
///
/// A passphrase of one to a few characters is sealed with all the strength of
/// Argon2id — and is still guessed from a short list, whatever the cost per
/// attempt. It therefore gives a false sense of security, worse than a
/// deliberate absence of passphrase. Empty remains an explicit choice (no
/// protection, loud warning); a *real* passphrase must reach this floor.
/// Red-team 8b.
const MIN_PASSPHRASE_LEN: usize = 8;

/// A `wallet.dat` from a seed other than the one the folder has known is
/// accepted: set by `--accept-other-seed`. See [`read_wallet`].
static ACCEPT_OTHER_SEED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Restricts the file to its owner.
///
/// Without this, `wallet.dat` was written with the default permissions —
/// often readable by everyone on a shared machine. Encrypting a file that
/// anyone can copy only protects against laziness.
/// The account name to pass to `icacls`, from the Windows environment
/// variables.
///
/// On a machine joined to a domain, the user name alone can designate two
/// different accounts; it is therefore qualified with the domain when that is
/// known. Without a user name, access cannot be granted to anyone — and it is
/// better to say so than to set a rule at random.
///
/// This function is not specific to Windows: it is string manipulation, and
/// it can therefore be tested everywhere, including where the rest does not
/// compile. It is compiled only where it is used — on Windows, and under test.
#[cfg(any(windows, test))]
fn windows_account_name(user: Option<&str>, domain: Option<&str>) -> Option<String> {
    let u = user?.trim();
    if u.is_empty() {
        return None;
    }
    match domain.map(str::trim) {
        Some(d) if !d.is_empty() => Some(format!("{d}\\{u}")),
        _ => Some(u.to_string()),
    }
}

/// Restricts access to a file to its owner alone. Returns `false` if the
/// restriction could not be set.
///
/// # The hole this function had
///
/// On Unix, it set mode `0600` — readable by the owner alone. On Windows, it
/// did **nothing at all**: the file inherited the permissions of its folder,
/// hence everything that folder lets through. Yet that is the system of most
/// users, and this file carries the seed: the one that rebuilds the entire
/// wallet, funds included. When the user has moreover declined a passphrase,
/// the seed is in it in plaintext.
///
/// Windows has no "mode 0600": permissions there are access control lists.
/// The equivalent takes two steps — **cut the inheritance** from the folder,
/// then grant access only to the **current account**. That is what `icacls`
/// does, present on every version of Windows since Vista.
///
/// # Why the result is returned rather than ignored
///
/// The restriction can legitimately fail: a wallet placed on a FAT32 USB
/// stick has no ACL at all. Silence would then be the worst choice — the user
/// would believe the file protected. The failure is therefore returned, so
/// that the caller can say so.
#[must_use]
fn restrict_access(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).is_ok()
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Without this flag, a black console window flashes at every save:
        // the wallet is started from a user interface, not from a terminal.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        // The account to grant access to.
        let Some(account) = windows_account_name(
            std::env::var("USERNAME").ok().as_deref(),
            std::env::var("USERDOMAIN").ok().as_deref(),
        ) else {
            return false;
        };

        std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{account}:F"))
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|s| s.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

/// Creates a temporary file **already** restricted to its owner.
///
/// # The defect this closes
///
/// The wallet's temporary file was created with the `umask` permissions —
/// 0644 with the usual 022 — filled, synced to disk, and only then switched to
/// 0600. Between creation and restriction, any account on the machine could
/// open it, and an open descriptor survives the `chmod`. The window included
/// the `fsync`, slow on an SD card, and opened at every write: every block
/// mined, every send, every address requested. Plaintext wallet: the seed;
/// sealed: enough to attack the passphrase offline.
///
/// On Unix, the mode is set by `O_CREAT` itself: the file never exists under
/// another one. `create_new` refuses a temporary file that would already be
/// there; a leftover from an interrupted write is removed first, never
/// reopened in place. On Windows, there is no mode at creation: the file is
/// created **empty**, restricted by `icacls`, and the first byte is written
/// only afterwards.
fn create_private_temp(tmp: &Path) -> Result<std::fs::File, String> {
    let _ = std::fs::remove_file(tmp);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        let f = std::fs::File::create(tmp).map_err(|e| e.to_string())?;
        if !restrict_access(tmp) {
            eprintln!(
                "warning: the access permissions of {} could not be restricted.",
                tmp.display()
            );
        }
        Ok(f)
    }
}

/// Creates the data directory, private from birth.
///
/// The directory was created with the default permissions — 0755 — and stayed
/// that way. A directory readable by others shows the names and sizes of
/// everything it contains, and it is the first link of all the windows this
/// file closes: a 0600 file in a 0700 directory is no longer within reach of
/// another account's `inotify`. The parent directories are created with the
/// ordinary permissions: they are not ours.
fn create_private_dir(d: &Path) -> Result<(), String> {
    if d.is_dir() {
        tighten_dir(d);
        return Ok(());
    }
    if let Some(parent) = d.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(d)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(d).map_err(|e| e.to_string())
    }
}

/// Tightens a data directory that is wider than 0700, and says so.
///
/// A directory created by an earlier version, or by a manual `mkdir`, is
/// brought back to its owner at the next start. A failure — a file system
/// without permissions, a FAT32 USB stick — is reported, never fatal:
/// refusing to open the wallet would not make the directory any more private.
/// On Windows, the permissions are those of the files, set one by one by
/// `icacls`.
fn tighten_dir(d: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(d) {
            if m.is_dir() && m.permissions().mode() & 0o077 != 0 {
                match std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)) {
                    Ok(()) => println!(
                        "  permissions of the directory {} restricted to its owner alone (0700)",
                        d.display()
                    ),
                    Err(e) => eprintln!(
                        "warning: the directory {} remains readable by other accounts \
                         (mode {:o}) and could not be restricted: {e}",
                        d.display(),
                        m.permissions().mode() & 0o777
                    ),
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = d;
}

/// The directory anchor: what it has known of its wallet.
///
/// # The defect this closes
///
/// The only link between a directory and *its* wallet was `wallet.seq`, an
/// integer. Nothing recorded that this directory was protected by a
/// passphrase, nor which seed it belonged to. A plaintext `wallet.dat`, from
/// another seed, carrying the current serial number, was read, believed, and
/// the process switched to "no passphrase" mode: mining and the displayed
/// balance became those of the foreign seed, the following writes were made
/// in plaintext, and nothing reported it. Anyone who writes into the
/// directory without running code under the account — a share, a restored
/// backup, a sync client — could divert an unattended miner.
///
/// The directory therefore records two facts, in `wallet.anchor`: "this
/// directory has seen a sealed wallet" — and that is never forgotten — and a
/// **public** fingerprint of the seed, `HMAC(seed, "Q21-DATADIR-v1")`, which
/// says nothing about the seed but is enough to recognize another one. A
/// non-sealed file in a directory that has seen a sealed one is refused;
/// another seed is refused unless `--accept-other-seed`. This is not a
/// defense against someone who can also erase the anchor: it is the same
/// limit, already accepted, as the anti-replay by serial number.
///
/// An older directory, without an anchor, acquires one at its first write.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
struct Anchor {
    /// This directory has already held a wallet sealed by a passphrase.
    sealed: bool,
    /// Public fingerprint of the seed this directory has known.
    seed: Option<[u8; 32]>,
}

fn anchor_path(d: &Path) -> PathBuf {
    d.join(q21_core::legacy::ANCHOR_FILE)
}

/// The public fingerprint of a seed, for the anchor.
fn dir_fingerprint(w: &Wallet) -> [u8; 32] {
    // Frozen label: the fingerprint it produces is stored in `wallet.anchor`.
    // Renaming it would make every existing directory refuse its own wallet.
    w.public_fingerprint(b"Q21-DATADIR-v1")
}

/// Is `known`, read from `wallet.anchor`, the fingerprint of this wallet?
///
/// An anchor written by 0.3.x holds the fingerprint under the legacy label:
/// it is accepted too, and the next wallet write records the new one. Both
/// are keyed by the seed, so accepting either opens nothing to someone who
/// does not hold it.
fn anchor_matches(known: &[u8; 32], w: &Wallet) -> bool {
    let current = dir_fingerprint(w);
    let legacy = w.public_fingerprint(q21_core::legacy::LEGACY_DATADIR_LABEL);
    q21_core::kdf::constant_time_eq(known, &current)
        | q21_core::kdf::constant_time_eq(known, &legacy)
}

fn read_anchor(d: &Path) -> Option<Anchor> {
    let text = std::fs::read_to_string(anchor_path(d)).ok()?;
    let mut a = Anchor::default();
    for line in text.lines() {
        match line.split_once('=') {
            Some(("sealed", v)) => a.sealed = v.trim() == "1",
            Some(("seed", v)) => {
                a.seed = hex_to_bytes(v.trim()).filter(|o| o.len() == 32).map(|o| {
                    let mut g = [0u8; 32];
                    g.copy_from_slice(&o);
                    g
                })
            }
            _ => {}
        }
    }
    Some(a)
}

fn write_anchor(d: &Path, a: &Anchor) {
    let path = anchor_path(d);
    let tmp = path.with_extension("anchor.tmp");
    let seed: String = a
        .seed
        .map(|g| g.iter().map(|o| format!("{o:02x}")).collect())
        .unwrap_or_default();
    let content = format!("sealed={}\nseed={seed}\n", u8::from(a.sealed));
    let written = create_private_temp(&tmp).and_then(|mut f| {
        use std::io::Write;
        f.write_all(content.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| e.to_string())
    });
    if written.is_ok() && std::fs::rename(&tmp, &path).is_ok() {
        let _ = restrict_access(&path);
    }
}

/// Serial number of the wallet file, kept separately.
///
/// # The replay it prevents
///
/// The sealed format carried neither a version nor a counter: two successive
/// sealings of the same wallet were interchangeable. Putting back an earlier
/// copy of `wallet.dat` moved `next_index` backwards **and** erased the list
/// of keys already used. On a one-time scheme, that means signing again with
/// an already revealed Lamport key: the private key becomes public.
///
/// The counter grows at every write and its high-water mark is kept in a
/// separate file. A `wallet.dat` older than what has already been seen is
/// refused, with a message that says what to do.
fn mempool_path(d: &Path) -> PathBuf {
    d.join("mempool.dat")
}

fn serial_path(d: &Path) -> PathBuf {
    d.join("wallet.seq")
}

/// Name of a network as it is written on the command line.
fn network_name(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

fn network_from_name(s: &str) -> Result<Network, String> {
    match s {
        "regtest" => Ok(Network::Regtest),
        "testnet" => Ok(Network::Testnet),
        "mainnet" => Err("mainnet does not exist: the protocol is not \
                          ready, and saying otherwise would be a lie."
            .into()),
        other => Err(format!(
            "unknown network: {other}. Expected: regtest or testnet."
        )),
    }
}

fn index_path(d: &Path) -> PathBuf {
    d.join("index.dat")
}

fn known_serial(d: &Path) -> u64 {
    std::fs::read_to_string(serial_path(d))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn record_serial(d: &Path, serial: u64) {
    let path = serial_path(d);
    // `wallet.seq.tmp`, not `wallet.tmp`: the latter is the temporary file of
    // the wallet itself. The two writes follow each other without overlapping,
    // but a temporary file created as 0644 under the name of the one that
    // carries the seed is exactly what a watcher is waiting to see.
    let tmp = path.with_extension("seq.tmp");
    let written = create_private_temp(&tmp).and_then(|mut f| {
        use std::io::Write;
        f.write_all(serial.to_string().as_bytes())
            .map_err(|e| e.to_string())
    });
    if written.is_ok() && std::fs::rename(&tmp, &path).is_ok() {
        // This file only carries a counter: its failure does not deserve a
        // warning, unlike the one that carries the seed.
        let _ = restrict_access(&path);
    }
}

/// Only one thread writes the wallet at a time.
///
/// # The defect this lock repairs
///
/// `write_wallet` reads the serial number, seals the content, writes
/// `wallet.dat`, then writes `wallet.seq`. Sealing costs an Argon2id
/// derivation: a few hundred milliseconds during which the serial number read
/// at the start gets stale.
///
/// Two concurrent writes — the RPC thread after a spend, the main thread at
/// shutdown — then interleave like this:
///
/// ```text
///   thread A  reads seq=5, serial=6, starts sealing ......................
///   thread B  reads seq=5, serial=6, seals, writes wallet(6), writes seq=6
///   thread B  reads seq=6, serial=7, seals, writes wallet(7), writes seq=7
///   thread A  ..... finishes and writes wallet(6)   <-- overwrites version 7
/// ```
///
/// What remains is a `wallet.seq` at 7 and a `wallet.dat` at 6. At the next
/// start, the anti-replay protection does exactly what it is asked to: it
/// refuses to open the wallet, announcing a restore from an old backup. The
/// wallet is intact, but the user reads that they may have revealed their
/// one-time keys.
///
/// The lock covers the whole sequence: reading the serial, sealing, writing
/// both files. Between processes, the directory lock of `q21_core::lock`
/// takes care of it.
static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn write_wallet(d: &Path, w: &Wallet) -> Result<(), String> {
    // A thread that panics while holding this lock poisons the mutex. We
    // carry on anyway: the protected data is the disk, not an in-memory
    // structure that a panic could have left half modified.
    let _serialized = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let network = match w.network() {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    };
    let serial = known_serial(d).saturating_add(1);
    // The indices already used are part of the wallet just as much as the
    // seed: losing them costs a private key.
    //
    // Indices that are only reserved are listed too: a binary that ignores
    // the `reserved=` line will treat them as consumed, which is the cautious
    // reading. See `Wallet::consumed_indices_for_file`.
    let consumed: Vec<String> = w
        .consumed_indices_for_file()
        .iter()
        .map(|i| i.to_string())
        .collect();
    // The reservations in progress, with the height of their reservation: this
    // is what makes it possible, at restart, to give back a coin that a
    // shutdown between the reservation and the broadcast would otherwise have
    // frozen forever.
    let reserved: Vec<String> = w
        .reserved_indices()
        .iter()
        .map(|(i, h)| format!("{i}:{h}"))
        .collect();
    // --- The address book labels.
    //
    // The text is hex-encoded, and that is not fussiness: the file format is
    // "one key, an equals sign, one value, per line", and a label is typed by a
    // human. A line break, a comma or an equals sign in "Marie = bakery"
    // would be enough to shift the reading of everything that follows — that
    // is, one day, the seed. Hexadecimal contains none of those characters,
    // by construction.
    let labels = labels_to_text(w.labels());
    // The addresses the holder requested themselves, to tell them apart from
    // the hundreds that mining derives. It is only a display order: losing
    // this line loses neither a key nor any funds.
    let requested: Vec<String> = w
        .requested_indices()
        .iter()
        .map(|i| i.to_string())
        .collect();
    // The plaintext is wiped when this function returns, whether it succeeds
    // or not: it carries the seed.
    //
    // The keys are written under their 0.4 names. A file written by 0.3.x
    // carries other names (see `q21_core::legacy::LEGACY_WALLET_KEYS`): it is
    // read under either, and this write converts it. The conversion cannot
    // happen at startup, since the file is sealed by the passphrase.
    let content = Secret(format!(
        "seed={}\nnext_index={}\nnetwork={}\nscheme={}\nserial={}\nverified_up_to={}\nconsumed={}\nlabels={}\nrequested={}\nreserved={}\n",
        w.seed_hex(),
        w.next_index(),
        network,
        w.scheme().as_u8(),
        serial,
        w.verified_up_to(),
        consumed.join(","),
        labels,
        requested.join(","),
        reserved.join(",")
    ));
    // The wallet is sealed if a passphrase is known to this session. The seed
    // must never touch the disk in plaintext when the user asked otherwise.
    let path = wallet_path(d);
    let passphrase = current_passphrase();
    // On mainnet, the seed NEVER touches the disk in plaintext. Elsewhere
    // (testnet, regtest), the choice remains the user's, with a warning. A
    // virtual machine snapshot, a cloud backup or a resold disk would expose
    // a seed written in plaintext — unacceptable for real value. This write
    // point is the only one through which the seed reaches the disk: the
    // guard here covers init, restore and mining.
    if w.network() == Network::Mainnet && passphrase.is_none() {
        return Err("mainnet wallet without a passphrase: refused.\n  \
             On mainnet, the seed must be encrypted by a passphrase,\n  \
             never written in plaintext. Provide a passphrase and run again:\n  \
             q21 --passphrase-file <path> ...   (a file only you can read, chmod 600)\n  \
             or   read -rs Q21_PASSPHRASE && export Q21_PASSPHRASE   then the command."
            .into());
    }
    let sealed = passphrase.is_some();
    let bytes = match &passphrase {
        Some(passphrase) => q21_core::kdf::seal(
            passphrase.as_bytes(),
            content.as_bytes(),
            q21_core::kdf::DEFAULT_COST,
        )
        .map_err(|e| e.to_string())?,
        // Plaintext: a copy, wiped like the original on return.
        None => content.as_bytes().to_vec(),
    };
    // Wiped on drop: in plaintext, these bytes are the seed.
    let bytes = SecretBytes(bytes);
    // --- The write goes through a temporary file, then a rename.
    //
    // `std::fs::write` truncates the existing file **before** writing the new
    // content. An interruption between the two — out of space, flat battery,
    // hard shutdown — left an empty or incomplete `wallet.dat`, that is, a
    // lost seed. The rename, on the other hand, is atomic: the file contains
    // the old version or the new one, never a mix.
    //
    // `wallet.seq` already had this precaution; the file that carries the
    // funds did not.
    //
    // The temporary file carries the seed: it is born already restricted to
    // its owner, it never exists at any moment under another mode. See
    // `create_private_temp` for the window this closes.
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = create_private_temp(&tmp)?;
        f.write_all(&bytes.0).map_err(|e| e.to_string())?;
        // All the way to the disk, not just to the system cache: this file
        // serves as a write-ahead record before a one-time signature, and a
        // power cut just after the rename must not give back an index that
        // was just consumed.
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    // The rename itself must reach the disk: without this, the directory may
    // still point to the old file after a power cut.
    if let Ok(dir) = std::fs::File::open(d) {
        let _ = dir.sync_all();
    }

    // --- The file that carries the funds.
    //
    // If its permissions could not be restricted, keeping quiet about it
    // would be the worst choice: the user would believe bytes protected that
    // are not. The case happens for real — a FAT32 USB stick has no ACL.
    if !restrict_access(&path) {
        eprintln!(
            "warning: the access permissions of {} could not be restricted.",
            path.display()
        );
        eprintln!("  This file carries the seed of your wallet. Avoid leaving it");
        eprintln!("  on a shared disk or a USB stick, and protect it with a");
        eprintln!("  passphrase if that is not already done.");
    }
    // The serial mark is set only after the successful write: otherwise an
    // interruption between the two would make the real wallet "too old".
    record_serial(d, serial);
    // The directory anchor follows: "has seen a sealed one" never becomes
    // false again, and the fingerprint is that of the seed just written — an
    // older directory, without an anchor, acquires it here.
    let previous = read_anchor(d).unwrap_or_default();
    let anchor = Anchor {
        sealed: previous.sealed || sealed,
        seed: Some(dir_fingerprint(w)),
    };
    if anchor != previous {
        write_anchor(d, &anchor);
    }

    // The address cache follows the wallet. Its failure is not fatal: it
    // costs startup time, never funds.
    if let Err(e) =
        AddressCache::new(addresses_path(d)).save(w.scheme(), &w.known_hashes(), &w.cache_key())
    {
        eprintln!("warning: address cache not written: {e}");
    }
    Ok(())
}

/// Passphrase kept for the lifetime of the process.
///
/// It is used to reopen the wallet **and** to seal it again after each
/// change. Asking for it twice per command would be an invitation to choose a
/// short passphrase.
///
/// # Why this is no longer a `OnceLock`
///
/// It used to be a `OnceLock`, and that held as long as the passphrase was
/// typed in a terminal: it arrived once, before everything else, and a wrong
/// passphrase ended the program. Once it is typed in a page — `setup.rs` —,
/// the user can make a mistake and try again. A `OnceLock` would have kept
/// the first value forever: the second attempt, even a correct one, would
/// have failed with the message of the first. The defect would have been
/// invisible in tests and permanent in use.
///
/// The outer value distinguishes "nobody has said anything yet" from "we know
/// there is no passphrase", which are not the same thing: the second allows
/// writing a plaintext wallet, the first does not.
static PASSPHRASE: std::sync::Mutex<Option<Option<Secret>>> = std::sync::Mutex::new(None);

/// A string wiped on drop: the passphrase must not survive in the heap when
/// it is forgotten or replaced — nor the plaintext of the wallet, which
/// carries the seed.
///
/// # The defect this closes
///
/// `current_passphrase()` returned an ordinary `String`, cloned at every
/// wallet write and never wiped; the plaintext of the wallet, before sealing
/// and after unsealing, likewise lived in a bare `String`. The wiping promised
/// by the comments — "no seed, no passphrase, no derived key" — only covered
/// the seed. Everything that goes through this type is wiped when it goes out
/// of scope.
struct Secret(String);

impl Secret {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Secret(self.0.clone())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Safe: only zeros are written, which are valid UTF-8.
        q21_core::kdf::wipe(unsafe { self.0.as_bytes_mut() });
    }
}

/// Bytes wiped on drop: the wallet ready to be written, which is the seed
/// itself when there is no passphrase.
struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        q21_core::kdf::wipe(&mut self.0);
    }
}

/// The kept passphrase, in a type that wipes itself on drop. Each call
/// returns a copy; the copy is wiped when the caller lets go of it.
fn current_passphrase() -> Option<Secret> {
    PASSPHRASE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|p| p.as_ref().cloned())
}

fn remember_passphrase(p: Option<String>) {
    *PASSPHRASE.lock().unwrap_or_else(|e| e.into_inner()) = Some(p.map(Secret));
}

/// The launch token of the node's server, when a launcher has drawn one.
///
/// # Why it does not go through the arguments of `cmd_node`
///
/// The launcher (`wallet`, `explorer`) opens the browser on an address whose
/// fragment is this token, then calls `cmd_node` in the same process. It
/// could have passed it as a pseudo-argument, like the session token; but a
/// pseudo-argument one day becomes a real documented argument, and a launch
/// token that you can supply yourself on a command line makes no sense — it
/// exists precisely so that it never appears there. It therefore lives here,
/// set once before startup, read once when the server is set up. See
/// `q21_core::http::serve_with_launch_token`.
static NODE_LAUNCH_TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// A launch token: sixteen bytes from the generator, in hexadecimal.
///
/// It is valid only once and for ten minutes; sixteen bytes are enough for it
/// not to be guessed within that time, and it stays short in a terminal.
fn draw_launch_token() -> Result<String, String> {
    let raw: [u8; 16] =
        q21_core::rng::bytes().map_err(|_| "system random generator unavailable".to_string())?;
    Ok(raw.iter().map(|o| format!("{o:02x}")).collect())
}

/// Forgets the kept passphrase, without deciding that there is none.
///
/// Used only in the case where a passphrase turned out to be wrong: we go
/// back to the "nothing has been said" state, and not to the "there is no
/// passphrase" state, which would allow writing a seed in plaintext.
fn forget_passphrase() {
    *PASSPHRASE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Encodes the address book for the `labels=` line of the wallet (a
/// frozen key name).
///
/// The text goes out in hexadecimal, and that is not fussiness: the file
/// format is "one key, an equals sign, one value, per line", and a label is
/// typed by a human. A line break, a comma or an equals sign in
/// "Marie = bakery" would be enough to shift the reading of everything that
/// follows — that is, one day, the seed. Hexadecimal contains none of those
/// characters, by construction.
fn labels_to_text(e: &std::collections::HashMap<u32, String>) -> String {
    let mut v: Vec<(&u32, &String)> = e.iter().collect();
    // Sorted: two writes of the same wallet must produce the same file,
    // otherwise an incremental backup copies everything every time for
    // nothing.
    v.sort_by_key(|(i, _)| **i);
    v.iter()
        .map(|(i, t)| {
            let hex: String = t.as_bytes().iter().map(|o| format!("{o:02x}")).collect();
            format!("{i}:{hex}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Reads back the `labels=` line.
///
/// A malformed entry is ignored **on its own**, without taking the others
/// with it: losing a name is annoying, losing the wallet is far worse. A
/// file written before the address book existed has no such line at all, and
/// simply yields an empty address book.
fn text_to_labels(value: &str) -> std::collections::HashMap<u32, String> {
    let mut m = std::collections::HashMap::new();
    for entry in value.split(',').filter(|s| !s.is_empty()) {
        let Some((i, hex)) = entry.split_once(':') else {
            continue;
        };
        let Ok(index) = i.parse::<u32>() else {
            continue;
        };
        let Some(bytes) = hex_to_bytes(hex) else {
            continue;
        };
        if let Ok(text) = String::from_utf8(bytes) {
            m.insert(index, text);
        }
    }
    m
}

/// Decodes a hexadecimal sequence. Returns `None` at the slightest anomaly.
///
/// Used for the address book labels. One half-byte too many, a character that
/// is not hexadecimal: that entry is given up rather than guessed. A lost
/// label is an inconvenience; a label guessed wrong is an address book that
/// can no longer be trusted.
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut v = Vec::with_capacity(s.len() / 2);
    let o = s.as_bytes();
    for p in o.chunks(2) {
        let pair = std::str::from_utf8(p).ok()?;
        v.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(v)
}

fn read_wallet(d: &Path) -> Result<Wallet, String> {
    let raw = std::fs::read(wallet_path(d))
        .map_err(|_| "no wallet here. Run `q21 init` first.".to_string())?;
    // The directory that carries the wallet belongs to its owner, and to them
    // alone. A wider directory — earlier version, manual `mkdir` — is
    // tightened here, on the first pass.
    tighten_dir(d);

    // --- The directory anchor, BEFORE believing the file.
    //
    // A non-sealed file in a directory that has known a sealed one is not the
    // wallet of this directory: it is a substitution, or a manipulation that
    // must be owned up to explicitly. We refuse before even deciding that
    // there is no passphrase — otherwise the next write would be made in
    // plaintext. See `Anchor`.
    let anchor = read_anchor(d).unwrap_or_default();
    let sealed = q21_core::kdf::is_sealed(&raw);
    if !sealed && anchor.sealed {
        return Err(format!(
            "this directory was protected by a passphrase; this file is not.\n             \
             The wallet.dat of {} is not the one this directory has known: it was\n             \
             replaced, or restored from a copy written without a passphrase. We refuse\n             \
             to open it rather than silently switch to plaintext.\n\n             \
             If this is intended — a wallet you moved here yourself —\n             \
             delete {} after checking that this file really is yours.",
            d.display(),
            anchor_path(d).display()
        ));
    }

    // A sealed wallet is recognized by its magic. We never guess: either the
    // file announces that it is encrypted, or it is not.
    let old_format = q21_core::kdf::is_legacy_format(&raw);
    // A sealed file below the default cost — 8 KiB and one pass, for example —
    // opens in a few microseconds: the passphrase is protected only by its
    // length. We say so, and reseal at the default once the passphrase is
    // verified, by the same path as the old format.
    let below_cost = sealed && q21_core::kdf::is_below_default_cost(&raw);
    // A wallet written by 0.3.x (sealed format 2, or the old key names) is
    // converted as soon as it is open, by the same path.
    let mut legacy_names = sealed && !q21_core::kdf::is_current_format(&raw);
    if below_cost && !old_format {
        let c = q21_core::kdf::stored_cost(&raw).unwrap_or(q21_core::kdf::DEFAULT_COST);
        eprintln!(
            "warning: this wallet is sealed with an Argon2id cost of {} KiB \
             and {} pass(es), below the default ({} KiB, {} passes): a short passphrase is \
             guessed quickly. It will be resealed at the default cost.",
            c.memory_kib,
            c.passes,
            q21_core::kdf::DEFAULT_COST.memory_kib,
            q21_core::kdf::DEFAULT_COST.passes
        );
    }
    // The plaintext carries the seed: it is wiped on return.
    let content: Secret = if sealed {
        let passphrase = match current_passphrase() {
            Some(p) => p,
            None => {
                let p = get_passphrase(None, true)?
                    .ok_or("this wallet is encrypted: a passphrase is required")?;
                remember_passphrase(Some(p));
                current_passphrase().ok_or("passphrase not kept")?
            }
        };
        let plaintext =
            q21_core::kdf::unseal(passphrase.as_bytes(), &raw).map_err(|e| e.to_string())?;
        Secret(String::from_utf8(plaintext).map_err(|_| "wallet unreadable after decryption")?)
    } else {
        remember_passphrase(None);
        Secret(String::from_utf8(raw).map_err(|_| "wallet unreadable")?)
    };

    let mut seed = None;
    let mut next_index = 0u32;
    let mut serial = 0u64;
    let mut consumed: Vec<u32> = Vec::new();
    let mut reserved: Vec<(u32, u64)> = Vec::new();
    let mut labels: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut requested: Vec<u32> = Vec::new();
    let mut verified_up_to = 0u64;
    let mut network = Network::Regtest;
    // Absent from wallets written before ML-DSA arrived: we fall back to
    // Lamport, which is what they contained.
    let mut scheme = SchemeId::LamportOts;
    // A file written by 0.3.x carries other key names: they are read as their
    // 0.4 equivalents (`q21_core::legacy::wallet_key`), and the next write
    // converts the file.
    for line in content.as_str().lines() {
        let (key, value) = match line.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        let name = q21_core::legacy::wallet_key(key);
        legacy_names |= name != key;
        match name {
            "seed" => seed = Wallet::seed_from_hex(value),
            "next_index" => next_index = value.parse().unwrap_or(0),
            "serial" => serial = value.parse().unwrap_or(0),
            "verified_up_to" => verified_up_to = value.parse().unwrap_or(0),
            "consumed" => {
                consumed = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            }
            // Absent from earlier wallets: no reservation in progress, and the
            // indices of `consumed=` stay consumed, which is the cautious
            // reading. A malformed entry is ignored on its own.
            "reserved" => {
                reserved = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| {
                        let (i, h) = s.split_once(':')?;
                        Some((i.parse().ok()?, h.parse().ok()?))
                    })
                    .collect()
            }
            // Absent from wallets written before the address book: reading
            // them simply gives an empty address book, never an error. A
            // malformed entry is ignored on its own, without taking the others
            // with it — losing a name is annoying, losing the wallet is far
            // worse.
            "labels" => labels = text_to_labels(value),
            // Absent from earlier wallets: their addresses all count as
            // derived by mining, which is only a display order.
            "requested" => {
                requested = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            }
            "scheme" => {
                scheme = value
                    .parse::<u8>()
                    .ok()
                    .and_then(SchemeId::from_u8)
                    .ok_or_else(|| format!("wallet unreadable: unknown scheme ({value})"))?
            }
            "network" => {
                network = match value {
                    "mainnet" => Network::Mainnet,
                    "testnet" => Network::Testnet,
                    _ => Network::Regtest,
                }
            }
            _ => {}
        }
    }

    let seed = seed.ok_or("wallet unreadable: seed missing or malformed")?;

    // --- A seed other than the one this directory has known.
    //
    // The file is readable — it is sealed by the right passphrase, or in
    // plaintext in a directory that has never seen a sealed one — but it is
    // not *the* wallet of this directory. On an unattended miner, adopting it
    // would send the rewards elsewhere until someone compares an address. We
    // refuse, unless explicitly confirmed.
    if let Some(known) = anchor.seed {
        if !anchor_matches(&known, &Wallet::from_seed(seed, network))
            && !ACCEPT_OTHER_SEED.load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(format!(
                "this wallet.dat carries a seed other than the one the directory {} has known.\n             \
                 This is the signature of a replaced file: a backup of another wallet,\n             \
                 a shared folder, a substitution. Opened without a word, it would divert mining\n             \
                 and show someone else's balance.\n\n             \
                 If this replacement is intended, run again with --accept-other-seed: the\n             \
                 directory will then remember this seed instead.",
                d.display()
            ));
        }
    }

    // --- Replay of an earlier file.
    //
    // A `wallet.dat` put back from a backup moves `next_index` backwards and
    // erases the indices already used. With Lamport, signing again with an
    // already revealed key publishes the private key. We refuse, and say how
    // to get out of the situation — never a silent refusal on a wallet.
    let expected = known_serial(d);
    if serial < expected {
        return Err(format!(
            "this wallet carries serial number {serial}, whereas this\n             directory has already seen a more recent one ({expected}).\n             This is the signature of a restore from an old backup.\n             Reusing such a file would sign again with one-time keys\n             already used, which reveals their private key.\n\n             If this restore is intended and you know that no key\n             has been used since, delete {}.",
            serial_path(d).display()
        ));
    }

    let cache = AddressCache::new(addresses_path(d));
    let mut w = Wallet::from_seed_scheme(seed, network, scheme).map_err(|_| {
        format!(
            "this wallet uses {}, which this binary cannot handle.\n             This binary was built with `--no-default-features`: rebuild it with `cargo build --release` (ML-DSA is included by default).",
            scheme.name()
        )
    })?;
    // Recovers the addresses already handed out. The cache avoids deriving
    // every key again; it is probed again by the wallet before being adopted,
    // and any anomaly falls back to the full derivation.
    // A cache written by 0.3.x is authenticated under the legacy key; it is
    // rewritten under the current one at the next wallet write.
    let adopted = match cache
        .load(scheme, &w.cache_key())
        .or_else(|e| cache.load(scheme, &w.legacy_cache_key()).map_err(|_| e))
    {
        Ok(h) if h.len() as u32 >= next_index => w.adopt_hashes(&h[..next_index as usize]),
        Ok(_) => false,
        Err(e) => {
            if cache.exists() {
                eprintln!("warning: address cache ignored ({e})");
            }
            false
        }
    };
    w.mark_consumed(&consumed);
    w.load_reservations(&reserved);
    w.load_labels(labels);
    w.load_requested(&requested);
    w.record_verification(verified_up_to);
    if !adopted {
        w.rescan(next_index);
        if next_index > 0 {
            let _ = cache.save(scheme, &w.known_hashes(), &w.cache_key());
        }
    }
    // A file sealed by the old derivation (PBKDF2), or by Argon2id below the
    // default cost, is resealed right away at the default, with the passphrase
    // just verified: the content does not change, only the lock is replaced.
    // A failure does not prevent opening — the file stays as it was.
    if old_format || below_cost {
        match write_wallet(d, &w) {
            Ok(()) => println!("  Wallet resealed with the default protection (Argon2id)."),
            Err(e) => eprintln!("warning: wallet not resealed ({e})"),
        }
    } else if legacy_names {
        match write_wallet(d, &w) {
            Ok(()) => println!("  Wallet converted to the 0.4 file format."),
            Err(e) => eprintln!("warning: wallet not converted to the 0.4 file format ({e})"),
        }
    }
    Ok(w)
}

/// Prunes the block file if enough blocks have accumulated.
///
/// The policy and its proof are in [`q21_core::pruning`]; here, we only plug
/// it into the directory and report on it on screen. The snapshot height is
/// not passed: pruning reads it again itself from the `state.dat` file, seal
/// verified, and refuses if it does not cover the window — that is what
/// prevents a snapshot whose write failed from vouching for the removal of
/// block bodies.
fn prune_if_useful(
    datadir: &Path,
    network: Network,
    node: &q21_core::net::Node,
    archive: &q21_core::store::BlockArchive,
    last: &mut u64,
) {
    let headers = q21_core::store::HeaderStore::new(headers_path(datadir));
    let key = match q21_core::state::datadir_key(datadir) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("warning: no pruning ({e}) — the file is intact");
            return;
        }
    };
    let snapshot = StateStore::new_sealed(state_path(datadir), key);
    let policy = q21_core::pruning::DEFAULT_POLICY;
    let result = node.with_chain(|c| {
        q21_core::pruning::prune(c, archive, &headers, &snapshot, network, policy, last)
    });
    match result {
        Ok(Some(report)) if report.removed > 0 => println!(
            "  pruning: {} bodies removed, {} kept, {} MiB freed",
            report.removed,
            report.kept,
            report.bytes_freed / (1024 * 1024)
        ),
        Ok(_) => {}
        Err(e) => eprintln!("warning: no pruning ({e}) — the file is intact"),
    }
}

/// Completes the header store of a pruned node up to the snapshot that was
/// just written. See [`q21_core::pruning::complete_header_store`]: this is
/// what makes a damaged header in the block file, between two prunings, no
/// longer cost the snapshot.
///
/// Only if the store already exists: its presence marks an adopted or
/// pruned directory, and a full node that has not pruned yet must be able to
/// revalidate from its block bodies.
fn complete_store_if_pruned(datadir: &Path, node: &q21_core::net::Node, up_to: u64) {
    let headers = q21_core::store::HeaderStore::new(headers_path(datadir));
    if !headers.exists() {
        return;
    }
    let r = node.with_chain(|c| q21_core::pruning::complete_header_store(c, &headers, up_to));
    if let Err(e) = r {
        eprintln!("warning: header store not completed ({e})");
    }
}

/// Moves the files of a chain from another genesis into a subfolder.
///
/// Nothing is deleted. The wallet, its serial, its address cache and the
/// node key stay in place: those are the person's files, not the chain's.
fn set_aside_old_chain(datadir: &Path, seen_genesis: Hash256) -> Result<(), String> {
    let hex = seen_genesis.to_hex();
    let folder = datadir.join(format!(
        "{}{}",
        q21_core::legacy::OLD_CHAIN_PREFIX,
        &hex[..12]
    ));
    std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    let to_move = [
        blocks_path(datadir),
        state_path(datadir),
        headers_path(datadir),
        index_path(datadir),
        peers_path(datadir),
        mempool_path(datadir),
        adoption_path(datadir),
    ];
    let mut moved = 0;
    for f in to_move {
        if f.exists() {
            let name = f.file_name().ok_or("empty file name")?;
            std::fs::rename(&f, folder.join(name)).map_err(|e| {
                format!("cannot move {} into {}: {e}", f.display(), folder.display())
            })?;
            moved += 1;
        }
    }
    println!();
    println!("  The network has restarted from a new genesis.");
    println!(
        "  The {moved} file(s) of the old chain ({}...) have been moved to",
        &hex[..12]
    );
    println!("      {}", folder.display());
    println!("  Your wallet has not moved. The new chain is syncing");
    println!("  from the network; the old balance belonged to the old chain.");
    println!();
    Ok(())
}

fn state_path(d: &Path) -> PathBuf {
    d.join("state.dat")
}

/// Adoption record: what the node **took on trust**, and whether it has
/// verified it itself since.
///
/// # Why this file exists
///
/// A node that started from a snapshot has not validated the history before
/// the snapshot: it trusted a commitment. It is a deliberate tradeoff — it is
/// usable in minutes instead of days — but a node that trusted and a node that
/// verified are not the same thing, and nothing told them apart. The second
/// omission is the most serious: without a written trace, the trust granted
/// one day becomes invisible forever.
///
/// It is therefore recorded, and the node says so as long as it is not
/// verified.
fn adoption_path(d: &Path) -> PathBuf {
    d.join("adoption.txt")
}

struct AdoptionRecord {
    height: u64,
    tip: Hash256,
    commitment: Hash256,
    /// The commitment was recorded by 0.3.x under the old labels
    /// (`legacy_commitment=`): compare it with
    /// [`q21_core::legacy::legacy_state_commitment`].
    legacy_commitment: bool,
    revalidated: bool,
}

fn write_adoption_record(d: &Path, f: &AdoptionRecord) -> Result<(), String> {
    let text = format!(
        "height={}\ntip={}\n{}={}\nrevalidated={}\n",
        f.height,
        f.tip.to_hex(),
        if f.legacy_commitment {
            "legacy_commitment"
        } else {
            "commitment"
        },
        f.commitment.to_hex(),
        if f.revalidated { "yes" } else { "no" }
    );
    std::fs::write(adoption_path(d), text).map_err(|e| e.to_string())
}

fn read_adoption_record(d: &Path) -> Option<AdoptionRecord> {
    let text = std::fs::read_to_string(adoption_path(d)).ok()?;
    let field = |key: &str| -> Option<String> {
        text.lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    };
    let hash = |key: &str| -> Option<Hash256> {
        let v = field(key)?;
        let o = hex_to_bytes(&v)?;
        if o.len() != 32 {
            return None;
        }
        let mut t = [0u8; 32];
        t.copy_from_slice(&o);
        Some(Hash256(t))
    };
    let (commitment, legacy_commitment) = match hash("commitment=") {
        Some(e) => (e, false),
        None => (hash("legacy_commitment=")?, true),
    };
    Some(AdoptionRecord {
        height: field("height=")?.parse().ok()?,
        tip: hash("tip=")?,
        commitment,
        legacy_commitment,
        revalidated: field("revalidated=").as_deref() == Some("yes"),
    })
}

/// The warning a non-revalidated node must display — everywhere, as long as
/// it has not verified things itself.
fn warn_if_not_revalidated(datadir: &Path) {
    if let Some(f) = read_adoption_record(datadir) {
        if !f.revalidated {
            eprintln!(
                "  ! state adopted at height {} and NOT revalidated: the history before\n    \
                 this height was taken on trust, not verified. To verify it:\n    \
                 q21 --datadir <here> revalidate --blocks <blocks.dat of a full node>",
                f.height
            );
        }
    }
}

/// Header store. Its presence marks an **adopted** directory: a node that
/// started from a snapshot, and whose header chain cannot be rebuilt from the
/// block file — since it does not have the block bodies from before the
/// snapshot.
fn headers_path(d: &Path) -> PathBuf {
    d.join(q21_core::legacy::HEADERS_FILE)
}

fn addresses_path(d: &Path) -> PathBuf {
    d.join("addresses.dat")
}

fn peers_path(d: &Path) -> PathBuf {
    d.join("peers.dat")
}

/// Sleeps `seconds`, but wakes up every second to see whether shutdown has
/// been requested. Returns true if shutdown is requested. We never block long
/// on a `sleep`: a Ctrl-C must cut things short.
fn watched_sleep(seconds: u64) -> bool {
    for _ in 0..seconds {
        if q21_core::shutdown::requested() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    q21_core::shutdown::requested()
}

/// The thread that keeps the port open on the router.
///
/// It opens, announces the external address to peers, sleeps half the lease,
/// then renews — a cycle that survives a router that restarts, without ever
/// lingering if the program dies. At shutdown, it removes the mapping.
///
/// A failure never stops the node: it remains a client that connects out to
/// the network, exactly as before this version. It tries again later.
fn port_mapping_loop(
    port: u16,
    node: std::sync::Arc<q21_core::net::Node>,
    state: std::sync::Arc<std::sync::Mutex<String>>,
    mapping: std::sync::Arc<std::sync::Mutex<Option<q21_core::nat::PortMapping>>>,
) {
    while !q21_core::shutdown::requested() {
        match q21_core::nat::open_port(port) {
            Ok(o) => {
                // The interface gets a short code, not the sentence: it
                // translates the code, and it never shows the public address
                // (a screenshot of the Network tab must not reveal it). The
                // full text stays in this window, for diagnosis.
                if let Ok(mut e) = state.lock() {
                    *e = format!("open {}", o.method);
                }
                println!(
                    "  router port mapping: succeeded via {} — external address {}:{}",
                    o.method, o.external_address, o.external_port
                );
                // We announce our external address: it enters the peers'
                // address books, then spreads. The address was already
                // verified to be public by `nat::open_port`.
                node.announce_address(q21_core::wire::NetAddr {
                    ip: o.external_address.octets(),
                    port: o.external_port,
                    last_seen: unix_now(),
                });
                let lease = if o.lease_seconds == 0 {
                    q21_core::nat::LEASE_SECONDS
                } else {
                    o.lease_seconds
                };
                if let Ok(mut g) = mapping.lock() {
                    *g = Some(o);
                }
                // Renewal at half-life, never less than one minute.
                if watched_sleep((lease as u64 / 2).max(60)) {
                    break;
                }
            }
            Err(e) => {
                if let Ok(mut g) = state.lock() {
                    *g = "failed".to_string();
                }
                println!(
                    "  router port mapping impossible: {e}\n  \
                     This node remains a client: it connects out to the network, but is not \
                     reachable from outside. Nothing is broken."
                );
                // We try again in five minutes: a router can come back, or the
                // user can enable NAT-PMP in the meantime.
                if watched_sleep(300) {
                    break;
                }
            }
        }
    }
    // Shutdown: we remove the mapping. Without guarantee, and without
    // importance — a lease that is not renewed expires on its own.
    if let Ok(mut g) = mapping.lock() {
        if let Some(o) = g.take() {
            q21_core::nat::close_port(&o, port);
        }
    }
}

/// The "is this node reachable from outside" setting: see
/// [`q21_core::settings::reachable`].
fn read_reachable(d: &Path) -> bool {
    q21_core::settings::reachable(d)
}

/// Writes the "reachable" setting: see [`q21_core::settings::set_reachable`].
fn write_reachable(d: &Path, reachable: bool) -> Result<(), String> {
    q21_core::settings::set_reachable(d, reachable)
}

/// Writes a snapshot of the monetary state, if the chain is long enough.
///
/// Failure is never fatal: a missing snapshot costs a slow start, not a lost
/// chain.
fn write_snapshot(datadir: &Path, chain: &Chain) {
    if let Some(i) = chain.snapshot() {
        let _ = write_taken_snapshot(datadir, &i);
    }
}

/// Writes a snapshot already taken: encoding, sealing and writing happen
/// **outside the chain lock**. Only taking the snapshot — a copy of the UTXO
/// set and the replay of the undo records — needs the lock; the rest, which
/// costs the most as the state grows, only needs the copy.
///
/// Returns the error in addition to displaying it: the caller that prunes
/// afterwards must know that the snapshot **is not** on disk. A first version
/// returned nothing, and the snapshot loop recorded the height as written and
/// then pruned on that belief — the block bodies between the old snapshot and
/// the window disappeared, and the node went backwards at restart.
fn write_taken_snapshot(datadir: &Path, i: &q21_core::state::Snapshot) -> Result<(), String> {
    let key = q21_core::state::datadir_key(datadir).map_err(|e| e.to_string());
    let written = key.and_then(|k| {
        StateStore::new_sealed(state_path(datadir), k)
            .save(i)
            .map_err(|e| e.to_string())
    });
    if let Err(e) = &written {
        eprintln!("warning: snapshot not written: {e}");
    }
    written
}

fn load_state(datadir: &Path) -> Result<DiskState, String> {
    load_state_with(datadir, None)
}

/// Can this binary verify everything this network can carry?
///
/// A binary built with `--no-default-features` does not have ML-DSA. Faced
/// with a chain that carries it, it would not say "I cannot verify": it would
/// say "this block is invalid" — for every block, hence for every peer, which
/// it would ban at the second one; and when replaying its own directory, it
/// would cut the archive as corrupted. Software that is not equipped to judge
/// must refuse to judge, not condemn.
///
/// On regtest, we warn without refusing: it is a local test bed, and that is
/// where Lamport is tested without ML-DSA.
fn scheme_guard(network: Network) -> Result<(), String> {
    let available = SchemeId::MlDsa87.is_available() && SchemeId::MlDsa65.is_available();
    scheme_guard_with(network, available).map(|warning| {
        if let Some(a) = warning {
            eprintln!("warning: {a}");
        }
    })
}

/// The judgment of [`scheme_guard`], separated from compilation so it can be
/// tested: `Ok(None)` starts, `Ok(Some(_))` starts with a warning, `Err`
/// refuses.
fn scheme_guard_with(network: Network, mldsa_available: bool) -> Result<Option<String>, String> {
    if mldsa_available {
        return Ok(None);
    }
    let explanation = "this binary was built without ML-DSA (`--no-default-features`): \
         it cannot verify the signatures this network carries. It could neither \
         follow the chain, nor reopen a directory that already contains some.";
    match network {
        Network::Regtest => Ok(Some(format!(
            "{explanation}\n               Regtest is tolerated: only Lamport \
             keys will work on it."
        ))),
        _ => Err(format!(
            "{explanation}\n\n                   Rebuild it:   cargo build --release   (ML-DSA \
             is included by default)\n                   or install the signed release \
             (see SIGNING.md)."
        )),
    }
}

/// Loads the state of the directory.
///
/// `forced_network` serves the wallet-less node: it is then the only source
/// of the answer to "which chain does this directory contain". With a wallet,
/// the answer comes from it, and a disagreement is an error — not something
/// settled silently.
fn load_state_with(datadir: &Path, forced_network: Option<Network>) -> Result<DiskState, String> {
    let timing = std::env::var("Q21_TIMING").is_ok();
    let t0 = std::time::Instant::now();

    let has_wallet = wallet_path(datadir).exists();
    let (mut wallet, wallet_less) = if has_wallet {
        (read_wallet(datadir)?, false)
    } else {
        match forced_network {
            Some(n) => {
                // Shell: never written, never handed out. Its seed keeps
                // nothing, and mining is refused further up precisely so that
                // no coin lands on a key that will die with the process.
                (Wallet::from_seed([0u8; 32], n), true)
            }
            None => {
                return Err(
                    "no wallet here.\n\n                       To create one:        q21 init testnet\n                       For a wallet-less node: q21 node --network testnet"
                        .into(),
                )
            }
        }
    };
    if timing {
        eprintln!("[timing] wallet {:.2} s", t0.elapsed().as_secs_f64());
    }
    let network = wallet.network();
    if let Some(n) = forced_network {
        if n != network {
            return Err(format!(
                "this directory contains a {network:?} chain, and you are asking for {n:?}.\n                   Use another directory: q21 --datadir <other> node --network {}",
                network_name(n)
            ));
        }
    }
    // Before touching any block file: can this binary verify what this
    // network carries? A replay that cannot verify would cut the archive as
    // corrupted.
    scheme_guard(network)?;

    // 1. Header scan: a sequential read, no block body decoded.
    //
    // A directory without a block file is not an error when we know which
    // network it is: the genesis is deterministic, so anyone can write it
    // themselves. This is what allows someone to join the network without
    // receiving a file from anybody — and therefore without having to trust
    // anybody for the root of the chain. The network is known here in every
    // case: from the wallet, or from the option.

    // --- A chain from another genesis: the network has restarted from zero.
    //
    // The test network changes its genesis at every rule change. The block
    // file found here then belongs to the old chain: we do not delete it, we
    // move it, with everything that depended on it, into a subfolder named
    // after its genesis. The wallet — seed, indices, address book — is not
    // touched; only its verification counter is reset to zero, since the
    // heights of the old chain no longer designate anything.
    if blocks_path(datadir).exists() {
        if let Err(q21_core::store::StoreError::ForeignGenesis { seen: seen_id, .. }) =
            BlockArchive::open(blocks_path(datadir), network)
        {
            set_aside_old_chain(datadir, seen_id)?;
            wallet.forget_verification();
            if !wallet_less {
                write_wallet(datadir, &wallet)?;
            }
        }
    }
    if !blocks_path(datadir).exists() {
        std::fs::create_dir_all(datadir).map_err(|e| e.to_string())?;
        let genesis = genesis_block(network);
        q21_core::store::BlockStore::new(blocks_path(datadir))
            .append(&genesis)
            .map_err(|e| e.to_string())?;
        println!("  genesis written: {}", genesis.header.block_id());
    }

    let (archive, headers_only, issue) =
        BlockArchive::open(blocks_path(datadir), network).map_err(|e| e.to_string())?;
    if headers_only.is_empty() {
        return Err(
            "the block file contains no readable block, not even the genesis: \
             this is the only loss that prevents starting. First put the wallet \
             somewhere safe (wallet.dat, wallet.seq, addresses.dat). Then, either move \
             blocks.dat, state.dat and headers.dat out of the directory — the genesis will be \
             rewritten and the network will supply the chain again —, or resync into an empty directory."
                .into(),
        );
    }
    if let Some(s) = issue {
        eprintln!("warning: {s}");
    }
    if timing {
        eprintln!("[timing] header scan {:.2} s", t0.elapsed().as_secs_f64());
    }
    let archive = std::sync::Arc::new(archive);

    // 2. The chain, rebuilt from what the disk allows: header store of an
    // adopted or pruned directory, snapshot and replay, or revalidation from
    // genesis. The path is in the library — `q21_core::pruning::resume_chain`
    // — so that it can be tested; its rule is that a local corruption costs
    // network traffic, never a refusal to start, as long as the genesis can be
    // read back.
    //
    // The directory seal: a snapshot from elsewhere will not be adopted.
    let key = q21_core::state::datadir_key(datadir).map_err(|e| e.to_string())?;
    let state = StateStore::new_sealed(state_path(datadir), key);
    let store = q21_core::store::HeaderStore::new(headers_path(datadir));
    let mut chain =
        q21_core::pruning::resume_chain(network, &archive, headers_only, &store, &state)?;

    if timing {
        eprintln!("[timing] chain ready {:.2} s", t0.elapsed().as_secs_f64());
    }
    chain.set_body_source(archive.clone());

    // --- A restore finds its addresses again, or it restores nothing.
    //
    // A wallet only recognizes the addresses it has derived. Restored from its
    // backup code, it has derived none: it therefore displayed a balance of
    // **zero** on a chain that held its funds, and the promise "this code is
    // enough to recover everything" was false. The test that showed it takes
    // three commands: create, mine, restore elsewhere.
    //
    // We apply the gap rule: derive in windows of two hundred indices as long
    // as something is found, stop when a whole window finds nothing.
    //
    // The trigger does not look at the number of derived addresses — it looks
    // at what the wallet RECOGNIZES. The old test `next_index <= 1` believed
    // it meant "freshly restored"; it does not. The home page draws an address
    // on opening, a click on "New address" draws another, and from the second
    // index on discovery no longer triggered. A holder restored, opened, and
    // saw zero on a chain that held their funds — the very defect this
    // function was meant to close stayed wide open as soon as the wallet was
    // touched.
    //
    // The right signal is simple: if the wallet sees NONE of its funds on a
    // chain that holds some, it must search. Once its addresses are found
    // again, it sees them, and discovery no longer triggers again — without
    // depending on a counter that the slightest action makes lie.
    let to_discover = !wallet_less
        && chain.height() > 0
        && !chain.utxo.is_empty()
        && !wallet.sees_funds(&chain.utxo);
    if to_discover {
        let before = wallet.next_index();
        let found = {
            let u = &chain.utxo;
            wallet.discover(|h| u.knows(h))
        };
        if found > 0 {
            println!(
                "  restore: {found} output(s) found on the chain, \n               {} address(es) derived again",
                wallet.next_index().saturating_sub(before)
            );
            // New addresses for this file: the one-time key scan, further
            // down, must cover them.
            if wallet.scheme().is_one_time() {
                wallet.forget_verification();
            }
            let _ = write_wallet(datadir, &wallet);
        }
    }

    // --- Catching up: what was handed out after the last write.
    //
    // See `Wallet::catch_up`. It is not enough to search when nothing is
    // seen; we must also search **beyond** what we believe we handed out,
    // because a hard shutdown during mining leaves the file behind the chain.
    if !wallet_less && !chain.utxo.is_empty() {
        let before = wallet.next_index();
        let caught_up = {
            let u = &chain.utxo;
            wallet.catch_up(|h| u.knows(h))
        };
        if caught_up > 0 {
            println!(
                "  catch-up: {caught_up} output(s) found beyond the recorded \n               addresses, {} address(es) recognized",
                wallet.next_index().saturating_sub(before)
            );
            if wallet.scheme().is_one_time() {
                wallet.forget_verification();
            }
            let _ = write_wallet(datadir, &wallet);
        }
    }

    // --- One-time keys: the chain has the last word.
    //
    // A wallet file can be replaced by an earlier version; the chain cannot.
    // If this wallet announces handed-out addresses but no consumed key, the
    // state is suspect — restore from a backup code, old backup, lost file.
    // On a one-time scheme, starting again from a clean slate amounts to
    // publishing a private key at the first payment.
    //
    // We then scan the chain to find the signatures already issued. It is
    // costly, and that is exactly why it is not done at every start — only
    // when the slate is clean while it should not be.
    //
    // This scan comes **after** discovery and catch-up: it marks as consumed
    // only indices the wallet knows, and it is discovery that teaches it
    // those. In the reverse order, a recovered address that had already
    // signed once could sign again.
    if wallet.scheme().is_one_time()
        && wallet.next_index() > 0
        && wallet.verified_up_to() < chain.height()
    {
        eprintln!(
            "checking one-time keys: no known consumption \n             for {} handed-out address(es). Scanning the chain...",
            wallet.next_index()
        );
        let mut found = 0usize;
        for h in 1..=chain.height() {
            if let Some(id) = chain.active_at(h) {
                if let Some(b) = archive.read(&id) {
                    found += wallet.record_spends(&b);
                }
            }
        }
        if found > 0 {
            eprintln!(
                "             {found} already used key(s) found in the chain: \n             they will not be used again."
            );
        } else {
            eprintln!("             no signature from this wallet in the chain.");
        }
        // The scan is recorded: it will only start again from here. Without
        // this, a wallet that never spends reread the whole chain at every
        // command — a cost that grows with the height, paid for nothing.
        wallet.record_verification(chain.height());
        if !wallet_less {
            let _ = write_wallet(datadir, &wallet);
        }
    }

    // --- Reservations left by a shutdown between reservation and broadcast.
    //
    // A reserved index carries the coin being spent. If the process died
    // before broadcasting, the chain will never carry the signature: once the
    // delay has passed, the index becomes free again. See
    // `Wallet::recheck_reservations`.
    if !wallet_less && reexamine_reservations(&mut wallet, &chain, &archive) {
        let _ = write_wallet(datadir, &wallet);
    }

    Ok(DiskState {
        chain,
        wallet,
        archive,
        datadir: datadir.to_path_buf(),
        wallet_less,
    })
}

/// Reexamines the wallet's reservations in the light of the chain, and says
/// what changed. Returns `true` if the wallet must be written again.
fn reexamine_reservations(wallet: &mut Wallet, chain: &Chain, archive: &BlockArchive) -> bool {
    if wallet.reserved_indices().is_empty() {
        return false;
    }
    let (confirmed, freed) = wallet.recheck_reservations(chain.height(), |h| {
        chain.active_at(h).and_then(|id| archive.read(&id))
    });
    if confirmed > 0 {
        println!("  {confirmed} reservation(s) confirmed by the chain: key(s) used.");
    }
    if freed > 0 {
        println!(
            "  {freed} reservation(s) released: no signature in the chain after \
             {} blocks, the coin is spendable again.",
            Wallet::RESERVATION_TIMEOUT
        );
    }
    confirmed + freed > 0
}

/// Address discovery as the node loop does it, followed by the one-time key
/// scan.
///
/// # The defect this closes
///
/// The spend scan only existed at load time. On a new machine, the order is
/// reversed — you restore, *then* the chain arrives — and discovery happened
/// here, in the loop, without rereading a single block. Until the next
/// restart, a Lamport key already revealed in a block was announced as
/// spendable, and the wallet signed a second time: both preimages of every
/// bit became public.
///
/// After a successful discovery on a one-time scheme, the chain is reread
/// from genesis **before** any write: the recovered addresses are new for
/// this file, and the earlier verification did not cover them. Returns the
/// number of recovered outputs.
fn discover_in_loop(w: &mut Wallet, c: &Chain) -> usize {
    let found = {
        let u = &c.utxo;
        if u.is_empty() {
            return 0;
        }
        w.discover(|e| u.knows(e))
    };
    if found > 0 && w.scheme().is_one_time() {
        w.forget_verification();
        let marked = w.scan_chain(c.height(), |h| c.block_at(h));
        if marked > 0 {
            println!(
                "  {marked} already used one-time key(s) found in the \
                 chain: they will not be used again."
            );
        }
    }
    found
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses an amount in Q21 without ever going through a float.
fn parse_amount(s: &str) -> Result<Amount, String> {
    let (whole, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if frac.len() > DECIMALS as usize {
        return Err(format!("at most {DECIMALS} decimals"));
    }
    let e: u64 = whole.parse().map_err(|_| format!("invalid amount: {s}"))?;
    let mut f: u64 = 0;
    if !frac.is_empty() {
        f = frac
            .parse()
            .map_err(|_| format!("invalid decimal part: {frac}"))?;
        for _ in frac.len()..DECIMALS as usize {
            f *= 10;
        }
    }
    e.checked_mul(UNITS_PER_COIN)
        .and_then(|v| v.checked_add(f))
        .map(Amount::from_units)
        .ok_or_else(|| "amount out of range".into())
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Translates the name of a scheme given on the command line.
///
/// Explicitly refuses what is not compiled in: better to fail here than to
/// derive addresses this binary will never be able to spend.
fn scheme_from_name(name: &str) -> Result<SchemeId, String> {
    let s = match name {
        "lamport" => SchemeId::LamportOts,
        "mldsa65" => SchemeId::MlDsa65,
        "mldsa87" => SchemeId::MlDsa87,
        other => {
            return Err(format!(
                "unknown scheme: {other}\n  expected: lamport, mldsa65, mldsa87"
            ))
        }
    };
    if !s.is_available() {
        return Err(format!(
            "{} is not compiled into this binary.\n  This binary was built with `--no-default-features`: rebuild it with `cargo build --release` (ML-DSA is included by default).",
            s.name()
        ));
    }
    Ok(s)
}

/// Does this string look like a backup code?
///
/// The human-readable prefix of the code is `q21seed`, preceded by a network
/// letter, followed by the Bech32 separator `1`. That is what we refuse to
/// see on a command line.
fn looks_like_backup_code(s: &str) -> bool {
    s.to_ascii_lowercase().contains("q21seed1")
}

/// Restores a wallet from its backup code.
///
/// The counterpart of the Bech32m code: a code that cannot be replayed is
/// useless. The chain will resync from the network; only the keys are
/// restored here.
///
/// # The defect this closes
///
/// `q21 restore <code>` received the seed — since the code *is* the seed —
/// as a process argument. It went into the terminal history
/// (`~/.bash_history`, in plaintext, often backed up), into
/// `/proc/<pid>/cmdline` readable by any account on the machine for the whole
/// run, into `ps`, into the audit logs, and on Windows into event 4688. This
/// is not a single-run secret: it is the entire wallet, permanently.
///
/// The code is therefore no longer accepted as an argument. It is read at the
/// terminal without echo, or from a file only you can read
/// (`--backup-code-file`, with the same permission check as
/// `--passphrase-file`). An argument that looks like a code is refused with
/// an explanation of why and what to do — it is already in the history, the
/// user might as well know.
fn cmd_restore(
    datadir: &Path,
    arguments: &[String],
    code_file: Option<&str>,
    passphrase_file: Option<&str>,
) -> Result<(), String> {
    if arguments.iter().any(|a| looks_like_backup_code(a)) {
        // The code is not repeated here, not even in part: the error may end
        // up in a log, and there is already enough of it in the history.
        return Err(
            "the backup code must not be given as an argument.\n\n             \
             A command argument is written to the terminal history, readable\n             \
             by any account on this machine in /proc/<pid>/cmdline for the whole\n             \
             run, and recorded by the audit logs. Yet this code IS the\n             \
             seed: whoever reads it holds the funds, with no time limit.\n\n             \
             This code is probably already in your terminal history:\n             \
             erase it (`history -d`, or the history file), then:\n\n                 \
             q21 restore [network] [scheme]\n                     \
             (the code is asked for at the terminal, without echo)\n\n                 \
             q21 --backup-code-file <file> restore [network] [scheme]\n                     \
             (a file only you can read: chmod 600, deleted afterwards)"
                .to_string(),
        );
    }
    let network = arguments.first().map(|s| s.as_str());
    let scheme = arguments.get(1).map(|s| s.as_str());
    let chosen_network = match network.unwrap_or("regtest") {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        other => return Err(format!("unknown network: {other}")),
    };
    let code = match code_file {
        Some(path) => Secret(read_secret_from_file(path, "backup code")?),
        None => {
            if !q21_core::prompt::is_interactive() {
                return Err(
                    "no terminal to ask for the backup code.\n\n                   \
                     Without a terminal, provide it in a file only you can read:\n\n                       \
                     q21 --backup-code-file <file> restore [network] [scheme]\n                           \
                     (chmod 600 on the file, and delete it afterwards)\n\n                   \
                     Never as an argument: it would stay in the terminal history."
                        .to_string(),
                );
            }
            let (typed, masked) =
                q21_core::prompt::read_passphrase("Backup code: ").map_err(|e| e.to_string())?;
            if !masked {
                eprintln!("  warning: terminal echo could not be turned off.");
            }
            if typed.trim().is_empty() {
                return Err("no backup code entered".to_string());
            }
            Secret(typed)
        }
    };
    let seed = Wallet::seed_from_backup(code.as_str(), chosen_network).map_err(|e| match e {
        q21_core::wallet::WalletError::BackupForOtherNetwork => {
            "this backup code belongs to another network".to_string()
        }
        q21_core::wallet::WalletError::BackupIsAnAddress => address_instead_of_code_message(chosen_network),
        _ => "backup code unreadable: the checksum does not match.\n                Check the copy — the Bech32 alphabet contains no 1, b, i or o."
            .to_string(),
    })?;
    cmd_init_with(datadir, network, scheme, passphrase_file, Some(seed))
}

/// `q21 diagnostic` — why this node does not connect.
///
/// # What it repairs
///
/// A wallet that cannot reach the network displays "waiting for a
/// computer". That is true and useless: the cause can be a name that does not
/// resolve, a port closed by a firewall, an entry point that is down, an
/// entry point that is full, or two different chains. Five failures, a single
/// message — and nobody, not even the person who wrote the program, can tell
/// them apart without a tool.
///
/// This command runs the four tests in order, on each bootstrap address, and
/// names the one that fails:
///
/// 1. is the bootstrap file there, and what does it contain;
/// 2. does the name resolve to addresses;
/// 3. does the port accept a TCP connection;
/// 4. does the Q21 handshake succeed — same network, same genesis.
///
/// It does not take the data directory lock: we diagnose while the wallet is
/// running, that is the whole point.
fn cmd_diagnostic(datadir: &Path, args: &[String]) -> Result<(), String> {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let network = match args.iter().position(|a| a == "--network") {
        Some(i) => network_from_name(args.get(i + 1).map(|s| s.as_str()).unwrap_or(""))?,
        None => Network::Testnet,
    };

    println!("Q21 diagnostic");
    println!();
    println!("  network          {}", network_name(network));
    let genesis = q21_core::chain::genesis_block(network);
    println!("  computed genesis {}", genesis.header.block_id());
    println!("  directory        {}", datadir.display());
    println!();

    // --- 1. The bootstrap addresses, and where they come from.
    let file = datadir.join(q21_core::bootstrap::FILE_NAME);
    let in_file = q21_core::bootstrap::bootstrap_from_datadir(datadir);
    let built_in: Vec<String> = q21_core::bootstrap::builtin_bootstrap(network)
        .iter()
        .map(|s| s.to_string())
        .collect();

    if file.exists() {
        println!("  {}: {} address(es)", file.display(), in_file.len());
    } else {
        println!("  {}: MISSING", file.display());
    }
    if !built_in.is_empty() {
        println!("  built into the binary: {}", built_in.len());
    }

    let next_to_program = q21_core::bootstrap::bootstrap_next_to_program();
    match std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.join(q21_core::bootstrap::FILE_NAME)))
    {
        Some(c) if c.exists() => {
            println!("  {}: {} address(es)", c.display(), next_to_program.len())
        }
        Some(c) => match q21_core::bootstrap::legacy_bootstrap_next_to_program() {
            Some(old) => println!(
                "  {}: MISSING, the 0.3.x file {} is read instead: {} address(es)",
                c.display(),
                old.display(),
                next_to_program.len()
            ),
            None => println!("  {}: MISSING", c.display()),
        },
        None => {}
    }

    let mut targets = in_file;
    targets.extend(next_to_program);
    targets.extend(built_in);
    targets.sort();
    targets.dedup();

    if targets.is_empty() {
        println!();
        println!("  VERDICT: no bootstrap address. This node will not look for anyone.");
        println!();
        println!("  Create {} and write one line into it:", file.display());
        println!("      bootstrap.q21.dev:21121");
        return Ok(());
    }

    // --- A throwaway in-memory node, with the genesis of this network. It is
    //     the one that will do the real handshakes: a protocol is not tested
    //     by reimplementing it on the side, it is tested with its own code.
    let chain = q21_core::chain::Chain::new(network, genesis);
    let node = std::sync::Arc::new(q21_core::net::Node::new(network, chain));

    let mut one_works = false;
    for target in &targets {
        println!();
        println!("  --- {target}");

        // --- 2. Resolution.
        let addresses = match q21_core::bootstrap::resolve(target, network) {
            Ok(a) if !a.is_empty() => a,
            Ok(_) => {
                println!("      name         NO ADDRESS — the name yields nothing");
                continue;
            }
            Err(e) => {
                println!("      name         UNRESOLVED: {e}");
                println!("      -> check the spelling, and your internet access");
                continue;
            }
        };
        println!(
            "      name         resolved: {}",
            addresses
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        for sa in &addresses {
            // --- 3. Does the port answer?
            let t0 = Instant::now();
            match TcpStream::connect_timeout(sa, Duration::from_secs(5)) {
                Ok(f) => {
                    println!("      port {sa}  OPEN in {} ms", t0.elapsed().as_millis());
                    drop(f);
                }
                Err(e) => {
                    println!("      port {sa}  CLOSED: {e}");
                    println!("      -> entry point down, or a firewall between you and it");
                    continue;
                }
            }

            // --- 4. The Q21 handshake.
            if node.is_connected_to(*sa) {
                continue;
            }
            if node.connect(*sa).is_err() {
                println!("      handshake    REFUSED at opening");
                continue;
            }
            let before = node.peer_count_established();
            let mut done = false;
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(8) {
                if node.peer_count_established() > before {
                    done = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if done {
                println!(
                    "      handshake    DONE — the peer announces height {}",
                    node.max_announced_height()
                );
                // The handshake does not carry the genesis: two nodes on
                // different chains complete it, then part ways at the header
                // exchange. We therefore look at whether the link HOLDS,
                // instead of announcing a chain identity we have not verified.
                // What this command knows, it says; what it does not know, it
                // does not make up.
                let t = Instant::now();
                while t.elapsed() < Duration::from_secs(6) {
                    if node.peer_count_established() <= before {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                if node.peer_count_established() > before {
                    println!("      link         HELD — the peer keeps us");
                    one_works = true;
                } else {
                    println!("      link         BROKEN right after the handshake");
                    println!("      -> different chains, most often: compare");
                    println!(
                        "         `q21 genesis {}` with the value published by the operator",
                        network_name(network)
                    );
                }
            } else {
                println!("      handshake    FAILED — the port answers but the peer turns us away");
                println!("      -> entry point full, or a different network");
            }
            let _ = std::io::stdout().flush();
        }
    }

    println!();
    if one_works {
        println!("  VERDICT: at least one entry point answers and keeps the link.");
        println!();
        println!("  The path is therefore open. If the wallet stays \"waiting\":");
        println!("  close it completely — only one instance at a time per directory —");
        println!(
            "  then start it again. And compare `q21 genesis {}` with the value",
            network_name(network)
        );
        println!("  published by the operator: it is the only check nothing automates.");
    } else {
        println!("  VERDICT: no reachable entry point.");
        println!("  The network cannot be joined while this lasts. It is not");
        println!("  your machine: the tests above say at which step it breaks.");
    }
    Ok(())
}

/// The message for someone who pasted an address where a code was expected.
///
/// It names both objects, says why one cannot do the job of the other, and
/// gives the prefix to look for. An address restores nothing, and that is a
/// property of the system, not a limitation: if it could, anyone with your
/// address would have your funds.
fn address_instead_of_code_message(network: Network) -> String {
    format!(
        "this is a receiving address ({}…), not a backup code.\n\n                \
         An address is for receiving; it cannot restore any wallet — otherwise\n                \
         anyone who knows it would have your funds. The backup code is the one displayed\n                \
         only once at creation, to be copied on paper: it starts with {}1…\n                \
         If you did not write it down, the wallet still exists where it was created:\n                \
         open it from that folder, the Info tab displays its backup code.",
        network.hrp(),
        q21_core::wallet::backup_code_hrp(network)
    )
}

fn cmd_init(
    datadir: &Path,
    network: Option<&str>,
    scheme: Option<&str>,
    passphrase_file: Option<&str>,
) -> Result<(), String> {
    cmd_init_with(datadir, network, scheme, passphrase_file, None)
}

/// Creates the chain and the wallet in a new directory.
///
/// This is the core of `init` and `restore`, extracted so that the setup page
/// can call it without going through a terminal. The function prints nothing
/// and asks for nothing: the passphrase must already be established — it is
/// [`write_wallet`] that uses it to seal.
///
/// The order matters, and it is the same as in the command-line version: the
/// wallet is written only after the genesis, so that a directory can never
/// contain a seed without the chain that goes with it.
fn write_new_chain(
    datadir: &Path,
    network: Network,
    scheme: SchemeId,
    given_seed: Option<[u8; 32]>,
) -> Result<(Wallet, q21_core::address::Address, q21_core::block::Block), String> {
    let mut wallet = match given_seed {
        Some(g) => Wallet::from_seed_scheme(g, network, scheme)
            .map_err(|_| format!("scheme unavailable: {}", scheme.name()))?,
        None => Wallet::generate_scheme(network, scheme).map_err(|e| match e {
            q21_core::wallet::WalletError::RandomnessUnavailable => {
                "the system random generator is unavailable: no key was created. \
                 Better no wallet than a predictable wallet."
                    .to_string()
            }
            _ => format!("scheme unavailable: {}", scheme.name()),
        })?,
    };
    let payee = wallet.new_address();
    let genesis = genesis_block(network);

    let store = q21_core::store::BlockStore::new(blocks_path(datadir));
    store.append(&genesis).map_err(|e| e.to_string())?;
    write_wallet(datadir, &wallet)?;
    Ok((wallet, payee, genesis))
}

fn cmd_init_with(
    datadir: &Path,
    network: Option<&str>,
    scheme: Option<&str>,
    passphrase_file: Option<&str>,
    given_seed: Option<[u8; 32]>,
) -> Result<(), String> {
    let network = match network.unwrap_or("regtest") {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        "mainnet" => {
            return Err("mainnet does not exist: the protocol is not ready, \
                        and saying otherwise would be a lie."
                .into())
        }
        other => return Err(format!("unknown network: {other}")),
    };

    if blocks_path(datadir).exists() {
        return Err(format!(
            "a chain already exists in {}. Delete the directory to start from scratch.",
            datadir.display()
        ));
    }
    create_private_dir(datadir)?;

    // By default, the best scheme this binary can handle.
    let scheme = match scheme {
        Some(n) => scheme_from_name(n)?,
        // The highest level the standard defines, because it costs nothing:
        // fifteen more milliseconds per full block, against a target of one
        // hundred and twenty seconds. See the documentation of
        // `SchemeId::MlDsa87`.
        None if SchemeId::MlDsa87.is_available() => SchemeId::MlDsa87,
        None => SchemeId::LamportOts,
    };
    if !scheme.allowed_on(network) {
        return Err(format!("{} is not allowed on this network.", scheme.name()));
    }

    // The passphrase is established BEFORE creating anything: a wallet
    // written in plaintext and then encrypted would have left a plaintext
    // trace on the disk, and a deleted file is not a destroyed file.
    if passphrase_file.is_none() && current_passphrase().is_none() {
        // --- A choice that was not made is not a choice.
        //
        // Without a terminal — double-clicked application, scheduled task,
        // redirected stream — `read_line` returns an empty line immediately.
        // The program understood "no passphrase" when nobody had chosen
        // anything, and created a wallet whose seed went to the disk in
        // plaintext.
        //
        // We refuse, and say how to do it otherwise. Both suggested ways work
        // without a terminal.
        if !q21_core::prompt::is_interactive() {
            return Err(
                "no terminal to ask for a passphrase.\n\n                   Creating a wallet without protection would write the seed in plaintext\n                   to the disk, and that is not a decision to make on your behalf.\n\n                   Two ways to provide the passphrase without a terminal:\n\n                       q21 --passphrase-file <path> init testnet\n                           (a file only you can read: chmod 600)\n\n                       read -rs Q21_PASSPHRASE && export Q21_PASSPHRASE\n                       q21 init testnet\n                           (never `Q21_PASSPHRASE=... q21` on a single line:\n                            the passphrase would stay in the terminal history)\n\n                   And if you really want a wallet without protection —\n                   on a test network, for example — run this command from\n                   a terminal and leave the passphrase empty."
                    .to_string(),
            );
        }
        // An input error (confirmations that never match, terminal closed)
        // stops the creation: turning it into "no passphrase" would write the
        // seed in plaintext on the user's behalf.
        let typed = q21_core::prompt::read_passphrase_confirmed(
            "Wallet passphrase (empty = no protection): ",
        )
        .map_err(|e| format!("passphrase: {e}"))?;
        // A non-empty passphrase below the floor is refused: better to stop
        // and let the user choose a real one, or choose empty knowingly, than
        // to seal a seed behind a guessable secret. See MIN_PASSPHRASE_LEN.
        if let Some(ref p) = typed {
            let n = p.chars().count();
            if n < MIN_PASSPHRASE_LEN {
                return Err(format!(
                    "passphrase too short ({n} character(s)): at least \
                     {MIN_PASSPHRASE_LEN} are needed, or none (leave it empty) for a wallet without \
                     protection, chosen knowingly. Run `init` again."
                ));
            }
        }
        remember_passphrase(typed);
    }
    if current_passphrase().is_none() {
        println!();
        println!("  WARNING: no passphrase.");
        println!("  The seed will be written IN PLAINTEXT in wallet.dat. Anyone who reads this");
        println!("  file — backup, resold disk, shared folder — will hold the funds");
        println!("  for good.");
        println!();
    }

    let (wallet, payee, genesis) = write_new_chain(datadir, network, scheme, given_seed)?;

    println!();
    println!("  Chain initialized in {}", datadir.display());
    println!("  Network           {network:?}");
    println!("  Scheme            {}", scheme.name());
    println!("  Genesis           {}", genesis.header.block_id());
    println!(
        "  Message           {}",
        String::from_utf8_lossy(&genesis.transactions[0].inputs[0].witness.signature)
    );
    println!(
        "  Genesis coin      {} Q21",
        Amount::from_units(GENESIS_PREMINT)
    );
    println!("  Payee             {payee}");
    println!();
    println!("  BACKUP CODE");
    println!();
    println!("    {}", wallet.backup_code());
    println!();
    println!("  Copy it on paper, away from this machine. It is the only way");
    println!("  to recover the funds if the file disappears — and it carries a");
    println!("  checksum: a typo will be detected, not suffered.");
    println!();
    println!(
        "  The genesis coin is a coinbase: it becomes spendable\n  \
         after {COINBASE_MATURITY} blocks. Run `q21 mine {}`.",
        COINBASE_MATURITY + 1
    );
    Ok(())
}

fn cmd_info(datadir: &Path) -> Result<(), String> {
    let e = load_state(datadir)?;
    let tip = e.chain.tip();
    let target = pow::target_from_compact(tip.bits).map_err(|x| format!("{x:?}"))?;

    println!("Chain");
    println!("  Network           {:?}", e.chain.network);
    println!("  Height            {}", e.chain.height());
    println!("  Tip               {}", e.chain.tip_id());
    println!(
        "  Timestamp         {} ({})",
        tip.time,
        if tip.time > unix_now() {
            "future"
        } else {
            "past"
        }
    );
    println!("  Difficulty        {:#010x}", tip.bits);
    println!("  Target            {}", short_hex(&target.to_be_bytes()));
    println!("  Cumulative work   {}", format_work(e.chain.total_work()));
    println!("  Known blocks      {}", e.chain.known_blocks());
    println!();
    println!("Currency");
    println!("  Issued            {} Q21", e.chain.total_issued());
    println!("  In the UTXO set   {} Q21", e.chain.utxo.total_value());
    println!("  Cap               {} Q21", Amount::from_units(MAX_SUPPLY));
    println!(
        "  Share issued      {:.6} %",
        100.0 * e.chain.total_issued().units() as f64 / MAX_SUPPLY as f64
    );
    println!(
        "  Next block        {} Q21",
        emission::block_subsidy(e.chain.height() + 1)
    );
    println!();
    println!("Wallet");
    println!(
        "  Spendable balance {} Q21",
        e.wallet.balance(&e.chain.utxo, e.chain.height())
    );
    println!("  Derived addresses {}", e.wallet.next_index());
    println!("  Tracked outputs   {}", e.chain.utxo.len());
    Ok(())
}

fn cmd_address(datadir: &Path) -> Result<(), String> {
    let mut e = load_state(datadir)?;
    let a = e.wallet.request_address();
    write_wallet(&e.datadir, &e.wallet)?;
    println!("{a}");
    println!();
    println!("Scheme: {}", a.scheme.name());
    if a.scheme.is_one_time() {
        println!(
            "One-time address: Lamport reveals the private key if it signs\n\
             twice. Each `q21 address` produces a new one, and that is\n\
             mandatory, not a privacy precaution."
        );
    } else {
        println!(
            "Reusable address: ML-DSA signs as many times as you like without\n\
             weakening the key. Each `q21 address` still produces a new one\n\
             — for privacy, this time, and not out of necessity."
        );
    }
    Ok(())
}

fn cmd_balance(datadir: &Path) -> Result<(), String> {
    let e = load_state(datadir)?;
    let h = e.chain.height();
    let balance = e.wallet.balance(&e.chain.utxo, h);
    let outputs = e.wallet.spendable(&e.chain.utxo, h);

    println!("{balance} Q21 spendable ({} outputs)", outputs.len());

    // What exists but is not mature yet.
    let mut immature = 0u64;
    for (_, entry) in e.chain.utxo.iter() {
        if entry.is_coinbase
            && h < entry.height + COINBASE_MATURITY
            && e.wallet.owns(&entry.output.pubkey_hash)
        {
            immature += entry.output.value.units();
        }
    }
    if immature > 0 {
        println!(
            "{} Q21 still immature ({COINBASE_MATURITY} blocks to maturity)",
            Amount::from_units(immature)
        );
    }

    // --- What a reused address has locked up.
    //
    // With a one-time signature, a key signs only once: if an address
    // receives two payments, only one of the two coins is spendable. Keeping
    // quiet about the second would make funds disappear without explanation.
    // We name it, and say what to do so that it does not happen again.
    warn_if_not_revalidated(datadir);

    let frozen = e.wallet.frozen_amount(&e.chain.utxo, h);
    if frozen.units() > 0 {
        let reused = e.wallet.reused_addresses(&e.chain.utxo, h);
        println!("{frozen} Q21 locked up by address reuse");
        println!(
            "  {} address(es) received more than one payment. A one-time key",
            reused.len()
        );
        println!("  signs only once: only the largest coin remains spendable.");
        println!("  Give a new address for each payment (q21 address).");
    }
    Ok(())
}

fn cmd_mine(datadir: &Path, n: Option<&str>) -> Result<(), String> {
    let n: u64 = n.unwrap_or("1").parse().map_err(|_| "invalid number")?;
    let mut e = load_state(datadir)?;

    // --- Pending transactions go into the blocks we mine.
    //
    // `q21 mine` ignored the mempool and mined empty blocks. A transaction
    // sent and then followed by a `mine` therefore stayed pending
    // indefinitely, even though the command seemed made to confirm it. That
    // is exactly the sequence the first user followed.
    let mut mempool = q21_core::mempool::Mempool::new();
    let store = q21_core::state::datadir_key(datadir)
        .ok()
        .map(|key| q21_core::state::MempoolStore::new(mempool_path(datadir), key));
    if let Some(m) = &store {
        if m.exists() {
            if let Ok(pending) = m.load() {
                let height = e.chain.height();
                let mut restored = 0usize;
                for tx in &pending {
                    if mempool
                        .accept(tx, &e.chain.utxo, e.chain.network, height)
                        .is_ok()
                    {
                        restored += 1;
                    }
                }
                if restored > 0 {
                    println!("mempool: {restored} transaction(s) to confirm");
                }
            }
        }
    }

    let start = std::time::Instant::now();
    let mut total_attempts = 0u64;

    let mut last_write = std::time::Instant::now();
    for i in 0..n {
        let addr = e.wallet.new_address();
        // The payee's scheme must be the one of its address, otherwise the
        // hash written into the output will match no key and the coin will be
        // lost.
        let scheme = addr.scheme;
        let t = unix_now().max(e.chain.tip().time + 1);

        let selection = mempool.select_for_block(q21_core::consensus::TARGET_BLOCK_WEIGHT);
        let block = e
            .chain
            .mine_block(addr.hash, scheme, &selection, t, 200_000_000)
            .ok_or_else(|| format!("no nonce found for block {}", e.chain.height() + 1))?;
        total_attempts += block.header.nonce;

        // Validation clock.
        //
        // A timestamp cannot exceed the current time by more than
        // MAX_FUTURE_TIME. Since the test network mines much faster than one
        // second per block, a burst ran into this bound after ~7,200 blocks —
        // which made any test on a long chain impossible.
        //
        // On Regtest **only**, we validate against a simulated clock that
        // follows the block. It is the equivalent of Bitcoin Core's
        // `setmocktime`, and it is confined to the network that has no value:
        // on testnet as on mainnet, the bound applies as is.
        let clock = if e.chain.network == Network::Regtest {
            block.header.time + 1
        } else {
            unix_now()
        };

        e.chain
            .connect(&block, clock)
            .map_err(|x| format!("block refused by our own validator: {x:?}"))?;
        e.archive.append(&block).map_err(|x| x.to_string())?;
        mempool.on_block_connected(&block);

        let reward = block.transactions[0].outputs[0].value;
        // Beyond a few hundred blocks, one line per block drowns the output
        // without teaching anyone anything.
        let verbose = n <= 200 || i + 1 == n || (i + 1) % 1_000 == 0;
        if verbose {
            println!(
                "block {:>6}  {}  +{} Q21",
                block.header.height,
                short_hex(block.header.block_id().as_bytes()),
                reward
            );
        }

        // The wallet follows the chain on disk: at the last block, and along
        // the way every thirty seconds. A hard shutdown then leaves only a few
        // addresses behind — which the catch-up at load time finds anyway.
        if i + 1 == n || last_write.elapsed() >= std::time::Duration::from_secs(30) {
            write_wallet(&e.datadir, &e.wallet)?;
            last_write = std::time::Instant::now();
        }
    }
    write_snapshot(&e.datadir, &e.chain);

    // What remains pending is written again; what was just confirmed
    // disappears. Leaving the file as is would bring back to life, at the
    // next start, transactions already in a block.
    if let Some(m) = &store {
        let remaining = mempool.ordered_transactions();
        if remaining.is_empty() {
            let _ = m.remove();
        } else if let Err(x) = m.save(&remaining) {
            eprintln!("warning: mempool not written again: {x}");
        }
    }

    let seconds = start.elapsed().as_secs_f64();
    println!();
    println!(
        "{n} block(s) in {seconds:.2} s — {:.0} hashes/s",
        total_attempts as f64 / seconds.max(0.001)
    );
    println!("Height: {}", e.chain.height());
    println!("Issued: {} Q21", e.chain.total_issued());
    Ok(())
}

fn cmd_send(
    datadir: &Path,
    address: Option<&String>,
    amount: Option<&String>,
) -> Result<(), String> {
    let address = address.ok_or("usage: q21 send <address> <amount>")?;
    let amount = amount.ok_or("usage: q21 send <address> <amount>")?;
    let mut e = load_state(datadir)?;

    let dest = Address::parse_on(address, e.chain.network)
        .map_err(|x| format!("invalid address: {x:?}"))?;
    let value = parse_amount(amount)?;
    let fee = Amount::from_units(1_000);

    let datadir = e.datadir.clone();
    let tx = e
        .wallet
        .create_transaction_multi_guarded(
            &e.chain.utxo,
            e.chain.height(),
            &[(dest, value)],
            fee,
            &mut |w| write_wallet(&datadir, w),
        )
        .map_err(|x| match x {
            q21_core::wallet::WalletError::InsufficientFunds {
                available: avail,
                requested: req,
            } => format!(
                "insufficient funds: {} Q21 available, {} Q21 requested",
                Amount::from_units(avail),
                Amount::from_units(req)
            ),
            other => format!("{other:?}"),
        })?;

    println!("Transaction  {}", tx.txid());
    println!("  to         {dest}");
    println!("  amount     {value} Q21");
    println!("  fee        {fee} Q21");
    println!("  inputs     {}", tx.inputs.len());
    println!("  size       {} bytes", tx.encode().len());
    println!(
        "  of which witness {} bytes ({} %)",
        tx.encode().len() - tx.encode_without_witness().len(),
        100 * (tx.encode().len() - tx.encode_without_witness().len()) / tx.encode().len().max(1)
    );

    // No mempool yet in phase 2: the transaction goes directly into a block
    // that we mine on the spot.
    println!();
    println!("Mining the block that contains it...");
    let addr = e.wallet.new_address();
    let t = unix_now().max(e.chain.tip().time + 1);
    let mempool: Vec<Transaction> = vec![tx];

    let block = e
        .chain
        .mine_block(addr.hash, addr.scheme, &mempool, t, 200_000_000)
        .ok_or("no nonce found")?;

    let fees_collected = e
        .chain
        .connect(&block, unix_now())
        .map_err(|x| format!("block refused: {x:?}"))?;
    e.archive.append(&block).map_err(|x| x.to_string())?;
    write_wallet(&e.datadir, &e.wallet)?;
    write_snapshot(&e.datadir, &e.chain);

    println!(
        "block {} mined — fees collected by the miner: {} Q21",
        block.header.height, fees_collected
    );
    println!(
        "Remaining balance: {} Q21",
        e.wallet.balance(&e.chain.utxo, e.chain.height())
    );
    Ok(())
}

fn cmd_block(datadir: &Path, height: Option<&str>) -> Result<(), String> {
    let h: u64 = height
        .ok_or("usage: q21 block <height>")?
        .parse()
        .map_err(|_| "invalid height")?;
    let e = load_state(datadir)?;
    // Through the chain, which knows how to fetch a pruned body from the
    // archive.
    let b = e
        .chain
        .block_at(h)
        .ok_or_else(|| format!("height {h} unknown (tip: {})", e.chain.height()))?;
    let b = &b;

    println!("Block {h}");
    println!("  Identifier    {}", b.header.block_id());
    println!("  Parent        {}", b.header.prev_block);
    println!("  Merkle        {}", b.header.merkle_root);
    println!("  Timestamp     {}", b.header.time);
    println!("  Difficulty    {:#010x}", b.header.bits);
    println!("  Nonce         {}", b.header.nonce);
    println!("  Uncles        {}", b.uncles.len());
    println!("  Size          {} bytes", b.encode().len());
    println!("  Subsidy       {} Q21", emission::block_subsidy(h));
    println!();
    println!("  {} transaction(s)", b.transactions.len());
    for (i, t) in b.transactions.iter().enumerate() {
        let label = if t.is_coinbase() {
            "coinbase"
        } else {
            "spend   "
        };
        println!(
            "    {i:>3} {label} {}  {} input(s) -> {} output(s)  {} Q21",
            short_hex(t.txid().as_bytes()),
            t.inputs.len(),
            t.outputs.len(),
            t.total_output().map(|a| a.to_string()).unwrap_or_default()
        );
    }
    Ok(())
}

fn cmd_utxo(datadir: &Path) -> Result<(), String> {
    let e = load_state(datadir)?;
    let h = e.chain.height();
    let mut ours = 0u64;
    let mut immature = 0u64;
    let mut n_ours = 0usize;

    for (_, entry) in e.chain.utxo.iter() {
        if e.wallet.owns(&entry.output.pubkey_hash) {
            n_ours += 1;
            if entry.is_coinbase && h < entry.height + COINBASE_MATURITY {
                immature += entry.output.value.units();
            } else {
                ours += entry.output.value.units();
            }
        }
    }

    println!("UTXO set");
    println!("  Total outputs     {}", e.chain.utxo.len());
    println!("  Total value       {} Q21", e.chain.utxo.total_value());
    println!("  Ours              {n_ours} outputs");
    println!("  Spendable         {} Q21", Amount::from_units(ours));
    println!("  Immature          {} Q21", Amount::from_units(immature));
    println!();
    println!(
        "  Anti-inflation check: {}",
        if e.chain.utxo.total_value().units() <= MAX_SUPPLY {
            "supply under the cap, OK"
        } else {
            "CAP EXCEEDED — consensus bug"
        }
    );
    Ok(())
}

/// `snapshot <export|verify> ...`
///
/// A portable snapshot is the state of the currency that can be given to
/// another machine to spare it from revalidating everything. It does not
/// carry its own trust: whoever adopts it compares its commitment with a
/// trusted value — the one displayed by their explorer. `export` writes it,
/// `verify` checks it.
/// Loads the state for a snapshot command, accepting an explicit
/// `--network`.
///
/// A bootstrap node — like the explorer server — runs **without a wallet**:
/// it then has no source to say which chain it is, and `load_state` would
/// fail for lack of a wallet. `--network` gives it that. With a wallet, the
/// option is superfluous: the chain comes from the wallet.
fn load_for_snapshot(datadir: &Path, options: &[String]) -> Result<DiskState, String> {
    let mut network = None;
    let mut i = 0;
    while i < options.len() {
        if options[i] == "--network" {
            network = Some(network_from_name(
                options.get(i + 1).ok_or("--network requires a value")?,
            )?);
            i += 2;
        } else {
            i += 1;
        }
    }
    match network {
        Some(r) => load_state_with(datadir, Some(r)),
        None => load_state(datadir),
    }
}

fn cmd_snapshot(datadir: &Path, args: &[String]) -> Result<(), String> {
    use q21_core::state::Snapshot;
    use q21_core::store::{BlockStore, HeaderStore};

    match args.first().map(|s| s.as_str()) {
        Some("export-sync") => {
            let folder = args
                .get(1)
                .ok_or("usage: q21 snapshot export-sync <folder> [--network <name>]")?;
            let e = load_for_snapshot(datadir, &args[2..])?;
            let network = e.chain.network;
            let s = e
                .chain
                .snapshot()
                .ok_or("the chain is too short for a snapshot: several blocks are needed")?;
            let h = s.height;

            // The headers from genesis up to the snapshot height: the header
            // chain that an adopting node cannot rebuild, for lack of the
            // block bodies from before the snapshot.
            let all = e.chain.headers();
            if h as usize >= all.len() {
                return Err("snapshot height inconsistent with the headers".into());
            }
            let headers = &all[..=h as usize];

            // A bounded window of block bodies around the snapshot: the uncle
            // double-payment rule rereads the few blocks preceding each
            // replayed block, up to MAX_UNCLE_AGE back. Without them, the first
            // block above the snapshot could not be validated.
            let margin = MAX_UNCLE_AGE + 2;
            let start = h.saturating_sub(margin);

            let d = Path::new(folder);
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;

            std::fs::write(d.join("snapshot.q21snap"), s.to_portable_bytes())
                .map_err(|err| format!("writing the snapshot: {err}"))?;

            let hs = HeaderStore::new(d.join("headers.q21hdr"));
            let _ = hs.remove();
            hs.append(headers).map_err(|e| e.to_string())?;

            // The body file starts with the genesis — a constant of the
            // network — so that the root check of the block file is satisfied
            // at adoption, then the window around the snapshot.
            let bs = BlockStore::new(d.join("bodies.dat"));
            let _ = bs.remove();
            bs.append(&genesis_block(network))
                .map_err(|e| e.to_string())?;
            for hh in start..=h {
                if hh == 0 {
                    continue; // the genesis is already written
                }
                let b = e
                    .chain
                    .block_at(hh)
                    .ok_or_else(|| format!("body of block {hh} missing"))?;
                bs.append(&b).map_err(|e| e.to_string())?;
            }

            let notice = format!(
                "Q21 fast-sync snapshot\n\
                 Network     {network:?}\n\
                 Height      {h}\n\
                 Tip         {}\n\
                 Commitment  {}\n\n\
                 To adopt it on a new machine, in an empty folder:\n  \
                 q21 --datadir <folder> snapshot adopt {folder} \\\n    \
                 --tip {} --commitment {}\n\n\
                 First compare the tip and the commitment with those displayed by a\n\
                 trusted source (your explorer).\n",
                s.tip,
                s.commitment(),
                s.tip,
                s.commitment()
            );
            std::fs::write(d.join("snapshot.txt"), &notice)
                .map_err(|err| format!("writing the notice: {err}"))?;

            println!("Snapshot written to: {folder}");
            print!("{notice}");
            Ok(())
        }
        Some("adopt") => {
            let folder = args
                .get(1)
                .ok_or("usage: q21 snapshot adopt <folder> --tip <hex> --commitment <hex>")?;
            let (mut tip_hex, mut commitment_hex) = (None, None);
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--tip" => {
                        tip_hex = Some(args.get(i + 1).ok_or("--tip requires a value")?.clone());
                        i += 2;
                    }
                    "--commitment" => {
                        commitment_hex = Some(
                            args.get(i + 1)
                                .ok_or("--commitment requires a value")?
                                .clone(),
                        );
                        i += 2;
                    }
                    other => return Err(format!("unknown option: {other}")),
                }
            }
            let tip = Hash256::from_hex(
                tip_hex
                    .ok_or("--tip <hex> is mandatory: the trusted tip")?
                    .trim(),
            )
            .ok_or("--tip: 64 hexadecimal characters expected")?;
            let commitment = Hash256::from_hex(
                commitment_hex
                    .ok_or("--commitment <hex> is mandatory: the trusted commitment")?
                    .trim(),
            )
            .ok_or("--commitment: 64 hexadecimal characters expected")?;

            // We only adopt into a blank folder: never on top of an existing
            // chain.
            if blocks_path(datadir).exists()
                || state_path(datadir).exists()
                || headers_path(datadir).exists()
            {
                return Err(format!(
                    "the folder {} already contains a chain: adoption is done \
                     only into an empty folder",
                    datadir.display()
                ));
            }

            let d = Path::new(folder);
            let bytes = std::fs::read(d.join("snapshot.q21snap"))
                .map_err(|e| format!("snapshot unreadable: {e}"))?;
            let mut snap = None;
            let mut last = None;
            for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
                match Snapshot::from_portable_bytes(&bytes, network) {
                    Ok(s) => {
                        snap = Some(s);
                        break;
                    }
                    Err(q21_core::state::StateError::WrongNetwork) => continue,
                    Err(e) => last = Some(e),
                }
            }
            let snap = snap.ok_or_else(|| {
                format!(
                    "invalid snapshot: {}",
                    last.map(|e| e.to_string()).unwrap_or_default()
                )
            })?;
            let network = snap.network;

            let hs = HeaderStore::new(d.join("headers.q21hdr"));
            let headers = hs
                .load(network)
                .map_err(|e| format!("headers unreadable: {e}"))?;

            // Validation, before writing anything: trust anchors and
            // authentication of the tip by the headers.
            Chain::adopt_snapshot(network, snap.clone(), &headers, tip, commitment)
                .map_err(|e| format!("adoption refused: {e}"))?;

            // The block bodies too, exactly as on the network path: a snapshot
            // folder supplied by a third party could carry the real headers,
            // the real snapshot — and arbitrary bodies, copied as is. The node
            // served them, and ran into them at the first reorg near the tip.
            // We only copy what matches, block by block, the header at the
            // same height.
            let (bodies, issue) = BlockStore::new(d.join("bodies.dat"))
                .load_all()
                .map_err(|e| format!("block bodies unreadable: {e}"))?;
            if let Some(s) = issue {
                return Err(format!(
                    "adoption refused: the body file is incomplete or damaged ({s})"
                ));
            }
            q21_core::fast_sync::check_bodies(network, &headers, &bodies)
                .map_err(|e| format!("adoption refused: {e}"))?;

            // Set up the adopted folder.
            std::fs::create_dir_all(datadir).map_err(|e| e.to_string())?;
            std::fs::copy(d.join("bodies.dat"), blocks_path(datadir))
                .map_err(|e| format!("copying the block bodies: {e}"))?;
            std::fs::copy(d.join("headers.q21hdr"), headers_path(datadir))
                .map_err(|e| format!("copying the headers: {e}"))?;
            let key = q21_core::state::datadir_key(datadir).map_err(|e| e.to_string())?;
            StateStore::new_sealed(state_path(datadir), key)
                .save(&snap)
                .map_err(|e| format!("writing the state: {e}"))?;

            // The trace of what was just taken on trust — as for adoption
            // from a peer. Both paths must leave it: an adopted folder without
            // a record would be a folder that forgot it had trusted.
            write_adoption_record(
                datadir,
                &AdoptionRecord {
                    height: snap.height,
                    tip,
                    commitment,
                    legacy_commitment: false,
                    revalidated: false,
                },
            )?;

            println!(
                "Snapshot adopted in {} at height {}.",
                datadir.display(),
                snap.height
            );
            println!("  Tip         {}", snap.tip);
            println!("  Commitment  {}", snap.commitment());
            println!();
            println!(
                "Start the node: it joins the network and catches up with the tip from there."
            );
            println!(
                "  q21 --datadir {} node --network {}",
                datadir.display(),
                network_name(network)
            );
            Ok(())
        }
        Some("export") => {
            let file = args
                .get(1)
                .ok_or("usage: q21 snapshot export <file> [--network <name>]")?;
            // The node must be stopped: the directory lock, taken at startup,
            // already enforces it. We rebuild the state at the tip from the
            // blocks, then take the snapshot a little behind (replayable).
            let e = load_for_snapshot(datadir, &args[2..])?;
            let s = e
                .chain
                .snapshot()
                .ok_or("the chain is too short for a snapshot: several blocks are needed")?;
            std::fs::write(file, s.to_portable_bytes())
                .map_err(|err| format!("cannot write: {err}"))?;

            println!("Portable snapshot written: {file}");
            println!("  Network     {:?}", s.network);
            println!("  Height      {}", s.height);
            println!("  Tip         {}", s.tip);
            println!("  Outputs     {}", s.utxo.len());
            println!("  Commitment  {}", s.commitment());
            println!();
            println!("To adopt it on another machine, the person compares this");
            println!("commitment with the one displayed by a trusted source (the explorer),");
            println!("then checks it:");
            println!(
                "  q21 snapshot verify <file> --commitment {}",
                s.commitment()
            );
            Ok(())
        }
        Some("verify") => {
            let file = args
                .get(1)
                .ok_or("usage: q21 snapshot verify <file> [--commitment <hex>]")?;
            let mut expected: Option<String> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--commitment" => {
                        expected = Some(
                            args.get(i + 1)
                                .ok_or("--commitment requires a value")?
                                .clone(),
                        );
                        i += 2;
                    }
                    other => return Err(format!("unknown option: {other}")),
                }
            }

            let bytes = std::fs::read(file).map_err(|err| format!("cannot read: {err}"))?;

            // The file carries its own network: we find it by trying all
            // three. Only one is valid, the others fail with "wrong network".
            let mut found = None;
            let mut last = None;
            for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
                match Snapshot::from_portable_bytes(&bytes, network) {
                    Ok(s) => {
                        found = Some(s);
                        break;
                    }
                    Err(q21_core::state::StateError::WrongNetwork) => continue,
                    Err(e) => last = Some(e),
                }
            }
            let s = found.ok_or_else(|| {
                format!(
                    "invalid snapshot: {}",
                    last.map(|e| e.to_string())
                        .unwrap_or_else(|| "unknown network".into())
                )
            })?;

            println!("Portable snapshot consistent.");
            println!("  Network     {:?}", s.network);
            println!("  Height      {}", s.height);
            println!("  Tip         {}", s.tip);
            println!("  Outputs     {}", s.utxo.len());
            println!("  Total       {} Q21", Amount::from_units(s.issued));
            println!("  Commitment  {}", s.commitment());
            println!();

            match expected {
                Some(exp) => {
                    let exp = exp.trim().to_lowercase();
                    if exp == s.commitment().to_hex() {
                        println!("  ✓ The commitment matches the trusted value provided.");
                        println!("    This snapshot does represent the expected state: it can");
                        println!("    be adopted.");
                        Ok(())
                    } else {
                        Err(format!(
                            "The commitment does NOT match the value provided — do not adopt.\n  \
                             expected: {exp}\n  got:      {}",
                            s.commitment().to_hex()
                        ))
                    }
                }
                None => {
                    println!("  No trusted commitment provided: the file is consistent");
                    println!("  with itself, but nothing proves yet that it describes the real");
                    println!(
                        "  chain. Before adopting it, compare the commitment above with the one"
                    );
                    println!(
                        "  displayed by a trusted source (your explorer), then run again with"
                    );
                    println!("  --commitment <hex>.");
                    Ok(())
                }
            }
        }
        _ => Err("usage: q21 snapshot <export|verify|export-sync|adopt> ...".to_string()),
    }
}

fn cmd_emission(year: Option<&str>) -> Result<(), String> {
    if let Some(a) = year {
        let a: u64 = a.parse().map_err(|_| "invalid year")?;
        let h = BLOCKS_PER_YEAR * a;
        println!("Year {a} (block {h})");
        println!("  Reward          {} Q21", emission::block_subsidy(h));
        println!("  Cumulative      {} Q21", emission::cumulative_emission(h));
        println!("  Total supply    {} Q21", emission::total_supply_at(h));
        println!(
            "  Share of cap    {:.4} %",
            100.0 * emission::total_supply_at(h).units() as f64 / MAX_SUPPLY as f64
        );
        return Ok(());
    }

    println!("Emission curve — cap {} Q21", MAX_SUPPLY_COINS);
    println!();
    println!("  Year  Reward/block           Cumulative      % of cap");
    for a in [1u64, 2, 4, 8, 12, 16, 20, 30, 45, 60, 100] {
        let h = BLOCKS_PER_YEAR * a;
        let cumulative = emission::total_supply_at(h);
        println!(
            "  {a:>3}    {:>14}    {:>15}    {:>6.2} %",
            emission::block_subsidy(h).to_string(),
            cumulative.to_string(),
            100.0 * cumulative.units() as f64 / MAX_SUPPLY as f64
        );
    }
    println!();
    println!("The curve is asymptotic: it approaches the cap without reaching it.");
    Ok(())
}

/// Displays a cumulative work in readable form.
///
/// Work is counted in expected attempts. As long as it fits in 64 bits it is
/// written out in full; beyond that, its order of magnitude in bits is given,
/// because lining up seventy digits helps nobody.
fn format_work(w: q21_core::uint::U256) -> String {
    let b = w.to_be_bytes();
    if b[..24] == [0u8; 24] {
        let mut low = [0u8; 8];
        low.copy_from_slice(&b[24..]);
        format!("{} expected attempts", u64::from_be_bytes(low))
    } else {
        format!("~2^{} expected attempts", w.bits())
    }
}

fn short_hex(b: &[u8]) -> String {
    let h: String = b.iter().take(8).map(|x| format!("{x:02x}")).collect();
    format!("{h}...")
}

fn cmd_pow(datadir: &Path, requested_network: Option<&str>, no_table: bool) -> Result<(), String> {
    use q21_core::consensus as k;
    use q21_core::memhard::{self, PartialTable, PowTable, TableParams};
    use std::io::Write;

    let network = match requested_network {
        Some("regtest") => Network::Regtest,
        Some("testnet") => Network::Testnet,
        Some("mainnet") => Network::Mainnet,
        Some(other) => return Err(format!("unknown network: {other}")),
        None => read_wallet(datadir)
            .map(|w| w.network())
            .unwrap_or(Network::Regtest),
    };
    let params = TableParams::for_network(network);
    let n = memhard::table_size(params, 0);
    let c = memhard::cache_size(params, 0);
    let mib = |elements: u64| elements as f64 * 32.0 / 1024.0 / 1024.0;

    println!("Two-level memory-hard proof of work — network {network:?}");
    println!();
    println!(
        "  Cache  (level 1)    {c} elements   {:>9.1} MiB   held by every node",
        mib(u64::from(c))
    );
    println!(
        "  Table  (level 2)    {n} elements   {:>9.1} MiB   held by miners",
        mib(u64::from(n))
    );
    println!("  Accesses/attempt    {}", k::POW_K);
    println!(
        "  Cache acc./element  {}   (theoretical penalty for refusing the table)",
        k::POW_J
    );
    println!(
        "  Growth              +{} % every {} blocks",
        k::POW_TABLE_GROWTH_PCT,
        k::POW_EPOCH_BLOCKS
    );
    println!();

    let header = q21_core::block::BlockHeader {
        version: 1,
        prev_block: q21_core::hash::Hash256::ZERO,
        merkle_root: q21_core::hash::Hash256([3u8; 32]),
        uncles_root: q21_core::hash::Hash256::ZERO,
        miner: q21_core::hash::Hash256([4u8; 32]),
        time: 1_755_000_000,
        bits: k::INITIAL_BITS,
        height: 1,
        nonce: 0,
    };

    print!("  Building the cache... ");
    let _ = std::io::stdout().flush();
    let t0 = std::time::Instant::now();
    let cache = memhard::cache_for(params, 0);
    println!("{:.2} s", t0.elapsed().as_secs_f64());

    if no_table {
        // Node mode: we only measure what verification costs, without ever
        // materializing the miner's 2 GiB.
        let without_table = fast_rate(std::time::Duration::from_secs(3), |i| {
            let mut h = header;
            h.nonce = i;
            std::hint::black_box(memhard::hash_verify_with_cache(&h, params, &cache));
        });
        println!();
        println!(
            "  Verification    {without_table:>12.0} blocks/s   ({:.0} us per block)",
            1e6 / without_table.max(1e-9)
        );
        println!(
            "  Catch-up        {:>12.0} s for 10 years of chain ({} blocks)",
            (10.0 * 365.25 * 86400.0 / k::TARGET_BLOCK_SECS as f64) / without_table.max(1e-9),
            (10.0 * 365.25 * 86400.0 / k::TARGET_BLOCK_SECS as f64) as u64
        );
        return Ok(());
    }

    print!("  Building the table... ");
    let _ = std::io::stdout().flush();
    let t0 = std::time::Instant::now();
    let table = PowTable::build_with_cache(&cache, params, 0);
    println!("{:.1} s", t0.elapsed().as_secs_f64());

    /// Measurement with a constant time budget.
    ///
    /// A fixed number of attempts is unusable here: between the fastest and
    /// the slowest strategy there are two orders of magnitude, and one of the
    /// two would end either in microseconds or in hours.
    fn rate(budget: std::time::Duration, attempt: impl FnMut(u64)) -> f64 {
        fast_rate(budget, attempt)
    }

    fn fast_rate(budget: std::time::Duration, mut attempt: impl FnMut(u64)) -> f64 {
        let t0 = std::time::Instant::now();
        let mut n = 0u64;
        loop {
            for _ in 0..16 {
                attempt(n);
                n += 1;
            }
            if t0.elapsed() >= budget {
                break;
            }
        }
        n as f64 / t0.elapsed().as_secs_f64()
    }

    let budget = std::time::Duration::from_secs(3);

    let with_table = rate(budget, |i| {
        let mut h = header;
        h.nonce = i;
        std::hint::black_box(memhard::hash_mining(&h, &table));
    });
    let without_table = rate(budget, |i| {
        let mut h = header;
        h.nonce = i;
        std::hint::black_box(memhard::hash_verify_with_cache(&h, params, &cache));
    });

    println!();
    println!("  With table      {with_table:>12.0} attempts/s");
    println!("  Without table   {without_table:>12.0} attempts/s");
    println!(
        "  Table advantage {:>12.1} x",
        with_table / without_table.max(1e-9)
    );

    // -----------------------------------------------------------------------
    // Time-memory tradeoff curve
    // -----------------------------------------------------------------------
    //
    // The ratio above compares two extremes that no circuit designer picks.
    // The real question is: what does an attempt cost when only a fraction of
    // the table is held? We reuse the table already built and simply ignore
    // its end — which is exactly what a miner who bought less memory would do.
    println!();
    println!("  Time-memory tradeoff");
    println!("  fraction    memory         attempts/s     relative cost");
    println!("  --------------------------------------------------------");

    let mut partial = PartialTable::from_table(table, cache.clone());
    let fractions: &[(u32, u32)] = &[(1, 1), (1, 2), (1, 4), (1, 8), (1, 16), (1, 64), (0, 1)];
    let mut reference = 0.0f64;

    for &(num, den) in fractions {
        partial.restrict(num, den);
        let d = rate(budget, |i| {
            let mut h = header;
            h.nonce = i;
            std::hint::black_box(memhard::hash_mining_partial(&h, &partial));
        });
        if num == 1 && den == 1 {
            reference = d;
        }
        println!(
            "  {:<10} {:>8.0} MiB  {:>12.0}   {:>8.1} x",
            format!("{num}/{den}"),
            partial.memory_bytes() as f64 / 1024.0 / 1024.0,
            d,
            reference / d.max(1e-9)
        );
    }

    println!();
    println!("  Reading");
    println!();
    println!("  The relative cost of the last line is the factor that a circuit");
    println!("  without a table must make up for. It is not made up only with");
    println!(
        "  computation: refusing the table multiplies by {} the number of memory",
        k::POW_J
    );
    println!("  accesses, hence the bandwidth — which silicon does not manufacture.");
    println!();
    println!("  The details of the measurement and its verdict are in PHASE6.md.");
    Ok(())
}

/// Identifier of the genesis block, for checking before joining.
///
/// # Why this command exists
///
/// Joining a network means deciding which chain you believe in. This decision
/// is made once, and it comes down to a single number: the identifier of the
/// genesis block. Two nodes that do not share it will never talk to each
/// other usefully — and it is better to find that out in three seconds than
/// after an hour of syncing that goes nowhere.
///
/// The Q21 genesis is distributed by nobody: it is **deterministic**. Everyone
/// computes it at home from the code, and compares. There is therefore nothing
/// to download, and nobody to believe — that is exactly the property you want
/// for the root of a chain.
fn cmd_genesis(network: Option<&str>) -> Result<(), String> {
    let networks: Vec<Network> = match network {
        Some(n) => vec![network_from_name(n)?],
        None => vec![Network::Regtest, Network::Testnet],
    };
    println!("Genesis");
    println!();
    for r in networks {
        let g = genesis_block(r);
        println!("  {}", network_name(r));
        println!("    identifier    {}", g.header.block_id());
        println!("    timestamp     {}", g.header.time);
        println!("    difficulty    {:#010x}", g.header.bits);
        println!(
            "    message       {}",
            String::from_utf8_lossy(&g.transactions[0].inputs[0].witness.signature)
        );
        println!("    P2P port      {}", q21_core::bootstrap::default_port(r));
        let bootstrap = q21_core::bootstrap::builtin_bootstrap(r);
        if bootstrap.is_empty() {
            println!("    bootstrap     none (network not open)");
        } else {
            println!("    bootstrap     {}", bootstrap.join(", "));
        }
        println!();
    }
    println!("  This value comes from no server: it is recomputed from the code.");
    println!("  If yours differs from someone else's, you are not on the same");
    println!("  chain — and no amount of syncing will change that.");
    Ok(())
}

fn cmd_security() -> Result<(), String> {
    use q21_core::consensus as k;
    println!("51 % attack — what Q21 protects, and what it does not");
    println!();
    println!("IMPOSSIBLE TO PREVENT, AND THAT IS A THEOREM");
    println!();
    println!("  Consensus defines the valid chain as the one that carries the most");
    println!("  work. A majority adversary produces more of it than all the others");
    println!("  combined, by definition. Refusing its chain would require knowing");
    println!("  that it is them: an identity, hence an authority, hence the end of");
    println!("  being permissionless.");
    println!();
    println!("  Anyone who sells immunity to 51 % is selling a disguised authority.");
    println!();
    println!("WHAT A 51 % ATTACKER CAN DO");
    println!();
    println!("  - reorganize recent blocks, hence cancel their own payments");
    println!("  - refuse to include certain transactions (censorship)");
    println!();
    println!("WHAT THEY CANNOT DO, EVEN WITH 99 % OF THE POWER");
    println!();
    println!("  - steal a coin whose key they do not have");
    println!("      protected by the signature, not by consensus");
    println!("  - create a single unit beyond the subsidy");
    println!("      every node checks the coinbase, alone, without trusting anyone");
    println!("  - raise the cap of 21,000,001");
    println!("  - change a rule: their blocks are rejected and they mine a chain");
    println!("      that nobody looks at");
    println!();
    println!("WHAT Q21 ADDS TO LIMIT ITS REACH");
    println!();
    println!("  - choice by cumulative work, never by chain length");
    println!(
        "  - rolling finality: no reorg beyond {} blocks ({} h)",
        k::MAX_REORG_DEPTH,
        k::MAX_REORG_DEPTH * k::TARGET_BLOCK_SECS / 3600
    );
    println!(
        "  - beyond {} blocks of depth, a fork must show +{} %",
        k::REORG_PENALTY_FROM_DEPTH,
        k::REORG_PENALTY_PCT_PER_BLOCK
    );
    println!("      work per additional block");
    println!("  - memory-hard proof of work: no hashpower rental market");
    println!("      exists for a new algorithm, and that is the real");
    println!("      protection of a small chain in its early days");
    println!("  - uncle rewards: the large miner loses their super-linear");
    println!("      advantage in propagation races");
    println!();
    println!("THE COST OF ROLLING FINALITY, STATED FRANKLY");
    println!();
    println!("  It does not remove the attack, it changes its nature. A network");
    println!(
        "  partition lasting more than {} blocks produces two chains that will",
        k::MAX_REORG_DEPTH
    );
    println!("  never reconcile on their own. A risk of silent rewriting is traded");
    println!("  for a risk of visible split. A split can be diagnosed and repaired;");
    println!("  a deep rewrite robs people without a sound.");
    Ok(())
}

/// Sets up an adopted state in a blank folder: validates the snapshot
/// (commitment, tip, authentication by the headers), then writes the header
/// store, the block bodies, and the sealed snapshot. Returns (height,
/// commitment).
///
/// A single implementation, shared by adoption from files
/// (`snapshot adopt`) and by peer-to-peer adoption (`node
/// --assume-commitment`).
fn stage_adopted_snapshot(
    datadir: &Path,
    network: Network,
    snapshot: &[u8],
    headers: &[q21_core::block::BlockHeader],
    bodies: &[q21_core::block::Block],
    tip: Hash256,
    commitment: Hash256,
) -> Result<(u64, Hash256), String> {
    use q21_core::state::{Snapshot, StateStore};
    use q21_core::store::{BlockStore, HeaderStore};

    let snap = Snapshot::from_portable_bytes(snapshot, network)
        .map_err(|e| format!("invalid snapshot: {e}"))?;
    Chain::adopt_snapshot(network, snap.clone(), headers, tip, commitment)
        .map_err(|e| format!("adoption refused: {e}"))?;
    // The block bodies too, before the slightest byte on disk: a snapshot
    // server could deliver the real headers and arbitrary bodies.
    q21_core::fast_sync::check_bodies(network, headers, bodies)
        .map_err(|e| format!("adoption refused: {e}"))?;

    if blocks_path(datadir).exists()
        || state_path(datadir).exists()
        || headers_path(datadir).exists()
    {
        return Err(format!(
            "the folder {} already contains a chain: adoption is done only \
             into an empty folder",
            datadir.display()
        ));
    }
    std::fs::create_dir_all(datadir).map_err(|e| e.to_string())?;
    HeaderStore::new(headers_path(datadir))
        .append(headers)
        .map_err(|e| e.to_string())?;
    let bs = BlockStore::new(blocks_path(datadir));
    for b in bodies {
        bs.append(b).map_err(|e| e.to_string())?;
    }
    let key = q21_core::state::datadir_key(datadir).map_err(|e| e.to_string())?;
    StateStore::new_sealed(state_path(datadir), key)
        .save(&snap)
        .map_err(|e| e.to_string())?;

    // The trace of what was just taken on trust. Without it, the trust
    // granted today would be invisible tomorrow.
    write_adoption_record(
        datadir,
        &AdoptionRecord {
            height: snap.height,
            tip,
            commitment,
            legacy_commitment: false,
            revalidated: false,
        },
    )?;
    Ok((snap.height, snap.commitment()))
}

/// Revalidates an adopted folder: replays the whole history from genesis and
/// compares the result with the commitment that was taken on trust.
///
/// # What this command brings
///
/// Adopting a snapshot is a loan of trust. Rechecking the work and the
/// compiled-in anchors make it very hard to betray, but they do not replace
/// the only proof that really counts: doing the computation yourself. That is
/// what this command does — and it is what makes fast sync honest. It is no
/// longer a permanent act of faith, only a shortcut that ends up being
/// verified.
///
/// A disagreement is never silent: the record is not marked, and the command
/// fails loudly. A node whose adopted state cannot be reproduced is a node
/// that was deceived.
fn cmd_revalidate(datadir: &Path, args: &[String]) -> Result<(), String> {
    use q21_core::store::BlockArchive;

    let Some(record) = read_adoption_record(datadir) else {
        println!(
            "This folder does not come from an adoption: it has validated its whole\n\
             history itself. Nothing to revalidate."
        );
        return Ok(());
    };
    if record.revalidated {
        println!(
            "Already revalidated: the history up to height {} was replayed and\n\
             does reproduce the adopted commitment.",
            record.height
        );
        return Ok(());
    }

    // The block bodies: those of the folder, or the ones we are pointed to. An
    // adopted node precisely lacks the history from before the snapshot; it
    // has to be given to it.
    let bodies = match args.iter().position(|a| a == "--blocks") {
        Some(i) => PathBuf::from(
            args.get(i + 1)
                .ok_or("usage: q21 revalidate [--blocks <path/blocks.dat>]")?,
        ),
        None => blocks_path(datadir),
    };
    let network = match args.iter().position(|a| a == "--network") {
        Some(i) => network_from_name(
            args.get(i + 1)
                .ok_or("usage: --network <mainnet|testnet|regtest>")?,
        )?,
        // Without an indication, we ask the folder itself — which assumes a
        // wallet. A wallet-less node must name its network.
        None => load_state_with(datadir, None)
            .map(|e| e.chain.network)
            .map_err(|_| {
                "cannot deduce the network of this folder: specify \
                 --network <mainnet|testnet|regtest>"
                    .to_string()
            })?,
    };

    println!("Revalidation from genesis, with {}", bodies.display());
    let (archive, headers, _) =
        BlockArchive::open(&bodies, network).map_err(|e| format!("block file: {e:?}"))?;
    let archive = std::sync::Arc::new(archive);

    let order =
        Chain::block_tree(&headers).map_err(|e| format!("block index unreadable: {e:?}"))?;
    if (order.active.len() as u64) <= record.height {
        return Err(format!(
            "these block bodies only go up to height {}: at least {} are needed to\n\
             revalidate. Provide the block file of a full node with\n\
             --blocks.",
            order.active.len().saturating_sub(1),
            record.height
        ));
    }

    let genesis = archive
        .read(&order.active[0])
        .ok_or("the genesis block is missing from the file")?;
    let mut c = Chain::new(network, genesis);
    c.set_body_source(archive.clone());
    for id in order.active.iter().skip(1).take(record.height as usize) {
        let b = archive
            .read(id)
            .ok_or_else(|| format!("missing body for {}", id.to_hex()))?;
        let t = b.header.time;
        c.connect(&b, t + 1)
            .map_err(|e| format!("block {} refused at revalidation: {e:?}", b.header.height))?;
    }

    // The verdict: the recomputed state must reproduce, to the bit, the one
    // that was adopted on trust.
    let tip = c.tip_id();
    let commitment = if record.legacy_commitment {
        q21_core::legacy::legacy_state_commitment(&c)
    } else {
        c.state_commitment()
    };
    if tip != record.tip || commitment != record.commitment {
        return Err(format!(
            "REVALIDATION FAILED — the adopted state cannot be reproduced.\n\
             \n  height       {}\n  tip    expected {}\n         got      {}\n\
             \n  commitment expected {}\n             got      {}\n\
             \nThis node was deceived during its adoption: its monetary state does\n\
             not match the real history. Do not use it. Start again\n\
             from an empty folder, with a trusted snapshot and commitment.",
            record.height,
            record.tip.to_hex(),
            tip.to_hex(),
            record.commitment.to_hex(),
            commitment.to_hex()
        ));
    }

    write_adoption_record(
        datadir,
        &AdoptionRecord {
            // Verified: from now on the record holds the commitment under
            // the current labels.
            commitment: c.state_commitment(),
            legacy_commitment: false,
            revalidated: true,
            ..record
        },
    )?;
    println!(
        "Revalidation succeeded: the history replayed from genesis reproduces\n\
         exactly the state adopted at height {}.\n\
         This node no longer trusts anyone for its state.",
        c.height()
    );
    Ok(())
}

/// Downloads a snapshot from one of the given peers, the first one that
/// answers and whose commitment matches, then adopts it into the folder.
fn adopt_from_peers(
    datadir: &Path,
    network: Network,
    targets: &[String],
    tip: Hash256,
    commitment: Hash256,
) -> Result<(), String> {
    let magic = q21_core::net::magic_for(network);
    let mut last = String::from("no peer contacted");
    for target in targets {
        let addresses = match q21_core::bootstrap::resolve(target, network) {
            Ok(a) => a,
            Err(e) => {
                last = e;
                continue;
            }
        };
        for addr in addresses {
            println!("  downloading the snapshot from {addr}...");
            match q21_core::fast_sync::download_sync_snapshot(
                addr,
                magic,
                0,
                commitment,
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(600),
            ) {
                Ok(fetched) => {
                    let (h, emp) = stage_adopted_snapshot(
                        datadir,
                        network,
                        &fetched.snapshot,
                        &fetched.headers,
                        &fetched.bodies,
                        tip,
                        commitment,
                    )?;
                    println!("  snapshot adopted at height {h}, commitment {emp}.");
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("  {addr}: {e}");
                    last = e;
                }
            }
        }
    }
    Err(format!(
        "no peer provided an adoptable snapshot. Last reason: {last}"
    ))
}

/// Minimum length of a token that guards spending methods.
///
/// Sixteen characters: beyond what can be guessed online, even without a
/// limit on attempts. The wallet launchers draw sixty-four.
const MIN_WALLET_TOKEN_LEN: usize = 16;

/// Can the RPC start with this token?
///
/// # The defect this closes
///
/// `--rpc-wallet` without `--rpc-token` started: the methods that move funds
/// answered without authentication on the loopback. The server's guards —
/// `Host` header, origin, `Content-Type` — stop a hostile web page, not
/// another program or another account on the same machine: a shared server,
/// a container, unprivileged malware. Any of them could call
/// `sendtoaddress`. The desktop wallet already drew a token; the command
/// line, on the other hand, left the option of not setting one.
///
/// An empty token is refused everywhere: it guards nothing and suggests the
/// opposite. A token that is too short is refused when it guards funds.
fn check_rpc_token(rpc_wallet: bool, token: Option<&str>) -> Result<(), String> {
    if let Some(j) = token {
        if j.trim().is_empty() {
            return Err("refused: the RPC token is empty.".into());
        }
    }
    if !rpc_wallet {
        return Ok(());
    }
    match token {
        None => Err(
            "refused: --rpc-wallet without a token. The wallet methods move funds,\n\
             \x20      and any program on this machine could call them.\n\
             \x20      Add --rpc-token-file <path> (a file readable only by you),\n\
             \x20      or use `q21 wallet`, which draws a token at every launch."
                .into(),
        ),
        Some(j) if j.trim().chars().count() < MIN_WALLET_TOKEN_LEN => Err(format!(
            "refused: with --rpc-wallet, the token must be at least \
             {MIN_WALLET_TOKEN_LEN} characters long."
        )),
        Some(_) => Ok(()),
    }
}

/// Reads an RPC token from a file: first line, whitespace removed.
///
/// On Unix, a file readable by other accounts is reported: the token is no
/// better guarded there than on the command line.
fn read_rpc_token(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("--rpc-token-file {}: {e}", path.display()))?;
    let token = text.lines().next().unwrap_or("").trim().to_string();
    if token.is_empty() {
        return Err(format!(
            "--rpc-token-file {}: the file is empty",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(path) {
            if m.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "warning: {} is readable by other accounts. chmod 600 {}",
                    path.display(),
                    path.display()
                );
            }
        }
    }
    Ok(token)
}

fn cmd_node(datadir: &Path, args: &[String]) -> Result<(), String> {
    use q21_core::net::Node;
    use std::sync::atomic::Ordering;

    let mut listen_on: Option<String> = None;
    let mut connect_to: Vec<String> = Vec::new();
    let mut mine = false;
    let mut duration = 0u64;
    let mut rpc: Option<String> = None;
    let mut rpc_token: Option<String> = None;
    // Domain name under which this node is published. See below: it is only
    // accepted on a wallet-less node.
    let mut rpc_public: Option<String> = None;
    let mut rpc_wallet = false;
    let mut threads: usize = 0;
    let mut target_peers: usize = 8;
    let mut quiet = false;
    let mut address_index = false;
    let mut prune = false;
    let mut forced_network: Option<Network> = None;
    let mut no_bootstrap = false;
    let mut upnp = false;
    let mut assume_commitment: Option<String> = None;
    let mut assume_tip: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--assume-commitment" if i + 1 < args.len() => {
                assume_commitment = Some(args[i + 1].clone());
                i += 2;
            }
            "--assume-tip" if i + 1 < args.len() => {
                assume_tip = Some(args[i + 1].clone());
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen_on = Some(args[i + 1].clone());
                i += 2;
            }
            "--connect" | "--bootstrap" if i + 1 < args.len() => {
                connect_to.push(args[i + 1].clone());
                i += 2;
            }
            // A public node does not want the built-in bootstrap list: it
            // **is** the bootstrap. Without this, two entry points of the same
            // network would spend their time calling each other.
            "--no-bootstrap" => {
                no_bootstrap = true;
                i += 1;
            }
            "--upnp" => {
                upnp = true;
                i += 1;
            }
            "--rpc" if i + 1 < args.len() => {
                rpc = Some(args[i + 1].clone());
                i += 2;
            }
            "--rpc-token" if i + 1 < args.len() => {
                rpc_token = Some(args[i + 1].clone());
                i += 2;
            }
            // The token read from a file. On the command line, it is readable
            // by any account on the machine in `/proc/<pid>/cmdline` — exactly
            // the ones it protects against.
            "--rpc-token-file" if i + 1 < args.len() => {
                rpc_token = Some(read_rpc_token(Path::new(&args[i + 1]))?);
                i += 2;
            }
            "--rpc-wallet" => {
                rpc_wallet = true;
                i += 1;
            }
            "--rpc-public" if i + 1 < args.len() => {
                rpc_public = Some(args[i + 1].clone());
                i += 2;
            }
            "--mine" => {
                mine = true;
                i += 1;
            }
            // The status report every two seconds is valuable when running a
            // node, and harmful in a wallet: it drowned the address to open
            // under dozens of identical lines, to the point that a user
            // believed nothing was happening.
            "--quiet" => {
                quiet = true;
                i += 1;
            }
            "--seconds" if i + 1 < args.len() => {
                duration = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--threads" if i + 1 < args.len() => {
                threads = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--peers" if i + 1 < args.len() => {
                target_peers = args[i + 1].parse().unwrap_or(8);
                i += 2;
            }
            // The address index is paid for in disk space and in writes at
            // every block. A node that validates the chain and keeps a wallet
            // has no need for it: it only searches its own addresses, and it
            // knows which ones. See `q21_core::index`.
            "--address-index" => {
                address_index = true;
                i += 1;
            }
            // Pruning keeps on disk what the node may still need to reread —
            // the reorg window and the history window — and summarizes the
            // rest in the snapshot. See `prune_if_useful`.
            "--prune" => {
                prune = true;
                i += 1;
            }
            // A bootstrap node has no wallet: it must therefore be told which
            // chain it is. With a wallet, the wallet carries the answer and
            // this option becomes a check.
            "--network" if i + 1 < args.len() => {
                forced_network = Some(network_from_name(&args[i + 1])?);
                i += 2;
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }

    check_rpc_token(rpc_wallet, rpc_token.as_deref())?;
    if rpc_wallet && std::env::args().any(|a| a == "--rpc-token") && cfg!(unix) {
        eprintln!(
            "warning: --rpc-token on the command line is readable by any\n\
             \x20              account on this machine (ps, /proc). With --rpc-wallet, prefer\n\
             \x20              --rpc-token-file <path>, a file readable only by you."
        );
    }

    // The shutdown handler is installed before anything else: a Ctrl-C
    // during loading must already be heard.
    if !q21_core::shutdown::install() {
        eprintln!(
            "warning: the system refused the shutdown handler.\n               A Ctrl-C will kill the process without writing the snapshot or the mempool."
        );
    }

    // --- Fast sync: adopt a peer's snapshot before loading.
    //
    // If the operator provides a trusted commitment and tip, and the folder
    // is blank, we download a snapshot from a peer and adopt it — after
    // checking that its commitment matches the given value. The loading that
    // follows then resumes from the adopted state, and ordinary sync catches
    // up with the tip. A folder that is already populated is never touched.
    if let (Some(ch), Some(th)) = (&assume_commitment, &assume_tip) {
        let network = forced_network.ok_or(
            "--assume-commitment requires --network: a new node has no \
             wallet to infer the chain from",
        )?;
        if blocks_path(datadir).exists() {
            eprintln!("  this folder already contains a chain: adoption is ignored.");
        } else {
            let commitment = Hash256::from_hex(ch.trim())
                .ok_or("--assume-commitment: 64 hexadecimal characters expected")?;
            let tip = Hash256::from_hex(th.trim())
                .ok_or("--assume-tip: 64 hexadecimal characters expected")?;
            let mut targets: Vec<String> = connect_to.clone();
            if targets.is_empty() && !no_bootstrap {
                targets = q21_core::bootstrap::builtin_bootstrap(network)
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
            }
            if targets.is_empty() {
                return Err(
                    "no peer to download the snapshot from: give --bootstrap <host>".into(),
                );
            }
            adopt_from_peers(datadir, network, &targets, tip, commitment)?;
        }
    }

    let mut state = load_state_with(datadir, forced_network)?;
    let wallet_less = state.wallet_less;

    // --- What a wallet-less node does not do.
    //
    // Mining on a shell would send the subsidy to a key derived from a seed
    // that is written nowhere: the coin would be created, valid, and lost at
    // the first restart. Better to refuse loudly than to produce money that
    // nobody will ever be able to spend.
    if wallet_less {
        if mine {
            return Err("--mine requires a wallet: without one, the subsidy \
                        would go to a key that will die with the process.\n                          Create one (q21 init testnet), or remove --mine."
                .into());
        }
        if rpc_wallet {
            return Err("--rpc-wallet requires a wallet.".into());
        }
        println!("  wallet-less: no wallet method served");
    }
    let network = state.chain.network;
    let start_height = state.chain.height();
    state.chain.set_mining_threads(threads);
    let effective_threads = state.chain.mining_threads();
    let node = std::sync::Arc::new(Node::new(network, state.chain));
    let wallet = std::sync::Arc::new(std::sync::Mutex::new(state.wallet));
    let archive = state.archive.clone();
    // The journal is plugged in before a single block can come in: every
    // accepted block — including those received from the network, and those
    // of side branches — is written to disk at the moment it is accepted.
    node.set_journal(archive.clone());

    // --- The address index, if requested.
    //
    // Invariant held here, and it is deliberately coarse: **the index matches
    // the top of the chain exactly, or else it is rebuilt from zero**.
    // Nothing in between.
    //
    // The reason lies in the table of output owners, which answers "who owned
    // the output that this input spends". It is reloaded from the node's UTXO
    // set, which only knows the outputs **still alive**. If the index lagged a
    // few blocks behind, the outputs created before that lag and spent during
    // it would have disappeared from the UTXO set: the corresponding spends
    // would be attributed to nobody, and an address's screen would show its
    // receipts without its sends.
    //
    // Keeping a table that survives the lag would require journaling the
    // consumed outputs too, hence more disk and a new way of being wrong.
    // Rebuilding costs the price of a scan — the one the wallet already pays
    // — and cannot lie.
    // A pruned node cannot serve as an explorer: the address index and the
    // search point to block bodies it no longer has. We refuse at startup,
    // rather than serve answers full of holes.
    if prune && (address_index || rpc_public.is_some()) {
        return Err(
            "--prune can be combined neither with --address-index nor with --rpc-public: \
                    an explorer must keep the whole history."
                .into(),
        );
    }
    let index = if address_index {
        let mut i = q21_core::index::Index::open(&index_path(datadir));
        let (height, top_id) = node.with_chain(|c| (c.height(), c.active_at(c.height())));
        let in_sync = !i.is_empty() && i.height() == height && i.block_id(height) == top_id;
        if in_sync {
            node.with_chain(|c| i.prime(&c.utxo));
            println!("  address index: {} block(s) resumed", i.indexed_blocks());
        } else {
            if !i.is_empty() {
                println!("  address index: out of sync, rebuilding");
            }
            i.clear();
            let start = std::time::Instant::now();
            node.with_chain(|c| {
                for h in 0..=c.height() {
                    if let Some(b) = c.block_at(h) {
                        if let Err(e) = i.index_block(&b) {
                            eprintln!("warning: {e}");
                            break;
                        }
                    }
                }
            });
            println!(
                "  address index: {} block(s), {} address(es), in {:.2} s",
                i.indexed_blocks(),
                i.known_addresses(),
                start.elapsed().as_secs_f64()
            );
        }
        Some(std::sync::Arc::new(std::sync::Mutex::new(i)))
    } else {
        None
    };

    // --- The mempool from the previous session.
    //
    // Each transaction goes through `accept` again, which revalidates it
    // against the chain as it is **now**. The chain may have moved on during
    // the shutdown: some are already confirmed, others have become
    // impossible. A mempool read back is never taken on trust.
    if let Ok(key) = q21_core::state::datadir_key(datadir) {
        let store = q21_core::state::MempoolStore::new(mempool_path(datadir), key);
        if store.exists() {
            match store.load() {
                Ok(pending) => {
                    let mut restored = 0usize;
                    let total = pending.len();
                    for tx in &pending {
                        let ok = node.with_chain_and_mempool(|c, m| {
                            m.accept(tx, &c.utxo, network, c.height()).is_ok()
                        });
                        if ok {
                            restored += 1;
                        }
                    }
                    if total > 0 {
                        println!("  mempool: {restored} transaction(s) restored out of {total}");
                    }
                }
                Err(e) => eprintln!("warning: mempool ignored ({e})"),
            }
        }
    }

    if !quiet {
        println!("Q21 node — network {network:?}, height {start_height}");
        // A node that started from a snapshot says so as long as it has not
        // verified things itself. Keeping quiet would let people believe it
        // validated a history it only trusted.
        warn_if_not_revalidated(datadir);
    }

    // State of the router port mapping, shared with the dedicated thread and
    // read by the RPC to display it honestly in the interface.
    let router_state: std::sync::Arc<std::sync::Mutex<String>> =
        std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let port_mapping: std::sync::Arc<std::sync::Mutex<Option<q21_core::nat::PortMapping>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));

    if let Some(a) = &listen_on {
        match node.listen(&q21_core::bootstrap::listen_address(a, network)) {
            Ok(local) => {
                println!("  listening on {local}");
                // Layer 2: ask the router to open this port, in a dedicated
                // thread that renews the lease and announces our address.
                // Reserved for the wallet (`--upnp`): the public bootstrap
                // node has a direct address and does not need it.
                if upnp {
                    let port = local.port();
                    let node_for_router = node.clone();
                    let state = router_state.clone();
                    let mapping = port_mapping.clone();
                    let _ = std::thread::Builder::new()
                        .name("upnp".to_string())
                        .spawn(move || port_mapping_loop(port, node_for_router, state, mapping));
                }
            }
            // A bind failure must not prevent the WALLET from starting:
            // listening is a bonus there, not a requirement. We fall back to
            // client mode, which works exactly as before this version. But
            // when the user explicitly asked for `--listen` (a bootstrap
            // node), the failure stays fatal: that is precisely what they
            // wanted.
            Err(e) if upnp => {
                println!(
                    "  cannot listen ({e}): this wallet starts in client mode. \
                     It connects out to the network, but is not reachable. Nothing is broken."
                );
                if let Ok(mut g) = router_state.lock() {
                    *g = format!("cannot listen ({e})");
                }
            }
            Err(e) => return Err(format!("cannot listen: {e}")),
        }
    }
    // --- Where we try to connect out to.
    //
    // Three sources, in this order: what the command line asks for, the
    // `bootstrap.txt` file of the folder, then the list built into the
    // binary. The first two win, because they come from the operator and the
    // third comes from me.
    let mut targets: Vec<String> = connect_to.clone();
    if !no_bootstrap {
        targets.extend(q21_core::bootstrap::bootstrap_from_datadir(datadir));
        // The file shipped with the program, flat next to the binary. It
        // comes after the data directory: what the user writes at home always
        // wins over what the release dropped there.
        targets.extend(q21_core::bootstrap::bootstrap_next_to_program());
        if let Some(old) = q21_core::bootstrap::legacy_bootstrap_next_to_program() {
            println!(
                "  bootstrap: reading the 0.3.x file {}. Rename it to {} next to the program.",
                old.display(),
                q21_core::bootstrap::FILE_NAME
            );
        }
        targets.extend(
            q21_core::bootstrap::builtin_bootstrap(network)
                .iter()
                .map(|s| s.to_string()),
        );
    }
    targets.sort();
    targets.dedup();
    if targets.is_empty() && listen_on.is_none() {
        println!(
            "  no bootstrap: this node will not look for anyone. Give it\n               --bootstrap <host>, or a bootstrap.txt file in {}\n               (the program also looks for one next to itself)",
            datadir.display()
        );
    }
    for a in &targets {
        match q21_core::bootstrap::resolve(a, network) {
            Ok(addresses) => {
                // A name can yield several addresses. We stop at the first one
                // that answers: the others will serve if this one goes down,
                // and the address book will have kept them.
                let mut opened = false;
                for sa in &addresses {
                    // --- The same machine written twice.
                    //
                    // The shipped file gives the bootstrap node under its name
                    // AND under its address, on purpose: a name can expire.
                    // Duplicates were removed by comparing the text, not the
                    // real address; both lines survived, and each node opened
                    // two connections to the same bootstrap node. Yet that one
                    // only gives four slots per address group, and a whole
                    // household goes out through the same one: two devices
                    // filled it, and the third stayed "waiting" forever. The
                    // reconnection loop already had this guard; startup did
                    // not.
                    if node.is_connected_to(*sa) {
                        println!("  {a}: already connected ({sa}), same machine");
                        opened = true;
                        break;
                    }
                    match node.connect(*sa) {
                        Ok(_) => {
                            println!("  connecting to {a} ({sa})");
                            opened = true;
                            break;
                        }
                        Err(e) => eprintln!("  failed to reach {a} ({sa}): {e}"),
                    }
                }
                if !opened && addresses.len() > 1 {
                    eprintln!("  {a}: none of the {} addresses answered", addresses.len());
                }
            }
            Err(e) => eprintln!("  unreadable bootstrap: {e}"),
        }
    }
    // Address book: what was learned during previous sessions.
    let address_book = AddrStore::new(peers_path(datadir));
    let learned: Vec<q21_core::wire::NetAddr> = address_book
        .load(network != Network::Mainnet, unix_now())
        .all()
        .iter()
        .map(|e| e.addr)
        .collect();
    if !learned.is_empty() {
        let n = node.seed_addresses(&learned);
        println!("  address book: {n} addresses reloaded");
    }
    // The mining switch. It starts from the value of the `--mine` flag, but
    // no longer stops there: the interface can turn it on and off without
    // restarting anything. The flag becomes a starting preference.
    let mining = std::sync::Arc::new(q21_core::mining::Mining::new(mine));
    // Current mining payee. `None` means "a new one is needed".
    let mut mining_payee: Option<(q21_core::hash::Hash256, SchemeId)> = None;
    // Height at which the last discovery attempt took place.
    let mut last_discovery: u64 = 0;
    if mine {
        println!("  mining enabled on {effective_threads} thread(s)");
    }

    // --- The RPC does not leave the machine unless you have said so twice.
    //
    // The `Host` header check already refuses any request that does not
    // present itself as local, and the token guards each method. But binding
    // the service to a public interface remains a decision that can be made
    // absent-mindedly — by copying the P2P listening address, for example —
    // and its consequences are not visible: the service answers, it simply
    // answers everyone.
    //
    // On a bootstrap server, P2P must be reachable and RPC must not. The two
    // options look too much alike to let the confusion pass silently.
    if let Some(address) = &rpc {
        let local = address.starts_with("127.")
            || address.starts_with("localhost:")
            || address.starts_with("[::1]");
        if !local {
            if rpc_token.is_none() {
                return Err(format!(
                    "refused: --rpc {address} leaves the loopback and no token \n                       is provided. Any machine that can reach you could query\n                       this node.\n\n                       Stay local:   --rpc 127.0.0.1:21080\n                       Or require a token: --rpc-token <secret>"
                ));
            }
            eprintln!(
                "WARNING: the RPC listens on {address}, off the loopback.\n\
                 \x20              The Host header check will refuse requests that do not\n\
                 \x20              present themselves as local, but the service is reachable.\n\
                 \x20              A bootstrap node has no reason to expose its RPC."
            );
        }
    }

    // --- Publishing an explorer is never publishing a wallet.
    //
    // `--rpc-public` makes the server accept a domain name in the `Host`
    // header, which disarms the anti-DNS-rebinding guard for that name. That
    // is exactly what is needed for an explorer behind a reverse proxy, and
    // exactly what must never be done when funds are served on the same port.
    // The refusal is here, before anything starts, and it is not negotiable.
    if let Some(name) = &rpc_public {
        if rpc_wallet || !wallet_less {
            return Err(format!(
                "refused: --rpc-public {name} publishes this node on the Internet, and this folder
                       carries a wallet. A public explorer is started from a
                       wallet-less folder:

                       q21 --datadir <wallet-less-folder> node --network testnet \\
                           --rpc 127.0.0.1:21080 --rpc-public {name}"
            ));
        }
        if rpc.is_none() {
            return Err("--rpc-public requires --rpc <address>".to_string());
        }
    }

    let _server = if let Some(address) = &rpc {
        // Any operation that modifies the wallet is written to disk
        // immediately. A spend recorded only in memory would disappear at the
        // next shutdown — and on a one-time scheme, the corresponding key
        // would be used again.
        let folder = datadir.to_path_buf();
        let ctx = q21_core::rpc::RpcContext {
            node: node.clone(),
            wallet: if rpc_wallet {
                Some(wallet.clone())
            } else {
                None
            },
            network,
            index: index.clone(),
            // The wallet-less node does not get the switch: it has nowhere to
            // pay a subsidy to, and refusing is more honest than a button
            // that would do nothing.
            mining: if wallet_less {
                None
            } else {
                Some(mining.clone())
            },
            on_change: if wallet_less {
                None
            } else {
                Some(std::sync::Arc::new(move |w: &Wallet| {
                    write_wallet(&folder, w).map_err(|e| {
                        eprintln!("ALERT: wallet not saved after a change: {e}");
                        e
                    })
                }))
            },
            // The scan budget only applies to a public service.
            scans: rpc_public.as_ref().map(|_| {
                std::sync::Arc::new(std::sync::Mutex::new(q21_core::rpc::ScanBucket::new()))
            }),
            // What the page needs to know to distinguish "I have nobody's
            // address" from "nobody let me in".
            configured_bootstrap: targets.len(),
            reachable: std::sync::atomic::AtomicBool::new(read_reachable(datadir)),
            // What governs THIS session: was listening requested at launch?
            // The wallet requests it when the setting was yes at startup; a
            // user can also request it by hand.
            reachable_session: listen_on.is_some(),
            router_status: Some(router_state.clone()),
            set_reachable: Some({
                let d = datadir.to_path_buf();
                std::sync::Arc::new(move |v: bool| write_reachable(&d, v))
            }),
        };
        // The explorer shell is served without a token: it carries no data,
        // and it is the one that asks the user for the token. Every RPC
        // method stays behind authentication.
        // The two static shells. They carry no data: it is the JavaScript that
        // queries the RPC, and the RPC requires the token.
        const PUBLICS: &[&str] = &["/", "/index.html", "/wallet", "/wallet.html"];
        let h = match &rpc_public {
            // Public explorer: no token — it is meant to be read by anyone —
            // but a declared name, and no wallet served, which the refusal
            // above has already guaranteed.
            Some(name) => q21_core::http::serve_public_web(address, name.clone(), move |req| {
                serve(&ctx, req, true)
            })
            .map_err(|e| e.to_string())?,
            // Started by `wallet` or `explorer`: the browser received a
            // launch token, not the session token. The server exchanges it
            // once, after which it is worth nothing.
            None => match (rpc_token.clone(), NODE_LAUNCH_TOKEN.get()) {
                (Some(token), Some(launch_token)) => q21_core::http::serve_with_launch_token(
                    address,
                    token,
                    launch_token.clone(),
                    PUBLICS,
                    move |req| serve(&ctx, req, false),
                )
                .map_err(|e| e.to_string())?,
                (token, _) => {
                    q21_core::http::serve_with_public(address, token, PUBLICS, move |req| {
                        serve(&ctx, req, false)
                    })
                    .map_err(|e| e.to_string())?
                }
            },
        };

        // In quiet mode, the launcher has already said everything: repeating
        // the address and the warnings would only lengthen what the user
        // must read to find the link.
        if !quiet {
            println!("  RPC and explorer on http://{}", h.addr);
            if rpc_wallet {
                println!("  WARNING: wallet methods enabled on this port.");
            } else {
                println!("  Wallet disabled (--rpc-wallet to enable it).");
            }
            if rpc_token.is_some() {
                // --- This message used to suggest the token in the address.
                //
                // `?token=...` stopped opening anything — an address ends up
                // in the browser history, in the logs of a reverse proxy and
                // in the `Referer` header — but this piece of advice survived
                // the fix, and thus invited people to do exactly what had
                // just been forbidden.
                println!("  Token required. The pages ask for it when opened.");
            }
        }
        Some(h)
    } else {
        None
    };

    if !quiet {
        println!("  Ctrl-C to stop");
        println!();
    }

    let start = std::time::Instant::now();
    let mut last_report = std::time::Instant::now();
    let mut last_height = node.height();
    // --- The sleep detector, on its own thread.
    //
    // It sleeps one second, looks at the wall clock, and starts again. If the
    // clock jumped by more than a minute between two wake-ups, the machine
    // slept — whatever the main loop did in the meantime. That is what
    // distinguishes a real sleep from a long loop iteration: building a
    // table, a batch of connections timing out, a block that is long to mine
    // no longer look like it. See the loop, below.
    let sleep_detected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let flag = sleep_detected.clone();
        std::thread::Builder::new()
            .name("sleep-watch".into())
            .spawn(move || {
                let mut previous = std::time::SystemTime::now();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let now = std::time::SystemTime::now();
                    if let Ok(gap) = now.duration_since(previous) {
                        if gap >= std::time::Duration::from_secs(60) {
                            flag.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    previous = now;
                }
            })
            .map_err(|e| format!("sleep-watch thread: {e}"))?;
    }
    let mut last_search = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .unwrap_or_else(std::time::Instant::now);
    // --- The snapshot is no longer written only at shutdown.
    //
    // It was only written after the loop, which assumes a clean shutdown. An
    // unplugging, a flat battery, a `kill -9`: none of these cases goes
    // through there. The node then restarted without a snapshot, and had to
    // rebuild its whole state from genesis — several minutes on an already
    // long chain, during which the user sees nothing.
    //
    // Five minutes is a compromise: rare enough for the cost to be invisible,
    // frequent enough for an outage never to cost more than five minutes of
    // replay. The snapshot is taken a little behind the tip, so writing often
    // does not erode the ability to reorg.
    const SNAPSHOT_PERIOD: std::time::Duration = std::time::Duration::from_secs(300);
    let mut last_snapshot = std::time::Instant::now();
    // The height of the last snapshot written: an idle node has no reason to
    // rewrite a hundred identical megabytes every five minutes, and a
    // Raspberry Pi SD card has a limited number of writes.
    // Deduplication key: height AND tip. Deduplicating on height alone left,
    // after a reorg that replaces the block at that height, a snapshot on
    // disk that was now off the chain, never rewritten — rejected at the next
    // restart (full replay). By also comparing the tip, a reorg at equal
    // height does trigger a new write.
    let mut snapshot_key: Option<(u64, q21_core::hash::Hash256)> = None;
    // Height of the tip at the last pruning: we do not rewrite the file every
    // five minutes for a few blocks.
    let mut last_pruned_height: u64 = 0;
    if prune {
        let p = q21_core::pruning::DEFAULT_POLICY;
        println!(
            "  pruning enabled: the disk keeps only the last {} block bodies \
             (about {} days), the rest is summarized in the snapshot",
            p.kept_bodies,
            p.kept_bodies * q21_core::consensus::TARGET_BLOCK_SECS / 86_400
        );
    }

    loop {
        if duration > 0 && start.elapsed().as_secs() >= duration {
            break;
        }
        if last_snapshot.elapsed() >= SNAPSHOT_PERIOD {
            // Taken under the lock, written outside: see `write_taken_snapshot`.
            let taken = node.with_chain(|c| c.snapshot());
            if let Some(i) = taken {
                // The key is recorded — and pruning attempted — only after a
                // **successful** write. A failure leaves `snapshot_key` as it
                // is: we will try again in five minutes, and nothing is
                // removed from the block file on the strength of a snapshot
                // that is not on disk.
                if snapshot_key != Some((i.height, i.tip))
                    && write_taken_snapshot(datadir, &i).is_ok()
                {
                    snapshot_key = Some((i.height, i.tip));
                    complete_store_if_pruned(datadir, &node, i.height);
                    if prune {
                        prune_if_useful(
                            datadir,
                            network,
                            &node,
                            archive.as_ref(),
                            &mut last_pruned_height,
                        );
                    }
                }
            }
            last_snapshot = std::time::Instant::now();
        }
        // Ctrl-C: we leave the loop rather than being killed on the spot.
        // Everything this node must write — mempool, snapshot, address book,
        // wallet — comes after this loop, and was never reached.
        if q21_core::shutdown::requested() {
            if !quiet {
                println!();
            }
            println!("  Shutdown requested. Writing...");
            break;
        }

        // Maintaining outbound connections.
        //
        // The address book only yields addresses from distinct network groups,
        // and distinct from those already connected: that is what prevents an
        // adversary holding a single range from taking all the slots. See
        // `addr`.
        // --- Did the machine go to sleep?
        //
        // During a sleep, all TCP links are dead — the router has forgotten its
        // table, the peer on the other side has given up. Waiting for the
        // silence timeout would make someone who just reopened their laptop
        // lose two more minutes. We therefore cut everything right away, and
        // ask the bootstrap addresses again on the next iteration. Being wrong
        // only costs a reconnection.
        //
        // Sleep used to be inferred from the duration of one iteration of this
        // loop. Yet an iteration can last a long time without the machine
        // having slept: eight connections to addresses that do not accept the
        // SYN, at ten seconds each, made eighty seconds — and the node then
        // cut itself off from **all** its peers, honest ones included, at
        // every iteration. A peer that slipped such addresses into the address
        // book isolated the node in a loop. The detector now lives on its own
        // thread and only looks at the wall clock.
        if sleep_detected.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let n = node.disconnect_all_peers();
            if n > 0 {
                println!("  waking up after sleep: {n} link(s) cut, starting over");
            }
            last_search = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(60))
                .unwrap_or_else(std::time::Instant::now);
        }

        if last_search.elapsed().as_secs() >= 15 {
            last_search = std::time::Instant::now();

            // --- First, free the slots held by dead peers.
            //
            // A TCP connection can outlive the machine on the other side: a
            // laptop whose lid is closed says nothing when it leaves. Without
            // this cleanup, the node believes it has a peer, therefore looks
            // for nobody, and stays stuck at the height it was at. It happened
            // on a real MacBook: height 442, nothing more while the other
            // machine kept mining.
            let cut = node.maintain_peers();
            if cut > 0 && !quiet {
                println!("  {cut} silent peer(s) disconnected");
            }

            let missing = target_peers.saturating_sub(node.peer_count_outbound());
            if missing > 0 {
                // --- Explicit bootstrap addresses first.
                //
                // They are not in the address book as long as no handshake
                // has succeeded — and it is precisely when nothing succeeds
                // that they are needed. What the user wrote on the command
                // line must be retried as long as peers are missing.
                for a in &targets {
                    if let Ok(addresses) = q21_core::bootstrap::resolve(a, network) {
                        for sa in addresses {
                            if node.is_connected_to(sa) {
                                continue;
                            }
                            if node.connect(sa).is_ok() {
                                if !quiet {
                                    println!("  reconnecting to {a} ({sa})");
                                }
                                break;
                            }
                        }
                    }
                }
                // --- Then the address book, for the remaining slots.
                let missing = target_peers.saturating_sub(node.peer_count_outbound());
                for a in node.addresses_to_try(missing) {
                    let sa = std::net::SocketAddr::from((a.ip, a.port));
                    match node.connect(sa) {
                        Ok(_) => node.note_connect_success(a.ip, a.port),
                        Err(_) => node.note_connect_failure(a.ip, a.port),
                    }
                }
            }
        }

        if mining.is_active() {
            // --- One address per block found, not per attempt.
            //
            // This line derived a new address **at every loop iteration**.
            // Measured on testnet: six seconds of mining had consumed 149
            // indices for 102 blocks. The wallet swelled for no reason, the
            // list of addresses became unreadable, and the address cache was
            // rewritten twenty times per second. On a one-time scheme —
            // Lamport, still accepted on regtest — it would have been worse
            // than waste.
            //
            // We therefore keep the payee as long as no block has come out.
            // One address per reward remains the right granularity: it avoids
            // publicly linking all of one's rewards together.
            //
            // The derivation stays outside the chain lock: holding two locks
            // at once is the shortest path to a deadlock.
            if mining_payee.is_none() {
                let mut w = wallet.lock().map_err(|_| "wallet locked")?;
                let a = w.new_address();
                mining_payee = Some((a.hash, a.scheme));
            }
            let (payee, scheme) = mining_payee.expect("derived just above");
            // The mempool transactions go into the block, in the topological
            // order imposed by the selection.
            let selection = node.with_mempool(|m| m.select_for_block(2_000_000));
            // The candidate is assembled under the lock; mining happens
            // outside. Mining under the lock froze the node for several
            // seconds per iteration — no block received, no peer served — and
            // building the table, at the epoch change, froze it for minutes.
            let (mut candidate, epoch, params, table_ready, threads) = node.with_chain(|c| {
                let t = unix_now().max(c.tip().time + 1);
                let b = c.mining_candidate(payee, scheme, &selection, t);
                let epoch = q21_core::memhard::epoch_of(b.header.height);
                (
                    b,
                    epoch,
                    c.pow_params(),
                    c.table_if_ready(epoch),
                    c.mining_threads(),
                )
            });
            let table = match table_ready {
                Some(t) => t,
                None => {
                    let mib = q21_core::memhard::table_size(params, epoch) as u64
                        * q21_core::consensus::POW_ELEMENT_SIZE as u64
                        / (1024 * 1024);
                    println!(
                        "  mining: building the table for epoch {epoch} ({}), \
                         the node stays in service meanwhile",
                        if mib == 0 {
                            "less than one MiB".to_string()
                        } else {
                            format!("{mib} MiB")
                        }
                    );
                    let t = std::sync::Arc::new(q21_core::memhard::PowTable::build(params, epoch));
                    node.with_chain(|c| c.adopt_table(t.clone()));
                    t
                }
            };
            // The rate shown on screen is a measurement: `attempt` is the
            // index of the winner, so `attempt + 1` attempts took place.
            let (block, attempts) = match q21_core::pow::mine_with_table_parallel(
                &mut candidate.header,
                &table,
                2_000_000,
                threads,
            ) {
                Ok(attempt) => (Some(candidate), attempt.saturating_add(1)),
                Err(done) => (None, done),
            };
            mining.count_attempts(attempts);
            if let Some(b) = block {
                // Same discipline as for a received block (`Node::integrer`):
                // connection, journal write and mempool cleanup under ONE
                // SINGLE holding of the lock. Previously, the connection took
                // the lock, released it, then it was taken again for the
                // mempool: a reorg pushed by a peer could slip in between and
                // make the mempool be cleaned against a block that had become
                // a side block. The network announcement stays outside the
                // lock.
                let ok = node.with_chain_and_mempool(|c, m| {
                    if c.connect(&b, unix_now()).is_ok() {
                        // The write goes through the journal, as for any
                        // accepted block: a single path to the disk.
                        q21_core::chain::Journal::record(archive.as_ref(), &b);
                        m.on_block_connected(&b);
                        true
                    } else {
                        false
                    }
                });
                if ok {
                    // What this block earns: the first output of the
                    // coinbase, which consensus requires to pay the miner —
                    // subsidy plus fees. It is the figure the mining screen
                    // shows next to each find.
                    let reward = b
                        .transactions
                        .first()
                        .and_then(|c| c.outputs.first())
                        .map(|o| o.value.units())
                        .unwrap_or(0);
                    mining.block_found(q21_core::mining::FoundBlock {
                        height: b.header.height,
                        block_id: b.header.block_id(),
                        reward,
                        timestamp: b.header.time,
                    });
                    // The reward is collected: the address has served, the
                    // next one will get another.
                    mining_payee = None;
                    // And the wallet is written right away: one block every
                    // two minutes, a sealing of a few tenths of a second.
                    // Without this, a hard shutdown moved `next_index` back on
                    // disk and the following rewards became invisible.
                    if !wallet_less {
                        if let Ok(w) = wallet.lock() {
                            if let Err(e) = write_wallet(datadir, &w) {
                                eprintln!("warning: wallet not written after the block: {e}");
                            }
                        }
                    }
                    node.announce_block(&b);
                }
            }
        } else {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        // --- Address discovery, retried as long as it makes sense.
        //
        // The load-time trigger only covers one case: the one where the chain
        // is already there. On a new machine, the order is reversed — you
        // restore, *then* you sync — and discovery would never take place.
        // The holder would see zero while their funds arrive before their
        // eyes.
        //
        // We therefore retry, but rarely: the height counter avoids deriving
        // two hundred ML-DSA keys again at every block received. The trigger
        // looks at what the wallet recognizes, not at `next_index`: see
        // `load_state_with` for the reason. As long as it sees none of its
        // funds on a chain that holds some, we search; as soon as it sees
        // them, we stop.
        //
        // The locks are taken in the RPC's order — wallet, then chain — never
        // the reverse: two opposite orders are a deadlock waiting to happen.
        if !wallet_less {
            let h = node.height();
            if h > last_discovery + 20 {
                last_discovery = h;
                let mut w = wallet.lock().map_err(|_| "wallet locked")?;
                let to_search = node.with_chain(|c| !c.utxo.is_empty() && !w.sees_funds(&c.utxo));
                if to_search {
                    // Discovery then one-time key scan, BEFORE the write: see
                    // `discover_in_loop`.
                    let found = node.with_chain(|c| discover_in_loop(&mut w, c));
                    if found > 0 {
                        println!(
                            "  restore: {found} output(s) found, {} address(es) derived again",
                            w.next_index()
                        );
                        let _ = write_wallet(datadir, &w);
                    }
                }
                // Reservations left by a shutdown between reservation and
                // broadcast: once the delay has passed, the coin becomes free
                // again. A node that never restarts must do it here.
                let change = node.with_chain(|c| {
                    if w.reserved_indices().is_empty() {
                        return false;
                    }
                    let (confirmed, freed) = w.recheck_reservations(c.height(), |h| c.block_at(h));
                    if freed > 0 {
                        println!(
                            "  {freed} reservation(s) released: no signature in the \
                             chain after {} blocks, the coin is spendable again.",
                            Wallet::RESERVATION_TIMEOUT
                        );
                    }
                    confirmed + freed > 0
                });
                if change {
                    let _ = write_wallet(datadir, &w);
                }
            }
        }

        // --- The index follows the chain.
        //
        // It is not plugged into the node itself: an index is a convenience,
        // and the block acceptance path is the most sensitive thing in this
        // program. We observe it from the outside, at the pace of the loop,
        // without being able to break anything in consensus.
        if let Some(index) = &index {
            if let Ok(mut i) = index.lock() {
                follow_index(&mut i, &node);
            }
        }

        if !quiet && last_report.elapsed().as_secs() >= 2 {
            let h = node.height();
            let s = &node.stats;
            println!(
                "height {h} (+{})  peers {} ({} groups, address book {})  mempool {}  \
                 blocks received {}  compacts {} of which {} without round trip  \
                 orphans {}  invalid {}",
                h.saturating_sub(last_height),
                node.peer_count(),
                node.peer_groups(),
                node.address_count(),
                node.mempool_len(),
                s.blocks_received.load(Ordering::Relaxed),
                s.compacts_received.load(Ordering::Relaxed),
                s.compacts_without_round_trip.load(Ordering::Relaxed),
                s.orphan_blocks.load(Ordering::Relaxed),
                s.invalid_blocks.load(Ordering::Relaxed),
            );
            last_height = h;
            last_report = std::time::Instant::now();
        }
    }

    node.shutdown();
    if !wallet_less {
        if let Ok(w) = wallet.lock() {
            let _ = write_wallet(datadir, &w);
        }
    }
    // The address book survives shutdown: without it, every restart would
    // start again from the bootstrap, which gives whoever controls that
    // bootstrap point a power they should not have.
    // The entries are written as they are: the failures and the date of the
    // last success are part of what this node has observed itself, and that
    // is precisely what makes it possible to tell a real peer from a merely
    // announced address. Rebuilding them from zero amounted to forgetting
    // everything.
    if let Err(e) = address_book.save_entries(&node.address_entries()) {
        eprintln!("warning: address book not written: {e}");
    }
    // --- The mempool survives shutdown.
    //
    // A sent transaction waits there for a miner to take it. It was written
    // nowhere: stopping the software before it was mined erased it, without a
    // word. A first user lived through it — send, stop to start mining,
    // transaction gone.
    //
    // On a populated network, a peer would have relayed and kept it. It was
    // therefore the isolated node — that of a desktop wallet — that paid for
    // this defect.
    if let Ok(key) = q21_core::state::datadir_key(datadir) {
        let pending = node.with_mempool(|m| m.ordered_transactions());
        let store = q21_core::state::MempoolStore::new(mempool_path(datadir), key);
        if pending.is_empty() {
            // An empty mempool deletes the file: leaving it would bring back
            // to life, at the next start, transactions already confirmed.
            let _ = store.remove();
        } else if let Err(e) = store.save(&pending) {
            eprintln!("warning: mempool not written: {e}");
        } else {
            println!("  {} pending transaction(s) kept", pending.len());
        }
    }
    // The snapshot is written at shutdown, not at every block: it is a
    // startup saving, not data whose loss would cost anything.
    let taken = node.with_chain(|c| c.snapshot());
    if let Some(i) = taken {
        if write_taken_snapshot(datadir, &i).is_ok() {
            complete_store_if_pruned(datadir, &node, i.height);
        }
    }
    println!();
    println!("Stopped. Final height: {}", node.height());
    // On Windows, the console handler waits for this signal before letting
    // the system kill the process.
    q21_core::shutdown::shutdown_done();
    Ok(())
}

/// HTTP router of the node.
///
/// Only two paths: the explorer page and the API. Everything else returns
/// 404 — a small surface is a surface that can be reviewed.
fn serve(
    ctx: &q21_core::rpc::RpcContext,
    req: q21_core::http::Request,
    public: bool,
) -> q21_core::http::Response {
    use q21_core::http::Response;
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            Response::html(q21_core::explorer::PAGE.to_string())
        }
        // --- The wallet has no business on a public explorer.
        //
        // Both pages talk to the same node, and a published node has no
        // wallet: the page could therefore move nothing. That is not a reason
        // to serve it.
        //
        // A penetration audit flagged it before going live: a visitor who
        // lands on `https://explorer.example.org/wallet` sees an authentic Q21
        // wallet interface, served by the project's official domain. That is
        // the exact setting of a phishing attack — except that here we are the
        // ones setting it up, and it gets people used to typing things into a
        // website. A surface that serves no purpose is removed.
        ("GET", "/wallet") | ("GET", "/wallet.html") if !public => {
            Response::html(q21_core::wallet_ui::PAGE.to_string())
        }
        // The client's address follows the request: in public mode, it is
        // what gives each client its own scan budget instead of a single one
        // for everybody. It is neither logged nor returned.
        ("POST", "/rpc") => Response::json(ctx.handle_from(&req.body, req.client)),
        ("GET", "/rpc") => Response::text(
            405,
            "The JSON-RPC API expects a POST request. Example:\n\n  \
             curl -s -X POST http://127.0.0.1:21080/rpc \\\n    \
             -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\"}'\n",
        ),
        _ => Response::not_found(),
    }
}

// ===========================================================================
// The desktop wallet
// ===========================================================================

/// Starts the wallet: a full node, a local page, and the browser.
///
/// # Why a full node, and not a light client
///
/// A light client asks a server what the chain contains. That is, it **trusts
/// someone** to know its own balance. Q21 moreover has no light client
/// protocol, and designing one would introduce a trust model that does not
/// exist today.
///
/// Here, the wallet **is** a node: it validates every block itself. What the
/// page displays, this machine has verified.
///
/// # The token, and why it travels in the fragment
///
/// The interface needs a token to talk to the RPC. Putting it in the query —
/// `?token=...` — would make it enter the browser history, the logs of any
/// proxy, and the `Referer` header of the first external resource loaded. A
/// secret that travels in an address is no longer a secret, and it is a flaw
/// that the phase 8b audit flagged and then closed.
///
/// The **fragment** — what follows the `#` — is never sent to the server. The
/// browser keeps it to itself. The page reads it, erases it at once from the
/// address bar, and then sends it as `Authorization`. It therefore leaves no
/// trace anywhere but in the tab's memory.
///
/// # What the fragment carries, and why it is no longer the token
///
/// The address is passed to the browser launcher as an **argument**, which
/// any account on the machine can read in `/proc/<pid>/cmdline` or with `ps`,
/// and which stays there as long as the browser lives. The fragment therefore
/// carries a **launch** token, short and single-use: the page exchanges it at
/// load time for the session token, which never leaves the process or the
/// tab. What lingers afterwards in `argv` no longer opens anything. On Linux,
/// the node moreover refuses connections from another account; elsewhere,
/// the launch token is the barrier, and the launcher says so.
fn cmd_wallet(datadir: &Path, args: &[String]) -> Result<(), String> {
    let mut port: u16 = 0;
    let mut no_browser = false;
    let mut rest: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1]
                    .parse()
                    .map_err(|_| "unreadable port".to_string())?;
                i += 2;
            }
            "--no-browser" => {
                no_browser = true;
                i += 1;
            }
            other => {
                rest.push(other.to_string());
                i += 1;
            }
        }
    }

    println!("Q21 Wallet");
    println!();

    // 1. A free port for the node, unless one is forced.
    //
    // It is drawn **before** setup: the setup page must know where to send
    // the browser when it is done, and it cannot ask a server that does not
    // exist yet.
    let port = if port != 0 {
        port
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("no port available: {e}"))?
            .local_addr()
            .map_err(|e| e.to_string())?
            .port()
    };

    // 2. The session token. Thirty-two bytes drawn from the system generator:
    //    it cannot be guessed, and it only serves for the duration of this
    //    run. The same one serves for setup and for the node — it is a
    //    session secret, not a per-server secret.
    let raw: [u8; 32] =
        q21_core::rng::bytes().map_err(|_| "system random generator unavailable".to_string())?;
    let token: String = raw.iter().map(|o| format!("{o:02x}")).collect();

    // 2a. The node's launch token: it is this one, and not the session
    //    token, that goes into the address opened by the browser — hence
    //    into the launcher's command line, readable by other accounts. The
    //    page exchanges it once for the session token; what lingers afterwards
    //    in `argv` no longer opens anything. See `http::serve_with_launch_token`.
    let node_launch_token = draw_launch_token()?;
    let _ = NODE_LAUNCH_TOKEN.set(node_launch_token.clone());

    // 3. Setup, if the wallet does not exist yet or if it is sealed and no
    //    passphrase was provided otherwise.
    //
    // This is what replaces the two terminal commands of before: `init` to
    // create, then the question "Wallet passphrase:" asked on a bare line.
    // Both are now done in screens.
    let passphrase_given = passphrase_from_env().is_some();
    let exists = wallet_path(datadir).exists();
    let sealed = exists
        && q21_core::kdf::is_sealed(&std::fs::read(wallet_path(datadir)).unwrap_or_default());
    let setup_needed = !exists || (sealed && !passphrase_given);

    if setup_needed {
        run_setup(
            datadir,
            &token,
            &node_launch_token,
            port,
            no_browser,
            exists && sealed,
        )?;
    }

    // 4. The wallet can now be read without asking anything: either setup
    //    just kept the passphrase, or it was already known, or the file is
    //    not sealed.
    read_wallet(datadir)?;

    let address = format!("127.0.0.1:{port}");
    let url = format!("http://{address}/wallet#{node_launch_token}");

    println!();

    // --- The address is always displayed.
    //
    // It used to be shown only when opening the browser was skipped. When
    // opening failed — a system without a default browser, a remote session,
    // a company policy — nothing remained on screen, and there was no way in.
    //
    // Showing it costs nothing: it is displayed on its owner's machine, in a
    // window they opened. What we refuse is for it to go elsewhere — into a
    // browser history, into the logs of a proxy. On its owner's own screen,
    // it is where it belongs.
    println!("  If the browser does not open, open this address:");
    println!();
    println!("      {url}");
    println!();
    // --- What follows the "#" is no longer the session token.
    //
    // It is a launch token: the page exchanges it once for the real one, and
    // it is destroyed. Saying so avoids people copying it believing they keep
    // a key, and explains the refusal when the link is opened a second time.
    println!("  This link works only once: the page it opens exchanges what");
    println!("  follows the \"#\" for the session token, after which it is worth");
    println!("  nothing. To open the wallet elsewhere, start the program again.");
    if !cfg!(target_os = "linux") {
        // On Linux, the kernel says which account holds each local connection
        // and the node refuses the others. Here, that information does not
        // exist: the single-use link is the barrier, and that must be known.
        println!();
        println!("  On this system, the node cannot know which account on the");
        println!("  machine connects to it: the single-use link is the only");
        println!("  barrier. Do not open this wallet on a computer where other");
        println!("  people have an account.");
    }
    println!();

    // The browser is already open if setup just did it: the setup page itself
    // sends the browser on to the wallet. Opening a second one would leave two
    // tabs, one of them dead.
    if !no_browser && !setup_needed {
        // The browser opens once the server is ready. We probe the port rather
        // than waiting a fixed duration: a fixed duration is always too short
        // on a loaded machine and too long elsewhere.
        let a = address.clone();
        let u = url.clone();
        std::thread::spawn(move || {
            for _ in 0..100 {
                if std::net::TcpStream::connect(&a).is_ok() {
                    if let Err(e) = open_browser(&u) {
                        eprintln!("  The browser could not be opened ({e}).");
                        eprintln!("  Open the address above by hand.");
                    }
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            eprintln!("  The server did not answer. Open the address above by hand.");
        });
    }
    println!("  The same node also serves the chain explorer, on the same");
    println!("  port: link at the bottom of the page, or http://{address}/");
    println!();
    println!("  This window runs the wallet. Leave it open.");
    println!();

    // --- How to stop.
    //
    // This paragraph used to say only one thing: "Ctrl-C to stop". That is
    // correct, and it was not enough. On Windows, a Ctrl-C received during a
    // `.bat` file makes the interpreter ask its own question — "Terminate
    // batch job (Y/N)?" — to which both answers close the window. The first
    // user read it as a failure, and stopped daring to stop their wallet.
    //
    // We therefore first give the way that asks no question: the button.
    println!("  To stop, either:");
    println!("    - the \"Close the wallet\" button, Info tab;");
    println!("    - close this window;");
    // The batch-file question exists only on Windows: elsewhere, mentioning
    // it made users look for a question that never comes.
    if cfg!(windows) {
        println!("    - Ctrl-C here. Windows then asks \"Terminate batch job");
        println!("      (Y/N)?\": answer Y. This is not an error,");
        println!("      everything is already saved when this question appears.");
    } else {
        println!("    - Ctrl-C here. Everything is saved before the program exits.");
    }
    println!();

    // 5. The node, with the wallet methods and the token.
    let mut arguments = vec![
        "--rpc".to_string(),
        address,
        "--rpc-wallet".to_string(),
        "--rpc-token".to_string(),
        token,
        // No status report: in a wallet it drowns the only useful
        // information, the address to open.
        "--quiet".to_string(),
    ];
    // Layers 1 and 2: only when the user turned it on (Network tab, stored in
    // `settings.txt`), the wallet listens for incoming connections and asks
    // the router to open its port. It is off by default: a reachable wallet
    // announces its owner's public address to the whole network, see
    // `q21_core::settings::reachable`. Nothing is added if the user already
    // set `--listen` by hand: their choice wins.
    if read_reachable(datadir) && !rest.iter().any(|a| a == "--listen") {
        arguments.push("--listen".to_string());
        arguments.push(String::new()); // default P2P port of the network
        arguments.push("--upnp".to_string());
    }
    arguments.extend(rest);
    cmd_node(datadir, &arguments)
}

// ===========================================================================
// Setup, in screens
// ===========================================================================

/// Creates or opens the wallet from a page, then returns.
///
/// The server lives for the duration of the exchange and dies afterwards: the
/// node starts after it, on **its own port**. See the header of
/// `q21_core::setup` for what this choice costs and what it avoids.
///
/// The function blocks until the page says it is done. When it returns, the
/// wallet exists on disk and the passphrase is kept for the lifetime of the
/// process.
fn run_setup(
    datadir: &Path,
    token: &str,
    node_launch_token: &str,
    node_port: u16,
    no_browser: bool,
    sealed: bool,
) -> Result<(), String> {
    use q21_core::http::Response;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // The case where a chain exists without a wallet: it is the folder of a
    // wallet-less node (started with `node --network <name>` and no wallet).
    // Grafting a new wallet onto it would write a second genesis over the
    // first. We refuse, and say so.
    if !sealed && blocks_path(datadir).exists() && !wallet_path(datadir).exists() {
        return Err(format!(
            "the folder {} contains a chain but no wallet.\n\n  \
             It is the folder of a wallet-less node. Use another one:\n\n      \
             q21 --datadir <a-new-folder> wallet",
            datadir.display()
        ));
    }

    let finished = Arc::new(AtomicBool::new(false));
    let datadir = datadir.to_path_buf();
    let finished_h = finished.clone();

    // The desktop wallet's network is testnet. It is the only one that
    // exists, and offering a choice with a single answer is a way to cause
    // hesitation without offering anything. `regtest` remains available on the
    // command line, where those who need it go.
    let network = Network::Testnet;

    let node_launch_token_page = node_launch_token.to_string();
    let respond = move |req: q21_core::http::Request| -> Response {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/welcome") => Response::html(q21_core::setup::PAGE.to_string()),
            ("POST", "/setup") => {
                let r = handle_setup(
                    &datadir,
                    network,
                    node_port,
                    &node_launch_token_page,
                    &req.body,
                    &finished_h,
                );
                Response::json(r.encode())
            }
            _ => Response::not_found(),
        }
    };

    // The HTML shell is served without a token — otherwise the page could not
    // even load to ask for one. It carries no data: it is the same rule as for
    // the explorer, and the list stays named path by path.
    //
    // This server has its own launch token: it is the one that goes into the
    // address opened by the browser, and the page exchanges it once for the
    // session token. The node's token, the page will receive it through
    // `status`, once authenticated, to send the browser there at the end.
    let setup_launch_token = draw_launch_token()?;
    let server = q21_core::http::serve_with_launch_token(
        "127.0.0.1:0",
        token.to_string(),
        setup_launch_token.clone(),
        &["/welcome"],
        respond,
    )
    .map_err(|e| format!("the setup server did not start: {e:?}"))?;
    let url = format!(
        "http://127.0.0.1:{}/welcome#{setup_launch_token}",
        server.addr.port()
    );

    if sealed {
        println!("  This wallet is protected by a passphrase.");
    } else {
        println!("  No wallet here: we are going to create one.");
    }
    println!();
    println!("  If the browser does not open, open this address:");
    println!();
    println!("      {url}");
    println!();

    if !no_browser {
        if let Err(e) = open_browser(&url) {
            eprintln!("  The browser could not be opened ({e}).");
            eprintln!("  Open the address above by hand.");
        }
    }

    // We wait for the page to say it is done. Without a time limit: it is a
    // human copying a backup code onto paper, and imposing a stopwatch on them
    // would be exactly the wrong idea.
    while !finished.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(120));
    }

    // This server does not die right away: the page still queries it to know
    // when the node is listening — it cannot ask the node itself, which is on
    // another origin. A watcher therefore waits for the node to be up, leaves
    // the page time to notice, then closes the door. Leaving a second server
    // open for the whole lifetime of the program would be attack surface with
    // no use.
    std::thread::spawn(move || {
        let target = std::net::SocketAddr::from(([127, 0, 0, 1], node_port));
        for _ in 0..600 {
            if std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_millis(200))
                .is_ok()
            {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        server.shutdown();
    });
    Ok(())
}

/// The body of the four setup methods.
///
/// Always returns a JSON object. An error is an `error` field carrying a
/// sentence meant to be read by someone, not a code.
fn handle_setup(
    datadir: &Path,
    network: Network,
    node_port: u16,
    node_launch_token: &str,
    body: &str,
    finished: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> q21_core::json::Json {
    use q21_core::json::Json;

    let error = |m: &str| Json::obj().set("error", Json::str(m)).build();

    let request = match q21_core::json::parse(body) {
        Ok(j) => j,
        Err(_) => return error("unreadable request"),
    };
    let method = request.get("method").and_then(|j| j.as_str()).unwrap_or("");
    let params = request.get("params");
    let text = |key: &str| -> Option<String> {
        params
            .and_then(|p| p.get(key))
            .and_then(|j| j.as_str())
            .map(|s| s.to_string())
    };

    match method {
        "status" => {
            let raw = std::fs::read(wallet_path(datadir)).unwrap_or_default();
            let what = if raw.is_empty() {
                "absent"
            } else if q21_core::kdf::is_sealed(&raw) {
                "sealed"
            } else {
                "plaintext"
            };
            Json::obj()
                .set("wallet", Json::str(what))
                .set("network", Json::str(network_name(network)))
                .set("node_port", Json::u64(node_port as u64))
                // The node's launch token, to send the browser there at the
                // end. It is only returned here, to a page that has already
                // proven it holds the session token; it will be valid only
                // once.
                .set("node_launch_token", Json::str(node_launch_token))
                .build()
        }

        "create" => {
            if wallet_path(datadir).exists() {
                return error("a wallet already exists in this folder");
            }
            // A code was provided: it is a restore. The seed comes from the
            // sheet of paper, not from the generator.
            let seed = match text("code") {
                Some(code) if !code.trim().is_empty() => {
                    match Wallet::seed_from_backup(code.trim(), network) {
                        Ok(g) => Some(g),
                        Err(q21_core::wallet::WalletError::BackupForOtherNetwork) => {
                            return error("this backup code belongs to another network")
                        }
                        Err(q21_core::wallet::WalletError::BackupIsAnAddress) => {
                            return error(&address_instead_of_code_message(network))
                        }
                        Err(_) => {
                            return error(
                                "backup code unreadable: the checksum does not \
                                 match. Check the copy — the alphabet used \
                                 contains no 1, b, i or o.",
                            )
                        }
                    }
                }
                _ => None,
            };

            // The passphrase is established BEFORE any write: `write_wallet`
            // reads it to seal, and a wallet written in plaintext and then
            // encrypted would have left a plaintext trace on the disk.
            match text("passphrase") {
                Some(p) if !p.is_empty() => remember_passphrase(Some(p)),
                // Empty string: the "no protection" choice, made knowingly in
                // the page, behind a checkbox that explains it.
                Some(_) => remember_passphrase(None),
                None => return error("no passphrase sent"),
            }

            let scheme = if SchemeId::MlDsa87.is_available() {
                SchemeId::MlDsa87
            } else {
                SchemeId::LamportOts
            };
            if create_private_dir(datadir).is_err() {
                forget_passphrase();
                return error("the data folder could not be created");
            }
            match write_new_chain(datadir, network, scheme, seed) {
                Ok((w, address, _)) => Json::obj()
                    .set("code", Json::str(w.backup_code()))
                    .set("address", Json::str(address.to_string()))
                    .build(),
                Err(e) => {
                    forget_passphrase();
                    error(&e)
                }
            }
        }

        "open" => {
            let passphrase = match text("passphrase") {
                Some(p) => p,
                None => return error("no passphrase sent"),
            };
            remember_passphrase(Some(passphrase));
            match read_wallet(datadir) {
                Ok(mut w) => {
                    let address = w.request_address().to_string();
                    Json::obj().set("address", Json::str(address)).build()
                }
                Err(e) => {
                    // We go back to "nothing has been said", and not to "there
                    // is no passphrase": the latter would allow a plaintext
                    // write at the next save.
                    forget_passphrase();
                    // A refusal from the directory anchor — substituted file —
                    // is not a wrong passphrase: the page must say it as is,
                    // otherwise the user retypes their passphrase forever.
                    if e.starts_with("this directory") || e.starts_with("this wallet.dat") {
                        eprintln!("error: {e}");
                        error(&e)
                    } else {
                        error("Incorrect passphrase. Try again.")
                    }
                }
            }
        }

        // "I am done": the page has everything it needs, the node can start.
        // We do not cut this server for all that — the page still needs it to
        // know when to go and look elsewhere.
        "start" => {
            finished.store(true, std::sync::atomic::Ordering::Relaxed);
            Json::obj().set("ok", Json::Bool(true)).build()
        }

        // "Is the node listening?" The page cannot ask it itself: the node is
        // on another origin, and the browser refuses to read its answer. This
        // server, on the other hand, has no same-origin policy to respect: it
        // opens a connection and says what it saw.
        "node" => {
            let ready = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], node_port)),
                std::time::Duration::from_millis(200),
            )
            .is_ok();
            Json::obj().set("ready", Json::Bool(ready)).build()
        }

        _ => error("unknown method"),
    }
}

/// Opens an address in the system's default browser.
///
/// No library: three commands, one per system. That is exactly what the
/// libraries we could have imported do, and it avoids adding a dependency to
/// software that keeps private keys.
fn open_browser(url: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let mut c = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        // `start` is a built-in command of the interpreter, hence `cmd /C`.
        // The first empty argument is the window title: without it, `start`
        // takes the address for a title and opens nothing.
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    c.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    Ok(())
}

/// Brings the index up to the level of the chain.
///
/// Three cases, and a single behavior for the two bad ones:
///
/// - **nothing to do**: the index is already at the top, and on the same
///   block;
/// - **extension**: the chain has moved on, the index follows block by block.
///   The outputs these blocks spend are either earlier and still alive —
///   hence known to the owners table — or created by the blocks themselves;
/// - **divergence**: a reorg changed the past. The index is rebuilt from zero.
///
/// Rebuilding on a reorg is more brutal than necessary: we could remove only
/// the abandoned branch. But the owners table would then have to be brought
/// back to its state before the fork, which requires journaling the consumed
/// outputs. A reorg is rare; a wrong address attribution goes unnoticed.
/// Between the two, we choose what cannot lie.
fn follow_index(index: &mut q21_core::index::Index, node: &std::sync::Arc<q21_core::net::Node>) {
    let height = node.height();
    if !index.is_empty() && index.height() == height {
        return;
    }
    let divergence = !index.is_empty() && {
        let h = index.height();
        node.with_chain(|c| c.active_at(h)) != index.block_id(h)
    };
    if divergence {
        eprintln!("  address index: reorg detected, rebuilding");
        index.clear();
    }
    let start = if index.is_empty() {
        0
    } else {
        index.height() + 1
    };
    node.with_chain(|c| {
        for h in start..=c.height() {
            if let Some(b) = c.block_at(h) {
                if let Err(e) = index.index_block(&b) {
                    eprintln!("warning: {e}");
                    return;
                }
            }
        }
    });
}

/// Opens the chain explorer in the browser.
///
/// # Why a separate command
///
/// The explorer is already served by `q21 wallet`: same process, same port,
/// same token, at the root rather than on `/wallet`. Someone with an open
/// wallet has nothing more to start, and the directory lock would forbid a
/// second program on the same folder anyway.
///
/// This command serves the other case: viewing the chain **without** opening
/// a wallet. The methods that move funds are then not exposed at all — not
/// disabled by a setting, absent.
///
/// # The index is enabled by default, here only
///
/// An explorer without an address index only half answers: address search
/// stops after two thousand blocks and says so. The node keeps its default —
/// see `q21_core::index` for the reason.
fn cmd_explorer(datadir: &Path, args: &[String]) -> Result<(), String> {
    let mut port: u16 = 0;
    let mut no_browser = false;
    let mut index = true;
    let mut rest: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1]
                    .parse()
                    .map_err(|_| "unreadable port".to_string())?;
                i += 2;
            }
            "--no-browser" => {
                no_browser = true;
                i += 1;
            }
            "--no-index" => {
                index = false;
                i += 1;
            }
            other => {
                rest.push(other.to_string());
                i += 1;
            }
        }
    }

    println!("Q21 Explorer");
    println!();

    // The network is read from the wallet: it is the wallet that says which
    // chain this directory contains. An explorer does not need its content,
    // but it needs this answer — and the file is sealed as a single block.
    // Hence the passphrase, even here.
    if q21_core::kdf::is_sealed(&std::fs::read(wallet_path(datadir)).unwrap_or_default())
        && passphrase_from_env().is_none()
    {
        println!("  This folder contains a wallet protected by a passphrase.");
        println!("  The explorer does not touch it: it only needs to read from it");
        println!("  which network this is. Type the passphrase, then Enter.");
        println!();
    }
    read_wallet(datadir)?;

    let port = if port != 0 {
        port
    } else {
        std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("no port available: {e}"))?
            .local_addr()
            .map_err(|e| e.to_string())?
            .port()
    };

    let raw: [u8; 32] =
        q21_core::rng::bytes().map_err(|_| "system random generator unavailable".to_string())?;
    let token: String = raw.iter().map(|o| format!("{o:02x}")).collect();
    // Same rule as for the wallet: the browser receives a single-use launch
    // token, never the session token.
    let launch_token = draw_launch_token()?;
    let _ = NODE_LAUNCH_TOKEN.set(launch_token.clone());
    let address = format!("127.0.0.1:{port}");
    let url = format!("http://{address}/#{launch_token}");

    println!();
    println!("  If the browser does not open, open this address:");
    println!();
    println!("      {url}");
    println!();
    println!("  This link works only once. No wallet method is");
    println!("  served by this process.");
    println!();

    if !no_browser {
        let a = address.clone();
        let u = url.clone();
        std::thread::spawn(move || {
            for _ in 0..200 {
                if std::net::TcpStream::connect(&a).is_ok() {
                    if let Err(e) = open_browser(&u) {
                        eprintln!("  The browser could not be opened ({e}).");
                    }
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    }
    println!("  This window runs the explorer. Leave it open.");
    println!("  Close it to stop.");
    println!();

    let mut arguments = vec![
        "--rpc".to_string(),
        address,
        "--rpc-token".to_string(),
        token,
    ];
    if index {
        arguments.push("--address-index".to_string());
    }
    arguments.push("--quiet".to_string());
    arguments.extend(rest);
    cmd_node(datadir, &arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A binary without ML-DSA refuses to start where ML-DSA circulates.
    ///
    /// Before this guard, it started, held every block to be invalid, banned
    /// its peers and cut its archive on replay. Regtest remains tolerated,
    /// with a warning: that is where Lamport is tested.
    #[test]
    fn a_binary_without_ml_dsa_refuses_to_start_outside_regtest() {
        for network in [Network::Mainnet, Network::Testnet] {
            let refusal = scheme_guard_with(network, false).expect_err("must refuse");
            assert!(refusal.contains("cargo build --release"), "{refusal}");
            assert!(refusal.contains("--no-default-features"), "{refusal}");
        }
        let tolerated = scheme_guard_with(Network::Regtest, false).expect("regtest tolerated");
        assert!(tolerated.expect("with a warning").contains("Lamport"));
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            assert_eq!(scheme_guard_with(network, true), Ok(None));
        }
    }

    /// The guard really is on the path of every load: a mainnet folder is
    /// refused before any file is opened.
    #[test]
    fn the_guard_comes_before_any_file() {
        let s = include_str!("q21.rs");
        let guard = s
            .find("scheme_guard(network)?;")
            .expect("call to the guard");
        let opening = s
            .find("BlockArchive::open(blocks_path(datadir), network)")
            .expect("opening");
        assert!(
            guard < opening,
            "the guard must come before opening the archive"
        );
    }

    /// The address book makes the round trip without losing anything.
    /// On mainnet, the seed never touches the disk in plaintext.
    ///
    /// September 2026 security campaign: a VM snapshot, a cloud backup or a
    /// resold disk would expose a seed written without a passphrase. The guard
    /// is at the single write point, so it covers init, restore and mining.
    /// Elsewhere (testnet, regtest), plaintext remains allowed, with a warning.
    #[test]
    fn a_mainnet_wallet_without_passphrase_is_refused() {
        use q21_core::wallet::Wallet;

        // No passphrase kept for this session.
        remember_passphrase(None);

        let base = std::env::temp_dir().join(format!(
            "q21_test_mainnet_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        // Mainnet, without a passphrase: refused.
        let d_main = base.join("main");
        std::fs::create_dir_all(&d_main).unwrap();
        let w_main = Wallet::from_seed([0x5a; 32], Network::Mainnet);
        let refusal = write_wallet(&d_main, &w_main)
            .expect_err("a mainnet wallet without a passphrase must be refused");
        assert!(
            refusal.contains("mainnet wallet without a passphrase"),
            "unexpected message: {refusal}"
        );
        assert!(
            !wallet_path(&d_main).exists(),
            "no wallet file must have been written in plaintext"
        );

        // Testnet, without a passphrase: allowed (informed choice).
        let d_test = base.join("test");
        std::fs::create_dir_all(&d_test).unwrap();
        let w_test = Wallet::from_seed([0x5a; 32], Network::Testnet);
        write_wallet(&d_test, &w_test).expect("a test wallet without a passphrase remains allowed");
        assert!(wallet_path(&d_test).exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn labels_survive_writing_and_reading_back() {
        let mut e = HashMap::new();
        e.insert(0u32, "for the plumber".to_string());
        e.insert(12, "rent — February".to_string());
        e.insert(7, "Marie, bakery".to_string());
        let text = labels_to_text(&e);
        assert_eq!(text_to_labels(&text), e);
    }

    /// A label cannot break the wallet file.
    ///
    /// That is the reason for the hexadecimal. The format is "one key, an
    /// equals sign, one value, per line": a line break or an equals sign in a
    /// name would shift the reading of everything that follows, and what
    /// follows contains the seed.
    #[test]
    fn a_label_cannot_break_the_format() {
        let mut e = HashMap::new();
        e.insert(3u32, "seed=0000\nnext_index=0,comma=equals".to_string());
        let text = labels_to_text(&e);
        assert!(!text.contains('\n'), "a line break survived: {text}");
        assert!(!text.contains('='), "an equals sign survived: {text}");
        // The comma separates entries: it must appear only between them,
        // never inside a name. Here there is only one entry.
        assert!(!text.contains(','), "a comma survived: {text}");
        assert_eq!(text_to_labels(&text), e, "the text must come back intact");
    }

    /// A damaged entry is lost on its own.
    ///
    /// Losing a name is annoying; losing the wallet is far worse. A file
    /// copied by hand, truncated, or written by a future version must never
    /// prevent opening one's funds.
    #[test]
    fn a_damaged_entry_does_not_take_the_others_with_it() {
        let m = text_to_labels("0:666f72,nocolon,x:6161,9:zz,4:676f6f64");
        assert_eq!(m.get(&0).map(|s| s.as_str()), Some("for"));
        assert_eq!(m.get(&4).map(|s| s.as_str()), Some("good"));
        assert_eq!(m.len(), 2, "only valid entries get in: {m:?}");
    }

    /// A wallet written before the address book reads without an address book.
    #[test]
    fn a_missing_address_book_is_not_an_error() {
        assert!(text_to_labels("").is_empty());
    }

    #[test]
    fn hex_refuses_what_it_does_not_understand() {
        assert_eq!(hex_to_bytes("48656c6c6f"), Some(b"Hello".to_vec()));
        assert_eq!(hex_to_bytes("abc"), None, "odd length");
        assert_eq!(hex_to_bytes("zz"), None, "outside the alphabet");
        assert_eq!(hex_to_bytes(""), Some(Vec::new()));
    }

    /// The account name passed to `icacls` decides who will be able to read
    /// the file that carries the seed. An error here is not a trifle: granting
    /// access to the wrong account, or to an empty account, would leave the
    /// file without real protection.
    ///
    /// This computation is deliberately separated from the Windows-specific
    /// code, so that it can be tested even where the rest does not compile.
    #[test]
    fn the_windows_account_name_is_qualified_with_the_domain() {
        // Common case: personal machine, domain = machine name.
        assert_eq!(
            windows_account_name(Some("user"), Some("DESKTOP-PC")),
            Some("DESKTOP-PC\\user".to_string())
        );
        // Without a known domain, the name alone is enough.
        assert_eq!(
            windows_account_name(Some("user"), None),
            Some("user".to_string())
        );
        // An empty domain must not produce a lopsided "\\user".
        assert_eq!(
            windows_account_name(Some("user"), Some("")),
            Some("user".to_string())
        );
        assert_eq!(
            windows_account_name(Some("user"), Some("   ")),
            Some("user".to_string())
        );
        // Stray spaces must not get into an access rule.
        assert_eq!(
            windows_account_name(Some("  user  "), Some("  DOM  ")),
            Some("DOM\\user".to_string())
        );
        // Without a user, nothing is granted to anyone: better to fail
        // plainly than to set a rule at random.
        assert_eq!(windows_account_name(None, Some("DOM")), None);
        assert_eq!(windows_account_name(Some(""), Some("DOM")), None);
        assert_eq!(windows_account_name(Some("   "), None), None);
    }

    /// Discovery in the node loop does not let a Lamport key already revealed
    /// in a block sign again.
    ///
    /// Replays the audit's proof P5 against the node path: a chain where index
    /// 0 receives all the coinbases and then spends one; a wallet restored
    /// from the same seed, discovered in the loop, must hold index 0 as
    /// consumed and no longer commit it.
    #[test]
    fn discovery_in_the_loop_scans_one_time_keys() {
        use q21_core::chain::GENESIS_TIME;
        use q21_core::sig::pubkey_hash;

        let seed = [0x21u8; 32];
        let mut origin = Wallet::from_seed(seed, Network::Regtest);
        let a0 = origin.new_address();
        let mut c = Chain::new(Network::Regtest, genesis_block(Network::Regtest));
        for i in 0..(COINBASE_MATURITY + 2) {
            let t = GENESIS_TIME + (i + 1) * TARGET_BLOCK_SECS;
            let b = c
                .mine_block(a0.hash, SchemeId::LamportOts, &[], t, 20_000_000)
                .unwrap();
            c.connect(&b, t + 1).unwrap();
        }
        let mut third_party = Wallet::from_seed([0x99; 32], Network::Regtest);
        let dest = third_party.new_address();
        let tx1 = origin
            .create_transaction(
                &c.utxo,
                c.height(),
                &dest,
                Amount::from_units(50_000),
                Amount::from_units(1_000),
            )
            .unwrap();
        let pk0 = tx1.inputs[0].witness.pubkey.clone();
        assert_eq!(pubkey_hash(SchemeId::LamportOts, &pk0), a0.hash);
        let t = GENESIS_TIME + (COINBASE_MATURITY + 3) * TARGET_BLOCK_SECS;
        let b = c
            .mine_block(a0.hash, SchemeId::LamportOts, &[tx1], t, 20_000_000)
            .unwrap();
        c.connect(&b, t + 1).unwrap();

        // The node path: discovery in the loop, chain already there.
        let mut restored = Wallet::from_seed(seed, Network::Regtest);
        assert!(discover_in_loop(&mut restored, &c) > 0);
        assert!(
            restored.is_consumed(0),
            "FINDING: key 0, revealed in a block, is held as free"
        );
        assert_eq!(restored.verified_up_to(), c.height());
        assert!(!restored
            .spendable(&c.utxo, c.height())
            .iter()
            .any(|(_, _, i)| *i == 0));
        let balance = restored.balance(&c.utxo, c.height()).units();
        let tx2 = restored
            .create_transaction(
                &c.utxo,
                c.height(),
                &dest,
                Amount::from_units(balance - 1_000),
                Amount::from_units(1_000),
            )
            .unwrap();
        assert!(
            !tx2.inputs.iter().any(|e| e.witness.pubkey == pk0),
            "FINDING: key 0 signed again"
        );
    }

    /// An argument that looks like a backup code is recognized, whatever its
    /// case and its network; a network or scheme name is not.
    #[test]
    fn a_backup_code_as_argument_is_recognized() {
        let code = Wallet::from_seed([0x5a; 32], Network::Regtest).backup_code();
        assert!(looks_like_backup_code(&code));
        assert!(looks_like_backup_code(&code.to_uppercase()));
        assert!(looks_like_backup_code(
            &Wallet::from_seed([0x5a; 32], Network::Testnet).backup_code()
        ));
        for word in ["regtest", "testnet", "lamport", "mldsa87", "--no-browser"] {
            assert!(!looks_like_backup_code(word), "{word}");
        }
    }

    /// The directory anchor makes the round trip, and a directory without an
    /// anchor reads as blank.
    #[test]
    fn the_directory_anchor_survives_writing_and_reading_back() {
        let d = std::env::temp_dir().join(format!("q21-anchor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(read_anchor(&d), None);
        let w = Wallet::from_seed([0x5a; 32], Network::Regtest);
        let a = Anchor {
            sealed: true,
            seed: Some(dir_fingerprint(&w)),
        };
        write_anchor(&d, &a);
        assert_eq!(read_anchor(&d), Some(a));
        let other = Wallet::from_seed([0x5b; 32], Network::Regtest);
        assert_ne!(dir_fingerprint(&w), dir_fingerprint(&other));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The wallet methods never open without a token.
    ///
    /// `--rpc-wallet` alone used to start, and answered `sendtoaddress`
    /// without authentication to any program on the machine.
    #[test]
    fn the_rpc_wallet_requires_a_token() {
        // Without a wallet, the token remains optional on the loopback.
        assert!(check_rpc_token(false, None).is_ok());
        assert!(check_rpc_token(false, Some("short")).is_ok());
        // With one: refused without a token, refused with a token too short.
        let e = check_rpc_token(true, None).unwrap_err();
        assert!(e.contains("without a token"), "{e}");
        assert!(check_rpc_token(true, Some("0123456789abcde")).is_err());
        assert!(check_rpc_token(true, Some("0123456789abcdef")).is_ok());
        // An empty token guards nothing: refused everywhere.
        assert!(check_rpc_token(false, Some("")).is_err());
        assert!(check_rpc_token(true, Some("   ")).is_err());
    }

    /// The token is read from a file, without its whitespace or line ending.
    #[test]
    fn the_token_is_read_from_a_file() {
        let d = std::env::temp_dir().join(format!("q21-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("token");
        std::fs::write(&f, "  0123456789abcdef0123  \nsecond line ignored\n").unwrap();
        assert_eq!(read_rpc_token(&f).unwrap(), "0123456789abcdef0123");
        std::fs::write(&f, "\n").unwrap();
        assert!(read_rpc_token(&f).is_err(), "an empty file is not a token");
        assert!(read_rpc_token(&d.join("absent")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
