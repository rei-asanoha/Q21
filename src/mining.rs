//! The mining state, shared between the node loop and the interface.
//!
//! # Why this module exists
//!
//! Mining used to be decided at startup, by a `--mine` flag, and could only be
//! undone by stopping the program. That was workable as long as the wallet was
//! driven from the command line. It no longer is: nobody accepts closing their
//! wallet to stop mining, and nobody should have to reread a console window to
//! know whether their machine is really searching.
//!
//! This module therefore carries two things, and nothing else:
//!
//! - **a switch** that the node loop reads on every round and that the
//!   interface toggles;
//! - **a counter** of what has been attempted, so that the displayed rate is a
//!   measurement and not an estimate.
//!
//! # The rate is measured over a sliding window
//!
//! An average since startup lies in two ways: it takes several minutes to
//! reflect a stop, and it flattens the slowdown of a machine that is heating
//! up. We therefore keep the count of the last closed interval and that of the
//! current interval, and the announced rate is that of the last interval of at
//! least one second. This is what a miner wants to know: what their machine is
//! doing now.
//!
//! # What this module does not do
//!
//! It does not mine. It knows neither the chain, nor the wallet, nor the proof
//! of work table. An object shared between a thread that handles funds and an
//! interface exposed to the browser must be as small as possible, and this one
//! cannot break anything: at worst it announces a wrong figure.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// A block found by this machine: what the miner wants to look back at.
///
/// The chain itself does not tell "my" blocks apart from the others — that is
/// intended, the miner changes address on every block so as not to be
/// trackable. Only this process knows what it found, and it only knew it for
/// the length of a log line. So we keep it here, for the screen.
#[derive(Clone, Copy)]
pub struct FoundBlock {
    pub height: u64,
    pub block_id: crate::hash::Hash256,
    /// What the coinbase pays the miner: subsidy plus fees.
    pub reward: u64,
    pub timestamp: u64,
}

/// Number of finds kept for display.
///
/// The screen shows a handful; keeping fifty leaves enough to look back over an
/// evening of mining without turning this shared object into an archive.
const FOUND_KEPT: usize = 50;

/// Minimum length of a measurement window.
const WINDOW: std::time::Duration = std::time::Duration::from_millis(1000);

/// Mining state, shared through `Arc`.
pub struct Mining {
    active: AtomicBool,
    /// Attempts since the program started. Never goes down.
    total_attempts: AtomicU64,
    /// Blocks found since startup.
    blocks: AtomicU64,
    /// Total paid to the miner since startup, in units.
    earned: AtomicU64,
    /// The latest finds, most recent first.
    found_blocks: Mutex<Vec<FoundBlock>>,
    /// Rate of the last closed window, in attempts per second.
    rate: Mutex<f64>,
    /// Current window: opening instant and attempts counted since.
    window: Mutex<(Instant, u64)>,
}

impl Default for Mining {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Mining {
    pub fn new(active: bool) -> Mining {
        Mining {
            active: AtomicBool::new(active),
            total_attempts: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            earned: AtomicU64::new(0),
            found_blocks: Mutex::new(Vec::new()),
            rate: Mutex::new(0.0),
            window: Mutex::new((Instant::now(), 0)),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Turns on or off. Returns the resulting state.
    ///
    /// Turning off resets the rate to zero right away: leaving the last figure
    /// displayed would suggest that the machine is still searching.
    pub fn set_active(&self, on: bool) -> bool {
        self.active.store(on, Ordering::Relaxed);
        if !on {
            *self.rate.lock().unwrap_or_else(|e| e.into_inner()) = 0.0;
            *self.window.lock().unwrap_or_else(|e| e.into_inner()) = (Instant::now(), 0);
        }
        on
    }

    /// Records `n` attempts made.
    ///
    /// Called by the node loop after each block attempt. It is the only place
    /// where the counter goes up.
    pub fn count_attempts(&self, n: u64) {
        self.total_attempts.fetch_add(n, Ordering::Relaxed);
        let mut f = self.window.lock().unwrap_or_else(|e| e.into_inner());
        f.1 += n;
        let elapsed = f.0.elapsed();
        if elapsed >= WINDOW {
            let d = f.1 as f64 / elapsed.as_secs_f64();
            *self.rate.lock().unwrap_or_else(|e| e.into_inner()) = d;
            *f = (Instant::now(), 0);
        }
    }

    pub fn block_found(&self, t: FoundBlock) {
        self.blocks.fetch_add(1, Ordering::Relaxed);
        self.earned.fetch_add(t.reward, Ordering::Relaxed);
        let mut v = self.found_blocks.lock().unwrap_or_else(|e| e.into_inner());
        v.insert(0, t);
        v.truncate(FOUND_KEPT);
    }

    /// The latest finds, most recent first.
    pub fn found(&self) -> Vec<FoundBlock> {
        self.found_blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Total paid to the miner since startup, in units.
    pub fn total_earned(&self) -> u64 {
        self.earned.load(Ordering::Relaxed)
    }

    /// Current rate, in attempts per second.
    ///
    /// Zero as long as no window has closed: better to announce nothing than a
    /// figure drawn from a tenth of a second.
    pub fn rate(&self) -> f64 {
        *self.rate.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn total_attempts(&self) -> u64 {
        self.total_attempts.load(Ordering::Relaxed)
    }

    pub fn blocks(&self) -> u64 {
        self.blocks.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_goes_both_ways() {
        let m = Mining::new(false);
        assert!(!m.is_active());
        assert!(m.set_active(true));
        assert!(m.is_active());
        assert!(!m.set_active(false));
        assert!(!m.is_active());
    }

    #[test]
    fn the_rate_stays_zero_until_a_window_has_closed() {
        let m = Mining::new(true);
        m.count_attempts(10_000);
        // The window lasts one second: nothing must be announced yet.
        assert_eq!(m.rate(), 0.0, "a rate drawn from an instant is not a rate");
        assert_eq!(m.total_attempts(), 10_000);
    }

    #[test]
    fn the_rate_is_computed_when_the_window_closes() {
        let m = Mining::new(true);
        m.count_attempts(1_000);
        std::thread::sleep(WINDOW + std::time::Duration::from_millis(60));
        m.count_attempts(1_000);
        let d = m.rate();
        assert!(d > 500.0 && d < 4_000.0, "rate beyond all reason: {d}");
    }

    #[test]
    fn turning_off_resets_the_rate_to_zero() {
        // Without this, the last measured figure stayed on screen and suggested
        // that the machine was still searching.
        let m = Mining::new(true);
        m.count_attempts(1_000);
        std::thread::sleep(WINDOW + std::time::Duration::from_millis(60));
        m.count_attempts(1_000);
        assert!(m.rate() > 0.0);
        m.set_active(false);
        assert_eq!(m.rate(), 0.0);
    }

    #[test]
    fn the_total_does_not_go_down_when_turned_off() {
        // The rate is a measurement of the moment; the total is a history.
        let m = Mining::new(true);
        m.count_attempts(4_242);
        m.set_active(false);
        assert_eq!(m.total_attempts(), 4_242);
    }

    fn find(h: u64, reward: u64) -> FoundBlock {
        FoundBlock {
            height: h,
            block_id: crate::hash::Hash256([7u8; 32]),
            reward,
            timestamp: 1_700_000_000 + h,
        }
    }

    #[test]
    fn blocks_are_counted_separately() {
        let m = Mining::new(true);
        m.block_found(find(1, 100));
        m.block_found(find(2, 250));
        assert_eq!(m.blocks(), 2);
        assert_eq!(
            m.total_attempts(),
            0,
            "a found block is not a counted attempt"
        );
        // The earnings add up, and the most recent find comes first: it is the
        // one the eye looks for when the screen comes alive.
        assert_eq!(m.total_earned(), 350);
        let t = m.found();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].height, 2);
    }

    #[test]
    fn the_log_of_finds_is_bounded() {
        // An object shared between the mining loop and the interface must not
        // grow without end: beyond the window, the old ones drop off, but the
        // count and the earnings forget nothing.
        let m = Mining::new(true);
        for h in 0..200u64 {
            m.block_found(find(h, 10));
        }
        assert_eq!(m.found().len(), FOUND_KEPT);
        assert_eq!(m.blocks(), 200);
        assert_eq!(m.total_earned(), 2_000);
        assert_eq!(
            m.found()[0].height,
            199,
            "the most recent one must come first"
        );
    }
}
