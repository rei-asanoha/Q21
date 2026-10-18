//! A peer's outgoing queue, drained by a thread of its own.
//!
//! # The defect this closes
//!
//! Up to v0.4.8, every message to a peer was written by the thread that
//! produced it, under the mutex of the peer's socket. A broadcast — a block, a
//! transaction, an address — wrote to each peer **in turn**, and a peer that
//! stopped reading (a stalled Tor circuit, a laptop gone to sleep) held the
//! writer for up to [`WRITE_TIMEOUT`](crate::net::WRITE_TIMEOUT) on every
//! message. Several such peers, and the thread was gone for minutes: the
//! mining loop could not announce its block, the RPC server could not return
//! from `sendtoaddress`, and the read loop that was relaying a block stopped
//! reading its own peer. Worse, `disconnect` took the socket's mutex to close
//! it — while holding the node's global lock — and so froze the whole node
//! behind the stalled write. That is what the 2-hour endurance test showed:
//! nodes silent for several minutes, every wallet answering "no response" at
//! the same time.
//!
//! # What replaces it
//!
//! Each peer has an [`Outbox`]: a FIFO of ready-made frames and one writer
//! thread that takes them out and writes them. Producers never touch the
//! socket:
//!
//! - [`Outbox::push`] never waits. It is what broadcasts use: one slow peer
//!   costs the others nothing. If that peer's queue is already full, the
//!   message is dropped **for that peer only** — it is not reading anyway, and
//!   the write timeout of its own thread will soon drop the connection.
//! - [`Outbox::push_wait`] waits for room, up to a deadline. It is what a
//!   peer's **own** read loop uses to answer it: a peer asking for more than it
//!   reads is slowed down, as it was before, but now it only slows itself.
//! - [`Outbox::close`] never waits either: it marks the queue closed and shuts
//!   the socket down through a clone of its own, without any mutex a writer
//!   could be holding.
//!
//! Frames are shared (`Arc<[u8]>`): a block relayed to twenty peers is
//! serialized once and stored once.
//!
//! # Memory
//!
//! A frame is accepted when the queue is empty, whatever its size — a single
//! message always gets through — or when the queue stays within
//! [`OUTBOX_MAX_BYTES`]. A peer therefore pins at most one frame being written
//! plus that bound, a few mebibytes.

use std::collections::VecDeque;
use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Bytes a peer's queue may hold beyond the frame being written.
///
/// Broadcasts are small (inventories of 36 bytes per item, compact
/// announcements): four mebibytes is tens of thousands of them, far more than
/// a reading peer ever lets pile up. A peer that does pile them up is not
/// reading.
pub const OUTBOX_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Stack of a writer thread. It does nothing but `write_all` on a slice.
const WRITER_STACK: usize = 256 * 1024;

/// Outcome of a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// The frame will be written.
    Queued,
    /// The queue was full: the frame was dropped for this peer.
    Full,
    /// The connection is closed.
    Closed,
}

struct State {
    queue: VecDeque<Arc<[u8]>>,
    bytes: usize,
    closed: bool,
}

/// A peer's outgoing queue. See the [module documentation](self).
pub struct Outbox {
    state: Mutex<State>,
    /// Signals the writer: a frame arrived, or the queue closed.
    ready: Condvar,
    /// Signals waiting producers: room was made, or the queue closed.
    room: Condvar,
    /// A clone of the socket, used only to shut it down.
    socket: TcpStream,
}

impl Outbox {
    /// Starts the writer thread of `stream`. The stream's write timeout must
    /// already be set: it is what ends a write to a peer that reads nothing.
    pub fn start(stream: TcpStream) -> std::io::Result<Arc<Outbox>> {
        let socket = stream.try_clone()?;
        let outbox = Arc::new(Outbox {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            ready: Condvar::new(),
            room: Condvar::new(),
            socket,
        });
        let o = outbox.clone();
        std::thread::Builder::new()
            .name("q21-peer-writer".into())
            .stack_size(WRITER_STACK)
            .spawn(move || o.write_loop(stream))?;
        Ok(outbox)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Nothing panics while holding this lock; recovering keeps a poisoned
        // queue usable rather than taking the node down with it.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn fits(s: &State, len: usize) -> bool {
        s.queue.is_empty() || s.bytes.saturating_add(len) <= OUTBOX_MAX_BYTES
    }

    fn enqueue(&self, s: &mut State, frame: Arc<[u8]>) {
        s.bytes += frame.len();
        s.queue.push_back(frame);
        self.ready.notify_one();
    }

    /// Queues `frame` without ever waiting.
    pub fn push(&self, frame: Arc<[u8]>) -> Push {
        let mut s = self.lock();
        if s.closed {
            return Push::Closed;
        }
        if !Self::fits(&s, frame.len()) {
            return Push::Full;
        }
        self.enqueue(&mut s, frame);
        Push::Queued
    }

    /// Queues `frame`, waiting up to `timeout` for room. A peer that leaves no
    /// room for that long is not reading: its connection is closed.
    pub fn push_wait(&self, frame: Arc<[u8]>, timeout: Duration) -> Push {
        let deadline = Instant::now() + timeout;
        let mut s = self.lock();
        loop {
            if s.closed {
                return Push::Closed;
            }
            if Self::fits(&s, frame.len()) {
                self.enqueue(&mut s, frame);
                return Push::Queued;
            }
            let now = Instant::now();
            if now >= deadline {
                drop(s);
                self.close();
                return Push::Closed;
            }
            s = self
                .room
                .wait_timeout(s, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Closes the connection: pending frames are dropped, the socket is shut
    /// down in both directions — which also ends the peer's read loop. Never
    /// waits for a write in progress.
    pub fn close(&self) {
        {
            let mut s = self.lock();
            if s.closed {
                return;
            }
            s.closed = true;
            s.queue.clear();
            s.bytes = 0;
        }
        self.ready.notify_all();
        self.room.notify_all();
        let _ = self.socket.shutdown(Shutdown::Both);
    }

    /// Is the connection closed?
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Bytes waiting, not counting the frame being written.
    pub fn queued_bytes(&self) -> usize {
        self.lock().bytes
    }

    fn write_loop(&self, mut stream: TcpStream) {
        loop {
            let frame = {
                let mut s = self.lock();
                loop {
                    if s.closed {
                        return;
                    }
                    if let Some(f) = s.queue.pop_front() {
                        s.bytes -= f.len();
                        break f;
                    }
                    s = self.ready.wait(s).unwrap_or_else(|e| e.into_inner());
                }
            };
            self.room.notify_all();
            // The write happens with no lock held: a stalled peer stalls this
            // thread, and nothing else.
            if stream
                .write_all(&frame)
                .and_then(|_| stream.flush())
                .is_err()
            {
                self.close();
                return;
            }
        }
    }
}

impl Drop for Outbox {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        (a, b)
    }

    fn frame(n: usize, byte: u8) -> Arc<[u8]> {
        vec![byte; n].into()
    }

    #[test]
    fn frames_arrive_in_order() {
        let (a, mut b) = pair();
        let o = Outbox::start(a).unwrap();
        for i in 0..100u8 {
            assert_eq!(o.push(frame(1000, i)), Push::Queued);
        }
        let mut got = vec![0u8; 100 * 1000];
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b.read_exact(&mut got).unwrap();
        for i in 0..100usize {
            assert!(got[i * 1000..(i + 1) * 1000].iter().all(|x| *x == i as u8));
        }
    }

    /// The defect itself: a peer that reads nothing must not hold the thread
    /// that writes to it — nor, through it, everyone else.
    #[test]
    fn a_peer_that_reads_nothing_never_blocks_the_producer() {
        let (a, _b) = pair(); // `_b` is never read
        a.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let o = Outbox::start(a).unwrap();
        let start = Instant::now();
        let mut full = 0;
        // Far more than the socket buffers and the queue together can hold.
        for _ in 0..400 {
            if o.push(frame(256 * 1024, 7)) == Push::Full {
                full += 1;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "{:?}",
            start.elapsed()
        );
        assert!(full > 0, "the queue must have filled up");
        assert!(o.queued_bytes() <= OUTBOX_MAX_BYTES);
    }

    /// A single frame larger than the bound still goes through.
    #[test]
    fn one_oversized_frame_is_accepted_when_the_queue_is_empty() {
        let (a, mut b) = pair();
        let o = Outbox::start(a).unwrap();
        let big = OUTBOX_MAX_BYTES + 1000;
        assert_eq!(o.push(frame(big, 3)), Push::Queued);
        let mut got = vec![0u8; big];
        b.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        b.read_exact(&mut got).unwrap();
        assert!(got.iter().all(|x| *x == 3));
    }

    /// Closing never waits for a write that is stuck, and ends the reading
    /// side too.
    #[test]
    fn close_is_immediate_even_with_a_stuck_write() {
        let (a, _b) = pair();
        a.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut reader = a.try_clone().unwrap();
        let o = Outbox::start(a).unwrap();
        for _ in 0..100 {
            o.push(frame(256 * 1024, 1));
        }
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        o.close();
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(o.is_closed());
        assert_eq!(o.push(frame(10, 1)), Push::Closed);
        // The read side of our own socket sees the shutdown.
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(matches!(reader.read(&mut buf), Ok(0) | Err(_)));
    }

    /// A reply waits for room, within its deadline, then gives up and closes.
    #[test]
    fn push_wait_waits_for_room_then_closes() {
        let (a, mut b) = pair();
        a.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let o = Outbox::start(a).unwrap();
        while o.push(frame(256 * 1024, 2)) == Push::Queued {}
        // The peer starts reading: room is made, the wait succeeds.
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0u8; 1 << 20];
            let mut total = 0usize;
            b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            while total < 8 << 20 {
                match b.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total += n,
                }
            }
            b
        });
        assert_eq!(
            o.push_wait(frame(256 * 1024, 2), Duration::from_secs(10)),
            Push::Queued
        );
        let b = reader.join().unwrap();
        // Now nobody reads. Fill until the kernel buffers are saturated too:
        // the queue stays full even after a pause.
        loop {
            while o.push(frame(256 * 1024, 2)) == Push::Queued {}
            std::thread::sleep(Duration::from_millis(200));
            if o.push(frame(256 * 1024, 2)) == Push::Full {
                break;
            }
        }
        // The wait times out and closes the connection.
        let start = Instant::now();
        assert_eq!(
            o.push_wait(frame(256 * 1024, 2), Duration::from_millis(300)),
            Push::Closed
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(o.is_closed());
        drop(b);
    }

    /// A write that fails closes the outbox: the peer's read loop then ends,
    /// and the node drops it.
    #[test]
    fn a_failed_write_closes_the_outbox() {
        let (a, b) = pair();
        let o = Outbox::start(a).unwrap();
        drop(b);
        let start = Instant::now();
        while !o.is_closed() && start.elapsed() < Duration::from_secs(5) {
            o.push(frame(64 * 1024, 9));
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(o.is_closed());
    }
}
