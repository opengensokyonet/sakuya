//! What the retention measurements share: a global allocator that counts
//! the live heap bytes of each thread, and a UDP binding of
//! \`sakuya_udp_tokio\` that two peers send to over the loopback interface.
//!
//! The binding reads the socket into blocks of 256 KiB
//! (\`sakuya_udp_tokio/src/shared.rs\`, \`BUFFER_SIZE\`, \`receive_once\`) and
//! hands each datagram out as a slice of its block. One peer, the attacker,
//! sends small datagrams whose bytes a test keeps; the other sends enough
//! datagrams in between to use up more than a block, so that each kept
//! datagram is in a block of its own. The other peer's datagrams are
//! dropped as soon as they are received.

#![allow(dead_code, reason = "each test program uses a part")]

use core::{
    cell::Cell,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    net::UdpSocket,
};

use bytes::Bytes;
use sakuya_clock_tokio::TokioClock;
use sakuya_link::{AcceptingLinkBinding, Link};
use sakuya_udp_tokio::{UdpBinding, UdpBindingConfig, UdpLink};

// ---- live heap bytes of the current thread ----

thread_local! {
    static LIVE: Cell<i64> = const { Cell::new(0) };
}

fn add_live(change: i64) {
    let _ = LIVE.try_with(|live| live.set(live.get() + change));
}

/// The bytes the current thread has allocated and not freed, with
/// [\`LiveBytes\`] as the global allocator.
pub fn live() -> i64 {
    LIVE.try_with(Cell::get).unwrap_or(0)
}

/// The system allocator, counting the live bytes of each thread.
pub struct LiveBytes;

// SAFETY: every operation is forwarded unchanged to \`System\`; the counting
// touches only a const-initialised thread-local \`Cell<i64>\`, which neither
// allocates nor registers a destructor.
#[allow(unsafe_code, reason = "a global allocator that counts")]
unsafe impl GlobalAlloc for LiveBytes {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds \`alloc\`'s contract.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            add_live(layout.size() as i64);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as in \`alloc\`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            add_live(layout.size() as i64);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        add_live(-(layout.size() as i64));
        // SAFETY: the caller upholds \`dealloc\`'s contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds \`realloc\`'s contract.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            add_live(new_size as i64 - layout.size() as i64);
        }
        new
    }
}

// ---- the setting ----

/// The receive windows of the default endpoint configuration
/// (\`sakuya_endpoint_v1/src/v1.rs\`, \`default_transport_parameters\`): 16 MiB
/// on the connection, 4 MiB on a bidirectional stream.
pub const CONNECTION_WINDOW: u32 = 16 << 20;
pub const STREAM_WINDOW: u32 = 4 << 20;

/// The block the UDP binding reads into (\`sakuya_udp_tokio/src/shared.rs\`,
/// \`BUFFER_SIZE\`: four receives of 64 KiB).
pub const BLOCK: usize = 256 * 1024;

/// The attacker's datagram: about what a short 1-RTT packet with a few
/// bytes of STREAM data comes to.
pub const CARRIER_LEN: usize = 40;

/// The other peer's datagrams, enough of them to use up more than a block.
const FILLER_LEN: usize = 1200;
const FILLERS: usize = BLOCK / FILLER_LEN + 1;

/// Runs \`test\` on a current-thread runtime, so that the counts of
/// [\`live\`] see all of it.
pub fn run(test: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime builds")
        .block_on(test);
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("finishes in time")
}

async fn next(link: &UdpLink<TokioClock>) -> bytes::BytesMut {
    within(link.recv())
        .await
        .expect("the link has not ended")
        .into_parts()
        .0
}

fn peer() -> UdpSocket {
    UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a loopback socket binds")
}

/// A binding and the two peers that send to it, each with its accepted
/// link.
pub struct Wire {
    _server: UdpBinding<TokioClock>,
    to: SocketAddr,
    attacker: UdpSocket,
    other: UdpSocket,
    from_attacker: UdpLink<TokioClock>,
    from_other: UdpLink<TokioClock>,
}

impl Wire {
    pub async fn new() -> Self {
        let server = UdpBinding::bind(
            UdpBindingConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            TokioClock,
        )
        .expect("a loopback socket binds");
        let to = server.local_address();
        let attacker = peer();
        let other = peer();
        attacker.send_to(&[0; CARRIER_LEN], to).unwrap();
        let from_attacker = within(server.accept()).await.unwrap();
        drop(next(&from_attacker).await);
        other.send_to(&[0; FILLER_LEN], to).unwrap();
        let from_other = within(server.accept()).await.unwrap();
        drop(next(&from_other).await);
        Self {
            _server: server,
            to,
            attacker,
            other,
            from_attacker,
            from_other,
        }
    }

    /// The attacker's next datagram, as the binding hands it out.
    pub async fn carrier(&self) -> Bytes {
        self.attacker.send_to(&[1; CARRIER_LEN], self.to).unwrap();
        next(&self.from_attacker).await.freeze()
    }

    /// The other peer's datagrams, more than a block of them, each dropped
    /// once received.
    pub async fn fill(&self) {
        for _ in 0..FILLERS {
            self.other.send_to(&[2; FILLER_LEN], self.to).unwrap();
            drop(next(&self.from_other).await);
        }
    }
}

/// A local close cause for the stream parts.
#[derive(Debug)]
pub struct CloseCause;

impl core::fmt::Display for CloseCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("test close")
    }
}

impl core::error::Error for CloseCause {}
