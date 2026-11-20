//! QUIC connections for sakuya: the tree of a connection's state and the
//! driver of its calls.
//!
//! A connection is one future, [`driver::ConnectionDriver`], polled from
//! the moment it is made until it ends. Its state is a tree of nodes
//! ([`tree`]): the connection, its logical link entries and logical paths,
//! the link paths of each logical path, and two kinds of child nodes that
//! come and go, the established layer and the recovery layer
//! ([`layer`]). A composition is a list of parts (`HList![v1::Part, …]`) and
//! a type of choices; every part has a share in every layer
//! ([`share::LayerShare`]): its data components ([`component`]) and the
//! kinds of its calls ([`call`]).
//!
//! The driver wakes exactly the calls whose wakers were called, folding the
//! wakes between two polls into one wake of its own waker ([`driver`]). It
//! lends each call, on each poll, the data of its node and of
//! the nodes above it ([`take::Lineage`]) and the other nodes
//! ([`others::OtherNodes`]). What a lend changes it publishes as
//! component events ([`component_event`]), and what it writes of the
//! components with a deadline is recorded; the driver then hands the events
//! to what subscribes to them and reads those deadlines again, round after
//! round until nothing more happens. Calls hand over
//! [`request::StructureRequest`]s to build, end or move nodes; expiries and
//! the handlers of events return them; the driver applies them at once. What reaches the
//! connection from outside its tree is taken in at the start of each poll,
//! before any call, by the components that act before the calls. Time
//! comes from one [`clock::MonotonicClock`], read once in each poll.
//!
//! QUIC version 1 is the part [`v1::Part`]. Its shares hold the keys of each
//! encryption level, the transport parameters, the entries of the logical
//! links and the roles of the link paths, and its modules hold the
//! handshake, the receiving and sending of packets with the frames of
//! version 1, loss detection and recovery through `sakuya_recovery`
//! ([`v1::loss_detection`], [`v1::recovery`]), the streams ([`v1::streams`]),
//! connection ID management ([`v1::connection_ids`]), key updates
//! ([`v1::key_update`]), address tokens ([`v1::address_token`]), Retry and
//! Version Negotiation handling ([`v1::retry`], [`v1::version_negotiation`]),
//! stateless reset detection ([`v1::stateless_reset`]), the idle timeout
//! ([`v1::idle`]) and the closing of the connection ([`v1::close`]). Its
//! calls are the advancing call of the connection, which runs the handshake, the
//! receiving call of each logical path and the one that migrates a client
//! to its server's preferred address, and the sending call of each link
//! path.
//!
//! The application's handles to a connection are the connection handle,
//! which asks for the close and waits for the reason of the close, the
//! handshake's result and the handles of the established layers, the handle
//! of an established layer, which opens and accepts streams, and
//! asynchronous stream writers and readers over `nitori_io`
//! ([`v1::application_handles`]).
//!
//! The host may choose a receiver of the connection's events, for qlog or
//! for tests ([`v1::events`]): packets sent, received, dropped and declared
//! lost, recovery metrics, transport parameters, the version and ALPN, the
//! connection's states, its keys and its close, and, from the application's
//! threads, the states of streams' parts, the stream data moved between the
//! application and the connection, and the events of the parts, such as the
//! datagrams of DATAGRAM moved and dropped for full queues. By default
//! nothing receives them, and the places that would give them compile to
//! nothing.
//!
//! Each extension of version 1 that sakuya implements has a package of its
//! own for this layer, which adds a part to the composition:
//! `sakuya_connection_datagram` for the DATAGRAM frame of RFC 9221, and
//! `sakuya_connection_reset_stream_at` for the reliable stream reset.
#![feature(
    allow_internal_unstable,
    associated_type_defaults,
    impl_trait_in_assoc_type,
    yield_expr
)]
#![expect(
    internal_features,
    reason = "`composition!` writes opaque associated types for crates that do not enable them"
)]
#![warn(missing_docs)]

extern crate alloc;

/// Declares an item that the tests of other packages use: public with the
/// feature `test-util`, and this crate's own otherwise. The item is written
/// with `pub`.
macro_rules! test_util_pub {
    ($(#[$attribute:meta])* pub $($item:tt)*) => {
        $(#[$attribute])*
        #[cfg(feature = "test-util")]
        pub $($item)*
        $(#[$attribute])*
        #[cfg(not(feature = "test-util"))]
        pub(crate) $($item)*
    };
}

pub mod call;
pub mod clock;
pub mod component;
pub mod component_event;
pub mod composition;
pub mod connection_id;
pub mod dispatch;
pub mod driver;
pub mod error;
pub mod feedback;
pub mod frame_source;
pub mod layer;
pub mod others;
pub mod prelude;
pub mod request;
pub mod role;
pub mod send_strategy;
pub mod share;
pub mod shared;
pub mod take;
pub mod tree;
pub mod v1;
pub mod write;
