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
//! The driver lends each call, on each poll, the data of its node and of
//! the nodes above it ([`take::Lineage`]) and the other nodes
//! ([`others::OtherNodes`]). What a lend takes mutably is recorded; the
//! driver then rereads what reads those components: their deadlines and
//! their rereads, round after round until nothing changes. Calls hand over
//! [`request::StructureRequest`]s to build, end or move nodes; expiries and
//! rereads return them; the driver applies them at once. Time comes from
//! one [`clock::MonotonicClock`], read once in each poll.
//!
//! QUIC version 1 is the part [`v1::Part`]. So far its shares hold the
//! keys, the transport parameters, the idle timeout, the entries of the
//! logical links and the roles of the link paths; it has no calls yet.
#![feature(associated_type_defaults)]
#![warn(missing_docs)]

pub mod call;
pub mod clock;
pub mod component;
pub mod driver;
pub mod layer;
pub mod others;
pub mod request;
pub mod share;
pub mod take;
pub mod tree;
pub mod v1;
