//! UDP link bindings and links for sakuya over a tokio runtime.
//!
//! A [`UdpBinding`] is one UDP socket. It takes new links as datagrams from
//! new peers arrive ([`AcceptingLinkBinding`](sakuya_link::AcceptingLinkBinding))
//! and sets up links to the peers it is asked to reach
//! ([`ConnectingLinkBinding`](sakuya_link::ConnectingLinkBinding)); each
//! [`UdpLink`] is one peer, from one local address, and all of them share
//! the socket. The links report the instants of their arrivals and sends on
//! the clock the binding was given, which the endpoint composed with them
//! uses as well.
//!
//! The socket does not fragment and ignores the path MTU the kernel learns,
//! reads and marks ECN, takes IPv4 on an IPv6 socket bound to the unspecified
//! address, and batches with GSO and GRO when the kernel can
//! ([`UdpBinding`]). It stops using GSO or ECN only once a send without it has
//! gone through, since the kernel refuses a send for these options with an
//! error that a datagram or a peer can cause as well ([`UdpLink`]).
//!
//! Whichever receive or accept of a binding holds the reader's turn reads the
//! socket for all of them, with the turn handed on when it is done or
//! dropped; a datagram read goes into the queue of its link, so a dropped
//! receive loses none. Datagrams that cannot be replied to (from port 0, or
//! to a broadcast or multicast address) make no link, and the links not yet
//! accepted share one bound on the datagrams they hold
//! ([`UdpBindingConfig::max_unaccepted_datagrams`]).
//!
//! Only Linux is supported: on other targets the crate is empty.

#![cfg_attr(target_os = "linux", feature(impl_trait_in_assoc_type))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(target_os = "linux")]
mod binding;
#[cfg(target_os = "linux")]
mod link;
#[cfg(target_os = "linux")]
mod shared;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use binding::{ConnectError, UdpBinding, UdpBindingConfig};
#[cfg(target_os = "linux")]
pub use link::{LinkEndedError, SendDatagramError, SocketFailedError, UdpLink, UdpLocal};
#[cfg(target_os = "linux")]
pub use sys::BindError;
