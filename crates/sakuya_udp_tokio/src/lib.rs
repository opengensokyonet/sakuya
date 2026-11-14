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
