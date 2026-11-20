//! What sakuya's own tests and test programs share; nothing here is for a
//! production composition.
//!
//! - [`verify`]: a certificate verifier for test roots, which checks the
//!   path, names and signatures as usual but skips Certificate
//!   Transparency, since test certificates carry no SCTs.
//! - [`pki`]: Ed25519 test roots and leaf certificates, built in memory.
//! - [`measure`]: counters of heap allocations and of a task's polls and
//!   wakes, for measuring a run.
//! - [`network`]: a network in memory between a server and its clients,
//!   with link bindings an endpoint takes and impairments (loss,
//!   reordering, duplication, corruption, blackholes, path MTU changes,
//!   rebinding) that follow from a seed, on tokio's paused time.
//!
//! The impairment tests of this package receive the connections' events with
//! `sakuya_qlog` and read the files back.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod measure;
pub mod network;
pub mod pki;
pub mod verify;
