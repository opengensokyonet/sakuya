//! The capabilities a server's handshake consults, with implementations
//! for plain Web connections.
//!
//! Each capability is a trait the server's handshake takes as a parameter:
//!
//! - [`choice`]: which cipher suite and key exchange group to use, from what
//!   the ClientHello offers.
//! - [`targets`]: which target the ClientHello asks for, and its
//!   application protocol.
//! - [`ticket`]: which session tickets to issue, and which offered ones to
//!   accept.
//!
//! The handshake checks what a capability returns against the protocol, so
//! an implementation decides within the rules and does not enforce them.

pub mod choice;
pub mod targets;
pub mod ticket;
