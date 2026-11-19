//! The credential of a handle ([`HandleCredential`]) and what a capability
//! holds it through ([`CredentialPointer`]).
//!
//! A capability of a stream's end, or of a datagram's ticket, is the way it
//! reaches the component it acts on together with a pointer to the
//! credential of what it holds. The credential has no content: holding it
//! is what says that the end or the ticket is still held. The component
//! hears that it is not once the last holder hands the credential back
//! through the capability's way, as its drop does; it then reclaims what
//! the credential stood for.
//!
//! An end is opened or accepted with the credential itself, by value; the
//! application turns it into a shared one ([`Arc`] or [`Rc`]) where it
//! wants several capabilities of the same end, and those can then be
//! cloned. Whatever the pointer, exactly one holder gets the credential
//! back.

use alloc::{rc::Rc, sync::Arc};

/// The credential of a handle (`HandleCredential`): that a stream's end,
/// or a datagram's ticket, is still held. It has no content and cannot be
/// cloned; only the connection's capabilities make one.
#[derive(Debug)]
pub struct HandleCredential {
    _private: (),
}

impl HandleCredential {
    /// The credential of an end or a ticket just given out.
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

/// What a capability holds its credential through (`CredentialPointer`):
/// the credential itself, or a shared pointer to it.
pub trait CredentialPointer: Sized {
    /// The credential, for the last holder of it; `None` for any other.
    fn into_credential(self) -> Option<HandleCredential>;
}

/// The credential itself has one holder.
impl CredentialPointer for HandleCredential {
    fn into_credential(self) -> Option<HandleCredential> {
        Some(self)
    }
}

/// The last of the clones gets the credential back ([`Arc::into_inner`]).
impl CredentialPointer for Arc<HandleCredential> {
    fn into_credential(self) -> Option<HandleCredential> {
        Arc::into_inner(self)
    }
}

/// The last of the clones gets the credential back ([`Rc::into_inner`]).
impl CredentialPointer for Rc<HandleCredential> {
    fn into_credential(self) -> Option<HandleCredential> {
        Rc::into_inner(self)
    }
}
