//! What a capability holds the credential of a handle through
//! ([`CredentialPointer`]).
//!
//! A capability of a stream's end, or of a datagram's ticket, is the way it
//! reaches the component it acts on together with a pointer to the
//! credential of what it holds. The credential is a type of the component
//! that gives it out, and is made by that component: nothing else can make
//! one. It names the stream's end or the datagram's ticket that is still
//! held, as a stream's writer
//! ([`StreamWriterCredential`](crate::v1::streams::StreamWriterCredential))
//! or reader
//! ([`StreamReaderCredential`](crate::v1::streams::StreamReaderCredential))
//! does; holding it is what says that the end or the ticket is still held.
//! The component hears that it is not once the last holder hands the
//! credential back through the capability's way, as its drop does; it then
//! reclaims what the credential names.
//!
//! An end is opened or accepted with the credential itself, by value; the
//! application turns it into a shared one ([`Arc`] or [`Rc`]) where it
//! wants several capabilities of the same end, and those can then be
//! cloned. Whatever the pointer, exactly one holder gets the credential
//! back.

use alloc::{rc::Rc, sync::Arc};

mod sealed {
    use alloc::{rc::Rc, sync::Arc};

    /// Only the credential itself, [`Arc`] and [`Rc`] point to a
    /// credential.
    pub trait Pointer<Cr> {}

    impl<Cr> Pointer<Cr> for Cr {}
    impl<Cr> Pointer<Cr> for Arc<Cr> {}
    impl<Cr> Pointer<Cr> for Rc<Cr> {}
}

/// What a capability holds the credential `Cr` through
/// (`CredentialPointer`): the credential itself, or a shared pointer to it,
/// [`Arc`] or [`Rc`].
///
/// These three are its only implementations, and no other can be written:
/// a pointer lends and gives back the credential it holds, so a capability
/// hands back the credential of what it holds and no other.
pub trait CredentialPointer<Cr>: sealed::Pointer<Cr> + Sized {
    /// The credential pointed to.
    fn credential(&self) -> &Cr;

    /// The credential, for the last holder of it; `None` for any other.
    fn into_credential(self) -> Option<Cr>;
}

/// The credential itself has one holder.
impl<Cr> CredentialPointer<Cr> for Cr {
    fn credential(&self) -> &Cr {
        self
    }

    fn into_credential(self) -> Option<Cr> {
        Some(self)
    }
}

/// The last of the clones gets the credential back ([`Arc::into_inner`]).
impl<Cr> CredentialPointer<Cr> for Arc<Cr> {
    fn credential(&self) -> &Cr {
        self
    }

    fn into_credential(self) -> Option<Cr> {
        Arc::into_inner(self)
    }
}

/// The last of the clones gets the credential back ([`Rc::into_inner`]).
impl<Cr> CredentialPointer<Cr> for Rc<Cr> {
    fn credential(&self) -> &Cr {
        self
    }

    fn into_credential(self) -> Option<Cr> {
        Rc::into_inner(self)
    }
}
