//! The routing input: one received datagram and the link it arrived on

use std::rc::Rc;
use std::sync::Arc;

use sakuya_link::LinkId;

/// A link whose identity routing can read.
///
/// Routing needs only the identity of the link a datagram arrived on: zero
/// length connection IDs are looked up by the link binding that produced it,
/// which [`LinkId::binding_id`] gives. Remote addresses and other facts come
/// from the transport adapter and are not part of this trait.
pub trait LinkIdentity {
    /// The identity of this link.
    fn link_id(&self) -> &LinkId;
}

impl LinkIdentity for LinkId {
    fn link_id(&self) -> &LinkId {
        self
    }
}

impl<Link: LinkIdentity + ?Sized> LinkIdentity for &Link {
    fn link_id(&self) -> &LinkId {
        (**self).link_id()
    }
}

impl<Link: LinkIdentity + ?Sized> LinkIdentity for Arc<Link> {
    fn link_id(&self) -> &LinkId {
        (**self).link_id()
    }
}

impl<Link: LinkIdentity + ?Sized> LinkIdentity for Rc<Link> {
    fn link_id(&self) -> &LinkId {
        (**self).link_id()
    }
}

/// One complete UDP datagram as a link delivered it, with that link.
///
/// It keeps only the complete payload and the link. The link identity, and
/// through it the link binding identity, are read from the link when needed
/// rather than stored again. Every datagram has exactly one original that a
/// candidate can take.
///
/// It is the datagram type of the claim mechanism: its bytes are the payload.
#[derive(Debug)]
pub struct ReceivedDatagram<Payload, Link> {
    payload: Payload,
    link: Link,
}

impl<Payload, Link> ReceivedDatagram<Payload, Link> {
    /// Pairs a received payload with the link it arrived on.
    pub fn new(payload: Payload, link: Link) -> Self {
        Self { payload, link }
    }

    /// The complete payload.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// The link the datagram arrived on.
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Returns the payload and the link.
    pub fn into_parts(self) -> (Payload, Link) {
        (self.payload, self.link)
    }
}

impl<Payload: AsRef<[u8]>, Link> AsRef<[u8]> for ReceivedDatagram<Payload, Link> {
    fn as_ref(&self) -> &[u8] {
        self.payload.as_ref()
    }
}
