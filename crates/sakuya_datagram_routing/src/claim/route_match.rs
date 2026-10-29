//! What routing recorded about one candidate's match

/// What routing recorded about why one route entry matched a datagram.
///
/// Routing produces one value per candidate: the match basis, the connection
/// ID interpretation it used, the ranges it checked and the association
/// handles the deliverer needs. The mechanism keeps it with the candidate,
/// lends it to the factory and to every judgment, and hands it over with the
/// datagram in [`DatagramAssociatedState`](super::DatagramAssociatedState). It
/// is not evidence of authentication or acceptance.
///
/// Only routing creates it. Its contents are filled in by datagram routing;
/// at present it carries no information.
#[derive(Debug)]
pub struct DatagramRouteMatchInfo {
    _private: (),
}

impl DatagramRouteMatchInfo {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "created only by datagram routing in this crate")
    )]
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}
