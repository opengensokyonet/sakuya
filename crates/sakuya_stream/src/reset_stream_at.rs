//! The reliable stream reset extension, as specified by the Internet-Draft
//! [draft-ietf-quic-reliable-stream-reset-11]. The draft is not an RFC and
//! may still change.
//!
//! With the extension an endpoint can reset a stream and still deliver a
//! prefix of it reliably: a `RESET_STREAM_AT` frame states a reliable size
//! next to the error code and the final size. The send direction is in
//! [`send`], the receive direction in [`receive`].
//!
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html

pub mod receive;
pub mod send;
