//! The capabilities of the application's handles, to bring them in at
//! once: `use sakuya_connection::prelude::*;`.
//!
//! Each handle's capabilities are traits implemented on the handle, so that
//! code generic over handles asks for what it uses (application-handles
//! «各部分的能力分到三级句柄»); they are named here to be imported, not to
//! be renamed.

pub use crate::v1::application_handles::{
    established_layer::{
        AcceptDetachedStreams, AcceptDetachedStreamsOwned, AcceptStreams, AcceptStreamsOwned,
        OpenDetachedStreams, OpenDetachedStreamsOwned, OpenStreams, OpenStreamsOwned,
    },
    stream::{StreamRead, StreamWrite},
};

#[cfg(feature = "reset_stream_at")]
pub use crate::reset_stream_at::StreamResetAt;

#[cfg(feature = "datagram")]
pub use crate::datagram::application::{
    DatagramSend, Datagrams, DatagramsOwned, DetachedDatagrams,
};
