//! The handles of a connection of version 1 in the application's hands:
//! the connection handle ([`connection`]), the handle of an established
//! layer ([`established_layer`]), and the stream writers and readers
//! ([`stream`]).
//!
//! The connection handle and the handles of the established layers hold
//! the connection in the wrapper the host chose
//! ([`SharedConnection`](crate::shared::SharedConnection)), and each of
//! their operations borrows it once: the connection handle is lent the
//! connection node, whose state ([`connection::ConnectionHandleState`])
//! follows the record of why the connection closed and learns from the
//! advancing call and the stream set what happened; an established
//! layer's handle is lent its layer while it is there, and opens and
//! accepts the streams of that one layer. The stream writers and readers
//! hold what the stream set gave them, and end with the layer.
//!
//! What each handle can do is a trait ([`established_layer::OpenStreams`],
//! [`established_layer::AcceptStreams`], [`stream::StreamWrite`],
//! [`stream::StreamRead`]), implemented on the handle, with where the
//! components it uses are and the place of the intent it publishes
//! inferred where it is called; the [prelude](crate::prelude) brings them
//! in. The bytes of a stream are read and written through nitori_io's
//! `Read`, `ReadChunk` and `Write`.

pub mod connection;
pub mod established_layer;
pub mod stream;
