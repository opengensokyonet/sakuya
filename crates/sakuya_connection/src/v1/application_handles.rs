//! The handles of a connection of version 1 in the application's hands:
//! the connection handle ([`connection`]), the handle of an established
//! layer ([`established_layer`]), and the stream writers and readers
//! ([`stream`]).
//!
//! The connection handle is there from the moment the connection is made:
//! it asks for the close, waits for the reason, the handshake's result and
//! the handles of the established layers. It shares a cell with the
//! connection node ([`connection::ConnectionHandleCell`]), which follows
//! the record of why the connection closed and learns from the advancing
//! call and the stream set of the established layer what happened. An
//! established layer's handle opens and accepts the streams of that one
//! layer; their writers and readers end with it.
//!
//! What each handle can do is a trait ([`established_layer::OpenStreams`],
//! [`established_layer::AcceptStreams`], [`stream::StreamWrite`],
//! [`stream::StreamRead`]), implemented on the handle, with the place of
//! the intent the handle publishes inferred where it is called; the
//! [prelude](crate::prelude) brings them in. The bytes of a stream are read
//! and written through nitori_io's `Read`, `ReadChunk` and `Write`.

pub mod connection;
pub mod established_layer;
pub mod stream;
