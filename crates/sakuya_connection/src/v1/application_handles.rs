//! The handles of a connection of version 1 in the application's hands:
//! the connection handle ([`connection`]), the handle of an established
//! layer ([`established_layer`]), the stream writers and readers
//! ([`stream`]), the capabilities of a stream's parts through the shared
//! connection ([`shared_stream`]), and the credential a capability holds
//! ([`credential`]).
//!
//! The connection handle and the handles of the established layers hold
//! the connection in the wrapper the host chose
//! ([`SharedConnection`](crate::shared::SharedConnection)), and each of
//! their operations borrows it once: the connection handle is lent the
//! connection node, whose state ([`connection::ConnectionHandleState`])
//! follows the record of why the connection closed and learns from the
//! advancing call and the stream set what happened; an established
//! layer's handle is lent its layer while it is there, and opens and
//! accepts the streams of that one layer. A stream writer or reader holds
//! the capability of its part and the pointer to its credential: through
//! the shared connection, lent the layer for each operation, or apart from
//! it, with what the stream set gave; it ends with the layer, and the
//! stream set hears that the last holder let go once the credential comes
//! back.
//!
//! What each handle can do is a trait ([`established_layer::OpenStreams`],
//! [`established_layer::AcceptStreams`], [`stream::StreamWrite`],
//! [`stream::StreamRead`]), implemented on the handle, with where the
//! components it uses are and the place of the intent it publishes
//! inferred where it is called; the [prelude](crate::prelude) brings them
//! in. The bytes of a stream are read and written through nitori_io's
//! `Read`, `ReadChunk` and `Write`.

pub mod connection;
pub mod credential;
pub mod established_layer;
pub mod shared_stream;
pub mod stream;
