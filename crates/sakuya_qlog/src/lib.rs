//! qlog for sakuya's connections: the events of a connection written as
//! one JSON-SEQ file, as the qlog drafts describe them
//! ([draft-ietf-quic-qlog-main-schema-15], the QUIC events of
//! [draft-ietf-quic-qlog-quic-events-14]). The drafts are not RFCs and may
//! still change.
//!
//! A host that wants qlog chooses [`QlogWriter`] as the receiver of the
//! connection's events
//! ([`HostChoices::Events`](sakuya_connection::v1::HostChoices::Events)),
//! and gives each connection a [`QlogConfig`] with the directory to write
//! into and the clock to read the events' times from. A connection given
//! no directory, or whose file cannot be made, records nothing; the
//! connection never fails for its log.
//!
//! The frames of a packet are read again from its plaintext and written
//! as the parts of the composition describe them ([`QlogPart`]): only a
//! host that chooses [`QlogWriter`] needs every part of its composition to
//! implement it, which version 1 and the extensions of this crate's
//! features do. The transport parameters are written as each parameter
//! type describes itself ([`QlogParameter`]).
//!
//! The file is named after the connection, `{ODCID}_{server|client}.sqlog`
//! in the directory, where the ODCID is the Destination Connection ID of
//! the client's first Initial packet, in lower case hexadecimal
//! (main-schema §12.1, quic-events §1.1); a file of that name is
//! replaced.
//!
//! Not written: the TLS secrets of `key_updated` (a key log has them), the
//! tokens of NEW_TOKEN frames, which let a later connection skip address
//! validation, and the contents of streams and datagrams; their lengths
//! are. The Ack Delay of ACK frames is not written either: qlog has it in
//! milliseconds, and the frame alone does not tell the exponent it is
//! scaled by.
//!
//! [draft-ietf-quic-qlog-main-schema-15]: https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-15.html
//! [draft-ietf-quic-qlog-quic-events-14]: https://www.ietf.org/archive/id/draft-ietf-quic-qlog-quic-events-14.html

#![warn(missing_docs)]

use core::{
    fmt::{self, Write as _},
    marker::PhantomData,
    net::SocketAddr,
};
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use sakuya_clock::MonotonicClock;
use sakuya_connection::v1::{
    events::{
        CloseTrigger, ConnectionClosed, ConnectionEvents, ConnectionState, DataLocation,
        DataMovedAdditionalInfo, DatagramDropped, EventInitiator, EventsStart, KeyChange,
        LossTrigger, LostPacket, PacketEvents, PlainPacket, RecoveryMetrics, SharedEvents,
        StreamDataMoved, StreamStateChange,
    },
    receive::DropReason,
};
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::{
    connection::ImmediateClose, receive::ReceiveStreamState, send::SendStreamState,
};
use sakuya_wire::{
    parameters::ParametersOf,
    v1::{
        encryption_level::EncryptionLevel,
        role::Role,
        stream_id::{Directionality, StreamId},
        transport_parameters::{TransportParameterSlots, TransportParameterSpace},
    },
    version::Version,
};

#[cfg(feature = "datagram")]
mod datagram;
pub mod json;
mod packet;
mod parameters;
mod part;
#[cfg(feature = "reset_stream_at")]
mod reset_stream_at;
mod v1;

pub use parameters::{QlogParameter, QlogParameterSlots};
pub use part::{CarriedData, QlogPart, QlogParts};

use json::ObjectWriter;

/// The URI of the QUIC event schema of the draft this crate follows
/// (quic-events §2.1: a draft's URI ends in its number).
pub const QUIC_EVENT_SCHEMA: &str = "urn:ietf:params:qlog:events:quic-14";

/// What the qlog of one connection is made from.
#[derive(Debug, Clone)]
pub struct QlogConfig<C> {
    /// The directory the file is written into (the interop runner's
    /// `QLOGDIR`); `None` records nothing.
    pub dir: Option<PathBuf>,
    /// The clock the times of the events are read from, the connection's;
    /// `None` records nothing.
    pub clock: Option<C>,
}

impl<C> Default for QlogConfig<C> {
    fn default() -> Self {
        Self {
            dir: None,
            clock: None,
        }
    }
}

/// The receiver of a connection's events that writes them as qlog, for the
/// list of parts `L`, reading times from the clock `C`.
///
/// The driver's events and those the application's threads give through
/// the handle ([`QlogShared`]) go into one file under one lock, which also
/// reads the time of each: the file is in the order of time (main-schema
/// §7).
pub struct QlogWriter<L, C: MonotonicClock> {
    shared: QlogShared<C>,
    /// The side of the connection.
    role: Role,
    /// The recovery metrics written last, to write only what changed
    /// (quic-events §7.2).
    metrics: Option<RecoveryMetrics>,
    parts: PhantomData<fn() -> L>,
}

impl<L, C: MonotonicClock> fmt::Debug for QlogWriter<L, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QlogWriter")
            .field("recording", &self.shared.enabled())
            .finish_non_exhaustive()
    }
}

/// The handle a [`QlogWriter`] shares with the application's threads: the
/// file, under a lock; none when the connection records nothing.
pub struct QlogShared<C: MonotonicClock>(Option<Arc<Mutex<QlogFile<C>>>>);

impl<C: MonotonicClock> Clone for QlogShared<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<C: MonotonicClock> fmt::Debug for QlogShared<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("QlogShared")
            .field(&self.0.is_some())
            .finish()
    }
}

/// The file of one connection, with what writing an event takes.
struct QlogFile<C: MonotonicClock> {
    out: BufWriter<File>,
    clock: C,
    /// The time the events are relative to: when the connection was made.
    start: C::Instant,
    /// The record being written, kept to reuse its storage.
    record: Vec<u8>,
    /// A write failed: nothing more is written.
    failed: bool,
}

/// What `mutex` holds, whether or not a holder panicked: a record is written
/// whole into the buffer before it goes to the file, so a panic leaves at
/// most a record that is not written.
fn lock<X>(mutex: &Mutex<X>) -> MutexGuard<'_, X> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<C: MonotonicClock> QlogFile<C> {
    /// The file of the connection that starts as `start`, in `dir`, with
    /// its header written; `None` when the file cannot be made.
    fn create(dir: &std::path::Path, clock: C, start: &EventsStart) -> Option<Self> {
        let vantage = match start.role {
            Role::Server => "server",
            Role::Client => "client",
        };
        let odcid = start.original_destination_connection_id.as_bytes();
        let mut name = String::with_capacity(odcid.len() * 2 + 15);
        for byte in odcid {
            // writing to a String does not fail
            let _ = write!(name, "{byte:02x}");
        }
        let _ = write!(name, "_{vantage}.sqlog");
        let file = File::create(dir.join(name)).ok()?;
        let now = clock.now();
        let mut this = Self {
            out: BufWriter::new(file),
            clock,
            start: now,
            record: Vec::new(),
            failed: false,
        };
        this.write_record(|record| {
            record
                .str("file_schema", "urn:ietf:params:qlog:file:sequential")
                .str("serialization_format", "application/qlog+json-seq")
                .str("title", "sakuya")
                .object("trace", |trace| {
                    trace
                        .object("common_fields", |common| {
                            common
                                .hex("group_id", odcid)
                                .str("time_format", "relative_to_epoch")
                                .object("reference_time", |reference| {
                                    // a monotonic clock has no known epoch
                                    // (main-schema §7.1)
                                    reference
                                        .str("clock_type", "monotonic")
                                        .str("epoch", "unknown");
                                });
                        })
                        .object("vantage_point", |vantage_point| {
                            vantage_point.str("type", vantage);
                        })
                        .array("event_schemas", |schemas| {
                            schemas.str(QUIC_EVENT_SCHEMA);
                        });
                });
        });
        (!this.failed).then_some(this)
    }

    /// Writes one record of JSON-SEQ: RS, the object `members` writes, LF
    /// (RFC 7464, main-schema §11.2).
    fn write_record(&mut self, members: impl FnOnce(&mut ObjectWriter<'_>)) {
        if self.failed {
            return;
        }
        self.record.clear();
        self.record.push(0x1e);
        json::object(&mut self.record, members);
        self.record.push(b'\n');
        if self.out.write_all(&self.record).is_err() {
            self.failed = true;
        }
    }

    /// Writes the event `name`, whose data `data` writes, at the time read
    /// now.
    fn event(&mut self, name: &'static str, data: impl FnOnce(&mut ObjectWriter<'_>)) {
        let now = self.clock.now();
        // the clock is monotonic and `start` was read from it first
        let time = if now >= self.start {
            now - self.start
        } else {
            core::time::Duration::ZERO
        };
        self.write_record(|record| {
            record
                .millis("time", time)
                .str("name", name)
                .object("data", data);
        });
    }

    fn flush(&mut self) {
        if !self.failed && self.out.flush().is_err() {
            self.failed = true;
        }
    }
}

impl<C: MonotonicClock> QlogShared<C> {
    /// Writes the event `name`, if the connection records.
    fn event(&self, name: &'static str, data: impl FnOnce(&mut ObjectWriter<'_>)) {
        if let Some(file) = &self.0 {
            lock(file).event(name, data);
        }
    }

    fn flush(&self) {
        if let Some(file) = &self.0 {
            lock(file).flush();
        }
    }
}

impl<L, C: MonotonicClock> QlogWriter<L, C> {
    fn event(&self, name: &'static str, data: impl FnOnce(&mut ObjectWriter<'_>)) {
        self.shared.event(name, data);
    }
}

impl<L, C: MonotonicClock> Drop for QlogWriter<L, C> {
    fn drop(&mut self) {
        self.shared.flush();
    }
}

/// qlog's name of a packet's type, from its encryption level.
fn packet_type(level: EncryptionLevel) -> &'static str {
    match level {
        EncryptionLevel::Initial => "initial",
        EncryptionLevel::ZeroRtt => "0RTT",
        EncryptionLevel::Handshake => "handshake",
        EncryptionLevel::OneRtt => "1RTT",
    }
}

fn initiator(initiator: EventInitiator) -> &'static str {
    match initiator {
        EventInitiator::Local => "local",
        EventInitiator::Remote => "remote",
    }
}

fn key_type(key: KeyChange) -> &'static str {
    match (key.sender, key.level) {
        (Role::Client, EncryptionLevel::Initial) => "client_initial_secret",
        (Role::Server, EncryptionLevel::Initial) => "server_initial_secret",
        (Role::Client, EncryptionLevel::ZeroRtt) => "client_0rtt_secret",
        (Role::Server, EncryptionLevel::ZeroRtt) => "server_0rtt_secret",
        (Role::Client, EncryptionLevel::Handshake) => "client_handshake_secret",
        (Role::Server, EncryptionLevel::Handshake) => "server_handshake_secret",
        (Role::Client, EncryptionLevel::OneRtt) => "client_1rtt_secret",
        (Role::Server, EncryptionLevel::OneRtt) => "server_1rtt_secret",
    }
}

fn data_location(location: DataLocation) -> &'static str {
    match location {
        DataLocation::Application => "application",
        DataLocation::Transport => "transport",
        DataLocation::Network => "network",
    }
}

fn send_state(state: SendStreamState) -> &'static str {
    match state {
        SendStreamState::Ready => "ready",
        SendStreamState::Send => "send",
        SendStreamState::DataSent => "data_sent",
        SendStreamState::ResetSent => "reset_sent",
        SendStreamState::DataRecvd => "data_received",
        SendStreamState::ResetRecvd => "reset_received",
    }
}

fn receive_state(state: ReceiveStreamState) -> &'static str {
    match state {
        ReceiveStreamState::Recv => "receive",
        ReceiveStreamState::SizeKnown => "size_known",
        ReceiveStreamState::DataRecvd => "data_received",
        ReceiveStreamState::ResetRecvd => "reset_received",
        ReceiveStreamState::DataRead => "data_read",
        ReceiveStreamState::ResetRead => "reset_read",
    }
}

/// The version as qlog writes it: four bytes in hexadecimal.
fn version_hex(version: Version) -> [u8; 4] {
    version.get().to_be_bytes()
}

impl<I, L, C> ConnectionEvents<I> for QlogWriter<L, C>
where
    C: MonotonicClock + 'static,
{
    const ENABLED: bool = true;
    type Config = QlogConfig<C>;
    type Shared = QlogShared<C>;

    fn new(config: &QlogConfig<C>, start: &EventsStart) -> Self {
        let file = match (&config.dir, &config.clock) {
            (Some(dir), Some(clock)) => QlogFile::create(dir, clock.clone(), start),
            _ => None,
        };
        Self {
            shared: QlogShared(file.map(|file| Arc::new(Mutex::new(file)))),
            role: start.role,
            metrics: None,
            parts: PhantomData,
        }
    }

    fn enabled(&self) -> bool {
        self.shared.enabled()
    }

    fn shared(&self) -> QlogShared<C> {
        self.shared.clone()
    }

    fn connection_started(&mut self, _: I) {
        // the connection's events do not carry the link's addresses yet;
        // both ends are written without them
        self.event("quic:connection_started", |data| {
            data.object("local", |_| {}).object("remote", |_| {});
        });
    }

    fn packet_dropped(&mut self, _: I, level: Option<EncryptionLevel>, reason: &DropReason) {
        let (trigger, details) = match reason {
            DropReason::Duplicate { .. } => ("duplicate", "duplicate"),
            DropReason::NoReceiveKeys { .. } => ("keys_unavailable", "no_receive_keys"),
            DropReason::PayloadNotOpened { .. } => ("decryption_failure", "payload_not_opened"),
            DropReason::HeaderProtectionNotRemoved { .. } => {
                ("decryption_failure", "header_protection_not_removed")
            }
            DropReason::TokenFromServer => ("invalid", "token_from_server"),
            DropReason::OtherSourceConnectionId { .. } => ("invalid", "other_source_connection_id"),
            DropReason::NotProtected => ("invalid", "not_protected"),
            DropReason::NoLinkPath => ("general", "no_link_path"),
            DropReason::LinkPathNotAdmitted => ("general", "link_path_not_admitted"),
            DropReason::OldLocalAddress => ("general", "old_local_address"),
            DropReason::Draining => ("general", "draining"),
        };
        self.event("quic:packet_dropped", |data| {
            if let Some(level) = level {
                data.object("header", |header| {
                    header.str("packet_type", packet_type(level));
                });
            }
            data.object("details", |object| {
                object.str("reason", details);
            })
            .str("trigger", trigger);
        });
    }

    fn packet_lost(&mut self, _: I, lost: &LostPacket) {
        let packet_type = match lost.space {
            PacketNumberSpaceKind::Initial => "initial",
            PacketNumberSpaceKind::Handshake => "handshake",
            PacketNumberSpaceKind::ApplicationData => "1RTT",
        };
        self.event("quic:packet_lost", |data| {
            data.object("header", |header| {
                header
                    .str("packet_type", packet_type)
                    .u64("packet_number", lost.number);
            });
            match lost.trigger {
                Some(LossTrigger::TimeThreshold) => {
                    data.str("trigger", "time_threshold");
                }
                Some(LossTrigger::ProbeTimeout) => {
                    data.str("trigger", "pto_expired");
                }
                None => {}
            }
        });
    }

    fn recovery_metrics(&mut self, _: I, metrics: &RecoveryMetrics) {
        let last = self.metrics.replace(*metrics);
        let changed = |field: fn(&RecoveryMetrics) -> u128| {
            last.as_ref()
                .is_none_or(|last| field(last) != field(metrics))
        };
        let fields = [
            changed(|m| m.min_rtt.as_micros()),
            changed(|m| m.smoothed_rtt.as_micros()),
            changed(|m| m.latest_rtt.as_micros()),
            changed(|m| m.rtt_variance.as_micros()),
            changed(|m| m.congestion_window as u128),
            changed(|m| m.bytes_in_flight as u128),
        ];
        if !fields.contains(&true) {
            return;
        }
        self.event("quic:recovery_metrics_updated", |data| {
            if fields[0] {
                data.millis("min_rtt", metrics.min_rtt);
            }
            if fields[1] {
                data.millis("smoothed_rtt", metrics.smoothed_rtt);
            }
            if fields[2] {
                data.millis("latest_rtt", metrics.latest_rtt);
            }
            if fields[3] {
                data.millis("rtt_variance", metrics.rtt_variance);
            }
            if fields[4] {
                data.u64("congestion_window", metrics.congestion_window as u64);
            }
            if fields[5] {
                data.u64("bytes_in_flight", metrics.bytes_in_flight as u64);
            }
        });
    }

    fn connection_closed(&mut self, _: I, closed: &ConnectionClosed) {
        self.event("quic:connection_closed", |data| {
            data.str("initiator", initiator(closed.initiator));
            let reason = match &closed.close {
                Some(ImmediateClose::Transport(close)) => {
                    v1::write_transport_error(data, "connection_error", close.code);
                    Some(&close.reason_phrase)
                }
                Some(ImmediateClose::Application(close)) => {
                    // the application protocol defines its codes, which
                    // this crate does not know
                    data.str("application_error", "unknown")
                        .u64("error_code", close.code.get().get());
                    Some(&close.reason_phrase)
                }
                None => None,
            };
            if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
                data.str("reason", &String::from_utf8_lossy(reason));
            }
            let trigger = match closed.trigger {
                CloseTrigger::IdleTimeout => "idle_timeout",
                CloseTrigger::Application => "application",
                CloseTrigger::Error => "error",
                CloseTrigger::VersionMismatch => "version_mismatch",
                CloseTrigger::StatelessReset => "stateless_reset",
                CloseTrigger::Aborted => "aborted",
                CloseTrigger::PeerClose => match closed.close {
                    Some(ImmediateClose::Application(_)) => "application",
                    _ => "error",
                },
                CloseTrigger::LinkEnded | CloseTrigger::RetryAbandoned => "unspecified",
            };
            data.str("trigger", trigger);
        });
        self.shared.flush();
    }

    fn connection_state(&mut self, _: I, state: ConnectionState) {
        let new = match state {
            ConnectionState::Attempted => "attempted",
            ConnectionState::HandshakeStarted => "handshake_started",
            ConnectionState::HandshakeComplete => "handshake_complete",
            ConnectionState::HandshakeConfirmed => "handshake_confirmed",
            ConnectionState::Closed => "closed",
        };
        self.event("quic:connection_state_updated", |data| {
            data.str("new", new);
        });
    }

    fn key_updated(&mut self, _: I, key: KeyChange) {
        // the secrets themselves are not written: a key log has them
        self.event("quic:key_updated", |data| {
            data.str("key_type", key_type(key)).str("trigger", "tls");
        });
    }

    fn key_discarded(&mut self, _: I, key: KeyChange) {
        self.event("quic:key_discarded", |data| {
            data.str("key_type", key_type(key)).str("trigger", "tls");
        });
    }

    fn version_information(&mut self, _: I, local: &[Version], chosen: Version) {
        // what this side offers or accepts: a client's versions, or a
        // server's (quic-events §5.1)
        let key = match self.role {
            Role::Client => "client_versions",
            Role::Server => "server_versions",
        };
        self.event("quic:version_information", |data| {
            data.array(key, |versions| {
                for version in local {
                    versions.hex(&version_hex(*version));
                }
            })
            .hex("chosen_version", &version_hex(chosen));
        });
    }

    fn alpn_information(&mut self, _: I, chosen: Option<&[u8]>) {
        let Some(chosen) = chosen else {
            return;
        };
        self.event("quic:alpn_information", |data| {
            data.object("chosen_alpn", |alpn| {
                alpn.hex("byte_value", chosen);
                if let Ok(text) = core::str::from_utf8(chosen) {
                    alpn.str("string_value", text);
                }
            });
        });
    }

    /// qlog has no event of its own for it: a warning of the main schema,
    /// whose message names the address and the reason.
    fn preferred_address_connect_failed(
        &mut self,
        _: I,
        address: SocketAddr,
        reason: &dyn fmt::Display,
    ) {
        let message = format!("no link to the preferred address {address}: {reason}");
        self.event("loglevel:warning", |data| {
            data.str("message", &message);
        });
    }
}

impl<I, L, C> PacketEvents<I, L> for QlogWriter<L, C>
where
    L: QlogParts + 'static,
    C: MonotonicClock + 'static,
    TransportParameterSlots<L>: QlogParameterSlots,
    L: ParametersOf<TransportParameterSpace>,
{
    fn packet_sent(&mut self, _: I, packet: &PlainPacket<'_>) {
        packet::packet_event::<L, C>(&self.shared, "quic:packet_sent", packet, true);
    }

    fn parameters_set(
        &mut self,
        _: I,
        from: EventInitiator,
        parameters: &TransportParameterSlots<L>,
    ) where
        L: ParametersOf<TransportParameterSpace>,
    {
        self.event("quic:parameters_set", |data| {
            data.str("initiator", initiator(from));
            parameters.write_parameters(data);
        });
    }

    fn packet_received(&mut self, _: I, packet: &PlainPacket<'_>) {
        packet::packet_event::<L, C>(&self.shared, "quic:packet_received", packet, false);
    }
}

impl<C: MonotonicClock> SharedEvents for QlogShared<C> {
    const ENABLED: bool = true;

    fn enabled(&self) -> bool {
        self.0.is_some()
    }

    fn stream_state(
        &self,
        stream_id: StreamId,
        change: StreamStateChange,
        trigger: EventInitiator,
    ) {
        let (side, old, new) = match change {
            StreamStateChange::Sending { old, new } => {
                ("sending", old.map(send_state), new.map(send_state))
            }
            StreamStateChange::Receiving { old, new } => {
                ("receiving", old.map(receive_state), new.map(receive_state))
            }
        };
        self.event("quic:stream_state_updated", |data| {
            data.u64("stream_id", stream_id.get().get())
                .str(
                    "stream_type",
                    match stream_id.directionality() {
                        Directionality::Bidirectional => "bidirectional",
                        Directionality::Unidirectional => "unidirectional",
                    },
                )
                .str("old", old.unwrap_or("idle"))
                .str("new", new.unwrap_or("destroyed"))
                .str("stream_side", side)
                .str("trigger", initiator(trigger));
        });
    }

    fn stream_data_moved(&self, moved: &StreamDataMoved) {
        self.event("quic:stream_data_moved", |data| {
            data.u64("stream_id", moved.stream_id.get().get())
                .u64("offset", moved.offset)
                .str("from", data_location(moved.from))
                .str("to", data_location(moved.to));
            match moved.additional_info {
                Some(DataMovedAdditionalInfo::FinSet) => {
                    data.str("additional_info", "fin_set");
                }
                Some(DataMovedAdditionalInfo::StreamReset) => {
                    data.str("additional_info", "stream_reset");
                }
                None => {}
            }
            data.object("raw", |raw| {
                raw.u64("length", moved.length);
            });
        });
    }

    fn datagram_data_moved(&self, length: usize, from: DataLocation, to: DataLocation) {
        self.event("quic:datagram_data_moved", |data| {
            data.str("from", data_location(from))
                .str("to", data_location(to))
                .object("raw", |raw| {
                    raw.u64("length", length as u64);
                });
        });
    }

    fn datagram_dropped(&self, length: usize, dropped: DatagramDropped) {
        let direction = match dropped {
            DatagramDropped::SendQueueFull => "sending",
            DatagramDropped::ReceiveQueueFull => "receiving",
        };
        self.event("quic:datagram_dropped", |data| {
            data.str("direction", direction)
                .object("raw", |raw| {
                    raw.u64("length", length as u64);
                })
                .str("trigger", "buffer_full");
        });
    }
}
