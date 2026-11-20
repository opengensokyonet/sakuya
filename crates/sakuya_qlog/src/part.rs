//! How the frames and the shared events of each part of a composition are
//! written ([`QlogPart`]), and of a list of parts ([`QlogParts`]).

use sakuya_connection::v1::events::{SharedEventsOfParts, SharedEventsPart};
use sakuya_wire::{
    parts::{CNil, Coproduct, HCons, HNil},
    v1::{
        frame::set::{FrameSet, FrameSetPart},
        stream_id::StreamId,
    },
};

use crate::json::{ArrayWriter, ObjectWriter};

/// The application data a frame carries, which moves between the transport
/// and the network with its packet (quic-events §5.15, §5.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarriedData {
    /// Data of a stream, as a STREAM frame carries it.
    Stream {
        /// The stream.
        stream_id: StreamId,
        /// Where in the stream the data starts.
        offset: u64,
        /// How many bytes.
        length: u64,
    },
    /// The payload of a datagram, as a DATAGRAM frame carries it.
    Datagram {
        /// How many bytes.
        length: u64,
    },
}

/// How the frames of a part of a composition are written as qlog's frame
/// objects (quic-events §8.13), and its own shared events as qlog's events.
///
/// The part is the one the composition lists, which reads its frames
/// ([`FrameSetPart`]) and gives the type of its events
/// ([`SharedEventsPart`]); its runs are read again from the plaintext of a
/// packet, a byte slice.
pub trait QlogPart: FrameSetPart + SharedEventsPart {
    /// Writes the frames of `run` into `frames`, one object each.
    fn write_run(run: &Self::Run<&[u8]>, frames: &mut ArrayWriter<'_>);

    /// The application data `run` carries, if any; by default none.
    fn carried_data(run: &Self::Run<&[u8]>) -> Option<CarriedData> {
        let _ = run;
        None
    }

    /// qlog's name of the event `event`, one of the part's own.
    fn shared_event_name(event: &Self::SharedEvent) -> &'static str;

    /// Writes the data of `event` into `data`.
    fn write_shared_event(event: &Self::SharedEvent, data: &mut ObjectWriter<'_>);
}

/// How the frames and the shared events of a list of parts are written: as
/// the part each run, or each event, belongs to writes it.
pub trait QlogParts: FrameSet + SharedEventsOfParts {
    /// Writes the frames of `run` into `frames`, one object each.
    fn write_run(run: &Self::Run<&[u8]>, frames: &mut ArrayWriter<'_>);

    /// The application data `run` carries, if any.
    fn carried_data(run: &Self::Run<&[u8]>) -> Option<CarriedData>;

    /// qlog's name of the event `event`, one of a part's own.
    fn shared_event_name(event: &Self::PartEvents) -> &'static str;

    /// Writes the data of `event` into `data`.
    fn write_shared_event(event: &Self::PartEvents, data: &mut ObjectWriter<'_>);
}

impl QlogParts for HNil {
    fn write_run(run: &CNil, _: &mut ArrayWriter<'_>) {
        match *run {}
    }

    fn carried_data(run: &CNil) -> Option<CarriedData> {
        match *run {}
    }

    fn shared_event_name(event: &CNil) -> &'static str {
        match *event {}
    }

    fn write_shared_event(event: &CNil, _: &mut ObjectWriter<'_>) {
        match *event {}
    }
}

impl<P: QlogPart, Ps: QlogParts> QlogParts for HCons<P, Ps> {
    fn write_run(run: &Self::Run<&[u8]>, frames: &mut ArrayWriter<'_>) {
        match run {
            Coproduct::Inl(run) => P::write_run(run, frames),
            Coproduct::Inr(run) => Ps::write_run(run, frames),
        }
    }

    fn carried_data(run: &Self::Run<&[u8]>) -> Option<CarriedData> {
        match run {
            Coproduct::Inl(run) => P::carried_data(run),
            Coproduct::Inr(run) => Ps::carried_data(run),
        }
    }

    fn shared_event_name(event: &Self::PartEvents) -> &'static str {
        match event {
            Coproduct::Inl(event) => P::shared_event_name(event),
            Coproduct::Inr(event) => Ps::shared_event_name(event),
        }
    }

    fn write_shared_event(event: &Self::PartEvents, data: &mut ObjectWriter<'_>) {
        match event {
            Coproduct::Inl(event) => P::write_shared_event(event, data),
            Coproduct::Inr(event) => Ps::write_shared_event(event, data),
        }
    }
}
