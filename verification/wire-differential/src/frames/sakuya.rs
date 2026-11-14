//! The adapter of `sakuya_wire`: reading a payload with a frame set, the
//! runs it gives in the neutral model, writing them back, and building
//! frames from the model.
use super::{Decoded, Frame};
use bytes::Buf;
use core::{fmt::Display, marker::PhantomData, num::NonZeroUsize, ops::Range};
use either::Either;
use nitori_call::{Direct, Receiver};
use nitori_io::ReadChunk;
use sakuya_wire::{
    assert_frame_types_disjoint,
    connection_id::{NonEmptyCid, StatelessResetToken},
    datagram::{self, DatagramFrame, codec::WriteDatagramFrameHostExt as _},
    frame::NoLength,
    parts::HList,
    reset_stream_at::{self, ResetStreamAtFrame, codec::WriteResetStreamAtFrameHostExt as _},
    v1::{
        self,
        application_error::ApplicationErrorCode,
        frame::{
            FrameRun,
            ack::{AckFrame, AckRange, AckRanges, EcnCounts},
            codec::WriteFrameRunHostExt as _,
            connection_close::{CloseErrorCode, ConnectionCloseFrame},
            crypto::CryptoFrame,
            data_blocked::DataBlockedFrame,
            handshake_done::HandshakeDoneFrame,
            max_data::MaxDataFrame,
            max_stream_data::MaxStreamDataFrame,
            max_streams::MaxStreamsFrame,
            new_connection_id::NewConnectionIdFrame,
            new_token::NewTokenFrame,
            padding::PaddingRun,
            path_challenge::PathChallengeFrame,
            path_response::PathResponseFrame,
            ping::PingFrame,
            reset_stream::ResetStreamFrame,
            retire_connection_id::RetireConnectionIdFrame,
            set::{FrameFieldsError, FrameSet, Frames, codec::ReadFrameError},
            stop_sending::StopSendingFrame,
            stream::StreamFrame,
            stream_data_blocked::StreamDataBlockedFrame,
            streams_blocked::StreamsBlockedFrame,
        },
        packet_number::PacketNumber,
        stream_count::StreamCount,
        stream_id::{Directionality, StreamId},
        transport_error::TransportErrorCode,
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};

/// The frame set of the differential comparison: version 1, DATAGRAM and
/// RESET_STREAM_AT.
pub type Full = HList![v1::Part, datagram::Part, reset_stream_at::Part];

/// The frame set of version 1 alone.
pub type V1Only = HList![v1::Part];

assert_frame_types_disjoint!(Full);
assert_frame_types_disjoint!(V1Only);

/// The chunk type of payload fields read from `H`.
pub type Chunk<H> = <Direct<H> as ReadChunk>::Chunk;

/// The failure of the source `H`.
pub type HostError<H> = <Direct<H> as nitori_io::Read>::Error;

/// An item a frame set of sakuya gives, of any of the parts of [`Full`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Run<D> {
    V1(FrameRun<D>),
    Datagram(DatagramFrame<D>),
    ResetStreamAt(ResetStreamAtFrame),
}

/// A frame set that sakuya reads with here, and how its items become a
/// [`Run`].
pub trait SakuyaSet: FrameSet {
    /// The item `item` of the set, taken out of the sum by the type of its
    /// part.
    fn run<D>(item: Self::Run<D>) -> Run<D>;
}

impl SakuyaSet for Full {
    fn run<D>(item: Self::Run<D>) -> Run<D> {
        match item.uninject::<FrameRun<D>, _>() {
            Ok(run) => Run::V1(run),
            Err(rest) => match rest.uninject::<DatagramFrame<D>, _>() {
                Ok(frame) => Run::Datagram(frame),
                Err(rest) => Run::ResetStreamAt(rest.extract()),
            },
        }
    }
}

impl SakuyaSet for V1Only {
    fn run<D>(item: Self::Run<D>) -> Run<D> {
        Run::V1(item.extract())
    }
}

/// Which step of reading an item failed, as the variant of
/// [`ReadFrameError`] states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// The Frame Type could not be read.
    FrameType,
    /// The Frame Type is encoded longer than necessary.
    LongerTypeEncoding,
    /// No part of the set claims the Frame Type.
    UnknownType,
    /// The fields after the Frame Type could not be read or break a rule.
    Fields,
}

/// The failure that ended a walk, as the error states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// The offset of the frame that failed.
    pub offset: usize,
    pub kind: FailureKind,
    /// The Frame Type the error reports, if it could be read.
    pub frame_type: Option<u64>,
    pub incomplete: bool,
    /// The transport error code the error corresponds to.
    pub code: u64,
    pub message: String,
}

/// The outcome of walking a payload with a frame set of sakuya.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read<D> {
    /// Each item read, with the bytes of the payload it was read from.
    pub runs: Vec<(Range<usize>, Run<D>)>,
    pub failure: Option<Failure>,
}

/// Walks `payload` with the frame set `S`.
pub fn read_with<S, H>(payload: H) -> Read<Chunk<H>>
where
    S: SakuyaSet,
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
    S::FieldsError<HostError<H>>: FrameFieldsError,
    ReadFrameError<HostError<H>, S::FieldsError<HostError<H>>>: Display,
{
    let mut frames = Frames::new(payload, PhantomData::<S>);
    let mut runs = Vec::new();
    let mut start = 0;
    while let Some(item) = frames.next() {
        match item {
            Ok(run) => {
                let end = frames.offset();
                runs.push((start..end, S::run(run)));
                start = end;
            }
            Err(error) => {
                let failure = failure(&error, frames.offset());
                return Read {
                    runs,
                    failure: Some(failure),
                };
            }
        }
    }
    Read {
        runs,
        failure: None,
    }
}

/// Walks `payload` with [`Full`].
pub fn read(payload: &[u8]) -> Read<&[u8]> {
    read_with::<Full, _>(payload)
}

/// Walks `payload` with [`V1Only`].
pub fn read_v1(payload: &[u8]) -> Read<&[u8]> {
    read_with::<V1Only, _>(payload)
}

/// The summary of `error`, for a frame at `offset`.
pub fn failure<E, C: FrameFieldsError>(error: &ReadFrameError<E, C>, offset: usize) -> Failure
where
    ReadFrameError<E, C>: Display,
{
    let kind = match error {
        ReadFrameError::FrameType { .. } => FailureKind::FrameType,
        ReadFrameError::LongerTypeEncoding { .. } => FailureKind::LongerTypeEncoding,
        ReadFrameError::UnknownType { .. } => FailureKind::UnknownType,
        ReadFrameError::Fields { .. } => FailureKind::Fields,
    };
    Failure {
        offset,
        kind,
        frame_type: error.frame_type().map(VarInt::get),
        incomplete: error.is_incomplete(),
        code: error.transport_error_code().get().get(),
        message: error.to_string(),
    }
}

impl<D: AsRef<[u8]>> Read<D> {
    /// What was read, in the neutral model.
    pub fn decoded(&self) -> Decoded {
        Decoded {
            frames: self.runs.iter().flat_map(|(_, run)| run.model()).collect(),
            failed: self.failure.is_some(),
        }
    }
}

impl<D: Buf + Clone + core::fmt::Debug> Read<D> {
    /// The first item that does not write back to the bytes it was read
    /// from, or whose `encoded_len` differs from their length, described.
    pub fn rewrite_mismatch(&self, payload: &[u8]) -> Option<String> {
        self.runs.iter().find_map(|(range, run)| {
            let written = run.clone().to_bytes();
            let length = run.encoded_len();
            let read = &payload[range.clone()];
            (written != read || length != read.len()).then(|| {
                format!(
                    "{run:?} read from {} at {range:?} writes {} with encoded_len {length}",
                    crate::tally::hex(read),
                    crate::tally::hex(&written)
                )
            })
        })
    }
}

impl<D: Buf> Run<D> {
    /// The number of bytes the write operation writes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::V1(run) => run.encoded_len(),
            Self::Datagram(frame) => frame.encoded_len(),
            Self::ResetStreamAt(frame) => frame.encoded_len(),
        }
    }

    /// The bytes the write operation of the run's type writes.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut output = Vec::new();
        let result = match self {
            Self::V1(run) => output.sync_write_frame_run_unpin(run),
            Self::Datagram(frame) => output.sync_write_datagram_frame_unpin(frame),
            Self::ResetStreamAt(frame) => output.sync_write_reset_stream_at_frame_unpin(frame),
        };
        result.expect("a Vec takes every byte");
        output
    }
}

fn u(field: VarIntField<VarInt>) -> u64 {
    field.get().get()
}

fn sid(field: VarIntField<StreamId>) -> u64 {
    field.get().get().get()
}

fn app(field: VarIntField<ApplicationErrorCode>) -> u64 {
    field.get().get().get()
}

fn uni(directionality: Directionality) -> bool {
    directionality == Directionality::Unidirectional
}

impl<D: AsRef<[u8]>> Run<D> {
    /// The frames of the run in the neutral model: one per PADDING frame of
    /// a run of them.
    pub fn model(&self) -> Vec<Frame> {
        let bytes = |data: &D| data.as_ref().to_vec();
        let frame = match self {
            Self::V1(run) => match run {
                FrameRun::Padding(run) => return vec![Frame::Padding; run.len().get()],
                FrameRun::Ping(_) => Frame::Ping,
                FrameRun::Ack(f) => Frame::Ack {
                    delay: u(f.ack_delay()),
                    ranges: f
                        .packet_ranges()
                        .map(|range| (range.start().get(), range.end().get()))
                        .collect(),
                    ecn: f
                        .ecn_counts()
                        .map(|counts| (u(counts.ect0), u(counts.ect1), u(counts.ce))),
                },
                FrameRun::ResetStream(f) => Frame::ResetStream {
                    id: sid(f.stream_id()),
                    code: app(f.application_error_code()),
                    final_size: u(f.final_size()),
                },
                FrameRun::StopSending(f) => Frame::StopSending {
                    id: sid(f.stream_id()),
                    code: app(f.application_error_code()),
                },
                FrameRun::Crypto(f) => Frame::Crypto {
                    offset: u(f.offset()),
                    data: bytes(f.data()),
                },
                FrameRun::NewToken(f) => Frame::NewToken {
                    token: bytes(f.token()),
                },
                FrameRun::Stream(f) => Frame::Stream {
                    id: sid(f.stream_id()),
                    offset: f.data_offset().get(),
                    fin: f.fin(),
                    has_length: f.length().is_right(),
                    data: bytes(f.data()),
                },
                FrameRun::MaxData(f) => Frame::MaxData(u(f.maximum_data())),
                FrameRun::MaxStreamData(f) => Frame::MaxStreamData {
                    id: sid(f.stream_id()),
                    limit: u(f.maximum_stream_data()),
                },
                FrameRun::MaxStreams(f) => Frame::MaxStreams {
                    uni: uni(f.directionality()),
                    count: f.maximum_streams().get().get(),
                },
                FrameRun::DataBlocked(f) => Frame::DataBlocked(u(f.maximum_data())),
                FrameRun::StreamDataBlocked(f) => Frame::StreamDataBlocked {
                    id: sid(f.stream_id()),
                    limit: u(f.maximum_stream_data()),
                },
                FrameRun::StreamsBlocked(f) => Frame::StreamsBlocked {
                    uni: uni(f.directionality()),
                    count: f.maximum_streams().get().get(),
                },
                FrameRun::NewConnectionId(f) => Frame::NewConnectionId {
                    sequence: u(f.sequence_number()),
                    retire_prior_to: u(f.retire_prior_to()),
                    cid: f.connection_id().as_bytes().to_vec(),
                    token: *f.stateless_reset_token().as_bytes(),
                },
                FrameRun::RetireConnectionId(f) => {
                    Frame::RetireConnectionId(u(f.sequence_number()))
                }
                FrameRun::PathChallenge(f) => Frame::PathChallenge(f.data()),
                FrameRun::PathResponse(f) => Frame::PathResponse(f.data()),
                FrameRun::ConnectionClose(f) => match f.error_code() {
                    CloseErrorCode::Transport { code, frame_type } => Frame::TransportClose {
                        code: code.get().get().get(),
                        frame_type: u(frame_type),
                        reason: bytes(f.reason_phrase()),
                    },
                    CloseErrorCode::Application { code } => Frame::ApplicationClose {
                        code: app(code),
                        reason: bytes(f.reason_phrase()),
                    },
                },
                FrameRun::HandshakeDone(_) => Frame::HandshakeDone,
            },
            Self::Datagram(f) => Frame::Datagram {
                has_length: f.length().is_right(),
                data: bytes(f.data()),
            },
            Self::ResetStreamAt(f) => Frame::ResetStreamAt {
                id: sid(f.stream_id()),
                code: app(f.application_error_code()),
                final_size: u(f.final_size()),
                reliable_size: u(f.reliable_size()),
            },
        };
        vec![frame]
    }
}

/// The widths in which [`build`] encodes variable-length integers.
#[derive(Clone, Debug, Default)]
pub struct Layout {
    /// The widths to use in turn, for every variable-length integer but the
    /// Frame Type; a width that cannot hold a value gives way to the
    /// shortest one. Empty for the shortest encodings throughout.
    pub widths: Vec<VarIntWidth>,
    /// Whether a STREAM frame at offset 0 has an Offset field.
    pub explicit_zero_offset: bool,
    next: usize,
}

impl Layout {
    /// The shortest encodings, and no Offset field for offset 0: the
    /// encoding a sender normally uses.
    pub fn shortest() -> Self {
        Self::default()
    }

    /// The layout that uses `widths` in turn.
    pub fn new(widths: Vec<VarIntWidth>, explicit_zero_offset: bool) -> Self {
        Self {
            widths,
            explicit_zero_offset,
            next: 0,
        }
    }

    /// The width of the next field, which holds `value`.
    fn width(&mut self, value: VarInt) -> VarIntWidth {
        let shortest = VarIntWidth::shortest(value);
        if self.widths.is_empty() {
            return shortest;
        }
        let width = self.widths[self.next % self.widths.len()];
        self.next += 1;
        if width.fits(value) { width } else { shortest }
    }

    /// The next field, which holds `value`.
    fn field<T: Copy + Into<VarInt> + TryFrom<VarInt>>(&mut self, value: T) -> VarIntField<T> {
        let width = self.width(value.into());
        VarIntField::new(value, width).unwrap_or_else(|_| VarIntField::shortest(value))
    }

    /// The next field, of a value below 2<sup>62</sup>.
    fn var(&mut self, value: u64) -> Option<VarIntField<VarInt>> {
        Some(self.field(VarInt::new(value).ok()?))
    }

    /// The width of the next Length field, for `length` bytes.
    fn length(&mut self, length: usize) -> Option<VarIntWidth> {
        Some(self.width(VarInt::try_from(length).ok()?))
    }
}

fn stream_id(layout: &mut Layout, id: u64) -> Option<VarIntField<StreamId>> {
    Some(layout.field(StreamId::from_var_int(VarInt::new(id).ok()?)))
}

fn app_code(layout: &mut Layout, code: u64) -> Option<VarIntField<ApplicationErrorCode>> {
    Some(layout.field(ApplicationErrorCode::new(VarInt::new(code).ok()?)))
}

fn directionality(uni: bool) -> Directionality {
    if uni {
        Directionality::Unidirectional
    } else {
        Directionality::Bidirectional
    }
}

/// The ACK frame of `ranges`, inclusive and largest first, with the fields
/// in the widths of `layout`; `None` for ranges an ACK frame cannot state.
fn ack(
    layout: &mut Layout,
    delay: u64,
    ranges: &[(u64, u64)],
    ecn: Option<(u64, u64, u64)>,
) -> Option<AckFrame> {
    let (&(smallest, largest), rest) = ranges.split_first()?;
    let largest_acknowledged = layout.field(PacketNumber::new(largest).ok()?);
    let ack_delay = layout.var(delay)?;
    let count_width = layout.length(rest.len())?;
    let first_ack_range = layout.var(largest.checked_sub(smallest)?)?;
    let mut previous = smallest;
    let mut ack_ranges = Vec::new();
    for &(start, end) in rest {
        let gap = previous.checked_sub(end)?.checked_sub(2)?;
        ack_ranges.push(AckRange {
            gap: layout.var(gap)?,
            ack_range_length: layout.var(end.checked_sub(start)?)?,
        });
        previous = start;
    }
    let ecn_counts = match ecn {
        Some((ect0, ect1, ce)) => Some(EcnCounts {
            ect0: layout.var(ect0)?,
            ect1: layout.var(ect1)?,
            ce: layout.var(ce)?,
        }),
        None => None,
    };
    AckFrame::new(
        largest_acknowledged,
        ack_delay,
        count_width,
        first_ack_range,
        AckRanges::from(ack_ranges),
        ecn_counts,
    )
    .ok()
}

/// `frame` as a sakuya frame, with the widths of `layout`; `None` for a
/// frame sakuya does not have, or whose fields break a rule of its
/// encoding.
pub fn build<'a>(frame: &'a Frame, layout: &mut Layout) -> Option<Run<&'a [u8]>> {
    let run = match frame {
        Frame::Padding => FrameRun::Padding(PaddingRun::new(NonZeroUsize::MIN)),
        Frame::Ping => FrameRun::Ping(PingFrame),
        Frame::Ack { delay, ranges, ecn } => FrameRun::Ack(ack(layout, *delay, ranges, *ecn)?),
        Frame::ResetStream {
            id,
            code,
            final_size,
        } => FrameRun::ResetStream(ResetStreamFrame::new(
            stream_id(layout, *id)?,
            app_code(layout, *code)?,
            layout.var(*final_size)?,
        )),
        Frame::StopSending { id, code } => FrameRun::StopSending(StopSendingFrame::new(
            stream_id(layout, *id)?,
            app_code(layout, *code)?,
        )),
        Frame::Crypto { offset, data } => {
            let offset = layout.var(*offset)?;
            let width = layout.length(data.len())?;
            FrameRun::Crypto(CryptoFrame::new(offset, width, data.as_slice()).ok()?)
        }
        Frame::NewToken { token } => {
            let width = layout.length(token.len())?;
            FrameRun::NewToken(NewTokenFrame::new(width, token.as_slice()).ok()?)
        }
        Frame::Stream {
            id,
            offset,
            fin,
            has_length,
            data,
        } => {
            let id = stream_id(layout, *id)?;
            let offset = if *offset == 0 && !layout.explicit_zero_offset {
                None
            } else {
                Some(layout.var(*offset)?)
            };
            let data = data.as_slice();
            let frame: StreamFrame<&[u8]> = if *has_length {
                let width = layout.length(data.len())?;
                StreamFrame::with_length(id, offset, width, data, *fin)
                    .ok()?
                    .into()
            } else {
                StreamFrame::without_length(id, offset, data, *fin)
                    .ok()?
                    .into()
            };
            FrameRun::Stream(frame)
        }
        Frame::MaxData(value) => FrameRun::MaxData(MaxDataFrame::new(layout.var(*value)?)),
        Frame::MaxStreamData { id, limit } => FrameRun::MaxStreamData(MaxStreamDataFrame::new(
            stream_id(layout, *id)?,
            layout.var(*limit)?,
        )),
        Frame::MaxStreams { uni, count } => FrameRun::MaxStreams(MaxStreamsFrame::new(
            directionality(*uni),
            layout.field(StreamCount::new(*count).ok()?),
        )),
        Frame::DataBlocked(value) => {
            FrameRun::DataBlocked(DataBlockedFrame::new(layout.var(*value)?))
        }
        Frame::StreamDataBlocked { id, limit } => FrameRun::StreamDataBlocked(
            StreamDataBlockedFrame::new(stream_id(layout, *id)?, layout.var(*limit)?),
        ),
        Frame::StreamsBlocked { uni, count } => FrameRun::StreamsBlocked(StreamsBlockedFrame::new(
            directionality(*uni),
            layout.field(StreamCount::new(*count).ok()?),
        )),
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            cid,
            token,
        } => FrameRun::NewConnectionId(
            NewConnectionIdFrame::new(
                layout.var(*sequence)?,
                layout.var(*retire_prior_to)?,
                NonEmptyCid::try_from(cid.as_slice()).ok()?,
                StatelessResetToken::new(*token),
            )
            .ok()?,
        ),
        Frame::RetireConnectionId(value) => {
            FrameRun::RetireConnectionId(RetireConnectionIdFrame::new(layout.var(*value)?))
        }
        Frame::PathChallenge(data) => FrameRun::PathChallenge(PathChallengeFrame::new(*data)),
        Frame::PathResponse(data) => FrameRun::PathResponse(PathResponseFrame::new(*data)),
        Frame::TransportClose {
            code,
            frame_type,
            reason,
        } => {
            let code = layout.field(TransportErrorCode::from(VarInt::new(*code).ok()?));
            let frame_type = layout.var(*frame_type)?;
            let width = layout.length(reason.len())?;
            FrameRun::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Transport { code, frame_type },
                    width,
                    reason.as_slice(),
                )
                .ok()?,
            )
        }
        Frame::ApplicationClose { code, reason } => {
            let code = app_code(layout, *code)?;
            let width = layout.length(reason.len())?;
            FrameRun::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Application { code },
                    width,
                    reason.as_slice(),
                )
                .ok()?,
            )
        }
        Frame::HandshakeDone => FrameRun::HandshakeDone(HandshakeDoneFrame),
        Frame::Datagram { has_length, data } => {
            let length = if *has_length {
                Either::Right(layout.length(data.len())?)
            } else {
                Either::Left(NoLength)
            };
            return Some(Run::Datagram(
                DatagramFrame::new(length, data.as_slice()).ok()?,
            ));
        }
        Frame::ResetStreamAt {
            id,
            code,
            final_size,
            reliable_size,
        } => {
            return Some(Run::ResetStreamAt(
                ResetStreamAtFrame::new(
                    stream_id(layout, *id)?,
                    app_code(layout, *code)?,
                    layout.var(*final_size)?,
                    layout.var(*reliable_size)?,
                )
                .ok()?,
            ));
        }
        Frame::ReferenceOnly(_) => return None,
    };
    Some(Run::V1(run))
}

/// `frames` written by sakuya with the widths of `layout`, or `None` if one
/// of them cannot be built.
pub fn write(frames: &[Frame], layout: &mut Layout) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    for frame in frames {
        output.extend(build(frame, layout)?.to_bytes());
    }
    Some(output)
}
