//! The reliable stream reset extension (RESET_STREAM_AT) as a part of a
//! connection.

use bytes::Buf;

use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};
use sakuya_wire::{
    parameters::ParametersPart,
    parts::HNil,
    reset_stream_at::{FrameType, ResetStreamAtFrame, codec},
    v1::{
        frame::set::{FrameSetPart, FrameTypeValues},
        transport_parameters::TransportParameterSpace,
    },
    var_int::VarInt,
};

use crate::{
    share::LogicalPathKeyShare,
    v1::streams::resets::{StreamResets, StreamResetsPart},
};

/// The reliable stream reset extension, one part of a composition.
#[derive(Debug)]
pub struct Part;

/// The extension leaves how streams are reset as it is, for now.
impl StreamResetsPart for Part {
    // 下一步换成可靠重置
    type Fold<Prev: StreamResets> = Prev;
}

/// The extension adds nothing to the key of a logical path.
impl LogicalPathKeyShare for Part {
    type Fields = HNil;
}

/// The transport parameters of the extension are those its wire format
/// defines.
impl ParametersPart<TransportParameterSpace> for Part {
    type Parameters =
        <sakuya_wire::reset_stream_at::Part as ParametersPart<TransportParameterSpace>>::Parameters;
}

/// The extension reads its frames as the wire format's part.
impl FrameSetPart for Part {
    type Run<D> = ResetStreamAtFrame;
    type Kind = FrameType;
    type TypeValue = FrameType;
    type FieldsError<E> = codec::ReadResetStreamAtFrameError<E>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::FRAME_TYPE_VALUES;

    fn type_value_of(value: VarInt) -> Option<FrameType> {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::type_value_of(value)
    }

    fn kind_of(type_value: FrameType) -> FrameType {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::kind_of(type_value)
    }

    fn run_kind<D>(run: &ResetStreamAtFrame) -> FrameType {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::run_kind::<D>(run)
    }

    fn read_run<H>(
        source: &mut H,
        type_value: FrameType,
    ) -> Result<
        <Self as FrameSetPart>::Run<<Direct<H> as ReadChunk>::Chunk>,
        <Self as FrameSetPart>::FieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::read_run(source, type_value)
    }
}
