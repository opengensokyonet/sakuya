//! The DATAGRAM extension ([RFC 9221]) as a part of a connection.
//!
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html

use bytes::Buf;

use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};
use sakuya_wire::{
    datagram::{DatagramFrame, DatagramTypeValue, FrameType, codec},
    parameters::ParametersPart,
    parts::HNil,
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

/// The DATAGRAM extension, one part of a composition.
#[derive(Debug)]
pub struct Part;

/// The extension leaves how streams are reset as it is.
impl StreamResetsPart for Part {
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
        <sakuya_wire::datagram::Part as ParametersPart<TransportParameterSpace>>::Parameters;
}

/// The extension reads its frames as the wire format's part.
impl FrameSetPart for Part {
    type Run<D> = DatagramFrame<D>;
    type Kind = FrameType;
    type TypeValue = DatagramTypeValue;
    type FieldsError<E> = codec::ReadDatagramFrameError<E>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        <sakuya_wire::datagram::Part as FrameSetPart>::FRAME_TYPE_VALUES;

    fn type_value_of(value: VarInt) -> Option<DatagramTypeValue> {
        <sakuya_wire::datagram::Part as FrameSetPart>::type_value_of(value)
    }

    fn kind_of(type_value: DatagramTypeValue) -> FrameType {
        <sakuya_wire::datagram::Part as FrameSetPart>::kind_of(type_value)
    }

    fn run_kind<D>(run: &DatagramFrame<D>) -> FrameType {
        <sakuya_wire::datagram::Part as FrameSetPart>::run_kind::<D>(run)
    }

    fn read_run<H>(
        source: &mut H,
        type_value: DatagramTypeValue,
    ) -> Result<
        <Self as FrameSetPart>::Run<<Direct<H> as ReadChunk>::Chunk>,
        <Self as FrameSetPart>::FieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        <sakuya_wire::datagram::Part as FrameSetPart>::read_run(source, type_value)
    }
}
