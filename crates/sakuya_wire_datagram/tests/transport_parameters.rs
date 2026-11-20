//! The transport parameters of both extensions with those of version 1,
//! through the public interface.
use core::marker::PhantomData;
use sakuya_wire::{
    parameters::KeyedParameter,
    parts::HList,
    var_int::{VarInt, codec::write_var_int},
};
use sakuya_wire_v1 as v1;
use sakuya_wire_v1::transport_parameters::{
    RememberedForZeroRtt,
    codec::read_remembered_transport_parameters,
    integer::{InitialMaxData, MaxAckDelay},
};

fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

/// Encodes one parameter.
fn tlv(id: u64, value: &[u8]) -> Vec<u8> {
    let mut encoding = Vec::new();
    write_var_int(&mut encoding, vi(id));
    write_var_int(&mut encoding, VarInt::try_from(value.len()).unwrap());
    encoding.extend_from_slice(value);
    encoding
}

fn integer(value: u64) -> Vec<u8> {
    let mut encoding = Vec::new();
    write_var_int(&mut encoding, vi(value));
    encoding
}

/// The parameters of extensions are remembered as their definitions say:
/// `reset_stream_at` must be, `max_datagram_frame_size` may be, and both are
/// kept; the order of the parts does not matter.
#[test]
fn remembered_parameters_of_extensions() {
    use sakuya_wire_datagram::{self as datagram, MaxDatagramFrameSize};
    use sakuya_wire_reset_stream_at::{self as reset_stream_at, ResetStreamAt};
    assert_eq!(
        ResetStreamAt::ATTRIBUTES.remembered_for_zero_rtt,
        RememberedForZeroRtt::Mandatory
    );
    assert_eq!(
        MaxDatagramFrameSize::ATTRIBUTES.remembered_for_zero_rtt,
        RememberedForZeroRtt::Optional
    );
    let mut encoding = tlv(0x1d, &[]);
    encoding.extend(tlv(0x04, &integer(7)));
    encoding.extend(tlv(0x0b, &integer(30)));
    encoding.extend(tlv(0x20, &integer(1200)));
    encoding.extend(tlv(31 * 1000 + 27, b"reserved"));

    macro_rules! check {
        ($parts:ty) => {{
            let remembered = read_remembered_transport_parameters(
                &mut encoding.as_slice(),
                PhantomData::<$parts>,
            )
            .unwrap();
            assert_eq!(
                remembered.get::<Option<ResetStreamAt>, _>(),
                &Some(ResetStreamAt)
            );
            assert_eq!(
                remembered.get::<Option<MaxDatagramFrameSize>, _>(),
                &Some(MaxDatagramFrameSize::new(vi(1200)))
            );
            assert_eq!(
                remembered.get::<Option<InitialMaxData>, _>(),
                &Some(InitialMaxData::new(vi(7)))
            );
            assert_eq!(remembered.get::<Option<MaxAckDelay>, _>(), &None);
        }};
    }
    check!(HList![v1::Part, reset_stream_at::Part, datagram::Part]);
    check!(HList![datagram::Part, v1::Part, reset_stream_at::Part]);
}
