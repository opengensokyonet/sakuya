//! The adapter of quinn-proto: its frame iterator and the encoders it has
//! for single frames.
//!
//! quinn-proto does not state whether a STREAM or DATAGRAM frame had a Length
//! field, so its frames are compared without it
//! ([`Decoded::without_lengths`]).
use super::{Decoded, Frame};
use bytes::{BufMut, Bytes};
use quinn_proto::{
    ConnectionId, Dir, StreamId as QStreamId, TransportErrorCode, VarInt as QVarInt,
    coding::Codec as _, frame as qf, range_set::ArrayRangeSet,
};

/// Walks `payload` with the frame iterator of quinn-proto.
///
/// quinn-proto refuses an empty payload as a whole (RFC 9000 §12.4: a packet
/// with no frames is a PROTOCOL_VIOLATION); that is no frame and no failure
/// here, as for the other readers, which leave the check to the packet.
pub fn read(payload: &[u8]) -> Decoded {
    let mut decoded = Decoded::default();
    let Ok(iter) = qf::Iter::new(Bytes::copy_from_slice(payload)) else {
        return decoded;
    };
    for item in iter {
        match item {
            Ok(frame) => decoded.frames.push(model(frame)),
            Err(_) => {
                decoded.failed = true;
                break;
            }
        }
    }
    decoded
}

/// Like [`read`], with the reason quinn-proto gives for a failure.
pub fn read_with_reason(payload: &[u8]) -> (Decoded, Option<&'static str>) {
    let mut decoded = Decoded::default();
    let Ok(iter) = qf::Iter::new(Bytes::copy_from_slice(payload)) else {
        return (decoded, None);
    };
    for item in iter {
        match item {
            Ok(frame) => decoded.frames.push(model(frame)),
            Err(error) => {
                decoded.failed = true;
                return (decoded, Some(error.reason));
            }
        }
    }
    (decoded, None)
}

fn model(frame: qf::Frame) -> Frame {
    use qf::Frame as Q;
    let uni = |dir| dir == Dir::Uni;
    match frame {
        Q::Padding => Frame::Padding,
        Q::Ping => Frame::Ping,
        Q::Ack(f) => Frame::Ack {
            delay: f.delay,
            ranges: f
                .iter()
                .map(|range| (*range.start(), *range.end()))
                .collect(),
            ecn: f.ecn.map(|counts| (counts.ect0, counts.ect1, counts.ce)),
        },
        Q::ResetStream(f) => Frame::ResetStream {
            id: u64::from(f.id),
            code: f.error_code.into_inner(),
            final_size: f.final_offset.into_inner(),
        },
        Q::StopSending(f) => Frame::StopSending {
            id: u64::from(f.id),
            code: f.error_code.into_inner(),
        },
        Q::Crypto(f) => Frame::Crypto {
            offset: f.offset,
            data: f.data.to_vec(),
        },
        Q::NewToken(f) => Frame::NewToken {
            token: f.token.to_vec(),
        },
        Q::Stream(f) => Frame::Stream {
            id: u64::from(f.id),
            offset: f.offset,
            fin: f.fin,
            has_length: false,
            data: f.data.to_vec(),
        },
        Q::MaxData(value) => Frame::MaxData(value.into_inner()),
        Q::MaxStreamData { id, offset } => Frame::MaxStreamData {
            id: u64::from(id),
            limit: offset,
        },
        Q::MaxStreams { dir, count } => Frame::MaxStreams {
            uni: uni(dir),
            count,
        },
        Q::DataBlocked { offset } => Frame::DataBlocked(offset),
        Q::StreamDataBlocked { id, offset } => Frame::StreamDataBlocked {
            id: u64::from(id),
            limit: offset,
        },
        Q::StreamsBlocked { dir, limit } => Frame::StreamsBlocked {
            uni: uni(dir),
            count: limit,
        },
        Q::NewConnectionId(f) => Frame::NewConnectionId {
            sequence: f.sequence,
            retire_prior_to: f.retire_prior_to,
            cid: f.id.to_vec(),
            token: f.reset_token.as_ref().try_into().expect("16-byte token"),
        },
        Q::RetireConnectionId { sequence } => Frame::RetireConnectionId(sequence),
        Q::PathChallenge(value) => Frame::PathChallenge(value.to_be_bytes()),
        Q::PathResponse(value) => Frame::PathResponse(value.to_be_bytes()),
        Q::Close(qf::Close::Connection(f)) => Frame::TransportClose {
            code: u64::from(f.error_code),
            frame_type: f.frame_type.map_or(0, |ty| ty.0),
            reason: f.reason.to_vec(),
        },
        Q::Close(qf::Close::Application(f)) => Frame::ApplicationClose {
            code: f.error_code.into_inner(),
            reason: f.reason.to_vec(),
        },
        Q::HandshakeDone => Frame::HandshakeDone,
        Q::Datagram(f) => Frame::Datagram {
            has_length: false,
            data: f.data.to_vec(),
        },
        Q::AckFrequency(_) => Frame::ReferenceOnly("ACK_FREQUENCY"),
        Q::ImmediateAck => Frame::ReferenceOnly("IMMEDIATE_ACK"),
    }
}

fn var(value: u64) -> QVarInt {
    QVarInt::from_u64(value).expect("a value below 2^62")
}

fn stream_id(id: u64) -> QStreamId {
    QStreamId::from(var(id))
}

/// Writes `frame` with the encoder quinn-proto has for it; `None` for frames
/// quinn-proto writes inline in its connection code, and for those it does
/// not have.
pub fn write(frame: &Frame) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match frame {
        Frame::Ack { delay, ranges, ecn } => {
            let mut set = ArrayRangeSet::new();
            for &(start, end) in ranges {
                set.insert(start..end + 1);
            }
            let counts = ecn.map(|(ect0, ect1, ce)| qf::EcnCounts { ect0, ect1, ce });
            qf::Ack::encode(*delay, &set, counts.as_ref(), &mut out);
        }
        Frame::ResetStream {
            id,
            code,
            final_size,
        } => qf::ResetStream {
            id: stream_id(*id),
            error_code: var(*code),
            final_offset: var(*final_size),
        }
        .encode(&mut out),
        Frame::StopSending { id, code } => qf::StopSending {
            id: stream_id(*id),
            error_code: var(*code),
        }
        .encode(&mut out),
        Frame::Crypto { offset, data } => qf::Crypto {
            offset: *offset,
            data: Bytes::copy_from_slice(data),
        }
        .encode(&mut out),
        Frame::NewToken { token } => qf::NewToken {
            token: Bytes::copy_from_slice(token),
        }
        .encode(&mut out),
        Frame::Stream {
            id,
            offset,
            fin,
            has_length,
            data,
        } => {
            qf::StreamMeta {
                id: stream_id(*id),
                offsets: *offset..*offset + data.len() as u64,
                fin: *fin,
            }
            .encode(*has_length, &mut out);
            out.put_slice(data);
        }
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            cid,
            token,
        } => qf::NewConnectionId {
            sequence: *sequence,
            retire_prior_to: *retire_prior_to,
            id: ConnectionId::new(cid),
            reset_token: (*token).into(),
        }
        .encode(&mut out),
        Frame::TransportClose {
            code,
            frame_type,
            reason,
        } => {
            let mut encoded = Vec::new();
            var(*code).encode(&mut encoded);
            let error_code = TransportErrorCode::decode(&mut encoded.as_slice())
                .expect("an encoded variable-length integer");
            qf::ConnectionClose {
                error_code,
                frame_type: (*frame_type != 0).then_some(qf::FrameType(*frame_type)),
                reason: Bytes::copy_from_slice(reason),
            }
            .encode(&mut out, usize::MAX);
        }
        Frame::ApplicationClose { code, reason } => qf::ApplicationClose {
            error_code: var(*code),
            reason: Bytes::copy_from_slice(reason),
        }
        .encode(&mut out, usize::MAX),
        Frame::Datagram { has_length, data } => qf::Datagram {
            data: Bytes::copy_from_slice(data),
        }
        .encode(*has_length, &mut out),
        _ => return None,
    }
    Some(out)
}
