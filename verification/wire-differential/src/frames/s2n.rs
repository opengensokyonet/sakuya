//! The adapter of s2n-quic-core: its frame decoder and encoders.
use super::{Decoded, Frame};
use core::ops::RangeInclusive;
use s2n_codec::{DecoderBufferMut, EncoderValue as _};
use s2n_quic_core::{
    frame::{self as sf, ack::AckRanges as _},
    stream::StreamType,
    varint::VarInt as SVarInt,
};

/// Walks `payload` with the frame decoder of s2n-quic-core.
pub fn read(payload: &[u8]) -> Decoded {
    read_with_error(payload).0
}

/// Like [`read`], with the error s2n-quic-core reports for a failure.
pub fn read_with_error(payload: &[u8]) -> (Decoded, Option<String>) {
    let mut storage = payload.to_vec();
    let mut buffer = DecoderBufferMut::new(&mut storage);
    let mut decoded = Decoded::default();
    while !buffer.is_empty() {
        match buffer.decode::<sf::FrameMut>() {
            Ok((frame, rest)) => {
                decoded.frames.extend(model(frame));
                buffer = rest;
            }
            Err(error) => {
                decoded.failed = true;
                return (decoded, Some(error.to_string()));
            }
        }
    }
    (decoded, None)
}

fn model(frame: sf::FrameMut<'_>) -> Vec<Frame> {
    use sf::Frame as S;
    let uni = |ty| ty == StreamType::Unidirectional;
    let frame = match frame {
        S::Padding(f) => return vec![Frame::Padding; f.length],
        S::Ping(_) => Frame::Ping,
        S::Ack(f) => Frame::Ack {
            delay: f.ack_delay.as_u64(),
            ranges: f
                .ack_ranges
                .ack_ranges()
                .map(|range| (range.start().as_u64(), range.end().as_u64()))
                .collect(),
            ecn: f.ecn_counts.map(|counts| {
                (
                    counts.ect_0_count.as_u64(),
                    counts.ect_1_count.as_u64(),
                    counts.ce_count.as_u64(),
                )
            }),
        },
        S::ResetStream(f) => Frame::ResetStream {
            id: f.stream_id.as_u64(),
            code: f.application_error_code.as_u64(),
            final_size: f.final_size.as_u64(),
        },
        S::StopSending(f) => Frame::StopSending {
            id: f.stream_id.as_u64(),
            code: f.application_error_code.as_u64(),
        },
        S::Crypto(f) => Frame::Crypto {
            offset: f.offset.as_u64(),
            data: f.data.into_less_safe_slice().to_vec(),
        },
        S::NewToken(f) => Frame::NewToken {
            token: f.token.to_vec(),
        },
        S::Stream(f) => Frame::Stream {
            id: f.stream_id.as_u64(),
            offset: f.offset.as_u64(),
            fin: f.is_fin,
            has_length: !f.is_last_frame,
            data: f.data.into_less_safe_slice().to_vec(),
        },
        S::MaxData(f) => Frame::MaxData(f.maximum_data.as_u64()),
        S::MaxStreamData(f) => Frame::MaxStreamData {
            id: f.stream_id.as_u64(),
            limit: f.maximum_stream_data.as_u64(),
        },
        S::MaxStreams(f) => Frame::MaxStreams {
            uni: uni(f.stream_type),
            count: f.maximum_streams.as_u64(),
        },
        S::DataBlocked(f) => Frame::DataBlocked(f.data_limit.as_u64()),
        S::StreamDataBlocked(f) => Frame::StreamDataBlocked {
            id: f.stream_id.as_u64(),
            limit: f.stream_data_limit.as_u64(),
        },
        S::StreamsBlocked(f) => Frame::StreamsBlocked {
            uni: uni(f.stream_type),
            count: f.stream_limit.as_u64(),
        },
        S::NewConnectionId(f) => Frame::NewConnectionId {
            sequence: f.sequence_number.as_u64(),
            retire_prior_to: f.retire_prior_to.as_u64(),
            cid: f.connection_id.to_vec(),
            token: *f.stateless_reset_token,
        },
        S::RetireConnectionId(f) => Frame::RetireConnectionId(f.sequence_number.as_u64()),
        S::PathChallenge(f) => Frame::PathChallenge(*f.data),
        S::PathResponse(f) => Frame::PathResponse(*f.data),
        S::ConnectionClose(f) => {
            let reason = f.reason.map_or_else(Vec::new, <[u8]>::to_vec);
            match f.frame_type {
                Some(frame_type) => Frame::TransportClose {
                    code: f.error_code.as_u64(),
                    frame_type: frame_type.as_u64(),
                    reason,
                },
                None => Frame::ApplicationClose {
                    code: f.error_code.as_u64(),
                    reason,
                },
            }
        }
        S::HandshakeDone(_) => Frame::HandshakeDone,
        S::Datagram(f) => Frame::Datagram {
            has_length: !f.is_last_frame,
            data: f.data.into_less_safe_slice().to_vec(),
        },
        S::DcStatelessResetTokens(_) => Frame::ReferenceOnly("DC_STATELESS_RESET_TOKENS"),
        S::MtuProbingComplete(_) => Frame::ReferenceOnly("MTU_PROBING_COMPLETE"),
    };
    vec![frame]
}

/// ACK ranges as s2n-quic-core encodes them.
struct Ranges(Vec<RangeInclusive<SVarInt>>);

impl sf::ack::AckRanges for Ranges {
    type Iter = std::vec::IntoIter<RangeInclusive<SVarInt>>;

    fn ack_ranges(&self) -> Self::Iter {
        self.0.clone().into_iter()
    }
}

/// Writes `frame` with s2n-quic-core; `None` for frames it does not have.
pub fn write(frame: &Frame) -> Option<Vec<u8>> {
    let var = |value: u64| SVarInt::new(value).expect("a value below 2^62");
    let stream_type = |uni| {
        if uni {
            StreamType::Unidirectional
        } else {
            StreamType::Bidirectional
        }
    };
    Some(match frame {
        Frame::Padding => sf::Padding { length: 1 }.encode_to_vec(),
        Frame::Ping => sf::Ping.encode_to_vec(),
        Frame::Ack { delay, ranges, ecn } => sf::Ack {
            ack_delay: var(*delay),
            ack_ranges: Ranges(
                ranges
                    .iter()
                    .map(|&(start, end)| var(start)..=var(end))
                    .collect(),
            ),
            ecn_counts: ecn.map(|(ect0, ect1, ce)| sf::ack::EcnCounts {
                ect_0_count: var(ect0),
                ect_1_count: var(ect1),
                ce_count: var(ce),
            }),
        }
        .encode_to_vec(),
        Frame::ResetStream {
            id,
            code,
            final_size,
        } => sf::ResetStream {
            stream_id: var(*id),
            application_error_code: var(*code),
            final_size: var(*final_size),
        }
        .encode_to_vec(),
        Frame::StopSending { id, code } => sf::StopSending {
            stream_id: var(*id),
            application_error_code: var(*code),
        }
        .encode_to_vec(),
        Frame::Crypto { offset, data } => sf::Crypto {
            offset: var(*offset),
            data: data.as_slice(),
        }
        .encode_to_vec(),
        Frame::NewToken { token } => sf::NewToken { token }.encode_to_vec(),
        Frame::Stream {
            id,
            offset,
            fin,
            has_length,
            data,
        } => sf::Stream {
            stream_id: var(*id),
            offset: var(*offset),
            is_last_frame: !*has_length,
            is_fin: *fin,
            data: data.as_slice(),
        }
        .encode_to_vec(),
        Frame::MaxData(value) => sf::MaxData {
            maximum_data: var(*value),
        }
        .encode_to_vec(),
        Frame::MaxStreamData { id, limit } => sf::MaxStreamData {
            stream_id: var(*id),
            maximum_stream_data: var(*limit),
        }
        .encode_to_vec(),
        Frame::MaxStreams { uni, count } => sf::MaxStreams {
            stream_type: stream_type(*uni),
            maximum_streams: var(*count),
        }
        .encode_to_vec(),
        Frame::DataBlocked(value) => sf::DataBlocked {
            data_limit: var(*value),
        }
        .encode_to_vec(),
        Frame::StreamDataBlocked { id, limit } => sf::StreamDataBlocked {
            stream_id: var(*id),
            stream_data_limit: var(*limit),
        }
        .encode_to_vec(),
        Frame::StreamsBlocked { uni, count } => sf::StreamsBlocked {
            stream_type: stream_type(*uni),
            stream_limit: var(*count),
        }
        .encode_to_vec(),
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            cid,
            token,
        } => sf::NewConnectionId {
            sequence_number: var(*sequence),
            retire_prior_to: var(*retire_prior_to),
            connection_id: cid,
            stateless_reset_token: token,
        }
        .encode_to_vec(),
        Frame::RetireConnectionId(value) => sf::RetireConnectionId {
            sequence_number: var(*value),
        }
        .encode_to_vec(),
        Frame::PathChallenge(data) => sf::PathChallenge { data }.encode_to_vec(),
        Frame::PathResponse(data) => sf::PathResponse { data }.encode_to_vec(),
        Frame::TransportClose {
            code,
            frame_type,
            reason,
        } => sf::ConnectionClose {
            error_code: var(*code),
            frame_type: Some(var(*frame_type)),
            reason: (!reason.is_empty()).then_some(reason.as_slice()),
        }
        .encode_to_vec(),
        Frame::ApplicationClose { code, reason } => sf::ConnectionClose {
            error_code: var(*code),
            frame_type: None,
            reason: (!reason.is_empty()).then_some(reason.as_slice()),
        }
        .encode_to_vec(),
        Frame::HandshakeDone => sf::HandshakeDone.encode_to_vec(),
        Frame::Datagram { has_length, data } => sf::Datagram {
            is_last_frame: !*has_length,
            data: data.as_slice(),
        }
        .encode_to_vec(),
        Frame::ResetStreamAt { .. } | Frame::ReferenceOnly(_) => return None,
    })
}
