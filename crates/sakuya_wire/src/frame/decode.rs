//! Decoding of frames from a packet payload.
use super::{
    Ack, AckRanges, ConnectionClose, Crypto, DataBlocked, Datagram, DecodeError, EcnCounts,
    Extensions, Frame, FrameType, HandshakeDone, MAX_CID_LEN, MAX_STREAM_COUNT, MaxData,
    MaxStreamData, MaxStreams, NewConnectionId, NewToken, Padding, PathChallenge, PathResponse,
    Ping, ResetStream, ResetStreamAt, RetireConnectionId, StopSending, Stream, StreamDataBlocked,
    StreamsBlocked, stream_bits, type_value,
};
use crate::{stream_id::Directionality, var_int::VarInt};
use core::num::NonZeroUsize;

/// Reads the fields of the frame that starts at `start`.
struct Reader<'a> {
    input: &'a [u8],
    start: usize,
    offset: usize,
    frame_type: Option<VarInt>,
}

impl<'a> Reader<'a> {
    fn truncated(&self, required: usize) -> DecodeError {
        DecodeError::Truncated {
            offset: self.start,
            frame_type: self.frame_type,
            required,
            available: self.input.len(),
        }
    }

    fn var_int(&mut self) -> Result<VarInt, DecodeError> {
        let rest = &self.input[self.offset..];
        match VarInt::decode(rest) {
            Ok((value, len)) => {
                self.offset += len;
                Ok(value)
            }
            Err(_) => {
                let len = rest
                    .first()
                    .map_or(1, |&first| VarInt::encoded_len_of(first));
                Err(self.truncated(self.offset + len))
            }
        }
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], DecodeError> {
        let end = usize::try_from(len)
            .ok()
            .and_then(|len| self.offset.checked_add(len));
        match end {
            Some(end) if end <= self.input.len() => {
                let field = &self.input[self.offset..end];
                self.offset = end;
                Ok(field)
            }
            _ => Err(self.truncated(end.unwrap_or(usize::MAX))),
        }
    }

    fn array<const LEN: usize>(&mut self) -> Result<&'a [u8; LEN], DecodeError> {
        match self.input[self.offset..].first_chunk::<LEN>() {
            Some(field) => {
                self.offset += LEN;
                Ok(field)
            }
            None => Err(self.truncated(self.offset + LEN)),
        }
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    fn rest(&mut self) -> &'a [u8] {
        let field = &self.input[self.offset..];
        self.offset = self.input.len();
        field
    }
}

pub(super) fn decode_at(
    input: &[u8],
    start: usize,
    extensions: Extensions,
) -> Result<(Frame<'_>, usize), DecodeError> {
    use type_value::*;
    let mut reader = Reader {
        input,
        start,
        offset: start,
        frame_type: None,
    };
    let frame_type = reader.var_int()?;
    reader.frame_type = Some(frame_type);
    let Some(kind) = FrameType::of(frame_type).filter(|&kind| extensions.permits(kind)) else {
        return Err(DecodeError::UnknownType {
            offset: start,
            frame_type,
        });
    };
    let value = frame_type.get();
    let frame = match kind {
        FrameType::Padding => {
            // A one-byte PADDING frame continues as far as the zero bytes go;
            // a longer encoding of type 0 is a single frame.
            if reader.offset - start == 1 {
                let zeros = input[reader.offset..]
                    .iter()
                    .take_while(|&&byte| byte == 0)
                    .count();
                reader.offset += zeros;
            }
            Frame::Padding(Padding {
                len: NonZeroUsize::MIN.saturating_add(reader.offset - start - 1),
            })
        }
        FrameType::Ping => Frame::Ping(Ping),
        FrameType::Ack => Frame::Ack(decode_ack(&mut reader, value == ACK_ECN)?),
        FrameType::ResetStream => Frame::ResetStream(ResetStream {
            stream_id: reader.var_int()?.into(),
            application_error_code: reader.var_int()?,
            final_size: reader.var_int()?,
        }),
        FrameType::StopSending => Frame::StopSending(StopSending {
            stream_id: reader.var_int()?.into(),
            application_error_code: reader.var_int()?,
        }),
        FrameType::Crypto => {
            let offset = reader.var_int()?;
            let length = reader.var_int()?;
            check_data_end(start, frame_type, offset, length.get())?;
            Frame::Crypto(Crypto {
                offset,
                data: reader.take(length.get())?,
            })
        }
        FrameType::NewToken => {
            let length = reader.var_int()?;
            let token = reader.take(length.get())?;
            if token.is_empty() {
                return Err(DecodeError::EmptyToken { offset: start });
            }
            Frame::NewToken(NewToken { token })
        }
        FrameType::Stream => {
            let stream_id = reader.var_int()?.into();
            let offset = if value & stream_bits::OFF != 0 {
                reader.var_int()?
            } else {
                VarInt::ZERO
            };
            let has_length = value & stream_bits::LEN != 0;
            let data = if has_length {
                let length = reader.var_int()?;
                check_data_end(start, frame_type, offset, length.get())?;
                reader.take(length.get())?
            } else {
                let data = reader.rest();
                check_data_end(start, frame_type, offset, data.len() as u64)?;
                data
            };
            Frame::Stream(Stream {
                stream_id,
                offset,
                data,
                fin: value & stream_bits::FIN != 0,
                has_length,
            })
        }
        FrameType::MaxData => Frame::MaxData(MaxData {
            maximum_data: reader.var_int()?,
        }),
        FrameType::MaxStreamData => Frame::MaxStreamData(MaxStreamData {
            stream_id: reader.var_int()?.into(),
            maximum_stream_data: reader.var_int()?,
        }),
        FrameType::MaxStreams => Frame::MaxStreams(MaxStreams {
            directionality: directionality(value == MAX_STREAMS_UNI),
            maximum_streams: stream_count(&mut reader, frame_type)?,
        }),
        FrameType::DataBlocked => Frame::DataBlocked(DataBlocked {
            maximum_data: reader.var_int()?,
        }),
        FrameType::StreamDataBlocked => Frame::StreamDataBlocked(StreamDataBlocked {
            stream_id: reader.var_int()?.into(),
            maximum_stream_data: reader.var_int()?,
        }),
        FrameType::StreamsBlocked => Frame::StreamsBlocked(StreamsBlocked {
            directionality: directionality(value == STREAMS_BLOCKED_UNI),
            maximum_streams: stream_count(&mut reader, frame_type)?,
        }),
        FrameType::NewConnectionId => {
            let sequence_number = reader.var_int()?;
            let retire_prior_to = reader.var_int()?;
            let length = reader.byte()?;
            if length == 0 || usize::from(length) > MAX_CID_LEN {
                return Err(DecodeError::ConnectionIdLength {
                    offset: start,
                    length,
                });
            }
            let connection_id = reader.take(length.into())?;
            let stateless_reset_token = reader.array()?;
            if retire_prior_to > sequence_number {
                return Err(DecodeError::RetirePriorTo {
                    offset: start,
                    sequence_number,
                    retire_prior_to,
                });
            }
            Frame::NewConnectionId(NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            })
        }
        FrameType::RetireConnectionId => Frame::RetireConnectionId(RetireConnectionId {
            sequence_number: reader.var_int()?,
        }),
        FrameType::PathChallenge => Frame::PathChallenge(PathChallenge {
            data: *reader.array()?,
        }),
        FrameType::PathResponse => Frame::PathResponse(PathResponse {
            data: *reader.array()?,
        }),
        FrameType::ConnectionClose => {
            let error_code = reader.var_int()?;
            let frame_type = if value == CONNECTION_CLOSE {
                Some(reader.var_int()?)
            } else {
                None
            };
            let length = reader.var_int()?;
            Frame::ConnectionClose(ConnectionClose {
                error_code,
                frame_type,
                reason_phrase: reader.take(length.get())?,
            })
        }
        FrameType::HandshakeDone => Frame::HandshakeDone(HandshakeDone),
        FrameType::ResetStreamAt => {
            let stream_id = reader.var_int()?.into();
            let application_error_code = reader.var_int()?;
            let final_size = reader.var_int()?;
            let reliable_size = reader.var_int()?;
            if reliable_size > final_size {
                return Err(DecodeError::ReliableSize {
                    offset: start,
                    final_size,
                    reliable_size,
                });
            }
            Frame::ResetStreamAt(ResetStreamAt {
                stream_id,
                application_error_code,
                final_size,
                reliable_size,
            })
        }
        FrameType::Datagram => {
            let has_length = value == DATAGRAM_WITH_LENGTH;
            let data = if has_length {
                let length = reader.var_int()?;
                reader.take(length.get())?
            } else {
                reader.rest()
            };
            Frame::Datagram(Datagram { data, has_length })
        }
    };
    Ok((frame, reader.offset - start))
}

pub(super) fn directionality(unidirectional: bool) -> Directionality {
    if unidirectional {
        Directionality::Unidirectional
    } else {
        Directionality::Bidirectional
    }
}

fn check_data_end(
    start: usize,
    frame_type: VarInt,
    data_offset: VarInt,
    length: u64,
) -> Result<(), DecodeError> {
    if length > VarInt::MAX.get() - data_offset.get() {
        return Err(DecodeError::DataEnd {
            offset: start,
            frame_type,
            data_offset,
            length,
        });
    }
    Ok(())
}

fn stream_count(reader: &mut Reader<'_>, frame_type: VarInt) -> Result<VarInt, DecodeError> {
    let maximum_streams = reader.var_int()?;
    if maximum_streams.get() > MAX_STREAM_COUNT {
        return Err(DecodeError::StreamCount {
            offset: reader.start,
            frame_type,
            maximum_streams,
        });
    }
    Ok(maximum_streams)
}

fn decode_ack<'a>(reader: &mut Reader<'a>, ecn: bool) -> Result<Ack<AckRanges<'a>>, DecodeError> {
    let frame_type = reader.frame_type.unwrap_or_default();
    let largest = reader.var_int()?.get();
    let ack_delay = reader.var_int()?;
    let count = reader.var_int()?.get();
    let ranges_start = reader.offset;
    let start = reader.start;
    let underflow = |index| DecodeError::AckRange {
        offset: start,
        frame_type,
        index,
    };
    let mut smallest = largest
        .checked_sub(reader.var_int()?.get())
        .ok_or_else(|| underflow(0))?;
    for index in 1..=count {
        let gap = reader.var_int()?.get();
        let length = reader.var_int()?.get();
        smallest = smallest
            .checked_sub(gap)
            .and_then(|value| value.checked_sub(2))
            .and_then(|largest| largest.checked_sub(length))
            .ok_or_else(|| underflow(index))?;
    }
    let encoded = &reader.input[ranges_start..reader.offset];
    let ecn_counts = if ecn {
        Some(EcnCounts {
            ect0: reader.var_int()?,
            ect1: reader.var_int()?,
            ce: reader.var_int()?,
        })
    } else {
        None
    };
    Ok(Ack {
        ack_delay,
        ranges: AckRanges {
            encoded,
            largest,
            previous_smallest: None,
            // Every range took at least one byte, so the count fits.
            remaining: usize::try_from(count).map_or(usize::MAX, |count| count + 1),
        },
        ecn_counts,
    })
}
