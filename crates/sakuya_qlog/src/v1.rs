//! QUIC version 1 as qlog writes it: its frames (quic-events §8.13) and its
//! transport parameters (quic-events §5.3, RFC 9000 §18.2).

use core::net::{SocketAddrV4, SocketAddrV6};
use sakuya_wire::v1::{
    frame::{FrameRun, connection_close::CloseErrorCode},
    stream_id::Directionality,
    transport_error::TransportErrorCode,
    transport_parameters::{
        connection_id::{
            InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
        },
        disable_active_migration::DisableActiveMigration,
        integer::{
            AckDelayExponent, ActiveConnectionIdLimit, InitialMaxData,
            InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni,
            InitialMaxStreamsBidi, InitialMaxStreamsUni, MaxAckDelay, MaxIdleTimeout,
            MaxUdpPayloadSize,
        },
        preferred_address::{PreferredAddress, PreferredAddressFamilies},
        stateless_reset_token::StatelessResetToken,
    },
};

use crate::{
    json::{ArrayWriter, ObjectWriter},
    parameters::QlogParameter,
    part::{CarriedData, QlogPart},
};

impl QlogPart for sakuya_connection::v1::Part {
    fn write_run(run: &FrameRun<&[u8]>, frames: &mut ArrayWriter<'_>) {
        frames.object(|frame| match run {
            FrameRun::Padding(padding) => {
                let length = padding.len().get() as u64;
                frame.str("frame_type", "padding").object("raw", |raw| {
                    raw.u64("length", length).u64("payload_length", length);
                });
            }
            FrameRun::Ping(_) => {
                frame.str("frame_type", "ping");
            }
            FrameRun::Ack(ack) => {
                // `ack_delay` is not written: the draft has it in
                // milliseconds, and the frame's field is in units of
                // 2^ack_delay_exponent microseconds, an exponent the sender
                // of the frame set in its transport parameters, which the
                // frame alone does not tell.
                frame
                    .str("frame_type", "ack")
                    .array("acked_ranges", |ranges| {
                        // largest first; a range of one packet is `[n]`
                        // (§8.13.3)
                        for range in ack.packet_ranges() {
                            let (from, to) = (range.start().get(), range.end().get());
                            ranges.array(|range| {
                                range.u64(from);
                                if to != from {
                                    range.u64(to);
                                }
                            });
                        }
                    });
                if let Some(ecn) = ack.ecn_counts() {
                    frame
                        .u64("ect1", ecn.ect1.get().get())
                        .u64("ect0", ecn.ect0.get().get())
                        .u64("ce", ecn.ce.get().get());
                }
            }
            FrameRun::ResetStream(reset) => {
                frame
                    .str("frame_type", "reset_stream")
                    .u64("stream_id", reset.stream_id().get().get().get())
                    // `$ApplicationError` has no names of its own: the
                    // number is given beside "unknown".
                    .str("error", "unknown")
                    .u64(
                        "error_code",
                        reset.application_error_code().get().get().get(),
                    )
                    .u64("final_size", reset.final_size().get().get());
            }
            FrameRun::StopSending(stop) => {
                frame
                    .str("frame_type", "stop_sending")
                    .u64("stream_id", stop.stream_id().get().get().get())
                    .str("error", "unknown")
                    .u64(
                        "error_code",
                        stop.application_error_code().get().get().get(),
                    );
            }
            FrameRun::Crypto(crypto) => {
                frame
                    .str("frame_type", "crypto")
                    .u64("offset", crypto.offset().get().get())
                    .object("raw", |raw| {
                        raw.u64("length", crypto.data().len() as u64);
                    });
            }
            FrameRun::NewToken(new_token) => {
                // the token's length alone: the token lets a later
                // connection from the client's address skip address
                // validation (RFC 9000 §8.1.3), past the life of this one
                let token: &[u8] = new_token.token();
                frame.str("frame_type", "new_token").object("token", |t| {
                    t.object("raw", |raw| {
                        raw.u64("length", token.len() as u64);
                    });
                });
            }
            FrameRun::Stream(stream) => {
                frame
                    .str("frame_type", "stream")
                    .u64("stream_id", stream.stream_id().get().get().get());
                // The offset defaults to 0, the fin to false (§8.13.9).
                if let Some(offset) = stream.offset() {
                    frame.u64("offset", offset.get().get());
                }
                if stream.fin() {
                    frame.bool("fin", true);
                }
                frame.object("raw", |raw| {
                    raw.u64("length", stream.data().len() as u64);
                });
            }
            FrameRun::MaxData(max) => {
                frame
                    .str("frame_type", "max_data")
                    .u64("maximum", max.maximum_data().get().get());
            }
            FrameRun::MaxStreamData(max) => {
                frame
                    .str("frame_type", "max_stream_data")
                    .u64("stream_id", max.stream_id().get().get().get())
                    .u64("maximum", max.maximum_stream_data().get().get());
            }
            FrameRun::MaxStreams(max) => {
                frame
                    .str("frame_type", "max_streams")
                    .str("stream_type", stream_type(max.directionality()))
                    .u64("maximum", max.maximum_streams().get().get());
            }
            FrameRun::DataBlocked(blocked) => {
                frame
                    .str("frame_type", "data_blocked")
                    .u64("limit", blocked.maximum_data().get().get());
            }
            FrameRun::StreamDataBlocked(blocked) => {
                frame
                    .str("frame_type", "stream_data_blocked")
                    .u64("stream_id", blocked.stream_id().get().get().get())
                    .u64("limit", blocked.maximum_stream_data().get().get());
            }
            FrameRun::StreamsBlocked(blocked) => {
                frame
                    .str("frame_type", "streams_blocked")
                    .str("stream_type", stream_type(blocked.directionality()))
                    .u64("limit", blocked.maximum_streams().get().get());
            }
            FrameRun::NewConnectionId(new) => {
                let cid = new.connection_id();
                let connection_id = cid.as_bytes();
                frame
                    .str("frame_type", "new_connection_id")
                    .u64("sequence_number", new.sequence_number().get().get())
                    .u64("retire_prior_to", new.retire_prior_to().get().get())
                    .u64("connection_id_length", connection_id.len() as u64)
                    .hex("connection_id", connection_id)
                    .hex(
                        "stateless_reset_token",
                        new.stateless_reset_token().as_bytes(),
                    );
            }
            FrameRun::RetireConnectionId(retire) => {
                frame
                    .str("frame_type", "retire_connection_id")
                    .u64("sequence_number", retire.sequence_number().get().get());
            }
            FrameRun::PathChallenge(challenge) => {
                frame
                    .str("frame_type", "path_challenge")
                    .hex("data", &challenge.data());
            }
            FrameRun::PathResponse(response) => {
                frame
                    .str("frame_type", "path_response")
                    .hex("data", &response.data());
            }
            FrameRun::ConnectionClose(close) => {
                frame.str("frame_type", "connection_close");
                let trigger = match close.error_code() {
                    CloseErrorCode::Transport { code, frame_type } => {
                        frame.str("error_space", "transport");
                        write_transport_error(frame, "error", code.get());
                        Some(frame_type.get().get())
                    }
                    CloseErrorCode::Application { code } => {
                        frame
                            .str("error_space", "application")
                            .str("error", "unknown")
                            .u64("error_code", code.get().get().get());
                        None
                    }
                };
                let reason: &[u8] = close.reason_phrase();
                if !reason.is_empty() {
                    match core::str::from_utf8(reason) {
                        Ok(text) => frame.str("reason", text),
                        Err(_) => frame.hex("reason_bytes", reason),
                    };
                }
                match trigger {
                    Some(value) => match frame_type_name(value) {
                        Some(name) => frame.str("trigger_frame_type", name),
                        None => frame.u64("trigger_frame_type", value),
                    },
                    None => frame,
                };
            }
            FrameRun::HandshakeDone(_) => {
                frame.str("frame_type", "handshake_done");
            }
        });
    }

    fn carried_data(run: &FrameRun<&[u8]>) -> Option<CarriedData> {
        match run {
            FrameRun::Stream(stream) => Some(CarriedData::Stream {
                stream_id: stream.stream_id().get(),
                offset: stream.data_offset().get(),
                length: stream.data().len() as u64,
            }),
            _ => None,
        }
    }
}

fn stream_type(directionality: Directionality) -> &'static str {
    match directionality {
        Directionality::Bidirectional => "bidirectional",
        Directionality::Unidirectional => "unidirectional",
    }
}

/// A transport error under `key`, with `error_code` for a code without a
/// name (§8.14, §8.16): the RFC 9000 name in lower case,
/// `crypto_error_0x1XX` in the CRYPTO_ERROR range, or "unknown" with the
/// number.
pub(crate) fn write_transport_error(
    object: &mut ObjectWriter<'_>,
    key: &'static str,
    code: TransportErrorCode,
) {
    if let Some(alert) = code.crypto_alert() {
        object.str(key, &format!("crypto_error_0x1{alert:02x}"));
    } else if let Some(name) = code.name() {
        object.str(key, &name.to_ascii_lowercase());
    } else {
        object
            .str(key, "unknown")
            .u64("error_code", code.get().get());
    }
}

/// The name qlog gives a frame type that RFC 9000 defines, by its Frame
/// Type value; the extensions' frame types are written as numbers.
fn frame_type_name(value: u64) -> Option<&'static str> {
    Some(match value {
        0x00 => "padding",
        0x01 => "ping",
        0x02 | 0x03 => "ack",
        0x04 => "reset_stream",
        0x05 => "stop_sending",
        0x06 => "crypto",
        0x07 => "new_token",
        0x08..=0x0f => "stream",
        0x10 => "max_data",
        0x11 => "max_stream_data",
        0x12 | 0x13 => "max_streams",
        0x14 => "data_blocked",
        0x15 => "stream_data_blocked",
        0x16 | 0x17 => "streams_blocked",
        0x18 => "new_connection_id",
        0x19 => "retire_connection_id",
        0x1a => "path_challenge",
        0x1b => "path_response",
        0x1c | 0x1d => "connection_close",
        0x1e => "handshake_done",
        _ => return None,
    })
}

/// A parameter whose value is one number, written under `$key`.
macro_rules! number_parameter {
    ($($parameter:ty => $key:literal, $value:expr;)*) => {$(
        impl QlogParameter for $parameter {
            fn write(&self, parameters: &mut ObjectWriter<'_>) {
                let value: fn(&$parameter) -> u64 = $value;
                parameters.u64($key, value(self));
            }
        }
    )*};
}

// `max_idle_timeout` and `max_ack_delay` are in milliseconds, as the draft
// has them; the others are as the RFC defines them.
number_parameter! {
    MaxIdleTimeout => "max_idle_timeout", |p| p.get().get();
    MaxUdpPayloadSize => "max_udp_payload_size", |p| p.get().get();
    AckDelayExponent => "ack_delay_exponent", |p| p.get().get();
    MaxAckDelay => "max_ack_delay", |p| p.get().get();
    ActiveConnectionIdLimit => "active_connection_id_limit", |p| p.get().get();
    InitialMaxData => "initial_max_data", |p| p.get().get();
    InitialMaxStreamDataBidiLocal => "initial_max_stream_data_bidi_local", |p| p.get().get();
    InitialMaxStreamDataBidiRemote => "initial_max_stream_data_bidi_remote", |p| p.get().get();
    InitialMaxStreamDataUni => "initial_max_stream_data_uni", |p| p.get().get();
    InitialMaxStreamsBidi => "initial_max_streams_bidi", |p| p.get().get();
    InitialMaxStreamsUni => "initial_max_streams_uni", |p| p.get().get();
}

/// A parameter whose value is a connection ID, written under `$key`.
macro_rules! connection_id_parameter {
    ($($parameter:ty => $key:literal;)*) => {$(
        impl QlogParameter for $parameter {
            fn write(&self, parameters: &mut ObjectWriter<'_>) {
                parameters.hex($key, self.get().as_bytes());
            }
        }
    )*};
}

connection_id_parameter! {
    OriginalDestinationConnectionId => "original_destination_connection_id";
    InitialSourceConnectionId => "initial_source_connection_id";
    RetrySourceConnectionId => "retry_source_connection_id";
}

impl QlogParameter for StatelessResetToken {
    fn write(&self, parameters: &mut ObjectWriter<'_>) {
        parameters.hex("stateless_reset_token", self.get().as_bytes());
    }
}

impl QlogParameter for DisableActiveMigration {
    fn write(&self, parameters: &mut ObjectWriter<'_>) {
        parameters.bool("disable_active_migration", true);
    }
}

impl QlogParameter for PreferredAddress {
    fn write(&self, parameters: &mut ObjectWriter<'_>) {
        parameters.object("preferred_address", |address| {
            match self.addresses {
                PreferredAddressFamilies::Ipv4(v4) => write_v4(address, v4),
                PreferredAddressFamilies::Ipv6(v6) => write_v6(address, v6),
                PreferredAddressFamilies::Both(v4, v6) => {
                    write_v4(address, v4);
                    write_v6(address, v6);
                }
            }
            address
                .hex("connection_id", self.connection_id.as_bytes())
                .hex(
                    "stateless_reset_token",
                    self.stateless_reset_token.as_bytes(),
                );
        });
    }
}

fn write_v4(address: &mut ObjectWriter<'_>, v4: SocketAddrV4) {
    address.object("address_v4", |a| {
        a.str("ip", &v4.ip().to_string())
            .u64("port", u64::from(v4.port()));
    });
}

fn write_v6(address: &mut ObjectWriter<'_>, v6: SocketAddrV6) {
    address.object("address_v6", |a| {
        a.str("ip", &v6.ip().to_string())
            .u64("port", u64::from(v6.port()));
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use core::marker::PhantomData;

    use sakuya_wire::{
        connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken as Token},
        parts::HList,
        v1::frame::set::Frames,
        var_int::VarInt,
    };

    use super::*;
    use crate::{json::object, part::QlogParts};

    /// The frames in `bytes`, written as a `frames` array.
    pub(crate) fn frames_of<P: QlogPart>(bytes: &[u8]) -> String {
        let mut buf = Vec::new();
        object(&mut buf, |o| {
            o.array("frames", |a| {
                for run in Frames::new(bytes, PhantomData::<HList![P]>) {
                    let Ok(run) = run else {
                        panic!("the test bytes do not read");
                    };
                    <HList![P] as QlogParts>::write_run(&run, a);
                }
            });
        });
        String::from_utf8(buf).unwrap()
    }

    pub(crate) fn parameter_of(write: impl FnOnce(&mut ObjectWriter<'_>)) -> String {
        let mut buf = Vec::new();
        object(&mut buf, write);
        String::from_utf8(buf).unwrap()
    }

    fn frames(bytes: &[u8]) -> String {
        frames_of::<sakuya_connection::v1::Part>(bytes)
    }

    fn one(frame: &str) -> String {
        format!(r#"{{"frames":[{frame}]}}"#)
    }

    #[test]
    fn padding_is_one_frame_for_the_run() {
        assert_eq!(
            frames(&[0, 0, 0]),
            one(r#"{"frame_type":"padding","raw":{"length":3,"payload_length":3}}"#)
        );
    }

    #[test]
    fn ping_and_handshake_done() {
        assert_eq!(frames(&[0x01]), one(r#"{"frame_type":"ping"}"#));
        assert_eq!(frames(&[0x1e]), one(r#"{"frame_type":"handshake_done"}"#));
    }

    #[test]
    fn ack_with_two_ranges() {
        // largest 10, delay 5, one more range, first range 1 (9..=10),
        // gap 0, range length 0 (7..=7)
        assert_eq!(
            frames(&[0x02, 10, 5, 1, 1, 0, 0]),
            one(r#"{"frame_type":"ack","acked_ranges":[[9,10],[7]]}"#)
        );
    }

    #[test]
    fn ack_with_ecn_counts() {
        assert_eq!(
            frames(&[0x03, 10, 5, 0, 0, 1, 2, 3]),
            one(r#"{"frame_type":"ack","acked_ranges":[[10]],"ect1":2,"ect0":1,"ce":3}"#)
        );
    }

    #[test]
    fn crypto_has_offset_and_length() {
        assert_eq!(
            frames(&[0x06, 5, 3, 1, 2, 3]),
            one(r#"{"frame_type":"crypto","offset":5,"raw":{"length":3}}"#)
        );
    }

    #[test]
    fn stream_with_fin() {
        let bytes = [0x0f, 4, 10, 2, 0xaa, 0xbb];
        assert_eq!(
            frames(&bytes),
            one(
                r#"{"frame_type":"stream","stream_id":4,"offset":10,"fin":true,"raw":{"length":2}}"#
            )
        );
        let run = Frames::new(
            &bytes[..],
            PhantomData::<HList![sakuya_connection::v1::Part]>,
        )
        .next()
        .unwrap()
        .unwrap();
        let sakuya_wire::parts::Coproduct::Inl(run) = run;
        match <sakuya_connection::v1::Part as QlogPart>::carried_data(&run) {
            Some(CarriedData::Stream {
                stream_id,
                offset,
                length,
            }) => {
                assert_eq!(stream_id.get().get(), 4);
                assert_eq!((offset, length), (10, 2));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn stream_without_offset_or_fin() {
        assert_eq!(
            frames(&[0x0a, 0, 1, 0xff]),
            one(r#"{"frame_type":"stream","stream_id":0,"raw":{"length":1}}"#)
        );
    }

    #[test]
    fn reset_stream() {
        assert_eq!(
            frames(&[0x04, 4, 0x10, 0x40, 0x64]),
            one(
                r#"{"frame_type":"reset_stream","stream_id":4,"error":"unknown","error_code":16,"final_size":100}"#
            )
        );
    }

    #[test]
    fn new_token_has_the_length_alone() {
        assert_eq!(
            frames(&[0x07, 3, 1, 2, 3]),
            one(r#"{"frame_type":"new_token","token":{"raw":{"length":3}}}"#)
        );
    }

    #[test]
    fn max_streams_both_kinds() {
        assert_eq!(
            frames(&[0x12, 5]),
            one(r#"{"frame_type":"max_streams","stream_type":"bidirectional","maximum":5}"#)
        );
        assert_eq!(
            frames(&[0x13, 5]),
            one(r#"{"frame_type":"max_streams","stream_type":"unidirectional","maximum":5}"#)
        );
    }

    #[test]
    fn new_connection_id() {
        let mut bytes = vec![0x18, 1, 0, 4, 1, 2, 3, 4];
        bytes.extend_from_slice(&[0xab; 16]);
        assert_eq!(
            frames(&bytes),
            one(&format!(
                r#"{{"frame_type":"new_connection_id","sequence_number":1,"retire_prior_to":0,"connection_id_length":4,"connection_id":"01020304","stateless_reset_token":"{}"}}"#,
                "ab".repeat(16)
            ))
        );
    }

    #[test]
    fn connection_close_transport_names_the_error_and_the_frame() {
        assert_eq!(
            frames(&[0x1c, 0x0a, 0x06, 2, b'n', b'o']),
            one(
                r#"{"frame_type":"connection_close","error_space":"transport","error":"protocol_violation","reason":"no","trigger_frame_type":"crypto"}"#
            )
        );
    }

    #[test]
    fn connection_close_transport_crypto_and_unknown_codes() {
        assert_eq!(
            frames(&[0x1c, 0x41, 0x28, 0, 0]),
            one(
                r#"{"frame_type":"connection_close","error_space":"transport","error":"crypto_error_0x128","trigger_frame_type":"padding"}"#
            )
        );
        assert_eq!(
            frames(&[0x1c, 0x20, 0x21, 0]),
            one(
                r#"{"frame_type":"connection_close","error_space":"transport","error":"unknown","error_code":32,"trigger_frame_type":33}"#
            )
        );
    }

    #[test]
    fn connection_close_application() {
        assert_eq!(
            frames(&[0x1d, 5, 0]),
            one(
                r#"{"frame_type":"connection_close","error_space":"application","error":"unknown","error_code":5}"#
            )
        );
        assert_eq!(
            frames(&[0x1d, 5, 2, 0xff, 0xfe]),
            one(
                r#"{"frame_type":"connection_close","error_space":"application","error":"unknown","error_code":5,"reason_bytes":"fffe"}"#
            )
        );
    }

    #[test]
    fn integer_parameter() {
        let text = parameter_of(|o| MaxIdleTimeout::new(VarInt::from_u32(30_000)).write(o));
        assert_eq!(text, r#"{"max_idle_timeout":30000}"#);
    }

    #[test]
    fn connection_id_parameter() {
        let id = ConnectionId::new(&[1, 2, 3, 4]).unwrap();
        let text = parameter_of(|o| InitialSourceConnectionId::new(id).write(o));
        assert_eq!(text, r#"{"initial_source_connection_id":"01020304"}"#);
    }

    #[test]
    fn flag_and_token_parameters() {
        let text = parameter_of(|o| {
            DisableActiveMigration.write(o);
            StatelessResetToken::new(Token::new([0x0f; 16])).write(o);
        });
        assert_eq!(
            text,
            format!(
                r#"{{"disable_active_migration":true,"stateless_reset_token":"{}"}}"#,
                "0f".repeat(16)
            )
        );
    }

    #[test]
    fn preferred_address_parameter() {
        let cid = NonEmptyCid::new(ConnectionId::new(&[9, 9]).unwrap()).unwrap();
        let address = PreferredAddress {
            addresses: PreferredAddressFamilies::Ipv4(SocketAddrV4::new(
                [192, 0, 2, 1].into(),
                443,
            )),
            connection_id: cid,
            stateless_reset_token: Token::new([1; 16]),
        };
        let text = parameter_of(|o| address.write(o));
        assert_eq!(
            text,
            format!(
                r#"{{"preferred_address":{{"address_v4":{{"ip":"192.0.2.1","port":443}},"connection_id":"0909","stateless_reset_token":"{}"}}}}"#,
                "01".repeat(16)
            )
        );
    }
}
