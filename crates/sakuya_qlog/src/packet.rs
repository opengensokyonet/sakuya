//! `packet_sent` and `packet_received` (quic-events §5.5, §5.6): the header
//! read from the plaintext, the frames read again with the list of parts,
//! and the application data they carry.

use core::marker::PhantomData;

use sakuya_clock::MonotonicClock;
use sakuya_connection::v1::events::PlainPacket;
use sakuya_wire::{
    v1::{encryption_level::EncryptionLevel, frame::set::Frames},
    var_int::codec::read_var_int,
};

use crate::{
    QlogParts, QlogShared, data_location,
    json::{ArrayWriter, ObjectWriter},
    packet_type,
    part::CarriedData,
};
use sakuya_connection::v1::events::DataLocation;

/// Writes the event `name` of `packet`, which this side `sent` or
/// received, and then a move of data for each frame that carries some: to
/// the network for a packet sent, from it for one received.
pub(crate) fn packet_event<L: QlogParts, C: MonotonicClock>(
    shared: &QlogShared<C>,
    name: &'static str,
    packet: &PlainPacket<'_>,
    sent: bool,
) {
    shared.event(name, |data| {
        data.object("header", |header| write_header(packet, header))
            .array("frames", |frames| {
                write_frames::<L>(packet.payload(), frames)
            })
            .object("raw", |raw| {
                raw.u64("length", raw_length(packet) as u64)
                    .u64("payload_length", packet.payload().len() as u64);
            });
        if packet.pmtu_probe {
            data.bool("is_mtu_probe_packet", true);
        }
    });
    let (from, to) = if sent {
        (DataLocation::Transport, DataLocation::Network)
    } else {
        (DataLocation::Network, DataLocation::Transport)
    };
    for run in Frames::new(packet.payload(), PhantomData::<L>) {
        let Ok(run) = run else {
            break;
        };
        match L::carried_data(&run) {
            Some(CarriedData::Stream {
                stream_id,
                offset,
                length,
            }) => shared.event("quic:stream_data_moved", |data| {
                data.u64("stream_id", stream_id.get().get())
                    .u64("offset", offset)
                    .str("from", data_location(from))
                    .str("to", data_location(to))
                    .object("raw", |raw| {
                        raw.u64("length", length);
                    });
            }),
            Some(CarriedData::Datagram { length }) => {
                shared.event("quic:datagram_data_moved", |data| {
                    data.str("from", data_location(from))
                        .str("to", data_location(to))
                        .object("raw", |raw| {
                            raw.u64("length", length);
                        });
                })
            }
            None => {}
        }
    }
}

/// Writes the frames of `payload`; a frame that cannot be read is written
/// as an unknown one with the bytes from it to the end, and ends the list.
fn write_frames<L: QlogParts>(payload: &[u8], frames: &mut ArrayWriter<'_>) {
    let mut runs = Frames::new(payload, PhantomData::<L>);
    while let Some(run) = runs.next() {
        match run {
            Ok(run) => L::write_run(&run, frames),
            Err(_) => {
                let mut rest = &payload[runs.offset()..];
                let length = rest.len() as u64;
                frames.object(|frame| {
                    frame.str("frame_type", "unknown");
                    // a frame type that does not read leaves the field out
                    if let Ok(frame_type) = read_var_int(&mut rest) {
                        frame.u64("frame_type_bytes", frame_type.get());
                    }
                    frame.object("raw", |raw| {
                        raw.u64("length", length);
                    });
                });
                break;
            }
        }
    }
}

/// The `raw.length` of `packet`: for a long header, the value of its Length
/// field, the packet number and the payload with the AEAD tag (§8.8); for a
/// short one, the whole packet.
fn raw_length(packet: &PlainPacket<'_>) -> usize {
    match packet.level {
        EncryptionLevel::OneRtt => packet.wire_len,
        EncryptionLevel::Initial | EncryptionLevel::ZeroRtt | EncryptionLevel::Handshake => {
            // the Packet Number Length is in the first byte (RFC 9000 §17.2)
            let number_len = packet
                .header()
                .first()
                .map_or(0, |first| usize::from(first & 0x03) + 1);
            packet
                .wire_len
                .saturating_sub(packet.header_len.saturating_sub(number_len))
        }
    }
}

/// Writes the header of `packet` as far as its plaintext tells it: the
/// type and number, the Packet Number Length, and for a long header the
/// version and both connection IDs, for a short one the spin and key phase
/// bits (RFC 9000 §17).
fn write_header(packet: &PlainPacket<'_>, header: &mut ObjectWriter<'_>) {
    header
        .str("packet_type", packet_type(packet.level))
        .u64("packet_number", packet.number);
    let bytes = packet.header();
    let Some(&first) = bytes.first() else {
        return;
    };
    header.u64("packet_number_length", u64::from(first & 0x03) + 1);
    if packet.level == EncryptionLevel::OneRtt {
        header
            .bool("spin_bit", first & 0x20 != 0)
            .bool("key_phase_bit", first & 0x04 != 0);
        return;
    }
    // Version (4), DCID Length (1), DCID, SCID Length (1), SCID
    let Some(version) = bytes.get(1..5) else {
        return;
    };
    header.hex("version", version);
    let Some((dcid, rest)) = length_prefixed(&bytes[5..]) else {
        return;
    };
    let Some((scid, _)) = length_prefixed(rest) else {
        return;
    };
    header
        .u64("dcil", dcid.len() as u64)
        .hex("dcid", dcid)
        .u64("scil", scid.len() as u64)
        .hex("scid", scid);
}

/// A field of one length byte followed by that many bytes, and the rest.
fn length_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    let len = usize::from(len);
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::object;

    type Parts = sakuya_wire::parts::HList![sakuya_connection::v1::Part];

    #[test]
    fn a_long_header_has_the_length_of_its_length_field() {
        // Initial, Packet Number Length 2; version, DCID of 1, SCID of 0,
        // token length 0, Length 2 bytes, packet number 2 bytes
        let bytes = [
            0xc1, 0, 0, 0, 1, 1, 0xaa, 0, 0, 0x40, 0x15, 0, 7,    // header
            0x01, // PING
        ];
        let packet = PlainPacket {
            level: EncryptionLevel::Initial,
            number: 7,
            bytes: &bytes,
            header_len: 13,
            wire_len: 13 + 1 + 16,
            pmtu_probe: false,
        };
        // the packet number, the payload and the tag
        assert_eq!(raw_length(&packet), 2 + 1 + 16);
        let mut buf = Vec::new();
        object(&mut buf, |o| {
            o.object("header", |header| write_header(&packet, header));
        });
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            r#"{"header":{"packet_type":"initial","packet_number":7,"packet_number_length":2,"version":"00000001","dcil":1,"dcid":"aa","scil":0,"scid":""}}"#
        );
    }

    #[test]
    fn a_short_header_has_the_length_of_the_packet() {
        let bytes = [0x44, 0xaa, 3, 0x01];
        let packet = PlainPacket {
            level: EncryptionLevel::OneRtt,
            number: 3,
            bytes: &bytes,
            header_len: 3,
            wire_len: 4 + 16,
            pmtu_probe: false,
        };
        assert_eq!(raw_length(&packet), 20);
        let mut buf = Vec::new();
        object(&mut buf, |o| {
            o.object("header", |header| write_header(&packet, header));
        });
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            r#"{"header":{"packet_type":"1RTT","packet_number":3,"packet_number_length":1,"spin_bit":false,"key_phase_bit":true}}"#
        );
    }

    #[test]
    fn a_frame_that_does_not_read_ends_the_list_as_unknown() {
        // PING, then a frame of type 0x40 0x21 that no part reads
        let payload = [0x01, 0x40, 0x21, 0xff];
        let mut buf = Vec::new();
        object(&mut buf, |o| {
            o.array("frames", |frames| write_frames::<Parts>(&payload, frames));
        });
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            r#"{"frames":[{"frame_type":"ping"},{"frame_type":"unknown","frame_type_bytes":33,"raw":{"length":3}}]}"#
        );
    }
}
