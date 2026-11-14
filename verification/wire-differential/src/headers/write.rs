//! The headers a sender writes: sakuya's writers against what the readers
//! of all three implementations read back, and against the encoders of the
//! references where they write the same bytes.
use super::{
    Kind, Packet, compare_quinn, compare_s2n,
    generate::{LongHeaderInput, RetryInput, ShortHeaderInput, VersionNegotiationInput},
    read_quinn, read_s2n, read_sakuya,
};
use crate::{
    hosts::{WaitingSink, run},
    tally::{self, Comparison},
};
use bytes::Bytes;
use quinn_proto::{
    ConnectionId as QCid,
    packet::{Header, InitialHeader, PacketNumber as QPacketNumber},
};
use s2n_codec::EncoderValue as _;
use s2n_quic_core::packet::{
    retry::Retry as SRetry, version_negotiation::VersionNegotiation as SVn,
};
use sakuya_packet_protection::{backend::ring::RingBackend, retry::compute_retry_integrity_tag};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, RawConnectionId},
    header::codec::WriteVersionNegotiationHostExt as _,
    v1::{
        header::{
            KeyPhase, LongPacketHeader, ShortPacketHeader,
            codec::{
                WriteLongPacketHeaderHostExt as _, WriteRetryPacketWithoutTagHostExt as _,
                WriteShortPacketHeaderHostExt as _,
            },
        },
        packet_number::PacketNumberLength,
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
    version::Version,
};

/// The width of `bytes` bytes.
fn width(bytes: usize) -> VarIntWidth {
    VarIntWidth::ALL[bytes.trailing_zeros() as usize]
}

/// A quinn-proto packet number of `length` bytes.
fn quinn_number(length: usize) -> QPacketNumber {
    match length {
        1 => QPacketNumber::U8(0),
        2 => QPacketNumber::U16(0),
        3 => QPacketNumber::U24(0),
        _ => QPacketNumber::U32(0),
    }
}

/// Fails unless `packet`, which sakuya wrote, reads back as `expected` in
/// sakuya and as the references read it in agreement with sakuya, or with
/// a named divergence.
fn check_reads(
    area: &str,
    packet: &[u8],
    dcid_len: usize,
    expected: &Packet,
) -> Result<(), String> {
    let len = ConnectionIdLength::new(dcid_len.min(20)).unwrap();
    let ours = read_sakuya(packet, len);
    if ours.as_ref() != Some(expected) {
        return Err(format!("sakuya reads {ours:?}, expected {expected:?}"));
    }
    for (name, result) in [
        ("quinn", compare_quinn(packet, len)),
        ("s2n", compare_s2n(packet, len)),
    ] {
        tally::tally(area, name, result, || tally::hex(packet));
        if result == Comparison::Unclassified {
            return Err(format!(
                "{name}: quinn={:?} s2n={:?} on {}",
                read_quinn(packet, len, true),
                read_s2n(packet, len),
                tally::hex(packet)
            ));
        }
    }
    Ok(())
}

/// Writes `input` with sakuya, which refuses exactly the fields too narrow
/// for their values, and checks the bytes against RFC 9000 §17.2 and
/// quinn-proto's encoder; then appends `input.length` bytes of packet number
/// and payload and checks what the readers read.
pub fn check_long(input: &LongHeaderInput) -> Result<(), String> {
    let dcid = ConnectionId::new(&input.dcid).unwrap();
    let scid = ConnectionId::new(&input.scid).unwrap();
    let pn_length = PacketNumberLength::new(input.pn_length).unwrap();
    let length_value = VarInt::new(input.length).unwrap();
    let length_fits = width(input.length_width).fits(length_value);
    let Ok(length) = VarIntField::new(length_value, width(input.length_width)) else {
        return if length_fits {
            Err("a Length field that fits is refused".into())
        } else {
            Ok(())
        };
    };
    if !length_fits {
        return Err("a Length field that does not fit is accepted".into());
    }
    let header = match input.packet_type {
        0 => {
            let token_fits =
                width(input.token_width).fits(VarInt::new(input.token.len() as u64).unwrap());
            match LongPacketHeader::initial(
                dcid,
                scid,
                width(input.token_width),
                Bytes::from(input.token.clone()),
                pn_length,
                length,
            ) {
                Ok(header) if token_fits => header,
                Err(_) if !token_fits => return Ok(()),
                result => return Err(format!("token width check: {result:?}")),
            }
        }
        1 => LongPacketHeader::zero_rtt(dcid, scid, pn_length, length),
        _ => LongPacketHeader::handshake(dcid, scid, pn_length, length),
    };

    let mut bytes = Vec::new();
    bytes
        .sync_write_long_packet_header_unpin(header.clone())
        .unwrap();
    let mut sink = WaitingSink::default();
    run(sink.write_long_packet_header_unpin(header.clone())).unwrap();
    if sink.written != bytes {
        return Err("a waiting sink receives other bytes".into());
    }

    // RFC 9000 §17.2: the form, the Fixed Bit, the type, zero reserved bits
    // and the packet number length.
    let first = 0xc0 | (input.packet_type << 4) | (input.pn_length as u8 - 1);
    let token_len = if input.packet_type == 0 {
        input.token_width + input.token.len()
    } else {
        0
    };
    let length_offset = 7 + input.dcid.len() + input.scid.len() + token_len;
    let pn_offset = length_offset + input.length_width;
    if bytes[0] != first || header.first_byte() != first {
        return Err(format!("first byte {:#x}, expected {first:#x}", bytes[0]));
    }
    if bytes.len() != pn_offset
        || header.packet_number_offset() != pn_offset
        || header.length_offset() != length_offset
    {
        return Err(format!("{} bytes, expected {pn_offset}", bytes.len()));
    }

    // quinn-proto writes the Token Length in its shortest encoding and
    // reserves two bytes for the Length, which it fills with the 2-byte
    // encoding of the value.
    let shortest_token = VarIntWidth::shortest(VarInt::new(input.token.len() as u64).unwrap())
        .encoded_len()
        == input.token_width;
    if input.length_width == 2 && (input.packet_type != 0 || shortest_token) {
        let (dst_cid, src_cid) = (QCid::new(&input.dcid), QCid::new(&input.scid));
        let number = quinn_number(input.pn_length);
        let quinn = match input.packet_type {
            0 => Header::Initial(InitialHeader {
                dst_cid,
                src_cid,
                token: Bytes::from(input.token.clone()),
                number,
                version: 1,
            }),
            ty => Header::Long {
                ty: if ty == 1 {
                    quinn_proto::LongType::ZeroRtt
                } else {
                    quinn_proto::LongType::Handshake
                },
                dst_cid,
                src_cid,
                number,
                version: 1,
            },
        };
        let mut theirs = Vec::new();
        let encoded = quinn.encode(&mut theirs);
        let filled = ((input.length as u16) | 0x4000).to_be_bytes();
        if theirs[..length_offset] != bytes[..length_offset]
            || bytes[length_offset..pn_offset] != filled
            || encoded.header_len - input.pn_length != pn_offset
        {
            return Err(format!("quinn writes {}", tally::hex(&theirs)));
        }
        tally::agree("write/long/quinn-bytes");
    }

    bytes.resize(pn_offset + input.length as usize, 0x5a);
    let expected = Packet {
        kind: [Kind::Initial, Kind::ZeroRtt, Kind::Handshake][usize::from(input.packet_type)],
        version: Some(1),
        dcid: input.dcid.clone(),
        scid: Some(input.scid.clone()),
        token: (input.packet_type == 0).then(|| input.token.clone()),
        integrity_tag: None,
        versions: None,
        pn_offset: Some(pn_offset),
        end: Some(bytes.len()),
    };
    check_reads("write/long", &bytes, 0, &expected)
}

/// Writes `input` with sakuya and checks the bytes against RFC 9000 §17.3.1
/// and quinn-proto's encoder, and what the readers read.
pub fn check_short(input: &ShortHeaderInput) -> Result<(), String> {
    let header = ShortPacketHeader::new(
        input.spin,
        if input.key_phase {
            KeyPhase::One
        } else {
            KeyPhase::Zero
        },
        PacketNumberLength::new(input.pn_length).unwrap(),
        ConnectionId::new(&input.dcid).unwrap(),
    );
    let mut bytes = Vec::new();
    bytes.sync_write_short_packet_header_unpin(header).unwrap();
    let mut sink = WaitingSink::default();
    run(sink.write_short_packet_header_unpin(header)).unwrap();
    if sink.written != bytes {
        return Err("a waiting sink receives other bytes".into());
    }
    // RFC 9000 §17.3.1: the Fixed Bit, the Spin Bit, zero reserved bits, the
    // Key Phase and the packet number length.
    let first = 0x40
        | if input.spin { 0x20 } else { 0 }
        | if input.key_phase { 0x04 } else { 0 }
        | (input.pn_length as u8 - 1);
    if bytes[0] != first
        || bytes[1..] != input.dcid[..]
        || header.packet_number_offset() != bytes.len()
    {
        return Err(format!("sakuya writes {}", tally::hex(&bytes)));
    }
    let mut theirs = Vec::new();
    Header::Short {
        spin: input.spin,
        key_phase: input.key_phase,
        dst_cid: QCid::new(&input.dcid),
        number: quinn_number(input.pn_length),
    }
    .encode(&mut theirs);
    if theirs[..bytes.len()] != bytes[..] {
        return Err(format!("quinn writes {}", tally::hex(&theirs)));
    }
    tally::agree("write/short/quinn-bytes");

    let pn_offset = bytes.len();
    bytes.extend(&input.rest);
    let expected = Packet {
        kind: Kind::Short,
        version: None,
        dcid: input.dcid.clone(),
        scid: None,
        token: None,
        integrity_tag: None,
        versions: None,
        pn_offset: Some(pn_offset),
        end: Some(bytes.len()),
    };
    check_reads("write/short", &bytes, input.dcid.len(), &expected)
}

/// Writes `input` with sakuya, appends the integrity tag sakuya computes, and
/// checks the bytes against RFC 9000 §17.2.5 and the encoders of quinn-proto
/// and s2n-quic-core, and what the readers read.
pub fn check_retry(input: &RetryInput) -> Result<(), String> {
    let dcid = ConnectionId::new(&input.dcid).unwrap();
    let scid = ConnectionId::new(&input.scid).unwrap();
    let mut bytes = Vec::new();
    bytes
        .sync_write_retry_packet_without_tag_unpin(input.unused, dcid, scid, &input.token)
        .unwrap();
    let mut sink = WaitingSink::default();
    run(sink.write_retry_packet_without_tag_unpin(input.unused, dcid, scid, &input.token)).unwrap();
    if sink.written != bytes {
        return Err("a waiting sink receives other bytes".into());
    }
    // RFC 9000 §17.2.5: the form, the Fixed Bit, type 3 and the Unused bits.
    let first = 0xf0 | (input.unused & 0x0f);
    let header_len = 7 + input.dcid.len() + input.scid.len();
    if bytes[0] != first || bytes.len() != header_len + input.token.len() {
        return Err(format!("sakuya writes {}", tally::hex(&bytes)));
    }
    if input.unused & 0x0f == 0 {
        // quinn-proto writes the Unused bits as zero.
        let mut theirs = Vec::new();
        Header::Retry {
            dst_cid: QCid::new(&input.dcid),
            src_cid: QCid::new(&input.scid),
            version: 1,
        }
        .encode(&mut theirs);
        if theirs[..] != bytes[..header_len] {
            return Err(format!("quinn writes {}", tally::hex(&theirs)));
        }
        tally::agree("write/retry/quinn-bytes");
    }
    let odcid = ConnectionId::new(&input.odcid).unwrap();
    let tag = compute_retry_integrity_tag(&RingBackend, &odcid, &bytes);
    bytes.extend(tag);
    let theirs = SRetry {
        tag: first,
        version: 1,
        destination_connection_id: &input.dcid,
        source_connection_id: &input.scid,
        retry_token: &input.token,
        retry_integrity_tag: &tag,
    }
    .encode_to_vec();
    if theirs != bytes {
        return Err(format!("s2n writes {}", tally::hex(&theirs)));
    }
    tally::agree("write/retry/s2n-bytes");
    let expected = Packet {
        kind: Kind::Retry,
        version: Some(1),
        dcid: input.dcid.clone(),
        scid: Some(input.scid.clone()),
        token: Some(input.token.clone()),
        integrity_tag: Some(tag.to_vec()),
        versions: None,
        pn_offset: None,
        end: Some(bytes.len()),
    };
    check_reads("write/retry", &bytes, 0, &expected)
}

/// Writes `input` with sakuya and checks the bytes against RFC 8999 §6 and the
/// encoders of quinn-proto and s2n-quic-core, and what the readers read.
pub fn check_version_negotiation(input: &VersionNegotiationInput) -> Result<(), String> {
    let dcid = RawConnectionId::new(&input.dcid).unwrap();
    let scid = RawConnectionId::new(&input.scid).unwrap();
    let versions: Vec<Version> = input.versions.iter().copied().map(Version::new).collect();
    let mut bytes = Vec::new();
    bytes
        .sync_write_version_negotiation_unpin(input.unused, &dcid, &scid, &versions)
        .unwrap();
    let mut sink = WaitingSink::default();
    run(sink.write_version_negotiation_unpin(input.unused, &dcid, &scid, &versions)).unwrap();
    if sink.written != bytes {
        return Err("a waiting sink receives other bytes".into());
    }
    let list: Vec<u8> = input
        .versions
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect();
    let header_len = 7 + input.dcid.len() + input.scid.len();
    // RFC 8999 §6: the form bit, then the Unused bits as the sender chose.
    if bytes[0] != 0x80 | input.unused
        || bytes[1..5] != [0; 4]
        || bytes.len() != header_len + list.len()
        || bytes[header_len..] != list[..]
    {
        return Err(format!("sakuya writes {}", tally::hex(&bytes)));
    }
    if input.dcid.len() <= 20 && input.scid.len() <= 20 {
        let mut theirs = Vec::new();
        Header::VersionNegotiate {
            random: input.unused & 0x7f,
            dst_cid: QCid::new(&input.dcid),
            src_cid: QCid::new(&input.scid),
        }
        .encode(&mut theirs);
        if theirs[..] != bytes[..header_len] {
            return Err(format!("quinn writes {}", tally::hex(&theirs)));
        }
        tally::agree("write/version-negotiation/quinn-bytes");
    }
    if input.unused & 0x40 != 0 {
        // s2n-quic-core sets the 0x40 bit that RFC 9000 §17.2.1 asks servers
        // to set.
        let theirs = SVn {
            tag: input.unused,
            destination_connection_id: &input.dcid,
            source_connection_id: &input.scid,
            supported_versions: &list[..],
        }
        .encode_to_vec();
        if theirs != bytes {
            return Err(format!("s2n writes {}", tally::hex(&theirs)));
        }
        tally::agree("write/version-negotiation/s2n-bytes");
    }
    let expected = Packet {
        kind: Kind::VersionNegotiation,
        version: Some(0),
        dcid: input.dcid.clone(),
        scid: Some(input.scid.clone()),
        token: None,
        integrity_tag: None,
        versions: Some(list),
        pn_offset: None,
        end: Some(bytes.len()),
    };
    check_reads("write/version-negotiation", &bytes, 0, &expected)
}
