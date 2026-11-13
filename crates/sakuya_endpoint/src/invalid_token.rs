//! The Initial packet that closes a connection attempt with INVALID_TOKEN.
//!
//! A client that returns a Retry token which does not validate will not
//! accept another Retry, so the server closes the attempt at once with
//! INVALID_TOKEN instead of letting the client time out
//! ([RFC 9000 §8.1.2]). The server keeps no state for the attempt and does
//! not enter the closing period; it sends one Initial packet holding the
//! CONNECTION_CLOSE frame.
//!
//! [RFC 9000 §8.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.2

use bytes::Bytes;
use core::num::NonZeroUsize;
use sakuya_packet_protection::{
    backend::{AEAD_TAG_LEN, CryptoBackend, HEADER_PROTECTION_SAMPLE_LEN},
    header_protection::HeaderProtectionKey,
    initial::{INITIAL_AEAD, InitialSecrets},
    packet_key::PacketKey,
    packet_number::TruncatedPacketNumber,
};
use sakuya_wire::{
    connection_id::ConnectionId,
    header::SAMPLE_DISTANCE,
    v1::{
        frame::{
            connection_close::{
                CloseErrorCode, ConnectionCloseFrame, codec::WriteConnectionCloseFrameHostExt as _,
            },
            padding::{PaddingRun, codec::WritePaddingRunHostExt as _},
        },
        header::{LongPacketHeader, codec::WriteLongPacketHeaderHostExt as _},
        packet_number::PacketNumber,
        transport_error::TransportErrorCode,
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};

/// Encodes the Initial packet that closes, with INVALID_TOKEN, the
/// connection attempt of a client Initial whose destination connection ID
/// was `client_dcid` and whose source connection ID was `client_scid`.
///
/// The packet is protected with the server's Initial keys derived from
/// `client_dcid` ([RFC 9001 §5.2]), the keys the client expects the server's
/// Initial packets under. Its destination connection ID is `client_scid` and
/// its source connection ID `scid`, usually from
/// [`generate_stateless_scid`](crate::retry::generate_stateless_scid). It
/// has no token and packet number 0, and its payload is one transport
/// CONNECTION_CLOSE frame with the error code INVALID_TOKEN, Frame Type 0
/// and an empty reason phrase ([RFC 9000 §19.19]), followed by PADDING
/// frames only if the payload would otherwise be too short for the header
/// protection sample ([RFC 9001 §5.4.2]).
///
/// The packet is not padded to 1200 bytes. [RFC 9000 §14.1] requires a
/// server to expand datagrams carrying ack-eliciting Initial packets, and a
/// packet holding only CONNECTION_CLOSE and PADDING frames is not
/// ack-eliciting ([RFC 9000 §1.2]).
///
/// [RFC 9000 §1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-1.2
/// [RFC 9000 §14.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1
/// [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
/// [RFC 9001 §5.2]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2
/// [RFC 9001 §5.4.2]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2
pub fn encode_invalid_token_close<B: CryptoBackend>(
    backend: &B,
    client_dcid: &ConnectionId,
    client_scid: &ConnectionId,
    scid: &ConnectionId,
) -> Bytes {
    let secrets = InitialSecrets::derive(backend, client_dcid);
    let packet_key = PacketKey::derive(backend, INITIAL_AEAD, &secrets.server);
    let header_key = HeaderProtectionKey::derive(backend, INITIAL_AEAD, &secrets.server);

    let close = ConnectionCloseFrame::new(
        CloseErrorCode::Transport {
            code: VarIntField::shortest(TransportErrorCode::INVALID_TOKEN),
            frame_type: VarIntField::shortest(VarInt::ZERO),
        },
        VarIntWidth::One,
        &[][..],
    );
    // invariant: a one-byte Reason Phrase Length field states the length of
    // an empty reason phrase.
    let close = close.expect("an empty reason phrase fits any width");
    let packet_number = PacketNumber::ZERO;
    let truncated = TruncatedPacketNumber::encode(packet_number, None);
    // invariant: packet number 0 with nothing acknowledged takes one byte.
    let truncated = truncated.expect("packet number 0 is encodable");
    let pn_length = truncated.encoded_len();

    // The packet number and the sealed payload together reach past the end
    // of the header protection sample.
    let plaintext_min = (SAMPLE_DISTANCE + HEADER_PROTECTION_SAMPLE_LEN)
        .saturating_sub(pn_length.get() + AEAD_TAG_LEN);
    let padding = NonZeroUsize::new(plaintext_min.saturating_sub(close.encoded_len()));
    let plaintext_len = close.encoded_len() + padding.map_or(0, NonZeroUsize::get);
    let length = VarInt::try_from(pn_length.get() + plaintext_len + AEAD_TAG_LEN);
    // invariant: the packet number, two frames of a few bytes and the tag
    // stay far below the variable-length integer limit.
    let length = length.expect("the Length of a small packet is a variable-length integer");
    let header = LongPacketHeader::initial(
        *client_scid,
        *scid,
        VarIntWidth::One,
        Bytes::new(),
        pn_length,
        VarIntField::shortest(length),
    );
    // invariant: a one-byte Token Length field states the length of an
    // empty token.
    let header = header.expect("an empty token fits any width");
    let pn_offset = header.packet_number_offset();

    let mut packet = Vec::new();
    // invariant: a `Vec` accepts every byte written to it.
    packet
        .sync_write_long_packet_header_unpin(header)
        .expect("a Vec accepts every byte");
    packet.extend_from_slice(truncated.as_bytes());
    let header_len = packet.len();
    packet
        .sync_write_connection_close_frame_unpin(close)
        .expect("a Vec accepts every byte");
    if let Some(padding) = padding {
        packet
            .sync_write_padding_run_unpin(PaddingRun::new(padding))
            .expect("a Vec accepts every byte");
    }
    packet.resize(packet.len() + AEAD_TAG_LEN, 0);

    // invariant: the packet holds the header and the tag, and its payload
    // is far below the AEAD limit.
    packet_key
        .seal(packet_number, &mut packet, header_len)
        .expect("the packet holds its header, payload and tag");
    // invariant: the payload was sized so that the sample exists, and the
    // packet number offset follows the first byte.
    header_key
        .apply(&mut packet, pn_offset)
        .expect("the packet holds the header protection sample");
    Bytes::from(packet)
}

#[cfg(test)]
mod tests {
    use super::encode_invalid_token_close;
    use core::marker::PhantomData;
    use sakuya_packet_protection::{
        backend::ring::RingBackend,
        header_protection::HeaderProtectionKey,
        initial::{INITIAL_AEAD, InitialSecrets},
        packet_key::PacketKey,
    };
    use sakuya_wire::{
        connection_id::ConnectionId,
        header::codec::ReadLongHeaderHostExt as _,
        parts::HList,
        v1::{
            self,
            frame::{FrameRun, connection_close::CloseErrorCode, set::Frames},
            header::{LongPacketType, TypeFields, codec::ReadLongPacketHostExt as _},
            packet_number::PacketNumber,
            transport_error::TransportErrorCode,
        },
        var_int::VarInt,
    };

    fn cid(bytes: &[u8]) -> ConnectionId {
        ConnectionId::new(bytes).unwrap()
    }

    /// Opens `datagram` as the client would: reads the Initial packet,
    /// removes header protection and packet protection with the keys of the
    /// server's Initial secret derived from `client_dcid`, and returns the
    /// packet, the packet number and the payload.
    fn open<'a>(
        datagram: &'a [u8],
        client_dcid: &ConnectionId,
    ) -> (v1::header::LongPacket<&'a [u8]>, PacketNumber, Vec<u8>) {
        let mut input = datagram;
        let header = input.sync_read_long_header_unpin().unwrap();
        let packet = input.sync_read_long_packet_unpin(header).unwrap();
        assert!(input.is_empty(), "the datagram holds one packet");
        let TypeFields::Initial { bounds, .. } = packet.fields() else {
            panic!("expected an Initial packet, got {:?}", packet.fields());
        };
        assert_eq!(bounds.end(), datagram.len());

        let secrets = InitialSecrets::derive(&RingBackend, client_dcid);
        let key = PacketKey::derive(&RingBackend, INITIAL_AEAD, &secrets.server);
        let hp = HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, &secrets.server);
        let mut private = datagram.to_vec();
        let truncated = hp
            .remove(&mut private, bounds.packet_number_offset())
            .unwrap();
        // The reserved bits are 0 once header protection is removed.
        assert_eq!(private[0] & 0x0c, 0);
        let number = truncated.decode(None);
        let header_len = bounds.packet_number_offset() + truncated.encoded_len().get();
        let payload = key.open(number, &mut private, header_len).unwrap().to_vec();
        (packet, number, payload)
    }

    #[test]
    fn the_client_reads_an_invalid_token_close() {
        let client_dcid = cid(&[0x11; 8]);
        let client_scid = cid(&[0x22; 5]);
        let scid = cid(&[0x33; 12]);
        let datagram = encode_invalid_token_close(&RingBackend, &client_dcid, &client_scid, &scid);

        let (packet, number, payload) = open(&datagram, &client_dcid);
        assert_eq!(packet.packet_type(), LongPacketType::Initial);
        assert!(packet.fixed_bit());
        assert_eq!(packet.header().version(), v1::header::VERSION);
        assert_eq!(packet.dcid(), &client_scid);
        assert_eq!(packet.scid(), &scid);
        let TypeFields::Initial { token, .. } = packet.fields() else {
            unreachable!()
        };
        assert!(token.is_empty());
        assert_eq!(number, PacketNumber::ZERO);

        let mut frames = Frames::new(payload.as_slice(), PhantomData::<HList![v1::Part]>);
        let Some(FrameRun::ConnectionClose(close)) =
            frames.next().map(|frame| frame.unwrap().extract())
        else {
            panic!("the payload starts with a CONNECTION_CLOSE frame");
        };
        let CloseErrorCode::Transport { code, frame_type } = close.error_code() else {
            panic!("expected a transport CONNECTION_CLOSE, got {close:?}");
        };
        assert_eq!(code.get(), TransportErrorCode::INVALID_TOKEN);
        assert_eq!(frame_type.get(), VarInt::ZERO);
        assert!(close.reason_phrase().is_empty());
        for frame in frames {
            let run = frame.unwrap().extract();
            assert!(matches!(run, FrameRun::Padding(_)), "{run:?}");
        }
    }

    #[test]
    fn the_client_keys_open_it_for_empty_connection_ids() {
        // With an empty source connection ID on both sides, the header is as
        // short as it gets; the sample is still within the packet.
        let client_dcid = cid(&[0x44; 8]);
        let datagram = encode_invalid_token_close(
            &RingBackend,
            &client_dcid,
            &ConnectionId::EMPTY,
            &ConnectionId::EMPTY,
        );
        let (packet, _, payload) = open(&datagram, &client_dcid);
        assert!(packet.dcid().is_empty());
        assert!(packet.scid().is_empty());
        assert_eq!(payload[..4], [0x1c, 0x0b, 0x00, 0x00]);

        // Another connection's keys do not open it.
        let mut input = &datagram[..];
        let header = input.sync_read_long_header_unpin().unwrap();
        let read = input.sync_read_long_packet_unpin(header).unwrap();
        let TypeFields::Initial { bounds, .. } = read.fields() else {
            unreachable!()
        };
        let other = InitialSecrets::derive(&RingBackend, &cid(&[0x55; 8]));
        let key = PacketKey::derive(&RingBackend, INITIAL_AEAD, &other.server);
        let hp = HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, &other.server);
        let mut private = datagram.to_vec();
        let truncated = hp
            .remove(&mut private, bounds.packet_number_offset())
            .unwrap();
        let header_len = bounds.packet_number_offset() + truncated.encoded_len().get();
        assert!(
            key.open(truncated.decode(None), &mut private, header_len)
                .is_err()
        );
    }
}
