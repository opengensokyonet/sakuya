//! Packet protection in sakuya and in rustls, whose QUIC keys quinn-proto
//! uses: Initial packets, the Packet Number field and the Retry integrity
//! tag.
use bytes::{Bytes, BytesMut};
use quinn_proto::{
    FixedLengthConnectionIdParser, PartialDecode,
    crypto::{HeaderKey, PacketKey as _},
    packet::Header,
};
use rustls::{
    Side,
    crypto::ring::default_provider,
    quic::{Keys, Version},
};
use sakuya_packet_protection::{
    backend::ring::RingBackend,
    header_protection::HeaderProtectionKey,
    initial::{INITIAL_AEAD, InitialSecrets},
    packet_key::PacketKey,
    packet_number::TruncatedPacketNumber,
};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength},
    v1::{
        header::{LongPacketHeader, TypeFields, codec::WriteLongPacketHeaderHostExt as _},
        packet_number::PacketNumber,
        protected_packet::{Packet, ProtectedPacket, into_packets},
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};

pub mod generate;
pub mod packet_number;
pub mod retry;

/// The AEAD tag length.
pub const TAG: usize = 16;

/// The Initial keys of one side, from rustls.
pub fn rustls_keys(dcid: &[u8], side: Side) -> Keys {
    let provider = default_provider();
    let suite = provider
        .cipher_suites
        .iter()
        .find_map(|suite| {
            let tls13 = suite.tls13()?;
            (suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
                .then(|| tls13.quic_suite())?
        })
        .unwrap();
    suite.keys(dcid, side, Version::V1)
}

/// An Initial packet to protect.
#[derive(Clone, Debug)]
pub struct Initial {
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub packet_number: u64,
    /// The largest packet number the peer acknowledged, which decides the
    /// length of the Packet Number field.
    pub largest_acked: Option<u64>,
    pub payload: Vec<u8>,
    /// The reserved bits of the first byte, in place; RFC 9000 §17.2 has
    /// them zero, but header protection covers whatever they are.
    pub reserved_bits: u8,
}

/// An unprotected packet: the header with the Packet Number field, the
/// payload and room for the tag.
pub struct Plain {
    pub bytes: Vec<u8>,
    pub pn_offset: usize,
    pub header_len: usize,
}

impl Initial {
    /// The unprotected packet, written with sakuya's header writer, or
    /// `None` if the packet number cannot be sent after `largest_acked`.
    pub fn plain(&self) -> Option<Plain> {
        let number = PacketNumber::new(self.packet_number).ok()?;
        let largest = self.largest_acked.map(|v| PacketNumber::new(v).unwrap());
        let truncated = TruncatedPacketNumber::encode(number, largest).ok()?;
        let length = truncated.as_bytes().len() + self.payload.len() + TAG;
        let length = VarIntField::shortest(VarInt::new(length as u64).unwrap());
        let header = LongPacketHeader::initial(
            ConnectionId::new(&self.dcid).ok()?,
            ConnectionId::new(&self.scid).ok()?,
            VarIntWidth::shortest(VarInt::new(self.token.len() as u64).unwrap()),
            Bytes::from(self.token.clone()),
            truncated.encoded_len(),
            length,
        )
        .unwrap();
        let mut bytes = Vec::new();
        bytes.sync_write_long_packet_header_unpin(header).unwrap();
        bytes[0] |= self.reserved_bits & 0x0c;
        let pn_offset = bytes.len();
        bytes.extend(truncated.as_bytes());
        let header_len = bytes.len();
        bytes.extend(&self.payload);
        bytes.extend([0; TAG]);
        Some(Plain {
            bytes,
            pn_offset,
            header_len,
        })
    }

    /// Protects the packet as `side` sends it, with sakuya.
    pub fn protect_sakuya(&self, side: Side) -> Option<Vec<u8>> {
        let Plain {
            mut bytes,
            pn_offset,
            header_len,
        } = self.plain()?;
        let dcid = ConnectionId::new(&self.dcid).ok()?;
        let secrets = InitialSecrets::derive(&RingBackend, &dcid);
        let secret = match side {
            Side::Client => &secrets.client,
            Side::Server => &secrets.server,
        };
        let key = PacketKey::derive(&RingBackend, INITIAL_AEAD, secret);
        let hp = HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, secret);
        key.seal(
            PacketNumber::new(self.packet_number).ok()?,
            &mut bytes,
            header_len,
        )
        .ok()?;
        hp.apply(&mut bytes, pn_offset).ok()?;
        Some(bytes)
    }

    /// Protects the packet as `side` sends it, with the rustls keys through
    /// the quinn-proto traits.
    pub fn protect_quinn(&self, side: Side) -> Option<Vec<u8>> {
        let Plain {
            mut bytes,
            pn_offset,
            header_len,
        } = self.plain()?;
        let keys = rustls_keys(&self.dcid, side);
        keys.local
            .packet
            .encrypt(self.packet_number, &mut bytes, header_len);
        keys.local.header.encrypt(pn_offset, &mut bytes);
        Some(bytes)
    }
}

/// What opening an Initial packet gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub packet_number: u64,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub payload: Vec<u8>,
    /// The first byte with header protection removed.
    pub first_byte: u8,
}

/// Opens the first packet of `datagram` with sakuya: cutting it from the
/// datagram, removing header protection, recovering the packet number and
/// opening the payload. `client_dcid` selects the keys, and `sender` the
/// direction.
pub fn open_sakuya(
    datagram: &[u8],
    client_dcid: &[u8],
    sender: Side,
    largest: Option<u64>,
) -> Result<Opened, &'static str> {
    let dcid = ConnectionId::new(client_dcid).map_err(|_| "dcid")?;
    let secrets = InitialSecrets::derive(&RingBackend, &dcid);
    let secret = match sender {
        Side::Client => &secrets.client,
        Side::Server => &secrets.server,
    };
    let key = PacketKey::derive(&RingBackend, INITIAL_AEAD, secret);
    let hp = HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, secret);

    let packet = into_packets(datagram, ConnectionIdLength::ZERO)
        .next()
        .ok_or("empty")?
        .map_err(|_| "cut")?;
    let Packet::Protected(ProtectedPacket::Initial(header, received)) = packet else {
        return Err("not an Initial packet");
    };
    let TypeFields::Initial { token, bounds, .. } = header.fields() else {
        unreachable!("an Initial packet has Initial fields")
    };
    let pn_offset = bounds.packet_number_offset();
    // The received bytes stay intact; protection is removed from a copy.
    let mut private = received.to_vec();
    let truncated = hp
        .remove(&mut private, pn_offset)
        .map_err(|_| "header protection")?;
    let number = truncated.decode(largest.map(|v| PacketNumber::new(v).unwrap()));
    let header_len = pn_offset + truncated.encoded_len().get();
    let first_byte = private[0];
    let payload = key
        .open(number, &mut private, header_len)
        .map_err(|_| "open")?
        .to_vec();
    Ok(Opened {
        packet_number: number.get(),
        dcid: header.dcid().as_bytes().to_vec(),
        scid: header.scid().as_bytes().to_vec(),
        token: received[token.clone()].to_vec(),
        payload,
        first_byte,
    })
}

/// Opens the first packet of `datagram` with quinn-proto's packet decoding
/// and the rustls keys.
pub fn open_quinn(
    datagram: &[u8],
    client_dcid: &[u8],
    sender: Side,
    largest: Option<u64>,
) -> Result<Opened, &'static str> {
    // The side that receives from `sender` holds its keys as remote keys.
    let keys = rustls_keys(
        client_dcid,
        match sender {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        },
    );
    let parser = FixedLengthConnectionIdParser::new(0);
    // The Fixed Bit is not enforced: sakuya leaves it to its caller, and the
    // first byte is authenticated either way.
    let (decode, _) = PartialDecode::new(BytesMut::from(datagram), &parser, &[1], true)
        .map_err(|_| "partial decode")?;
    if !decode.is_initial() {
        return Err("not an Initial packet");
    }
    let header_key: &dyn HeaderKey = &keys.remote.header;
    let decoded = decode.finish(Some(header_key)).map_err(|_| "finish")?;
    let Header::Initial(header) = &decoded.header else {
        return Err("not an Initial packet");
    };
    let expected = largest.map_or(0, |v| v + 1);
    let number = header.number.expand(expected);
    let mut payload = decoded.payload.clone();
    keys.remote
        .packet
        .decrypt(number, &decoded.header_data, &mut payload)
        .map_err(|_| "open")?;
    Ok(Opened {
        packet_number: number,
        dcid: header.dst_cid.to_vec(),
        scid: header.src_cid.to_vec(),
        token: header.token.to_vec(),
        payload: payload.to_vec(),
        first_byte: decoded.header_data[0],
    })
}
