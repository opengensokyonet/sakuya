//! Cutting a datagram into the packets it coalesces ([RFC 9000 §12.2]).
//!
//! sakuya cuts with `v1::protected_packet::into_packets`; quinn-proto
//! with `PartialDecode` on the bytes the previous packet left, and
//! s2n-quic-core with `ProtectedPacket::decode` on the remaining buffer.
//! The neutral model [`Split`] lists the packets with their ranges in the
//! datagram, the packets ignored because their Destination Connection ID
//! differs from the first packet's, and where cutting stopped.
//!
//! [RFC 9000 §12.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2
use super::{Kind, compare_quinn, compare_s2n, decode_s2n, read_quinn};
use crate::tally::{self, Comparison};
use bytes::BytesMut;
use nitori_io::{SplitTo, SplitToError};
use quinn_proto::{FixedLengthConnectionIdParser, LongType, PartialDecode, ProtectedHeader};
use sakuya_wire::{
    connection_id::ConnectionIdLength,
    v1::{
        header::TypeFields,
        protected_packet::{IntoPacketsError, Packet as Cut, ProtectedPacket, into_packets},
    },
};
use std::{cell::Cell, ops::Range};

/// One item of a split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// A packet: its kind, its bytes and its Destination Connection ID.
    Packet {
        kind: Kind,
        range: Range<usize>,
        dcid: Vec<u8>,
    },
    /// A packet whose Destination Connection ID differs from the first
    /// packet's.
    Ignored { range: Range<usize> },
}

impl Item {
    fn range(&self) -> &Range<usize> {
        match self {
            Self::Packet { range, .. } | Self::Ignored { range } => range,
        }
    }
}

/// The packets of a datagram, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Split {
    pub items: Vec<Item>,
    /// The offset of the packet whose boundary could not be read, which
    /// ended the cutting.
    pub stopped_at: Option<usize>,
}

impl Split {
    /// Marks the packets after the first whose Destination Connection ID
    /// differs from the first one's as ignored, as RFC 9000 §12.2 has a
    /// receiver do.
    fn ignore_other_dcids(mut self) -> Self {
        let Some(Item::Packet { dcid: first, .. }) = self.items.first().cloned() else {
            return self;
        };
        for item in &mut self.items {
            if let Item::Packet { range, dcid, .. } = item
                && *dcid != first
            {
                *item = Item::Ignored {
                    range: range.clone(),
                };
            }
        }
        self
    }
}

/// A piece of a datagram that remembers where it starts. The rest that
/// `into_packets` keeps reports its start through `cursor`.
#[derive(Clone, Debug)]
struct Tracked<'a> {
    bytes: &'a [u8],
    start: usize,
    cursor: Option<&'a Cell<usize>>,
}

impl SplitTo for Tracked<'_> {
    fn split_to(&mut self, at: usize) -> Result<Self, SplitToError> {
        let piece = SplitTo::split_to(&mut self.bytes, at)?;
        let start = self.start;
        self.start += at;
        if let Some(cursor) = self.cursor {
            cursor.set(self.start);
        }
        Ok(Self {
            bytes: piece,
            start,
            cursor: None,
        })
    }
}

impl AsRef<[u8]> for Tracked<'_> {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

/// Cuts `datagram` apart with sakuya.
///
/// Each packet is also checked against reading the bytes cut for it with
/// the header layers: the ranges it holds give the same token, list and
/// offsets.
pub fn split_sakuya(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Split {
    let cursor = Cell::new(0);
    let rest = Tracked {
        bytes: datagram,
        start: 0,
        cursor: Some(&cursor),
    };
    let mut split = Split::default();
    let mut packets = into_packets(rest, short_dcid_len);
    loop {
        let start = cursor.get();
        let Some(item) = packets.next() else { break };
        match item {
            Ok(packet) => {
                let bytes = packet.bytes();
                assert_eq!(bytes.start, start, "a packet starts where the last ended");
                let range = start..start + bytes.bytes.len();
                let (kind, dcid) = check_cut(&packet, short_dcid_len);
                split.items.push(Item::Packet { kind, range, dcid });
            }
            Err(IntoPacketsError::DcidDiffersFromFirst) => {
                split.items.push(Item::Ignored {
                    range: start..cursor.get(),
                });
            }
            Err(IntoPacketsError::UnreadableBoundary { .. }) => {
                assert_eq!(cursor.get(), start, "an unreadable packet is not cut off");
                split.stopped_at = Some(start);
            }
        }
    }
    assert_eq!(
        split.stopped_at.is_none(),
        cursor.get() == datagram.len(),
        "the cutting ends at the end of the datagram unless it stopped"
    );
    split
}

/// The kind and Destination Connection ID of a packet sakuya cut, after
/// checking its ranges against reading its bytes.
fn check_cut(packet: &Cut<Tracked<'_>>, short_dcid_len: ConnectionIdLength) -> (Kind, Vec<u8>) {
    let bytes = packet.bytes().bytes;
    let read = super::read_sakuya(bytes, short_dcid_len).expect("a cut packet reads");
    assert_eq!(
        read.end,
        Some(bytes.len()),
        "a cut packet ends where it reads"
    );
    let dcid = match packet {
        Cut::Protected(ProtectedPacket::OneRtt(header, _)) => {
            assert_eq!(*header.protected(), read.pn_offset.unwrap()..bytes.len());
            header.dcid().as_bytes().to_vec()
        }
        Cut::Protected(
            ProtectedPacket::Initial(header, _)
            | ProtectedPacket::ZeroRtt(header, _)
            | ProtectedPacket::Handshake(header, _),
        )
        | Cut::Retry(header, _) => {
            let model = super::long_packet_model(header, |range| bytes[range.clone()].to_vec());
            assert_eq!(model, read, "a cut packet holds what reading it gives");
            if let TypeFields::Initial {
                bounds, protected, ..
            }
            | TypeFields::ZeroRtt { bounds, protected }
            | TypeFields::Handshake { bounds, protected } = header.fields()
            {
                assert_eq!(*protected, bounds.packet_number_offset()..bounds.end());
            }
            header.dcid().as_bytes().to_vec()
        }
        Cut::VersionNegotiation(negotiation, _) => {
            assert_eq!(
                Some(&bytes[negotiation.versions().clone()]),
                read.versions.as_deref()
            );
            negotiation.dcid().as_bytes().to_vec()
        }
    };
    assert_eq!(dcid, read.dcid);
    (read.kind, dcid)
}

/// Cuts `datagram` apart with quinn-proto, the Fixed Bit not enforced, and
/// ignores the packets RFC 9000 §12.2 has a receiver ignore.
pub fn split_quinn(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Split {
    let parser = FixedLengthConnectionIdParser::new(short_dcid_len.get());
    let mut split = Split::default();
    let mut offset = 0;
    let mut rest = Some(BytesMut::from(datagram));
    while let Some(bytes) = rest.take().filter(|bytes| !bytes.is_empty()) {
        let Ok((decode, next)) = PartialDecode::new(bytes, &parser, &[1], true) else {
            split.stopped_at = Some(offset);
            break;
        };
        let kind = match &decode.plain_header {
            ProtectedHeader::Initial(_) => Kind::Initial,
            ProtectedHeader::Long {
                ty: LongType::ZeroRtt,
                ..
            } => Kind::ZeroRtt,
            ProtectedHeader::Long {
                ty: LongType::Handshake,
                ..
            } => Kind::Handshake,
            ProtectedHeader::Retry { .. } => Kind::Retry,
            ProtectedHeader::Short { .. } => Kind::Short,
            ProtectedHeader::VersionNegotiate { .. } => Kind::VersionNegotiation,
        };
        let end = offset + decode.len();
        split.items.push(Item::Packet {
            kind,
            range: offset..end,
            dcid: decode.dst_cid().to_vec(),
        });
        offset = end;
        rest = next;
    }
    split.ignore_other_dcids()
}

/// Cuts `datagram` apart with s2n-quic-core and ignores the packets RFC 9000
/// §12.2 has a receiver ignore.
pub fn split_s2n(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Split {
    let mut split = Split::default();
    let mut offset = 0;
    while offset < datagram.len() {
        let Some((packet, len)) = decode_s2n(&datagram[offset..], short_dcid_len) else {
            split.stopped_at = Some(offset);
            break;
        };
        split.items.push(Item::Packet {
            kind: packet.kind,
            range: offset..offset + len,
            dcid: packet.dcid,
        });
        offset += len;
    }
    split.ignore_other_dcids()
}

/// The offset where two splits stop agreeing: the end of the last item both
/// have.
fn divergence(ours: &Split, theirs: &Split) -> usize {
    ours.items
        .iter()
        .zip(&theirs.items)
        .take_while(|(a, b)| a == b)
        .last()
        .map_or(0, |(item, _)| item.range().end)
}

/// Classifies a divergence of two splits by the packet where they part:
/// the comparison of the single packet there names the category.
fn classify(
    ours: &Split,
    theirs: &Split,
    datagram: &[u8],
    single: impl FnOnce(&[u8]) -> Comparison,
) -> Comparison {
    if ours == theirs {
        return Comparison::Agree;
    }
    match single(&datagram[divergence(ours, theirs)..]) {
        Comparison::Known(category) => Comparison::Known(category),
        Comparison::Agree | Comparison::Unclassified => Comparison::Unclassified,
    }
}

pub fn compare_quinn_split(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Comparison {
    classify(
        &split_sakuya(datagram, short_dcid_len),
        &split_quinn(datagram, short_dcid_len),
        datagram,
        |rest| compare_quinn(rest, short_dcid_len),
    )
}

pub fn compare_s2n_split(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Comparison {
    classify(
        &split_sakuya(datagram, short_dcid_len),
        &split_s2n(datagram, short_dcid_len),
        datagram,
        |rest| compare_s2n(rest, short_dcid_len),
    )
}

/// Compares the splits against both references and tallies the results.
pub fn compare_all(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> [Comparison; 2] {
    let results = [
        ("quinn", compare_quinn_split(datagram, short_dcid_len)),
        ("s2n", compare_s2n_split(datagram, short_dcid_len)),
    ];
    for (name, result) in results {
        tally::tally("split", name, result, || {
            format!(
                "dcid_len={} {} ours={:?} quinn={:?} s2n={:?} first={:?}",
                short_dcid_len.get(),
                tally::hex(datagram),
                split_sakuya(datagram, short_dcid_len),
                split_quinn(datagram, short_dcid_len),
                split_s2n(datagram, short_dcid_len),
                read_quinn(datagram, short_dcid_len, true),
            )
        });
    }
    [results[0].1, results[1].1]
}
