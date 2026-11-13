//! Writing one packet into the datagram being written.
//!
//! A [`PacketWriter`] is started by the datagram writer with the packet's
//! send attempt and the keys of its level. Starting it writes the header:
//! the packet number is encoded against the largest acknowledged one of its
//! space at this moment (RFC 9000 §17.1, Appendix A.2), and a long header's
//! Length field is reserved at a fixed width, wide enough for the longest
//! packet the rest of the datagram can take (RFC 9000 §16 does not require
//! the shortest encoding). [`open`](PacketWriter::open) turns it into the
//! open packet frame sources write into; the writer goes with the open
//! packet, and with the closed packet it may turn into.
//!
//! When it is dropped with a frame written, the packet is sealed: PADDING
//! is added so the header protection sample lies inside the packet (RFC
//! 9001 §5.4.2), and, for the last packet of the datagram, so the datagram
//! reaches its floor; it goes before the frames when the last frame extends
//! to the end of the packet. Then the packet number is in place, the Length
//! field gets its value, the payload is protected and then the header, and
//! the send attempt is sealed with the packet's size; the sealed packet
//! stays in the datagram. Dropped without a frame, the header is taken back
//! and no packet number is used, unless the datagram needs a packet of
//! PADDING alone to reach its floor after an earlier packet. Dropped while a
//! panic unwinds, it does nothing.

use core::{fmt, num::NonZeroUsize};

use bytes::{BufMut as _, Bytes, BytesMut};
use sakuya_link::MIN_DATAGRAM_SIZE;
use sakuya_packet_protection::{
    backend::{AEAD_TAG_LEN, CryptoBackend},
    header_protection::HeaderProtectionKey,
    packet_key::PacketKey,
    packet_number::{EncodePacketNumberError, TruncatedPacketNumber},
};
use sakuya_recovery::send_journals::PacketSendAttempt;
use sakuya_wire::{
    connection_id::ConnectionId,
    header::SAMPLE_DISTANCE,
    v1::{
        encryption_level::EncryptionLevel,
        frame::padding::{PaddingRun, codec::WritePaddingRunHostExt as _},
        header::{
            LongPacketHeader, ShortPacketHeader,
            codec::{WriteLongPacketHeaderHostExt as _, WriteShortPacketHeaderHostExt as _},
        },
        packet_number::PacketNumber,
        role::Role,
    },
    var_int::{VarInt, VarIntField, VarIntWidth, codec::WriteVarIntFieldHostExt as _},
};

use super::{
    aead_usage::AeadUsage,
    datagram_batch::DatagramState,
    keys::{DirectionKeys, OneRttSendKeys},
};
use crate::write::{
    FlightClass, NotLast, OpenPacket, PacketWriting, PaddingSummary, SummaryOf, sealed,
};

/// The spin bit of every short header: nothing measures the RTT with it,
/// and an endpoint that does not may set it to any value (RFC 9000
/// §17.4).
const SPIN: bool = false;

/// The invariant of every write at the end of the buffer: a `BytesMut`
/// takes every byte.
const TAKES_EVERY_BYTE: &str = "a BytesMut takes every byte";

/// What a packet starts with: its level, the keys it is protected with and
/// what its header carries besides the datagram's connection ID.
pub(super) enum PacketStart<'d, B: CryptoBackend> {
    /// An Initial packet.
    Initial {
        keys: &'d DirectionKeys<B>,
        scid: ConnectionId,
        token: Bytes,
    },
    /// A 0-RTT packet.
    ZeroRtt {
        keys: &'d DirectionKeys<B>,
        scid: ConnectionId,
    },
    /// A Handshake packet.
    Handshake {
        keys: &'d DirectionKeys<B>,
        scid: ConnectionId,
    },
    /// A 1-RTT packet.
    OneRtt {
        keys: &'d OneRttSendKeys<B>,
        usage: &'d mut AeadUsage,
    },
}

/// The keys a packet is protected with.
enum SealingKeys<'d, B: CryptoBackend> {
    /// Those of Initial, 0-RTT or Handshake.
    Level(&'d DirectionKeys<B>),
    /// The current sending generation of 1-RTT, whose use is counted.
    OneRtt {
        keys: &'d OneRttSendKeys<B>,
        usage: &'d mut AeadUsage,
    },
}

impl<B: CryptoBackend> SealingKeys<'_, B> {
    fn packet(&self) -> &PacketKey<B> {
        match self {
            Self::Level(keys) => &keys.packet,
            Self::OneRtt { keys, .. } => keys.packet(),
        }
    }

    fn header(&self) -> &HeaderProtectionKey<B> {
        match self {
            Self::Level(keys) => &keys.header,
            Self::OneRtt { keys, .. } => keys.header(),
        }
    }
}

/// The form of a packet's header.
#[derive(Debug, Clone, Copy)]
enum HeaderForm {
    /// A long header, whose Length field, `length_offset` bytes into the
    /// packet, is reserved at `width`.
    Long {
        length_offset: usize,
        width: VarIntWidth,
    },
    /// A short header.
    Short,
}

/// What the frames written so far make of the packet.
#[derive(Debug, Clone, Copy, Default)]
struct Written {
    frame: bool,
    ack_eliciting: bool,
    in_flight: bool,
    expands_datagram: bool,
}

/// One packet being written into a datagram.
///
/// `A` is its send attempt, `B` the crypto backend of its keys.
pub struct PacketWriter<'d, A, B>
where
    A: PacketSendAttempt,
    A::Summary: From<PaddingSummary>,
    B: CryptoBackend,
{
    buffer: &'d mut BytesMut,
    datagram: &'d mut DatagramState,
    slot: &'d mut Option<A::Sealed>,
    /// Kept until the packet is sealed or taken back.
    attempt: Option<A>,
    keys: SealingKeys<'d, B>,
    level: EncryptionLevel,
    number: PacketNumber,
    form: HeaderForm,
    /// Where the packet starts in the buffer.
    start: usize,
    /// The offset of the Packet Number field in the packet.
    pn_offset: usize,
    /// The length of the header, up to the end of the Packet Number field.
    header_len: usize,
    written: Written,
    closed: bool,
    more_follow: bool,
    pmtu_probe: bool,
}

impl<A, B> fmt::Debug for PacketWriter<'_, A, B>
where
    A: PacketSendAttempt,
    A::Summary: From<PaddingSummary>,
    B: CryptoBackend,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketWriter")
            .field("level", &self.level)
            .field("number", &self.number)
            .field("start", &self.start)
            .field("header_len", &self.header_len)
            .field("written", &self.written)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl<'d, A, B> PacketWriter<'d, A, B>
where
    A: PacketSendAttempt,
    A::Summary: From<PaddingSummary>,
    B: CryptoBackend,
{
    /// Write the header of the packet `start` describes at the end of
    /// `buffer`, in the datagram of `datagram`, for `attempt`, whose sealed
    /// packet goes into `slot`.
    pub(super) fn start(
        buffer: &'d mut BytesMut,
        datagram: &'d mut DatagramState,
        slot: &'d mut Option<A::Sealed>,
        attempt: A,
        start: PacketStart<'d, B>,
        largest_acked: Option<PacketNumber>,
    ) -> Result<Self, EncodePacketNumberError> {
        let number = attempt.packet_number();
        let truncated = TruncatedPacketNumber::encode(number, largest_acked)?;
        let pn_length = truncated.encoded_len();
        let packet_start = buffer.len();
        let dcid = datagram.dcid;
        // the Length value never exceeds what is left of the datagram
        let room = datagram
            .max_len
            .saturating_sub(packet_start - datagram.start);
        let width = VarIntWidth::shortest(VarInt::try_from(room).unwrap_or(VarInt::MAX));
        let reserved = VarIntField::new(VarInt::ZERO, width);
        // invariant: zero fits in every width
        let reserved = reserved.expect("zero fits in every width");
        let long = |header: LongPacketHeader, buffer: &mut BytesMut| {
            let form = HeaderForm::Long {
                length_offset: header.length_offset(),
                width,
            };
            let pn_offset = header.packet_number_offset();
            buffer
                .sync_write_long_packet_header_unpin(header)
                .expect(TAKES_EVERY_BYTE);
            (form, pn_offset)
        };
        let (level, keys, (form, pn_offset)) = match start {
            PacketStart::Initial { keys, scid, token } => {
                // invariant: a token is far shorter than 2^62 bytes
                let token_len =
                    VarInt::try_from(token.len()).expect("a token is shorter than 2^62");
                let header = LongPacketHeader::initial(
                    dcid,
                    scid,
                    VarIntWidth::shortest(token_len),
                    token,
                    pn_length,
                    reserved,
                );
                // invariant: the shortest width holds the token's length
                let header = header.expect("the shortest width holds the token length");
                (
                    EncryptionLevel::Initial,
                    SealingKeys::Level(keys),
                    long(header, buffer),
                )
            }
            PacketStart::ZeroRtt { keys, scid } => {
                let header = LongPacketHeader::zero_rtt(dcid, scid, pn_length, reserved);
                (
                    EncryptionLevel::ZeroRtt,
                    SealingKeys::Level(keys),
                    long(header, buffer),
                )
            }
            PacketStart::Handshake { keys, scid } => {
                let header = LongPacketHeader::handshake(dcid, scid, pn_length, reserved);
                (
                    EncryptionLevel::Handshake,
                    SealingKeys::Level(keys),
                    long(header, buffer),
                )
            }
            PacketStart::OneRtt { keys, usage } => {
                let header = ShortPacketHeader::new(SPIN, keys.key_phase(), pn_length, dcid);
                let pn_offset = header.packet_number_offset();
                buffer
                    .sync_write_short_packet_header_unpin(header)
                    .expect(TAKES_EVERY_BYTE);
                (
                    EncryptionLevel::OneRtt,
                    SealingKeys::OneRtt { keys, usage },
                    (HeaderForm::Short, pn_offset),
                )
            }
        };
        buffer.extend_from_slice(truncated.as_bytes());
        let header_len = pn_offset + pn_length.get();
        debug_assert_eq!(buffer.len() - packet_start, header_len);
        Ok(Self {
            buffer,
            datagram,
            slot,
            attempt: Some(attempt),
            keys,
            level,
            number,
            form,
            start: packet_start,
            pn_offset,
            header_len,
            written: Written::default(),
            closed: false,
            more_follow: false,
            pmtu_probe: false,
        })
    }

    /// The packet number the packet gets if it is sealed.
    pub fn packet_number(&self) -> PacketNumber {
        self.number
    }

    /// The packet is a PMTU probe: its loss is no congestion signal (RFC
    /// 9000 §14.4).
    pub fn mark_pmtu_probe(&mut self) {
        self.pmtu_probe = true;
    }

    /// The open packet frame sources write into, for sources of class `C`,
    /// in the position [`NotLast`].
    pub fn open<C>(self) -> OpenPacket<Self, C, NotLast> {
        OpenPacket::new(self)
    }

    /// The length of the payload written so far.
    fn payload_len(&self) -> usize {
        self.buffer.len() - self.start - self.header_len
    }

    /// The PADDING the payload needs so the header protection sample lies
    /// inside the packet: the Packet Number field and the payload together
    /// at least four bytes (RFC 9001 §5.4.2).
    fn sample_shortfall(&self) -> usize {
        let pn_len = self.header_len - self.pn_offset;
        SAMPLE_DISTANCE.saturating_sub(pn_len + self.payload_len())
    }

    /// Write `len` bytes of PADDING: before the frames when the packet is
    /// closed, after them otherwise.
    fn write_padding(&mut self, len: NonZeroUsize) {
        let run = PaddingRun::new(len);
        if self.closed {
            let frames = self.buffer.split_off(self.start + self.header_len);
            self.buffer
                .sync_write_padding_run_unpin(run)
                .expect(TAKES_EVERY_BYTE);
            self.buffer.unsplit(frames);
        } else {
            self.buffer
                .sync_write_padding_run_unpin(run)
                .expect(TAKES_EVERY_BYTE);
        }
    }

    /// Seal the packet with `attempt`, or take its header back.
    fn finish(&mut self, mut attempt: A) {
        if self.written.frame {
            if self.level == EncryptionLevel::Initial
                && (self.datagram.role == Role::Client || self.written.ack_eliciting)
            {
                // RFC 9000 §14.1
                self.datagram.raise_floor(MIN_DATAGRAM_SIZE);
            }
            if self.written.expands_datagram {
                // RFC 9000 §8.2.1, §8.2.2; the largest size already keeps
                // within the anti-amplification limit
                self.datagram.raise_floor(MIN_DATAGRAM_SIZE);
            }
        }
        let sample = self.sample_shortfall();
        let unpadded = self.buffer.len() - self.datagram.start + sample + AEAD_TAG_LEN;
        let to_floor = if self.more_follow {
            0
        } else {
            self.datagram.floor.saturating_sub(unpadded)
        };
        if !self.written.frame {
            // only to bring the datagram to its floor after an earlier
            // packet, when it fits
            let padding_alone = to_floor > 0
                && self.datagram.packets > 0
                && unpadded + to_floor <= self.datagram.max_len;
            if !padding_alone {
                self.buffer.truncate(self.start);
                return;
            }
        }
        if let Some(padding) = NonZeroUsize::new(sample + to_floor) {
            self.write_padding(padding);
            attempt.record_frame(PaddingSummary.into(), false, true);
            self.written.frame = true;
            self.written.in_flight = true;
        }
        self.buffer.put_bytes(0, AEAD_TAG_LEN);
        let packet_len = self.buffer.len() - self.start;
        if let HeaderForm::Long {
            length_offset,
            width,
        } = self.form
        {
            // invariant: the width was chosen for the longest packet the
            // datagram can take, and the packet keeps within it
            let length = VarInt::try_from(packet_len - self.pn_offset)
                .ok()
                .and_then(|length| VarIntField::new(length, width).ok())
                .expect("the reserved width holds the packet's length");
            (&mut self.buffer[self.start + length_offset..])
                .sync_write_var_int_field_unpin(length)
                .expect("the reserved Length field lies inside the packet");
        }
        let packet = &mut self.buffer[self.start..];
        // invariant: the tag has its room, and the payload is long enough
        // to sample
        self.keys
            .packet()
            .seal(self.number, packet, self.header_len)
            .expect("the packet has room for its tag");
        self.keys
            .header()
            .apply(packet, self.pn_offset)
            .expect("the payload is long enough to sample");
        if let SealingKeys::OneRtt { usage, .. } = &mut self.keys {
            usage.sealed();
        }
        // invariant: a frame was recorded
        let sealed = attempt
            .seal(packet_len, self.pmtu_probe)
            .expect("a packet with a frame is sealed");
        *self.slot = Some(sealed);
        self.datagram.packets += 1;
        if self.written.in_flight {
            self.datagram.in_flight += packet_len;
        }
        if self.level == EncryptionLevel::OneRtt {
            self.datagram.ends_with_short_header = true;
        }
    }
}

impl<A, B> sealed::Writing for PacketWriter<'_, A, B>
where
    A: PacketSendAttempt,
    A::Summary: From<PaddingSummary>,
    B: CryptoBackend,
{
}

impl<A, B> PacketWriting for PacketWriter<'_, A, B>
where
    A: PacketSendAttempt,
    A::Summary: From<PaddingSummary>,
    B: CryptoBackend,
{
    type Attempt = A;

    fn room(&self, class: FlightClass) -> usize {
        let datagram_len = self.buffer.len() - self.datagram.start;
        let room = self
            .datagram
            .max_len
            .saturating_sub(datagram_len + AEAD_TAG_LEN);
        let room = match class {
            FlightClass::AckOnly => room,
            // once a frame counts in flight, so does the whole packet
            FlightClass::InFlight => {
                let packet_len = self.buffer.len() - self.start + AEAD_TAG_LEN;
                room.min(
                    self.datagram
                        .in_flight_room
                        .saturating_sub(self.datagram.in_flight + packet_len),
                )
            }
        };
        // a frame shorter than the shortfall is padded up to it
        if room >= self.sample_shortfall() {
            room
        } else {
            0
        }
    }

    fn buffer(&mut self) -> &mut BytesMut {
        self.buffer
    }

    fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    fn frame_written(
        &mut self,
        summary: SummaryOf<Self>,
        ack_eliciting: bool,
        in_flight: bool,
        expands_datagram: bool,
    ) {
        // invariant: the attempt is kept until the writer is dropped
        self.attempt
            .as_mut()
            .expect("the attempt is kept until the packet is sealed")
            .record_frame(summary, ack_eliciting, in_flight);
        self.written.frame = true;
        self.written.ack_eliciting |= ack_eliciting;
        self.written.in_flight |= in_flight;
        self.written.expands_datagram |= expands_datagram;
    }

    fn close(&mut self) {
        self.closed = true;
    }

    fn conclude(&mut self, more: bool) {
        self.more_follow = more;
    }
}

impl<A, B> Drop for PacketWriter<'_, A, B>
where
    A: PacketSendAttempt,
    A::Summary: From<PaddingSummary>,
    B: CryptoBackend,
{
    fn drop(&mut self) {
        // a panic ends the whole connection: no packet number is used
        if std::thread::panicking() {
            return;
        }
        if let Some(attempt) = self.attempt.take() {
            self.finish(attempt);
        }
    }
}
