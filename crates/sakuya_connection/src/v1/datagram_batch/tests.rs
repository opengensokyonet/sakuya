//! Datagrams and packets written, read back with the receiving side's
//! opening.

use core::{cell::Cell, num::NonZeroUsize};
use std::rc::Rc;

use bytes::{Bytes, BytesMut};
use sakuya_packet_protection::{
    backend::{AeadAlgorithm, KdfAlgorithm, ring::RingBackend},
    initial::{INITIAL_AEAD, InitialSecrets},
    secret::TrafficSecret,
};
use sakuya_recovery::{
    congestion::{
        CongestionContext, CongestionController, InFlightPacket, RemovedPacket,
        SpuriouslyLostPacket,
    },
    pacing::{Pacer, PacingInput},
    pto::ProbeCount,
    send_journals::{DequeSealedPacket, DequeSendJournals, SendJournals},
};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength},
    frame::NoLength,
    v1::{
        frame::{
            ack::AckFrame, crypto::CryptoFrame, path_response::PathResponseFrame, ping::PingFrame,
            stream::StreamFrame,
        },
        protected_packet::{Packet, ProtectedPacket, into_packets},
        stream_id::{Directionality, Initiator, StreamId},
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};

use super::*;
use crate::{
    v1::{
        amplification::{AddressValidation, AntiAmplificationFactor},
        keys::OneRttKeys,
        receive::{Opened, ReceiveGeneration, open, open_one_rtt, packet_number_offset},
    },
    write::{AckOnlyClass, InFlightClass, Last, NotLast, Supplied, ToPacketEndFrame},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Summary {
    Padding,
    Frame(&'static str),
}

impl From<PaddingSummary> for Summary {
    fn from(_: PaddingSummary) -> Self {
        Self::Padding
    }
}

type Journals = DequeSendJournals<u64, Summary, ()>;
pub(in crate::v1) type Batch =
    DatagramBatch<DequeSealedPacket, DequeSealedPacket, DequeSealedPacket, usize>;

/// A pacer that only counts what it is charged, and a congestion
/// controller that gives each packet sealed its own size.
#[derive(Debug, Default)]
pub(in crate::v1) struct Charged(usize);

impl CongestionController<u64> for Charged {
    type SentState = usize;
    type LossState = ();
    fn window(&self) -> usize {
        usize::MAX
    }
    fn on_packet_sealed(&mut self, bytes: usize, _: bool, _: u64) -> usize {
        bytes
    }
    fn on_spurious_loss(
        &mut self,
        _: (),
        _: impl Iterator<Item = SpuriouslyLostPacket<u64>>,
        _: &CongestionContext<u64>,
    ) {
    }
    fn on_ce(&mut self, _: u64, _: u64, _: &CongestionContext<u64>) {}
    fn on_lost(
        &mut self,
        _: impl Iterator<Item = InFlightPacket<u64, usize>>,
        _: &CongestionContext<u64>,
    ) {
    }
    fn on_persistent_congestion(&mut self, _: &CongestionContext<u64>) {}
    fn wants_recovery_send(&mut self) -> bool {
        false
    }
    fn on_acked(
        &mut self,
        _: impl Iterator<Item = InFlightPacket<u64, usize>>,
        _: &CongestionContext<u64>,
    ) {
    }
    fn on_removed(
        &mut self,
        _: impl Iterator<Item = RemovedPacket<usize>>,
        _: &CongestionContext<u64>,
    ) {
    }
    fn on_max_datagram_size_changed(&mut self, _: usize, _: bool, _: &CongestionContext<u64>) {}
}

impl Pacer<u64> for Charged {
    fn next_release(&self) -> Option<u64> {
        None
    }
    fn allowance(&self) -> usize {
        usize::MAX
    }
    fn refill(&mut self, _: u64, _: PacingInput) {}
    fn on_charged(&mut self, bytes: usize) {
        self.0 += bytes;
    }
}

/// A connection ID that records the size it was used for.
pub(in crate::v1) struct RecordedCid {
    id: ConnectionId,
    used: Rc<Cell<Option<usize>>>,
}

impl ConnectionIdUse for RecordedCid {
    fn connection_id(&self) -> ConnectionId {
        self.id
    }
    fn used(self, datagram_len: usize) {
        self.used.set(Some(datagram_len));
    }
}

const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

fn dcid() -> ConnectionId {
    ConnectionId::new(&DCID).unwrap()
}

fn scid() -> ConnectionId {
    ConnectionId::new(&[7, 7, 7, 7]).unwrap()
}

/// What the end of a datagram is charged to.
pub(in crate::v1) struct Accounts {
    congestion: LinkPathCongestionState<u64>,
    pacer: Charged,
    amplification: AntiAmplification,
    used: Rc<Cell<Option<usize>>>,
    /// The length of the connection IDs this side asks the peer to send
    /// with: that of [`scid`] unless a test changes it.
    local_id_length: ConnectionIdLength,
}

impl Accounts {
    pub(in crate::v1) fn new() -> Self {
        let mut amplification = AntiAmplification::new(AntiAmplificationFactor::MAX);
        amplification.received(1000);
        Self {
            congestion: LinkPathCongestionState::new(),
            pacer: Charged::default(),
            amplification,
            used: Rc::new(Cell::new(None)),
            local_id_length: scid().length(),
        }
    }

    pub(in crate::v1) fn start<'b>(
        &'b mut self,
        batch: &'b mut Batch,
        role: Role,
        max_len: usize,
        in_flight_room: usize,
        probe: bool,
    ) -> DatagramWriter<
        'b,
        DequeSealedPacket,
        DequeSealedPacket,
        DequeSealedPacket,
        RecordedCid,
        Charged,
        u64,
    > {
        let cid = RecordedCid {
            id: dcid(),
            used: Rc::clone(&self.used),
        };
        batch.start_datagram(
            0,
            cid,
            role,
            self.local_id_length,
            max_len,
            in_flight_room,
            probe,
            &mut self.congestion,
            &mut self.pacer,
            &mut self.amplification,
        )
    }

    /// The anti-amplification credit left of the 3000 bytes given.
    fn credit(&self) -> u64 {
        self.amplification
            .credit(AddressValidation::NotValidated)
            .unwrap()
    }
}

fn initial_keys() -> DirectionKeys<RingBackend> {
    let secrets = InitialSecrets::derive(&RingBackend, &dcid());
    DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.client)
}

fn secret(byte: u8) -> TrafficSecret {
    TrafficSecret::new(KdfAlgorithm::HkdfSha256, &[byte; 32]).unwrap()
}

fn handshake_keys() -> DirectionKeys<RingBackend> {
    DirectionKeys::derive(&RingBackend, AeadAlgorithm::Aes128Gcm, &secret(3))
}

/// The 1-RTT keys of the sender, and those of the receiver.
pub(in crate::v1) fn one_rtt_keys() -> (OneRttKeys<RingBackend, u64>, OneRttKeys<RingBackend, u64>)
{
    let mut sender = OneRttKeys::NotYet;
    sender.install(RingBackend, AeadAlgorithm::Aes128Gcm, secret(1), secret(2));
    let mut receiver = OneRttKeys::NotYet;
    receiver.install(RingBackend, AeadAlgorithm::Aes128Gcm, secret(2), secret(1));
    (sender, receiver)
}

fn crypto(data: &'static [u8]) -> CryptoFrame<Bytes> {
    CryptoFrame::new(
        VarIntField::shortest(VarInt::ZERO),
        VarIntWidth::One,
        Bytes::from_static(data),
    )
    .unwrap()
}

fn stream_to_end(data: &'static [u8]) -> StreamFrame<Bytes, NoLength> {
    let id = StreamId::new(Initiator::Client, Directionality::Bidirectional, 0).unwrap();
    StreamFrame::without_length(
        VarIntField::shortest(id),
        None,
        Bytes::from_static(data),
        false,
    )
    .unwrap()
}

/// The protected packets of `datagram`.
fn packets(datagram: &[u8]) -> Vec<ProtectedPacket<BytesMut>> {
    into_packets(
        BytesMut::from(datagram),
        ConnectionIdLength::new(DCID.len()).unwrap(),
    )
    .map(|packet| match packet.unwrap() {
        Packet::Protected(packet) => packet,
        other => panic!("not a protected packet: {other:?}"),
    })
    .collect()
}

/// `packet` opened with `keys`: what was opened and the plaintext payload.
fn opened(
    keys: &DirectionKeys<RingBackend>,
    packet: ProtectedPacket<BytesMut>,
) -> (Opened, Vec<u8>) {
    let pn_offset = packet_number_offset(&packet).unwrap();
    let mut bytes = packet.into_bytes();
    let opened = open(keys, &mut bytes, pn_offset, None).unwrap();
    let payload = bytes[opened.payload.clone()].to_vec();
    (opened, payload)
}

/// The record of the first packet `journals` sealed into `packet`.
fn record(
    journals: &mut Journals,
    packet: DequeSealedPacket,
) -> sakuya_recovery::send_journals::SentPacketRecord<u64, Summary, ()> {
    journals.sent(packet, 1).clone()
}

#[test]
fn a_client_initial_and_a_handshake_packet_are_coalesced_and_padded_to_1200() {
    let (ik, hk) = (initial_keys(), handshake_keys());
    let (mut initial, mut handshake) = (Journals::new(), Journals::new());
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::new(4).unwrap());
    {
        let mut datagram = accounts.start(&mut batch, Role::Client, 1500, 1500, false);
        {
            let packet = datagram
                .start_initial_packet(initial.start_attempt(()), &ik, None, scid(), Bytes::new())
                .unwrap();
            let mut open = packet.open::<InFlightClass>();
            open.write_frame(crypto(b"hello"), Summary::Frame("crypto"))
                .unwrap();
            open.conclude(true);
        }
        assert_eq!(datagram.floor(), 1200, "a client's Initial packet");
        let packet = datagram
            .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
        open.conclude(false);
    }
    let bytes: Vec<Vec<u8>> = batch.datagrams().map(<[u8]>::to_vec).collect();
    assert_eq!(bytes.len(), 1);
    assert_eq!(bytes[0].len(), 1200);

    let mut read = packets(&bytes[0]).into_iter();
    let (first, second) = (read.next().unwrap(), read.next().unwrap());
    assert!(read.next().is_none());
    let first_len = first.bytes().len();
    let second_len = second.bytes().len();
    // the Length fields split the datagram where the packets end
    assert_eq!(first_len + second_len, 1200);
    let (opened_initial, payload) = opened(&ik, first);
    assert_eq!(opened_initial.number, PacketNumber::ZERO);
    assert_eq!(payload[..2], [0x06, 0x00]); // CRYPTO, Offset 0
    assert_eq!(payload.len(), crypto(b"hello").encoded_len());
    let (opened_handshake, payload) = opened(&hk, second);
    assert_eq!(opened_handshake.number, PacketNumber::ZERO);
    assert_eq!(payload[0], 0x01); // PING, then PADDING
    assert!(payload[1..].iter().all(|&b| b == 0));

    // the end of the datagram is charged once
    assert_eq!(accounts.congestion.bytes_in_flight(), 1200);
    assert_eq!(accounts.pacer.0, 1200);
    assert_eq!(accounts.credit(), 3000 - 1200);
    assert_eq!(accounts.used.get(), Some(1200));

    let entry = batch.take_accepted(1).next().unwrap();
    assert_eq!(entry.len(), 1200);
    assert!(batch.is_empty());
    // each packet is charged its own bytes in flight
    let (initial_packet, handshake_packet) = (entry.initial.unwrap(), entry.handshake.unwrap());
    assert_eq!(
        initial_packet.in_flight.as_ref().map(|charge| charge.bytes),
        Some(first_len)
    );
    assert_eq!(
        handshake_packet
            .in_flight
            .as_ref()
            .map(|charge| charge.bytes),
        Some(second_len)
    );
    let initial_record = record(&mut initial, initial_packet.sealed);
    assert_eq!(initial_record.bytes, first_len);
    assert_eq!(initial_record.summaries, [Summary::Frame("crypto")]);
    assert!(initial_record.ack_eliciting && initial_record.in_flight);
    let handshake_record = record(&mut handshake, handshake_packet.sealed);
    assert_eq!(handshake_record.bytes, second_len);
    assert_eq!(
        handshake_record.summaries,
        [Summary::Frame("ping"), Summary::Padding]
    );
    assert!(entry.application_data.is_none());
    assert_eq!(initial.next_packet_number(), PacketNumber::new(1).unwrap());
}

#[test]
fn a_short_packet_is_padded_for_the_header_protection_sample() {
    let (sender, receiver) = one_rtt_keys();
    let mut application = Journals::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let mut packet = datagram
            .start_one_rtt_packet(
                application.start_attempt(()),
                sender.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        packet.mark_pmtu_probe();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
    }
    let bytes = batch.datagrams().next().unwrap().to_vec();
    // first byte, DCID, a one-byte packet number, PING and two PADDING, tag
    assert_eq!(bytes.len(), 1 + 8 + 1 + 3 + 16);
    let mut packet = BytesMut::from(&bytes[..]);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    assert_eq!(packet[opened.payload.clone()], [0x01, 0x00, 0x00]);
    assert_eq!(opened.first_byte & 0x24, 0, "spin bit and Key Phase 0");
    assert_eq!(usage.sealed_with_current(), 1);

    let entry = batch.take_first().unwrap();
    let record = record(&mut application, entry.application_data.unwrap().sealed);
    assert!(record.pmtu_probe);
    assert_eq!(record.summaries, [Summary::Frame("ping"), Summary::Padding]);
}

#[test]
fn a_datagram_is_22_bytes_longer_than_the_local_connection_ids() {
    let (sender, receiver) = one_rtt_keys();
    let mut application = Journals::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    accounts.local_id_length = ConnectionIdLength::new(8).unwrap();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_one_rtt_packet(
                application.start_attempt(()),
                sender.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
    }
    let bytes = batch.datagrams().next().unwrap().to_vec();
    // first byte, DCID, a one-byte packet number, PING and two PADDING for
    // the sample, tag: 29 bytes, one short of the 8-byte connection IDs
    // this side asks for and 22 (RFC 9000 §10.3)
    assert_eq!(bytes.len(), 8 + 22);
    let mut packet = BytesMut::from(&bytes[..]);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    assert_eq!(packet[opened.payload.clone()], [0x01, 0x00, 0x00, 0x00]);
}

#[test]
fn a_packet_after_a_key_update_has_the_next_key_phase() {
    let (mut sender, receiver) = one_rtt_keys();
    sender.initiate_update();
    let mut application = Journals::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_one_rtt_packet(
                application.start_attempt(()),
                sender.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
    }
    let mut packet = BytesMut::from(batch.datagrams().next().unwrap());
    // the receiver, still at generation 0, opens it with the next one
    let (opened, generation) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    assert_eq!(generation, ReceiveGeneration::Next);
    assert_eq!(opened.first_byte & 0x04, 0x04, "Key Phase 1");
    assert_eq!(usage.sealed_with_current(), 1);
}

#[test]
fn padding_goes_before_the_frames_of_a_closed_packet() {
    let (sender, receiver) = one_rtt_keys();
    let mut application = Journals::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    let response = PathResponseFrame::new([9; 8]);
    let stream = stream_to_end(b"to the end");
    let stream_len = ToPacketEndFrame::encoded_len(&stream);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_one_rtt_packet(
                application.start_attempt(()),
                sender.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(response, Summary::Frame("path response"))
            .unwrap();
        // not the last position: it cannot close the packet
        let open = open.into_last().unwrap_err().make_last();
        let closed = open.write_last(stream, Summary::Frame("stream")).unwrap();
        Supplied::<_, _, Last>::Closed(closed).conclude(false);
    }
    let bytes = batch.datagrams().next().unwrap().to_vec();
    // PATH_RESPONSE expands the datagram (RFC 9000 §8.2.2)
    assert_eq!(bytes.len(), 1200);
    let mut packet = BytesMut::from(&bytes[..]);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    let payload = &packet[opened.payload.clone()];
    let frames = 9 + stream_len;
    let padding = payload.len() - frames;
    assert!(payload[..padding].iter().all(|&b| b == 0));
    assert_eq!(payload[padding], 0x1b); // PATH_RESPONSE
    assert_eq!(payload[padding + 9] & 0xf8, 0x08); // STREAM
    assert!(payload.ends_with(b"to the end"));

    let record = record(
        &mut application,
        batch.take_first().unwrap().application_data.unwrap().sealed,
    );
    assert_eq!(
        record.summaries,
        [
            Summary::Frame("path response"),
            Summary::Frame("stream"),
            Summary::Padding
        ]
    );
}

#[test]
fn a_packet_without_frames_takes_its_header_back() {
    let hk = handshake_keys();
    let mut handshake = Journals::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        {
            let packet = datagram
                .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
                .unwrap();
            let open = packet.open::<InFlightClass>();
            assert!(open.remaining() > 0);
        }
        assert_eq!(datagram.len(), 0);
        assert!(datagram.is_empty());
    }
    assert!(batch.is_empty());
    assert_eq!(handshake.next_packet_number(), PacketNumber::ZERO);
    assert_eq!(accounts.used.get(), None);
    assert_eq!(accounts.congestion.bytes_in_flight(), 0);
    assert_eq!(accounts.pacer.0, 0);
    assert_eq!(accounts.credit(), 3000);
}

#[test]
fn a_frame_that_does_not_fit_comes_back_unwritten() {
    let (sender, _) = one_rtt_keys();
    let mut application = Journals::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    let mut datagram = accounts.start(&mut batch, Role::Server, 60, 1500, false);
    let packet = datagram
        .start_one_rtt_packet(
            application.start_attempt(()),
            sender.send().unwrap(),
            &mut usage,
            None,
        )
        .unwrap();
    let mut open = packet.open::<InFlightClass>();
    // the datagram, less the header (1 + 8 + 1) and the tag
    assert_eq!(open.remaining(), 60 - 10 - 16);
    let rejected = open
        .write_frame(crypto(&[1; 40]), Summary::Frame("crypto"))
        .unwrap_err();
    assert_eq!(rejected.error().frame_len(), 43);
    assert_eq!(rejected.error().remaining(), 34);
    assert_eq!(rejected.into_frame().data().len(), 40);
    assert_eq!(open.remaining(), 34);

    let rejected = open
        .make_last()
        .write_last(stream_to_end(&[2; 40]), Summary::Frame("stream"))
        .unwrap_err();
    assert_eq!(rejected.error().remaining(), 34);
    let (open, _) = rejected.into_parts();
    let open = open.into_position::<NotLast>();
    assert_eq!(open.remaining(), 34);
    drop(open);
    assert!(datagram.is_empty());
    assert_eq!(datagram.len(), 0);
}

#[test]
fn ack_only_content_is_not_limited_by_what_may_go_in_flight() {
    let hk = handshake_keys();
    let mut handshake = Journals::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 0, false);
        let packet = datagram
            .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
            .unwrap();
        let open = packet.open::<InFlightClass>();
        assert_eq!(open.remaining(), 0);
        let mut open = open.into_class::<AckOnlyClass>();
        assert!(open.remaining() > 1000);
        let ack = AckFrame::from_packet_ranges(
            [PacketNumber::ZERO..=PacketNumber::new(3).unwrap()],
            VarIntField::shortest(VarInt::ZERO),
            None,
        )
        .unwrap();
        open.write_frame(ack, Summary::Frame("ack")).unwrap();
    }
    let len = batch.datagrams().next().unwrap().len();
    assert_eq!(accounts.congestion.bytes_in_flight(), 0);
    assert_eq!(accounts.pacer.0, 0);
    assert_eq!(accounts.credit(), 3000 - len as u64);
    let packet = batch.take_first().unwrap().handshake.unwrap();
    assert!(packet.in_flight.is_none());
    let record = record(&mut handshake, packet.sealed);
    assert!(!record.ack_eliciting && !record.in_flight);
    assert_eq!(record.summaries, [Summary::Frame("ack")]);
}

#[test]
fn a_probe_uses_a_permit() {
    let hk = handshake_keys();
    let mut handshake = Journals::new();
    let mut accounts = Accounts::new();
    accounts.congestion.grant_probe_permits(ProbeCount::Two);
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, true);
        let packet = datagram
            .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
    }
    let len = batch.datagrams().next().unwrap().len();
    assert_eq!(accounts.congestion.probe_permits(), 1);
    assert_eq!(accounts.congestion.bytes_in_flight(), len);
    assert_eq!(accounts.pacer.0, len);
}

#[test]
fn a_packet_of_padding_alone_brings_the_datagram_to_its_floor() {
    let (ik, hk) = (initial_keys(), handshake_keys());
    let (mut initial, mut handshake) = (Journals::new(), Journals::new());
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Client, 1500, 1500, false);
        {
            let packet = datagram
                .start_initial_packet(initial.start_attempt(()), &ik, None, scid(), Bytes::new())
                .unwrap();
            let mut open = packet.open::<InFlightClass>();
            open.write_frame(crypto(b"hello"), Summary::Frame("crypto"))
                .unwrap();
            open.conclude(true);
        }
        // what was planned for the Handshake packet is gone
        let packet = datagram
            .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
            .unwrap();
        drop(packet.open::<InFlightClass>());
    }
    let bytes = batch.datagrams().next().unwrap().to_vec();
    assert_eq!(bytes.len(), 1200);
    let second = packets(&bytes).pop().unwrap();
    let (_, payload) = opened(&hk, second);
    assert!(payload.iter().all(|&b| b == 0));
    let record = record(
        &mut handshake,
        batch.take_first().unwrap().handshake.unwrap().sealed,
    );
    assert_eq!(record.summaries, [Summary::Padding]);
    assert!(!record.ack_eliciting && record.in_flight);
}

#[test]
fn a_server_pads_only_an_ack_eliciting_initial_packet() {
    let ik = initial_keys();
    let mut initial = Journals::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::new(2).unwrap());
    let ack = || {
        AckFrame::from_packet_ranges(
            [PacketNumber::ZERO..=PacketNumber::ZERO],
            VarIntField::shortest(VarInt::ZERO),
            None,
        )
        .unwrap()
    };
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_initial_packet(initial.start_attempt(()), &ik, None, scid(), Bytes::new())
            .unwrap();
        let mut open = packet.open::<AckOnlyClass>();
        open.write_frame(ack(), Summary::Frame("ack")).unwrap();
    }
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_initial_packet(initial.start_attempt(()), &ik, None, scid(), Bytes::new())
            .unwrap();
        let mut open = packet.open::<AckOnlyClass>();
        open.write_frame(ack(), Summary::Frame("ack")).unwrap();
        let mut open = open.into_class::<InFlightClass>();
        open.write_frame(crypto(b"hello"), Summary::Frame("crypto"))
            .unwrap();
    }
    let lens: Vec<usize> = batch.datagrams().map(<[u8]>::len).collect();
    assert!(lens[0] < 1200);
    assert_eq!(lens[1], 1200);
    assert!(batch.is_full());
    // the batch keeps its datagrams until they are taken out
    let mut discarded: Vec<_> = batch
        .take_discarded(|datagram| datagram.len() < 1200)
        .collect();
    assert_eq!(discarded.len(), 1);
    assert_eq!(batch.len(), 1);
    assert!(discarded.pop().unwrap().initial.is_some());
}

#[test]
#[should_panic(expected = "at most one packet of each packet number space")]
fn a_second_packet_of_a_space_is_a_mistake() {
    let hk = handshake_keys();
    let mut handshake = Journals::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
    {
        let packet = datagram
            .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
        open.conclude(true);
    }
    let mut other = Journals::new();
    let _ = datagram.start_handshake_packet(other.start_attempt(()), &hk, None, scid());
}

#[test]
#[should_panic(expected = "a packet with a short header is the last of its datagram")]
fn nothing_follows_a_short_packet() {
    let (sender, _) = one_rtt_keys();
    let hk = handshake_keys();
    let (mut application, mut handshake) = (Journals::new(), Journals::new());
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
    {
        let packet = datagram
            .start_one_rtt_packet(
                application.start_attempt(()),
                sender.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
    }
    let _ = datagram.start_handshake_packet(handshake.start_attempt(()), &hk, None, scid());
}

#[test]
fn a_panic_neither_seals_nor_batches() {
    let hk = handshake_keys();
    let mut handshake = Journals::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(PingFrame, Summary::Frame("ping")).unwrap();
        panic!("a frame source panicked");
    }));
    assert!(unwound.is_err());
    assert!(batch.is_empty());
    assert_eq!(handshake.next_packet_number(), PacketNumber::ZERO);
    assert_eq!(accounts.used.get(), None);
    assert_eq!(accounts.congestion.bytes_in_flight(), 0);
}

#[test]
fn a_probe_with_only_an_ack_uses_no_permit() {
    let hk = handshake_keys();
    let mut handshake = Journals::new();
    let mut accounts = Accounts::new();
    accounts.congestion.grant_probe_permits(ProbeCount::Two);
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, true);
        let packet = datagram
            .start_handshake_packet(handshake.start_attempt(()), &hk, None, scid())
            .unwrap();
        let mut open = packet.open::<AckOnlyClass>();
        let ack = AckFrame::from_packet_ranges(
            [PacketNumber::ZERO..=PacketNumber::ZERO],
            VarIntField::shortest(VarInt::ZERO),
            None,
        )
        .unwrap();
        open.write_frame(ack, Summary::Frame("ack")).unwrap();
    }
    assert_eq!(batch.len(), 1);
    assert_eq!(accounts.congestion.probe_permits(), 2);
    assert_eq!(accounts.congestion.bytes_in_flight(), 0);
}

#[test]
fn a_datagram_taken_out_takes_its_bytes_with_it() {
    let ik = initial_keys();
    let mut initial = Journals::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::new(2).unwrap());
    let ack = || {
        AckFrame::from_packet_ranges(
            [PacketNumber::ZERO..=PacketNumber::ZERO],
            VarIntField::shortest(VarInt::ZERO),
            None,
        )
        .unwrap()
    };
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_initial_packet(initial.start_attempt(()), &ik, None, scid(), Bytes::new())
            .unwrap();
        let mut open = packet.open::<AckOnlyClass>();
        open.write_frame(ack(), Summary::Frame("ack")).unwrap();
    }
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1500, 1500, false);
        let packet = datagram
            .start_initial_packet(initial.start_attempt(()), &ik, None, scid(), Bytes::new())
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        open.write_frame(crypto(b"hello"), Summary::Frame("crypto"))
            .unwrap();
    }
    let later = batch.datagrams().nth(1).unwrap().to_vec();
    let discarded: Vec<_> = batch
        .take_discarded(|datagram| datagram.len() < 1200)
        .collect();
    assert_eq!(discarded.len(), 1);
    // what goes to the link and what settles it stay paired
    assert_eq!(batch.outgoing().len(), batch.entries().count());
    for (outgoing, entry) in batch.outgoing().iter().zip(batch.entries()) {
        assert_eq!(outgoing.payload.len(), entry.len());
    }
    assert_eq!(batch.outgoing()[0].payload[..], later[..]);
    assert_eq!(batch.entries().next().unwrap().len(), 1200);
}
