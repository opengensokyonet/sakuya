//! The bytes a level keeps, and the CRYPTO frames written from them.

use core::{marker::PhantomData, num::NonZeroUsize};

use bytes::BytesMut;
use sakuya_recovery::send_journals::{DequeSendJournals, SendJournals as _};
use sakuya_wire::{
    parts::{CNil, Coproduct, HList},
    v1::{
        frame::{FrameRun, set::Frames},
        role::Role,
    },
};

use super::*;
use crate::v1::{
    aead_usage::AeadUsage,
    datagram_batch::tests::{Accounts, Batch, one_rtt_keys},
    feedback::FeedbackSummary,
    receive::open_one_rtt,
};

fn v(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

fn data(len: usize, from: u8) -> Bytes {
    (0..len).map(|i| from.wrapping_add(i as u8)).collect()
}

fn buffer_of(len: usize) -> OffsetMapCryptoSendBuffer {
    let mut buffer = OffsetMapCryptoSendBuffer::new();
    buffer.append(data(len, 0));
    buffer
}

fn taken(buffer: &mut OffsetMapCryptoSendBuffer, max_len: usize) -> Option<(u64, usize)> {
    buffer
        .take_unsent(max_len)
        .map(|(offset, data)| (offset.get(), data.len()))
}

#[test]
fn unsent_bytes_go_out_in_order_once() {
    let mut buffer = OffsetMapCryptoSendBuffer::new();
    buffer.append(data(10, 0));
    buffer.append(data(10, 10));
    assert_eq!(buffer.written_end(), v(20));
    // a block is handed out up to its end at most
    assert_eq!(taken(&mut buffer, 4), Some((0, 4)));
    assert_eq!(taken(&mut buffer, 100), Some((4, 6)));
    let (offset, bytes) = buffer.take_unsent(100).unwrap();
    assert_eq!((offset, &bytes[..]), (v(10), &data(10, 10)[..]));
    assert_eq!(buffer.first_unsent(), None);
    assert_eq!(buffer.take_unsent(100), None);
}

#[test]
fn lost_bytes_are_sent_again_at_their_offsets() {
    let mut buffer = buffer_of(30);
    assert_eq!(taken(&mut buffer, 10), Some((0, 10)));
    assert_eq!(taken(&mut buffer, 10), Some((10, 10)));
    buffer.lost(v(0), 10);
    // the lost range comes before what was never sent
    assert_eq!(buffer.first_unsent(), Some(v(0)));
    let (offset, bytes) = buffer.take_unsent(100).unwrap();
    assert_eq!((offset, &bytes[..]), (v(0), &data(10, 0)[..]));
    assert_eq!(taken(&mut buffer, 100), Some((20, 10)));
}

#[test]
fn acknowledged_bytes_stay_acknowledged_when_a_copy_is_lost() {
    let mut buffer = buffer_of(30);
    assert_eq!(taken(&mut buffer, 30), Some((0, 30)));
    buffer.acknowledged(v(10), 10);
    // the packet that carried all of it is lost: only what is not
    // acknowledged is sent again
    buffer.lost(v(0), 30);
    assert_eq!(taken(&mut buffer, 100), Some((0, 10)));
    assert_eq!(taken(&mut buffer, 100), Some((20, 10)));
    assert_eq!(buffer.first_unsent(), None);
}

#[test]
fn a_late_acknowledgment_takes_lost_bytes_out_of_the_unsent() {
    let mut buffer = buffer_of(20);
    assert_eq!(taken(&mut buffer, 20), Some((0, 20)));
    buffer.lost(v(0), 20);
    buffer.acknowledged(v(0), 20);
    assert_eq!(buffer.first_unsent(), None);
    // what is acknowledged from the start is released
    assert!(buffer.blocks.is_empty());
    assert_eq!(buffer.released_end, 20);
}

#[test]
fn acknowledged_data_is_released_from_the_first_byte_not_acknowledged() {
    let mut buffer = OffsetMapCryptoSendBuffer::new();
    buffer.append(data(10, 0));
    buffer.append(data(10, 10));
    assert_eq!(taken(&mut buffer, 10), Some((0, 10)));
    assert_eq!(taken(&mut buffer, 10), Some((10, 10)));
    buffer.acknowledged(v(5), 10);
    // bytes 0..5 are not acknowledged: nothing is released
    assert_eq!(buffer.released_end, 0);
    buffer.acknowledged(v(0), 5);
    assert_eq!(buffer.released_end, 15);
    // the second block is cut to what is not acknowledged
    assert_eq!(buffer.blocks.len(), 1);
    assert_eq!(&buffer.blocks[&15][..], &data(5, 15)[..]);
    // bytes 15..20 are lost and sent again from the cut block
    buffer.lost(v(10), 10);
    let (offset, bytes) = buffer.take_unsent(100).unwrap();
    assert_eq!((offset, &bytes[..]), (v(15), &data(5, 15)[..]));
}

#[test]
fn the_engine_writes_at_its_level_and_only_moves_forward() {
    let mut sender = CryptoSender::<OffsetMapCryptoSendBuffer>::new();
    sender.write(data(3, 0)).unwrap();
    sender.move_output_to(CryptoLevel::Handshake);
    sender.write(data(4, 0)).unwrap();
    sender.move_output_to(CryptoLevel::Initial);
    assert_eq!(sender.writing(), CryptoLevel::Handshake);
    assert_eq!(sender.first_unsent(CryptoLevel::Initial), Some(v(0)));
    assert_eq!(sender.first_unsent(CryptoLevel::Handshake), Some(v(0)));
    assert!(!sender.has_unsent(CryptoLevel::OneRtt));
}

#[test]
fn a_discarded_level_keeps_nothing() {
    let mut sender = CryptoSender::<OffsetMapCryptoSendBuffer>::new();
    sender.write(data(3, 0)).unwrap();
    sender.discard(CryptoLevel::Initial);
    assert!(sender.is_discarded(CryptoLevel::Initial));
    assert!(!sender.has_unsent(CryptoLevel::Initial));
    // what comes back of its packets, or is written to it, is dropped
    sender.lost(CryptoLevel::Initial, v(0), 3);
    sender.write(data(3, 0)).unwrap();
    assert!(!sender.has_unsent(CryptoLevel::Initial));
}

/// The CRYPTO frames `sender` writes of `level` into a 1-RTT packet of a
/// datagram of at most `max_len` bytes, as the peer reads them, with the
/// summaries the packet's record keeps; and whether it wrote any.
#[allow(clippy::type_complexity)]
fn crypto_frames_written(
    sender: &mut CryptoSender<OffsetMapCryptoSendBuffer>,
    level: CryptoLevel,
    max_len: usize,
) -> (Vec<(u64, Vec<u8>)>, Vec<CryptoSummary>, bool) {
    type Summary = Coproduct<FeedbackSummary<u64>, CNil>;
    let (keys, receiver) = one_rtt_keys();
    let mut journals = DequeSendJournals::<u64, Summary, ()>::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    let wrote;
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, max_len, max_len, false);
        let packet = datagram
            .start_one_rtt_packet(
                journals.start_attempt(()),
                keys.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let mut open = packet.open::<InFlightClass>();
        wrote = sender.write_frames(level, &mut open);
    }
    let summaries = journals
        .take_link_path(&())
        .flat_map(|record| record.summaries)
        .filter_map(|summary| match summary {
            Coproduct::Inl(summary) => summary.get::<CryptoSummary, _>().copied(),
            Coproduct::Inr(never) => match never {},
        })
        .collect();
    let Some(datagram) = batch.datagrams().next() else {
        return (Vec::new(), summaries, wrote);
    };
    let mut packet = BytesMut::from(datagram);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    let payload = &packet[opened.payload.clone()];
    let frames = Frames::new(payload, PhantomData::<HList![sakuya_wire::v1::Part]>)
        .filter_map(|run| match run.unwrap().extract() {
            FrameRun::Crypto(frame) => Some((frame.offset().get().get(), frame.data().to_vec())),
            _ => None,
        })
        .collect();
    (frames, summaries, wrote)
}

#[test]
fn crypto_frames_take_what_the_room_holds_with_their_summaries() {
    let mut sender = CryptoSender::<OffsetMapCryptoSendBuffer>::new();
    sender.move_output_to(CryptoLevel::OneRtt);
    sender.write(data(100, 0)).unwrap();
    sender.write(data(100, 100)).unwrap();
    // a 1-RTT packet takes 26 bytes beyond its frames here; 60 bytes of
    // room: a frame of 57 bytes of data at offset 0 (type, offset, length)
    let (frames, summaries, wrote) = crypto_frames_written(&mut sender, CryptoLevel::OneRtt, 86);
    assert!(wrote);
    assert_eq!(frames, [(0, data(57, 0).to_vec())]);
    assert_eq!(
        summaries,
        [CryptoSummary {
            level: CryptoLevel::OneRtt,
            offset: v(0),
            len: 57
        }]
    );
    assert_eq!(sender.first_unsent(CryptoLevel::OneRtt), Some(v(57)));
    // a larger packet takes the rest of the first block and some of the
    // second, as two frames
    let (frames, summaries, _) = crypto_frames_written(&mut sender, CryptoLevel::OneRtt, 26 + 100);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], (57, data(43, 57).to_vec()));
    assert_eq!(frames[1].0, 100);
    let len = frames[1].1.len();
    // 3 + 43, then the frame at offset 100 takes two bytes for its offset
    assert_eq!(len, 100 - (3 + 43) - 4);
    assert_eq!(
        summaries,
        [
            CryptoSummary {
                level: CryptoLevel::OneRtt,
                offset: v(57),
                len: 43
            },
            CryptoSummary {
                level: CryptoLevel::OneRtt,
                offset: v(100),
                len
            },
        ]
    );
}

#[test]
fn nothing_is_written_of_a_level_without_unsent_bytes() {
    let mut sender = CryptoSender::<OffsetMapCryptoSendBuffer>::new();
    sender.write(data(10, 0)).unwrap();
    let (frames, summaries, wrote) = crypto_frames_written(&mut sender, CryptoLevel::OneRtt, 1200);
    assert!(!wrote);
    assert!(frames.is_empty() && summaries.is_empty());
    sender.discard(CryptoLevel::Initial);
    let (_, _, wrote) = crypto_frames_written(&mut sender, CryptoLevel::Initial, 1200);
    assert!(!wrote);
}
