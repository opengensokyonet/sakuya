//! Times sakuya's readers on inputs built to make them work: transport
//! parameters with many distinct unknown IDs, and ACK frames with as many
//! ranges as a payload of a given size holds.
use core::marker::PhantomData;
use sakuya_wire::{
    parts::HList,
    v1::{
        self,
        frame::{FrameRun, ack::AckRange, set::Frames},
    },
};
use std::time::Instant;
use wire_differential::parameters::sakuya::{self, Parts};

/// `count` parameters with distinct two-byte IDs from 0x40 up, which no
/// part claims, each with an empty value.
fn unknown_parameters(count: usize) -> Vec<u8> {
    assert!(count <= 0x3f00, "distinct two-byte IDs above 0x40");
    let mut bytes = Vec::with_capacity(3 * count);
    for index in 0..count {
        let id = 0x4000 | (0x40 + index as u16);
        bytes.extend(id.to_be_bytes());
        bytes.push(0);
    }
    bytes
}

/// An ACK frame of `size` bytes, as many ACK Ranges of gap 0 and length 0
/// as fit below the largest packet number.
fn ack_frame(size: usize) -> (Vec<u8>, usize) {
    // Type, Largest Acknowledged in 8 bytes, ACK Delay, ACK Range Count in
    // 4 bytes, First ACK Range, then two bytes per range.
    let ranges = (size - 1 - 8 - 1 - 4 - 1) / 2;
    let mut bytes = vec![0x02];
    bytes.extend(0xffff_ffff_ffff_ffffu64.to_be_bytes());
    bytes.push(0);
    bytes.extend((0x8000_0000u32 | ranges as u32).to_be_bytes());
    bytes.push(0);
    bytes.resize(bytes.len() + 2 * ranges, 0);
    (bytes, ranges)
}

fn main() {
    println!("transport parameters, distinct unknown IDs:");
    for count in [100, 1000, 4000, 16000] {
        let bytes = unknown_parameters(count);
        let start = Instant::now();
        let parameters = sakuya::read_with::<Parts>(&bytes, v1::role::Role::Client)
            .expect("distinct unknown parameters are accepted");
        let elapsed = start.elapsed();
        assert_eq!(parameters.unknown.len(), count);
        println!(
            "  {count:>6} parameters, {:>6} bytes: {elapsed:?}",
            bytes.len()
        );
    }

    println!("ACK frame with the most ranges a payload holds:");
    for size in [1200usize, 65527] {
        let (bytes, ranges) = ack_frame(size);
        let start = Instant::now();
        let mut frames = Frames::new(bytes.as_slice(), PhantomData::<HList![v1::Part]>);
        let run = frames
            .next()
            .expect("one item")
            .expect("the frame is valid");
        let elapsed = start.elapsed();
        let FrameRun::Ack(ack) = run.extract() else {
            panic!("an ACK frame");
        };
        assert_eq!(ack.ranges().len(), ranges);
        assert!(frames.next().is_none());
        println!(
            "  {size:>6} bytes: {ranges} ranges, {} bytes of ranges held, {elapsed:?}",
            ranges * size_of::<AckRange>(),
        );
    }
}
