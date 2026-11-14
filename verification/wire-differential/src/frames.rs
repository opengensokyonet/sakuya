//! Frames: a neutral model of what a packet payload holds, an adapter per
//! implementation that reads and writes it, and the classification of the
//! divergences between the readers.
//!
//! The model states values only: the references do not keep the width of
//! each variable-length integer, so neither does the model. Whether sakuya
//! keeps every detail of an encoding is checked on sakuya alone, by writing
//! back what it read ([`sakuya::Read::rewrite_mismatch`]).
//!
//! sakuya reads with the frame set of version 1, DATAGRAM and
//! RESET_STREAM_AT ([`sakuya::Full`]); quinn-proto and s2n-quic-core read
//! DATAGRAM and extension frames of their own, and neither reads
//! RESET_STREAM_AT.
pub mod classify;
pub mod generate;
pub mod quinn;
pub mod s2n;
pub mod sakuya;

/// A frame as every implementation can state it.
///
/// A PADDING frame is one byte; a run of them is as many frames, so that
/// readers which take a run as one frame and readers which take each byte as
/// a frame give the same sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Padding,
    Ping,
    Ack {
        delay: u64,
        /// Inclusive `(smallest, largest)` packet number ranges, largest
        /// first.
        ranges: Vec<(u64, u64)>,
        /// ECT0, ECT1 and ECN-CE counts.
        ecn: Option<(u64, u64, u64)>,
    },
    ResetStream {
        id: u64,
        code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        code: u64,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    NewToken {
        token: Vec<u8>,
    },
    Stream {
        id: u64,
        /// The offset of the data; 0 when the frame has no Offset field.
        offset: u64,
        fin: bool,
        has_length: bool,
        data: Vec<u8>,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        limit: u64,
    },
    MaxStreams {
        uni: bool,
        count: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    StreamsBlocked {
        uni: bool,
        count: u64,
    },
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        cid: Vec<u8>,
        token: [u8; 16],
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    TransportClose {
        code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },
    ApplicationClose {
        code: u64,
        reason: Vec<u8>,
    },
    HandshakeDone,
    Datagram {
        has_length: bool,
        data: Vec<u8>,
    },
    /// RESET_STREAM_AT, which only sakuya reads.
    ResetStreamAt {
        id: u64,
        code: u64,
        final_size: u64,
        reliable_size: u64,
    },
    /// A frame of an extension that only a reference reads, by name.
    ReferenceOnly(&'static str),
}

/// What a reader gives for a payload: the frames it read, and whether it
/// stopped at a frame it rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    pub frames: Vec<Frame>,
    pub failed: bool,
}

impl Decoded {
    /// The same frames without the presence of Length fields, for comparing
    /// with a reader that does not state it.
    pub fn without_lengths(&self) -> Self {
        let frames = self
            .frames
            .iter()
            .cloned()
            .map(|mut frame| {
                if let Frame::Stream { has_length, .. } | Frame::Datagram { has_length, .. } =
                    &mut frame
                {
                    *has_length = false;
                }
                frame
            })
            .collect();
        Self {
            frames,
            failed: self.failed,
        }
    }
}

/// The value and the encoded width of the Frame Type at the start of
/// `bytes`, read without regard to frame sets; `None` if `bytes` ends within
/// it.
pub fn frame_type_at(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let width = 1usize << (first >> 6);
    let rest = bytes.get(1..width)?;
    let value = rest.iter().fold(u64::from(first & 0x3f), |value, &byte| {
        value << 8 | u64::from(byte)
    });
    Some((value, width))
}

/// The width of the shortest encoding of `value`, below 2<sup>62</sup>.
pub fn shortest_width(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}
