//! Writing frames into a packet: what every part's frame sources write
//! with.

/// The summary of the PADDING a packet writer writes: it has nothing to
/// hand back when the packet is acknowledged or declared lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PaddingSummary;
