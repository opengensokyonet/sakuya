//! Receive buffers: reassembly and in-order delivery of one stream's data.
//!
//! A [`StreamReceiveBuffer`] reassembles the data of one stream from STREAM frames
//! that may arrive out of order, duplicated or overlapping, and delivers it in
//! order, each byte at most once. It is also the only authority for two
//! cumulative facts of the stream:
//!
//! - the accounted end (`accounted_end`): the highest end offset, or final
//!   size, that any input of the stream has stated. Flow control charges the
//!   stream up to this end ([RFC 9000 §4.5]); reading or discarding data never
//!   lowers it, and inputs that store nothing still raise it.
//! - the final size (`final_size`) once a FIN or a reset has stated it.
//!
//! The ranges held, the gaps between them, the end of the contiguous readable
//! data and the read cursor stay inside the buffer. The stream receive
//! component asks the questions it needs answered — what can be delivered now,
//! how far delivery has progressed — and does not recompute them from a range
//! table. The buffer does not answer which ranges have arrived: that is a
//! protocol fact the stream receive component keeps from the frames' metadata,
//! whatever happens to the data.
//!
//! The buffer is told about the local delivery limits only through its
//! inputs: STREAM payloads arrive already trimmed to the data acceptance limit
//! (while still carrying the frame's original offset, end and FIN), reads are
//! bounded by the delivery limit, and [`StreamReceiveBuffer::release_from`] and
//! [`StreamReceiveBuffer::destroy`] release data that no delivery will need.
//!
//! [`fragmented::FragmentedStreamReceiveBuffer`] implements it with a `BTreeMap` of
//! fragments.
//!
//! [RFC 9000 §4.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5
use bytes::{BufMut, Bytes};
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

pub mod fragmented;

/// The data of one STREAM frame as handed to a receive buffer.
///
/// `offset`, `end` and `fin` are the frame's own values, before any local
/// trimming: they take part in accounting and final size even when none of
/// the payload is kept. `payload` is the part of the frame data the stream
/// receive component accepted: a prefix of the frame data, starting at
/// `offset`, cut where the local acceptance limit ends. It can be empty.
///
/// The constructor checks `offset + payload.len() <= end`, so every offset
/// inside the payload is a [`VarInt`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamDataInput {
    offset: VarInt,
    end: VarInt,
    fin: bool,
    payload: Bytes,
    payload_end: VarInt,
}

impl StreamDataInput {
    /// Describes a frame covering `[offset, end)` whose accepted prefix is
    /// `payload`.
    ///
    /// # Errors
    ///
    /// [`StreamDataInputError`] if `end` is below `offset` or `payload` is
    /// longer than `[offset, end)`.
    pub fn new(
        offset: VarInt,
        end: VarInt,
        fin: bool,
        payload: Bytes,
    ) -> Result<Self, StreamDataInputError> {
        ensure!(
            offset <= end,
            stream_data_input_error::EndBeforeOffsetSnafu { offset, end }
        );
        let payload_end =
            offset_add(offset, payload.len()).filter(|payload_end| *payload_end <= end);
        let Some(payload_end) = payload_end else {
            return stream_data_input_error::PayloadBeyondEndSnafu {
                offset,
                end,
                payload_len: payload.len(),
            }
            .fail();
        };
        Ok(Self {
            offset,
            end,
            fin,
            payload,
            payload_end,
        })
    }

    /// The frame's offset.
    pub fn offset(&self) -> VarInt {
        self.offset
    }

    /// The end of the frame's data, `offset` plus the frame's data length.
    pub fn end(&self) -> VarInt {
        self.end
    }

    /// Whether the frame carries FIN, stating `end` as the final size.
    pub fn fin(&self) -> bool {
        self.fin
    }

    /// The accepted prefix of the frame's data.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// The end of the accepted prefix, `offset + payload.len()`; at most
    /// `end`.
    pub fn payload_end(&self) -> VarInt {
        self.payload_end
    }

    /// Splits the input into offset, end, FIN and accepted payload.
    pub fn into_parts(self) -> (VarInt, VarInt, bool, Bytes) {
        (self.offset, self.end, self.fin, self.payload)
    }
}

/// Failures of [`StreamDataInput::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(stream_data_input_error), visibility(pub(crate)))]
pub enum StreamDataInputError {
    /// The frame's end lies below its offset.
    #[snafu(display("stream data end {end} lies below its offset {offset}"))]
    EndBeforeOffset {
        /// The frame's offset.
        offset: VarInt,
        /// The frame's end.
        end: VarInt,
    },
    /// The accepted payload is longer than the frame's data.
    #[snafu(display("{payload_len} payload bytes at offset {offset} pass the frame end {end}"))]
    PayloadBeyondEnd {
        /// The frame's offset.
        offset: VarInt,
        /// The frame's end.
        end: VarInt,
        /// The length of the accepted payload.
        payload_len: usize,
    },
}

/// Reassembly, in-order delivery and the cumulative receive facts of one
/// stream.
///
/// The buffer answers purpose-specific questions instead of exposing its
/// ranges. This method set is provisional.
///
/// # Contract
///
/// - **Accounting.** [`accounted_end`](Self::accounted_end) is the maximum of
///   every `end` passed to [`receive_data`](Self::receive_data) and every
///   value passed to [`receive_final_size`](Self::receive_final_size). It
///   never decreases, also not after reads, [`release_from`] or [`destroy`].
/// - **Final size.** The first FIN or final size input sets
///   [`final_size`](Self::final_size); later different values do not change
///   it. Checking that inputs agree is the stream receive component's job: it
///   compares the inputs with the values it queried before handing them over.
///   An input that contradicts earlier ones must not make the buffer panic.
/// - **Delivery.** Reads hand out contiguous data starting at
///   [`delivered_end`](Self::delivered_end), never data at or beyond the
///   `limit` they are given, and each byte at most once. A returned chunk is
///   never empty. `delivered_end` advances by exactly the bytes handed out.
/// - **Duplicates.** Data at offsets already delivered, or already held, is
///   ignored; a shorter duplicate never replaces longer held data.
/// - **Release.** After [`release_from`] or [`destroy`] the released data is
///   gone for good, and payload arriving after `destroy` is not kept; the
///   accounted end and the final size keep being maintained from input
///   metadata. The buffer keeps no record of which ranges arrived: the
///   ranges are a protocol fact that the stream receive component keeps from
///   the frames' metadata, not something that is lost with the data.
///
/// [`release_from`]: Self::release_from
/// [`destroy`]: Self::destroy
pub trait StreamReceiveBuffer {
    /// The block type handed out by [`read_chunk`](Self::read_chunk).
    type Chunk;

    /// Takes the data of one STREAM frame.
    fn receive_data(&mut self, input: StreamDataInput);

    /// Takes a final size stated without payload, by a reset.
    fn receive_final_size(&mut self, final_size: VarInt);

    /// The accounted end: the highest end offset or final size any input has
    /// stated.
    fn accounted_end(&self) -> VarInt;

    /// The final size, once an input has stated one.
    fn final_size(&self) -> Option<VarInt>;

    /// How far data has been handed out: every byte below this offset has
    /// been delivered, none at or above it.
    fn delivered_end(&self) -> VarInt;

    /// Hands out the next contiguous block below `limit`, if one is held at
    /// [`delivered_end`](Self::delivered_end).
    fn read_chunk(&mut self, limit: VarInt) -> Option<Self::Chunk>;

    /// Copies contiguous data below `limit` into `target`, as much as fits,
    /// and returns the number of bytes copied.
    fn read_into<T: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut T) -> usize;

    /// Releases the held data at and above `end`; data below `end` stays
    /// deliverable.
    fn release_from(&mut self, end: VarInt);

    /// Destroys the data: releases all held data and stops keeping payload.
    ///
    /// Only the data is destroyed. Which ranges arrived is not the buffer's
    /// to keep, so nothing about them is lost here.
    fn destroy(&mut self);
}

/// `offset + len`, if it is a [`VarInt`].
pub(crate) fn offset_add(offset: VarInt, len: usize) -> Option<VarInt> {
    VarInt::try_from(len)
        .ok()
        .and_then(|len| offset.checked_add(len))
}

/// The length of `[from, to)` as a `usize`, saturating at `usize::MAX`; zero
/// when `to` is not above `from`.
pub(crate) fn span(from: VarInt, to: VarInt) -> usize {
    usize::try_from(to.get().saturating_sub(from.get())).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
