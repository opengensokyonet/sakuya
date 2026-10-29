use super::{
    ExposeUsageError, ExposedEnd, ResetRetention, Selection, SelectionConstraints, SendBuffer,
    TransmissionReceipt, VisibilitySettlement,
};
use crate::connection_send_credit::{ConnectionCreditReservation, ConnectionSendFlowController};
use bytes::Bytes;
use sakuya_wire::var_int::VarInt;
use std::collections::BTreeMap;

/// A send buffer that keeps each appended [`Bytes`] as it arrived, keyed by
/// its stream offset.
///
/// Appending stores the handle without copying the payload; a reset shortens
/// the retained data by slicing, also without copying. Connection credit
/// coverage is kept in an embedded [`VisibilitySettlement`].
///
/// Selection and feedback are not available yet: their placeholder types have
/// no values.
#[derive(Debug, Default)]
pub struct BasicSendBuffer {
    written_end: VarInt,
    retained: BTreeMap<VarInt, Bytes>,
    visibility: VisibilitySettlement,
    retention: Option<ResetRetention>,
}

impl BasicSendBuffer {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The retained data in offset order, as `(offset, bytes)`.
    pub fn retained(&self) -> impl Iterator<Item = (VarInt, &Bytes)> {
        self.retained.iter().map(|(&offset, bytes)| (offset, bytes))
    }

    /// The visibility settlement: exposure end, exposed final size and
    /// uncommitted coverage.
    pub fn visibility(&self) -> &VisibilitySettlement {
        &self.visibility
    }

    /// The reset retention applied last, if any.
    pub fn retention(&self) -> Option<ResetRetention> {
        self.retention
    }
}

impl SendBuffer for BasicSendBuffer {
    fn written_end(&self) -> VarInt {
        self.written_end
    }

    fn exposure_end(&self) -> VarInt {
        self.visibility.exposure_end()
    }

    fn append(&mut self, bytes: Bytes, connection_credit_reservation: ConnectionCreditReservation) {
        assert!(
            self.retention.is_none(),
            "a send buffer takes no data after a reset"
        );
        let length = VarInt::try_from(bytes.len()).expect("appended length is a VarInt");
        assert_eq!(
            connection_credit_reservation.amount(),
            length,
            "a connection credit reservation must cover exactly the appended data"
        );
        let offset = self.written_end;
        self.written_end = offset
            .checked_add(length)
            .expect("the written end stays a VarInt");
        self.visibility.cover(offset, connection_credit_reservation);
        if !bytes.is_empty() {
            self.retained.insert(offset, bytes);
        }
    }

    fn apply_reset(&mut self, retention: ResetRetention) {
        debug_assert!(retention.reliable_size <= retention.final_size);
        debug_assert!(retention.final_size <= self.written_end);
        self.visibility.fix_final_size(retention.final_size);

        // Data at and beyond the reliable size loses its eligibility for
        // sending; the entry straddling the reliable size is sliced.
        let reliable_size = retention.reliable_size;
        drop(self.retained.split_off(&reliable_size));
        if let Some((&offset, bytes)) = self.retained.range_mut(..reliable_size).next_back() {
            let kept = reliable_size.get() - offset.get();
            if let Ok(kept) = usize::try_from(kept)
                && kept < bytes.len()
            {
                bytes.truncate(kept);
            }
        }
        self.retention = Some(retention);
    }

    fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        end: ExposedEnd,
        connection: &mut ConnectionSendFlowController,
    ) -> Result<VarInt, ExposeUsageError> {
        self.visibility
            .expose_usage_through(usage_end, end, self.written_end, connection)
    }

    fn select(&mut self, constraints: SelectionConstraints) -> Selection {
        match constraints {}
    }

    fn on_acknowledged(&mut self, receipt: TransmissionReceipt) {
        match receipt {}
    }

    fn on_lost(&mut self, receipt: TransmissionReceipt) {
        match receipt {}
    }
}
