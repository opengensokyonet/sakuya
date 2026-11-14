//! When this side initiates a 1-RTT key update, and the rules of the peer's
//! key updates it enforces (RFC 9001 §6).
//!
//! This side initiates a key update only as the packets sealed with the
//! current sending generation near the confidentiality limit of their AEAD
//! (§6.6): from three quarters of it on. ChaCha20-Poly1305, whose limit
//! lies beyond the number of packets, never updates. An update may be
//! initiated once the handshake is confirmed and, unless the sending
//! generation is the first, once the peer has acknowledged a packet sealed
//! with it (§6.1); from that acknowledgment three current probe timeouts
//! are waited, the largest among the link paths (§6.5). The wait is not
//! kept where the keys may seal only one more packet within the limit,
//! which is kept for the packet that closes the connection (§6.6); an
//! update §6.1 still forbids there closes the connection with
//! AEAD_LIMIT_REACHED.
//!
//! The sending call of a link path makes the check before each filling
//! ([`prepare_one_rtt_packets`]), which also notes the number of the next
//! packet of the Application Data space as sent with the generation the
//! 1-RTT packets from it on are sealed with, for the logical path; the
//! filling stops at a 1-RTT packet that would leave only the closing one,
//! and the next filling checks again. An ACK
//! frame of the Application Data space whose Largest Acknowledged is at
//! least the lowest number the logical path sent with the current sending
//! generation confirms that generation ([`ack_received`]).
//!
//! Two rules of §6.2 that an endpoint may enforce close the connection with
//! KEY_UPDATE_ERROR ([`KeyUpdateError`]): the peer updates a second time
//! before this side has sent, with the keys of the first update, an ACK
//! frame for the packet that made them current; and an ACK frame in a
//! packet protected with older keys acknowledges a packet sealed with newer
//! ones. The rule of §6.4 is never met, as the
//! [`key_phase`](super::key_phase) module says.

use core::time::Duration;

use sakuya_packet_protection::backend::CryptoBackend;
use sakuya_wire::v1::packet_number::PacketNumber;
use snafu::Snafu;

use super::{
    aead_usage::{AeadLimitReachedError, AeadUsage},
    confirmation::HandshakeConfirmation,
    key_phase::KeyPhaseNumbers,
    keys::{OneRttKeys, Promotion},
};
use crate::{
    clock::CheckedAdd,
    take::{GetAt, Lineage},
};

/// The peer broke a rule of 1-RTT key updates that RFC 9001 §6.2 lets an
/// endpoint enforce.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum KeyUpdateError {
    /// The peer updated its keys a second time before this side sent, with
    /// the keys of the first update, an ACK frame for the packet that made
    /// them current: it did not wait for its update to be confirmed.
    #[snafu(display(
        "packet {number} updates the keys again before packet {trigger}, \
         which updated them, was acknowledged"
    ))]
    ConsecutiveUpdates {
        /// The packet that made the current receiving generation current.
        trigger: PacketNumber,
        /// The packet that updated the keys again.
        number: PacketNumber,
    },
    /// An ACK frame in a packet protected with older keys acknowledges a
    /// packet this side sealed with newer ones: the peer received a packet
    /// of a key update and did not update its own keys.
    #[snafu(display(
        "an ACK frame under older keys acknowledges packet {largest}, \
         and the newer keys seal every packet from {lowest_newer} on"
    ))]
    AckWithOldKeys {
        /// The frame's Largest Acknowledged.
        largest: PacketNumber,
        /// The lowest packet number the logical path sent with newer keys
        /// than those of the packet that carried the frame.
        lowest_newer: PacketNumber,
    },
}

/// Before 1-RTT packets numbered from `number` on are started on a logical
/// path at `now`: initiate a key update when one is due and may be
/// initiated, as the [module documentation](self) says, and note `number`
/// as sent with the sending generation the packets are sealed with. No
/// packet of the space numbered from `number` on is sealed with older keys
/// (RFC 9001 §6.4).
///
/// The lineage holds the connection's 1-RTT keys at `Io`, its AEAD usage
/// at `Iu` and whether the handshake is confirmed at `Ih`, and the logical
/// path's key phase numbers at `Ikp`. `probe_timeout` gives the current
/// probe timeout, the largest among the link paths; it is asked only when
/// an update is due. The keys and the usage are taken mutably only to
/// initiate, the numbers only for the first packet of a sending generation.
///
/// # Errors
///
/// [`AeadLimitReachedError::ConfidentialityLimitReached`]: the current
/// sending generation may seal only the closing packet within its AEAD's
/// limit, and no key update may be initiated. Nothing is changed then.
pub(crate) fn prepare_one_rtt_packets<B, I, V, F, Io, Iu, Ih, Ikp>(
    lineage: &mut Lineage<'_, V>,
    number: PacketNumber,
    now: I,
    probe_timeout: F,
) -> Result<(), AeadLimitReachedError>
where
    B: CryptoBackend,
    I: Copy + Ord + CheckedAdd<Duration>,
    V: GetAt<OneRttKeys<B, I>, Io>
        + GetAt<AeadUsage, Iu>
        + GetAt<HandshakeConfirmation, Ih>
        + GetAt<KeyPhaseNumbers, Ikp>,
    F: FnOnce() -> Duration,
{
    let initiate = update_now(
        lineage.get::<OneRttKeys<B, I>, Io>(),
        lineage.get::<AeadUsage, Iu>(),
        *lineage.get::<HandshakeConfirmation, Ih>(),
        now,
        probe_timeout,
    )?;
    if initiate {
        lineage.get_mut::<OneRttKeys<B, I>, Io>().initiate_update();
        lineage.get_mut::<AeadUsage, Iu>().send_keys_updated();
    }
    let Some(generation) = lineage
        .get::<OneRttKeys<B, I>, Io>()
        .send()
        .map(|keys| keys.generation().generation())
    else {
        return Ok(());
    };
    if lineage
        .get::<KeyPhaseNumbers, Ikp>()
        .lowest_sent(generation)
        .is_none()
    {
        lineage
            .get_mut::<KeyPhaseNumbers, Ikp>()
            .sent(generation, number);
    }
    Ok(())
}

/// Whether a key update may be initiated, as the keys stand.
enum UpdatePermission<I> {
    /// Not yet: the handshake is not confirmed, the keys only send, or the
    /// peer has acknowledged no packet of the current sending generation.
    Forbidden,
    /// At once: the sending generation is the first.
    Now,
    /// Three probe timeouts after the peer acknowledged a packet of the
    /// current sending generation at the instant.
    AfterAcknowledgment(I),
}

/// Whether to initiate a key update before the next 1-RTT packet is sealed
/// with `keys`, whose use is counted in `usage`, at `now`.
fn update_now<B, I, F>(
    keys: &OneRttKeys<B, I>,
    usage: &AeadUsage,
    confirmation: HandshakeConfirmation,
    now: I,
    probe_timeout: F,
) -> Result<bool, AeadLimitReachedError>
where
    B: CryptoBackend,
    I: Copy + Ord + CheckedAdd<Duration>,
    F: FnOnce() -> Duration,
{
    let Some(send) = keys.send() else {
        return Ok(false);
    };
    let aead = send.generation().aead();
    if !usage.update_due(aead) {
        return Ok(false);
    }
    let permission = match keys {
        OneRttKeys::Live(keys) if confirmation == HandshakeConfirmation::Confirmed => {
            if send.generation().generation() == 0 {
                UpdatePermission::Now
            } else {
                keys.send_confirmed_at().map_or(
                    UpdatePermission::Forbidden,
                    UpdatePermission::AfterAcknowledgment,
                )
            }
        }
        _ => UpdatePermission::Forbidden,
    };
    if usage.only_closing_packet_left(aead) {
        return match permission {
            UpdatePermission::Forbidden => Err(AeadLimitReachedError::ConfidentialityLimitReached),
            UpdatePermission::Now | UpdatePermission::AfterAcknowledgment(_) => Ok(true),
        };
    }
    Ok(match permission {
        UpdatePermission::Forbidden => false,
        UpdatePermission::Now => true,
        // a wait past what the instant type represents never ends: the
        // closing packet's reserve is not waited for
        UpdatePermission::AfterAcknowledgment(at) => at
            .checked_add(probe_timeout().saturating_mul(3))
            .is_some_and(|end| now >= end),
    })
}

/// An ACK frame whose Largest Acknowledged is `largest` arrived at `at`, in
/// the Application Data space of a logical path, in a packet opened with
/// the 1-RTT key generation `opened_with`: check it against the newer keys
/// this side sealed with, and let it confirm the current sending
/// generation, as the [module documentation](self) says.
///
/// The lineage holds the connection's 1-RTT keys at `Io` and the logical
/// path's key phase numbers at `Ikp`. The keys are taken mutably only when
/// the frame confirms the sending generation.
///
/// # Errors
///
/// [`KeyUpdateError::AckWithOldKeys`]: the frame acknowledges a packet
/// sealed with newer keys than `opened_with`. Nothing is confirmed then.
pub(crate) fn ack_received<B, I, V, Io, Ikp>(
    lineage: &mut Lineage<'_, V>,
    opened_with: u64,
    largest: PacketNumber,
    at: I,
) -> Result<(), KeyUpdateError>
where
    B: CryptoBackend,
    I: Copy,
    V: GetAt<OneRttKeys<B, I>, Io> + GetAt<KeyPhaseNumbers, Ikp>,
{
    let numbers = *lineage.get::<KeyPhaseNumbers, Ikp>();
    if let Some(lowest_newer) = numbers.lowest_sent_after(opened_with)
        && largest >= lowest_newer
    {
        return AckWithOldKeysSnafu {
            largest,
            lowest_newer,
        }
        .fail();
    }
    let confirms = match lineage.get::<OneRttKeys<B, I>, Io>() {
        OneRttKeys::Live(keys) if keys.send_confirmed_at().is_none() => numbers
            .lowest_sent(keys.send().generation().generation())
            .is_some_and(|lowest| largest >= lowest),
        _ => false,
    };
    if confirms && let OneRttKeys::Live(keys) = lineage.get_mut::<OneRttKeys<B, I>, Io>() {
        keys.send_confirmed(at);
    }
    Ok(())
}

/// The packet numbered `number` was opened with the next receiving
/// generation and made `promotion`: check, against the logical path's
/// `numbers` from before the promotion, that the peer did not update again
/// before its last update was confirmed.
///
/// Only an update of the peer's is checked: when this side initiated, its
/// sending generation was ahead, and the promotion is the peer's answer.
/// When another logical path promoted the generation before, this one
/// knows no trigger and checks nothing.
///
/// # Errors
///
/// [`KeyUpdateError::ConsecutiveUpdates`]: this side has sent no ACK frame
/// for the packet that made the previous generation current on the
/// logical path.
pub(crate) fn check_peer_update(
    numbers: &KeyPhaseNumbers,
    promotion: Promotion,
    number: PacketNumber,
) -> Result<(), KeyUpdateError> {
    if !promotion.send_updated {
        return Ok(());
    }
    // invariant: a promoted generation follows the one it replaced
    let replaced = promotion.generation - 1;
    match numbers.trigger(replaced) {
        Some((trigger, false)) => ConsecutiveUpdatesSnafu { trigger, number }.fail(),
        Some((_, true)) | None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
