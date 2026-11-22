//! What every part of version 1 makes its components from, given once by
//! whoever makes the connection ([`CommonConnectionArgs`]); version 1's
//! arguments of the connection node hold them
//! ([`ConnectionArgs::common`](super::ConnectionArgs::common)), and a
//! component finds them with [`FindArgs`].

use sakuya_wire_v1::{connection_id::ConnectionId, transport_parameters::TransportParameterSlots};

use super::{
    amplification::AntiAmplificationFactor,
    close_request::CloseRequestCell,
    common_choices::{
        ApplicationErrorOf, EventsConfigOf, ResumedParametersPolicyOf, StreamSetConfigOf, V1Choices,
    },
    link::LinkFacts,
};
use crate::{
    component::ArgsOf,
    layer,
    share::{ConnectionArgsOf, FindArgs},
};

/// What every part of version 1 needs to make its components in the
/// connection node, given once by whoever makes the connection.
pub struct CommonConnectionArgs<T: V1Choices, L> {
    /// The Destination Connection ID of the client's first Initial packet,
    /// which the Initial secrets are derived from (RFC 9001 §5.2): the one a
    /// client chose, the one a server found in the first datagrams.
    pub client_dcid: ConnectionId,
    /// The Destination Connection ID of the client's very first Initial
    /// packet when a server sent a Retry before making the connection, and
    /// `client_dcid` is the Source Connection ID of that Retry: the
    /// `original_destination_connection_id` the server sends, with
    /// `client_dcid` as its `retry_source_connection_id` (RFC 9000 §7.3).
    /// `None` without a Retry, and always for a client.
    pub original_destination_connection_id: Option<ConnectionId>,
    /// How many times the bytes received from an address not yet validated
    /// may be sent to it.
    pub anti_amplification: AntiAmplificationFactor,
    /// The transport parameters of version 1 as configured; among them
    /// this side's maximum idle timeout.
    pub transport_parameters: TransportParameterSlots,
    /// What is known about the connection's first logical link.
    pub first_link: LinkFacts,
    /// What decides how version 1's transport parameters go when a server
    /// resumes a connection; a client does not use it.
    pub resumed_parameters_policy: ResumedParametersPolicyOf<T>,
    /// The cell the application's request to close the connection is put
    /// in; the connection node keeps a clone of it, and whoever lets the
    /// application ask keeps another.
    pub close_request: CloseRequestCell<ApplicationErrorOf<T>>,
    /// What the stream set of the established layer is configured with;
    /// the connection node keeps it until the layer is built.
    pub stream_set: StreamSetConfigOf<T>,
    /// What the receiver of the connection's events is made from
    /// ([`CommonHostChoices::Events`](super::common_choices::CommonHostChoices::Events)); its default records nothing for
    /// [`NoEvents`](super::events::NoEvents).
    pub events: EventsConfigOf<T, L>,
}

/// The arguments every part of version 1 makes its components from, among
/// the parts' arguments `args` of the connection node; `I` is where they
/// are, which the compiler infers.
pub fn common_args<T: V1Choices, L, I>(
    args: &mut ArgsOf<T, L, layer::Connection>,
) -> &mut CommonConnectionArgs<T, L>
where
    ConnectionArgsOf<T, L>: FindArgs<CommonConnectionArgs<T, L>, I>,
    L: crate::share::LineagePartList<T>,
{
    args.find_args_mut()
}
