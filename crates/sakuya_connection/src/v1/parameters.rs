//! Transport parameters in a connection: the peer's, and each part's own,
//! the error of a failure of reading the peer's, and the checks of version
//! 1 on the connection IDs the peer's state (RFC 9000 §7.3).

use core::convert::Infallible;

use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::codec::ReadParametersError,
    parts::{CoprodInjector, PartsError, Selector},
    v1::transport_parameters::{
        codec::ReadTransportParametersError,
        connection_id::{
            InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
        },
    },
};
use snafu::{Snafu, ensure};

use super::{error::ConnectionError, receive::v1_error};
use crate::error::{ConnectionErrorOf, TransportParameterValueErrorsOf};

/// The peer's transport parameters: one component of the connection node,
/// read by whoever uses them.
///
/// `S` is the slots of the transport parameter types of the parts of the
/// connection. Values are written only after every part has checked its
/// own, so whatever reads them reads checked parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransportParameters<S> {
    /// Not known yet.
    NotYet,
    /// A client that offers 0-RTT: the slots remembered from the earlier
    /// connection, only those whose parameters 0-RTT must remember (RFC
    /// 9000 §7.4.1); they govern 0-RTT packets only.
    Remembered(S),
    /// The parameters the peer sent in this handshake.
    Known(S),
}

impl<S> PeerTransportParameters<S> {
    /// The slots, remembered or known, if there are any.
    pub fn slots(&self) -> Option<&S> {
        match self {
            Self::NotYet => None,
            Self::Remembered(slots) | Self::Known(slots) => Some(slots),
        }
    }

    /// The slots the peer sent in this handshake, once they are known.
    pub fn known(&self) -> Option<&S> {
        match self {
            Self::Known(slots) => Some(slots),
            Self::NotYet | Self::Remembered(_) => None,
        }
    }

    /// Remember the slots of an earlier connection, as a client that offers
    /// 0-RTT does before the peer's parameters are known.
    pub fn remember(&mut self, slots: S) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "remembering parameters over known ones"
        );
        *self = Self::Remembered(slots);
    }

    /// Set the parameters the peer sent in this handshake.
    pub fn set_known(&mut self, slots: S) {
        debug_assert!(
            !matches!(self, Self::Known(_)),
            "the peer's parameters are known twice"
        );
        *self = Self::Known(slots);
    }
}

/// The transport parameters a part sends: one configuration component of
/// that part in the connection node.
///
/// `P` is the part's own transport parameters. They are given when the
/// connection is made and stay as they were sent for the rest of the
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTransportParameters<P> {
    /// As configured; the handshake has not sent them yet, and a server
    /// may still settle them by the application protocol it selects and by
    /// whether it resumes.
    Configured(P),
    /// As sent; they no longer change.
    Sent(P),
}

impl<P> LocalTransportParameters<P> {
    /// The parameters as sent, once they are.
    pub fn sent(&self) -> Option<&P> {
        match self {
            Self::Sent(parameters) => Some(parameters),
            Self::Configured(_) => None,
        }
    }

    /// The parameters as configured, while they are not sent.
    pub fn configured(&self) -> Option<&P> {
        match self {
            Self::Configured(parameters) => Some(parameters),
            Self::Sent(_) => None,
        }
    }

    /// The parameters are sent as `settle` makes them from the configured
    /// ones; they no longer change.
    pub fn send_with(&mut self, settle: impl FnOnce(&P) -> P) {
        match self {
            Self::Configured(configured) => {
                let sent = settle(configured);
                *self = Self::Sent(sent);
            }
            Self::Sent(_) => debug_assert!(false, "transport parameters are sent twice"),
        }
    }
}

/// How the peer's transport parameters, once read, fail the checks of
/// version 1 on the connection IDs: each closes the connection with
/// TRANSPORT_PARAMETER_ERROR (RFC 9000 §7.3).
///
/// Failures of reading them are not here: one of the encoding, or of the
/// value of a parameter of version 1, is
/// [`ConnectionError::ReadTransportParameters`], and one of the value of a
/// parameter of another part is that part's error
/// ([`TransportParameterValueErrorPart`](crate::error::TransportParameterValueErrorPart)).
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum PeerTransportParametersError {
    /// The peer sent no `initial_source_connection_id`.
    #[snafu(display("initial_source_connection_id absent"))]
    InitialSourceConnectionIdAbsent,
    /// The peer's `initial_source_connection_id` is not the Source
    /// Connection ID of the first Initial packet that opened from it.
    #[snafu(display("initial_source_connection_id {received:?} is not the peer's"))]
    InitialSourceConnectionIdMismatch {
        /// The connection ID it states.
        received: ConnectionId,
    },
    /// The server sent no `original_destination_connection_id`.
    #[snafu(display("original_destination_connection_id absent"))]
    OriginalDestinationConnectionIdAbsent,
    /// The server's `original_destination_connection_id` is not the
    /// Destination Connection ID of the client's first Initial packet.
    #[snafu(display("original_destination_connection_id {received:?} is not the client's"))]
    OriginalDestinationConnectionIdMismatch {
        /// The connection ID it states.
        received: ConnectionId,
    },
    /// The server sent a `retry_source_connection_id`, though the client
    /// received no Retry.
    #[snafu(display("retry_source_connection_id {received:?} without a Retry"))]
    RetrySourceConnectionIdWithoutRetry {
        /// The connection ID it states.
        received: ConnectionId,
    },
}

/// The connection's error for the peer's transport parameters that could
/// not be read into the slots of the parts `L`: version 1's for a failure
/// of the encoding as a whole, the error of the part whose type claims the
/// parameter for a value that breaks a rule of the type.
pub(super) fn read_transport_parameters_error<L, Iv>(
    error: ReadTransportParametersError<Infallible, L>,
) -> ConnectionErrorOf<L>
where
    L: TransportParameterValueErrorsOf,
    L::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
{
    let source = match error {
        ReadParametersError::Id { source } => ReadParametersError::Id { source },
        ReadParametersError::Length { id, source } => ReadParametersError::Length { id, source },
        ReadParametersError::Value { id, source } => ReadParametersError::Value { id, source },
        ReadParametersError::Duplicate { source } => ReadParametersError::Duplicate { source },
        ReadParametersError::NotAdmitted { source } => ReadParametersError::NotAdmitted { source },
        ReadParametersError::InvalidValue {
            id,
            source: PartsError(source),
        } => return PartsError(L::value_error(id, source)),
    };
    v1_error::<L, Iv>(ConnectionError::ReadTransportParameters { source })
}

/// Check that the peer's `initial_source_connection_id` among `slots`
/// states `chosen`, the Source Connection ID of the first Initial packet
/// that opened from it; `None` when none opened, which none matches.
pub(super) fn check_initial_source<S, I>(
    slots: &S,
    chosen: Option<ConnectionId>,
) -> Result<(), PeerTransportParametersError>
where
    S: Selector<Option<InitialSourceConnectionId>, I>,
{
    let received = Selector::<Option<InitialSourceConnectionId>, I>::get(slots)
        .ok_or(PeerTransportParametersError::InitialSourceConnectionIdAbsent)?
        .get();
    ensure!(
        Some(received) == chosen,
        InitialSourceConnectionIdMismatchSnafu { received }
    );
    Ok(())
}

/// Check, as a client that received no Retry, that the server's
/// `original_destination_connection_id` among `slots` states `original`,
/// and that it sent no `retry_source_connection_id`.
pub(super) fn check_server_destination<S, Io, Ir>(
    slots: &S,
    original: ConnectionId,
) -> Result<(), PeerTransportParametersError>
where
    S: Selector<Option<OriginalDestinationConnectionId>, Io>
        + Selector<Option<RetrySourceConnectionId>, Ir>,
{
    let received = Selector::<Option<OriginalDestinationConnectionId>, Io>::get(slots)
        .ok_or(PeerTransportParametersError::OriginalDestinationConnectionIdAbsent)?
        .get();
    ensure!(
        received == original,
        OriginalDestinationConnectionIdMismatchSnafu { received }
    );
    if let Some(retry) = Selector::<Option<RetrySourceConnectionId>, Ir>::get(slots) {
        return RetrySourceConnectionIdWithoutRetrySnafu {
            received: retry.get(),
        }
        .fail();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use bytes::Buf;
    use nitori_call::ReceiverAccess;
    use nitori_io::{Write, calls::WriteAllError};
    use sakuya_wire::{
        parameters::{KeyedParameter, ParametersPart, TrailingBytesError, ValueSource},
        parts::{Coprod, Coproduct, HList},
        v1::{
            role::Role,
            transport_error::TransportErrorCode,
            transport_parameters::{
                RememberedForZeroRtt, SentBy, TransportParameterAttributes,
                TransportParameterSpace, TransportParameters,
                codec::ReadTransportParametersHostExt as _, integer::AckDelayExponent,
            },
        },
        var_int::VarInt,
    };

    use super::*;
    use crate::{
        error::{ConnectionErrorPart, TransportParameterValueErrorPart},
        v1::{Part, close::TransportClose},
    };

    fn id(byte: u8) -> ConnectionId {
        ConnectionId::new(&[byte; 8]).unwrap()
    }

    /// The ID of the parameter of the extension of the tests.
    const EXTENSION_ID: u32 = 0x2a;

    /// The parameter of the extension of the tests: its value is empty.
    struct Flag;

    impl KeyedParameter for Flag {
        type Space = TransportParameterSpace;
        type ValueError = TrailingBytesError;

        const ID: VarInt = VarInt::from_u32(EXTENSION_ID);
        const ATTRIBUTES: TransportParameterAttributes = TransportParameterAttributes {
            sent_by: SentBy::Either,
            remembered_for_zero_rtt: RememberedForZeroRtt::Prohibited,
        };

        fn read_value<D: Buf + Unpin>(_: &mut ValueSource<D>) -> Result<Self, TrailingBytesError> {
            Ok(Self)
        }

        fn value_len(&self) -> usize {
            0
        }

        async fn write_value<F, A>(&self, _: &mut A) -> Result<(), WriteAllError<F::Error>>
        where
            F: Write,
            A: ReceiverAccess<Family = F>,
        {
            Ok(())
        }
    }

    /// An extension with a transport parameter of its own, after version 1.
    struct Extension;

    /// The extension's error: the value of its parameter broke the rule of
    /// its type.
    #[derive(Debug)]
    struct ExtensionValueError {
        id: VarInt,
        #[expect(dead_code, reason = "the tests match the ID only")]
        source: PartsError<Coprod![TrailingBytesError]>,
    }

    impl ConnectionErrorPart for Extension {
        type ConnectionError = ExtensionValueError;
    }

    impl ParametersPart<TransportParameterSpace> for Extension {
        type Parameters = HList![Flag];
    }

    impl TransportParameterValueErrorPart<Coprod![TrailingBytesError]> for Extension {
        fn value_error(
            id: VarInt,
            source: PartsError<Coprod![TrailingBytesError]>,
        ) -> ExtensionValueError {
            ExtensionValueError { id, source }
        }
    }

    /// The connection's error for `encoding`, sent by a server, read for
    /// the parts `L`.
    fn read_error<L, Iv>(encoding: &[u8]) -> ConnectionErrorOf<L>
    where
        L: TransportParameterValueErrorsOf,
        L::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
    {
        let mut source = encoding;
        match source.sync_read_transport_parameters_unpin(Role::Server, PhantomData::<L>) {
            Ok(_) => panic!("the transport parameters were read"),
            Err(error) => read_transport_parameters_error::<L, Iv>(error),
        }
    }

    /// The read failure in version 1's error, which closes with
    /// TRANSPORT_PARAMETER_ERROR.
    fn v1_read_failure<Rest>(
        error: PartsError<Coproduct<ConnectionError, Rest>>,
    ) -> ReadTransportParametersError<Infallible> {
        let PartsError(Coproduct::Inl(error)) = error else {
            panic!("not version 1's error");
        };
        assert_eq!(error.code(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
        match error {
            ConnectionError::ReadTransportParameters { source } => source,
            other => panic!("not a read failure: {other:?}"),
        }
    }

    type V1Alone = HList![Part];
    type WithExtension = HList![Part, Extension];

    #[test]
    fn a_read_failure_of_version_1_alone_is_its_error() {
        // max_idle_timeout twice
        let error = read_error::<V1Alone, _>(&[0x01, 0x01, 0x05, 0x01, 0x01, 0x05]);
        assert!(matches!(
            v1_read_failure(error),
            ReadParametersError::Duplicate { source } if source.id() == VarInt::from_u32(0x01)
        ));
        // a Length of 4 with one byte after it
        let error = read_error::<V1Alone, _>(&[0x01, 0x04, 0x05]);
        let failure = v1_read_failure(error);
        assert!(matches!(failure, ReadParametersError::Value { .. }));
        assert!(failure.is_incomplete());
        // ack_delay_exponent 21
        let error = read_error::<V1Alone, _>(&[0x0a, 0x01, 0x15]);
        let failure = v1_read_failure(error);
        assert!(failure.value_error::<AckDelayExponent>().is_some());
    }

    #[test]
    fn the_value_of_another_parts_parameter_is_that_parts_error() {
        let error = read_error::<WithExtension, _>(&[EXTENSION_ID as u8, 0x01, 0x00]);
        assert!(matches!(
            error,
            PartsError(Coproduct::Inr(Coproduct::Inl(ExtensionValueError { id, .. })))
                if id == VarInt::from_u32(EXTENSION_ID)
        ));
        // the value of a parameter of version 1 stays version 1's
        let error = read_error::<WithExtension, _>(&[0x0a, 0x01, 0x15]);
        assert!(
            v1_read_failure(error)
                .value_error::<AckDelayExponent>()
                .is_some()
        );
        // the extension's parameter twice is a failure of the encoding
        let error =
            read_error::<WithExtension, _>(&[EXTENSION_ID as u8, 0x00, EXTENSION_ID as u8, 0x00]);
        assert!(matches!(
            v1_read_failure(error),
            ReadParametersError::Duplicate { source }
                if source.id() == VarInt::from_u32(EXTENSION_ID)
        ));
    }

    #[test]
    fn the_initial_source_connection_id_states_the_peers() {
        let mut parameters = TransportParameters::<&[u8]>::new();
        assert!(matches!(
            check_initial_source::<_, _>(&parameters.known, Some(id(1))),
            Err(PeerTransportParametersError::InitialSourceConnectionIdAbsent)
        ));
        parameters.set(InitialSourceConnectionId::new(id(2)));
        assert!(matches!(
            check_initial_source::<_, _>(&parameters.known, Some(id(1))),
            Err(PeerTransportParametersError::InitialSourceConnectionIdMismatch { received })
                if received == id(2)
        ));
        assert!(matches!(
            check_initial_source::<_, _>(&parameters.known, None),
            Err(PeerTransportParametersError::InitialSourceConnectionIdMismatch { .. })
        ));
        assert!(check_initial_source::<_, _>(&parameters.known, Some(id(2))).is_ok());
    }

    #[test]
    fn a_server_states_the_clients_first_destination_and_no_retry() {
        let mut parameters = TransportParameters::<&[u8]>::new();
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(1)),
            Err(PeerTransportParametersError::OriginalDestinationConnectionIdAbsent)
        ));
        parameters.set(OriginalDestinationConnectionId::new(id(2)));
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(1)),
            Err(PeerTransportParametersError::OriginalDestinationConnectionIdMismatch { received })
                if received == id(2)
        ));
        assert!(check_server_destination::<_, _, _>(&parameters.known, id(2)).is_ok());
        parameters.set(RetrySourceConnectionId::new(id(3)));
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(2)),
            Err(PeerTransportParametersError::RetrySourceConnectionIdWithoutRetry { received })
                if received == id(3)
        ));
    }
}
