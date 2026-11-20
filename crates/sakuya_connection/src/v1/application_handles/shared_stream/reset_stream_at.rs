//! The capabilities through the shared connection with the reliable stream
//! reset extension: a writer resets at a reliable size through the stream
//! set, whatever it is.

use core::borrow::Borrow;

use frunk_core::HList;
use sakuya_stream::reset_stream_at::send;
use sakuya_wire::{parts::Selector, v1::application_error::ApplicationErrorCode, var_int::VarInt};

use super::{HeldSetTakes, SharedStreamSend};
use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    reset_stream_at::{ResetAtError, ResetStreamAtSet, StreamResetAt},
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::{GetAt, TakeEach},
    v1::{
        Choices, CloseCauseOf, SendParametersOf, StreamSetFamilyOf,
        application_handles::{
            connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf},
            credential::{CredentialPointer, HandleCredential},
        },
        send::SendTypes,
        send_planning::{
            ComponentPublishing, HostSendStrategyTypes, PublisherOf, StrategyPublisherFor,
        },
        streams::{
            StreamsOf,
            resets::{StreamResetsOf, StreamResetsOfParts},
            send::StreamIntent,
        },
    },
};

/// A writer through the shared connection resets at a reliable size
/// through the stream set, whatever it is
/// ([`ResetStreamAtSet::reset_at`]).
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I> StreamResetAt
    for SharedStreamSend<T, L, S, (Ie, Ic, Ir, Is, In, I), C>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer + Borrow<HandleCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: ResetStreamAtSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        >,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<CloseCauseOf<T, L>>> {
        self.with_held(|set, publish, held| {
            set.reset_at::<I, _>(publish, held, code, reliable_size)
        })
        .unwrap_or_else(|ended| Err(send::ResetAtError::from(ended).into()))
    }
}
