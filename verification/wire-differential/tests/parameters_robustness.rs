//! Properties of sakuya's transport parameter reader and writer on any
//! input: no panic, one error code, the same results on every kind of
//! source and sink, a writer that reproduces what was read, and the parts
//! of a parameter list changing only the parameters they define.
use core::marker::PhantomData;
use nitori_io::{bridge::Std, calls::WriteAllError};
use proptest::{prelude::*, sample::Index};
use sakuya_wire::{
    parameters::{UnknownParameter, codec::ReadParametersError},
    v1::{
        role::Role,
        transport_error::TransportErrorCode,
        transport_parameters::codec::{
            ReadRememberedTransportParametersHostExt as _, ReadTransportParametersHostExt as _,
            WriteTransportParametersError, WriteTransportParametersHostExt as _,
        },
    },
    var_int::VarInt,
};
use wire_differential::{
    cases,
    hosts::{Failing, OneByte, SourceFailed, Waiting, WaitingSink, run},
    parameters::{
        MAX_DATAGRAM_FRAME_SIZE, RESET_STREAM_AT, encode, entries,
        generate::parameters,
        is_canonical,
        sakuya::{self, Parts, V1},
    },
    sakuya_model,
    tally::{self, hex},
};

fn role() -> impl Strategy<Value = Role> {
    prop_oneof![Just(Role::Client), Just(Role::Server)]
}

/// The receiver's error of a failure, if it came from the receiver.
fn host_error<E, A, C>(error: &ReadParametersError<E, A, C>) -> Option<&E> {
    match error {
        ReadParametersError::Id { source } | ReadParametersError::Length { source, .. } => {
            source.host_error()
        }
        ReadParametersError::Value { source, .. } => source.host_error(),
        _ => None,
    }
}

proptest! {
    #![proptest_config(cases::config(20_000))]

    /// A failure is TRANSPORT_PARAMETER_ERROR and says something; a success
    /// reads the whole input. A source that waits before every byte gives
    /// the same result as the byte slice.
    #[test]
    fn parameters_read_any_input(bytes in parameters(), sender in role()) {
        let mut source = bytes.as_slice();
        let direct = source.sync_read_transport_parameters_unpin(sender, PhantomData::<Parts>);
        match &direct {
            Ok(_) => prop_assert!(source.is_empty()),
            Err(error) => {
                prop_assert_eq!(error.transport_error_code(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
                prop_assert!(!error.to_string().is_empty());
            }
        }
        let mut waiting = Waiting::new(&bytes);
        let waited = run(waiting.read_transport_parameters_unpin(sender, PhantomData::<Parts>));
        prop_assert_eq!(format!("{direct:?}"), format!("{waited:?}"), "{}", hex(&bytes));
    }

    /// A source that fails partway reports its own failure, or a failure
    /// of the content before that point, never an incomplete input.
    #[test]
    fn failing_sources_report_their_failure(bytes in parameters(), sender in role(), limit in any::<Index>()) {
        if bytes.is_empty() {
            return Ok(());
        }
        let limit = limit.index(bytes.len());
        let mut failing = Failing::new(&bytes, limit);
        let error = run(failing.read_transport_parameters_unpin(sender, PhantomData::<Parts>))
            .expect_err("the source fails before its end");
        prop_assert!(!error.is_incomplete(), "{} at {}: {}", hex(&bytes), limit, error);
        let mut prefix = &bytes[..limit];
        let before = prefix.sync_read_transport_parameters_unpin(sender, PhantomData::<Parts>);
        if host_error(&error) == Some(&SourceFailed) {
            // The bytes before the failure are a sequence or end within a
            // parameter.
            prop_assert!(before.as_ref().map_or_else(|e| e.is_incomplete(), |_| true), "{}", hex(&bytes));
        } else {
            let whole = sakuya::read(&bytes, sender).expect_err("the content fails");
            prop_assert_eq!(format!("{error:?}"), format!("{whole:?}"), "{}", hex(&bytes));
        }
    }

    /// Every proper prefix of an accepted input that ends between two
    /// parameters is accepted; every other prefix is incomplete.
    #[test]
    fn truncated_parameters_fail_cleanly(bytes in parameters(), sender in role()) {
        if sakuya::read(&bytes, sender).is_err() {
            return Ok(());
        }
        let list = entries(&bytes).expect("an accepted input is a sequence");
        let ends: Vec<usize> = (0..=list.len()).map(|count| encode(&list[..count]).len()).collect();
        for cut in 0..bytes.len() {
            let result = sakuya::read(&bytes[..cut], sender);
            if ends.contains(&cut) {
                prop_assert!(result.is_ok(), "cut {} of {}", cut, hex(&bytes));
            } else {
                let error = result.expect_err("a cut within a parameter");
                prop_assert!(error.is_incomplete(), "cut {} of {}: {}", cut, hex(&bytes), error);
            }
        }
    }

    /// What sakuya writes for an accepted input is `encoded_len` bytes,
    /// passes `validate`, reads back to the same parameters, the unknown
    /// ones in the same order with the same values, and is written again
    /// byte for byte. An input in the order and the shortest encodings
    /// sakuya writes is written back byte for byte.
    #[test]
    fn parameters_rewrite_stably(bytes in parameters(), sender in role()) {
        let Ok(parameters) = sakuya::read(&bytes, sender) else { return Ok(()) };
        prop_assert!(parameters.validate(sender).is_ok());
        let written = sakuya::write(parameters.clone(), sender);
        let again = sakuya::read(&written, sender).expect("what sakuya writes it reads");
        prop_assert_eq!(&again, &parameters, "{}", hex(&bytes));
        prop_assert_eq!(&sakuya::write(again, sender), &written, "{}", hex(&bytes));
        prop_assert!(is_canonical(&written), "{}", hex(&written));
        if is_canonical(&bytes) {
            prop_assert_eq!(&written, &bytes);
            tally::agree("parameters/canonical");
        }
    }

    /// Sinks that wait or take one byte at a time receive the same bytes,
    /// and a sink that fills up stops the writer with the bytes it took.
    #[test]
    fn parameters_write_to_any_sink(bytes in parameters(), sender in role(), room in any::<Index>()) {
        let Ok(parameters) = sakuya::read(&bytes, sender) else { return Ok(()) };
        let written = sakuya::write(parameters.clone(), sender);

        let mut waiting = WaitingSink::default();
        run(waiting.write_transport_parameters_unpin(parameters.clone(), sender)).unwrap();
        prop_assert_eq!(&waiting.written, &written);

        let mut one_byte = Std::new(OneByte::default());
        one_byte.sync_write_transport_parameters_unpin(parameters.clone(), sender).unwrap();
        prop_assert_eq!(&one_byte.get_ref().0, &written);

        if written.is_empty() {
            return Ok(());
        }
        let room = room.index(written.len());
        let mut storage = vec![0u8; room];
        let mut full = storage.as_mut_slice();
        match full.sync_write_transport_parameters_unpin(parameters, sender) {
            Err(WriteTransportParametersError::Write { source: WriteAllError::WriteZero { source } }) => {
                prop_assert_eq!(source.completed, room);
            }
            other => prop_assert!(false, "{:?}", other),
        }
        prop_assert_eq!(&storage[..], &written[..room]);
    }

    /// The parameters remembered for 0-RTT are those a server sent, less
    /// the seven of RFC 9000 7.4.1 a client must not remember and the
    /// unknown ones; storing max_datagram_frame_size is optional (RFC 9221
    /// 3) and kept, storing reset_stream_at mandatory (draft 3).
    #[test]
    fn remembered_parameters_keep_the_remembered_slots(bytes in parameters()) {
        let mut source = bytes.as_slice();
        let remembered = source.sync_read_remembered_transport_parameters_unpin(PhantomData::<Parts>);
        match (remembered, sakuya::read(&bytes, Role::Server)) {
            (Ok(remembered), Ok(mut expected)) => {
                sakuya::forget_for_zero_rtt(&mut expected);
                prop_assert_eq!(remembered, expected.known, "{}", hex(&bytes));
            }
            (Err(a), Err(b)) => prop_assert_eq!(format!("{a:?}"), format!("{b:?}")),
            (a, b) => prop_assert!(false, "{:?} {:?} on {}", a, b, hex(&bytes)),
        }
    }

    /// Without the extension parts, their parameters are unknown and kept
    /// with their values in place; every other parameter reads the same.
    #[test]
    fn extension_parameters_without_their_parts_are_unknown(bytes in parameters(), sender in role()) {
        let extensions = [MAX_DATAGRAM_FRAME_SIZE, RESET_STREAM_AT];
        let is_extension = |id: VarInt| extensions.contains(&id.get());
        let all = sakuya::read(&bytes, sender);
        let v1 = sakuya::read_with::<V1>(&bytes, sender);
        match (&all, &v1) {
            (Ok(all), Ok(v1)) => {
                let without_datagram = |model: wire_differential::parameters::Params| {
                    wire_differential::parameters::Params { max_datagram_frame_size: 0, ..model }
                };
                prop_assert_eq!(sakuya_model!(v1, 0), without_datagram(sakuya::model(all)));
                let others: Vec<_> = v1.unknown.iter().filter(|p| !is_extension(p.id)).copied().collect();
                prop_assert_eq!(&others, &all.unknown);
                let list = entries(&bytes).unwrap();
                let kept: Vec<_> = v1.unknown.iter().filter(|p| is_extension(p.id)).copied().collect();
                let expected: Vec<_> = list
                    .iter()
                    .filter(|entry| extensions.contains(&entry.id))
                    .map(|entry| UnknownParameter::new(VarInt::try_from(entry.id).unwrap(), entry.value.as_slice()))
                    .collect();
                prop_assert_eq!(kept, expected);
            }
            // The extension parameter is a duplicate or has an invalid
            // value; without its part it is unknown.
            (
                Err(error @ (ReadParametersError::Duplicate { .. } | ReadParametersError::InvalidValue { .. })),
                _,
            ) if error.id().is_some_and(is_extension) => {}
            (Err(a), Err(b)) => {
                prop_assert_eq!(a.id(), b.id());
                prop_assert_eq!(a.to_string(), b.to_string());
                prop_assert_eq!(a.is_incomplete(), b.is_incomplete());
            }
            (a, b) => prop_assert!(false, "{:?} {:?} on {}", a, b, hex(&bytes)),
        }
    }
}

#[test]
fn zz_report() {
    tally::report("transport parameters, sakuya alone");
}
