//! Properties of sakuya's transport parameter reader and writer on any
//! input: no panic, one error code, a writer that reproduces what was read,
//! and the parts of a parameter list changing only the parameters they define.
use core::marker::PhantomData;
use proptest::prelude::*;
use sakuya_wire::{
    parameters::{UnknownParameter, codec::ReadParametersError},
    v1::{
        role::Role,
        transport_error::TransportErrorCode,
        transport_parameters::codec::{
            read_remembered_transport_parameters, read_transport_parameters,
            write_transport_parameters,
        },
    },
    var_int::VarInt,
};
use wire_differential::{
    cases,
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

proptest! {
    #![proptest_config(cases::config(20_000))]

    /// A failure is TRANSPORT_PARAMETER_ERROR and says something; a success
    /// reads the whole input.
    #[test]
    fn parameters_read_any_input(bytes in parameters(), sender in role()) {
        let mut source = bytes.as_slice();
        let direct = read_transport_parameters(&mut source, sender, PhantomData::<Parts>);
        match &direct {
            Ok(_) => prop_assert!(source.is_empty()),
            Err(error) => {
                prop_assert_eq!(error.transport_error_code(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
                prop_assert!(!error.to_string().is_empty());
            }
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

    /// A buffer with exactly the room the parameters take receives the
    /// bytes a growing buffer gets.
    #[test]
    fn parameters_write_to_a_buffer_of_their_size(bytes in parameters(), sender in role()) {
        let Ok(parameters) = sakuya::read(&bytes, sender) else { return Ok(()) };
        let written = sakuya::write(parameters.clone(), sender);
        let mut storage = vec![0u8; written.len()];
        write_transport_parameters(&mut storage.as_mut_slice(), parameters, sender).unwrap();
        prop_assert_eq!(&storage, &written);
    }

    /// The parameters remembered for 0-RTT are those a server sent, less
    /// the seven of RFC 9000 7.4.1 a client must not remember and the
    /// unknown ones; storing max_datagram_frame_size is optional (RFC 9221
    /// 3) and kept, storing reset_stream_at mandatory (draft 3).
    #[test]
    fn remembered_parameters_keep_the_remembered_slots(bytes in parameters()) {
        let mut source = bytes.as_slice();
        let remembered = read_remembered_transport_parameters(&mut source, PhantomData::<Parts>);
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
