//! Reading a server's first flight takes the datagrams of one attempt only:
//! those over the link of the first datagram read, from the client's
//! Source Connection ID. Another counts toward nothing, so that what came
//! from another address raises no anti-amplification limit (RFC 9000
//! §8.1).

use super::*;

#[test]
fn reading_the_first_flight_drops_the_datagrams_of_another_link_or_source() {
    reset();
    common::strategy::plan_nothing();
    let first = link();
    let other = link();
    let mut receiver = test_receiver();
    let hello = client_hello();
    let one = padded(
        &[],
        |payload| long_packet(INITIAL, 0, payload),
        &crypto_at(0, &hello[..20]),
    );
    // the same connection IDs over another link, and the same link with
    // another Source Connection ID
    let elsewhere = padded(&[], |payload| long_packet(INITIAL, 1, payload), &ping());
    let other_source = padded(
        &[],
        |payload| client_long_packet(INITIAL, 2, payload),
        &ping(),
    );
    let two = padded(
        &[],
        |payload| long_packet(INITIAL, 3, payload),
        &crypto_at(20, &hello[20..]),
    );
    let size = one.len() + two.len();
    deliver(one, &first, ms(1));
    deliver(elsewhere, &other, ms(2));
    deliver(other_source, &first, ms(3));
    deliver(two, &first, ms(4));
    let (state, result) = read_first(&mut receiver);
    assert_eq!(result, Ok(()));
    assert!(state.first_client_hello().is_some());
    assert_eq!(state.received_bytes(), size);
}
