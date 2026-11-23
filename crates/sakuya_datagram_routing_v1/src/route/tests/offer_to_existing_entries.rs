//! Offering reflowed work to the existing entries only, before a check that
//! is meant for a datagram no entry takes

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::support::{Domain, Judging, Recorder, cid, initial, link, local_end};

#[test]
fn work_is_given_back_when_no_entry_exists() {
    let mut domain = Domain::new(&[8]);
    domain.route(initial(&cid(1), &cid(9)), &link(&local_end()));
    let work = domain.next_work().unwrap();
    let work = domain
        .router
        .offer_to_existing_entries(work)
        .expect("no entry takes it");
    assert_eq!(work.offered_len(), 0, "the history is as it was");
    assert_eq!(
        &work.datagram().payload()[..],
        &initial(&cid(1), &cid(9))[..]
    );
    // Nothing was prepared or published on the way.
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 0);
    assert_eq!(domain.factory.accepted_count(), 0);
    assert_eq!(domain.index().key_counts(), (0, 0));

    // The work resumes as it would have.
    domain.router.resume(work);
    assert_eq!(domain.factory.accepted_count(), 1);
}

/// Inputs A and B both find nothing in their first round. A is resumed and
/// publishes a receiver; B, offered to the existing entries only, goes to it
/// without anything prepared for B.
fn second_offered_to_the_first_receiver(judging: Judging) -> (Domain, Arc<Recorder>) {
    let mut domain = Domain::new(&[8]);
    *domain.factory.shared().judging.lock().unwrap() = judging;
    let end = local_end();
    domain.route(initial(&cid(1), &cid(10)), &link(&end));
    domain.route(initial(&cid(1), &cid(11)), &link(&end));
    let first = domain.next_work().unwrap();
    let second = domain.next_work().unwrap();
    domain.router.resume(first);
    let published = Arc::clone(&domain.factory.shared().accepted.lock().unwrap()[0].deliverer);
    assert!(domain.router.offer_to_existing_entries(second).is_none());
    assert_eq!(published.delivery_count(), 1);
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 1);
    assert_eq!(domain.factory.accepted_count(), 1);
    (domain, published)
}

#[test]
fn work_goes_to_a_receiver_published_after_it_was_handed_off() {
    let (mut domain, published) = second_offered_to_the_first_receiver(Judging::Accept);
    let owned = published.settle();
    assert_eq!(owned.len(), 1);
    assert_eq!(&owned[0].payload()[..], &initial(&cid(1), &cid(11))[..]);
    assert_eq!(domain.drain(), 0);
}

#[test]
fn work_every_existing_entry_leaves_comes_back_and_is_not_offered_again() {
    let (mut domain, published) = second_offered_to_the_first_receiver(Judging::Reject);
    assert!(published.settle().is_empty());
    let work = domain.next_work().expect("B reflows again");
    assert_eq!(work.offered_len(), 1);
    let work = domain
        .router
        .offer_to_existing_entries(work)
        .expect("the receiver that left it is not offered it again");
    assert_eq!(published.delivery_count(), 0);
    domain.router.resume(work);
    assert_eq!(domain.factory.accepted_count(), 2);
}

#[test]
fn zero_length_work_goes_to_a_receiver_of_its_local_end() {
    let mut domain = Domain::new(&[0]);
    let end = local_end();
    domain.route(initial(&[], &cid(10)), &link(&end));
    domain.route(initial(&[], &cid(11)), &link(&end));
    let first = domain.next_work().unwrap();
    let second = domain.next_work().unwrap();
    domain.router.resume(first);
    let published = Arc::clone(&domain.factory.shared().accepted.lock().unwrap()[0].deliverer);
    assert!(domain.router.offer_to_existing_entries(second).is_none());
    assert_eq!(published.delivery_count(), 1);
}
