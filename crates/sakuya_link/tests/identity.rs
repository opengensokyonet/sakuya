use sakuya_link::LinkId;
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    hash::{BuildHasher, RandomState},
    sync::Barrier,
    thread,
};

struct UdpLink;
struct TestLink;
trait Marker {}

type Id = LinkId<u16, u16>;

const _: () = {
    const fn shared<T: Send + Sync>() {}
    shared::<Id>();
};

#[test]
fn allocations_differ() {
    let link = Id::new::<UdpLink>(1, 2);
    assert_ne!(link, Id::new::<UdpLink>(1, 2));
    assert_eq!(link, link.clone());
}

#[test]
fn any_type_parameter_allocates() {
    let links = [
        Id::new::<UdpLink>(1, 2),
        Id::new::<UdpLink>(1, 2),
        Id::new::<TestLink>(1, 2),
        Id::new::<str>(1, 2),
        Id::new::<[u8]>(1, 2),
        Id::new::<dyn Marker>(1, 2),
    ];
    assert_eq!(links.iter().collect::<HashSet<_>>().len(), links.len());
}

#[test]
fn ends_are_kept_and_cloned() {
    let link = LinkId::new::<UdpLink>(String::from("local"), String::from("peer"));
    let cloned = link.clone();
    assert_eq!(cloned.local, "local");
    assert_eq!(cloned.peer, "peer");
    assert_eq!(link, cloned);
}

#[test]
fn mapped_ends_keep_the_identity() {
    let first = Id::new::<UdpLink>(1, 2);
    let second = Id::new::<UdpLink>(1, 2);
    let into_sum = |id: Id| id.map(Ok::<u16, ()>, Err::<(), u16>);
    let (first_sum, second_sum) = (into_sum(first.clone()), into_sum(second.clone()));
    assert_eq!(first_sum.local, Ok(1));
    assert_eq!(first_sum.peer, Err(2));
    assert_ne!(first_sum, second_sum);
    assert_eq!(first_sum, into_sum(first.clone()));
    assert_eq!(first_sum.cmp(&second_sum), first.cmp(&second));
}

fn assert_consistent<T: Ord + std::hash::Hash>(ids: &[T]) {
    let hasher = RandomState::new();
    for a in ids {
        for b in ids {
            let equal = a == b;
            assert_eq!(equal, a.cmp(b) == Ordering::Equal);
            assert_eq!(a.partial_cmp(b), Some(a.cmp(b)));
            assert_eq!(a.cmp(b), b.cmp(a).reverse());
            if equal {
                assert_eq!(hasher.hash_one(a), hasher.hash_one(b));
            }
            for c in ids {
                if a < b && b < c {
                    assert!(a < c);
                }
            }
        }
    }
}

#[test]
fn eq_hash_and_ord_agree() {
    let mut links = Vec::new();
    for end in 0..8 {
        links.push(Id::new::<UdpLink>(end, 0));
        links.push(Id::new::<TestLink>(0, 0));
    }
    links.extend(links.clone());
    assert_consistent(&links);
    assert_eq!(links.iter().collect::<HashSet<_>>().len(), 16);
    assert_eq!(links.iter().collect::<BTreeSet<_>>().len(), 16);
}

#[test]
fn concurrent_allocations_differ() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 2_000;
    let start = Barrier::new(THREADS);
    let links: Vec<Vec<Id>> = thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    (0..PER_THREAD).map(|_| Id::new::<UdpLink>(1, 2)).collect()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    });
    assert_eq!(
        links.iter().flatten().collect::<HashSet<_>>().len(),
        THREADS * PER_THREAD
    );
}

#[test]
fn debug_shows_only_the_identity() {
    let link = LinkId::new::<UdpLink>("secret local", "secret peer");
    let link = format!("{link:?}");
    assert!(link.starts_with("LinkId("), "{link}");
    assert!(link.contains("UniqueId("), "{link}");
    assert!(!link.contains("secret"), "{link}");
}
