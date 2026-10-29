use sakuya_link::{BindingId, LinkId};
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
    hash::{BuildHasher, RandomState},
    sync::Barrier,
    thread,
};

struct UdpBinding;
struct UdpLink;
struct TestBinding;
struct TestLink;
trait Marker {}

const _: () = {
    const fn shared<T: Send + Sync>() {}
    shared::<BindingId>();
    shared::<LinkId>();
};

#[test]
fn allocations_differ() {
    let binding = BindingId::new::<UdpBinding>();
    assert_ne!(binding, BindingId::new::<UdpBinding>());
    assert_eq!(binding, binding.clone());

    let link = LinkId::new::<UdpLink>(binding.clone());
    assert_ne!(link, LinkId::new::<UdpLink>(binding.clone()));
    assert_eq!(link, link.clone());
}

#[test]
fn any_type_parameter_allocates() {
    let ids = [
        BindingId::new::<UdpBinding>(),
        BindingId::new::<UdpBinding>(),
        BindingId::new::<TestBinding>(),
        BindingId::new::<str>(),
        BindingId::new::<dyn Marker>(),
    ];
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());

    let links = [
        LinkId::new::<UdpLink>(ids[0].clone()),
        LinkId::new::<UdpLink>(ids[0].clone()),
        LinkId::new::<TestLink>(ids[2].clone()),
        LinkId::new::<[u8]>(ids[3].clone()),
    ];
    assert_eq!(links.iter().collect::<HashSet<_>>().len(), links.len());
}

#[test]
fn link_returns_its_source_binding() {
    let first = BindingId::new::<UdpBinding>();
    let second = BindingId::new::<TestBinding>();
    let from_first = LinkId::new::<UdpLink>(first.clone());
    let from_second = LinkId::new::<UdpLink>(second.clone());
    let cloned = from_first.clone();

    assert_eq!(from_first.binding_id(), &first);
    assert_eq!(from_second.binding_id(), &second);
    assert_eq!(cloned.binding_id(), &first);
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
    let mut bindings = Vec::new();
    for _ in 0..4 {
        bindings.push(BindingId::new::<UdpBinding>());
        bindings.push(BindingId::new::<TestBinding>());
    }
    bindings.extend(bindings.clone());
    assert_consistent(&bindings);
    assert_eq!(bindings.iter().collect::<HashSet<_>>().len(), 8);
    assert_eq!(bindings.iter().collect::<BTreeSet<_>>().len(), 8);

    let mut links = Vec::new();
    for binding in &bindings[..8] {
        links.push(LinkId::new::<UdpLink>(binding.clone()));
        links.push(LinkId::new::<TestLink>(binding.clone()));
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
    let (bindings, links): (Vec<_>, Vec<_>) = thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    let bindings: Vec<_> = (0..PER_THREAD)
                        .map(|_| BindingId::new::<UdpBinding>())
                        .collect();
                    let links: Vec<_> = bindings
                        .iter()
                        .map(|binding| LinkId::new::<UdpLink>(binding.clone()))
                        .collect();
                    (bindings, links)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .unzip()
    });

    let bindings: HashSet<_> = bindings.into_iter().flatten().collect();
    assert_eq!(bindings.len(), THREADS * PER_THREAD);
    let links: Vec<_> = links.into_iter().flatten().collect();
    for link in &links {
        assert!(bindings.contains(link.binding_id()));
    }
    assert_eq!(
        links.iter().collect::<HashSet<_>>().len(),
        THREADS * PER_THREAD
    );
}

#[test]
fn debug_shows_the_identity_and_the_source_binding() {
    let binding = BindingId::new::<UdpBinding>();
    let link = LinkId::new::<UdpLink>(binding.clone());
    let binding = format!("{binding:?}");
    let link = format!("{link:?}");
    assert!(binding.starts_with("BindingId("), "{binding}");
    assert!(binding.contains("UniqueId("), "{binding}");
    assert!(link.starts_with("LinkId {"), "{link}");
    assert!(link.contains(&binding), "{link}");
}
