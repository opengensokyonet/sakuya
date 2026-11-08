//! A model of routing rounds under generated registrations, revocations,
//! datagrams, judgments and reflow: which entries each round offers a
//! datagram to, that an entry gets one chance per datagram, and that every
//! datagram ends with exactly one owner, or is released.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use proptest::prelude::*;
use sakuya_link::{BindingId, LinkId};
use sakuya_wire::v1::header::LongPacketType;
use sakuya_wire::version::Version;

use super::support::*;
use crate::claim::deliverer::DatagramDeliverer as _;
use crate::claim::delivery::DatagramDelivery;
use crate::route::association::{MatchAssociation, PacketForms};
use crate::route::index::RouteEntryRegistration;
use crate::route::interpretation::FirstPacketInterpretation;

const CIDS: [u8; 2] = [0xa1, 0xb2];
const SHORT_LENGTHS: [usize; 2] = [0, 8];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Assoc {
    Local(usize),
    Initial(usize),
    Zero(usize),
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Initial { cid: Option<usize>, full: bool },
    ZeroRtt { cid: Option<usize> },
    Handshake { cid: Option<usize> },
    Retry { cid: Option<usize> },
    Short { cid: usize },
    Negotiation { cid: Option<usize> },
}

#[derive(Clone, Debug)]
enum Op {
    Register {
        assoc: Assoc,
        forms: u8,
        accept: bool,
    },
    Revoke {
        at: prop::sample::Index,
    },
    Route {
        kind: Kind,
        binding: usize,
    },
    Judge {
        at: prop::sample::Index,
        accept: bool,
    },
    Settle {
        at: prop::sample::Index,
    },
    Resume,
    CanPrepare(bool),
}

fn op() -> impl Strategy<Value = Op> {
    let cid = 0..CIDS.len();
    let opt_cid = prop::option::weighted(0.8, cid.clone());
    let assoc = prop_oneof![
        cid.clone().prop_map(Assoc::Local),
        cid.clone().prop_map(Assoc::Initial),
        (0..2usize).prop_map(Assoc::Zero),
    ];
    let kind = prop_oneof![
        5 => (opt_cid.clone(), prop::bool::weighted(0.85))
            .prop_map(|(cid, full)| Kind::Initial { cid, full }),
        2 => opt_cid.clone().prop_map(|cid| Kind::ZeroRtt { cid }),
        2 => opt_cid.clone().prop_map(|cid| Kind::Handshake { cid }),
        1 => opt_cid.clone().prop_map(|cid| Kind::Retry { cid }),
        3 => cid.prop_map(|cid| Kind::Short { cid }),
        1 => opt_cid.prop_map(|cid| Kind::Negotiation { cid }),
    ];
    let at = any::<prop::sample::Index>;
    prop_oneof![
        5 => (assoc, 0u8..4, prop::bool::weighted(0.3))
            .prop_map(|(assoc, forms, accept)| Op::Register { assoc, forms, accept }),
        2 => at().prop_map(|at| Op::Revoke { at }),
        6 => (kind, 0..2usize).prop_map(|(kind, binding)| Op::Route { kind, binding }),
        2 => (at(), any::<bool>()).prop_map(|(at, accept)| Op::Judge { at, accept }),
        5 => at().prop_map(|at| Op::Settle { at }),
        4 => Just(Op::Resume),
        1 => any::<bool>().prop_map(Op::CanPrepare),
    ]
}

fn forms_of(choice: u8) -> PacketForms {
    match choice {
        0 => PacketForms::ALL,
        1 => PacketForms::INITIAL | PacketForms::ZERO_RTT,
        2 => PacketForms::SHORT | PacketForms::HANDSHAKE,
        _ => PacketForms::INITIAL,
    }
}

struct Entry {
    label: u32,
    assoc: Assoc,
    forms: PacketForms,
    recorder: Arc<Recorder>,
    accept: bool,
    registration: Option<RouteEntryRegistration<Target>>,
}

type Chance = (u32, FirstPacketInterpretation);

/// What the model knows about one datagram.
struct ModelDatagram {
    /// The rounds' lookup keys and interpretations.
    lookups: Vec<(Assoc, FirstPacketInterpretation)>,
    on_unclaimed: bool,
    offered: HashSet<Chance>,
    live: usize,
    taken: bool,
    reflowing: bool,
    /// Whether this round's single last-takes candidate was exclusive.
    exclusive: bool,
    finished: bool,
}

struct Model {
    domain: Domain,
    links: [LinkId; 2],
    bindings: [BindingId; 2],
    entries: Vec<Entry>,
    datagrams: BTreeMap<u32, ModelDatagram>,
    /// Pending deliveries per entry label, in delivery order.
    pending: BTreeMap<u32, Vec<u32>>,
    next_tag: u32,
    next_label: u32,
    can_prepare: bool,
}

fn tagged(mut bytes: Vec<u8>, tag: u32) -> Vec<u8> {
    bytes.extend(tag.to_be_bytes());
    bytes
}

fn tag_of(payload: &[u8]) -> u32 {
    u32::from_be_bytes(*payload.last_chunk().unwrap())
}

impl Model {
    fn new() -> Self {
        let bindings = [binding(), binding()];
        Self {
            domain: Domain::new(&SHORT_LENGTHS),
            links: [link(&bindings[0]), link(&bindings[1])],
            bindings,
            entries: Vec::new(),
            datagrams: BTreeMap::new(),
            pending: BTreeMap::new(),
            next_tag: 0,
            next_label: 1,
            can_prepare: true,
        }
    }

    fn association(&self, assoc: Assoc) -> MatchAssociation {
        match assoc {
            Assoc::Local(cid_index) => MatchAssociation::LocalCid(nonempty(&cid(CIDS[cid_index]))),
            Assoc::Initial(cid_index) => {
                MatchAssociation::InitialDcid(nonempty(&cid(CIDS[cid_index])))
            }
            Assoc::Zero(binding_index) => {
                MatchAssociation::ZeroCid(self.bindings[binding_index].clone())
            }
        }
    }

    fn applicable(&self, assoc: Assoc, interpretation: FirstPacketInterpretation) -> Vec<u32> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.registration.is_some()
                    && entry.assoc == assoc
                    && entry.forms.contains(interpretation.form())
            })
            .map(|entry| entry.label)
            .collect()
    }

    fn offer(&mut self, tag: u32, fresh: &[Chance]) {
        let datagram = self.datagrams.get_mut(&tag).unwrap();
        datagram.live = fresh.len();
        datagram.exclusive = fresh.len() == 1 && !datagram.on_unclaimed;
        for chance in fresh {
            assert!(
                datagram.offered.insert(*chance),
                "two chances for {chance:?}"
            );
            self.pending.entry(chance.0).or_default().push(tag);
        }
    }

    fn deliveries(&self) -> BTreeMap<u32, usize> {
        self.entries
            .iter()
            .map(|entry| (entry.label, entry.recorder.delivery_count()))
            .collect()
    }

    fn check_deliveries(&self) {
        for entry in &self.entries {
            let pending = self.pending.get(&entry.label).map_or(0, Vec::len);
            assert_eq!(
                entry.recorder.delivery_count(),
                pending,
                "deliveries held by entry {}",
                entry.label
            );
        }
    }

    fn finish_if_exited(&mut self, tag: u32) {
        let datagram = self.datagrams.get_mut(&tag).unwrap();
        if datagram.live == 0 && !datagram.taken {
            if datagram.on_unclaimed {
                datagram.reflowing = true;
            } else {
                datagram.finished = true;
            }
        }
    }

    fn route(&mut self, kind: Kind, binding_index: usize) {
        if self.datagrams.len() >= 16 {
            return;
        }
        let tag = self.next_tag;
        self.next_tag += 1;
        let scid = cid(0x5c);
        let dcid_of =
            |cid_index: Option<usize>| cid_index.map_or(Vec::new(), |i| cid(CIDS[i]).to_vec());
        let long_interpretation = |packet_type| FirstPacketInterpretation::Long {
            version: Version::V1,
            packet_type,
        };
        let by_dcid = |cid_index: Option<usize>, with_initial: bool, interpretation| {
            let mut lookups = Vec::new();
            match cid_index {
                Some(i) => {
                    lookups.push((Assoc::Local(i), interpretation));
                    if with_initial {
                        lookups.push((Assoc::Initial(i), interpretation));
                    }
                }
                None => lookups.push((Assoc::Zero(binding_index), interpretation)),
            }
            lookups
        };
        let (bytes, lookups, on_unclaimed) = match kind {
            Kind::Initial {
                cid: cid_index,
                full,
            } => {
                let interpretation = long_interpretation(LongPacketType::Initial);
                let bytes = if full {
                    initial(&dcid_of(cid_index), &scid)
                } else {
                    long(LongPacketType::Initial, &dcid_of(cid_index), &scid, 30)
                };
                (bytes, by_dcid(cid_index, true, interpretation), full)
            }
            Kind::ZeroRtt { cid: cid_index } => {
                let interpretation = long_interpretation(LongPacketType::ZeroRtt);
                let bytes = long(LongPacketType::ZeroRtt, &dcid_of(cid_index), &scid, 30);
                (bytes, by_dcid(cid_index, true, interpretation), false)
            }
            Kind::Handshake { cid: cid_index } => {
                let interpretation = long_interpretation(LongPacketType::Handshake);
                let bytes = long(LongPacketType::Handshake, &dcid_of(cid_index), &scid, 30);
                (bytes, by_dcid(cid_index, false, interpretation), false)
            }
            Kind::Retry { cid: cid_index } => {
                let interpretation = long_interpretation(LongPacketType::Retry);
                let bytes = long(LongPacketType::Retry, &dcid_of(cid_index), &scid, 0);
                (bytes, by_dcid(cid_index, false, interpretation), false)
            }
            Kind::Short { cid: cid_index } => {
                let lookups = vec![
                    (
                        Assoc::Zero(binding_index),
                        FirstPacketInterpretation::Short {
                            dcid_len: dcid_len(0),
                        },
                    ),
                    (
                        Assoc::Local(cid_index),
                        FirstPacketInterpretation::Short {
                            dcid_len: dcid_len(8),
                        },
                    ),
                ];
                (short(&cid(CIDS[cid_index]), 30), lookups, false)
            }
            Kind::Negotiation { cid: cid_index } => (
                version_negotiation(&dcid_of(cid_index), &scid),
                by_dcid(
                    cid_index,
                    false,
                    FirstPacketInterpretation::VersionNegotiation,
                ),
                false,
            ),
        };
        let fresh: Vec<Chance> = lookups
            .iter()
            .flat_map(|&(assoc, interpretation)| {
                self.applicable(assoc, interpretation)
                    .into_iter()
                    .map(move |label| (label, interpretation))
            })
            .collect();
        self.datagrams.insert(
            tag,
            ModelDatagram {
                lookups,
                on_unclaimed,
                offered: HashSet::new(),
                live: 0,
                taken: false,
                reflowing: false,
                exclusive: false,
                finished: false,
            },
        );
        self.offer(tag, &fresh);
        let link = self.links[binding_index].clone();
        self.domain.route(tagged(bytes, tag), &link);
        self.finish_if_exited(tag);
        self.check_kind_of_last_delivery(tag, &fresh);
    }

    /// Only a single last-takes candidate is delivered exclusively.
    fn check_kind_of_last_delivery(&self, tag: u32, fresh: &[Chance]) {
        let exclusive = self.datagrams[&tag].exclusive;
        for (label, _) in fresh {
            let entry = self.entries.iter().find(|e| e.label == *label).unwrap();
            let held = entry.recorder.take();
            let last_exclusive = matches!(held.last(), Some(DatagramDelivery::Exclusive(_)));
            assert_eq!(last_exclusive, exclusive);
            for delivery in held {
                entry.recorder.deliver(delivery);
            }
        }
    }

    fn settle(&mut self, label: u32) {
        let pending = self.pending.remove(&label).unwrap_or_default();
        let entry = self.entries.iter().find(|e| e.label == label).unwrap();
        let accept = entry.accept;
        let owned: Vec<u32> = entry
            .recorder
            .settle()
            .iter()
            .map(|datagram| tag_of(datagram.payload()))
            .collect();
        let mut expected = Vec::new();
        for tag in pending {
            let datagram = self.datagrams.get_mut(&tag).unwrap();
            if !datagram.taken {
                let sole = datagram.live == 1 && !datagram.on_unclaimed;
                if accept || sole {
                    datagram.taken = true;
                    datagram.finished = true;
                    expected.push(tag);
                }
            }
            datagram.live -= 1;
            self.finish_if_exited(tag);
        }
        assert_eq!(owned, expected, "datagrams entry {label} ended up owning");
    }

    fn resume(&mut self) {
        let Some(work) = self.domain.next_work() else {
            assert!(
                !self.datagrams.values().any(|d| d.reflowing && !d.finished),
                "an unclaimed datagram was not handed off"
            );
            return;
        };
        let tag = tag_of(work.datagram().payload());
        let datagram = &self.datagrams[&tag];
        assert!(datagram.reflowing, "only unclaimed datagrams reflow");
        assert_eq!(work.offered_len(), datagram.offered.len());
        let fresh: Vec<Chance> = datagram
            .lookups
            .iter()
            .flat_map(|&(assoc, interpretation)| {
                self.applicable(assoc, interpretation)
                    .into_iter()
                    .map(move |label| (label, interpretation))
            })
            .filter(|chance| !datagram.offered.contains(chance))
            .collect();
        let lookups = datagram.lookups.clone();
        self.datagrams.get_mut(&tag).unwrap().reflowing = false;
        if fresh.is_empty() && !self.can_prepare {
            self.domain.router.resume(work);
            self.datagrams.get_mut(&tag).unwrap().finished = true;
            return;
        }
        self.offer(tag, &fresh);
        self.domain.router.resume(work);
        if !fresh.is_empty() {
            return;
        }
        // Nothing fresh: the prepared receiver was published and owns the
        // first datagram.
        let [accepted] = <[_; 1]>::try_from(self.domain.factory.take_accepted())
            .ok()
            .expect("a receiver was published");
        assert_eq!(tag_of(accepted.datagram.get().payload()), tag);
        let (assoc, interpretation) = *lookups.last().unwrap();
        assert_eq!(
            accepted.registration.entry().matcher().association(),
            &self.association(assoc)
        );
        assert!(
            accepted
                .registration
                .entry()
                .matcher()
                .applies(&interpretation)
        );
        let label = accepted.deliverer.label;
        self.entries.push(Entry {
            label,
            assoc,
            forms: PacketForms::INITIAL | PacketForms::ZERO_RTT,
            recorder: accepted.deliverer,
            accept: false,
            registration: Some(accepted.registration),
        });
        let datagram = self.datagrams.get_mut(&tag).unwrap();
        datagram.taken = true;
        datagram.finished = true;
    }

    fn apply(&mut self, op: &Op) {
        match *op {
            Op::Register {
                assoc,
                forms,
                accept,
            } => {
                let label = self.next_label;
                self.next_label += 1;
                let recorder = Recorder::new(
                    label,
                    if accept {
                        Judging::Accept
                    } else {
                        Judging::Reject
                    },
                );
                let forms = forms_of(forms);
                let registration = register_forms(
                    self.domain.index(),
                    self.association(assoc),
                    forms,
                    &recorder,
                );
                self.entries.push(Entry {
                    label,
                    assoc,
                    forms,
                    recorder,
                    accept,
                    registration: Some(registration),
                });
            }
            Op::Revoke { at } => {
                if !self.entries.is_empty() {
                    let index = at.index(self.entries.len());
                    self.entries[index].registration = None;
                }
            }
            Op::Route { kind, binding } => self.route(kind, binding),
            Op::Judge { at, accept } => {
                if !self.entries.is_empty() {
                    let index = at.index(self.entries.len());
                    let entry = &mut self.entries[index];
                    entry.accept = accept;
                    entry.recorder.judge_with(if accept {
                        Judging::Accept
                    } else {
                        Judging::Reject
                    });
                }
            }
            Op::Settle { at } => {
                if !self.entries.is_empty() {
                    let label = self.entries[at.index(self.entries.len())].label;
                    self.settle(label);
                }
            }
            Op::Resume => self.resume(),
            Op::CanPrepare(can_prepare) => {
                self.can_prepare = can_prepare;
                *self.domain.factory.shared().can_prepare.lock().unwrap() = can_prepare;
            }
        }
        self.check_deliveries();
    }

    fn finish(mut self) {
        loop {
            let labels: Vec<u32> = self.entries.iter().map(|entry| entry.label).collect();
            for label in labels {
                self.settle(label);
            }
            if !self.datagrams.values().any(|d| d.reflowing && !d.finished) {
                break;
            }
            self.resume();
        }
        assert!(
            self.datagrams.values().all(|d| d.finished),
            "every datagram ends with one owner or is released"
        );
        assert_eq!(
            self.domain.next_work().map(|_| ()),
            None,
            "a work item stayed queued"
        );
        for entry in &mut self.entries {
            entry.registration = None;
        }
        assert_eq!(
            self.domain.index().key_counts(),
            (0, 0),
            "revoked entries left buckets"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        max_shrink_iters: 4000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn routing_rounds_follow_the_model(ops in prop::collection::vec(op(), 0..60)) {
        let mut model = Model::new();
        for op in &ops {
            let before = model.deliveries();
            model.apply(op);
            // No delivery appears outside an operation that routes or resumes.
            if !matches!(op, Op::Route { .. } | Op::Resume) {
                for (label, count) in before {
                    let now = model.deliveries()[&label];
                    assert!(now <= count, "a delivery appeared for entry {label}");
                }
            }
        }
        model.finish();
    }
}
