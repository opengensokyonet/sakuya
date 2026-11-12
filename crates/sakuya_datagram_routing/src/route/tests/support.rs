//! Shared fixtures: packets built from the version 1 header rules, a
//! recording deliverer, a receiver factory and a reflow queue

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sakuya_link::{BindingId, LinkId};
use sakuya_wire::connection_id::ConnectionIdLength;
use sakuya_wire::header::codec::{ReadLongHeaderHostExt as _, ReadShortHeaderHostExt as _};
use sakuya_wire::v1::header::{
    self as v1, FIXED_BIT, LongPacketType, RETRY_INTEGRITY_TAG_LEN,
    codec::ReadLongPacketHostExt as _,
};
use sakuya_wire::var_int::{VarInt, codec::WriteVarIntHostExt as _};
use sakuya_wire::version::Version;

use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::candidate::{DatagramClaimAccess, DatagramClaimOutcome};
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::DatagramDelivery;
use crate::claim::delivery::ExclusiveDatagram;
use crate::claim::erased::SendDatagramDeliverer;
use crate::claim::queue::{DatagramDeliveryPoster, DatagramDeliveryQueue};
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::route::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
    ReflowHandoff, UnclaimedWork,
};
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::datagram::ReceivedDatagram;
use crate::route::index::{RouteEntryRegistration, RouteIndex};
use crate::route::interpretation::{FirstPacketInterpretation, RecognizedInitial};
use crate::route::recognizer::ConnectionIdLengths;
use crate::route::reset::{StatelessResetTarget, StatelessResetTokens};
use crate::route::router::{DatagramRouter, VersionService};

/// This side's end of a test link: a stand-in for a local address.
pub(super) type Local = u32;
/// The peer's end of a test link: a stand-in for a remote address.
pub(super) type Peer = u32;
pub(super) type TestLinkId = LinkId<Local, Peer>;
pub(super) type Datagram = ReceivedDatagram<Vec<u8>, TestLinkId>;
pub(super) type Work = UnclaimedWork<Vec<u8>, TestLinkId>;
pub(super) type Reflow = DatagramDeliveryPoster<Work>;
pub(super) type Handoff = ReflowHandoff<Reflow, Local>;
pub(super) type Target = dyn SendDatagramDeliverer<Datagram, Local, Handoff>;
pub(super) type Index = RouteIndex<Target, Local>;
pub(super) type Router = DatagramRouter<
    Vec<u8>,
    TestLinkId,
    Target,
    ConnectionIdLengths,
    Arc<StatelessResetTokens<ResetProbe>>,
    VersionProbe,
    InitialAcceptance<Factory, Reflow>,
>;

pub(super) struct TestLink;

static NEXT_END: AtomicU32 = AtomicU32::new(1);

/// A local end that no other call of this function returned.
pub(super) fn local_end() -> Local {
    NEXT_END.fetch_add(1, Ordering::Relaxed)
}

/// A new link whose local end is `local`, with a peer end no other link of
/// this function has.
pub(super) fn link(local: &Local) -> TestLinkId {
    LinkId::new::<TestLink>(
        *local,
        NEXT_END.fetch_add(1, Ordering::Relaxed),
        &BindingId::new(),
    )
}

pub(super) fn datagram(bytes: Vec<u8>, link: &TestLinkId) -> Datagram {
    ReceivedDatagram::new(bytes, link.clone())
}

/// A recognizer for the given short header connection ID lengths.
pub(super) fn lengths(lengths: &[usize]) -> ConnectionIdLengths {
    ConnectionIdLengths::new(lengths.iter().map(|&length| dcid_len(length)))
}

pub(super) fn dcid_len(length: usize) -> ConnectionIdLength {
    ConnectionIdLength::new(length).unwrap()
}

pub(super) fn cid(label: u8) -> [u8; 8] {
    [label; 8]
}

pub(super) fn nonempty(bytes: &[u8]) -> sakuya_wire::connection_id::NonEmptyCid {
    bytes.try_into().unwrap()
}

fn type_bits(packet_type: LongPacketType) -> u8 {
    match packet_type {
        LongPacketType::Initial => 0b00,
        LongPacketType::ZeroRtt => 0b01,
        LongPacketType::Handshake => 0b10,
        LongPacketType::Retry => 0b11,
    }
}

/// A version 1 long header packet of `packet_type`, with a two-byte packet
/// number and `payload` protected bytes after it, padded to `total` bytes.
pub(super) fn long(
    packet_type: LongPacketType,
    dcid: &[u8],
    scid: &[u8],
    payload: usize,
) -> Vec<u8> {
    let mut packet = vec![0x80 | FIXED_BIT | (type_bits(packet_type) << 4) | 0x01];
    packet.extend(v1::VERSION.to_be_bytes());
    packet.push(u8::try_from(dcid.len()).unwrap());
    packet.extend(dcid);
    packet.push(u8::try_from(scid.len()).unwrap());
    packet.extend(scid);
    match packet_type {
        LongPacketType::Retry => {
            packet.extend(b"retry token");
            packet.extend([0x5a; RETRY_INTEGRITY_TAG_LEN]);
        }
        _ => {
            if packet_type == LongPacketType::Initial {
                packet
                    .sync_write_var_int_unpin(VarInt::from_u32(0))
                    .unwrap();
            }
            let length = 2 + payload;
            packet
                .sync_write_var_int_unpin(VarInt::from_u32(u32::try_from(length).unwrap()))
                .unwrap();
            packet.extend(std::iter::repeat_n(0xa5, length));
        }
    }
    if dcid.len() <= 20 && scid.len() <= 20 {
        let mut input = packet.as_slice();
        let header = input.sync_read_long_header_unpin().unwrap();
        let parsed = input.sync_read_long_packet_unpin(header).unwrap();
        assert_eq!(parsed.packet_type(), packet_type);
    }
    packet
}

/// A version 1 Initial padded to the 1200 bytes a server requires.
pub(super) fn initial(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let header = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 1 + 2;
    long(LongPacketType::Initial, dcid, scid, 1200 - header - 2)
}

/// A short header packet with `dcid` and a packet number and payload.
pub(super) fn short(dcid: &[u8], rest: usize) -> Vec<u8> {
    let mut packet = vec![FIXED_BIT | 0x01];
    packet.extend(dcid);
    packet.extend(std::iter::repeat_n(0x3c, rest));
    let mut input = packet.as_slice();
    let header = input
        .sync_read_short_header_unpin(ConnectionIdLength::new(dcid.len()).unwrap())
        .unwrap();
    assert_eq!(header.dcid().as_bytes(), dcid);
    packet
}

/// A Version Negotiation packet offering version 1.
pub(super) fn version_negotiation(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80 | 0x3f];
    packet.extend(Version::NEGOTIATION.to_be_bytes());
    packet.push(u8::try_from(dcid.len()).unwrap());
    packet.extend(dcid);
    packet.push(u8::try_from(scid.len()).unwrap());
    packet.extend(scid);
    packet.extend(v1::VERSION.to_be_bytes());
    packet
}

/// A long header of another version.
pub(super) fn other_version(version: Version, dcid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xc0];
    packet.extend(version.to_be_bytes());
    packet.push(u8::try_from(dcid.len()).unwrap());
    packet.extend(dcid);
    packet.push(0);
    packet.extend([0; 32]);
    packet
}

/// How a [`Recorder`] judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Judging {
    Reject,
    Accept,
}

/// A deliverer that keeps every delivery, together with the judgment its
/// receiver passes to attempts.
pub(super) struct Recorder {
    pub(super) label: u32,
    judging: Mutex<Judging>,
    claims: AtomicUsize,
    deliveries: Mutex<Vec<DatagramDelivery<Datagram, Local, Handoff>>>,
}

impl Recorder {
    pub(super) fn new(label: u32, judging: Judging) -> Arc<Self> {
        Arc::new(Self {
            label,
            judging: Mutex::new(judging),
            claims: AtomicUsize::new(0),
            deliveries: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn judge_with(&self, judging: Judging) {
        *self.judging.lock().unwrap() = judging;
    }

    pub(super) fn claim_calls(&self) -> usize {
        self.claims.load(Ordering::SeqCst)
    }

    pub(super) fn delivery_count(&self) -> usize {
        self.deliveries.lock().unwrap().len()
    }

    pub(super) fn take(&self) -> Vec<DatagramDelivery<Datagram, Local, Handoff>> {
        std::mem::take(&mut self.deliveries.lock().unwrap())
    }

    /// The interpretations of the deliveries received so far.
    pub(super) fn interpretations(&self) -> Vec<FirstPacketInterpretation> {
        self.deliveries
            .lock()
            .unwrap()
            .iter()
            .map(|delivery| route_match(delivery).interpretation())
            .collect()
    }

    /// The judgment of this recorder's receiver: counts the call and decides
    /// by the current mode.
    pub(super) fn judge<'access>(
        &self,
        access: DatagramClaimAccess<'access, Datagram>,
    ) -> DatagramClaimOutcome<'access, (), (), Datagram> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        match *self.judging.lock().unwrap() {
            Judging::Reject => DatagramClaimOutcome::Unclaimed(access),
            Judging::Accept => DatagramClaimOutcome::Claimed(access.into_exclusive(), ()),
        }
    }

    /// Attempts every competing delivery with [`judge`](Self::judge) and
    /// consumes every exclusive one, returning the datagrams this deliverer
    /// ended up owning.
    pub(super) fn settle(&self) -> Vec<Datagram> {
        let mut owned = Vec::new();
        for delivery in self.take() {
            let exclusive = match delivery {
                DatagramDelivery::Exclusive(exclusive) => exclusive,
                DatagramDelivery::Competing(candidate) => {
                    match ready(candidate.try_exclusive(|access, _route| self.judge(access))) {
                        DatagramClaimAttempt::Claimed(exclusive, ())
                        | DatagramClaimAttempt::Exclusive(exclusive) => exclusive,
                        DatagramClaimAttempt::Unclaimed(candidate) => {
                            drop(candidate);
                            continue;
                        }
                        DatagramClaimAttempt::Abandoned(())
                        | DatagramClaimAttempt::ClaimedElsewhere => continue,
                    }
                }
            };
            owned.push(exclusive.consume().0.into_inner());
        }
        owned
    }
}

/// Polls once and expects completion.
pub(super) fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("expected the attempt to complete without waiting"),
    }
}

pub(super) fn route_match(
    delivery: &DatagramDelivery<Datagram, Local, Handoff>,
) -> &DatagramRouteMatchInfo<Local> {
    match delivery {
        DatagramDelivery::Competing(candidate) => candidate.route_match(),
        DatagramDelivery::Exclusive(exclusive) => exclusive.route_match(),
    }
}

impl DatagramDeliverer<Datagram, Local> for Recorder {
    type Handoff = Handoff;

    fn deliver(&self, delivery: DatagramDelivery<Datagram, Local, Handoff>) {
        self.deliveries.lock().unwrap().push(delivery);
    }
}

/// Registers `recorder` under `association` for every form of version 1.
pub(super) fn register(
    index: &Arc<Index>,
    association: MatchAssociation<Local>,
    recorder: &Arc<Recorder>,
) -> RouteEntryRegistration<Target, Local> {
    register_forms(index, association, PacketForms::ALL, recorder)
}

pub(super) fn register_forms(
    index: &Arc<Index>,
    association: MatchAssociation<Local>,
    forms: PacketForms,
    recorder: &Arc<Recorder>,
) -> RouteEntryRegistration<Target, Local> {
    index.register(
        RouteMatcher::new(association, forms, Version::V1),
        Arc::clone(recorder) as Arc<Target>,
    )
}

/// The receiver of a newly published Initial entry.
pub(super) struct Accepted {
    pub(super) registration: RouteEntryRegistration<Target, Local>,
    pub(super) datagram: ExclusiveDatagram<Datagram>,
    pub(super) initial: RecognizedInitial<Local>,
    pub(super) deliverer: Arc<Recorder>,
}

/// Records what the receiver received; a hook may run before it records.
pub(super) struct TestReceiver {
    deliverer: Arc<Recorder>,
    accepted: Arc<Mutex<Vec<Accepted>>>,
    #[allow(clippy::type_complexity)]
    before: Option<Box<dyn FnOnce(&Arc<Recorder>) + Send>>,
}

impl InitialDatagramReceiver<Vec<u8>, TestLinkId, Target> for TestReceiver {
    fn receive_first(
        self,
        registration: RouteEntryRegistration<Target, Local>,
        datagram: ExclusiveDatagram<Datagram>,
        initial: RecognizedInitial<Local>,
    ) {
        if let Some(before) = self.before {
            before(&self.deliverer);
        }
        self.accepted.lock().unwrap().push(Accepted {
            registration,
            datagram,
            initial,
            deliverer: self.deliverer,
        });
    }
}

/// Prepares a [`Recorder`] per accepted Initial.
#[derive(Clone)]
pub(super) struct Factory {
    shared: Arc<FactoryShared>,
}

pub(super) struct FactoryShared {
    pub(super) accepted: Arc<Mutex<Vec<Accepted>>>,
    pub(super) prepared: AtomicUsize,
    pub(super) can_prepare: Mutex<bool>,
    pub(super) judging: Mutex<Judging>,
    #[allow(clippy::type_complexity)]
    pub(super) during_prepare: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    pub(super) barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[allow(clippy::type_complexity)]
    pub(super) before_receive: Mutex<Option<Box<dyn FnOnce(&Arc<Recorder>) + Send>>>,
}

impl Factory {
    pub(super) fn new() -> Self {
        Self {
            shared: Arc::new(FactoryShared {
                accepted: Arc::default(),
                prepared: AtomicUsize::new(0),
                can_prepare: Mutex::new(true),
                judging: Mutex::new(Judging::Reject),
                during_prepare: Mutex::new(None),
                barrier: Mutex::new(None),
                before_receive: Mutex::new(None),
            }),
        }
    }

    pub(super) fn shared(&self) -> &FactoryShared {
        &self.shared
    }

    pub(super) fn take_accepted(&self) -> Vec<Accepted> {
        std::mem::take(&mut self.shared.accepted.lock().unwrap())
    }

    pub(super) fn accepted_count(&self) -> usize {
        self.shared.accepted.lock().unwrap().len()
    }
}

impl InitialReceiverFactory<Vec<u8>, TestLinkId, Target> for Factory {
    type Receiver = TestReceiver;

    fn admits(&self, _initial: &RecognizedInitial<Local>, datagram: &Datagram) -> bool {
        datagram.payload().len() >= 1200
    }

    fn prepare(
        &self,
        _initial: &RecognizedInitial<Local>,
    ) -> Option<PreparedReceiver<Target, TestReceiver>> {
        if let Some(during) = self.shared.during_prepare.lock().unwrap().take() {
            during();
        }
        let barrier = self.shared.barrier.lock().unwrap().clone();
        if let Some(barrier) = barrier {
            barrier.wait();
        }
        if !*self.shared.can_prepare.lock().unwrap() {
            return None;
        }
        let label =
            1000 + u32::try_from(self.shared.prepared.fetch_add(1, Ordering::SeqCst)).unwrap();
        let deliverer = Recorder::new(label, *self.shared.judging.lock().unwrap());
        let receiver = TestReceiver {
            deliverer: Arc::clone(&deliverer),
            accepted: Arc::clone(&self.shared.accepted),
            before: self.shared.before_receive.lock().unwrap().take(),
        };
        Some(PreparedReceiver::new(deliverer as Arc<Target>, receiver))
    }
}

/// Records datagrams of unsupported versions.
#[derive(Clone, Default)]
pub(super) struct VersionProbe(pub(super) Arc<Mutex<Vec<Version>>>);

impl VersionService<Vec<u8>, TestLinkId> for VersionProbe {
    fn unsupported_version(&self, version: Version, _datagram: Datagram) {
        self.0.lock().unwrap().push(version);
    }
}

/// Counts the stateless resets it receives.
#[derive(Clone, Default)]
pub(super) struct ResetProbe(pub(super) Arc<AtomicUsize>);

impl StatelessResetTarget for ResetProbe {
    fn stateless_reset_received(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A complete routing domain for tests.
pub(super) struct Domain {
    pub(super) router: Arc<Router>,
    pub(super) reflow: DatagramDeliveryQueue<Work>,
    pub(super) factory: Factory,
    pub(super) resets: Arc<StatelessResetTokens<ResetProbe>>,
    pub(super) versions: VersionProbe,
}

impl Domain {
    pub(super) fn new(short_lengths: &[usize]) -> Self {
        let reflow = DatagramDeliveryQueue::new(NonZeroUsize::new(16).unwrap()).unwrap();
        let factory = Factory::new();
        let resets = StatelessResetTokens::new();
        let versions = VersionProbe::default();
        let router = Arc::new(
            DatagramRouter::new(RouteIndex::new(), lengths(short_lengths))
                .with_stateless_reset(Arc::clone(&resets))
                .with_version_service(versions.clone())
                .with_initial_acceptance(InitialAcceptance::new(
                    factory.clone(),
                    Arc::new(reflow.poster()),
                )),
        );
        Self {
            router,
            reflow,
            factory,
            resets,
            versions,
        }
    }

    pub(super) fn index(&self) -> &Arc<Index> {
        self.router.index()
    }

    pub(super) fn route(&self, bytes: Vec<u8>, link: &TestLinkId) {
        self.router.route(datagram(bytes, link));
    }

    /// Takes the next reflow work, if any.
    pub(super) fn next_work(&mut self) -> Option<Work> {
        self.reflow.try_recv()
    }

    /// Resumes reflow work until none is queued; returns how many rounds ran.
    /// Each round runs on this stack only after the previous one returned.
    pub(super) fn drain(&mut self) -> usize {
        let mut rounds = 0;
        while let Some(work) = self.reflow.try_recv() {
            self.router.resume(work);
            rounds += 1;
        }
        rounds
    }
}
