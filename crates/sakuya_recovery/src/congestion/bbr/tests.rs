use super::{
    Bbr, BbrConfig, BbrConfigError, BbrDeliverySnapshot, BbrLossEpisode, BbrState, MinRtt,
    UNBOUNDED, WindowedMax,
};
use crate::{
    congestion::{
        CongestionContext, CongestionController, CongestionWindowConfig, InFlightPacket,
        InitialWindow, SealedPacket, SpuriouslyLostPacket,
    },
    pacing::{Pacer, PacingInput},
    rtt::RttEstimate,
};
use core::{num::NonZeroUsize, time::Duration};
use std::collections::VecDeque;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn micros(value: u64) -> Duration {
    Duration::from_micros(value)
}

fn bbr() -> Bbr<Duration> {
    Bbr::new(BbrConfig::recommended(ms(1)), 1200)
}

/// An event at `now` ms with `bytes_in_flight` left, and an RTT sample of
/// 40 ms: smoothed, latest and minimum.
fn context(now: u64, bytes_in_flight: usize) -> CongestionContext<Duration> {
    CongestionContext {
        now: ms(now),
        bytes_in_flight,
        rtt: RttEstimate {
            latest: ms(40),
            min: ms(40),
            smoothed: ms(40),
            variation: ms(20),
        },
        rtt_sampled: true,
        max_datagram_size: 1200,
    }
}

fn seal(
    bbr: &mut Bbr<Duration>,
    now: u64,
    bytes_in_flight: usize,
    app_limited: bool,
) -> InFlightPacket<Duration, BbrDeliverySnapshot<Duration>> {
    let sent_state = bbr.on_packet_sealed(&SealedPacket {
        bytes: 1200,
        app_limited,
        bytes_in_flight,
        now: ms(now),
    });
    InFlightPacket {
        bytes: 1200,
        sent_at: ms(now),
        app_limited,
        sent_state,
    }
}

fn input() -> PacingInput {
    PacingInput {
        window: 12000,
        smoothed_rtt: ms(40),
        max_datagram_size: 1200,
    }
}

/// A packet of the simulated path.
struct Flight {
    sent_at: Duration,
    /// When its ACK arrives; `None` if the bottleneck dropped it.
    acked_at: Option<Duration>,
    snapshot: BbrDeliverySnapshot<Duration>,
}

/// The step of the simulation's clock between events.
const STEP: Duration = Duration::from_micros(100);

/// A path with one bottleneck of `rate` bytes per second, a two-way
/// propagation delay and a FIFO buffer of `buffer` bytes. The sender sends
/// 1200-byte packets whenever the window and the pacer let it and it has
/// data; each packet gets its own ACK, and a dropped packet is declared
/// lost by the ACK of a later one.
struct Path {
    bbr: Bbr<Duration>,
    now: Duration,
    serialization: Duration,
    propagation: Duration,
    buffer: usize,
    link_free_at: Duration,
    flights: VecDeque<Flight>,
    bytes_in_flight: usize,
    has_data: bool,
    app_limited: bool,
    rtt: RttEstimate,
    sampled: bool,
}

impl Path {
    fn new(rate: u64, propagation: Duration, buffer: usize) -> Self {
        Self {
            bbr: bbr(),
            now: Duration::ZERO,
            serialization: Duration::from_nanos(1200 * 1_000_000_000 / rate),
            propagation,
            buffer,
            link_free_at: Duration::ZERO,
            flights: VecDeque::new(),
            bytes_in_flight: 0,
            has_data: true,
            app_limited: false,
            rtt: RttEstimate::initial(ms(333)),
            sampled: false,
        }
    }

    fn context(&self, now: Duration, rtt_sampled: bool) -> CongestionContext<Duration> {
        CongestionContext {
            now,
            bytes_in_flight: self.bytes_in_flight,
            rtt: self.rtt,
            rtt_sampled,
            max_datagram_size: 1200,
        }
    }

    fn send(&mut self) {
        self.bytes_in_flight += 1200;
        let snapshot = self.bbr.on_packet_sealed(&SealedPacket {
            bytes: 1200,
            app_limited: self.app_limited,
            bytes_in_flight: self.bytes_in_flight,
            now: self.now,
        });
        let start = self.link_free_at.max(self.now);
        let queued =
            ((start - self.now).as_nanos() * 1200 / self.serialization.as_nanos()) as usize;
        let acked_at = (queued + 1200 <= self.buffer).then(|| {
            self.link_free_at = start + self.serialization;
            self.link_free_at + self.propagation
        });
        self.flights.push_back(Flight {
            sent_at: self.now,
            acked_at,
            snapshot,
        });
    }

    /// Sends what the window and the pacer allow at this instant; the
    /// link path is limited by the application when it has room and no
    /// data, until the window or the pacer holds it back.
    fn send_what_is_allowed(&mut self) {
        let input = PacingInput {
            window: self.bbr.window(),
            smoothed_rtt: self.rtt.smoothed,
            max_datagram_size: 1200,
        };
        self.bbr.refill(self.now, input);
        loop {
            let room =
                self.bytes_in_flight + 1200 <= self.bbr.window() && self.bbr.allowance() >= 1200;
            if !room {
                if self.has_data {
                    self.app_limited = false;
                }
                return;
            }
            if !self.has_data {
                self.app_limited = true;
                return;
            }
            self.send();
            self.bbr.on_charged(1200);
        }
    }

    /// Delivers the next ACK if it is due; whether there was one.
    fn deliver_one(&mut self) -> bool {
        let Some(index) = self.flights.iter().position(|f| f.acked_at.is_some()) else {
            return false;
        };
        let Some(at) = self.flights[index].acked_at.filter(|at| *at <= self.now) else {
            return false;
        };
        let lost: Vec<Flight> = self.flights.drain(..index).collect();
        let acked = self.flights.pop_front().unwrap();
        let latest = at - acked.sent_at;
        if self.sampled {
            self.rtt.min = self.rtt.min.min(latest);
            let deviation = self.rtt.smoothed.abs_diff(latest);
            self.rtt.variation = (self.rtt.variation * 3 + deviation) / 4;
            self.rtt.smoothed = (self.rtt.smoothed * 7 + latest) / 8;
        } else {
            self.rtt = RttEstimate {
                latest,
                min: latest,
                smoothed: latest,
                variation: latest / 2,
            };
            self.sampled = true;
        }
        self.rtt.latest = latest;
        if !lost.is_empty() {
            self.bytes_in_flight -= 1200 * lost.len();
            let context = self.context(at, true);
            let packets = lost.into_iter().map(|flight| InFlightPacket {
                bytes: 1200,
                sent_at: flight.sent_at,
                app_limited: false,
                sent_state: flight.snapshot,
            });
            let _ = self.bbr.on_lost(packets, &context);
        }
        self.bytes_in_flight -= 1200;
        let context = self.context(at, true);
        let packet = InFlightPacket {
            bytes: 1200,
            sent_at: acked.sent_at,
            app_limited: false,
            sent_state: acked.snapshot,
        };
        self.bbr.on_acked([packet].into_iter(), &context);
        true
    }

    /// Runs until `done` holds after an event, or until `limit`; whether
    /// `done` held.
    fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&Self) -> bool) -> bool {
        while self.now < limit {
            let mut next = self.now + STEP;
            if let Some(at) = self.flights.iter().find_map(|f| f.acked_at) {
                next = next.min(at.max(self.now));
            }
            self.now = next.min(limit);
            while self.deliver_one() {
                if done(self) {
                    return true;
                }
                self.send_what_is_allowed();
            }
            self.send_what_is_allowed();
            if done(self) {
                return true;
            }
        }
        false
    }

    /// Takes the `count` oldest packets in flight out and declares them
    /// lost now; they arrived all the same.
    fn declare_lost(
        &mut self,
        count: usize,
    ) -> (BbrLossEpisode, Vec<SpuriouslyLostPacket<Duration>>) {
        let lost: Vec<Flight> = self.flights.drain(..count).collect();
        self.bytes_in_flight -= 1200 * count;
        let spurious = lost
            .iter()
            .map(|flight| SpuriouslyLostPacket {
                bytes: 1200,
                sent_at: flight.sent_at,
            })
            .collect();
        let context = self.context(self.now, false);
        let packets = lost.into_iter().map(|flight| InFlightPacket {
            bytes: 1200,
            sent_at: flight.sent_at,
            app_limited: false,
            sent_state: flight.snapshot,
        });
        (self.bbr.on_lost(packets, &context), spurious)
    }
}

/// 1.2 MB/s (one packet per millisecond), 40 ms of propagation delay, and
/// a buffer that never drops.
fn path() -> Path {
    Path::new(1_200_000, ms(40), usize::MAX)
}

#[test]
fn the_configuration_is_checked() {
    let window = CongestionWindowConfig::RECOMMENDED;
    let burst = NonZeroUsize::new(256).unwrap();
    assert_eq!(
        BbrConfig::new(window, ms(1), burst, 0),
        Err(BbrConfigError::ZeroSeed)
    );
    // The initial window is 10 datagrams.
    assert_eq!(
        BbrConfig::new(window, ms(1), NonZeroUsize::new(9).unwrap(), 7),
        Err(BbrConfigError::MaxBurstBelowInitialWindow {
            max_burst_datagrams: NonZeroUsize::new(9).unwrap(),
            initial_window_datagrams: 10,
        })
    );
    let config = BbrConfig::new(window, ms(1), NonZeroUsize::new(10).unwrap(), 7).unwrap();
    assert_eq!(config.seed(), 7);
    assert_eq!(config.timer_granularity(), ms(1));
    assert_eq!(config.max_burst_datagrams().get(), 10);
}

#[test]
fn initialization_follows_on_init() {
    let bbr = bbr();
    assert_eq!(bbr.state(), BbrState::Startup);
    assert_eq!(bbr.window(), 12000);
    assert_eq!(bbr.min_rtt(), None);
    // InitPacingRate without an RTT: 2.77 × 12000 bytes / 1 ms (§5.6.2).
    assert!((bbr.pacing_rate() - 33_240_000.0).abs() < 1e-3);
    // SetSendQuantum: the rate in 1 ms, below 64 KB (§5.6.3).
    assert_eq!(bbr.send_quantum(), 33240);
}

#[test]
fn the_first_rtt_sample_sets_the_initial_pacing_rate_again() {
    let mut bbr = bbr();
    let packet = seal(&mut bbr, 0, 1200, false);
    bbr.on_acked([packet].into_iter(), &context(40, 0));
    // 2.77 × 12000 bytes / 40 ms; the bandwidth of the first sample,
    // 2.77 × 30000 × 0.99, is lower (§5.6.2).
    assert!((bbr.pacing_rate() - 831_000.0).abs() < 1e-3);
    assert_eq!(bbr.min_rtt(), Some(ms(40)));
}

#[test]
fn application_limited_samples_do_not_lower_max_bw() {
    let mut bbr = bbr();
    // Sent with nothing in flight and acknowledged 40 ms later:
    // 1200 bytes / 40 ms.
    let packet = seal(&mut bbr, 0, 1200, false);
    bbr.on_acked([packet].into_iter(), &context(40, 0));
    assert!((bbr.max_bw() - 30_000.0).abs() < 1e-6);
    // Limited by the application and slower: discarded (§5.5.4).
    let packet = seal(&mut bbr, 100, 1200, true);
    assert!(packet.sent_state.0.is_app_limited);
    bbr.on_acked([packet].into_iter(), &context(180, 0));
    assert!((bbr.max_bw() - 30_000.0).abs() < 1e-6);
    // Limited by the application and faster, 2400 bytes / 40 ms: taken.
    let a = seal(&mut bbr, 200, 1200, true);
    let b = seal(&mut bbr, 200, 2400, true);
    bbr.on_acked([a, b].into_iter(), &context(240, 0));
    assert!((bbr.max_bw() - 60_000.0).abs() < 1e-6);
}

#[test]
fn startup_ends_after_three_rounds_without_growth() {
    let mut path = path();
    assert!(path.run_until(ms(5000), |p| p.bbr.state() != BbrState::Startup));
    let bbr = &path.bbr;
    // A.1: three rounds that grew less than 25% (§5.3.1.2), and a
    // bandwidth within 2% of the bottleneck's.
    assert!(bbr.full_bw_reached && bbr.full_bw_now);
    assert_eq!(bbr.full_bw_count, 3);
    assert_eq!(bbr.state(), BbrState::Drain);
    assert!((bbr.max_bw() / 1_200_000.0 - 1.0).abs() < 0.02);
    // Drain paces at half the bandwidth, less the margin (§5.3.2).
    assert!((bbr.pacing_rate() - 0.5 * 0.99 * bbr.bw).abs() < 1e-6);
    // No loss was seen: no bound on the data in flight.
    assert_eq!(bbr.inflight_longterm, UNBOUNDED);
}

#[test]
fn drain_ends_once_the_queue_is_drained() {
    let mut path = path();
    assert!(path.run_until(ms(5000), |p| p.bbr.state() == BbrState::Drain));
    let drain_start_round = path.bbr.drain_start_round;
    assert!(path.run_until(ms(5000), |p| p.bbr.state() != BbrState::Drain));
    let bbr = &path.bbr;
    // A.3: it left Drain because the data in flight fell to the BDP, not
    // after three rounds (§5.3.2).
    assert!(bbr.round_count <= drain_start_round + 3);
    assert!(path.bytes_in_flight <= bbr.inflight(bbr.bw, 1.0));
    // EnterProbeBW starts at ProbeBW_DOWN, which is already below the BDP
    // and without a bound: ProbeBW_CRUISE on the same ACK (§5.3.3.9).
    assert_eq!(bbr.state(), BbrState::ProbeBwCruise);
    assert_eq!(bbr.cycle_stamp, Some(path.now));
}

#[test]
fn probe_bw_cycles_through_its_four_states() {
    let mut path = path();
    assert!(path.run_until(ms(5000), |p| p.bbr.state() == BbrState::ProbeBwCruise));
    let mut states = vec![BbrState::ProbeBwCruise];
    let mut up_rounds = None;
    let mut refill_at = None;
    path.run_until(ms(9000), |p| {
        let state = p.bbr.state();
        if states.last() != Some(&state) {
            if state == BbrState::ProbeBwRefill && refill_at.is_none() {
                refill_at = Some((p.now, p.bbr.cycle_stamp, p.bbr.bw_probe_wait));
            }
            if state == BbrState::ProbeBwUp {
                // ProbeBW_UP paces at 1.25 times the bandwidth (§5.3.3.5).
                assert!((p.bbr.pacing_rate() - 1.25 * 0.99 * p.bbr.bw).abs() < 1e-6);
                up_rounds = Some(p.bbr.round_count);
            }
            if state == BbrState::ProbeBwDown {
                // A.5: the bandwidth stopped growing for three rounds.
                assert!(p.bbr.round_count >= up_rounds.unwrap() + 3);
            }
            states.push(state);
        }
        states.len() >= 6
    });
    assert_eq!(
        states,
        [
            BbrState::ProbeBwCruise,
            BbrState::ProbeBwRefill,
            BbrState::ProbeBwUp,
            BbrState::ProbeBwDown,
            BbrState::ProbeBwCruise,
            BbrState::ProbeBwRefill,
        ]
    );
    // The first probe came after at most min(T_bbr, T_reno): the BDP is
    // 40 packets, below 63 rounds of 41 ms and below 2 s (§5.3.3.8.2).
    let (at, cycle_stamp, _) = refill_at.unwrap();
    assert!(at - cycle_stamp.unwrap() < ms(2000));
    // Nothing was lost: no bound on the data in flight.
    assert_eq!(path.bbr.inflight_longterm, UNBOUNDED);
}

#[test]
fn probe_rtt_comes_after_ten_seconds_without_a_lower_rtt() {
    // 120 kB/s and 40 ms: a BDP of 6000 bytes, half of which is below
    // MinPipeCwnd.
    let mut path = Path::new(120_000, ms(40), usize::MAX);
    assert!(path.run_until(ms(20000), |p| p.bbr.state() == BbrState::ProbeBwCruise));
    let stamp = path.bbr.min_rtt.unwrap().stamp;
    assert!(path.run_until(ms(20000), |p| p.bbr.state() == BbrState::ProbeRtt));
    // A.10: the minimum RTT expired (§5.3.4.3), and the window is
    // ProbeRTTCwnd, which is MinPipeCwnd: four packets (§5.6.4.5).
    assert!(path.now > stamp + ms(10000));
    assert_eq!(path.bbr.window(), 4800);
    let entered = path.now;
    let entered_round = path.bbr.round_count;
    let prior_cwnd = path.bbr.prior_cwnd;
    assert!(path.run_until(ms(30000), |p| p.bbr.state() != BbrState::ProbeRtt));
    // At least 200 ms and one round with the data in flight at most
    // ProbeRTTCwnd, then back to ProbeBW (§5.3.4.4).
    assert!(path.now - entered > ms(200));
    assert!(path.bbr.round_count > entered_round);
    assert_eq!(path.bbr.state(), BbrState::ProbeBwCruise);
    assert_eq!(path.bbr.min_rtt.unwrap().stamp, path.now);
    // RestoreCwnd, bounded by the model afterwards.
    assert!(path.bbr.window() > 4800);
    assert!(path.bbr.window() <= prior_cwnd.max(path.bbr.max_inflight));
}

#[test]
fn a_restart_after_idle_skips_probe_rtt() {
    let mut path = path();
    assert!(path.run_until(ms(5000), |p| p.bbr.state() == BbrState::ProbeBwCruise));
    path.has_data = false;
    assert!(path.run_until(ms(6000), |p| p.bytes_in_flight == 0));
    path.send_what_is_allowed();
    assert!(path.app_limited);
    // A.11: idle for longer than the minimum RTT filter.
    path.now += ms(11000);
    path.has_data = true;
    path.send_what_is_allowed();
    // HandleRestartFromIdle in ProbeBW: pacing at the bandwidth (§5.4.1).
    assert!(path.bbr.idle_restart);
    assert!((path.bbr.pacing_rate() - 0.99 * path.bbr.bw).abs() < 1e-6);
    let restarted = path.now;
    assert!(!path.run_until(restarted + ms(1000), |p| p.bbr.state()
        == BbrState::ProbeRtt));
    // The expired minimum RTT was refreshed by the first sample instead.
    assert!(path.bbr.min_rtt.unwrap().stamp > restarted);
    assert!(!path.bbr.idle_restart);
}

#[test]
fn startup_ends_on_high_loss() {
    let window = CongestionWindowConfig::new(InitialWindow::new(20, 24000), 2).unwrap();
    let burst = NonZeroUsize::new(256).unwrap();
    let mut bbr = Bbr::new(BbrConfig::new(window, ms(1), burst, 1).unwrap(), 1200);
    let mut packets: VecDeque<_> = (1..=20)
        .map(|n| seal(&mut bbr, 0, 1200 * n, false))
        .collect();
    let first = packets.pop_front().unwrap();
    bbr.on_acked([first].into_iter(), &context(40, 22800));
    // Sent after the first ACK, before the losses.
    let later = seal(&mut bbr, 40, 24000, false);
    // Six packets declared lost at once: a loss recovery starts.
    let lost: Vec<_> = packets.drain(..6).collect();
    let _ = bbr.on_lost(lost.into_iter(), &context(45, 16800));
    assert_eq!(bbr.loss_events_in_round, 6);
    bbr.on_acked([later].into_iter(), &context(80, 15600));
    // A.2: the round ended in loss recovery with 6 losses and 7200 bytes
    // lost of 24000 in flight, above 2% (§5.3.1.3).
    assert!(bbr.full_bw_reached);
    assert_eq!(bbr.undo_state, Some(BbrState::Startup));
    // max(BBR.bdp, BBR.inflight_latest): 30000 bytes/s × 40 ms, and one
    // packet delivered in the round.
    assert_eq!(bbr.inflight_longterm, 1200);
    // 15600 bytes in flight is above Inflight(1.0) of 4800: still draining.
    assert_eq!(bbr.state(), BbrState::Drain);
}

#[test]
fn a_spurious_loss_returns_to_probing() {
    let mut path = path();
    assert!(path.run_until(ms(5000), |p| p.bbr.state() == BbrState::ProbeBwUp));
    assert!(path.bbr.check_probe_loss);
    let (episode, spurious) = path.declare_lost(5);
    // 6000 bytes lost of about 2.25 BDP in flight: too high (§5.5.10.2).
    assert_eq!(path.bbr.state(), BbrState::ProbeBwDown);
    assert_eq!(path.bbr.undo_state, Some(BbrState::ProbeBwUp));
    assert!(path.bbr.prev_probe_too_high);
    assert!(path.bbr.inflight_longterm < UNBOUNDED);
    assert!(path.bbr.recovery_start.is_some());
    // A.18: all five arrived after all (§5.5.11.2).
    let context = path.context(path.now, false);
    let delivered = path.bbr.rate_sampler.delivered();
    path.bbr
        .on_spurious_loss(episode, spurious.clone().into_iter(), &context);
    assert_eq!(path.bbr.rate_sampler.delivered(), delivered + 6000);
    assert_eq!(path.bbr.state(), BbrState::ProbeBwRefill);
    assert_eq!(path.bbr.inflight_longterm, UNBOUNDED);
    assert_eq!(path.bbr.undo_state, None);
    assert!(path.bbr.recovery_start.is_none());
    // An episode is undone once.
    path.bbr.state = BbrState::ProbeBwDown;
    path.bbr
        .on_spurious_loss(episode, spurious.into_iter(), &context);
    assert_eq!(path.bbr.state(), BbrState::ProbeBwDown);
}

#[test]
fn a_spurious_loss_of_part_of_an_episode_is_not_undone() {
    let mut bbr = bbr();
    // An empty batch starts no loss recovery.
    let _ = bbr.on_lost(core::iter::empty(), &context(50, 0));
    assert!(bbr.recovery_start.is_none());
    let a = seal(&mut bbr, 0, 1200, false);
    let b = seal(&mut bbr, 0, 2400, false);
    let episode = bbr.on_lost([a, b].into_iter(), &context(100, 0));
    let packet = SpuriouslyLostPacket {
        bytes: 1200,
        sent_at: ms(0),
    };
    bbr.on_spurious_loss(episode, [packet].into_iter(), &context(110, 0));
    assert!(bbr.recovery_start.is_some());
    bbr.on_spurious_loss(episode, [packet].into_iter(), &context(120, 0));
    assert!(bbr.recovery_start.is_none());
}

#[test]
fn persistent_congestion_takes_the_window_to_the_minimum() {
    let mut bbr = bbr();
    // Five losses: fewer than StartupFullLossCnt, so Startup goes on.
    let packets: Vec<_> = (1..=5)
        .map(|n| seal(&mut bbr, 0, 1200 * n, false))
        .collect();
    let before = seal(&mut bbr, 90, 7200, false);
    let _ = bbr.on_lost(packets.into_iter(), &context(100, 1200));
    bbr.on_persistent_congestion(&context(100, 1200));
    // RFC 9002 §7.6.2: the minimum window, two datagrams.
    assert_eq!(bbr.window(), 2400);
    assert_eq!(bbr.prior_cwnd, 12000);
    // An ACK within the recovery: 2400 + 1200, raised to MinPipeCwnd
    // (§5.6.4.6).
    bbr.on_acked([before].into_iter(), &context(130, 0));
    assert_eq!(bbr.window(), 4800);
    // The ACK of a packet sent after the recovery started ends it: the
    // saved window is restored (§5.6.4.4), and grows by the 1200 bytes
    // acknowledged while less than the initial window was delivered.
    let after = seal(&mut bbr, 130, 1200, false);
    bbr.on_acked([after].into_iter(), &context(170, 0));
    assert!(bbr.recovery_start.is_none());
    assert_eq!(bbr.window(), 13200);
}

#[test]
fn ce_marks_count_as_losses_of_the_round() {
    let mut bbr = bbr();
    bbr.state = BbrState::ProbeBwCruise;
    bbr.full_bw_reached = true;
    bbr.max_bw_slots = [120_000.0, 0.0];
    bbr.max_bw = 120_000.0;
    bbr.bw = 120_000.0;
    bbr.min_rtt = Some(MinRtt {
        value: ms(40),
        stamp: ms(0),
    });
    bbr.cycle_stamp = Some(ms(0));
    bbr.bw_probe_wait = ms(2500);
    let packet = seal(&mut bbr, 10, 1200, false);
    bbr.on_ce(1, ms(10), &context(30, 1200));
    // One marked datagram counts as 1200 bytes lost (§3.7).
    assert_eq!(bbr.rate_sampler.lost(), 1200);
    assert!(bbr.is_loss_in_round);
    assert_eq!(bbr.loss_events_in_round, 1);
    assert!(!bbr.loss_episode.undoable);
    bbr.on_acked([packet].into_iter(), &context(50, 0));
    // The round ends with a loss while not probing: the short-term model
    // comes down to max(latest, 0.7 × its value) (§5.5.10.3).
    assert!((bbr.bw_shortterm - 84_000.0).abs() < 1e-6);
    assert_eq!(bbr.inflight_shortterm, 8400);
    assert!((bbr.bw - 84_000.0).abs() < 1e-6);
    // max_inflight = 2 × 84000 × 40 ms + 1200 extra acknowledged.
    assert_eq!(bbr.window(), 7920);
}

#[test]
fn the_pacer_refills_at_the_pacing_rate_up_to_two_timer_granularities() {
    let mut bbr = bbr();
    assert_eq!(Pacer::<Duration>::next_release(&bbr), None);
    bbr.refill(Duration::ZERO, input());
    // Full at the first refill: 33.24 MB/s over 2 ms, 66480 bytes.
    assert_eq!(bbr.allowance(), 66480);
    assert_eq!(Pacer::<Duration>::next_release(&bbr), None);
    bbr.on_charged(66480);
    // 1200 bytes at 33.24 MB/s: 36101.08 ns, rounded up.
    assert_eq!(
        Pacer::<Duration>::next_release(&bbr),
        Some(Duration::from_nanos(36102))
    );
    // 0.03 bytes in 1 ns: none yet, and the time stays.
    bbr.refill(Duration::from_nanos(1), input());
    assert_eq!(bbr.allowance(), 0);
    bbr.refill(micros(20), input());
    // 664.8 bytes in 20 µs.
    assert_eq!(bbr.allowance(), 664);
    let release = Pacer::<Duration>::next_release(&bbr).unwrap();
    // The other 536 bytes from 20 µs: 16125.15 ns, rounded up.
    assert_eq!(release, micros(20) + Duration::from_nanos(16126));
    bbr.refill(release, input());
    assert_eq!(bbr.allowance(), 1200);
    assert_eq!(Pacer::<Duration>::next_release(&bbr), None);
    // Never more than two timer granularities' worth.
    bbr.refill(ms(100), input());
    assert_eq!(bbr.allowance(), 66480);
    bbr.on_charged(70000);
    assert_eq!(bbr.allowance(), 0);
}

#[test]
fn the_pacers_burst_is_at_least_the_initial_window_and_at_most_the_configured_datagrams() {
    let window = CongestionWindowConfig::RECOMMENDED;
    // 33.24 MB/s over 2 × 100 µs is 6648 bytes, below the initial window.
    let fine = BbrConfig::new(window, micros(100), NonZeroUsize::new(256).unwrap(), 1).unwrap();
    let mut bbr = Bbr::new(fine, 1200);
    bbr.refill(Duration::ZERO, input());
    assert_eq!(bbr.allowance(), 12000);
    // 33.24 MB/s over 2 × 10 ms is 664800 bytes, above 20 datagrams.
    let coarse = BbrConfig::new(window, ms(10), NonZeroUsize::new(20).unwrap(), 1).unwrap();
    let mut bbr = Bbr::new(coarse, 1200);
    bbr.refill(Duration::ZERO, input());
    assert_eq!(bbr.allowance(), 24000);
    // The send quantum stays the draft's: 1 ms of the rate.
    assert_eq!(bbr.send_quantum(), 33240);
}

#[test]
fn the_windowed_max_forgets_old_samples() {
    let mut filter = WindowedMax::new();
    assert_eq!(filter.update(0, 10, 10), 10);
    assert_eq!(filter.update(3, 5, 10), 10);
    assert_eq!(filter.update(8, 7, 10), 10);
    // Round 11 is past the window of the sample of round 0.
    assert_eq!(filter.update(11, 6, 10), 7);
    assert_eq!(filter.update(12, 20, 10), 20);
}

#[test]
fn a_duplicate_initial_crypto_is_answered_once() {
    use crate::pto::PtoPolicy;
    let mut bbr = bbr();
    assert!(PtoPolicy::<Duration>::on_duplicate_initial_crypto(&mut bbr));
    assert!(!PtoPolicy::<Duration>::on_duplicate_initial_crypto(
        &mut bbr
    ));
    assert!(!bbr.wants_recovery_send());
}
