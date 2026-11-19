//! The migration policy RFC 9000 recommends and the fixed part's rules,
//! over links whose peer ends are socket addresses.
use core::time::Duration;
use std::net::SocketAddr;

use sakuya_link::{BindingId, LinkId};
use sakuya_wire::v1::transport_parameters::preferred_address::PreferredAddressFamilies;

use super::{
    ConnectionMigration, LinkPathAdmission, LinkPathAdmissionContext, LinkPathFacts,
    MigrationDecision, MigrationPolicy, OldLocalAddressContext, OldLocalAddressPacketHandling,
    PathChallengeContext, PathChallengeTiming, PeerMovedContext, PreferredAddressContext,
    Rfc9000MigrationPolicy, SameNetworkAddressChange, SettlingContext, SwitchRecovery,
    SwitchTiming,
    rules::{FailedValidation, LinkPathState, MigrationStep, Switch, SwitchLayer, hold_fallback},
};
use crate::{role::LinkPathRole, v1::amplification::AddressValidation};

type Id = LinkId<(), SocketAddr>;

fn link(peer: &str) -> Id {
    LinkId::new::<()>((), peer.parse().unwrap(), &BindingId::new())
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

const PTO: Duration = Duration::from_millis(100);

/// The state of the link path over `link` in `role`, with a recovery layer
/// whose probe timeout is [`PTO`] in the roles that have one.
fn state(
    link: &Id,
    role: LinkPathRole<Duration>,
    validated: bool,
) -> LinkPathState<'_, (), SocketAddr, Duration> {
    LinkPathState {
        link,
        role,
        validation: if validated {
            AddressValidation::Validated
        } else {
            AddressValidation::NotValidated
        },
        pto: role.has_recovery().then_some(PTO),
    }
}

/// The policy RFC 9000 recommends, which counts the peers moved it is told
/// of and switches as `timing` says.
#[derive(Debug)]
struct Counting {
    timing: SwitchTiming,
    asked: usize,
}

impl Default for Counting {
    fn default() -> Self {
        Self {
            timing: SwitchTiming::Now,
            asked: 0,
        }
    }
}

impl<Lo: Clone + Eq> MigrationPolicy<Lo, SocketAddr, Duration> for Counting {
    fn admit(
        &mut self,
        cx: &LinkPathAdmissionContext<'_, Lo, SocketAddr, Duration>,
    ) -> LinkPathAdmission<Lo, SocketAddr> {
        Rfc9000MigrationPolicy.admit(cx)
    }

    fn on_peer_moved(
        &mut self,
        cx: &PeerMovedContext<'_, Lo, SocketAddr, Duration>,
    ) -> MigrationDecision<Lo, SocketAddr> {
        self.asked += 1;
        MigrationDecision {
            timing: self.timing,
            ..Rfc9000MigrationPolicy.on_peer_moved(cx)
        }
    }

    fn challenge_timing(&self, cx: &PathChallengeContext) -> PathChallengeTiming {
        MigrationPolicy::<(), SocketAddr, Duration>::challenge_timing(&Rfc9000MigrationPolicy, cx)
    }

    fn settling_for(&self, cx: &SettlingContext) -> Duration {
        MigrationPolicy::<(), SocketAddr, Duration>::settling_for(&Rfc9000MigrationPolicy, cx)
    }

    fn choose_preferred_address(&mut self, cx: &PreferredAddressContext<'_>) -> Option<SocketAddr> {
        MigrationPolicy::<(), SocketAddr, Duration>::choose_preferred_address(
            &mut Rfc9000MigrationPolicy,
            cx,
        )
    }

    fn on_old_local_address(
        &mut self,
        cx: &OldLocalAddressContext,
    ) -> OldLocalAddressPacketHandling {
        MigrationPolicy::<(), SocketAddr, Duration>::on_old_local_address(
            &mut Rfc9000MigrationPolicy,
            cx,
        )
    }
}

fn migration(timing: SwitchTiming) -> ConnectionMigration<Counting, (), SocketAddr> {
    ConnectionMigration {
        policy: Counting { timing, asked: 0 },
        ..ConnectionMigration::default()
    }
}

fn facts(
    link: &Id,
    role: LinkPathRole<Duration>,
    since: u64,
    fallback: bool,
) -> LinkPathFacts<(), SocketAddr, Duration> {
    LinkPathFacts {
        link: link.clone(),
        role,
        since: ms(since),
        validation: AddressValidation::Validated,
        fallback,
    }
}

fn admission_cx<'a>(
    new: &'a Id,
    link_paths: &'a [LinkPathFacts<(), SocketAddr, Duration>],
) -> LinkPathAdmissionContext<'a, (), SocketAddr, Duration> {
    LinkPathAdmissionContext {
        link: new,
        link_paths,
        local_disabled_active_migration: true,
        peer_switched_local_id: false,
        now: ms(1000),
    }
}

#[test]
fn only_the_port_changing_on_the_same_end_proves_a_same_network_address_change() {
    let old = link("198.51.100.7:50000");
    let port = link("198.51.100.7:50001");
    let address = link("203.0.113.9:40000");
    let change = SameNetworkAddressChange::check(&old, &port).expect("the port changed");
    assert!(change.from() == &old && change.to() == &port);
    assert!(change.is(&old, &port) && !change.is(&port, &old));
    let back = change.reversed();
    assert!(back.is(&port, &old));
    assert!(SameNetworkAddressChange::check(&old, &address).is_none());
    // the same peer end is no change, even over another link
    let again = link("198.51.100.7:50000");
    assert!(SameNetworkAddressChange::check(&old, &again).is_none());
    // this side's end moved
    let elsewhere = LinkId::new::<()>(
        1u8,
        "198.51.100.7:50001".parse::<SocketAddr>().unwrap(),
        &BindingId::new(),
    );
    let here = LinkId::new::<()>(
        0u8,
        "198.51.100.7:50000".parse::<SocketAddr>().unwrap(),
        &BindingId::new(),
    );
    assert!(SameNetworkAddressChange::check(&here, &elsewhere).is_none());
}

#[test]
fn the_recommended_policy_keeps_four_candidates_and_one_settling_link_path() {
    let [a, b, c, d, e, s1, s2, f] = [
        "10.0.0.1:1",
        "10.0.0.1:2",
        "10.0.0.1:3",
        "10.0.0.1:4",
        "10.0.0.1:5",
        "10.0.0.1:6",
        "10.0.0.1:7",
        "10.0.0.1:8",
    ]
    .map(link);
    let new = link("10.0.0.1:9");
    let link_paths = [
        facts(&a, LinkPathRole::Active, 0, false),
        // the oldest candidate is the fallback, which stays
        facts(&f, LinkPathRole::Candidate, 1, true),
        facts(&c, LinkPathRole::Candidate, 30, false),
        facts(&b, LinkPathRole::Candidate, 20, false),
        facts(&d, LinkPathRole::Candidate, 40, false),
        facts(&e, LinkPathRole::Candidate, 50, false),
        facts(&s2, LinkPathRole::Settling(ms(2000)), 70, false),
        facts(&s1, LinkPathRole::Settling(ms(2000)), 60, false),
    ];
    let LinkPathAdmission::Accept { end } =
        Rfc9000MigrationPolicy.admit(&admission_cx(&new, &link_paths))
    else {
        panic!("every link path is admitted");
    };
    // five candidates and the new one: the two oldest but the fallback end;
    // of two settling, the older ends
    assert_eq!(end, [b, c, s1]);
    let few = [facts(&a, LinkPathRole::Active, 0, false)];
    assert_eq!(
        Rfc9000MigrationPolicy.admit(&admission_cx(&new, &few)),
        LinkPathAdmission::Accept { end: Vec::new() }
    );
}

#[test]
fn the_fixed_part_ends_neither_the_active_link_path_nor_the_fallback() {
    struct EndAll;
    impl MigrationPolicy<(), SocketAddr, Duration> for EndAll {
        fn admit(
            &mut self,
            cx: &LinkPathAdmissionContext<'_, (), SocketAddr, Duration>,
        ) -> LinkPathAdmission<(), SocketAddr> {
            let mut end: Vec<_> = cx
                .link_paths
                .iter()
                .map(|facts| facts.link.clone())
                .collect();
            end.push(cx.link.clone());
            LinkPathAdmission::Accept { end }
        }
        fn on_peer_moved(
            &mut self,
            _: &PeerMovedContext<'_, (), SocketAddr, Duration>,
        ) -> MigrationDecision<(), SocketAddr> {
            unreachable!("not asked")
        }
        fn challenge_timing(&self, _: &PathChallengeContext) -> PathChallengeTiming {
            unreachable!("not asked")
        }
        fn settling_for(&self, _: &SettlingContext) -> Duration {
            unreachable!("not asked")
        }
        fn choose_preferred_address(
            &mut self,
            _: &PreferredAddressContext<'_>,
        ) -> Option<SocketAddr> {
            unreachable!("not asked")
        }
        fn on_old_local_address(
            &mut self,
            _: &OldLocalAddressContext,
        ) -> OldLocalAddressPacketHandling {
            unreachable!("not asked")
        }
    }
    let [a, b, c] = ["10.0.0.1:1", "10.0.0.1:2", "10.0.0.1:3"].map(link);
    let new = link("10.0.0.1:9");
    let link_paths = [
        facts(&a, LinkPathRole::Active, 0, false),
        facts(&b, LinkPathRole::Settling(ms(2000)), 10, true),
        facts(&c, LinkPathRole::Candidate, 20, false),
    ];
    let mut migration = ConnectionMigration::<_, (), SocketAddr> {
        policy: EndAll,
        fallback: None,
        moved: None,
        left_local: None,
        holds_back: None,
        failed_active: None,
        may_await: false,
    };
    assert_eq!(
        migration.admit(&admission_cx(&new, &link_paths)),
        Some(vec![c])
    );
}

#[test]
fn a_dropped_admission_builds_nothing() {
    struct DropAll;
    impl MigrationPolicy<(), SocketAddr, Duration> for DropAll {
        fn admit(
            &mut self,
            cx: &LinkPathAdmissionContext<'_, (), SocketAddr, Duration>,
        ) -> LinkPathAdmission<(), SocketAddr> {
            assert!(cx.local_disabled_active_migration);
            LinkPathAdmission::Drop
        }
        fn on_peer_moved(
            &mut self,
            _: &PeerMovedContext<'_, (), SocketAddr, Duration>,
        ) -> MigrationDecision<(), SocketAddr> {
            unreachable!("not asked")
        }
        fn challenge_timing(&self, _: &PathChallengeContext) -> PathChallengeTiming {
            unreachable!("not asked")
        }
        fn settling_for(&self, _: &SettlingContext) -> Duration {
            unreachable!("not asked")
        }
        fn choose_preferred_address(
            &mut self,
            _: &PreferredAddressContext<'_>,
        ) -> Option<SocketAddr> {
            unreachable!("not asked")
        }
        fn on_old_local_address(
            &mut self,
            _: &OldLocalAddressContext,
        ) -> OldLocalAddressPacketHandling {
            unreachable!("not asked")
        }
    }
    let a = link("10.0.0.1:1");
    let new = link("10.0.0.1:9");
    let link_paths = [facts(&a, LinkPathRole::Active, 0, false)];
    let mut migration = ConnectionMigration::<_, (), SocketAddr> {
        policy: DropAll,
        fallback: None,
        moved: None,
        left_local: None,
        holds_back: None,
        failed_active: None,
        may_await: false,
    };
    assert_eq!(migration.admit(&admission_cx(&new, &link_paths)), None);
}

#[test]
fn the_recommended_policy_switches_at_once_and_moves_the_layer_within_a_network_address() {
    let old = link("198.51.100.7:50000");
    let port = link("198.51.100.7:50001");
    let address = link("203.0.113.9:40000");
    let moved = |to: &Id| {
        Rfc9000MigrationPolicy.on_peer_moved(&PeerMovedContext {
            from: &old,
            to,
            peer_switched_local_id: false,
            now: ms(1000),
        })
    };
    let decision = moved(&port);
    assert_eq!(decision.timing, SwitchTiming::Now);
    assert!(matches!(decision.recovery, SwitchRecovery::Move(change) if change.is(&old, &port)));
    assert_eq!(
        moved(&address),
        MigrationDecision {
            timing: SwitchTiming::Now,
            recovery: SwitchRecovery::New,
        }
    );
}

#[test]
fn the_recommended_challenge_timing_doubles_from_the_probe_timeout() {
    let timing = |attempt, path_pto| {
        MigrationPolicy::<(), SocketAddr, Duration>::challenge_timing(
            &Rfc9000MigrationPolicy,
            &PathChallengeContext {
                attempt,
                path_pto,
                active_pto: ms(300),
                initial_pto: ms(999),
            },
        )
    };
    assert_eq!(
        timing(1, Some(ms(100))),
        PathChallengeTiming {
            resend_after: ms(100),
            abandon_after: ms(2997),
        }
    );
    assert_eq!(timing(3, Some(ms(100))).resend_after, ms(400));
    // without a recovery layer, from the probe timeout of a new path
    assert_eq!(timing(2, None).resend_after, ms(1998));
    assert_eq!(timing(u8::MAX, None).resend_after, Duration::MAX);
    assert_eq!(
        MigrationPolicy::<(), SocketAddr, Duration>::settling_for(
            &Rfc9000MigrationPolicy,
            &SettlingContext { pto: ms(100) }
        ),
        ms(300)
    );
}

#[test]
fn a_switch_takes_only_the_non_probing_packet_of_the_highest_number_on_another_link_path() {
    let a = link("198.51.100.7:50000");
    let b = link("198.51.100.7:50001");
    let mut migration = migration(SwitchTiming::Now);
    let active = state(&a, LinkPathRole::Active, true);
    let arrival = state(&b, LinkPathRole::Candidate, false);
    let processed =
        |migration: &mut ConnectionMigration<_, _, _>,
         arrival: &LinkPathState<'_, _, _, _>,
         active: Option<&LinkPathState<'_, _, _, _>>,
         moves| { migration.on_processed(arrival, false, active, moves, false, ms(1000)) };
    assert_eq!(
        processed(&mut migration, &arrival, Some(&active), false),
        MigrationStep::Stay
    );
    assert_eq!(
        processed(&mut migration, &active, None, true),
        MigrationStep::Stay
    );
    assert_eq!(migration.policy.asked, 0);
}

#[test]
fn a_port_change_moves_the_recovery_layer_and_the_active_one_becomes_a_candidate() {
    let a = link("198.51.100.7:50000");
    let b = link("198.51.100.7:50001");
    let mut migration = migration(SwitchTiming::Now);
    let step = migration.on_processed(
        &state(&b, LinkPathRole::Candidate, false),
        false,
        Some(&state(&a, LinkPathRole::Active, true)),
        true,
        false,
        ms(1000),
    );
    assert_eq!(
        step,
        MigrationStep::Switch(Switch {
            to: b.clone(),
            from: Some((a.clone(), LinkPathRole::Candidate)),
            layer: SwitchLayer::Move,
        })
    );
    assert_eq!(migration.fallback(), Some(&a));
    // the candidate the layer moved from is the validated fallback: a packet
    // there switches back, the layer moving back, the policy not asked
    let step = migration.on_processed(
        &state(&a, LinkPathRole::Candidate, true),
        false,
        Some(&state(&b, LinkPathRole::Active, false)),
        true,
        false,
        ms(1100),
    );
    assert_eq!(
        step,
        MigrationStep::Switch(Switch {
            to: a.clone(),
            from: Some((b, LinkPathRole::Candidate)),
            layer: SwitchLayer::Move,
        })
    );
    assert_eq!(migration.policy.asked, 1);
    assert_eq!(migration.fallback(), None);
}

#[test]
fn a_new_address_gets_a_new_layer_and_the_active_one_settles() {
    let a = link("198.51.100.7:50000");
    let b = link("203.0.113.9:40000");
    let mut migration = migration(SwitchTiming::Now);
    let step = migration.on_processed(
        &state(&b, LinkPathRole::Candidate, false),
        false,
        Some(&state(&a, LinkPathRole::Active, true)),
        true,
        true,
        ms(1000),
    );
    // three probe timeouts of the link path that settles
    assert_eq!(
        step,
        MigrationStep::Switch(Switch {
            to: b.clone(),
            from: Some((a.clone(), LinkPathRole::Settling(ms(1300)))),
            layer: SwitchLayer::New { initial_rtt: None },
        })
    );
    assert_eq!(migration.fallback(), Some(&a));
    // a packet on the validated `Settling` one switches back to it, with its
    // own layer, the policy not asked again
    let step = migration.on_processed(
        &state(&a, LinkPathRole::Settling(ms(1300)), true),
        false,
        Some(&state(&b, LinkPathRole::Active, false)),
        true,
        false,
        ms(1100),
    );
    assert_eq!(
        step,
        MigrationStep::Switch(Switch {
            to: a,
            from: Some((b, LinkPathRole::Settling(ms(1400)))),
            layer: SwitchLayer::Keep,
        })
    );
    assert_eq!(migration.policy.asked, 1);
    assert_eq!(migration.fallback(), None);
}

#[test]
fn a_move_that_names_other_link_paths_gets_a_new_layer() {
    let a = link("198.51.100.7:50000");
    let b = link("198.51.100.7:50001");
    let c = link("198.51.100.7:50002");
    struct Stale(SameNetworkAddressChange<(), SocketAddr>);
    impl MigrationPolicy<(), SocketAddr, Duration> for Stale {
        fn admit(
            &mut self,
            _: &LinkPathAdmissionContext<'_, (), SocketAddr, Duration>,
        ) -> LinkPathAdmission<(), SocketAddr> {
            unreachable!("not asked")
        }
        fn on_peer_moved(
            &mut self,
            _: &PeerMovedContext<'_, (), SocketAddr, Duration>,
        ) -> MigrationDecision<(), SocketAddr> {
            MigrationDecision {
                timing: SwitchTiming::Now,
                recovery: SwitchRecovery::Move(self.0.clone()),
            }
        }
        fn challenge_timing(&self, _: &PathChallengeContext) -> PathChallengeTiming {
            unreachable!("not asked")
        }
        fn settling_for(&self, cx: &SettlingContext) -> Duration {
            cx.pto
        }
        fn choose_preferred_address(
            &mut self,
            _: &PreferredAddressContext<'_>,
        ) -> Option<SocketAddr> {
            unreachable!("not asked")
        }
        fn on_old_local_address(
            &mut self,
            _: &OldLocalAddressContext,
        ) -> OldLocalAddressPacketHandling {
            unreachable!("not asked")
        }
    }
    let mut migration = ConnectionMigration::<_, (), SocketAddr> {
        policy: Stale(SameNetworkAddressChange::check(&a, &c).unwrap()),
        fallback: None,
        moved: None,
        left_local: None,
        holds_back: None,
        failed_active: None,
        may_await: false,
    };
    let step = migration.on_processed(
        &state(&b, LinkPathRole::Candidate, false),
        false,
        Some(&state(&a, LinkPathRole::Active, true)),
        true,
        false,
        ms(1000),
    );
    assert_eq!(
        step,
        MigrationStep::Switch(Switch {
            to: b,
            from: Some((a, LinkPathRole::Settling(ms(1100)))),
            layer: SwitchLayer::New { initial_rtt: None },
        })
    );
}

#[test]
fn a_switch_after_validation_waits_and_is_made_once_validated() {
    let a = link("198.51.100.7:50000");
    let b = link("203.0.113.9:40000");
    let mut migration = migration(SwitchTiming::AfterValidation);
    let candidate = state(&b, LinkPathRole::Candidate, false);
    let active = state(&a, LinkPathRole::Active, true);
    let step = migration.on_processed(&candidate, false, Some(&active), true, false, ms(1000));
    assert_eq!(step, MigrationStep::Await(SwitchRecovery::New));
    // later packets there do not ask again
    let step = migration.on_processed(&candidate, true, Some(&active), true, false, ms(1010));
    assert_eq!(step, MigrationStep::Stay);
    assert_eq!(migration.policy.asked, 1);
    // validated with the response back over it: the new layer starts with
    // the challenge's RTT
    let step = migration.on_validated(
        &candidate,
        Some(SwitchRecovery::New),
        Some(&active),
        Some(ms(30)),
        ms(1030),
    );
    assert_eq!(
        step,
        MigrationStep::Switch(Switch {
            to: b.clone(),
            from: Some((a.clone(), LinkPathRole::Settling(ms(1330)))),
            layer: SwitchLayer::New {
                initial_rtt: Some(ms(30)),
            },
        })
    );
    // validated, the new active link path needs no fallback
    assert_eq!(migration.fallback(), None);
    // a candidate validated with nothing waiting stays as it is
    assert_eq!(
        migration.on_validated(
            &state(&a, LinkPathRole::Candidate, false),
            None,
            None,
            None,
            ms(1040)
        ),
        MigrationStep::Stay
    );
}

#[test]
fn a_move_after_validation_moves_the_layer_of_the_active_link_path_then() {
    let a = link("198.51.100.7:50000");
    let b = link("198.51.100.7:50001");
    let mut migration = migration(SwitchTiming::AfterValidation);
    let candidate = state(&b, LinkPathRole::Candidate, false);
    let active = state(&a, LinkPathRole::Active, true);
    let MigrationStep::Await(recovery) =
        migration.on_processed(&candidate, false, Some(&active), true, false, ms(1000))
    else {
        panic!("the switch waits")
    };
    let step = migration.on_validated(
        &candidate,
        Some(recovery),
        Some(&active),
        Some(ms(30)),
        ms(1030),
    );
    assert_eq!(
        step,
        MigrationStep::Switch(Switch {
            to: b,
            from: Some((a, LinkPathRole::Candidate)),
            layer: SwitchLayer::Move,
        })
    );
}

#[test]
fn the_active_link_path_validated_needs_no_fallback() {
    let a = link("198.51.100.7:50000");
    let b = link("203.0.113.9:40000");
    let mut migration = migration(SwitchTiming::Now);
    let step = migration.on_processed(
        &state(&b, LinkPathRole::Candidate, false),
        false,
        Some(&state(&a, LinkPathRole::Active, true)),
        true,
        false,
        ms(1000),
    );
    assert!(matches!(step, MigrationStep::Switch(_)));
    assert_eq!(migration.fallback(), Some(&a));
    let step = migration.on_validated(
        &state(&b, LinkPathRole::Active, false),
        None,
        None,
        None,
        ms(1030),
    );
    assert_eq!(step, MigrationStep::Stay);
    assert_eq!(migration.fallback(), None);
}

#[test]
fn a_failed_validation_ends_a_candidate_and_reverts_the_active_link_path() {
    let a = link("198.51.100.7:50000");
    let b = link("203.0.113.9:40000");
    let c = link("192.0.2.5:1000");
    let mut migration = migration(SwitchTiming::Now);
    assert_eq!(
        migration.on_validation_failed(&state(&c, LinkPathRole::Candidate, false), None, ms(900)),
        FailedValidation::End(c)
    );
    let step = migration.on_processed(
        &state(&b, LinkPathRole::Candidate, false),
        false,
        Some(&state(&a, LinkPathRole::Active, true)),
        true,
        false,
        ms(1000),
    );
    assert!(matches!(step, MigrationStep::Switch(_)));
    let outcome = migration.on_validation_failed(
        &state(&b, LinkPathRole::Active, false),
        Some(&state(&a, LinkPathRole::Settling(ms(1300)), true)),
        ms(1200),
    );
    assert_eq!(
        outcome,
        FailedValidation::Revert {
            switch: Switch {
                to: a.clone(),
                from: Some((b.clone(), LinkPathRole::Settling(ms(1500)))),
                layer: SwitchLayer::Keep,
            },
            end: b.clone(),
        }
    );
    assert_eq!(migration.fallback(), None);
    // nothing validated is left to revert to
    assert_eq!(
        migration.on_validation_failed(&state(&b, LinkPathRole::Active, false), None, ms(1200)),
        FailedValidation::NoFallback
    );
}

#[test]
fn a_failed_validation_after_a_port_change_moves_the_layer_back() {
    let a = link("198.51.100.7:50000");
    let b = link("198.51.100.7:50001");
    let mut migration = migration(SwitchTiming::Now);
    let step = migration.on_processed(
        &state(&b, LinkPathRole::Candidate, false),
        false,
        Some(&state(&a, LinkPathRole::Active, true)),
        true,
        false,
        ms(1000),
    );
    assert!(matches!(step, MigrationStep::Switch(_)));
    let outcome = migration.on_validation_failed(
        &state(&b, LinkPathRole::Active, false),
        Some(&state(&a, LinkPathRole::Candidate, true)),
        ms(1200),
    );
    assert_eq!(
        outcome,
        FailedValidation::Revert {
            switch: Switch {
                to: a,
                from: Some((b.clone(), LinkPathRole::Candidate)),
                layer: SwitchLayer::Move,
            },
            end: b,
        }
    );
}

#[test]
fn an_ended_link_path_is_no_fallback_and_moves_nothing_back() {
    let a = link("198.51.100.7:50000");
    let b = link("198.51.100.7:50001");
    let mut migration = migration(SwitchTiming::Now);
    let step = migration.on_processed(
        &state(&b, LinkPathRole::Candidate, false),
        false,
        Some(&state(&a, LinkPathRole::Active, true)),
        true,
        false,
        ms(1000),
    );
    assert!(matches!(step, MigrationStep::Switch(_)));
    migration.link_path_ended(&a);
    assert_eq!(migration.fallback(), None);
    assert!(migration.moved.is_none());
}

#[test]
fn the_fallback_settles_at_least_until_the_validation_gives_up() {
    let mut role = LinkPathRole::Settling(ms(1300));
    assert!(hold_fallback(&mut role, ms(1200)).is_none());
    assert_eq!(role, LinkPathRole::Settling(ms(1300)));
    assert!(hold_fallback(&mut role, ms(4000)).is_some());
    assert_eq!(role, LinkPathRole::Settling(ms(4000)));
    let mut candidate = LinkPathRole::<Duration>::Candidate;
    assert!(hold_fallback(&mut candidate, ms(4000)).is_none());
}

/// A logical link from this side's end numbered `local` to `peer`.
fn at(local: u8, peer: &str) -> LinkId<u8, SocketAddr> {
    LinkId::new::<()>(local, peer.parse().unwrap(), &BindingId::new())
}

/// [`state`] of a link with a local end of its own.
fn state_at(
    link: &LinkId<u8, SocketAddr>,
    role: LinkPathRole<Duration>,
    validated: bool,
) -> LinkPathState<'_, u8, SocketAddr, Duration> {
    LinkPathState {
        link,
        role,
        validation: if validated {
            AddressValidation::Validated
        } else {
            AddressValidation::NotValidated
        },
        pto: role.has_recovery().then_some(PTO),
    }
}

/// The migration, the original link path's logical link and the
/// preferred one's.
type Moved = (
    ConnectionMigration<Counting, u8, SocketAddr>,
    LinkId<u8, SocketAddr>,
    LinkId<u8, SocketAddr>,
);

/// A server that moved from its original local end, 0, to its preferred
/// one, 1: the move waited for the validation of the new link path, with a
/// new recovery layer, and the policy was not asked.
fn moved_to_preferred() -> Moved {
    let original = at(0, "198.51.100.7:50000");
    let preferred = at(1, "198.51.100.7:50000");
    let mut migration = ConnectionMigration::<Counting, u8, SocketAddr> {
        policy: Counting::default(),
        ..ConnectionMigration::default()
    };
    let active = state_at(&original, LinkPathRole::Active, true);
    let step = migration.on_processed(
        &state_at(&preferred, LinkPathRole::Candidate, false),
        false,
        Some(&active),
        true,
        true,
        ms(1000),
    );
    assert_eq!(step, MigrationStep::Await(SwitchRecovery::New));
    assert_eq!(migration.policy().asked, 0, "the policy is not asked");
    assert_eq!(migration.left_local(), None);
    let step = migration.on_validated(
        &state_at(&preferred, LinkPathRole::Candidate, true),
        Some(SwitchRecovery::New),
        Some(&active),
        Some(ms(20)),
        ms(1020),
    );
    let MigrationStep::Switch(switch) = step else {
        panic!("the validation makes the switch, not {step:?}")
    };
    assert_eq!(switch.to, preferred);
    assert_eq!(
        switch.layer,
        SwitchLayer::New {
            initial_rtt: Some(ms(20))
        }
    );
    assert!(
        matches!(&switch.from, Some((from, LinkPathRole::Settling(_))) if *from == original),
        "the original link path settles: {:?}",
        switch.from
    );
    assert_eq!(migration.left_local(), Some(&0));
    (migration, original, preferred)
}

#[test]
fn a_link_path_at_another_local_end_waits_for_its_validation_whatever_the_policy() {
    moved_to_preferred();
}

#[test]
fn a_packet_processed_at_the_old_local_end_without_switching_back_switches_nothing() {
    let (mut migration, original, preferred) = moved_to_preferred();
    let settling = state_at(&original, LinkPathRole::Settling(ms(2000)), true);
    let active = state_at(&preferred, LinkPathRole::Active, true);
    migration.holds_back = Some(original.clone());
    assert_eq!(
        migration.on_processed(&settling, false, Some(&active), true, false, ms(1100)),
        MigrationStep::Stay
    );
    // the next one, which the policy lets switch back, does
    let step = migration.on_processed(&settling, false, Some(&active), true, false, ms(1110));
    assert!(
        matches!(&step, MigrationStep::Switch(switch) if switch.to == original),
        "{step:?}"
    );
    assert_eq!(
        migration.left_local(),
        Some(&1),
        "the preferred local end is the one left now"
    );
}

#[test]
fn the_recommended_policy_tries_the_addresses_of_a_preferred_address_in_order_each_once() {
    let ipv4 = "192.0.2.50:4433".parse::<SocketAddr>().unwrap();
    let ipv6 = "[2001:db8::50]:4433".parse::<SocketAddr>().unwrap();
    let (SocketAddr::V4(v4), SocketAddr::V6(v6)) = (ipv4, ipv6) else {
        unreachable!("one of each family")
    };
    let choose = |offered: PreferredAddressFamilies, failed: &[SocketAddr]| {
        MigrationPolicy::<(), SocketAddr, Duration>::choose_preferred_address(
            &mut Rfc9000MigrationPolicy,
            &PreferredAddressContext {
                offered: &offered,
                failed,
            },
        )
    };
    let both = PreferredAddressFamilies::Both(v4, v6);
    assert_eq!(choose(both, &[]), Some(ipv4));
    assert_eq!(choose(both, &[ipv4]), Some(ipv6));
    assert_eq!(choose(both, &[ipv4, ipv6]), None);
    assert_eq!(choose(PreferredAddressFamilies::Ipv6(v6), &[]), Some(ipv6));
    assert_eq!(choose(PreferredAddressFamilies::Ipv4(v4), &[ipv4]), None);
}

#[test]
fn the_recommended_policy_drops_the_newer_packets_at_an_old_local_end_and_processes_the_late() {
    let handling = |newer| {
        MigrationPolicy::<(), SocketAddr, Duration>::on_old_local_address(
            &mut Rfc9000MigrationPolicy,
            &OldLocalAddressContext { newer },
        )
    };
    assert_eq!(handling(true), OldLocalAddressPacketHandling::Drop);
    assert_eq!(handling(false), OldLocalAddressPacketHandling::Process);
}
