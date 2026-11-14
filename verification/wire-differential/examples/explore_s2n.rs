//! Groups the payloads on which sakuya and s2n-quic-core read differently by
//! the outcome of the comparison, the error s2n-quic-core reports and the
//! step at which sakuya failed, with a sample of each group.
//!
//! Usage: `explore_s2n [count]`, 200000 payloads by default.
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use std::collections::BTreeMap;
use wire_differential::{
    frames::{classify, generate::payload, s2n, sakuya},
    tally::{Comparison, hex},
};

fn main() {
    let count: usize = std::env::args().nth(1).map_or(200_000, |count| {
        count.parse().expect("a number of payloads")
    });
    let mut runner = TestRunner::deterministic();
    let strategy = payload();
    let mut groups: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for _ in 0..count {
        let bytes = strategy
            .new_tree(&mut runner)
            .expect("the strategy generates")
            .current();
        let ours = sakuya::read(&bytes);
        let (theirs, error) = s2n::read_with_error(&bytes);
        let comparison = classify::compare(&bytes, &ours, &theirs, true);
        if comparison == Comparison::Agree {
            continue;
        }
        let outcome = match comparison {
            Comparison::Known(category) => category,
            _ => "UNCLASSIFIED",
        };
        let sakuya = ours.failure.as_ref().map(|failure| failure.kind);
        let key = format!("{outcome}\n         s2n {error:?}, sakuya {sakuya:?}");
        let entry = groups.entry(key).or_insert_with(|| (0, hex(&bytes)));
        entry.0 += 1;
    }
    for (key, (count, sample)) in groups {
        let sample: String = sample.chars().take(150).collect();
        println!("{count:>8} {key}\n         {sample}");
    }
}
