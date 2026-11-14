//! The outcome of a comparison, and counts of the outcomes across a run.
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// The result of comparing sakuya with one reference on one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    /// Both read the same.
    Agree,
    /// A divergence with a verdict from the RFCs, named by its category.
    Known(&'static str),
    /// A divergence nobody has judged.
    Unclassified,
}

type Counts = BTreeMap<String, (u64, String)>;

fn counts() -> &'static Mutex<Counts> {
    static COUNTS: OnceLock<Mutex<Counts>> = OnceLock::new();
    COUNTS.get_or_init(Default::default)
}

/// Counts one occurrence of `category`, keeping the first sample.
pub fn record(category: &str, sample: impl FnOnce() -> String) {
    let mut counts = counts().lock().unwrap();
    let entry = counts
        .entry(category.to_owned())
        .or_insert_with(|| (0, sample()));
    entry.0 += 1;
}

/// Counts a comparison that agreed.
pub fn agree(area: &str) {
    record(&format!("{area}/agree"), String::new);
}

/// Counts the result of comparing with the reference `reference` in `area`;
/// `sample` describes the input for the first occurrence of a divergence.
pub fn tally(area: &str, reference: &str, result: Comparison, sample: impl FnOnce() -> String) {
    match result {
        Comparison::Agree => agree(&format!("{area}/{reference}")),
        Comparison::Known(category) => record(&format!("{area}/{reference}/{category}"), sample),
        Comparison::Unclassified => record(&format!("{area}/{reference}/UNCLASSIFIED"), sample),
    }
}

/// Prints the counts and the first sample of each category.
pub fn report(title: &str) {
    let counts = counts().lock().unwrap();
    println!("--- tally: {title}");
    for (category, (count, sample)) in counts.iter() {
        println!("{count:>12} {category} {sample}");
    }
}

/// Lowercase hexadecimal of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
