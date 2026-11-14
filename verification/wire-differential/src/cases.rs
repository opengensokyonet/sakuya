//! The configuration of the property tests.
use proptest::test_runner::Config;

/// A proptest configuration with `default` cases, or as many as the
/// `WIRE_CASES` environment variable states, and no persisted failures.
pub fn config(default: u32) -> Config {
    let cases = std::env::var("WIRE_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default);
    Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    }
}

/// Whether divergences are only counted, not failed on: the `WIRE_EXPLORE`
/// environment variable is set.
pub fn exploring() -> bool {
    std::env::var_os("WIRE_EXPLORE").is_some()
}
