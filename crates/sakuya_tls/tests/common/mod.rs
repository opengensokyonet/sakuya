//! Helpers shared by the integration tests.

#[allow(dead_code)]
pub mod backend;
pub mod rfc8448;

/// The bytes of a hexadecimal string.
#[allow(dead_code)]
pub fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
