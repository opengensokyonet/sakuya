//! JSON, written by hand: objects and arrays into a byte buffer, with the
//! strings escaped as RFC 8259 requires.
//!
//! Member names are given by this crate and the parts, as `'static` lower
//! case ASCII names (main-schema §11.2); they are written as they are.
//! Every string value is escaped.

use core::time::Duration;
use std::io::Write as _;

/// A JSON object being written: members are added in order, and the object
/// is closed when the closure that writes it returns.
#[derive(Debug)]
pub struct ObjectWriter<'a> {
    buf: &'a mut Vec<u8>,
    empty: bool,
}

/// A JSON array being written: elements are added in order, and the array
/// is closed when the closure that writes it returns.
#[derive(Debug)]
pub struct ArrayWriter<'a> {
    buf: &'a mut Vec<u8>,
    empty: bool,
}

/// Writes one JSON object into `buf`, its members by `members`: the
/// object a part's writing of its frames, parameters and events is given
/// is one of these, and so is what a part's tests read back.
pub fn object(buf: &mut Vec<u8>, members: impl FnOnce(&mut ObjectWriter<'_>)) {
    buf.push(b'{');
    members(&mut ObjectWriter { buf, empty: true });
    buf.push(b'}');
}

impl ObjectWriter<'_> {
    fn key(&mut self, key: &'static str) {
        debug_assert!(
            key.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "member name {key:?}"
        );
        if !self.empty {
            self.buf.push(b',');
        }
        self.empty = false;
        self.buf.push(b'"');
        self.buf.extend_from_slice(key.as_bytes());
        self.buf.extend_from_slice(b"\":");
    }

    /// A member whose value is the string `value`.
    pub fn str(&mut self, key: &'static str, value: &str) -> &mut Self {
        self.key(key);
        string(self.buf, value);
        self
    }

    /// A member whose value is the number `value`.
    pub fn u64(&mut self, key: &'static str, value: u64) -> &mut Self {
        self.key(key);
        number(self.buf, value);
        self
    }

    /// A member whose value is `value`.
    pub fn bool(&mut self, key: &'static str, value: bool) -> &mut Self {
        self.key(key);
        self.buf
            .extend_from_slice(if value { b"true" } else { b"false" });
        self
    }

    /// A member whose value is `value` in milliseconds, a number with three
    /// decimal places (qlog's durations and times are in milliseconds).
    pub fn millis(&mut self, key: &'static str, value: Duration) -> &mut Self {
        self.key(key);
        millis(self.buf, value);
        self
    }

    /// A member whose value is `bytes` as a string of lower case hexadecimal
    /// digits (qlog's `hexstring`).
    pub fn hex(&mut self, key: &'static str, bytes: &[u8]) -> &mut Self {
        self.key(key);
        hex(self.buf, bytes);
        self
    }

    /// A member whose value is an object, written by `members`.
    pub fn object(
        &mut self,
        key: &'static str,
        members: impl FnOnce(&mut ObjectWriter<'_>),
    ) -> &mut Self {
        self.key(key);
        object(self.buf, members);
        self
    }

    /// A member whose value is an array, written by `elements`.
    pub fn array(
        &mut self,
        key: &'static str,
        elements: impl FnOnce(&mut ArrayWriter<'_>),
    ) -> &mut Self {
        self.key(key);
        self.buf.push(b'[');
        elements(&mut ArrayWriter {
            buf: self.buf,
            empty: true,
        });
        self.buf.push(b']');
        self
    }
}

impl ArrayWriter<'_> {
    fn next(&mut self) -> &mut Vec<u8> {
        if !self.empty {
            self.buf.push(b',');
        }
        self.empty = false;
        self.buf
    }

    /// An element that is the string `value`.
    pub fn str(&mut self, value: &str) -> &mut Self {
        string(self.next(), value);
        self
    }

    /// An element that is the number `value`.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        number(self.next(), value);
        self
    }

    /// An element that is `bytes` as a hexadecimal string.
    pub fn hex(&mut self, bytes: &[u8]) -> &mut Self {
        hex(self.next(), bytes);
        self
    }

    /// An element that is an object, written by `members`.
    pub fn object(&mut self, members: impl FnOnce(&mut ObjectWriter<'_>)) -> &mut Self {
        object(self.next(), members);
        self
    }

    /// An element that is an array, written by `elements`.
    pub fn array(&mut self, elements: impl FnOnce(&mut ArrayWriter<'_>)) -> &mut Self {
        let buf = self.next();
        buf.push(b'[');
        elements(&mut ArrayWriter { buf, empty: true });
        buf.push(b']');
        self
    }
}

fn number(buf: &mut Vec<u8>, value: u64) {
    // writing to a vector does not fail
    let _ = write!(buf, "{value}");
}

fn millis(buf: &mut Vec<u8>, value: Duration) {
    let micros = value.as_micros();
    // writing to a vector does not fail
    let _ = write!(buf, "{}.{:03}", micros / 1000, micros % 1000);
}

fn hex(buf: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    buf.push(b'"');
    for byte in bytes {
        buf.push(DIGITS[usize::from(byte >> 4)]);
        buf.push(DIGITS[usize::from(byte & 0x0f)]);
    }
    buf.push(b'"');
}

/// `value` as a JSON string: `"` and `\` escaped, and the control
/// characters below U+0020 as `\u00XX` (RFC 8259 §7).
fn string(buf: &mut Vec<u8>, value: &str) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    buf.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            0..0x20 => {
                buf.extend_from_slice(b"\\u00");
                buf.push(DIGITS[usize::from(byte >> 4)]);
                buf.push(DIGITS[usize::from(byte & 0x0f)]);
            }
            _ => buf.push(byte),
        }
    }
    buf.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(members: impl FnOnce(&mut ObjectWriter<'_>)) -> String {
        let mut buf = Vec::new();
        object(&mut buf, members);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn members_and_nesting() {
        let text = written(|o| {
            o.str("name", "quic:packet_sent")
                .u64("number", 18_446_744_073_709_551_615)
                .bool("probe", false)
                .millis("time", Duration::from_micros(12_345_678))
                .hex("dcid", &[0x0a, 0xff])
                .object("header", |h| {
                    h.u64("packet_number", 0);
                })
                .array("frames", |a| {
                    a.object(|f| {
                        f.str("frame_type", "ping");
                    })
                    .u64(1)
                    .str("x")
                    .array(|a| {
                        a.u64(2).u64(3);
                    });
                })
                .array("empty", |_| {})
                .object("none", |_| {});
        });
        assert_eq!(
            text,
            r#"{"name":"quic:packet_sent","number":18446744073709551615,"probe":false,"time":12345.678,"dcid":"0aff","header":{"packet_number":0},"frames":[{"frame_type":"ping"},1,"x",[2,3]],"empty":[],"none":{}}"#
        );
    }

    #[test]
    fn strings_are_escaped() {
        let text = written(|o| {
            o.str("reason", "a\"b\\c\nd\u{1}é");
        });
        assert_eq!(text, "{\"reason\":\"a\\\"b\\\\c\\nd\\u0001é\"}");
    }

    #[test]
    fn small_durations_keep_three_places() {
        let text = written(|o| {
            o.millis("a", Duration::from_micros(5))
                .millis("b", Duration::ZERO);
        });
        assert_eq!(text, r#"{"a":0.005,"b":0.000}"#);
    }
}
