//! A [`KeyLog`] that writes the NSS SSLKEYLOGFILE format to a file.

use core::fmt::Write as _;
use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    path::Path,
    sync::{Mutex, PoisonError},
};

use sakuya_tls::{
    key_log::{KeyLog, KeyLogLabel},
    message::HelloRandom,
};

/// A key log that appends a line for each secret to a file: the label, the
/// client_random and the secret, the last two in lowercase hexadecimal
/// (RFC 9850).
///
/// The file is shared by every connection that holds the log; each line is
/// written whole under a lock and flushed at once, so that a tool reading
/// the file meanwhile sees whole lines. A line that cannot be written is
/// reported once on standard error and the handshake goes on, as a key log
/// is only for debugging.
#[derive(Debug)]
pub struct KeyLogFile {
    file: Mutex<Option<File>>,
}

impl KeyLogFile {
    /// The key log appending to the file at `path`, created if it does not
    /// exist.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened for appending.
    pub fn append_to(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(Some(file)),
        })
    }

    /// The line for `secret` under `label` of the connection with
    /// `client_random`, with its line feed.
    fn line(label: KeyLogLabel, client_random: &HelloRandom, secret: &[u8]) -> String {
        let mut line = String::with_capacity(label.as_str().len() + 2 * (32 + secret.len()) + 3);
        line.push_str(label.as_str());
        line.push(' ');
        hex(&mut line, &client_random.0);
        line.push(' ');
        hex(&mut line, secret);
        line.push('\n');
        line
    }
}

fn hex(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        // invariant: writing to a String does not fail
        write!(out, "{byte:02x}").expect("a string takes the digits");
    }
}

impl KeyLog for KeyLogFile {
    fn log(&self, label: KeyLogLabel, client_random: &HelloRandom, secret: &[u8]) {
        let line = Self::line(label, client_random, secret);
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(open) = file.as_mut()
            && let Err(error) = open.write_all(line.as_bytes()).and_then(|()| open.flush())
        {
            eprintln!("the key log stops: {error}");
            *file = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_the_label_the_random_and_the_secret_in_hexadecimal() {
        let mut random = [0; 32];
        random[0] = 0xab;
        random[31] = 0x01;
        let line = KeyLogFile::line(
            KeyLogLabel::ServerHandshakeTrafficSecret,
            &HelloRandom(random),
            &[0x00, 0xff, 0x10],
        );
        assert_eq!(
            line,
            format!(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET ab{}01 00ff10\n",
                "00".repeat(30)
            )
        );
    }

    #[test]
    fn lines_are_appended_to_the_file() {
        let dir =
            std::env::temp_dir().join(format!("sakuya-interop-key-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.log");
        std::fs::write(&path, "# earlier\n").unwrap();
        let log = KeyLogFile::append_to(&path).unwrap();
        log.log(
            KeyLogLabel::ClientTrafficSecret0,
            &HelloRandom([1; 32]),
            &[2; 4],
        );
        log.log(
            KeyLogLabel::ServerTrafficSecret0,
            &HelloRandom([1; 32]),
            &[3; 4],
        );
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "# earlier");
        assert!(lines[1].starts_with("CLIENT_TRAFFIC_SECRET_0 0101"));
        assert!(lines[1].ends_with(" 02020202"));
        assert!(lines[2].starts_with("SERVER_TRAFFIC_SECRET_0 "));
    }
}
