//! The client's side of `datagram`: datagrams of known content, sent to
//! the server and waited for until they come back.

use core::time::Duration;
use std::path::Path;

use bytes::{BufMut as _, Bytes, BytesMut};

use super::{DOWNLOADS, Failed};

/// How many datagrams the client sends under `datagram`.
pub(super) const DATAGRAMS: u32 = 50;
/// How many times the client sends the datagrams that did not come back.
const DATAGRAM_ROUNDS: u32 = 5;
/// How long the client waits in each round for the datagrams to come back.
const DATAGRAM_WAIT: Duration = Duration::from_secs(2);

/// The `index`th datagram of `size` bytes: the index and the size, four
/// bytes each, then the low byte of the index repeated.
pub(super) fn datagram(index: u32, size: usize) -> Bytes {
    let mut payload = BytesMut::with_capacity(size);
    payload.put_u32(index);
    // invariant: sizes are at most the guaranteed size, below 1200 bytes
    payload.put_u32(u32::try_from(size).expect("a small size"));
    payload.put_bytes(index.to_be_bytes()[3], size - 8);
    payload.freeze()
}

/// What became of a datagram handed to the connection.
pub(super) enum Sending {
    /// It was taken.
    Taken,
    /// The send queue is full; it may be handed over again later.
    Full,
    /// It cannot be sent: why.
    Refused(String),
}

/// Sends [`DATAGRAMS`] datagrams of sizes from 8 bytes up to `limit`, the
/// size that fits any link path in use, through `send` and
/// waits for the server to send each back, as `receive` gives them (`None`
/// once the connection ended); those that do not come back are sent
/// again, up to [`DATAGRAM_ROUNDS`] times. Writes what came back to
/// `/downloads/datagram.txt`, and succeeds when every datagram came back
/// as it was sent.
pub(super) async fn exchange<F>(
    limit: usize,
    send: impl Fn(Bytes) -> Sending,
    receive: impl Fn() -> F,
) -> Result<(), Failed>
where
    F: core::future::Future<Output = Option<Bytes>>,
{
    let largest = limit;
    if largest < 8 {
        eprintln!("sakuya client: the connection takes datagrams of {limit} bytes at most");
        return Err(Failed);
    }
    let count = DATAGRAMS as usize;
    let sizes: Vec<usize> = (0..count)
        .map(|index| 8 + (largest - 8) * index / (count - 1))
        .collect();
    let mut back = vec![false; count];
    let mut mismatched = 0_usize;
    let mut unexpected = 0_usize;
    let mut rounds = 0;
    let mut ended = false;
    while rounds < DATAGRAM_ROUNDS && !ended && back.iter().any(|back| !back) {
        rounds += 1;
        for (index, size) in sizes.iter().enumerate() {
            if back[index] {
                continue;
            }
            // invariant: fewer than 2^32 datagrams
            let payload = datagram(u32::try_from(index).expect("an index"), *size);
            loop {
                match send(payload.clone()) {
                    Sending::Taken => break,
                    Sending::Full => tokio::time::sleep(Duration::from_millis(1)).await,
                    Sending::Refused(why) => {
                        eprintln!(
                            "sakuya client: datagram {index} of {size} bytes is refused: {why}"
                        );
                        return Err(Failed);
                    }
                }
            }
        }
        let deadline = tokio::time::Instant::now() + DATAGRAM_WAIT;
        while back.iter().any(|back| !back) {
            let Ok(received) = tokio::time::timeout_at(deadline, receive()).await else {
                break;
            };
            let Some(payload) = received else {
                eprintln!("sakuya client: the connection ended while datagrams were out");
                ended = true;
                break;
            };
            let index = (payload.len() >= 4)
                .then(|| u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]))
                .map(|index| index as usize)
                .filter(|index| *index < count);
            match index {
                Some(index) if payload == datagram(index as u32, sizes[index]) => {
                    back[index] = true;
                }
                Some(_) => mismatched += 1,
                None => unexpected += 1,
            }
        }
        eprintln!(
            "sakuya client: datagram round {rounds}: {} of {count} came back",
            back.iter().filter(|back| **back).count()
        );
    }
    let missing: Vec<usize> = (0..count).filter(|index| !back[*index]).collect();
    let summary = format!(
        "sent {count} largest {largest} limit {limit} rounds {rounds} back {} missing {missing:?} mismatched {mismatched} unexpected {unexpected}\n",
        count - missing.len()
    );
    eprintln!("sakuya client: datagrams: {}", summary.trim_end());
    if let Err(error) = std::fs::write(Path::new(DOWNLOADS).join("datagram.txt"), &summary) {
        eprintln!("sakuya client: datagram.txt cannot be written: {error}");
        return Err(Failed);
    }
    if missing.is_empty() && mismatched == 0 && unexpected == 0 {
        Ok(())
    } else {
        Err(Failed)
    }
}
