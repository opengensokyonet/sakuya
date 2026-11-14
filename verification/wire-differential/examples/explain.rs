//! Prints what each implementation reads from a packet payload given in
//! hexadecimal, and how the comparison classifies it.
//!
//! Usage: `explain <hex>`
use wire_differential::frames::{classify, quinn, s2n, sakuya};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hexadecimal input"))
        .collect()
}

fn main() {
    let Some(input) = std::env::args().nth(1) else {
        eprintln!("usage: explain <hex>");
        std::process::exit(2);
    };
    let payload = unhex(&input);
    let ours = sakuya::read(&payload);
    println!("sakuya");
    for (range, run) in &ours.runs {
        println!("  {range:?} {run:?}");
    }
    if let Some(failure) = &ours.failure {
        println!("  failed: {failure:?}");
    }
    let v1 = sakuya::read_v1(&payload);
    if v1.failure != ours.failure {
        println!("sakuya, version 1 alone: failed: {:?}", v1.failure);
    }
    let (theirs, reason) = quinn::read_with_reason(&payload);
    println!("quinn  {:?}", theirs.frames);
    if let Some(reason) = reason {
        println!("  failed: {reason}");
    }
    let (theirs, error) = s2n::read_with_error(&payload);
    println!("s2n    {:?}", theirs.frames);
    if let Some(error) = error {
        println!("  failed: {error}");
    }
    println!("against quinn: {:?}", classify::compare_quinn(&payload));
    println!("against s2n:   {:?}", classify::compare_s2n(&payload));
    if let Some(mismatch) = ours.rewrite_mismatch(&payload) {
        println!("rewrite differs: {mismatch}");
    }
}
