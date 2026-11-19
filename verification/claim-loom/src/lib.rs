//! Loom models of the claim core of `sakuya_datagram_routing`; see the tests
//! and the README.

#[cfg(not(sakuya_loom))]
compile_error!(
    "build with RUSTFLAGS=\"--cfg sakuya_loom\", so that the claim core takes loom's atomics"
);
