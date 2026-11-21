# claim-loom

Explores the claim core of `sakuya_datagram_routing_v1` with
[loom](https://github.com/tokio-rs/loom): two candidates of one datagram on
two threads, under every interleaving and the weak memory orderings loom
models. This package is not a member of the sakuya workspace and has its own
dependency graph; no package of the workspace depends on it.

Built with `--cfg sakuya_loom`, the routing crate takes the claim core's
reference count, participation count and commit flag from loom; nothing else
in it changes, and without the flag it does not depend on loom. The candidates
come out of a real router over the routing crate's index of one thread, with
a mutex of loom as the lock they judge under, so loom also explores who holds
the lock when. The index is only used before the threads start.

## Running

Run from this directory; rustup selects the toolchain of the repository root.

```sh
RUSTFLAGS="--cfg sakuya_loom" cargo test --release
```

Without the flag the package does not compile.

## What the models check

- Two candidates that exit at once, or one that exits while the other's
  judgment leaves the datagram, hand an admitted Initial off exactly once.
- A candidate that takes the datagram while the other exits suppresses the
  hand-off, and of two candidates that both take it, exactly one wins.
- When the routing domain does not admit the Initial, the last participant
  takes the datagram or releases it, and nothing is handed off.

The routing tables and the queues of a domain shared between threads are not
modelled here; `verification/routing-shuttle` explores those.
