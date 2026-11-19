# routing-shuttle

Explores the interleavings of `sakuya_datagram_routing` when its routing
domain is shared between threads, with [Shuttle](https://github.com/awslabs/shuttle).
This package is not a member of the sakuya workspace and has its own
dependency graph; no package of the workspace depends on it.

The routing domain is made of the parts `sakuya_sync_std` gives a host whose
threads share it: the route index `DashMapRouteIndex`, the claim lock
`TokioMutexDatagramClaimLock` and the reflow queue
`MutexDatagramDeliveryQueue`. Neither crate is modified. `shim/dashmap` is a
stand-in for the part of the `dashmap` 6 API that `sakuya_sync_std` uses,
built on Shuttle's `RwLock`, and `Cargo.toml` patches `dashmap` with it, so
that every access to a bucket of the index is a scheduling point. The
fixtures in `src/lib.rs` use Shuttle's threads and mutexes, and a judgment
yields while it holds the claim lock, so that the other candidates of a
datagram try to take the lock meanwhile.

## Running

Run these from this directory; rustup selects the toolchain of the
repository root.

```sh
cargo test --release
cargo test --release -- --test-threads=1 --nocapture
```

Every scenario runs under Shuttle's depth-first scheduler, which enumerates
all of its schedules; a scenario fails if the search reaches the bound of
2,000,000 schedules. The second command prints how many schedules each
scenario has and how long the search took.

## What is explored

- A key handed from its Initial association to its local association while
  a 0-RTT packet is looked up: the lookup finds at least one of them.
- Two unclaimed Initials of one key resumed at once: one receiver is
  published, and the other datagram is offered to it; when that receiver
  leaves it, the datagram reflows once and creates a receiver of its own.
- A local entry registered while an Initial is rechecked: the datagram goes
  to exactly one of the local entry and a new receiver.
- One entry revoked and another registered under the same key while a
  lookup runs: exactly the revoked instance goes.
- A receiver closing while another Initial of its key arrives: the datagram
  reflows exactly once.
- The candidates of one datagram attempting it on separate threads: exactly
  one wins and nothing is handed off; when all of them exit, the datagram is
  handed off exactly once, with every entry recorded as having had its
  chance.

## What is not explored

The mutex of `tokio`, the mutexes of std and the atomics have no scheduling
point inside, so Shuttle does not interleave within them; the shim also puts
all keys of one map behind one lock, where real shards may let accesses to
different keys run at once. Shuttle runs every thread with sequentially
consistent memory, so weak memory orderings are outside these checks. The
endpoint, connections, stateless reset tokens and short header routing take
no part in the scenarios.
