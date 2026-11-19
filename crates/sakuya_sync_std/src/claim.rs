//! The lock the candidates of one datagram compete under, for candidates
//! that move between threads.

use sakuya_datagram_routing::claim::lock::DatagramClaimLock;

/// The claim lock of a routing domain shared between threads
/// (`TokioMutexDatagramClaimLock`): the mutex of `tokio`, which an attempt
/// waits for without blocking its thread.
///
/// Its locks are `Send` and `Sync` when the datagram is `Send`, and a wait
/// withdrawn by dropping it lets the next waiter go on.
#[derive(Debug)]
pub enum TokioMutexDatagramClaimLock {}

impl DatagramClaimLock for TokioMutexDatagramClaimLock {
    type Lock<T> = tokio::sync::Mutex<T>;

    fn new<T>(value: T) -> tokio::sync::Mutex<T> {
        tokio::sync::Mutex::new(value)
    }

    async fn with<T, R>(lock: &tokio::sync::Mutex<T>, op: impl FnOnce(&mut T) -> R) -> R {
        let mut value = lock.lock().await;
        op(&mut value)
    }

    fn try_with<T, R>(lock: &tokio::sync::Mutex<T>, op: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut value = lock.try_lock().ok()?;
        Some(op(&mut value))
    }

    fn get_mut<T>(lock: &mut tokio::sync::Mutex<T>) -> &mut T {
        lock.get_mut()
    }
}
