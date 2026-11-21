//! Where a client keeps the address validation tokens servers gave it.
//!
//! A server sends a client tokens in NEW_TOKEN frames; the client returns one
//! when it next connects to the same server, so that the server can count
//! its address as validated before the handshake ([RFC 9000 §8.1.3]). A
//! client keeps them in an [`AddressTokenStore`], per server name: a token
//! applies to any server the connection it came on was authenticated for,
//! whatever the server's address.
//!
//! A token taken out is not handed out again, since reusing one in another
//! attempt would let observers link the attempts. Tokens from Retry packets
//! are never kept. A client that wants to break continuity with servers
//! uses `()`, which keeps nothing.
//!
//! [RFC 9000 §8.1.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3

use alloc::{collections::VecDeque, sync::Arc};
use core::{fmt, hash::Hash, num::NonZeroUsize};

use bytes::Bytes;
use hashbrown::HashMap;
use nitori_sync::SharedState as _;
use sakuya_connection::v1::address_token::AddressTokenSink;

use crate::synchronization::EndpointSynchronization;

/// Where a client keeps tokens, per server name.
pub trait AddressTokenStore<K> {
    /// Keeps `token`, received from `server_name`.
    fn insert(&self, server_name: K, token: Bytes);

    /// Takes a token for `server_name` out of the store, or `None` when it
    /// has none. The store does not hand the same token out again.
    fn take(&self, server_name: &K) -> Option<Bytes>;
}

/// Keeps nothing: [`take`](AddressTokenStore::take) is always `None`.
impl<K> AddressTokenStore<K> for () {
    fn insert(&self, _server_name: K, _token: Bytes) {}

    fn take(&self, _server_name: &K) -> Option<Bytes> {
        None
    }
}

impl<K, S: AddressTokenStore<K> + ?Sized> AddressTokenStore<K> for &S {
    fn insert(&self, server_name: K, token: Bytes) {
        (**self).insert(server_name, token);
    }

    fn take(&self, server_name: &K) -> Option<Bytes> {
        (**self).take(server_name)
    }
}

impl<K, S: AddressTokenStore<K> + ?Sized> AddressTokenStore<K> for Arc<S> {
    fn insert(&self, server_name: K, token: Bytes) {
        (**self).insert(server_name, token);
    }

    fn take(&self, server_name: &K) -> Option<Bytes> {
        (**self).take(server_name)
    }
}

/// Tokens in memory, a bounded queue per server name, each handed out once.
///
/// `take` hands out the newest token of the server name: the most recently
/// received one is the most likely to be valid still. Each server name keeps
/// at most a fixed number of tokens, the oldest going first, and a token
/// equal to one kept is not kept twice. The store keeps tokens for at most a
/// fixed number of server names, a new one replacing an arbitrary one past
/// it. Tokens do not expire here: the client does not know how long a server
/// accepts them, and an expired one only makes the server treat the address
/// as not validated.
///
/// Clones share the same tokens, which are kept in the wrapper of the
/// synchronization `Y` the host chose for its endpoint.
pub struct BoundedAddressTokenStore<K, Y: EndpointSynchronization> {
    tokens_per_server: NonZeroUsize,
    server_capacity: NonZeroUsize,
    tokens: Y::SharedState<ServerTokens<K, Y>>,
}

/// The tokens of a [`BoundedAddressTokenStore`], by server name.
type ServerTokens<K, Y> = HashMap<K, VecDeque<Bytes>, <Y as EndpointSynchronization>::HashBuilder>;

impl<K, Y: EndpointSynchronization> BoundedAddressTokenStore<K, Y> {
    /// The most tokens [`new`](Self::new) keeps for each server name: 2.
    pub const DEFAULT_TOKENS_PER_SERVER: NonZeroUsize = NonZeroUsize::new(2).unwrap();

    /// The most server names [`new`](Self::new) keeps tokens for: 1024.
    pub const DEFAULT_SERVER_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

    /// An empty store with [`DEFAULT_TOKENS_PER_SERVER`] and
    /// [`DEFAULT_SERVER_CAPACITY`].
    ///
    /// [`DEFAULT_TOKENS_PER_SERVER`]: Self::DEFAULT_TOKENS_PER_SERVER
    /// [`DEFAULT_SERVER_CAPACITY`]: Self::DEFAULT_SERVER_CAPACITY
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(
            Self::DEFAULT_TOKENS_PER_SERVER,
            Self::DEFAULT_SERVER_CAPACITY,
        )
    }

    /// An empty store that keeps at most `tokens_per_server` tokens for each
    /// server name and tokens for at most `server_capacity` server names.
    #[must_use]
    pub fn with_limits(tokens_per_server: NonZeroUsize, server_capacity: NonZeroUsize) -> Self {
        Self {
            tokens_per_server,
            server_capacity,
            tokens: Y::share(HashMap::with_hasher(Y::HashBuilder::default())),
        }
    }

    /// The most tokens the store keeps for each server name.
    #[must_use]
    pub fn tokens_per_server(&self) -> NonZeroUsize {
        self.tokens_per_server
    }

    /// The most server names the store keeps tokens for.
    #[must_use]
    pub fn server_capacity(&self) -> NonZeroUsize {
        self.server_capacity
    }
}

impl<K, Y: EndpointSynchronization> Default for BoundedAddressTokenStore<K, Y> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, Y: EndpointSynchronization> Clone for BoundedAddressTokenStore<K, Y> {
    fn clone(&self) -> Self {
        Self {
            tokens_per_server: self.tokens_per_server,
            server_capacity: self.server_capacity,
            tokens: self.tokens.clone(),
        }
    }
}

impl<K, Y: EndpointSynchronization> fmt::Debug for BoundedAddressTokenStore<K, Y> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedAddressTokenStore")
            .field("tokens_per_server", &self.tokens_per_server)
            .field("server_capacity", &self.server_capacity)
            .finish_non_exhaustive()
    }
}

/// The tokens are borrowed for one insertion or one taking at a time; the
/// tokens dropped meanwhile are bytes, whose dropping runs no other code.
impl<K: Clone + Eq + Hash, Y: EndpointSynchronization> AddressTokenStore<K>
    for BoundedAddressTokenStore<K, Y>
{
    fn insert(&self, server_name: K, token: Bytes) {
        self.tokens.with(|tokens| {
            if tokens.len() >= self.server_capacity.get()
                && !tokens.contains_key(&server_name)
                && let Some(evicted) = tokens.keys().next().cloned()
            {
                tokens.remove(&evicted);
            }
            let queue = tokens.entry(server_name).or_default();
            if queue.contains(&token) {
                return;
            }
            if queue.len() >= self.tokens_per_server.get() {
                queue.pop_front();
            }
            queue.push_back(token);
        });
    }

    fn take(&self, server_name: &K) -> Option<Bytes> {
        self.tokens.with(|tokens| {
            let queue = tokens.get_mut(server_name)?;
            let token = queue.pop_back();
            if queue.is_empty() {
                tokens.remove(server_name);
            }
            token
        })
    }
}

/// The store `S` bound to the server name `K` of one connection: where the
/// connection puts the tokens its server gives it.
///
/// It is made when a client connection starts, with a clone of the store
/// in the configuration then and the server name the connection was made
/// for, which is also the name the token it starts with was taken for.
#[derive(Clone, Debug)]
pub struct KeyedAddressTokenSink<S, K> {
    store: S,
    server_name: K,
}

impl<S, K> KeyedAddressTokenSink<S, K> {
    /// `store`, keeping tokens for `server_name`.
    pub fn new(store: S, server_name: K) -> Self {
        Self { store, server_name }
    }

    /// The server name tokens are kept for.
    pub fn server_name(&self) -> &K {
        &self.server_name
    }
}

impl<S: AddressTokenStore<K>, K: Clone> AddressTokenSink for KeyedAddressTokenSink<S, K> {
    fn keep(&self, token: Bytes) {
        self.store.insert(self.server_name.clone(), token);
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressTokenStore, BoundedAddressTokenStore, KeyedAddressTokenSink};
    use crate::synchronization::RefCellEndpointSynchronization;
    use bytes::Bytes;
    use nitori_sync::SharedState as _;
    use sakuya_connection::v1::address_token::AddressTokenSink as _;
    use std::{num::NonZeroUsize, sync::Arc};

    /// The store of the tests, on one thread.
    type Store = BoundedAddressTokenStore<
        &'static str,
        RefCellEndpointSynchronization<std::hash::RandomState>,
    >;

    fn token(byte: u8) -> Bytes {
        Bytes::from(vec![byte; 4])
    }

    #[test]
    fn take_hands_out_the_newest_token_once() {
        let store = Store::new();
        store.insert("example.com", token(1));
        store.insert("example.com", token(2));
        assert_eq!(store.take(&"example.net"), None);
        assert_eq!(store.take(&"example.com"), Some(token(2)));
        assert_eq!(store.take(&"example.com"), Some(token(1)));
        assert_eq!(store.take(&"example.com"), None);
    }

    #[test]
    fn each_server_keeps_its_newest_tokens() {
        let store = Store::new();
        assert_eq!(store.tokens_per_server().get(), 2);
        for byte in 1..=3 {
            store.insert("example.com", token(byte));
        }
        assert_eq!(store.take(&"example.com"), Some(token(3)));
        assert_eq!(store.take(&"example.com"), Some(token(2)));
        assert_eq!(store.take(&"example.com"), None);
    }

    #[test]
    fn an_equal_token_is_kept_once() {
        let store = Store::new();
        store.insert("example.com", token(1));
        store.insert("example.com", token(2));
        store.insert("example.com", token(1));
        // The repeat neither pushed token 1 out nor took a place.
        assert_eq!(store.take(&"example.com"), Some(token(2)));
        assert_eq!(store.take(&"example.com"), Some(token(1)));
        assert_eq!(store.take(&"example.com"), None);
    }

    #[test]
    fn a_new_server_replaces_one_past_the_capacity() {
        let store =
            Store::with_limits(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(2).unwrap());
        store.insert("a.example", token(1));
        store.insert("b.example", token(2));
        // A server already kept is not a new one.
        store.insert("a.example", token(3));
        assert_eq!(store.tokens.with(|tokens| tokens.len()), 2);
        store.insert("c.example", token(4));
        assert_eq!(store.tokens.with(|tokens| tokens.len()), 2);
        let kept = [store.take(&"a.example"), store.take(&"b.example")];
        assert_eq!(kept.iter().filter(|kept| kept.is_none()).count(), 1);
        assert_eq!(store.take(&"c.example"), Some(token(4)));
        assert_eq!(Store::DEFAULT_SERVER_CAPACITY.get(), 1024);
    }

    #[test]
    fn clones_share_the_tokens() {
        let store = Store::new();
        let clone = store.clone();
        store.insert("example.com", token(1));
        assert_eq!(clone.take(&"example.com"), Some(token(1)));
        assert_eq!(store.take(&"example.com"), None);
    }

    #[test]
    fn unit_keeps_nothing() {
        let store = ();
        store.insert("example.com", token(1));
        assert_eq!(
            AddressTokenStore::<&str>::take(&store, &"example.com"),
            None
        );
    }

    #[test]
    #[allow(
        clippy::arc_with_non_send_sync,
        reason = "the forwarding of `Arc` is tested with the store of one thread"
    )]
    fn references_and_arcs_forward() {
        fn round_trip(store: impl AddressTokenStore<&'static str>) -> Option<Bytes> {
            store.insert("example.com", token(1));
            store.take(&"example.com")
        }
        let store = Store::new();
        assert_eq!(round_trip(&store), Some(token(1)));
        assert_eq!(round_trip(Arc::new(store)), Some(token(1)));
    }

    #[test]
    fn a_keyed_sink_keeps_tokens_for_its_server_name() {
        let store = Store::new();
        let sink = KeyedAddressTokenSink::new(store.clone(), "example.com");
        sink.keep(token(1));
        assert_eq!(store.take(&"example.com"), Some(token(1)));
        assert_eq!(store.take(&"example.org"), None);
    }
}
