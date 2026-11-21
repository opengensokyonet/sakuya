use std::{
    collections::{BTreeSet, HashMap},
    num::NonZeroUsize,
};

use time::UtcDateTime;

use super::{NewTokenId, ValidNewToken};

/// The NEW_TOKEN tokens an endpoint has accepted, so that it accepts each at
/// most once ([RFC 9000 §8.1.4]).
///
/// The record holds at most its capacity. A token is kept until it expires,
/// after which it would not validate again anyway; when the record is full,
/// the token that expires first is forgotten to make room, so such a token
/// could be accepted a second time. Only the endpoint's reflow driver uses
/// the record, so it takes no lock.
///
/// [RFC 9000 §8.1.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4
#[derive(Debug)]
pub struct UsedNewTokens {
    capacity: NonZeroUsize,
    expiry: HashMap<NewTokenId, UtcDateTime>,
    by_expiry: BTreeSet<(UtcDateTime, NewTokenId)>,
}

impl UsedNewTokens {
    /// An empty record of at most `capacity` tokens.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            expiry: HashMap::new(),
            by_expiry: BTreeSet::new(),
        }
    }

    /// Records `token` as accepted at `now`; `false` when it was accepted
    /// before and is still recorded, in which case it must not be accepted
    /// again.
    pub fn accept_once(&mut self, token: &ValidNewToken, now: UtcDateTime) -> bool {
        self.forget_expired(now);
        if self.expiry.contains_key(&token.id) {
            return false;
        }
        if self.expiry.len() >= self.capacity.get()
            && let Some((expires_at, id)) = self.by_expiry.pop_first()
        {
            self.expiry.remove(&id);
            debug_assert!(expires_at > now, "expired entries were forgotten above");
        }
        self.expiry.insert(token.id, token.expires_at);
        self.by_expiry.insert((token.expires_at, token.id));
        true
    }

    /// The number of tokens recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.expiry.len()
    }

    /// Whether no token is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expiry.is_empty()
    }

    /// Forgets the tokens that expire at or before `now`.
    fn forget_expired(&mut self, now: UtcDateTime) {
        while let Some(&(expires_at, id)) = self.by_expiry.first()
            && expires_at <= now
        {
            self.by_expiry.pop_first();
            self.expiry.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use time::UtcDateTime;

    use super::UsedNewTokens;
    use crate::address_token::{NewTokenAddress, NewTokenId, ValidNewToken};

    fn start() -> UtcDateTime {
        UtcDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn token(id: u8, expires_in: u64) -> ValidNewToken {
        ValidNewToken {
            address: NewTokenAddress::Validated,
            id: NewTokenId([id; 16]),
            expires_at: start() + Duration::from_secs(expires_in),
        }
    }

    #[test]
    fn a_token_is_accepted_once() {
        let mut used = UsedNewTokens::new(NonZeroUsize::new(4).unwrap());
        assert!(used.accept_once(&token(1, 60), start()));
        assert!(!used.accept_once(&token(1, 60), start()));
        assert!(used.accept_once(&token(2, 60), start()));
        assert_eq!(used.len(), 2);
    }

    #[test]
    fn expired_tokens_are_forgotten() {
        let mut used = UsedNewTokens::new(NonZeroUsize::new(4).unwrap());
        assert!(used.accept_once(&token(1, 60), start()));
        let later = start() + Duration::from_secs(60);
        assert!(used.accept_once(&token(2, 120), later));
        assert_eq!(used.len(), 1);
    }

    #[test]
    fn a_full_record_forgets_the_token_that_expires_first() {
        let mut used = UsedNewTokens::new(NonZeroUsize::new(2).unwrap());
        assert!(used.accept_once(&token(1, 90), start()));
        assert!(used.accept_once(&token(2, 30), start()));
        assert!(used.accept_once(&token(3, 60), start()));
        assert_eq!(used.len(), 2);
        assert!(!used.accept_once(&token(1, 90), start()));
        assert!(!used.accept_once(&token(3, 60), start()));
        assert!(used.accept_once(&token(2, 30), start()));
    }
}
