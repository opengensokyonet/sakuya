use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use nitori_crypto::{
    Aead, AeadAlgorithm, AeadKey, ExpandLength, HashAlgorithm, Hkdf, Random, RandomError, Secret,
    Supported,
};
use sakuya_wire::connection_id::ConnectionId;
use snafu::Snafu;
use time::UtcDateTime;

use super::{
    AddressTokens, DEFAULT_NEW_TOKEN_LIFETIME, DEFAULT_RETRY_TOKEN_LIFETIME,
    ExactTokenAddressPolicy, NewTokenAddress, NewTokenId, NewTokenIssuer, TokenAddressPolicy,
    TokenKind, TokenOutcome, ValidNewToken,
};

/// The secret key that seals an endpoint's address validation tokens.
///
/// Instances that accept one another's tokens are given the same key. The
/// bytes are overwritten when the key is dropped, and `Debug` does not print
/// them.
pub struct AddressTokenKey(Secret);

impl AddressTokenKey {
    /// The length of the key in bytes.
    pub const LEN: usize = 32;

    /// A key drawn from `random`.
    ///
    /// # Errors
    ///
    /// Fails when the random source fails.
    pub fn generate<R: Random + ?Sized>(random: &R) -> Result<Self, RandomError> {
        let mut bytes = random.random::<{ Self::LEN }>()?;
        let key = Self::from_bytes(&bytes);
        bytes.fill(0);
        Ok(key)
    }

    /// The key with the bytes `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        // invariant: `LEN` is within the capacity of a `Secret`.
        Self(Secret::new(bytes).expect("an address token key fits in a secret"))
    }
}

impl fmt::Debug for AddressTokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressTokenKey").finish_non_exhaustive()
    }
}

/// How long the tokens of an [`AeadAddressTokens`] are accepted after they
/// are issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddressTokenLifetimes {
    /// How long a Retry token is accepted.
    pub retry: Duration,
    /// How long a NEW_TOKEN token is accepted.
    pub new_token: Duration,
}

impl Default for AddressTokenLifetimes {
    /// [`DEFAULT_RETRY_TOKEN_LIFETIME`] and [`DEFAULT_NEW_TOKEN_LIFETIME`].
    fn default() -> Self {
        Self {
            retry: DEFAULT_RETRY_TOKEN_LIFETIME,
            new_token: DEFAULT_NEW_TOKEN_LIFETIME,
        }
    }
}

/// Address validation tokens sealed with an AEAD under a key only the
/// server knows.
///
/// A token is a byte that tells a Retry token from a NEW_TOKEN token,
/// followed by a random salt and the sealed contents: when the token was
/// issued, the client address it was issued to, and for a Retry token the
/// original Destination Connection ID. Each token is sealed with its own key,
/// derived with HKDF-SHA256 from the endpoint's [`AddressTokenKey`] and the
/// salt, under AES-256-GCM; deriving a key per token keeps the AEAD's limit
/// on random nonces under one key out of reach however many tokens are
/// issued. So the tokens are hard to guess, protected against change, unique
/// to each client, and unlinkable to the connection that issued them
/// ([RFC 9000 §8.1.3], [RFC 9000 §8.1.4]).
///
/// Whether the client's address matches the one a token was issued to is
/// decided by the [`TokenAddressPolicy`] `P`. Clones share the key.
///
/// [RFC 9000 §8.1.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3
/// [RFC 9000 §8.1.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4
pub struct AeadAddressTokens<C: Aead + Hkdf, P = ExactTokenAddressPolicy> {
    sealer: Arc<Sealer<C>>,
    policy: P,
}

impl<C: Aead + Hkdf, P: Clone> Clone for AeadAddressTokens<C, P> {
    fn clone(&self) -> Self {
        Self {
            sealer: Arc::clone(&self.sealer),
            policy: self.policy.clone(),
        }
    }
}

impl<C: Aead + Hkdf, P: fmt::Debug> fmt::Debug for AeadAddressTokens<C, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadAddressTokens")
            .field("lifetimes", &self.sealer.lifetimes)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<C: Aead + Hkdf + Random, P: TokenAddressPolicy> AeadAddressTokens<C, P> {
    /// Tokens sealed by `backend` under `key`, accepted for `lifetimes`, with
    /// addresses compared by `policy`.
    ///
    /// # Errors
    ///
    /// Fails when `backend` does not support AES-256-GCM or SHA-256.
    pub fn new(
        backend: C,
        key: AddressTokenKey,
        lifetimes: AddressTokenLifetimes,
        policy: P,
    ) -> Result<Self, AeadAddressTokensError> {
        let aead = backend
            .aead_algorithm(TOKEN_AEAD)
            .ok_or(AeadAddressTokensError::AeadUnsupported)?;
        let hash = backend
            .hash_algorithm(TOKEN_HASH)
            .ok_or(AeadAddressTokensError::HashUnsupported)?;
        Ok(Self {
            sealer: Arc::new(Sealer {
                backend,
                key: key.0,
                aead,
                hash,
                lifetimes,
            }),
            policy,
        })
    }
}

/// [`AeadAddressTokens::new`] cannot use the backend it was given.
#[derive(Debug, Snafu)]
pub enum AeadAddressTokensError {
    /// The backend does not support AES-256-GCM.
    #[snafu(display("the backend does not support AES-256-GCM"))]
    AeadUnsupported,
    /// The backend does not support SHA-256.
    #[snafu(display("the backend does not support SHA-256"))]
    HashUnsupported,
}

impl<C, P> AddressTokens for AeadAddressTokens<C, P>
where
    C: Aead + Hkdf + Random,
    P: TokenAddressPolicy,
{
    type NewTokenIssuer = AeadNewTokenIssuer<C>;

    fn new_token_issuer(&self) -> AeadNewTokenIssuer<C> {
        AeadNewTokenIssuer {
            sealer: Arc::clone(&self.sealer),
        }
    }

    fn issue_retry(
        &self,
        peer: &SocketAddr,
        original_dcid: &ConnectionId,
        now: UtcDateTime,
    ) -> Result<Bytes, RandomError> {
        self.sealer
            .issue(TokenKind::Retry, peer, Some(original_dcid), now)
    }

    fn validate(&self, token: &[u8], peer: &SocketAddr, now: UtcDateTime) -> TokenOutcome {
        let kind = match token.first() {
            Some(&RETRY_MARKER) => TokenKind::Retry,
            Some(&NEW_TOKEN_MARKER) => TokenKind::NewToken,
            _ => return TokenOutcome::InvalidNewToken,
        };
        let invalid = match kind {
            TokenKind::Retry => TokenOutcome::InvalidRetry,
            TokenKind::NewToken => TokenOutcome::InvalidNewToken,
        };
        let Some(opened) = self.sealer.open(kind, token) else {
            return invalid;
        };
        let lifetime = match kind {
            TokenKind::Retry => self.sealer.lifetimes.retry,
            TokenKind::NewToken => self.sealer.lifetimes.new_token,
        };
        let expires_at = expiry(opened.issued_at, lifetime);
        if now >= expires_at || !self.policy.matches(kind, &opened.address, peer) {
            return invalid;
        }
        match (kind, opened.original_dcid) {
            (TokenKind::Retry, Some(original_dcid)) => TokenOutcome::Retry { original_dcid },
            (TokenKind::NewToken, None) => TokenOutcome::NewToken(ValidNewToken {
                address: if opened.address.ip() == peer.ip() {
                    NewTokenAddress::Validated
                } else {
                    NewTokenAddress::LooselyMatched
                },
                id: NewTokenId(opened.salt),
                expires_at,
            }),
            // An authentic token was issued with the contents of its kind;
            // these arms are reached only with another key's tokens laid out
            // differently.
            _ => invalid,
        }
    }
}

/// Issues the NEW_TOKEN tokens of one connection for an
/// [`AeadAddressTokens`], sharing its key.
pub struct AeadNewTokenIssuer<C: Aead + Hkdf> {
    sealer: Arc<Sealer<C>>,
}

impl<C: Aead + Hkdf> Clone for AeadNewTokenIssuer<C> {
    fn clone(&self) -> Self {
        Self {
            sealer: Arc::clone(&self.sealer),
        }
    }
}

impl<C: Aead + Hkdf> fmt::Debug for AeadNewTokenIssuer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadNewTokenIssuer").finish_non_exhaustive()
    }
}

impl<C: Aead + Hkdf + Random> NewTokenIssuer for AeadNewTokenIssuer<C> {
    fn issue(&self, peer: &SocketAddr, now: UtcDateTime) -> Result<Bytes, RandomError> {
        self.sealer.issue(TokenKind::NewToken, peer, None, now)
    }
}

/// The AEAD that seals tokens.
const TOKEN_AEAD: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

/// The hash of the HKDF that derives each token's key.
const TOKEN_HASH: HashAlgorithm = HashAlgorithm::Sha256;

/// The first byte of a Retry token.
const RETRY_MARKER: u8 = 1;

/// The first byte of a NEW_TOKEN token.
const NEW_TOKEN_MARKER: u8 = 2;

/// The length of the random salt each token's key is derived with.
const SALT_LEN: usize = 16;

/// The HKDF info label of a token's key; the marker and the salt follow it.
const KEY_LABEL: &[u8] = b"sakuya address token";

/// The bytes before the sealed contents: the marker and the salt.
const PREFIX_LEN: usize = 1 + SALT_LEN;

/// The nonce of every token. Each key seals one token only.
const NONCE: [u8; AeadAlgorithm::NONCE_LEN] = [0; AeadAlgorithm::NONCE_LEN];

/// What every token of an [`AeadAddressTokens`] shares.
struct Sealer<C: Aead + Hkdf> {
    backend: C,
    key: Secret,
    aead: Supported<C, AeadAlgorithm>,
    hash: Supported<C, HashAlgorithm>,
    lifetimes: AddressTokenLifetimes,
}

/// The sealed contents of a token, opened.
struct Opened {
    salt: [u8; SALT_LEN],
    issued_at: UtcDateTime,
    address: SocketAddr,
    original_dcid: Option<ConnectionId>,
}

impl<C: Aead + Hkdf + Random> Sealer<C> {
    /// A token of `kind` for `peer`, carrying `original_dcid` for a Retry
    /// token.
    fn issue(
        &self,
        kind: TokenKind,
        peer: &SocketAddr,
        original_dcid: Option<&ConnectionId>,
        now: UtcDateTime,
    ) -> Result<Bytes, RandomError> {
        let salt = self.backend.random::<SALT_LEN>()?;
        let marker = marker(kind);
        let mut token = Vec::with_capacity(PREFIX_LEN + 64 + AeadAlgorithm::TAG_LEN);
        token.push(marker);
        token.extend_from_slice(&salt);
        token.extend_from_slice(&unix_millis(now).to_be_bytes());
        put_address(&mut token, peer);
        if let Some(original_dcid) = original_dcid {
            // invariant: a connection ID is at most 20 bytes.
            token.push(original_dcid.as_bytes().len() as u8);
            token.extend_from_slice(original_dcid.as_bytes());
        }
        let tag = self
            .token_key(marker, &salt)
            .seal_in_place(&NONCE, &[marker], &mut token[PREFIX_LEN..])
            // invariant: the contents are under 100 bytes, far within the
            // AEAD's limit.
            .expect("token contents are within the AEAD limit");
        token.extend_from_slice(&tag);
        Ok(Bytes::from(token))
    }
}

impl<C: Aead + Hkdf> Sealer<C> {
    /// Opens a token whose first byte says it is of `kind`; `None` when it is
    /// not authentic or not laid out as one.
    fn open(&self, kind: TokenKind, token: &[u8]) -> Option<Opened> {
        let (prefix, rest) = token.split_at_checked(PREFIX_LEN)?;
        let (sealed, tag) = rest.split_last_chunk::<{ AeadAlgorithm::TAG_LEN }>()?;
        let marker = prefix[0];
        let salt: [u8; SALT_LEN] = prefix[1..].try_into().ok()?;
        let mut contents = sealed.to_vec();
        self.token_key(marker, &salt)
            .open_in_place(&NONCE, &[marker], &mut contents, tag)
            .ok()?;
        let (issued_at, contents) = contents.split_first_chunk::<8>()?;
        let issued_at = from_unix_millis(i64::from_be_bytes(*issued_at))?;
        let (address, contents) = take_address(contents)?;
        let original_dcid = match kind {
            TokenKind::Retry => {
                let (&len, cid) = contents.split_first()?;
                if cid.len() != usize::from(len) {
                    return None;
                }
                Some(ConnectionId::new(cid).ok()?)
            }
            TokenKind::NewToken => contents.is_empty().then_some(None)?,
        };
        Some(Opened {
            salt,
            issued_at,
            address,
            original_dcid,
        })
    }

    /// The key that seals the token with `marker` and `salt`.
    fn token_key(&self, marker: u8, salt: &[u8; SALT_LEN]) -> C::Key {
        let key = self.backend.expand(
            self.hash,
            &self.key,
            &[KEY_LABEL, &[marker], salt],
            // invariant: the AES-256-GCM key length is 32, within 1..=64.
            ExpandLength::new(TOKEN_AEAD.key_len() as u8).expect("the key length is in range"),
        );
        self.backend
            .aead_key(self.aead, key.as_bytes())
            // invariant: the key was expanded to the algorithm's key length.
            .expect("the derived key has the AEAD's key length")
    }
}

fn marker(kind: TokenKind) -> u8 {
    match kind {
        TokenKind::Retry => RETRY_MARKER,
        TokenKind::NewToken => NEW_TOKEN_MARKER,
    }
}

/// When a token issued at `issued_at` stops being accepted.
fn expiry(issued_at: UtcDateTime, lifetime: Duration) -> UtcDateTime {
    let lifetime = time::Duration::try_from(lifetime).unwrap_or(time::Duration::MAX);
    issued_at.saturating_add(lifetime)
}

/// Milliseconds since the Unix epoch. Every `UtcDateTime` fits in an `i64`
/// of milliseconds.
fn unix_millis(time: UtcDateTime) -> i64 {
    (time.unix_timestamp_nanos() / 1_000_000) as i64
}

fn from_unix_millis(millis: i64) -> Option<UtcDateTime> {
    UtcDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000).ok()
}

/// The family byte of an IPv4 address.
const IPV4: u8 = 4;

/// The family byte of an IPv6 address.
const IPV6: u8 = 6;

fn put_address(out: &mut Vec<u8>, address: &SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            out.push(IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
}

fn take_address(input: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let (&family, rest) = input.split_first()?;
    let (ip, rest) = match family {
        IPV4 => {
            let (octets, rest) = rest.split_first_chunk::<4>()?;
            (IpAddr::V4(Ipv4Addr::from(*octets)), rest)
        }
        IPV6 => {
            let (octets, rest) = rest.split_first_chunk::<16>()?;
            (IpAddr::V6(Ipv6Addr::from(*octets)), rest)
        }
        _ => return None,
    };
    let (port, rest) = rest.split_first_chunk::<2>()?;
    Some((SocketAddr::new(ip, u16::from_be_bytes(*port)), rest))
}

#[cfg(test)]
mod tests;
