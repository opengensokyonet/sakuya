//! What the connection keeps about each logical link it uses, besides the
//! anti-amplification limit.

use super::amplification::AddressValidation;

/// The connection's one clone of a logical link, in the entry of that
/// logical link: every link path over it sends through this clone.
#[derive(Debug)]
pub struct LinkClone<Lk>(pub Lk);

/// What the connection knows about a logical link.
///
/// It belongs to the connection, not to the link: whether an address is
/// validated depends on what this connection has seen, such as a token
/// that the endpoint checked before making it (RFC 9000 §8.1.2, §8.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFacts {
    /// Whether the address of the logical link is validated.
    pub validation: AddressValidation,
}

/// What the connection was made with for its first logical link, kept in
/// the connection node until the entry of that link is built, which takes
/// the facts.
#[derive(Debug)]
pub struct FirstLinkStart {
    facts: Option<LinkFacts>,
}

impl FirstLinkStart {
    /// The connection is made with `facts` about its first logical link.
    pub fn new(facts: LinkFacts) -> Self {
        Self { facts: Some(facts) }
    }

    /// The facts about the first logical link, the first time they are
    /// asked for; `None` afterwards.
    pub fn take_facts(&mut self) -> Option<LinkFacts> {
        self.facts.take()
    }
}
