//! Transport parameters in a connection: the peer's, and each part's own.

/// The peer's transport parameters: one component of the connection node,
/// read by whoever uses them.
///
/// `S` is the slots of the transport parameter types of the parts of the
/// connection. Values are written only after every part has checked its
/// own, so whatever reads them reads checked parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransportParameters<S> {
    /// Not known yet.
    NotYet,
    /// A client that offers 0-RTT: the slots remembered from the earlier
    /// connection, only those whose parameters 0-RTT must remember (RFC
    /// 9000 §7.4.1); they govern 0-RTT packets only.
    Remembered(S),
    /// The parameters the peer sent in this handshake.
    Known(S),
}

impl<S> PeerTransportParameters<S> {
    /// The slots, remembered or known, if there are any.
    pub fn slots(&self) -> Option<&S> {
        match self {
            Self::NotYet => None,
            Self::Remembered(slots) | Self::Known(slots) => Some(slots),
        }
    }

    /// The slots the peer sent in this handshake, once they are known.
    pub fn known(&self) -> Option<&S> {
        match self {
            Self::Known(slots) => Some(slots),
            Self::NotYet | Self::Remembered(_) => None,
        }
    }

    /// Remember the slots of an earlier connection, as a client that offers
    /// 0-RTT does before the peer's parameters are known.
    pub fn remember(&mut self, slots: S) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "remembering parameters over known ones"
        );
        *self = Self::Remembered(slots);
    }

    /// Set the parameters the peer sent in this handshake.
    pub fn set_known(&mut self, slots: S) {
        debug_assert!(
            !matches!(self, Self::Known(_)),
            "the peer's parameters are known twice"
        );
        *self = Self::Known(slots);
    }
}

/// The transport parameters a part sends: one configuration component of
/// that part in the connection node.
///
/// `P` is the part's own transport parameters. They are given when the
/// connection is made and stay as they were sent for the rest of the
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTransportParameters<P> {
    /// As configured; the handshake has not sent them yet, and a server
    /// may still settle them by the application protocol it selects and by
    /// whether it resumes.
    Configured(P),
    /// As sent; they no longer change.
    Sent(P),
}

impl<P> LocalTransportParameters<P> {
    /// The parameters as sent, once they are.
    pub fn sent(&self) -> Option<&P> {
        match self {
            Self::Sent(parameters) => Some(parameters),
            Self::Configured(_) => None,
        }
    }

    /// The parameters as configured, while they are not sent.
    pub fn configured(&self) -> Option<&P> {
        match self {
            Self::Configured(parameters) => Some(parameters),
            Self::Sent(_) => None,
        }
    }

    /// The parameters are sent as `settle` makes them from the configured
    /// ones; they no longer change.
    pub fn send_with(&mut self, settle: impl FnOnce(&P) -> P) {
        match self {
            Self::Configured(configured) => {
                let sent = settle(configured);
                *self = Self::Sent(sent);
            }
            Self::Sent(_) => debug_assert!(false, "transport parameters are sent twice"),
        }
    }
}
