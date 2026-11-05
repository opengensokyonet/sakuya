//! CRYPTO streams and transport parameters in memory, as the receivers a
//! handshake engine is lent: a buffer per level for what a side receives
//! and for what it sends.

use bytes::{Buf, BufMut, Bytes};
use core::{
    pin::Pin,
    task::{Context, Poll},
};
use nitori_call::{BorrowedReceiver, family_receiver};
use nitori_io::{Read, Write};
use sakuya_tls::{
    client::engine::ClientTransport,
    engine::{CryptoInput, CryptoLevel, CryptoOutput},
    extension::OpaqueData,
    server::{
        engine::{Negotiated, ServerTransport},
        targets::SelectedTarget,
        ticket::TicketState,
    },
};
use std::collections::VecDeque;

/// A failure of the receivers in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Bytes of the level left were not read.
    Unread(CryptoLevel),
    /// The transport parameters were refused.
    Parameters,
}

pub fn index(level: CryptoLevel) -> usize {
    match level {
        CryptoLevel::Initial => 0,
        CryptoLevel::Handshake => 1,
        CryptoLevel::OneRtt => 2,
    }
}

pub const LEVELS: [CryptoLevel; 3] = [
    CryptoLevel::Initial,
    CryptoLevel::Handshake,
    CryptoLevel::OneRtt,
];

/// What one side receives: a buffer per level and the current level.
pub struct Incoming {
    pub levels: [VecDeque<u8>; 3],
    pub current: CryptoLevel,
}

impl Default for Incoming {
    fn default() -> Self {
        Self {
            levels: Default::default(),
            current: CryptoLevel::Initial,
        }
    }
}

family_receiver!(impl [] for Incoming);

impl Read for Incoming {
    type Error = Fault;

    fn poll_read<'v, Output: BufMut + ?Sized>(
        host: Pin<&mut BorrowedReceiver<'v, Incoming>>,
        _: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<usize, Fault>>
    where
        Self: 'v,
    {
        let incoming = host.get_pin_mut().get_mut();
        let buffer = &mut incoming.levels[index(incoming.current)];
        if buffer.is_empty() {
            return Poll::Pending;
        }
        let len = buffer.len().min(destination.remaining_mut());
        for byte in buffer.drain(..len) {
            destination.put_u8(byte);
        }
        Poll::Ready(Ok(len))
    }
}

impl CryptoInput for Incoming {
    type LevelError = Fault;

    fn move_to<'v>(
        view: Pin<&mut BorrowedReceiver<'v, Incoming>>,
        level: CryptoLevel,
    ) -> Result<(), Fault>
    where
        Self: 'v,
    {
        let incoming = view.get_pin_mut().get_mut();
        if !incoming.levels[index(incoming.current)].is_empty() {
            return Err(Fault::Unread(incoming.current));
        }
        incoming.current = level;
        Ok(())
    }
}

/// What one side sends: a buffer per level and the current level.
pub struct Outgoing {
    pub levels: [Vec<u8>; 3],
    pub current: CryptoLevel,
}

impl Default for Outgoing {
    fn default() -> Self {
        Self {
            levels: Default::default(),
            current: CryptoLevel::Initial,
        }
    }
}

family_receiver!(impl [] for Outgoing);

impl Write for Outgoing {
    type Error = Fault;

    fn poll_write<'v, Input: Buf + ?Sized>(
        host: Pin<&mut BorrowedReceiver<'v, Outgoing>>,
        _: &mut Context<'_>,
        input: &mut Input,
    ) -> Poll<Result<usize, Fault>>
    where
        Self: 'v,
    {
        let outgoing = host.get_pin_mut().get_mut();
        let buffer = &mut outgoing.levels[index(outgoing.current)];
        let len = input.remaining();
        while input.has_remaining() {
            let chunk = input.chunk();
            let chunk_len = chunk.len();
            buffer.extend_from_slice(chunk);
            input.advance(chunk_len);
        }
        Poll::Ready(Ok(len))
    }
}

impl CryptoOutput for Outgoing {
    fn move_to<'v>(view: Pin<&mut BorrowedReceiver<'v, Outgoing>>, level: CryptoLevel)
    where
        Self: 'v,
    {
        view.get_pin_mut().get_mut().current = level;
    }
}

/// The server's connection side of the transport parameters.
pub struct ServerParameters {
    pub local: Bytes,
    pub peer: Option<Bytes>,
    pub early_data: bool,
    pub refuse: bool,
}

family_receiver!(impl [] for ServerParameters);

impl ServerTransport<&'static str> for ServerParameters {
    type Error = Fault;

    fn negotiate<'v>(
        view: Pin<&mut BorrowedReceiver<'v, ServerParameters>>,
        peer: &[u8],
        _selected: &SelectedTarget<&'static str>,
        resumed: Option<&TicketState<&'static str>>,
    ) -> Result<Negotiated, Fault>
    where
        Self: 'v,
    {
        let parameters = view.get_pin_mut().get_mut();
        if parameters.refuse {
            return Err(Fault::Parameters);
        }
        parameters.peer = Some(Bytes::copy_from_slice(peer));
        let compatible =
            resumed.is_some_and(|state| state.resumable.transport_parameters == parameters.local);
        Ok(Negotiated {
            local: OpaqueData::new(parameters.local.clone()).unwrap(),
            early_data: parameters.early_data && compatible,
        })
    }
}

/// The client's connection side of the transport parameters.
pub struct ClientParameters {
    pub local: Bytes,
    pub peer: Option<Bytes>,
}

family_receiver!(impl [] for ClientParameters);

impl ClientTransport for ClientParameters {
    type Error = Fault;

    fn local<'v>(view: Pin<&mut BorrowedReceiver<'v, ClientParameters>>) -> OpaqueData<Bytes>
    where
        Self: 'v,
    {
        OpaqueData::new(view.get_pin_mut().get_mut().local.clone()).unwrap()
    }

    fn peer<'v>(
        view: Pin<&mut BorrowedReceiver<'v, ClientParameters>>,
        peer: &[u8],
    ) -> Result<(), Fault>
    where
        Self: 'v,
    {
        view.get_pin_mut().get_mut().peer = Some(Bytes::copy_from_slice(peer));
        Ok(())
    }
}
