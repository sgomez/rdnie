// Derived from JMulticard: see LICENSE.jmulticard.md.

use std::{
    ffi::{CStr, CString},
    time::Duration,
};

use pcsc::{
    Attribute, Card, Context, Disposition, MAX_BUFFER_SIZE, Protocol, Protocols, ReaderState,
    Scope, ShareMode, State, Transaction,
};

use crate::{Error, Transport, is_dnie};

/// PC/SC transport: `PCSC.framework` on macOS, WinSCard on Windows and pcsc-lite on Linux.
pub struct PcscTransport {
    context: Context,
    reader: CString,
    card: Connection,
}

impl PcscTransport {
    /// Connects in shared mode to the first reader holding a DNIe.
    ///
    /// Reads each reader's ATR without resetting the card, and takes the first reader whose
    /// ATR is a DNIe, burned ones included, as `DnieFactory.getDnie` does.
    ///
    /// # Errors
    ///
    /// [`Error::NoReader`] if the system has no reader, [`Error::NotDnie`] if a reader holds a
    /// card that is not a DNIe, [`Error::NoCard`] if every reader is empty, and otherwise
    /// [`Error::Transport`] with the first PC/SC failure.
    pub fn connect_first_dnie() -> Result<Self, Error> {
        let context = Context::establish(Scope::User).map_err(connecting)?;
        let readers = context.list_readers_owned().map_err(connecting)?;
        let (reader, card) = first_dnie(readers.into_iter().map(|reader| probe(&context, reader)))?;
        Ok(Self {
            context,
            reader,
            card,
        })
    }

    /// Lists the names of the system's readers, in system order.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if PC/SC fails. No readers is an empty list.
    pub fn readers() -> Result<Vec<String>, Error> {
        let context = Context::establish(Scope::User).map_err(connecting)?;
        reader_names(context.list_readers_owned())
    }

    /// Connects in shared mode to the named reader, without checking the ATR.
    ///
    /// The session classifies the card when it opens.
    ///
    /// # Errors
    ///
    /// [`Error::NoReader`] if the system has no reader of that name, [`Error::NoCard`] if the
    /// reader is empty, and otherwise [`Error::Transport`].
    pub fn connect(reader: &str) -> Result<Self, Error> {
        let reader = reader_cstring(reader)?;
        let context = Context::establish(Scope::User).map_err(connecting)?;
        let card = connect_shared(&context, &reader, Protocols::ANY).map_err(connecting)?;
        Ok(Self {
            context,
            reader,
            card: Connection(Ok(card)),
        })
    }

    /// The name of the reader this transport is connected to.
    #[must_use]
    pub fn reader(&self) -> String {
        self.reader.to_string_lossy().into_owned()
    }
}

fn reader_names(readers: Result<Vec<CString>, pcsc::Error>) -> Result<Vec<String>, Error> {
    match readers {
        Ok(readers) => Ok(readers
            .into_iter()
            .map(|reader| reader.to_string_lossy().into_owned())
            .collect()),
        Err(pcsc::Error::NoReadersAvailable) => Ok(Vec::new()),
        Err(error) => Err(connecting(error)),
    }
}

fn reader_cstring(name: &str) -> Result<CString, Error> {
    CString::new(name).map_err(|_| Error::NoReader)
}

/// Departs from `SmartcardIoConnection`: asks for the protocols the cached ATR offers instead of
/// `ANY`, which macOS's own CCID driver serves with T=1 only, failing on a T=0-only DNIe.
fn connect_shared(
    context: &Context,
    reader: &CStr,
    protocols: Protocols,
) -> Result<Card, pcsc::Error> {
    let protocols = match (protocols, cached_atr(context, reader)) {
        (Protocols::ANY, Some(atr)) => offered_protocols(&atr),
        (protocols, _) => protocols,
    };
    context.connect(reader, ShareMode::Shared, protocols)
}

/// The ATR PC/SC keeps for the reader, readable while the card is powered down.
fn cached_atr(context: &Context, reader: &CStr) -> Option<Vec<u8>> {
    let mut states = [ReaderState::new(reader, State::UNAWARE)];
    context
        .get_status_change(Duration::ZERO, &mut states)
        .ok()?;
    Some(states[0].atr().to_vec())
}

/// T=0 when the ATR has no TD1, as ISO 7816-3 reads it; otherwise PC/SC chooses.
fn offered_protocols(atr: &[u8]) -> Protocols {
    match atr.get(1) {
        Some(format) if format & 0x80 == 0 => Protocols::T0,
        _ => Protocols::ANY,
    }
}

/// What connecting to one reader found.
enum Probe<C> {
    Card(C, Vec<u8>),
    Empty,
    Failed(pcsc::Error),
}

fn probe(context: &Context, reader: CString) -> Probe<(CString, Connection)> {
    let attempt = connect_shared(context, &reader, Protocols::ANY).and_then(|card| {
        let atr = pcsc_atr(&card);
        let card = Connection(Ok(card));
        atr.map(|atr| (card, atr))
    });
    match attempt {
        Ok((card, atr)) => Probe::Card((reader, card), atr),
        Err(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard) => Probe::Empty,
        Err(error) => Probe::Failed(error),
    }
}

/// The first card with a DNIe ATR, or the error `DnieFactory.getDnie` gives for the readers.
fn first_dnie<C>(probes: impl IntoIterator<Item = Probe<C>>) -> Result<C, Error> {
    let mut readers = 0;
    let mut wrong_card = false;
    let mut failure = None;
    for probe in probes {
        readers += 1;
        match probe {
            Probe::Card(card, atr) if is_dnie(&atr) => return Ok(card),
            Probe::Card(..) => wrong_card = true,
            Probe::Empty => {}
            Probe::Failed(error) => failure = failure.or(Some(error)),
        }
    }
    Err(match failure {
        _ if readers == 0 => Error::NoReader,
        _ if wrong_card => Error::NotDnie,
        None => Error::NoCard,
        Some(error) => Error::Transport(error.to_string()),
    })
}

/// Card handle that disconnects with `LeaveCard`, as `SmartcardIoConnection.close` does.
///
/// Holds why the last reconnect failed instead of a handle, so later calls report it.
struct Connection(Result<Card, pcsc::Error>);

impl Connection {
    fn card(&self) -> Result<&Card, Error> {
        usable(&self.0)
    }

    fn card_mut(&mut self) -> Result<&mut Card, Error> {
        usable_mut(&mut self.0)
    }

    fn disconnect(&mut self, disposition: Disposition) {
        if let Ok(card) = std::mem::replace(&mut self.0, Err(pcsc::Error::InvalidHandle)) {
            if let Err((card, _)) = card.disconnect(disposition) {
                // Dropping it would disconnect with ResetCard.
                std::mem::forget(card);
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.disconnect(Disposition::LeaveCard);
    }
}

fn usable<C>(handle: &Result<C, pcsc::Error>) -> Result<&C, Error> {
    handle.as_ref().map_err(|error| connecting(*error))
}

fn usable_mut<C>(handle: &mut Result<C, pcsc::Error>) -> Result<&mut C, Error> {
    handle.as_mut().map_err(|error| connecting(*error))
}

/// Replaces the handle with a new connection, keeping the failure if there is none.
fn reopen<C>(
    handle: &mut Result<C, pcsc::Error>,
    connect: impl FnOnce() -> Result<C, pcsc::Error>,
) -> Result<&C, Error> {
    *handle = connect();
    usable(handle)
}

impl Transport for PcscTransport {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let result = transmit(self.card.card()?, apdu);
        let result = removed_if_empty(result, || reader_empty(&self.context, &self.reader));
        recovering(result, || reconnect(&mut self.card))
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        atr(self.card.card()?)
    }

    /// Disconnects with `ResetCard` and reconnects to the same reader with the negotiated
    /// protocol, as `SmartcardIoConnection.reset` does; also reconnects after a failed reset.
    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        let protocol = self.card.card().map_or(Protocols::ANY, negotiated);
        self.card.disconnect(Disposition::ResetCard);
        let (context, reader) = (&self.context, &self.reader);
        atr(reopen(&mut self.card.0, || {
            connect_shared(context, reader, protocol)
        })?)
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let result = in_transaction(self.card.card_mut()?, body);
        let result = removed_if_empty(result, || reader_empty(&self.context, &self.reader));
        recovering(result, || reconnect(&mut self.card))
    }
}

/// Some PC/SC stacks answer a pulled card with another code, such as macOS with
/// `SCARD_E_NOT_TRANSACTED`.
fn removed_if_empty<R>(result: Result<R, Error>, empty: impl FnOnce() -> bool) -> Result<R, Error> {
    match result {
        Err(Error::Transport(_)) if empty() => Err(Error::CardRemoved),
        result => result,
    }
}

/// Asks the context, since the card's handle may no longer answer.
fn reader_empty(context: &Context, reader: &CStr) -> bool {
    let mut states = [ReaderState::new(reader, State::UNAWARE)];
    context
        .get_status_change(Duration::ZERO, &mut states)
        .is_ok()
        && states[0].event_state().contains(State::EMPTY)
}

fn in_transaction<R>(
    card: &mut Card,
    body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
) -> Result<R, Error> {
    let mut transaction = InTransaction(card.transaction().map_err(connected)?);
    let result = body(&mut transaction);
    let ended = transaction
        .0
        .end(Disposition::LeaveCard)
        .map_err(|(_, error)| connected(error));
    outcome(result, ended)
}

/// PC/SC keeps answering `SCARD_W_RESET_CARD` on a handle until it reconnects.
fn recovering<R>(result: Result<R, Error>, reconnect: impl FnOnce()) -> Result<R, Error> {
    if matches!(result, Err(Error::CardReset)) {
        reconnect();
    }
    result
}

fn reconnect(connection: &mut Connection) {
    if let Ok(card) = connection.card_mut() {
        let protocol = negotiated(card);
        // A failed reconnect surfaces on the next operation.
        let _ = card.reconnect(ShareMode::Shared, protocol, Disposition::LeaveCard);
    }
}

fn negotiated(card: &Card) -> Protocols {
    match card
        .status2_owned()
        .ok()
        .and_then(|status| status.protocol2())
    {
        Some(Protocol::T0) => Protocols::T0,
        Some(Protocol::T1) => Protocols::T1,
        Some(Protocol::RAW) => Protocols::RAW,
        None => Protocols::ANY,
    }
}

fn outcome<R>(result: Result<R, Error>, ended: Result<(), Error>) -> Result<R, Error> {
    let value = result?;
    ended.map(|()| value)
}

/// The card while a PC/SC transaction holds it.
struct InTransaction<'card>(Transaction<'card>);

impl Transport for InTransaction<'_> {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        transmit(&self.0, apdu)
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        atr(&self.0)
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        Err(Error::Transport(
            "cannot reset the card inside a transaction".into(),
        ))
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

fn transmit(card: &Card, apdu: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buffer = [0; MAX_BUFFER_SIZE];
    let response = card.transmit(apdu, &mut buffer).map_err(connected)?;
    Ok(response.to_vec())
}

fn atr(card: &Card) -> Result<Vec<u8>, Error> {
    pcsc_atr(card).map_err(connected)
}

fn pcsc_atr(card: &Card) -> Result<Vec<u8>, pcsc::Error> {
    card.get_attribute_owned(Attribute::AtrString)
}

fn connecting(error: pcsc::Error) -> Error {
    match error {
        pcsc::Error::NoReadersAvailable | pcsc::Error::UnknownReader => Error::NoReader,
        pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard => Error::NoCard,
        error => Error::Transport(error.to_string()),
    }
}

fn connected(error: pcsc::Error) -> Error {
    match error {
        pcsc::Error::RemovedCard | pcsc::Error::NoSmartcard => Error::CardRemoved,
        pcsc::Error::ResetCard => Error::CardReset,
        error => Error::Transport(error.to_string()),
    }
}

#[cfg(test)]
mod tests;
