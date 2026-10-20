// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection, module jmulticard-jsr268 (Tomás García-Merás)
// rdnie takes the EUPL 1.1+ branch of the dual licence below.
//
// Controlador Java de la Secretaria de Estado de Administraciones Publicas
// para el DNI electronico.
//
// El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
// que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
// para la realizacion de procesos de autenticacion, firma electronica y validacion
// de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
// el acceso a los certificados y claves del DNI electronico, asi como la realizacion
// de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
// sido disenado para su funcionamiento independiente del sistema operativo final.
//
// Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
// e Impulso de la Administracion Electronica
//
// Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
// o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
// licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
// en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
// su compatibilidad con otros componentes.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// Lesser GNU General Public License publicada por la Free Software Foundation,
// tanto en la version 2.1 de la Licencia, o en una version posterior.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// European Union Public License publicada por la Comision Europea,
// tanto en la version 1.1 de la Licencia, o en una version posterior.
//
// Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
//
// Deberia recibir una copia de la European Union Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
//
// Este programa es distribuido con la esperanza de que sea util, pero
// SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
// o idoneidad para un proposito particular.

use std::ffi::CString;

use pcsc::{
    Attribute, Card, Context, Disposition, MAX_BUFFER_SIZE, Protocol, Protocols, Scope, ShareMode,
    Transaction,
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
    /// # Errors
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

    /// The card's current ATR.
    ///
    /// # Errors
    ///
    /// [`Error::CardRemoved`] if the card left the reader, [`Error::CardReset`] if it was reset,
    /// and [`Error::Transport`] if PC/SC fails otherwise.
    pub fn atr(&self) -> Result<Vec<u8>, Error> {
        atr(self.card.card()?)
    }
}

/// What connecting to one reader found.
enum Probe<C> {
    Card(C, Vec<u8>),
    Empty,
    Failed(pcsc::Error),
}

fn probe(context: &Context, reader: CString) -> Probe<(CString, Connection)> {
    let attempt = context
        .connect(&reader, ShareMode::Shared, Protocols::ANY)
        .and_then(|card| {
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
        recovering(result, || reconnect(&mut self.card))
    }

    /// Disconnects with `ResetCard` and reconnects to the same reader with the negotiated
    /// protocol, as `SmartcardIoConnection.reset` does; also reconnects after a failed reset.
    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        let protocol = self.card.card().map_or(Protocols::ANY, negotiated);
        self.card.disconnect(Disposition::ResetCard);
        let (context, reader) = (&self.context, &self.reader);
        atr(reopen(&mut self.card.0, || {
            context.connect(reader, ShareMode::Shared, protocol)
        })?)
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let result = in_transaction(self.card.card_mut()?, body);
        recovering(result, || reconnect(&mut self.card))
    }
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
        pcsc::Error::NoSmartcard => Error::NoCard,
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
mod tests {
    use super::*;

    #[test]
    fn reports_card_reset_as_its_own_error() {
        assert!(matches!(
            connected(pcsc::Error::ResetCard),
            Error::CardReset
        ));
    }

    #[test]
    fn reports_a_missing_reader_while_connecting() {
        assert!(matches!(
            connecting(pcsc::Error::NoReadersAvailable),
            Error::NoReader
        ));
        assert!(matches!(
            connecting(pcsc::Error::UnknownReader),
            Error::NoReader
        ));
    }

    #[test]
    fn reports_an_empty_reader_while_connecting() {
        assert!(matches!(
            connecting(pcsc::Error::NoSmartcard),
            Error::NoCard
        ));
    }

    #[test]
    fn reports_other_failures_while_connecting_as_transport_errors() {
        assert!(matches!(
            connecting(pcsc::Error::SharingViolation),
            Error::Transport(_)
        ));
    }

    #[test]
    fn reports_a_removed_card_while_connected() {
        assert!(matches!(
            connected(pcsc::Error::RemovedCard),
            Error::CardRemoved
        ));
        assert!(matches!(
            connected(pcsc::Error::NoSmartcard),
            Error::CardRemoved
        ));
    }

    #[test]
    fn keeps_the_body_error_over_a_failed_end() {
        let outcome = outcome::<()>(Err(Error::CardReset), Err(Error::Transport("end".into())));
        assert!(matches!(outcome, Err(Error::CardReset)));
    }

    #[test]
    fn reports_a_failed_end_after_a_successful_body() {
        let outcome = outcome(Ok(1), Err(Error::Transport("end".into())));
        assert!(matches!(outcome, Err(Error::Transport(_))));
    }

    #[test]
    fn reconnects_only_after_a_card_reset() {
        let reconnects = |result: Result<(), Error>| {
            let mut reconnected = false;
            let _ = recovering(result, || reconnected = true);
            reconnected
        };
        assert!(reconnects(Err(Error::CardReset)));
        assert!(!reconnects(Err(Error::ChannelLost)));
        assert!(!reconnects(Err(Error::CardRemoved)));
        assert!(!reconnects(Ok(())));
    }

    #[test]
    fn a_failed_reopen_leaves_no_handle_and_later_calls_fail() {
        let mut handle = Ok("A");
        let reopened = reopen(&mut handle, || Err(pcsc::Error::NoSmartcard)).copied();
        assert!(matches!(reopened, Err(Error::NoCard)));
        assert!(matches!(usable(&handle), Err(Error::NoCard)));
        assert!(matches!(usable_mut(&mut handle), Err(Error::NoCard)));
    }

    #[test]
    fn a_lost_handle_reports_the_reconnect_failure_as_mapped() {
        let mut handle = Ok("A");
        let _ = reopen(&mut handle, || Err(pcsc::Error::UnknownReader));
        assert!(matches!(usable(&handle), Err(Error::NoReader)));
        let _ = reopen(&mut handle, || Err(pcsc::Error::SharingViolation));
        assert!(matches!(usable(&handle), Err(Error::Transport(_))));
    }

    #[test]
    fn a_later_reopen_restores_the_handle() {
        let mut handle = Ok("A");
        let _ = reopen(&mut handle, || Err(pcsc::Error::NoSmartcard));
        assert_eq!(reopen(&mut handle, || Ok("A")).ok(), Some(&"A"));
        assert_eq!(usable(&handle).ok(), Some(&"A"));
    }

    const DNIE_3: [u8; 20] = [
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55,
        0x04, 0x21, 0x03, 0x90, 0x00,
    ];

    const BURNED_DNIE: [u8; 20] = [
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55,
        0x04, 0x21, 0x03, 0x65, 0x81,
    ];

    const OTHER_CARD: [u8; 4] = [0x3B, 0x02, 0x14, 0x50];

    fn card(reader: &str, atr: &[u8]) -> Probe<String> {
        Probe::Card(reader.to_owned(), atr.to_vec())
    }

    #[test]
    fn scanning_no_readers_finds_no_reader() {
        assert!(matches!(first_dnie::<String>([]), Err(Error::NoReader)));
    }

    #[test]
    fn scanning_takes_the_reader_with_a_dnie() {
        let scan = first_dnie([card("A", &DNIE_3)]);
        assert_eq!(scan.ok().as_deref(), Some("A"));
    }

    #[test]
    fn scanning_takes_a_burned_dnie_so_the_session_reports_it() {
        let scan = first_dnie([Probe::Empty, card("B", &BURNED_DNIE)]);
        assert_eq!(scan.ok().as_deref(), Some("B"));
    }

    #[test]
    fn scanning_prefers_a_wrong_card_over_an_empty_reader() {
        let scan = first_dnie([Probe::Empty, card("B", &OTHER_CARD), Probe::Empty]);
        assert!(matches!(scan, Err(Error::NotDnie)));
    }

    #[test]
    fn scanning_only_empty_readers_finds_no_card() {
        let scan = first_dnie::<String>([Probe::Empty, Probe::Empty]);
        assert!(matches!(scan, Err(Error::NoCard)));
    }

    #[test]
    fn scanning_reports_the_first_failure_when_no_card_is_found() {
        let scan = first_dnie::<String>([
            Probe::Empty,
            Probe::Failed(pcsc::Error::SharingViolation),
            Probe::Failed(pcsc::Error::ReaderUnavailable),
        ]);
        let Err(Error::Transport(message)) = scan else {
            panic!("expected a transport error, got {scan:?}");
        };
        assert_eq!(message, pcsc::Error::SharingViolation.to_string());
    }

    #[test]
    fn scanning_takes_a_dnie_after_a_failing_reader() {
        let scan = first_dnie([
            Probe::Failed(pcsc::Error::SharingViolation),
            card("B", &DNIE_3),
        ]);
        assert_eq!(scan.ok().as_deref(), Some("B"));
    }

    #[test]
    fn reports_other_failures_while_connected_as_transport_errors() {
        assert!(matches!(
            connected(pcsc::Error::SharingViolation),
            Error::Transport(_)
        ));
    }
}
