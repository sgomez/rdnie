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

use std::{
    ffi::CString,
    ops::{Deref, DerefMut},
};

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
    /// [`Error::Transport`] if PC/SC fails and [`Error::NoDnie`] if no reader holds a DNIe.
    pub fn connect_first_dnie() -> Result<Self, Error> {
        let context = Context::establish(Scope::User).map_err(transport)?;
        let readers = context.list_readers_owned().map_err(transport)?;
        let mut failure = None;
        for reader in readers {
            let attempt = context
                .connect(&reader, ShareMode::Shared, Protocols::ANY)
                .map(|card| Connection(Some(card)))
                .and_then(|card| pcsc_atr(&card).map(|atr| (card, atr)));
            match attempt {
                Ok((card, atr)) if is_dnie(&atr) => {
                    return Ok(Self {
                        context,
                        reader,
                        card,
                    });
                }
                Ok(_) | Err(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard) => {}
                Err(error) => failure = failure.or(Some(error)),
            }
        }
        Err(failure.map_or(Error::NoDnie, transport))
    }

    /// The card's current ATR.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if PC/SC cannot read it.
    pub fn atr(&self) -> Result<Vec<u8>, Error> {
        atr(&self.card)
    }
}

/// Card handle that disconnects with `LeaveCard`, as `SmartcardIoConnection.close` does.
struct Connection(Option<Card>);

impl Connection {
    fn disconnect(&mut self, disposition: Disposition) {
        if let Some(card) = self.0.take() {
            if let Err((card, _)) = card.disconnect(disposition) {
                // Dropping it would disconnect with ResetCard.
                std::mem::forget(card);
            }
        }
    }
}

impl Deref for Connection {
    type Target = Card;

    fn deref(&self) -> &Card {
        self.0
            .as_ref()
            .expect("the card is only taken on disconnect")
    }
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Card {
        self.0
            .as_mut()
            .expect("the card is only taken on disconnect")
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.disconnect(Disposition::LeaveCard);
    }
}

impl Transport for PcscTransport {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let result = transmit(&self.card, apdu);
        recovering(result, || reconnect(&mut self.card))
    }

    /// Disconnects with `ResetCard` and reconnects with the negotiated protocol, as `SmartcardIoConnection.reset` does.
    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        let protocol = negotiated(&self.card);
        self.card.disconnect(Disposition::ResetCard);
        let card = self
            .context
            .connect(&self.reader, ShareMode::Shared, protocol)
            .map_err(transport)?;
        self.card = Connection(Some(card));
        atr(&self.card)
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let result = in_transaction(&mut self.card, body);
        recovering(result, || reconnect(&mut self.card))
    }
}

fn in_transaction<R>(
    card: &mut Card,
    body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
) -> Result<R, Error> {
    let mut transaction = InTransaction(card.transaction().map_err(transport)?);
    let result = body(&mut transaction);
    let ended = transaction
        .0
        .end(Disposition::LeaveCard)
        .map_err(|(_, error)| transport(error));
    outcome(result, ended)
}

/// PC/SC keeps answering `SCARD_W_RESET_CARD` on a handle until it reconnects.
fn recovering<R>(result: Result<R, Error>, reconnect: impl FnOnce()) -> Result<R, Error> {
    if matches!(result, Err(Error::CardReset)) {
        reconnect();
    }
    result
}

fn reconnect(card: &mut Card) {
    let protocol = negotiated(card);
    // A failed reconnect surfaces on the next operation.
    let _ = card.reconnect(ShareMode::Shared, protocol, Disposition::LeaveCard);
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
    let response = card.transmit(apdu, &mut buffer).map_err(transport)?;
    Ok(response.to_vec())
}

fn atr(card: &Card) -> Result<Vec<u8>, Error> {
    pcsc_atr(card).map_err(transport)
}

fn pcsc_atr(card: &Card) -> Result<Vec<u8>, pcsc::Error> {
    card.get_attribute_owned(Attribute::AtrString)
}

#[allow(clippy::needless_pass_by_value)]
fn transport(error: pcsc::Error) -> Error {
    match error {
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
            transport(pcsc::Error::ResetCard),
            Error::CardReset
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
        assert!(!reconnects(Ok(())));
    }

    #[test]
    fn reports_other_failures_as_transport_errors() {
        assert!(matches!(
            transport(pcsc::Error::NoSmartcard),
            Error::Transport(_)
        ));
    }
}
