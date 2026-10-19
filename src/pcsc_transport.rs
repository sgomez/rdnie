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

use pcsc::{
    Attribute, Card, Context, Disposition, MAX_BUFFER_SIZE, Protocols, Scope, ShareMode,
    Transaction,
};

use crate::{Error, Transport, is_dnie};

/// PC/SC transport: `PCSC.framework` on macOS, WinSCard on Windows and pcsc-lite on Linux.
pub struct PcscTransport {
    card: Card,
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
        readers
            .iter()
            .filter_map(|reader| {
                context
                    .connect(reader, ShareMode::Shared, Protocols::ANY)
                    .ok()
            })
            .find(|card| atr(card).is_ok_and(|atr| is_dnie(&atr)))
            .map(|card| Self { card })
            .ok_or(Error::NoDnie)
    }
}

impl Transport for PcscTransport {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        transmit(&self.card, apdu)
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.card
            .reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard)
            .map_err(transport)?;
        atr(&self.card)
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let mut transaction = InTransaction(self.card.transaction().map_err(transport)?);
        let result = body(&mut transaction);
        let ended = transaction
            .0
            .end(Disposition::LeaveCard)
            .map_err(|(_, error)| transport(error));
        outcome(result, ended)
    }
}

/// The body's own error wins: a reset card also fails to end its transaction, which would hide it.
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
        self.0
            .reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard)
            .map_err(transport)?;
        atr(&self.0)
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
    card.get_attribute_owned(Attribute::AtrString)
        .map_err(transport)
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
    fn reports_other_failures_as_transport_errors() {
        assert!(matches!(
            transport(pcsc::Error::NoSmartcard),
            Error::Transport(_)
        ));
    }
}
