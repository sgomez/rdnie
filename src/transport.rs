// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.connection.AbstractApduConnectionIso7816 (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.GetResponseApduCommand (Carlos Gamuci Millán, Tomás García-Merás)
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

use zeroize::Zeroize;

use crate::{Command, Error, Response};

/// Channel the APDUs travel through: PC/SC in production, an emulator in tests.
///
/// After [`Error::CardRemoved`] the transport is spent: open a new transport and a new session.
pub trait Transport {
    /// Sends a raw APDU and returns the response including its status word.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the APDU does not reach the card, [`Error::CardReset`] if the
    /// card was reset since the last command and [`Error::CardRemoved`] if it left the reader.
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error>;

    /// Resets the card and returns its ATR.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the card cannot be reset, [`Error::NoReader`] or
    /// [`Error::NoCard`] if the reader or card is gone on reconnecting. After a failed reset,
    /// every call returns that error until a later reset reconnects.
    fn reset(&mut self) -> Result<Vec<u8>, Error>;

    /// Runs `body` with exclusive access to the card.
    ///
    /// # Errors
    ///
    /// Those of `body`, [`Error::Transport`] if the transaction cannot start or end,
    /// [`Error::CardReset`] if the card was reset before it started and [`Error::CardRemoved`]
    /// if it left the reader.
    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error>
    where
        Self: Sized;

    /// Sends a command, completing `61xx` with `GET RESPONSE` and resending a plain command on `6Cxx`.
    ///
    /// A command gets at most 256 `GET RESPONSE` and at most 2 consecutive `6Cxx` resends.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transmit_raw`], [`Command::to_bytes`] and [`Response::parse`], and
    /// [`Error::Status`] with the last status word if the card keeps asking past a bound.
    fn transmit(&mut self, command: &Command) -> Result<Response, Error> {
        let mut resent = None;
        let result = follow(self, command, &mut resent);
        if let Some(mut copy) = resent {
            copy.data.zeroize();
        }
        result
    }
}

/// Keeps the latest resent copy in `resent`, so the caller wipes it on every exit.
fn follow<T: Transport + ?Sized>(
    transport: &mut T,
    command: &Command,
    resent: &mut Option<Command>,
) -> Result<Response, Error> {
    let mut data = Vec::new();
    let mut get_responses = 0;
    let mut resends = 0;
    loop {
        let sent = resent.as_ref().unwrap_or(command);
        let response = Response::parse(&transport.transmit_raw(&sent.to_bytes()?)?)?;
        let [sw1, sw2] = response.status.0.to_be_bytes();
        if sw1 == WRONG_LENGTH && sent.cla == PLAIN_CLA {
            if resends == MAX_RESENDS {
                return Err(Error::Status(response.status));
            }
            resends += 1;
            let next = Command {
                le: Some(short_le(sw2)),
                ..sent.clone()
            };
            if let Some(mut old) = resent.replace(next) {
                old.data.zeroize();
            }
            continue;
        }
        resends = 0;
        data.extend(response.data);
        if sw1 != RESPONSE_PENDING {
            return Ok(Response {
                data,
                status: response.status,
            });
        }
        if get_responses == MAX_GET_RESPONSES {
            return Err(Error::Status(response.status));
        }
        get_responses += 1;
        if let Some(mut old) = resent.replace(get_response(sw2)) {
            old.data.zeroize();
        }
    }
}

const RESPONSE_PENDING: u8 = 0x61;
const MAX_GET_RESPONSES: usize = 256;
pub(crate) const MAX_RESENDS: usize = 2;
pub(crate) const WRONG_LENGTH: u8 = 0x6C;
// Protected commands are resent by the secure channel, not here.
const PLAIN_CLA: u8 = 0x00;

fn get_response(le: u8) -> Command {
    Command {
        cla: PLAIN_CLA,
        ins: 0xC0,
        p1: 0x00,
        p2: 0x00,
        data: vec![],
        le: Some(short_le(le)),
    }
}

pub(crate) fn short_le(le: u8) -> u16 {
    match le {
        0 => 256,
        le => le.into(),
    }
}
