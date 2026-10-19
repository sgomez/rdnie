// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.dnie.Dnie (Tomás García-Merás)
// - es.gob.jmulticard.card.dnie.Dnie3 (Tomás García-Merás)
// - es.gob.jmulticard.apdu.dnie.RetriesLeftApduCommand (Tomás García-Merás, Sergio Martínez Rico)
// - es.gob.jmulticard.apdu.dnie.VerifyApduCommand (Tomás García-Merás)
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

//! The PIN channel, the retry counter and `VERIFY` sent through it, and the switch to the user
//! channel, as `Dnie` and `Dnie3` run them.

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Command, Error, StatusWord, Transport, cwa14890, files,
    key_sets::{Channel, KeySet},
    secure_messaging::SecureMessaging,
};

const VERIFY: u8 = 0x20;

/// The holder's PIN, wiped from memory when dropped.
pub struct Pin(Zeroizing<String>);

impl Pin {
    /// Wraps the PIN the holder typed.
    #[must_use]
    pub fn new(pin: String) -> Self {
        Self(Zeroizing::new(pin))
    }
}
const RETRIES_LEFT: u8 = 0x63;
const RETRIES_MASK: u8 = 0xF0;
const RETRIES_TAG: u8 = 0xC0;
const BLOCKED: StatusWord = StatusWord(0x6983);

/// Opens the PIN channel and reads how many PIN attempts are left, without sending a PIN.
pub(crate) fn retries_left(card: &mut dyn Transport, idesp: Option<&str>) -> Result<u8, Error> {
    let mut channel = open_pin_channel(card, idesp)?;
    query_retries(&mut channel, card)
}

/// Rereads the retries, sends `pin` once through the PIN channel and returns the user channel.
pub(crate) fn verify(
    card: &mut dyn Transport,
    idesp: Option<&str>,
    pin: Pin,
) -> Result<SecureMessaging, Error> {
    let mut channel = open_pin_channel(card, idesp)?;
    query_retries(&mut channel, card)?;
    let mut command = Command {
        cla: 0x00,
        ins: VERIFY,
        p1: 0x00,
        p2: 0x00,
        data: pin.0.as_bytes().to_vec(),
        le: None,
    };
    drop(pin);
    let response = channel.transmit(card, &command);
    command.data.zeroize();
    response?.into_success()?;
    open_user_channel(&mut channel, card, idesp)
}

fn query_retries(channel: &mut SecureMessaging, card: &mut dyn Transport) -> Result<u8, Error> {
    let response = channel.transmit(
        card,
        &Command {
            cla: 0x00,
            ins: VERIFY,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
            le: Some(256),
        },
    )?;
    match response.status.0.to_be_bytes() {
        [RETRIES_LEFT, sw2] if sw2 & RETRIES_MASK == RETRIES_TAG => Ok(sw2 & !RETRIES_MASK),
        _ if response.status == BLOCKED => Err(Error::PinBlocked),
        _ => Err(Error::Status(response.status)),
    }
}

/// Selects the master file, whose refusal `Dnie3` only warns about, then authenticates.
fn open_pin_channel(
    card: &mut dyn Transport,
    idesp: Option<&str>,
) -> Result<SecureMessaging, Error> {
    match files::select_master_file(card) {
        Ok(()) | Err(Error::Status(_)) => {}
        Err(error) => return Err(error),
    }
    cwa14890::open(card, KeySet::for_card(idesp, Channel::Pin))
}

/// Selects the master file through the PIN channel, as `Dnie3.openUserChannel` does, then
/// authenticates with the user keys.
fn open_user_channel(
    pin_channel: &mut SecureMessaging,
    card: &mut dyn Transport,
    idesp: Option<&str>,
) -> Result<SecureMessaging, Error> {
    pin_channel
        .transmit(card, &files::master_file_selection())?
        .into_success()?;
    cwa14890::open(card, KeySet::for_card(idesp, Channel::User))
}
