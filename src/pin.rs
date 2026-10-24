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
    key_sets::{Channel, ComponentRoots, KeyGeneration, KeySet},
    secure_messaging::SecureChannel,
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

    /// Refuses a PIN that is not 8 to 16 characters, counted as UTF-16 units, before any APDU is
    /// sent.
    pub(crate) fn check_format(&self) -> Result<(), Error> {
        if PIN_LENGTH.contains(&self.0.encode_utf16().count()) {
            Ok(())
        } else {
            Err(Error::InvalidPinFormat)
        }
    }

    /// The low byte of each UTF-16 unit, as `VerifyApduCommand` casts each `char`.
    fn encode(&self) -> Vec<u8> {
        self.0
            .encode_utf16()
            .map(|unit| unit.to_le_bytes()[0])
            .collect()
    }
}

const PIN_LENGTH: std::ops::RangeInclusive<usize> = 8..=16;
const RETRIES_LEFT: u8 = 0x63;
const RETRIES_MASK: u8 = 0xF0;
const RETRIES_TAG: u8 = 0xC0;
const BLOCKED: StatusWord = StatusWord(0x6983);

/// Opens the PIN channel and reads how many PIN attempts are left, without sending a PIN.
pub(crate) fn retries_left(
    card: &mut dyn Transport,
    generation: KeyGeneration,
    roots: &ComponentRoots,
) -> Result<u8, Error> {
    let mut channel = open_pin_channel(card, generation, roots)?;
    query_retries(&mut channel)
}

/// Rereads the retries and, if they are still `expected` and not zero, sends `pin` once through
/// the PIN channel and returns the user channel over `card`.
pub(crate) fn verify<'a>(
    card: &'a mut dyn Transport,
    generation: KeyGeneration,
    roots: &ComponentRoots,
    pin: Pin,
    expected: u8,
) -> Result<SecureChannel<'a>, Error> {
    let mut channel = open_pin_channel(card, generation, roots)?;
    let retries = query_retries(&mut channel)?;
    if retries == 0 {
        return Err(Error::PinBlocked);
    }
    if retries != expected {
        return Err(Error::PinRetriesChanged);
    }
    let mut command = Command {
        cla: 0x00,
        ins: VERIFY,
        p1: 0x00,
        p2: 0x00,
        data: pin.encode(),
        le: None,
    };
    drop(pin);
    let response = channel.transmit(&command);
    command.data.zeroize();
    let response = response?;
    if response.status != StatusWord::SUCCESS {
        return Err(refusal(response.status));
    }
    open_user_channel(channel, generation, roots)
}

/// What a status word other than success means for a `VERIFY` that carried the PIN.
fn refusal(status: StatusWord) -> Error {
    match retries_in(status) {
        Some(retries_left) if retries_left > 0 => Error::WrongPin { retries_left },
        Some(_) => Error::PinBlocked,
        None if status == BLOCKED => Error::PinBlocked,
        None => Error::Status(status),
    }
}

fn retries_in(status: StatusWord) -> Option<u8> {
    match status.0.to_be_bytes() {
        [RETRIES_LEFT, sw2] if sw2 & RETRIES_MASK == RETRIES_TAG => Some(sw2 & !RETRIES_MASK),
        _ => None,
    }
}

fn query_retries(channel: &mut SecureChannel<'_>) -> Result<u8, Error> {
    let response = channel.transmit(&Command {
        cla: 0x00,
        ins: VERIFY,
        p1: 0x00,
        p2: 0x00,
        data: vec![],
        le: Some(256),
    })?;
    match retries_in(response.status) {
        Some(retries) => Ok(retries),
        None if response.status == BLOCKED => Err(Error::PinBlocked),
        None => Err(Error::Status(response.status)),
    }
}

/// Selects the master file, whose refusal `Dnie3` only warns about, then authenticates.
fn open_pin_channel<'a>(
    card: &'a mut dyn Transport,
    generation: KeyGeneration,
    roots: &ComponentRoots,
) -> Result<SecureChannel<'a>, Error> {
    match files::select_master_file(card) {
        Ok(()) | Err(Error::Status(_)) => {}
        Err(error) => return Err(error),
    }
    cwa14890::open(
        card,
        KeySet::for_generation(generation, Channel::Pin),
        roots,
    )
}

/// Selects the master file and authenticates with the user keys, all through the PIN channel, as
/// `Dnie3.openUserChannel` does, and drops the PIN channel.
fn open_user_channel<'a>(
    mut pin_channel: SecureChannel<'a>,
    generation: KeyGeneration,
    roots: &ComponentRoots,
) -> Result<SecureChannel<'a>, Error> {
    pin_channel
        .transmit(&files::master_file_selection())?
        .into_success()?;
    cwa14890::open_inside(
        pin_channel,
        KeySet::for_generation(generation, Channel::User),
        roots,
    )
}
