// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.iso7816four.AbstractIso7816FourCard (Tomás García-Merás, Alberto Martínez)
// - es.gob.jmulticard.apdu.iso7816four.SelectFileApduResponse (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.SelectDfByNameApduCommand (Carlos Gamuci Millán, Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.SelectFileByIdApduCommand (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.ReadBinaryApduCommand (Tomás García-Merás)
// - es.gob.jmulticard.card.Location (Alberto Martínez, Tomás García-Merás)
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

//! Plain file access below any secure channel: SELECT by name or path, and chunked READ BINARY.

use crate::{Command, Error, StatusWord, Transport};

const MASTER_FILE_NAME: &[u8] = b"Master.File";
const MASTER_FILE_ID: [u8; 2] = [0x3F, 0x00];
const MAX_READ_CHUNK: usize = 0xDE;
const SELECT: u8 = 0xA4;
const READ_BINARY: u8 = 0xB0;
const EOF_REACHED: StatusWord = StatusWord(0x6282);
const OFFSET_OUTSIDE_EF: StatusWord = StatusWord(0x6B00);
const FCI: u8 = 0x6F;

/// Absolute path to a file, without the master file.
pub(crate) struct Location(Vec<[u8; 2]>);

impl Location {
    /// Builds a location from file IDs, dropping any `3F00`; `None` if no file is left.
    pub(crate) fn new(path: &[u8]) -> Option<Self> {
        let ids = path.chunks(2).map(|id| <[u8; 2]>::try_from(id).ok());
        let ids: Option<Vec<[u8; 2]>> = ids.collect();
        let ids = ids?
            .into_iter()
            .filter(|id| *id != MASTER_FILE_ID)
            .collect::<Vec<_>>();
        (!ids.is_empty()).then_some(Self(ids))
    }

    /// ID of the file the path ends in.
    pub(crate) fn last_file(&self) -> Option<[u8; 2]> {
        self.0.last().copied()
    }
}

/// Selects the master file by name, then each file in `location`, and reads the last one whole.
pub(crate) fn read(card: &mut dyn Transport, location: &Location) -> Result<Vec<u8>, Error> {
    select_master_file(card)?;
    let mut length = 0;
    for id in &location.0 {
        length = select(card, 0x00, id)?;
    }
    read_binary_complete(card, length)
}

/// Selects the master file by name.
pub(crate) fn select_master_file(card: &mut dyn Transport) -> Result<(), Error> {
    card.transmit(&master_file_selection())?
        .into_success()
        .map(drop)
}

/// `SELECT` of the master file by name.
pub(crate) fn master_file_selection() -> Command {
    selection(0x04, MASTER_FILE_NAME)
}

fn selection(p1: u8, file: &[u8]) -> Command {
    Command {
        cla: 0x00,
        ins: SELECT,
        p1,
        p2: 0x00,
        data: file.to_vec(),
        le: None,
    }
}

/// Selects a file and returns the length its FCI announces.
fn select(card: &mut dyn Transport, p1: u8, file: &[u8]) -> Result<usize, Error> {
    let response = card.transmit(&selection(p1, file))?;
    let fci = response.into_success()?;
    if fci.is_empty() {
        return Ok(0);
    }
    if fci[0] != FCI || fci.len() <= 2 {
        return Err(Error::Status(StatusWord::SUCCESS));
    }
    Ok(file_length(&fci))
}

/// The file length in an FCI, from tag `81` or the proprietary tag `85`; 0 if absent.
fn file_length(fci: &[u8]) -> usize {
    let [_, length, body @ ..] = fci else {
        return 0;
    };
    if usize::from(*length) != body.len() {
        return 0;
    }
    let mut index = 0;
    let mut file_length = take(body, 0x81, &mut index);
    // A second `81` carries the file ID, then `84` the DF name.
    take(body, 0x81, &mut index);
    take(body, 0x84, &mut index);
    if body.get(index) == Some(&0x85) && body.get(index + 1) == Some(&10) {
        file_length = body.get(index + 5..index + 7);
    }
    match file_length {
        Some([high, low, ..]) => usize::from(u16::from_be_bytes([*high, *low])),
        _ => 0,
    }
}

/// The value of the `tag` TLV at `index`, moving `index` past it.
fn take<'a>(body: &'a [u8], tag: u8, index: &mut usize) -> Option<&'a [u8]> {
    if body.get(*index) != Some(&tag) {
        return None;
    }
    let length = usize::from(*body.get(*index + 1)?);
    let value = body.get(*index + 2..*index + 2 + length)?;
    *index += 2 + length;
    Some(value)
}

/// Reads `length` bytes of the selected file in chunks, stopping early at `6282` or `6B00`.
fn read_binary_complete(card: &mut dyn Transport, length: usize) -> Result<Vec<u8>, Error> {
    let mut content = Vec::with_capacity(length);
    let mut offset = 0;
    while offset < length {
        let [p1, p2] = u16::try_from(offset)
            .map_err(|_| Error::CommandTooLong(offset))?
            .to_be_bytes();
        let response = card.transmit(&Command {
            cla: 0x00,
            ins: READ_BINARY,
            p1,
            p2,
            data: vec![],
            le: Some(u16::try_from((length - offset).min(MAX_READ_CHUNK)).unwrap_or(0)),
        })?;
        match response.status {
            OFFSET_OUTSIDE_EF => break,
            status if status.is_success() || status == EOF_REACHED => {
                content.extend(response.data);
                if status == EOF_REACHED {
                    break;
                }
            }
            status => return Err(Error::Status(status)),
        }
        offset += MAX_READ_CHUNK;
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::{Location, MAX_READ_CHUNK, read, select_master_file};
    use crate::{
        cwa14890,
        emulator::{DNIE_3_ATR, EmulatedDnie, component_root_public_key},
        key_sets::{ComponentRoots, R1_USER},
        secure_messaging::Protected,
        session::tests::card_with_channel,
    };

    const FILE: [u8; 2] = [0x60, 0x10];

    fn read_under_channel(card: EmulatedDnie) -> Vec<u8> {
        let mut card = card;
        let roots = ComponentRoots::only(component_root_public_key());
        let mut channel = cwa14890::open(&mut card, &R1_USER, &roots).unwrap();
        let mut protected = Protected {
            channel: &mut channel,
            card: &mut card,
        };
        read(
            &mut protected,
            &Location::new(&[0x3F, 0x00, 0x60, 0x10]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn keeps_the_chunks_a_secure_channel_authenticated_only_up_to_a_warning() {
        let content: Vec<u8> = (0..=255).cycle().take(300).collect();
        let card = card_with_channel()
            .with_file(&[FILE], content.clone())
            .overstating_length(&[FILE], 200);
        assert_eq!(read_under_channel(card), content[..MAX_READ_CHUNK]);
    }

    #[test]
    fn selects_the_master_file_whatever_a_card_answers_with_9000() {
        let mut card =
            EmulatedDnie::new(&DNIE_3_ATR).answering_master_file_selection_with(&[1, 2, 3]);
        assert!(select_master_file(&mut card).is_ok());
    }
}
