// Derived from JMulticard: see LICENSE.jmulticard.md.

//! Plain file access below any secure channel: SELECT by name or path, and chunked READ BINARY.

use crate::{Command, Error, StatusWord, channel::CommandChannel};

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
pub(crate) fn read(card: &mut dyn CommandChannel, location: &Location) -> Result<Vec<u8>, Error> {
    select_master_file(card)?;
    let mut length = 0;
    for id in &location.0 {
        length = select(card, 0x00, id)?;
    }
    read_binary_complete(card, length)
}

/// Selects the master file by name.
pub(crate) fn select_master_file(card: &mut dyn CommandChannel) -> Result<(), Error> {
    card.transmit(&master_file_selection())?
        .into_success()
        .map(drop)
}

/// Selects the master file, ignoring a refusal, to drop a channel a previous operation left open.
pub(crate) fn leave_any_channel(card: &mut dyn CommandChannel) -> Result<(), Error> {
    match select_master_file(card) {
        Ok(()) | Err(Error::Status(_)) => Ok(()),
        Err(error) => Err(error),
    }
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
fn select(card: &mut dyn CommandChannel, p1: u8, file: &[u8]) -> Result<usize, Error> {
    let response = card.transmit(&selection(p1, file))?;
    fci_length(&response.into_success()?)
}

/// The file length an FCI announces; 0 if the card sent none.
pub(crate) fn fci_length(fci: &[u8]) -> Result<usize, Error> {
    if fci.is_empty() {
        return Ok(0);
    }
    if fci[0] != FCI || fci.len() <= 2 {
        return Err(Error::Status(StatusWord::SUCCESS));
    }
    Ok(file_length(fci))
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
fn read_binary_complete(card: &mut dyn CommandChannel, length: usize) -> Result<Vec<u8>, Error> {
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
mod tests;
