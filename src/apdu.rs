use std::fmt;

use crate::{Error, standard_error_codes};

/// ISO 7816-4 command in short format, the only one the DNIe uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Command {
    /// Class byte.
    pub(crate) cla: u8,
    /// Instruction byte.
    pub(crate) ins: u8,
    /// First parameter.
    pub(crate) p1: u8,
    /// Second parameter.
    pub(crate) p2: u8,
    /// Command data.
    pub(crate) data: Vec<u8>,
    /// Expected response length; `Some(256)` encodes as `00`.
    pub(crate) le: Option<u16>,
}

impl Command {
    /// Serialises the command as a short APDU.
    ///
    /// # Errors
    ///
    /// [`Error::CommandTooLong`] if the data exceeds 255 bytes or `le` exceeds 256.
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut apdu = vec![self.cla, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            let lc = u8::try_from(self.data.len())
                .map_err(|_| Error::CommandTooLong(self.data.len()))?;
            apdu.push(lc);
            apdu.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            apdu.push(match le {
                256 => 0,
                _ => u8::try_from(le).map_err(|_| Error::CommandTooLong(le.into()))?,
            });
        }
        Ok(apdu)
    }
}

/// SW1-SW2 status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusWord(pub u16);

impl StatusWord {
    /// `90 00`.
    pub const SUCCESS: Self = Self(0x9000);

    /// Whether the card accepted the command.
    #[must_use]
    pub fn is_success(self) -> bool {
        self == Self::SUCCESS
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = format!("{:02X} {:02X}", self.0 >> 8, self.0 & 0xFF);
        match standard_error_codes::describe(self.0) {
            Some(description) => write!(f, "{description} ({code})"),
            None => f.write_str(&code),
        }
    }
}

/// Card response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    /// Data without the status word.
    pub data: Vec<u8>,
    /// Status word.
    pub status: StatusWord,
}

impl Response {
    /// Splits the data from the trailing status word.
    ///
    /// # Errors
    ///
    /// [`Error::TruncatedResponse`] if fewer than two bytes arrive.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let [data @ .., sw1, sw2] = raw else {
            return Err(Error::TruncatedResponse(raw.len()));
        };
        Ok(Self {
            data: data.to_vec(),
            status: StatusWord(u16::from_be_bytes([*sw1, *sw2])),
        })
    }

    /// Returns the data if the card accepted the command.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] with the status word otherwise.
    pub fn into_success(self) -> Result<Vec<u8>, Error> {
        if self.status.is_success() {
            Ok(self.data)
        } else {
            Err(Error::Status(self.status))
        }
    }
}

#[cfg(test)]
mod tests;
