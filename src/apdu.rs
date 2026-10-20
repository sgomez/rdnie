use std::fmt;

use crate::{Error, standard_error_codes};

/// ISO 7816-4 command in short format, the only one the DNIe uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// First parameter.
    pub p1: u8,
    /// Second parameter.
    pub p2: u8,
    /// Command data.
    pub data: Vec<u8>,
    /// Expected response length; `Some(256)` encodes as `00`.
    pub le: Option<u16>,
}

impl Command {
    /// Serialises the command as a short APDU.
    ///
    /// # Errors
    ///
    /// [`Error::CommandTooLong`] if the data exceeds 255 bytes or `le` exceeds 256.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
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
pub struct Response {
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
mod tests {
    use super::*;

    fn command(data: Vec<u8>, le: Option<u16>) -> Command {
        Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data,
            le,
        }
    }

    #[test]
    fn encodes_header_only() {
        assert_eq!(
            command(vec![], None).to_bytes().unwrap(),
            [0x00, 0xA4, 0x04, 0x00]
        );
    }

    #[test]
    fn encodes_data_and_le() {
        assert_eq!(
            command(vec![0xAA, 0xBB], Some(16)).to_bytes().unwrap(),
            [0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x10]
        );
    }

    #[test]
    fn encodes_le_256_as_zero() {
        assert_eq!(command(vec![], Some(256)).to_bytes().unwrap()[4], 0x00);
    }

    #[test]
    fn rejects_data_longer_than_short_apdu() {
        assert!(matches!(
            command(vec![0; 256], None).to_bytes(),
            Err(Error::CommandTooLong(256))
        ));
    }

    #[test]
    fn rejects_le_above_256() {
        assert!(matches!(
            command(vec![], Some(257)).to_bytes(),
            Err(Error::CommandTooLong(257))
        ));
    }

    #[test]
    fn splits_data_from_status_word() {
        let response = Response::parse(&[0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(response.data, [0x01, 0x02]);
        assert!(response.status.is_success());
    }

    #[test]
    fn rejects_response_without_status_word() {
        assert!(matches!(
            Response::parse(&[0x90]),
            Err(Error::TruncatedResponse(1))
        ));
    }

    #[test]
    fn reports_failing_status_word() {
        let error = Response::parse(&[0x6A, 0x82])
            .unwrap()
            .into_success()
            .unwrap_err();
        assert_eq!(error.to_string(), "card answered file not found (6A 82)");
    }

    #[test]
    fn describes_a_known_status_word_before_its_code() {
        assert_eq!(
            StatusWord(0x6982).to_string(),
            "security status not satisfied (69 82)"
        );
    }

    #[test]
    fn shows_only_the_code_of_an_undescribed_status_word() {
        assert_eq!(StatusWord(0x6300).to_string(), "63 00");
        assert_eq!(StatusWord::SUCCESS.to_string(), "90 00");
    }
}
