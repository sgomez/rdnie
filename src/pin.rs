// Derived from JMulticard: see LICENSE.jmulticard.md.

//! The PIN guard: the retry counter and `VERIFY` through the PIN channel, as `Dnie` and `Dnie3` run them.

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Command, Error, KeyGeneration, StatusWord, Transport, card_authenticator::CardAuthenticator,
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

/// The never-blind PIN policy: the retries last shown are what the next verified operation expects.
pub(crate) struct PinGuard {
    authenticator: CardAuthenticator,
    shown: Option<u8>,
}

impl PinGuard {
    pub(crate) fn new(authenticator: CardAuthenticator) -> Self {
        Self {
            authenticator,
            shown: None,
        }
    }

    pub(crate) fn key_generation(&self) -> KeyGeneration {
        self.authenticator.key_generation()
    }

    /// Reads the retries in their own transaction and records them as shown unless the read fails.
    pub(crate) fn read_retries(&mut self, transport: &mut impl Transport) -> Result<u8, Error> {
        let retries = self.query(transport)?;
        self.shown = Some(retries);
        Ok(retries)
    }

    /// Checks the retries shown, sends `pin` once and runs `work`, all in one transaction.
    pub(crate) fn verified<R>(
        &mut self,
        transport: &mut impl Transport,
        pin: Pin,
        work: impl FnOnce(&mut SecureChannel<'_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        pin.check_format()?;
        let expected = match self.shown.take() {
            Some(shown) => shown,
            None => self.query(transport)?,
        };
        if expected == 0 {
            return Err(Error::PinBlocked);
        }
        let authenticator = &self.authenticator;
        let result = transport.transaction(|card| {
            let mut channel = authenticator.open_pin_channel(card)?;
            match query_retries(&mut channel)? {
                0 => return Err(Error::PinBlocked),
                retries if retries != expected => return Err(Error::PinRetriesChanged),
                _ => {}
            }
            send_verify(&mut channel, pin)?;
            work(&mut authenticator.open_user_channel(channel)?)
        });
        if let Err(Error::WrongPin { retries_left }) = result {
            self.shown = Some(retries_left);
        }
        result
    }

    fn query(&self, transport: &mut impl Transport) -> Result<u8, Error> {
        transport.transaction(|card| query_retries(&mut self.authenticator.open_pin_channel(card)?))
    }
}

fn send_verify(channel: &mut SecureChannel<'_>, pin: Pin) -> Result<(), Error> {
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
    Ok(())
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
