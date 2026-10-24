// Derived from JMulticard: see LICENSE.jmulticard.md.

//! The retry counter and `VERIFY` sent through the PIN channel, as `Dnie` and `Dnie3` run them.

use zeroize::{Zeroize, Zeroizing};

use crate::{
    Command, Error, StatusWord, Transport, card_authenticator::CardAuthenticator,
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
    authenticator: &CardAuthenticator,
) -> Result<u8, Error> {
    let mut channel = authenticator.open_pin_channel(card)?;
    query_retries(&mut channel)
}

/// Rereads the retries and, if they are still `expected` and not zero, sends `pin` once through
/// the PIN channel and returns the user channel over `card`.
pub(crate) fn verify<'a>(
    card: &'a mut dyn Transport,
    authenticator: &CardAuthenticator,
    pin: Pin,
    expected: u8,
) -> Result<SecureChannel<'a>, Error> {
    let mut channel = authenticator.open_pin_channel(card)?;
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
    authenticator.open_user_channel(channel)
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
