// Derived from JMulticard: see LICENSE.jmulticard.md.

use crate::{Command, Error, Response, channel};

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

    /// The card's current ATR, read without touching the card.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if it cannot be read, [`Error::CardReset`] if the card was reset since
    /// the last command and [`Error::CardRemoved`] if it left the reader.
    fn atr(&self) -> Result<Vec<u8>, Error>;

    /// Resets the card and returns its ATR. rdnie never calls it; it is there for callers.
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

    /// Sends a command, completing `61xx` with `GET RESPONSE` and resending a plain command on `6Cxx`
    /// and once on `69 87`, which a DNIe answers after a leftover secure channel.
    ///
    /// A command gets at most 256 `GET RESPONSE`, at most 2 consecutive `6Cxx` resends and one
    /// `69 87` resend.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transmit_raw`], [`Command::to_bytes`] and [`Response::parse`], and
    /// [`Error::Status`] with the last status word if the card keeps asking past a bound.
    fn transmit(&mut self, command: &Command) -> Result<Response, Error> {
        channel::follow_up(|apdu| self.transmit_raw(apdu), command)
    }
}
