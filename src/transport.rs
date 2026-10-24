// Derived from JMulticard: see LICENSE.jmulticard.md.

use crate::{Atr, Error};

/// The connection to the card: PC/SC in production, an emulator in tests.
///
/// After [`Error::CardRemoved`] the transport is spent: open a new transport and a new session.
pub trait Transport {
    /// The card's current ATR, read without touching the card.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if it cannot be read, [`Error::CardReset`] if the card was reset since
    /// the last command and [`Error::CardRemoved`] if it left the reader.
    fn atr(&self) -> Result<Atr, Error>;

    /// Runs `body` with exclusive access to the card, through a [`Port`] alive only inside it.
    ///
    /// A decorator gets its port from the inner transport's transaction.
    ///
    /// # Errors
    ///
    /// Those of `body`, [`Error::Transport`] if the transaction cannot start or end,
    /// [`Error::CardReset`] if the card was reset before it started and [`Error::CardRemoved`]
    /// if it left the reader.
    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Port) -> Result<R, Error>,
    ) -> Result<R, Error>
    where
        Self: Sized;
}

/// Sends bytes to the card inside a [`Transport::transaction`].
pub trait Port {
    /// Sends a raw APDU and returns the raw response with its status word.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the APDU does not reach the card, [`Error::CardReset`] if the
    /// card was reset since the last command and [`Error::CardRemoved`] if it left the reader.
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error>;
}
