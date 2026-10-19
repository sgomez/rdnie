use crate::{Command, Error, Response};

/// Channel the APDUs travel through: PC/SC in production, an emulator in tests.
pub trait Transport {
    /// Sends a raw APDU and returns the response including its status word.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if the APDU does not reach the card.
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error>;

    /// Sends a command and splits the response into data and status word.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transmit_raw`], [`Command::to_bytes`] and [`Response::parse`].
    fn transmit(&mut self, command: &Command) -> Result<Response, Error> {
        Response::parse(&self.transmit_raw(&command.to_bytes()?)?)
    }
}
