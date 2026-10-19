use pcsc::{Card, Context, MAX_BUFFER_SIZE, Protocols, Scope, ShareMode};

use crate::{Error, Transport, is_dnie};

/// PC/SC transport: `PCSC.framework` on macOS, WinSCard on Windows and pcsc-lite on Linux.
pub struct PcscTransport {
    card: Card,
}

impl PcscTransport {
    /// Connects in shared mode to the first reader holding a DNIe.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] if PC/SC fails and [`Error::NoDnie`] if no reader holds a DNIe.
    pub fn connect_first_dnie() -> Result<Self, Error> {
        let context = Context::establish(Scope::User).map_err(transport)?;
        let readers = context.list_readers_owned().map_err(transport)?;
        readers
            .iter()
            .filter_map(|reader| {
                context
                    .connect(reader, ShareMode::Shared, Protocols::ANY)
                    .ok()
            })
            .find(|card| {
                card.get_attribute_owned(pcsc::Attribute::AtrString)
                    .is_ok_and(|atr| is_dnie(&atr))
            })
            .map(|card| Self { card })
            .ok_or(Error::NoDnie)
    }
}

impl Transport for PcscTransport {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buffer = [0; MAX_BUFFER_SIZE];
        let response = self.card.transmit(apdu, &mut buffer).map_err(transport)?;
        Ok(response.to_vec())
    }
}

#[allow(clippy::needless_pass_by_value)]
fn transport(error: pcsc::Error) -> Error {
    Error::Transport(error.to_string())
}
