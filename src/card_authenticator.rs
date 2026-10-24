// Derived from JMulticard: see LICENSE.jmulticard.md.

//! The card authenticator: the card's key generation and the trusted component roots, which open
//! the PIN channel and the user channel as `Dnie3` does.

use crate::{
    Error,
    channel::{CommandChannel, PlainChannel},
    cwa14890, files,
    key_sets::{Channel, ComponentRoots, KeyGeneration, KeySet},
    secure_messaging::SecureChannel,
};

/// Support numbers from this one on take the second key generation.
const R2_IDESP: &str = "BMP100001";

/// Opens the CWA-14890 channels of one card with the key sets of its generation.
pub(crate) struct CardAuthenticator {
    generation: KeyGeneration,
    roots: ComponentRoots,
}

impl CardAuthenticator {
    /// Resolves the card's stored support number, as `DnieFactory` does; an empty or absent one
    /// takes the second generation.
    pub(crate) fn from_idesp(idesp: Option<&str>, roots: ComponentRoots) -> Self {
        let generation = if idesp.is_some_and(|idesp| !idesp.is_empty() && idesp < R2_IDESP) {
            KeyGeneration::First
        } else {
            KeyGeneration::Second
        };
        Self { generation, roots }
    }

    #[cfg(test)]
    pub(crate) fn new(generation: KeyGeneration, roots: ComponentRoots) -> Self {
        Self { generation, roots }
    }

    pub(crate) fn key_generation(&self) -> KeyGeneration {
        self.generation
    }

    /// Selects the master file, whose refusal `Dnie3` only warns about, then authenticates with
    /// the PIN keys.
    pub(crate) fn open_pin_channel<'a>(
        &self,
        mut card: PlainChannel<'a>,
    ) -> Result<SecureChannel<'a>, Error> {
        files::leave_any_channel(&mut card)?;
        cwa14890::open(card, self.keys(Channel::Pin), &self.roots)
    }

    /// Selects the master file and authenticates with the user keys, all through `pin_channel`,
    /// as `Dnie3.openUserChannel` does, and drops `pin_channel`.
    pub(crate) fn open_user_channel<'a>(
        &self,
        mut pin_channel: SecureChannel<'a>,
    ) -> Result<SecureChannel<'a>, Error> {
        pin_channel
            .transmit(&files::master_file_selection())?
            .into_success()?;
        cwa14890::open_inside(pin_channel, self.keys(Channel::User), &self.roots)
    }

    fn keys(&self, channel: Channel) -> &'static KeySet {
        KeySet::for_generation(self.generation, channel)
    }
}

#[cfg(test)]
mod tests;
