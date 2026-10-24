// Derived from JMulticard: see LICENSE.jmulticard.md.

//! The bounded `6Cxx` resend shared by the transport and the secure channel.

use zeroize::Zeroize;

use crate::{Command, Error, StatusWord};

const WRONG_LENGTH: u8 = 0x6C;
const MAX_RESENDS: usize = 2;

/// Holds the latest resent copy of a command and wipes it on drop.
#[derive(Default)]
pub(crate) struct Resends {
    copy: Option<Command>,
    consecutive: usize,
}

impl Resends {
    /// The command to send now: the latest copy, or `command` if none was made.
    pub(crate) fn current<'a>(&'a self, command: &'a Command) -> &'a Command {
        self.copy.as_ref().unwrap_or(command)
    }

    /// Whether `status` is a `6Cxx` asking for another Le.
    pub(crate) fn is_wrong_length(status: StatusWord) -> bool {
        status.0.to_be_bytes()[0] == WRONG_LENGTH
    }

    /// Replaces the current command by a copy with the Le a `6Cxx` asks for.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] with `status` once 2 resends in a row were made.
    pub(crate) fn resend_with_le(
        &mut self,
        command: &Command,
        status: StatusWord,
    ) -> Result<(), Error> {
        if self.consecutive == MAX_RESENDS {
            return Err(Error::Status(status));
        }
        self.consecutive += 1;
        let next = Command {
            le: Some(short_le(status.0.to_be_bytes()[1])),
            ..self.current(command).clone()
        };
        self.replace(next);
        Ok(())
    }

    /// Replaces the current command by an unrelated one and ends the run of resends.
    pub(crate) fn replace_with(&mut self, next: Command) {
        self.consecutive = 0;
        self.replace(next);
    }

    fn replace(&mut self, next: Command) {
        if let Some(mut old) = self.copy.replace(next) {
            old.data.zeroize();
        }
    }
}

impl Drop for Resends {
    fn drop(&mut self) {
        if let Some(copy) = &mut self.copy {
            copy.data.zeroize();
        }
    }
}

pub(crate) fn short_le(le: u8) -> u16 {
    match le {
        0 => 256,
        le => le.into(),
    }
}
