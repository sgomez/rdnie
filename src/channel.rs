// Derived from JMulticard: see LICENSE.jmulticard.md.

//! The command level the protocol speaks, and the plain channel that carries it to the card.

use crate::{
    Command, Error, Response, StatusWord, Transport,
    resend::{Resends, short_le},
};

const RESPONSE_PENDING: u8 = 0x61;
// A DNIe answers it to the first plain command after a leftover secure channel, and drops it.
const SM_DATA_MISSING: StatusWord = StatusWord(0x6987);
const MAX_GET_RESPONSES: usize = 256;
// Protected commands are resent by the secure channel, not here.
const PLAIN_CLA: u8 = 0x00;

/// Sends a command and returns the card's answer.
pub(crate) trait CommandChannel {
    fn transmit(&mut self, command: &Command) -> Result<Response, Error>;
}

/// Completes `61xx` with `GET RESPONSE` and resends a plain command on `6Cxx` and once on `69 87`;
/// past a bound, [`Error::Status`] with the last status word.
pub(crate) struct PlainChannel<'a> {
    card: &'a mut dyn Transport,
}

impl<'a> PlainChannel<'a> {
    pub(crate) fn new(card: &'a mut dyn Transport) -> Self {
        Self { card }
    }
}

impl CommandChannel for PlainChannel<'_> {
    fn transmit(&mut self, command: &Command) -> Result<Response, Error> {
        follow_up(|apdu| self.card.transmit_raw(apdu), command)
    }
}

/// The plain channel's exchange over `transmit_raw`, which [`Transport::transmit`] shares.
pub(crate) fn follow_up(
    mut transmit_raw: impl FnMut(&[u8]) -> Result<Vec<u8>, Error>,
    command: &Command,
) -> Result<Response, Error> {
    let mut data = Vec::new();
    let mut get_responses = 0;
    let mut resends = Resends::default();
    let mut channel_dropped = false;
    loop {
        let sent = resends.current(command);
        let response = Response::parse(&transmit_raw(&sent.to_bytes()?)?)?;
        let plain = sent.cla == PLAIN_CLA;
        if response.status == SM_DATA_MISSING && plain {
            if channel_dropped {
                return Err(Error::Status(response.status));
            }
            channel_dropped = true;
            continue;
        }
        if Resends::is_wrong_length(response.status) && plain {
            resends.resend_with_le(command, response.status)?;
            continue;
        }
        data.extend(response.data);
        let [sw1, sw2] = response.status.0.to_be_bytes();
        if sw1 != RESPONSE_PENDING {
            return Ok(Response {
                data,
                status: response.status,
            });
        }
        if get_responses == MAX_GET_RESPONSES {
            return Err(Error::Status(response.status));
        }
        get_responses += 1;
        resends.replace_with(get_response(sw2));
    }
}

fn get_response(le: u8) -> Command {
    Command {
        cla: PLAIN_CLA,
        ins: 0xC0,
        p1: 0x00,
        p2: 0x00,
        data: vec![],
        le: Some(short_le(le)),
    }
}

#[cfg(test)]
mod tests;
