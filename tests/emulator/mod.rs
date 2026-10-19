//! Emulated DNIe behind the `Transport` seam, generated at test time from no real card data.
// Each test crate uses a different part of the emulator.
#![allow(dead_code)]

use rdnie::{Error, Transport};

/// DNIe 3.0 ATR: byte 15 is `04`.
pub const DNIE_3_ATR: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

const GET_CHALLENGE: u8 = 0x84;
const GET_RESPONSE: u8 = 0xC0;
const CHALLENGE_LENGTH: usize = 8;

/// How the card hands back response data.
#[derive(Clone, Copy)]
pub enum Delivery {
    /// In the response itself.
    Direct,
    /// Announced with `61xx` and served by `GET RESPONSE` at most `chunk` bytes at a time.
    GetResponse { chunk: usize },
    /// Only when Le matches its length; otherwise `6Cxx` with the right one.
    ExactLe,
}

/// Card side of the protocol.
pub struct EmulatedDnie {
    atr: Vec<u8>,
    delivery: Delivery,
    pending: Vec<u8>,
}

impl EmulatedDnie {
    pub fn new(atr: &[u8]) -> Self {
        Self {
            atr: atr.to_vec(),
            delivery: Delivery::Direct,
            pending: Vec::new(),
        }
    }

    pub fn delivering(mut self, delivery: Delivery) -> Self {
        self.delivery = delivery;
        self
    }

    fn answer(&mut self, ins: u8, le: Option<usize>) -> Vec<u8> {
        match ins {
            GET_CHALLENGE => {
                let challenge: Vec<u8> = (0xA0..).take(CHALLENGE_LENGTH).collect();
                self.deliver(challenge, le)
            }
            GET_RESPONSE if !self.pending.is_empty() => self.serve_pending(le.unwrap_or(256)),
            GET_RESPONSE => vec![0x69, 0x85],
            _ => vec![0x6D, 0x00],
        }
    }

    fn deliver(&mut self, data: Vec<u8>, le: Option<usize>) -> Vec<u8> {
        match self.delivery {
            Delivery::Direct => with_status(data, 0x9000),
            Delivery::GetResponse { .. } => {
                let announced = length_byte(data.len());
                self.pending = data;
                vec![0x61, announced]
            }
            Delivery::ExactLe if le == Some(data.len()) => with_status(data, 0x9000),
            Delivery::ExactLe => vec![0x6C, length_byte(data.len())],
        }
    }

    fn serve_pending(&mut self, le: usize) -> Vec<u8> {
        let Delivery::GetResponse { chunk } = self.delivery else {
            unreachable!("only get-response delivery leaves data pending")
        };
        let served: Vec<u8> = self
            .pending
            .drain(..le.min(chunk).min(self.pending.len()))
            .collect();
        match self.pending.len() {
            0 => with_status(served, 0x9000),
            left => with_status(served, 0x6100 | u16::from(length_byte(left))),
        }
    }
}

impl Transport for EmulatedDnie {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let [_cla, ins, _p1, _p2, body @ ..] = apdu else {
            return Ok(vec![0x67, 0x00]);
        };
        if *ins != GET_RESPONSE {
            self.pending.clear();
        }
        Ok(self.answer(*ins, short_le(body)))
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.pending.clear();
        Ok(self.atr.clone())
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

fn short_le(body: &[u8]) -> Option<usize> {
    let le = match body {
        [le] => *le,
        [lc, rest @ ..] if rest.len() == usize::from(*lc) + 1 => rest[usize::from(*lc)],
        _ => return None,
    };
    Some(if le == 0 { 256 } else { usize::from(le) })
}

fn length_byte(length: usize) -> u8 {
    u8::try_from(length % 256).expect("reduced modulo 256")
}

fn with_status(mut data: Vec<u8>, status: u16) -> Vec<u8> {
    data.extend_from_slice(&status.to_be_bytes());
    data
}
