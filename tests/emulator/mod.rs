//! Emulated DNIe behind the `Transport` seam, generated at test time from no real card data.
// Each test crate uses a different part of the emulator.
#![allow(dead_code)]

mod pkcs15;

use std::collections::BTreeMap;

use rdnie::{Error, Transport};

pub use pkcs15::HolderCertificate;

/// DNIe 3.0 ATR: byte 15 is `04`.
pub const DNIE_3_ATR: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

const SELECT: u8 = 0xA4;
const READ_BINARY: u8 = 0xB0;
const GET_CHALLENGE: u8 = 0x84;
const GET_RESPONSE: u8 = 0xC0;
const CHALLENGE_LENGTH: usize = 8;
const MASTER_FILE_NAME: &[u8] = b"Master.File";
const IDESP: [u8; 2] = [0x00, 0x06];

/// File path below the master file.
type Path = Vec<[u8; 2]>;

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
    files: BTreeMap<Path, File>,
    current: Path,
}

struct File {
    content: Vec<u8>,
    /// Length the FCI announces, which a card may overstate.
    announced: usize,
}

struct Apdu<'a> {
    ins: u8,
    p1: u8,
    p2: u8,
    data: &'a [u8],
    le: Option<usize>,
}

impl EmulatedDnie {
    pub fn new(atr: &[u8]) -> Self {
        Self {
            atr: atr.to_vec(),
            delivery: Delivery::Direct,
            pending: Vec::new(),
            files: BTreeMap::new(),
            current: Vec::new(),
        }
    }

    pub fn delivering(mut self, delivery: Delivery) -> Self {
        self.delivery = delivery;
        self
    }

    /// Stores `content` at `path`, given from the master file down.
    pub fn with_file(mut self, path: &[[u8; 2]], content: Vec<u8>) -> Self {
        let announced = content.len();
        self.files
            .insert(path.to_vec(), File { content, announced });
        self
    }

    /// Makes the FCI of the file at `path` announce more bytes than it holds.
    pub fn overstating_length(mut self, path: &[[u8; 2]], extra: usize) -> Self {
        let file = self.files.get_mut(path).expect("file stored before");
        file.announced = file.content.len() + extra;
        self
    }

    pub fn with_idesp(self, idesp: &[u8]) -> Self {
        self.with_file(&[IDESP], idesp.to_vec())
    }

    /// Stores the certificates with the CDF and PrKDF that describe them.
    pub fn with_certificates(self, certificates: &[HolderCertificate]) -> Self {
        let card = certificates.iter().fold(self, |card, certificate| {
            card.with_file(&[certificate.file], certificate.stored())
        });
        card.with_file(&pkcs15::CDF, pkcs15::cdf(certificates))
            .with_file(&pkcs15::PRKDF, pkcs15::prkdf(certificates))
    }

    fn answer(&mut self, apdu: &Apdu) -> Vec<u8> {
        match apdu.ins {
            SELECT => self.select(apdu),
            READ_BINARY => self.read_binary(apdu),
            GET_CHALLENGE => {
                let challenge: Vec<u8> = (0xA0..).take(CHALLENGE_LENGTH).collect();
                self.deliver(challenge, apdu.le)
            }
            GET_RESPONSE if !self.pending.is_empty() => self.serve_pending(apdu.le.unwrap_or(256)),
            GET_RESPONSE => vec![0x69, 0x85],
            _ => vec![0x6D, 0x00],
        }
    }

    fn select(&mut self, apdu: &Apdu) -> Vec<u8> {
        match (apdu.p1, apdu.data) {
            (0x04, MASTER_FILE_NAME) => {
                self.current.clear();
                with_status(vec![], 0x9000)
            }
            (0x00, &[high, low]) => {
                let mut path = self.current_df();
                path.push([high, low]);
                let announced = match self.files.get(&path) {
                    Some(file) => file.announced,
                    None if self.files.keys().any(|file| file.starts_with(&path)) => 0,
                    None => return vec![0x6A, 0x82],
                };
                self.current = path;
                let mut proprietary = vec![0x81, 0x02];
                proprietary.extend_from_slice(&u16::try_from(announced).unwrap().to_be_bytes());
                proprietary.extend_from_slice(&[0x82, 0x01, 0x01, 0x83, 0x02, high, low]);
                let mut fci = vec![0x6F, u8::try_from(proprietary.len()).unwrap()];
                fci.extend(proprietary);
                self.deliver(fci, apdu.le)
            }
            _ => vec![0x6A, 0x86],
        }
    }

    /// The selected path if it is a directory, or the directory holding the selected file.
    fn current_df(&self) -> Path {
        let mut path = self.current.clone();
        if self.files.contains_key(&path) {
            path.pop();
        }
        path
    }

    fn read_binary(&mut self, apdu: &Apdu) -> Vec<u8> {
        let Some(file) = self.files.get(&self.current) else {
            return vec![0x69, 0x86];
        };
        let offset = usize::from(u16::from_be_bytes([apdu.p1, apdu.p2]));
        if offset >= file.content.len() {
            return vec![0x6B, 0x00];
        }
        let wanted = apdu.le.unwrap_or(256);
        let end = file.content.len().min(offset + wanted);
        let data = file.content[offset..end].to_vec();
        if data.len() < wanted {
            with_status(data, 0x6282)
        } else {
            self.deliver(data, apdu.le)
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
        let Some(apdu) = parse(apdu) else {
            return Ok(vec![0x67, 0x00]);
        };
        if apdu.ins != GET_RESPONSE {
            self.pending.clear();
        }
        Ok(self.answer(&apdu))
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.pending.clear();
        self.current.clear();
        Ok(self.atr.clone())
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

fn parse(apdu: &[u8]) -> Option<Apdu<'_>> {
    let [_cla, ins, p1, p2, body @ ..] = apdu else {
        return None;
    };
    let (data, le) = match body {
        [] => (&[][..], None),
        [le] => (&[][..], Some(*le)),
        [lc, rest @ ..] if rest.len() == usize::from(*lc) => (rest, None),
        [lc, rest @ ..] if rest.len() == usize::from(*lc) + 1 => {
            let (data, le) = rest.split_at(usize::from(*lc));
            (data, Some(le[0]))
        }
        _ => return None,
    };
    Some(Apdu {
        ins: *ins,
        p1: *p1,
        p2: *p2,
        data,
        le: le.map(|le| if le == 0 { 256 } else { usize::from(le) }),
    })
}

fn length_byte(length: usize) -> u8 {
    u8::try_from(length % 256).expect("reduced modulo 256")
}

fn with_status(mut data: Vec<u8>, status: u16) -> Vec<u8> {
    data.extend_from_slice(&status.to_be_bytes());
    data
}
