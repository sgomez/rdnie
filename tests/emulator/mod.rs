//! Emulated DNIe behind the `Transport` seam, generated at test time from no real card data.
// Each test crate uses a different part of the emulator.
#![allow(dead_code, unused_imports)]

mod channel;
mod chip;
mod pkcs15;

use std::collections::BTreeMap;

use rdnie::{Error, Transport};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

use channel::CardChannel;
use chip::Chip;
pub use chip::{Handshake, TerminalKey, component_root_public_key, foreign_root_public_key};
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
const GET_CHIP_INFO: u8 = 0xB8;
const MSE: u8 = 0x22;
const PSO: u8 = 0x2A;
const INTERNAL_AUTHENTICATE: u8 = 0x88;
const EXTERNAL_AUTHENTICATE: u8 = 0x82;
const VERIFY: u8 = 0x20;
const CHALLENGE: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
const PROTECTED: u8 = 0x0C;
const MASTER_FILE_NAME: &[u8] = b"Master.File";
const IDESP: [u8; 2] = [0x00, 0x06];
const ICC_CERTIFICATE: [u8; 2] = [0x60, 0x1F];
const INTERMEDIATE_CERTIFICATE: [u8; 2] = [0x60, 0x20];
const DEFAULT_RETRIES: u8 = 3;
/// PIN of every emulated card unless a test sets another.
pub const DEFAULT_PIN: &str = "TestPin1";

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
    chip: Option<Chip>,
    channel: Option<CardChannel>,
    retries: u8,
    retries_answer: Option<u16>,
    pin: Vec<u8>,
    pin_verified: bool,
    user_channel: bool,
    holder_keys: BTreeMap<[u8; 2], RsaPrivateKey>,
    signing_key: Option<[u8; 2]>,
    transactions: usize,
    commands: usize,
    pin_queries: Vec<PinQuery>,
    retry_lost_between_transactions: bool,
    fault: Option<Fault>,
}

/// A `VERIFY` the card received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinQuery {
    /// Number of the transaction it arrived in, from 1.
    pub transaction: usize,
    /// Whether it carried a PIN rather than asking for the retries.
    pub with_pin: bool,
}

/// One failure the card inflicts on the next protected command.
#[derive(Clone, Copy)]
enum Fault {
    Reset,
    ChannelLost,
    BadResponseMac,
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
            chip: None,
            channel: None,
            retries: DEFAULT_RETRIES,
            retries_answer: None,
            pin: DEFAULT_PIN.as_bytes().to_vec(),
            pin_verified: false,
            user_channel: false,
            holder_keys: BTreeMap::new(),
            signing_key: None,
            transactions: 0,
            commands: 0,
            pin_queries: Vec::new(),
            retry_lost_between_transactions: false,
            fault: None,
        }
    }

    /// Lets the card open a CWA-14890 channel with any of `terminals`.
    pub fn with_secure_channel(self, terminals: &[TerminalKey]) -> Self {
        let mut card = self
            .with_file(&[ICC_CERTIFICATE], chip::component_certificate())
            .with_file(
                &[INTERMEDIATE_CERTIFICATE],
                chip::intermediate_certificate(),
            );
        card.chip = Some(Chip::new(terminals));
        card
    }

    /// Stores a component certificate that the test CA did not sign.
    pub fn with_untrusted_component_certificate(self) -> Self {
        self.with_file(&[ICC_CERTIFICATE], chip::foreign_component_certificate())
    }

    /// Stores a CA certificate that the test root did not sign.
    pub fn with_untrusted_intermediate_certificate(self) -> Self {
        self.with_file(
            &[INTERMEDIATE_CERTIFICATE],
            chip::foreign_intermediate_certificate(),
        )
    }

    /// Drops the CA certificate from `3F00/6020`.
    pub fn without_intermediate_certificate(mut self) -> Self {
        self.files.remove([INTERMEDIATE_CERTIFICATE].as_slice());
        self
    }

    /// How many INTERNAL AUTHENTICATE commands the card received.
    pub fn internal_authentications(&self) -> usize {
        self.chip
            .as_ref()
            .map_or(0, |chip| chip.internal_authentications)
    }

    /// PIN attempts left; 0 means blocked.
    pub fn with_pin_retries(mut self, retries: u8) -> Self {
        self.retries = retries;
        self
    }

    /// Sets the PIN the card accepts.
    pub fn with_pin(mut self, pin: &str) -> Self {
        self.pin = pin.as_bytes().to_vec();
        self
    }

    /// Answers the retries query with `status` whatever the PIN state.
    pub fn answering_retries_with(mut self, status: u16) -> Self {
        self.retries_answer = Some(status);
        self
    }

    /// Corrupts `Kicc` in the internal authentication answer after hashing it.
    pub fn tampering_internal_authentication(mut self) -> Self {
        self.chip_mut().tamper_internal_authentication = true;
        self
    }

    /// Burns one PIN attempt between transactions once the retries were read, as another process
    /// trying a PIN between the two phases would.
    pub fn losing_a_retry_between_phases(mut self) -> Self {
        self.retry_lost_between_transactions = true;
        self
    }

    /// Whether the holder's PIN is verified on the card right now.
    pub fn pin_verified(&self) -> bool {
        self.pin_verified
    }

    /// Every `VERIFY` the card received, in order.
    pub fn pin_queries(&self) -> &[PinQuery] {
        &self.pin_queries
    }

    /// APDUs the card received.
    pub fn commands(&self) -> usize {
        self.commands
    }

    /// Resets the card on the next protected command, which the transport reports.
    pub fn resetting_mid_channel(mut self) -> Self {
        self.fault = Some(Fault::Reset);
        self
    }

    /// Answers `66 88` to the next protected command, as a card that dropped the channel.
    pub fn losing_the_channel(mut self) -> Self {
        self.fault = Some(Fault::ChannelLost);
        self
    }

    /// Corrupts the MAC of the next protected response.
    pub fn corrupting_a_response_mac(mut self) -> Self {
        self.fault = Some(Fault::BadResponseMac);
        self
    }

    /// The randomness of every handshake the card accepted.
    pub fn handshakes(&self) -> &[Handshake] {
        self.chip.as_ref().map_or(&[], |chip| &chip.handshakes)
    }

    fn chip_mut(&mut self) -> &mut Chip {
        self.chip.as_mut().expect("secure channel enabled before")
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
        let mut card = certificates.iter().fold(self, |card, certificate| {
            card.with_file(&[certificate.file], certificate.stored())
        });
        for certificate in certificates {
            if let (Some(file), Some(key)) = (certificate.key_file, &certificate.key) {
                card.holder_keys.insert(file, key.clone());
            }
        }
        card.with_file(&pkcs15::CDF, pkcs15::cdf(certificates))
            .with_file(&pkcs15::PRKDF, pkcs15::prkdf(certificates))
    }

    fn answer(&mut self, apdu: &Apdu) -> Vec<u8> {
        match apdu.ins {
            SELECT => self.select(apdu),
            READ_BINARY => self.read_binary(apdu),
            GET_CHALLENGE => self.deliver(CHALLENGE.to_vec(), apdu.le),
            GET_RESPONSE if !self.pending.is_empty() => self.serve_pending(apdu.le.unwrap_or(256)),
            GET_RESPONSE => vec![0x69, 0x85],
            _ if self.chip.is_some() => self.authenticate(apdu),
            _ => vec![0x6D, 0x00],
        }
    }

    fn authenticate(&mut self, apdu: &Apdu) -> Vec<u8> {
        match (apdu.ins, apdu.p1, apdu.p2) {
            (GET_CHIP_INFO, _, _) => self.deliver(chip::SERIAL.to_vec(), apdu.le),
            (MSE, 0x81, 0xB6) | (PSO, 0x00, 0xAE) => vec![0x90, 0x00],
            (MSE, 0xC1, 0xA4) => self
                .chip_mut()
                .select_terminal(apdu.data)
                .to_be_bytes()
                .to_vec(),
            (INTERNAL_AUTHENTICATE, _, _) => match self.chip_mut().internal_authenticate(apdu.data)
            {
                Ok(answer) => self.deliver(answer, apdu.le),
                Err(status) => status.to_be_bytes().to_vec(),
            },
            (EXTERNAL_AUTHENTICATE, _, _) => {
                self.channel = self.chip_mut().external_authenticate(apdu.data, CHALLENGE);
                self.user_channel = self.chip_mut().user_terminal();
                if self.channel.is_some() {
                    vec![0x90, 0x00]
                } else {
                    vec![0x63, 0x00]
                }
            }
            (VERIFY, _, _) => vec![0x69, 0x82],
            _ => vec![0x6D, 0x00],
        }
    }

    fn answer_protected(&mut self, apdu: &[u8]) -> Vec<u8> {
        let mut channel = self.channel.take().expect("protected only with a channel");
        let Some(inner) = channel.unwrap(apdu) else {
            return vec![0x66, 0x88];
        };
        let answer = if inner.ins == VERIFY {
            self.pin_queries.push(PinQuery {
                transaction: self.transactions,
                with_pin: !inner.data.is_empty(),
            });
            if inner.data.is_empty() {
                self.retries_status().to_be_bytes().to_vec()
            } else {
                self.verify_pin(&inner.data).to_be_bytes().to_vec()
            }
        } else if (inner.ins, inner.p1, inner.p2) == (MSE, 0x41, 0xB6) {
            self.select_signing_key(&inner.data).to_be_bytes().to_vec()
        } else if (inner.ins, inner.p1, inner.p2) == (PSO, 0x9E, 0x9A) {
            self.sign(&inner.data)
        } else {
            let delivery = std::mem::replace(&mut self.delivery, Delivery::Direct);
            let answer = self.answer(&Apdu {
                ins: inner.ins,
                p1: inner.p1,
                p2: inner.p2,
                data: &inner.data,
                le: inner.le,
            });
            self.delivery = delivery;
            answer
        };
        let response = channel.wrap(&answer);
        match self.channel {
            Some(_) => self.mark_last_handshake_inside_channel(),
            None => self.channel = Some(channel),
        }
        response
    }

    /// A channel negotiated inside another replaces it once its last answer is wrapped.
    fn mark_last_handshake_inside_channel(&mut self) {
        if let Some(handshake) = self.chip_mut().handshakes.last_mut() {
            handshake.inside_channel = true;
        }
    }

    fn verify_pin(&mut self, pin: &[u8]) -> u16 {
        if self.user_channel {
            return 0x6982;
        }
        if self.retries == 0 {
            return 0x6983;
        }
        if pin == self.pin {
            self.pin_verified = true;
            self.retries = DEFAULT_RETRIES;
            return 0x9000;
        }
        self.retries -= 1;
        self.retries_status()
    }

    /// `MSE SET DST` data `84 02 <key file>`.
    fn select_signing_key(&mut self, data: &[u8]) -> u16 {
        match data {
            [0x84, 0x02, high, low] if self.holder_keys.contains_key(&[*high, *low]) => {
                self.signing_key = Some([*high, *low]);
                0x9000
            }
            _ => 0x6A88,
        }
    }

    /// PKCS#1 v1.5 signature of a `DigestInfo`, only in the user channel with the PIN verified.
    fn sign(&mut self, digest_info: &[u8]) -> Vec<u8> {
        if !self.user_channel || !self.pin_verified {
            return vec![0x69, 0x82];
        }
        let Some(key) = self
            .signing_key
            .and_then(|file| self.holder_keys.get(&file))
        else {
            return vec![0x69, 0x85];
        };
        let signature = key
            .sign(Pkcs1v15Sign::new_unprefixed(), digest_info)
            .expect("DigestInfo fits the holder key");
        with_status(signature, 0x9000)
    }

    fn retries_status(&self) -> u16 {
        match (self.retries_answer, self.retries) {
            (Some(status), _) => status,
            (None, 0) => 0x6983,
            (None, retries) => 0x63C0 | u16::from(retries),
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
        self.commands += 1;
        let protected = apdu.first().is_some_and(|cla| cla & PROTECTED == PROTECTED);
        if protected && self.channel.is_some() {
            return match self.fault.take() {
                Some(Fault::Reset) => {
                    self.reset()?;
                    Err(Error::CardReset)
                }
                Some(Fault::ChannelLost) => {
                    self.channel = None;
                    Ok(vec![0x66, 0x88])
                }
                Some(Fault::BadResponseMac) => {
                    let mut response = self.answer_protected(apdu);
                    let mac_end = response.len() - 3;
                    response[mac_end] ^= 0xFF;
                    Ok(response)
                }
                None => Ok(self.answer_protected(apdu)),
            };
        }
        let Some(apdu) = parse(apdu) else {
            return Ok(vec![0x67, 0x00]);
        };
        if apdu.ins != GET_RESPONSE {
            self.pending.clear();
            self.channel = None;
        }
        Ok(self.answer(&apdu))
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.pending.clear();
        self.current.clear();
        self.channel = None;
        self.user_channel = false;
        self.pin_verified = false;
        self.signing_key = None;
        if let Some(chip) = &mut self.chip {
            chip.reset();
        }
        Ok(self.atr.clone())
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.transactions += 1;
        if self.retry_lost_between_transactions && !self.pin_queries.is_empty() {
            self.retry_lost_between_transactions = false;
            self.retries = self.retries.saturating_sub(1);
        }
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
