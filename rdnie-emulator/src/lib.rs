//! Emulated DNIe behind the `Transport` seam, generated at run time from no real card data.
//!
//! The default API is covered by semver. The `faults` feature adds the knobs rdnie's own tests
//! use (delivery modes, response shapes, handshake faults, custom files, certificates, channel
//! faults, counters and logs) and is outside semver: it can change in any release.
//!
#![cfg_attr(
    not(feature = "faults"),
    doc = "Without `faults`, the knobs are not there:\n\n```compile_fail\nrdnie_emulator::EmulatedDnie::new(&[]);\n```"
)]
// rdnie's unit tests compile this source as a module and use only part of it.
#![allow(dead_code, unused_imports)]
// Pedantic lints for library APIs, which this test fixture was written without.
#![allow(
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::missing_panics_doc,
    clippy::wildcard_imports
)]

mod channel;
mod chip;
mod commands;
mod faults;
mod pkcs15;
mod terminal_keys;

use std::collections::BTreeMap;

use rdnie::{Error, KeyGeneration, Transport};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use channel::CardChannel;
#[cfg(any(test, feature = "faults"))]
pub use channel::ResponseShape;
#[cfg(not(any(test, feature = "faults")))]
use channel::ResponseShape;
use chip::Chip;
#[cfg(any(test, feature = "faults"))]
pub use chip::{
    Handshake, TerminalKey, component_certificate, component_root_public_key,
    foreign_root_public_key, intermediate_certificate,
};
#[cfg(not(any(test, feature = "faults")))]
use chip::{
    Handshake, TerminalKey, component_certificate, component_root_public_key,
    foreign_root_public_key, intermediate_certificate,
};
#[cfg(any(test, feature = "faults"))]
pub use faults::{DNIE_3_ATR, DNIE_4_ATR, Delivery, HandshakeFault, PinQuery};
#[cfg(not(any(test, feature = "faults")))]
use faults::{DNIE_3_ATR, DNIE_4_ATR, Delivery, HandshakeFault, PinQuery};
#[cfg(any(test, feature = "faults"))]
pub use pkcs15::{CDF, HolderCertificate, PRKDF, cdf, prkdf};
#[cfg(not(any(test, feature = "faults")))]
use pkcs15::{CDF, HolderCertificate, PRKDF, cdf, prkdf};
#[cfg(any(test, feature = "faults"))]
pub use terminal_keys::terminal_keys;
#[cfg(not(any(test, feature = "faults")))]
use terminal_keys::terminal_keys;

const FIRST_GENERATION_IDESP: &[u8] = b"BMP000001";
const SECOND_GENERATION_IDESP: &[u8] = b"BMP100001";

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
    verify_answer: Option<u16>,
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
    presence: Presence,
    master_file_answer: Vec<u8>,
    handshake_fault: Option<HandshakeFault>,
    unauthenticated_read: Option<u16>,
    endless: Option<Endless>,
    response_shape: ResponseShape,
    scheduled: Vec<(Step, Strike)>,
}

/// A step of a session, named by what the consumer does rather than by APDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `Session::open`.
    Opening,
    /// The first read of the holder's certificates.
    Certificates,
    /// Reading the remaining PIN retries.
    PinRetries,
    /// Sending the PIN with `VERIFY`.
    Verify,
    /// Having the card sign.
    Signing,
}

/// What strikes the card at a [`Step`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Strike {
    Removal,
    Reset,
}

/// A request to try again the card repeats to every protected command it targets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Endless {
    /// Outer `61xx`, then again to every `GET RESPONSE`.
    Pending,
    /// Inner `6Cxx`.
    WrongLength,
    /// Inner `6Cxx`, only to a `VERIFY` carrying a PIN.
    WrongLengthOnPin,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Presence {
    Inserted,
    Removed,
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

// Methods, not functions, so the keys can become per card without breaking callers.
#[allow(clippy::unused_self)]
impl EmulatedDnie {
    /// The component root the card's chain ends in, to pass to `Session::open_trusting`.
    pub fn component_root(&self) -> RsaPublicKey {
        component_root_public_key()
    }

    /// Public key of the holder's signing certificate.
    pub fn signing_public_key(&self) -> RsaPublicKey {
        pkcs15::signing_public_key()
    }

    /// Public key of the holder's authentication certificate.
    pub fn authentication_public_key(&self) -> RsaPublicKey {
        pkcs15::authentication_public_key()
    }
}

impl EmulatedDnie {
    fn blank(atr: &[u8]) -> Self {
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
            verify_answer: None,
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
            presence: Presence::Inserted,
            master_file_answer: Vec::new(),
            handshake_fault: None,
            unauthenticated_read: None,
            endless: None,
            response_shape: ResponseShape::Standard,
            scheduled: Vec::new(),
        }
    }

    fn stored_file(mut self, path: &[[u8; 2]], content: Vec<u8>) -> Self {
        let announced = content.len();
        self.files
            .insert(path.to_vec(), File { content, announced });
        self
    }

    fn secure_channel(self, terminals: &[TerminalKey]) -> Self {
        let mut card = self
            .stored_file(&[ICC_CERTIFICATE], chip::component_certificate())
            .stored_file(
                &[INTERMEDIATE_CERTIFICATE],
                chip::intermediate_certificate(),
            );
        card.chip = Some(Chip::new(terminals));
        card
    }

    fn certificates(self, certificates: &[HolderCertificate]) -> Self {
        let mut card = certificates.iter().fold(self, |card, certificate| {
            card.stored_file(&[certificate.file], certificate.stored())
        });
        for certificate in certificates {
            if let (Some(file), Some(key)) = (certificate.key_file, &certificate.key) {
                card.holder_keys.insert(file, key.clone());
            }
        }
        card.stored_file(&pkcs15::CDF, pkcs15::cdf(certificates))
            .stored_file(&pkcs15::PRKDF, pkcs15::prkdf(certificates))
    }

    /// A DNIe 3.0 that opens the secure channel with rdnie's terminal keys, expects
    /// [`DEFAULT_PIN`] with 3 retries left, and holds the signing and authentication certificates
    /// of a fictitious holder, document number `IDCES-99999999R`.
    pub fn dnie_3() -> Self {
        Self::dnie(&DNIE_3_ATR)
    }

    /// A DNIe 4.0, which differs from [`EmulatedDnie::dnie_3`] only in its ATR. This is rdnie's
    /// model of the card, not verified against a real DNIe 4.0.
    pub fn dnie_4() -> Self {
        Self::dnie(&DNIE_4_ATR)
    }

    /// Makes the card report the IDESP of `generation`, so rdnie picks that terminal key set.
    /// Cards start in the second generation.
    pub fn with_key_generation(self, generation: KeyGeneration) -> Self {
        self.stored_file(
            &[IDESP],
            if generation == KeyGeneration::First {
                FIRST_GENERATION_IDESP
            } else {
                SECOND_GENERATION_IDESP
            }
            .to_vec(),
        )
    }

    fn dnie(atr: &[u8]) -> Self {
        Self::blank(atr)
            .with_key_generation(KeyGeneration::Second)
            .secure_channel(&terminal_keys())
            .certificates(&[
                HolderCertificate::holder_authentication(1),
                HolderCertificate::holder_signing(2),
            ])
    }

    /// PIN attempts left, 0 to 3; 0 means blocked.
    pub fn with_pin_retries(mut self, retries: u8) -> Self {
        assert!(retries <= DEFAULT_RETRIES, "PIN retries go from 0 to 3");
        self.retries = retries;
        self
    }

    /// Sets the PIN the card accepts.
    pub fn with_pin(mut self, pin: &str) -> Self {
        self.pin = pin.as_bytes().to_vec();
        self
    }

    fn faulty(&self, fault: HandshakeFault) -> bool {
        self.handshake_fault == Some(fault)
    }

    /// Pulls the card out when `step` starts: that call and every later one report it removed.
    pub fn removing_card_at(mut self, step: Step) -> Self {
        self.scheduled.push((step, Strike::Removal));
        self
    }

    /// Resets the card when `step` starts: that call reports it reset, once.
    pub fn resetting_card_at(mut self, step: Step) -> Self {
        self.scheduled.push((step, Strike::Reset));
        self
    }

    fn strike(&mut self, step: Step) -> Result<(), Error> {
        let Some(at) = self.scheduled.iter().position(|(due, _)| *due == step) else {
            return Ok(());
        };
        match self.scheduled.remove(at).1 {
            Strike::Removal => {
                self.presence = Presence::Removed;
                Err(Error::CardRemoved)
            }
            Strike::Reset => {
                self.reset()?;
                Err(Error::CardReset)
            }
        }
    }

    fn chip_mut(&mut self) -> &mut Chip {
        self.chip.as_mut().expect("secure channel enabled before")
    }
}
