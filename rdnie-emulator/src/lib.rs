//! Emulated DNIe behind the `Transport` seam, generated at run time from no real card data.
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
mod pkcs15;
mod terminal_keys;

use std::collections::BTreeMap;

use rdnie::{Error, KeyGeneration, Transport};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use channel::CardChannel;
pub use channel::ResponseShape;
use chip::Chip;
pub use chip::{
    Handshake, TerminalKey, component_certificate, component_root_public_key,
    foreign_root_public_key, intermediate_certificate,
};
pub use pkcs15::{CDF, HolderCertificate, PRKDF, cdf, prkdf};
pub use terminal_keys::terminal_keys;

/// DNIe 3.0 ATR: byte 15 is `04`.
pub const DNIE_3_ATR: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

/// DNIe 4.0 ATR as rdnie models it, not checked against a real DNIe 4.0: the 3.0 ATR with the
/// chip bytes of the Atos card, the same operating system.
pub const DNIE_4_ATR: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x20, 0x02, 0x4C, 0x34, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

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

/// How the card hands back response data.
#[derive(Clone, Copy)]
pub enum Delivery {
    /// In the response itself.
    Direct,
    /// Announced with `61xx` and served by `GET RESPONSE` at most `chunk` bytes at a time.
    GetResponse {
        /// Most bytes per `GET RESPONSE`.
        chunk: usize,
    },
    /// Only when Le matches its length; otherwise `6Cxx` with the right one.
    ExactLe,
    /// Answers `61xx` to the command and to every `GET RESPONSE`.
    EndlessPending,
    /// Answers `6Cxx` to every command, whatever its Le.
    EndlessWrongLength,
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

/// A step of the handshake the card fails.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFault {
    /// Refuses `MSE SET` selecting the key that verifies the certificates.
    RefusingMseVerifyCertificate,
    /// Refuses `PSO VERIFY CERTIFICATE`.
    RefusingVerifyCertificate,
    /// Refuses `MSE SET` selecting the keys of the authentication.
    RefusingMseAuthentication,
    /// Refuses `INTERNAL AUTHENTICATE`.
    RefusingInternalAuthenticate,
    /// Refuses `GET CHALLENGE`.
    RefusingChallenge,
    /// Refuses `GET CHIP INFO`.
    RefusingChipInfo,
    /// Refuses `EXTERNAL AUTHENTICATE`.
    RefusingExternalAuthenticate,
    /// Resets the card on `EXTERNAL AUTHENTICATE`.
    ResettingOnExternalAuthenticate,
    /// The reader fails on `EXTERNAL AUTHENTICATE`.
    FailingOnExternalAuthenticate,
}

/// A `VERIFY` the card received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinQuery {
    /// Number of the transaction it arrived in, from 1.
    pub transaction: usize,
    /// Whether it carried a PIN rather than asking for the retries.
    pub with_pin: bool,
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
    /// A card answering with `atr`, holding no files and expecting [`DEFAULT_PIN`].
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
        }
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
        self.with_idesp(if generation == KeyGeneration::First {
            FIRST_GENERATION_IDESP
        } else {
            SECOND_GENERATION_IDESP
        })
    }

    fn dnie(atr: &[u8]) -> Self {
        Self::new(atr)
            .with_key_generation(KeyGeneration::Second)
            .with_secure_channel(&terminal_keys())
            .with_certificates(&[
                HolderCertificate::holder_authentication(1),
                HolderCertificate::holder_signing(2),
            ])
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

    /// Sets the PIN the card accepts, as raw bytes.
    pub fn with_pin_bytes(mut self, pin: &[u8]) -> Self {
        self.pin = pin.to_vec();
        self
    }

    /// Answers the retries query with `status` whatever the PIN state.
    pub fn answering_retries_with(mut self, status: u16) -> Self {
        self.retries_answer = Some(status);
        self
    }

    /// Answers a `VERIFY` carrying the PIN with `status`, without checking the PIN.
    pub fn answering_verify_with(mut self, status: u16) -> Self {
        self.verify_answer = Some(status);
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

    /// Fails `fault` of the handshake.
    pub fn failing(mut self, fault: HandshakeFault) -> Self {
        self.handshake_fault = Some(fault);
        self
    }

    fn faulty(&self, fault: HandshakeFault) -> bool {
        self.handshake_fault == Some(fault)
    }

    /// Pulls the card out: every later call reports it removed.
    pub fn remove_card(&mut self) {
        self.presence = Presence::Removed;
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

    /// Answers the next protected `READ BINARY` with its plain data under the outer `status`.
    pub fn answering_a_read_unauthenticated_with(mut self, status: u16) -> Self {
        self.unauthenticated_read = Some(status);
        self
    }

    /// Answers `61xx` to every protected command and to every `GET RESPONSE` after it.
    pub fn pending_forever_inside_the_channel(mut self) -> Self {
        self.endless = Some(Endless::Pending);
        self
    }

    /// Answers `6Cxx` inside the channel to every protected command, whatever its Le.
    pub fn asking_a_wrong_length_forever_inside_the_channel(mut self) -> Self {
        self.endless = Some(Endless::WrongLength);
        self
    }

    /// Answers `6Cxx` inside the channel to every `VERIFY` carrying a PIN, without checking it.
    pub fn asking_a_wrong_length_forever_on_the_pin(mut self) -> Self {
        self.endless = Some(Endless::WrongLengthOnPin);
        self
    }

    /// Lays out every protected response as `shape`.
    pub fn shaping_responses(mut self, shape: ResponseShape) -> Self {
        self.response_shape = shape;
        self
    }

    /// Answers SELECT of the master file by name with `9000` and `answer`, which is no FCI.
    pub fn answering_master_file_selection_with(mut self, answer: &[u8]) -> Self {
        self.master_file_answer = answer.to_vec();
        self
    }

    /// The randomness of every handshake the card accepted.
    pub fn handshakes(&self) -> &[Handshake] {
        self.chip.as_ref().map_or(&[], |chip| &chip.handshakes)
    }

    fn chip_mut(&mut self) -> &mut Chip {
        self.chip.as_mut().expect("secure channel enabled before")
    }

    /// Hands back response data as `delivery`.
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

    /// Stores `idesp` as the card's IDESP.
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
}
