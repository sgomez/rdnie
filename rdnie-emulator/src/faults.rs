//! Fault knobs behind the `faults` feature, which is outside semver.

use super::*;

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

#[cfg(any(test, feature = "faults"))]
impl EmulatedDnie {
    /// A card answering with `atr`, holding no files and expecting [`DEFAULT_PIN`].
    pub fn new(atr: &[u8]) -> Self {
        Self::blank(atr)
    }

    /// Lets the card open a CWA-14890 channel with any of `terminals`.
    pub fn with_secure_channel(self, terminals: &[TerminalKey]) -> Self {
        self.secure_channel(terminals)
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

    /// Hands back response data as `delivery`.
    pub fn delivering(mut self, delivery: Delivery) -> Self {
        self.delivery = delivery;
        self
    }

    /// Stores `content` at `path`, given from the master file down.
    pub fn with_file(self, path: &[[u8; 2]], content: Vec<u8>) -> Self {
        self.stored_file(path, content)
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
        self.certificates(certificates)
    }
}
