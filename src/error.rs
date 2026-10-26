use crate::StatusWord;

/// Failures talking to the DNIe.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The reader or transport layer did not deliver the APDU.
    #[error("transport failed: {0}")]
    Transport(String),
    /// The card answered with an error status word.
    #[error("card answered {0}")]
    Status(StatusWord),
    /// The response is too short to carry a status word.
    #[error("response of {0} bytes has no status word")]
    TruncatedResponse(usize),
    /// A command does not fit in a short APDU, as when the card declares a file longer than an
    /// offset can address.
    #[error("{0} bytes do not fit in a short APDU")]
    CommandTooLong(usize),
    /// A secure messaging response failed its MAC check or is malformed.
    #[error("secure channel failed: {0}")]
    SecureChannel(&'static str),
    /// The card answered `66 88`: it no longer recognises the secure channel.
    #[error("secure channel lost")]
    ChannelLost,
    /// The system has no smart card reader, or the named reader does not exist.
    #[error("no smart card reader found")]
    NoReader,
    /// No scanned reader holds a card, or the named reader is empty.
    #[error("no card in the reader")]
    NoCard,
    /// The card left the reader while connected: open a new transport and session.
    #[error("the card was removed")]
    CardRemoved,
    /// The card is not a DNIe.
    #[error("the card is not a DNIe")]
    NotDnie,
    /// The card is a DNIe 1.0 or 2.0.
    #[error("DNIe 1.0 and 2.0 are not supported")]
    LegacyDnie,
    /// The DNIe has its volatile memory erased (ATR ending in `65 81`).
    #[error("the DNIe is burned")]
    BurnedDnie,
    /// A PKCS#15 directory cannot be decoded.
    #[error("malformed PKCS#15 directory")]
    MalformedPkcs15,
    /// The bytes are not an X.509 certificate.
    #[error("not an X.509 certificate")]
    MalformedCertificate,
    /// The PIN is blocked: no attempt is left.
    #[error("the PIN is blocked")]
    PinBlocked,
    /// The PIN is not 8 to 16 characters long.
    #[error("the PIN must be 8 to 16 characters long")]
    InvalidPinFormat,
    /// The card refused the PIN.
    #[error("wrong PIN, {retries_left} attempts left")]
    WrongPin {
        /// Attempts the card still allows.
        retries_left: u8,
    },
    /// The retries on the card differ from those the session expects.
    #[error("the PIN retries changed since the session last knew them")]
    PinRetriesChanged,
    /// The session expects no retries: read them with `Session::pin_retries_left` first.
    #[error("the PIN retries were not read in this session")]
    PinRetriesNotRead,
    /// The digest is not as long as its hash algorithm makes them.
    #[error("digest of {actual} bytes where its algorithm gives {expected}")]
    DigestLength {
        /// Length the algorithm produces.
        expected: usize,
        /// Length received.
        actual: usize,
    },
    /// The card was reset, so any state built on it is lost.
    #[error("the card was reset")]
    CardReset,
}
