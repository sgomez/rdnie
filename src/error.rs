use crate::StatusWord;

/// Failures talking to the DNIe.
#[derive(Debug, thiserror::Error)]
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
    /// The command does not fit in a short APDU.
    #[error("{0} bytes do not fit in a short APDU")]
    CommandTooLong(usize),
    /// No reader holds a DNIe.
    #[error("no DNIe in any reader")]
    NoDnie,
    /// The card is not a DNIe.
    #[error("the card is not a DNIe")]
    NotDnie,
    /// The card is a DNIe 1.0 or 2.0.
    #[error("DNIe 1.0 and 2.0 are not supported")]
    LegacyDnie,
    /// The DNIe has its volatile memory erased (ATR ending in `65 81`).
    #[error("the DNIe is burned")]
    BurnedDnie,
    /// The card was reset, so any state built on it is lost.
    #[error("the card was reset")]
    CardReset,
}
