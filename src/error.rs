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
}
