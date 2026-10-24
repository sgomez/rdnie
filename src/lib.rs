//! Driver for the Spanish electronic ID card (DNIe) that talks APDU to the card, without PKCS#11 or system drivers.

// Lets the unit tests compile the source of `rdnie-emulator`, which names this crate `rdnie`.
#[cfg(test)]
extern crate self as rdnie;

mod apdu;
mod atr;
mod card_authenticator;
mod certificates;
mod channel;
mod cwa14890;
#[cfg(test)]
#[path = "../rdnie-emulator/src/lib.rs"]
mod emulator;
mod error;
mod files;
#[cfg(test)]
mod fuzz_seeds;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;
mod holder;
mod key_sets;
#[cfg(feature = "pcsc")]
mod pcsc_transport;
mod pin;
mod pkcs15;
#[cfg(test)]
#[path = "../tests/recorder/mod.rs"]
mod recorder;
mod resend;
mod secure_messaging;
mod session;
mod signature;
mod standard_error_codes;
mod transport;

pub(crate) use apdu::Command;
pub(crate) use apdu::Response;
pub use apdu::StatusWord;
pub use atr::{describe_atr, is_dnie};
pub use certificates::{Certificate, INTERMEDIATE_CA_LABEL, KeyReference, SIGNATURE_LABEL};
pub use error::Error;
pub use holder::Holder;
pub use key_sets::KeyGeneration;
#[cfg(feature = "pcsc")]
pub use pcsc_transport::PcscTransport;
pub use pin::Pin;
pub use session::Session;
pub use signature::DigestAlgorithm;
pub use transport::{Port, Transport};
