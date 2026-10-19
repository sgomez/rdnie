//! Driver for the Spanish electronic ID card (DNIe) that talks APDU to the card, without PKCS#11 or system drivers.

// Lets the unit tests share the emulator of the integration tests.
#[cfg(test)]
extern crate self as rdnie;

mod apdu;
mod atr;
mod certificates;
#[cfg(test)]
#[path = "../tests/emulator/mod.rs"]
mod emulator;
mod error;
mod files;
#[cfg(feature = "pcsc")]
mod pcsc_transport;
mod pkcs15;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the CWA-14890 channel is its caller")
)]
mod secure_messaging;
mod session;
mod transport;

pub use apdu::{Command, Response, StatusWord};
pub use atr::is_dnie;
pub use certificates::{Certificate, KeyReference};
pub use error::Error;
#[cfg(feature = "pcsc")]
pub use pcsc_transport::PcscTransport;
pub use session::Session;
pub use transport::Transport;
