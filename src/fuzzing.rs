//! Entry points of the `fuzz/` crate into the parsers of card data, built only under `cfg(fuzzing)`.

use crate::{Error, Holder, Response, certificates, files, pkcs15};

/// A response APDU, its status word and its description.
pub fn apdu(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let response = Response::parse(raw)?;
    let _ = response.status.to_string();
    response.into_success()
}

/// The FCI a SELECT returns, and the same bytes as a PKCS#15 path.
pub fn files(fci: &[u8]) -> Result<usize, Error> {
    let _ = files::Location::new(fci).and_then(|location| location.last_file());
    files::fci_length(fci)
}

/// A CDF, whose objects carry labels, and a PrKDF, whose objects do not.
pub fn pkcs15(file: &[u8]) -> Result<usize, Error> {
    Ok(pkcs15::entries(file, true)?.len() + pkcs15::entries(file, false)?.len())
}

/// A stored certificate, plain or compressed.
pub fn certificates(stored: &[u8]) -> Result<Vec<u8>, Error> {
    certificates::stored_x509(stored.to_vec())
}

/// The holder's data in a certificate.
pub fn holder(der: &[u8]) -> Result<Holder, Error> {
    Holder::from_der(der)
}
