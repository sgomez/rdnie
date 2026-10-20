//! Entry points of the `fuzz/` crate into the parsers of card data, built only under `cfg(fuzzing)`.

use crate::{
    Error, Holder, Response, StatusWord, certificates, cwa14890, files, key_sets::ComponentRoots,
    pkcs15, secure_messaging::SecureMessaging,
};

const BLOCK: usize = 8;

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

/// The response the card protects for the fixed channel: the first two bytes are its status word and
/// the rest, cut to whole blocks, its plain data with any padding.
pub fn secure_messaging(input: &[u8]) -> Result<Response, Error> {
    let Some((status, plain)) = input.split_first_chunk() else {
        return Response::parse(input);
    };
    let plain = &plain[..plain.len() - plain.len() % BLOCK];
    let mut channel = SecureMessaging::fixed();
    let protected = channel.protected_response(plain, StatusWord(u16::from_be_bytes(*status)));
    channel.unprotect(&Response::parse(&protected)?)
}

/// A protected response as it arrives, checked against the fixed channel.
pub fn secure_messaging_raw(raw: &[u8]) -> Result<Response, Error> {
    SecureMessaging::fixed().unprotect(&Response::parse(raw)?)
}

/// The internal authentication challenge, a component certificate and the card's answer.
pub fn cwa14890(input: &[u8]) -> Result<bool, Error> {
    cwa14890::check_answers(input, &ComponentRoots::embedded())
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
