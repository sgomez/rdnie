// Derived from JMulticard: see LICENSE.jmulticard.md.

//! The holder's certificates and the keys they pair with, read from the files `Dnie.loadCertificates` reads.

use std::fmt;

use der::{Decode, Reader, SliceReader};
use flate2::{Decompress, FlushDecompress, Status};

use crate::{
    Error,
    channel::CommandChannel,
    files::{self, Location},
    pkcs15,
};

const CDF: &[u8] = &[0x50, 0x15, 0x60, 0x04];
const PRKDF: &[u8] = &[0x50, 0x15, 0x60, 0x01];
/// Bytes before the zlib stream of a compressed certificate.
const COMPRESSION_HEADER: usize = 8;
/// Bytes a stored certificate may inflate to, well above any certificate the card holds.
const MAX_INFLATED: u64 = 16 * 1024;

/// Label of the DNIe intermediate CA certificate, which has no key on the card.
pub const INTERMEDIATE_CA_LABEL: &str = "CertCAIntermediaDGP";

/// Label of the holder's signature certificate, whose key signs.
pub const SIGNATURE_LABEL: &str = "CertFirmaDigital";

/// Certificate of the holder, paired with its private key on the card.
#[non_exhaustive]
pub struct Certificate {
    /// PKCS#15 label, exactly as the CDF stores it.
    pub label: String,
    /// Private key that matches the certificate.
    pub key: KeyReference,
}

/// Private key on the card, as the PrKDF describes it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyReference {
    pub(crate) id: Vec<u8>,
    pub(crate) file: [u8; 2],
}

// Card data stays out of logs.
impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate").finish_non_exhaustive()
    }
}

impl fmt::Debug for KeyReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyReference").finish_non_exhaustive()
    }
}

/// The CDF's certificates, each with its label and file path.
pub(crate) fn cdf(card: &mut dyn CommandChannel) -> Result<Vec<pkcs15::Entry>, Error> {
    let location = Location::new(CDF).expect("the CDF path is valid");
    pkcs15::entries(&files::read(card, &location)?, true)
}

/// The PrKDF's keys, each with its file path.
pub(crate) fn prkdf(card: &mut dyn CommandChannel) -> Result<Vec<pkcs15::Entry>, Error> {
    let location = Location::new(PRKDF).expect("the PrKDF path is valid");
    pkcs15::entries(&files::read(card, &location)?, false)
}

/// The CDF certificates the PrKDF has a key for, each paired with it by identifier.
pub(crate) fn keyed(
    cdf: &[pkcs15::Entry],
    prkdf: &[pkcs15::Entry],
) -> Result<Vec<Certificate>, Error> {
    let mut certificates = Vec::with_capacity(cdf.len());
    for entry in cdf {
        if let Some(key) = prkdf.iter().find(|key| key.id == entry.id) {
            let file = location(&key.path)?
                .last_file()
                .ok_or(Error::MalformedPkcs15)?;
            certificates.push(Certificate {
                label: entry.label.clone(),
                key: KeyReference {
                    id: entry.id.clone(),
                    file,
                },
            });
        }
    }
    Ok(certificates)
}

/// The X.509 certificate stored in the file of `entry`.
pub(crate) fn read(card: &mut dyn CommandChannel, entry: &pkcs15::Entry) -> Result<Vec<u8>, Error> {
    stored_x509(files::read(card, &location(&entry.path)?)?)
}

fn location(path: &[u8]) -> Result<Location, Error> {
    Location::new(path).ok_or(Error::MalformedPkcs15)
}

/// The X.509 certificate a certificate file stores, inflated if compressed.
pub(crate) fn stored_x509(stored: Vec<u8>) -> Result<Vec<u8>, Error> {
    x509(&decompressed(stored)).ok_or(Error::MalformedCertificate)
}

/// The X.509 certificate at the start of `stored`, without the bytes after it.
fn x509(stored: &[u8]) -> Option<Vec<u8>> {
    let der = SliceReader::new(stored).ok()?.tlv_bytes().ok()?;
    x509_cert::Certificate::from_der(der).ok()?;
    Some(der.to_vec())
}

/// The certificate inflated, or as stored if it does not inflate.
fn decompressed(stored: Vec<u8>) -> Vec<u8> {
    inflate(&stored).unwrap_or(stored)
}

fn inflate(stored: &[u8]) -> Option<Vec<u8>> {
    let stream = stored.get(COMPRESSION_HEADER..)?;
    let mut inflater = Decompress::new(true);
    let mut der = Vec::new();
    loop {
        der.reserve(1024);
        let consumed = usize::try_from(inflater.total_in()).ok()?;
        let produced = inflater.total_out();
        let status = inflater
            .decompress_vec(&stream[consumed..], &mut der, FlushDecompress::None)
            .ok()?;
        if inflater.total_out() > MAX_INFLATED {
            return None;
        }
        if status == Status::StreamEnd {
            return Some(der);
        }
        if inflater.total_out() == produced {
            return None;
        }
    }
}

#[cfg(test)]
mod tests;
