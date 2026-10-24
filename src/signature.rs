// Derived from JMulticard: see LICENSE.jmulticard.md.

//! Signing a caller's digest in the user channel, as `Dnie.signOperation` does.

use crate::{Command, Error, KeyReference, Transport, secure_messaging::SecureChannel};

const SHA256_HEADER: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_HEADER: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_HEADER: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];
const PRIVATE_KEY_REFERENCE: u8 = 0x84;

/// Hash algorithm of the digest to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    fn digest_info_header(self) -> &'static [u8] {
        match self {
            Self::Sha256 => SHA256_HEADER,
            Self::Sha384 => SHA384_HEADER,
            Self::Sha512 => SHA512_HEADER,
        }
    }
}

/// The PKCS#1 `DigestInfo` of `digest`, if its length is the one `algorithm` produces.
pub(crate) fn digest_info(algorithm: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>, Error> {
    let header = algorithm.digest_info_header();
    let expected = usize::from(header[header.len() - 1]);
    if digest.len() != expected {
        return Err(Error::DigestLength {
            expected,
            actual: digest.len(),
        });
    }
    Ok([header, digest].concat())
}

/// Selects `key` with `MSE SET DST` and has the card sign `digest_info` with `PSO`.
pub(crate) fn sign(
    channel: &mut SecureChannel<'_>,
    key: &KeyReference,
    digest_info: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let [high, low] = key.file;
    let template = vec![PRIVATE_KEY_REFERENCE, 0x02, high, low];
    send(channel, 0x22, 0x41, 0xB6, template)?;
    send(channel, 0x2A, 0x9E, 0x9A, digest_info)
}

fn send(
    channel: &mut SecureChannel<'_>,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let command = Command {
        cla: 0x00,
        ins,
        p1,
        p2,
        data,
        le: None,
    };
    channel.transmit(&command)?.into_success()
}
