//! Holder certificates and the PKCS#15 CDF and PrKDF that describe them, built at test time.

use std::{io::Write, str::FromStr, sync::LazyLock, time::Duration};

use flate2::{Compression, write::ZlibEncoder};
use rsa::{
    RsaPrivateKey,
    pkcs1v15::{Signature, SigningKey},
    pkcs8::EncodePublicKey,
    rand_core::OsRng,
    sha2::Sha256,
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{Decode, Encode},
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

pub const CDF: [[u8; 2]; 2] = [[0x50, 0x15], [0x60, 0x04]];
pub const PRKDF: [[u8; 2]; 2] = [[0x50, 0x15], [0x60, 0x01]];

const MASTER_FILE: [u8; 2] = [0x3F, 0x00];
const SEQUENCE: u8 = 0x30;
const OCTET_STRING: u8 = 0x04;
// Cards pad their files up to the size they were created with.
const PADDING: usize = 16;
const HOLDER_KEY_BITS: usize = 2048;

static HOLDER_KEY: LazyLock<RsaPrivateKey> =
    LazyLock::new(|| RsaPrivateKey::new(&mut OsRng, HOLDER_KEY_BITS).unwrap());

/// A certificate on the card, with fake DER content of the given length.
#[derive(Clone)]
pub struct HolderCertificate {
    pub der: Vec<u8>,
    pub file: [u8; 2],
    pub key_file: Option<[u8; 2]>,
    /// Private key the card signs with, for certificates of a real key pair.
    pub key: Option<RsaPrivateKey>,
    id: u8,
    compressed: bool,
    trailing: usize,
    cdf_path: Option<Vec<u8>>,
    cdf_label: Option<Vec<u8>>,
}

impl HolderCertificate {
    /// A self-signed X.509 certificate of at least `length` bytes.
    pub fn new(id: u8, length: usize) -> Self {
        let base = x509_der(id, "");
        let padding = "a".repeat(length.saturating_sub(base.len()));
        Self::with_der(id, x509_der(id, &padding))
    }

    /// A self-signed X.509 certificate of a holder key pair the card can sign with.
    pub fn signing(id: u8) -> Self {
        Self {
            key: Some(HOLDER_KEY.clone()),
            ..Self::new(id, 0)
        }
    }

    /// A self-signed X.509 certificate issued to `subject`.
    pub fn with_subject(id: u8, subject: Name) -> Self {
        Self::with_der(id, x509_der_of(id, subject))
    }

    /// A certificate whose bytes are DER-shaped but not X.509.
    pub fn not_x509(id: u8, length: usize) -> Self {
        Self::with_der(id, fake_der(id, length))
    }

    /// Lists the certificate in the CDF under this path instead of its own file.
    pub fn listed_at(mut self, path: &[u8]) -> Self {
        self.cdf_path = Some(path.to_vec());
        self
    }

    fn with_der(id: u8, der: Vec<u8>) -> Self {
        Self {
            der,
            file: [0x70, id],
            key_file: Some([0x01, id]),
            key: None,
            id,
            compressed: false,
            trailing: 0,
            cdf_path: None,
            cdf_label: Some(format!("Cert{id}").into_bytes()),
        }
    }

    /// Stores `label` as the CDF label.
    pub fn labelled(mut self, label: &str) -> Self {
        self.cdf_label = Some(label.as_bytes().to_vec());
        self
    }

    /// Stores `label` as the CDF label, whether or not it is UTF-8.
    pub fn labelled_bytes(mut self, label: &[u8]) -> Self {
        self.cdf_label = Some(label.to_vec());
        self
    }

    /// Leaves the label out of the CDF object.
    pub fn without_label(mut self) -> Self {
        self.cdf_label = None;
        self
    }

    pub fn compressed(mut self) -> Self {
        self.compressed = true;
        self
    }

    /// Stores `bytes` of padding after the DER.
    pub fn followed_by(mut self, bytes: usize) -> Self {
        self.trailing = bytes;
        self
    }

    pub fn without_key(mut self) -> Self {
        self.key_file = None;
        self
    }

    /// The bytes the card stores: the DER and its padding, or an 8-byte header and the DER in zlib.
    pub fn stored(&self) -> Vec<u8> {
        if !self.compressed {
            let mut stored = self.der.clone();
            stored.resize(stored.len() + self.trailing, 0xFF);
            return stored;
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&self.der).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut stored = Vec::new();
        stored.extend_from_slice(&u32::try_from(self.der.len()).unwrap().to_le_bytes());
        stored.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_le_bytes());
        stored.extend(compressed);
        stored
    }

    fn pkcs15_id(&self) -> Vec<u8> {
        vec![0x4B, 0x49, 0x44, self.id]
    }

    fn label(&self) -> Vec<u8> {
        tlv(0x0C, format!("Cert{}", self.id).as_bytes())
    }
}

pub fn cdf(certificates: &[HolderCertificate]) -> Vec<u8> {
    padded(certificates.iter().map(|certificate| {
        let path = certificate
            .cdf_path
            .clone()
            .unwrap_or_else(|| [MASTER_FILE, certificate.file].concat());
        sequence(&[
            sequence(
                &certificate
                    .cdf_label
                    .iter()
                    .map(|l| tlv(0x0C, l))
                    .collect::<Vec<_>>(),
            ),
            sequence(&[tlv(OCTET_STRING, &certificate.pkcs15_id())]),
            tlv(0xA1, &sequence(&[sequence(&[tlv(OCTET_STRING, &path)])])),
        ])
    }))
}

pub fn prkdf(certificates: &[HolderCertificate]) -> Vec<u8> {
    padded(certificates.iter().rev().filter_map(|certificate| {
        let path = [MASTER_FILE, CDF[0], certificate.key_file?].concat();
        Some(sequence(&[
            sequence(&[certificate.label(), tlv(0x03, &[0x06, 0x40])]),
            sequence(&[
                tlv(OCTET_STRING, &certificate.pkcs15_id()),
                tlv(0x03, &[0x05, 0x20]),
                tlv(0x03, &[0x03, 0xB8]),
                tlv(0x02, &[certificate.id]),
            ]),
            tlv(0xA0, &sequence(&[])),
            tlv(
                0xA1,
                &sequence(&[
                    sequence(&[tlv(OCTET_STRING, &path)]),
                    tlv(0x02, &[0x08, 0x00]),
                ]),
            ),
        ]))
    }))
}

fn padded(objects: impl Iterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut file: Vec<u8> = objects.flatten().collect();
    file.extend_from_slice(&[0; PADDING]);
    file
}

fn sequence(children: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &children.concat())
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    match u8::try_from(value.len()) {
        Ok(length) if length < 0x80 => encoded.push(length),
        Ok(length) => encoded.extend_from_slice(&[0x81, length]),
        Err(_) => {
            encoded.push(0x82);
            encoded.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        }
    }
    encoded.extend_from_slice(value);
    encoded
}

/// A SEQUENCE header and filler derived from `seed`: DER-shaped, but no real certificate.
fn fake_der(seed: u8, length: usize) -> Vec<u8> {
    let filler = (0..length - 4).map(|index| {
        let byte = (index * 31 + usize::from(seed) * 17) % 251;
        u8::try_from(byte).unwrap()
    });
    let mut der = vec![SEQUENCE, 0x82];
    der.extend_from_slice(&u16::try_from(length - 4).unwrap().to_be_bytes());
    der.extend(filler);
    der
}

fn x509_der(id: u8, common_name: &str) -> Vec<u8> {
    x509_der_of(
        id,
        Name::from_str(&format!("CN=Test holder{common_name}")).unwrap(),
    )
}

fn x509_der_of(id: u8, subject: Name) -> Vec<u8> {
    let key = HOLDER_KEY.clone();
    let spki = SubjectPublicKeyInfoOwned::from_der(
        key.to_public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let signer = SigningKey::<Sha256>::new(key);
    let certificate = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(u32::from(id)),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        subject,
        spki,
        &signer,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap();
    certificate.to_der().unwrap()
}
