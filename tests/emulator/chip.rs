//! Card side of the CWA-14890 mutual authentication, with an ICC key pair and component
//! certificate generated at test time.

use std::{str::FromStr, sync::LazyLock, time::Duration};

use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, SigningKey},
    pkcs8::EncodePublicKey,
    rand_core::{OsRng, RngCore},
    sha2::Sha256,
    traits::PublicKeyParts,
};
use sha1::{Digest, Sha1};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{Decode, Encode},
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

use super::channel::CardChannel;

/// Bytes of every RSA key in the handshake.
pub const KEY_LENGTH: usize = 128;
/// GET CHIP INFO answer; the driver left-pads it to 8 bytes.
pub const SERIAL: [u8; 7] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16];

const PUBLIC_EXPONENT: u32 = 65_537;
const SEED_LENGTH: usize = 32;
const HASH_LENGTH: usize = 20;
const PADDING_LENGTH: usize = KEY_LENGTH - SEED_LENGTH - HASH_LENGTH - 2;
const FRAME_START: u8 = 0x6A;
const FRAME_END: u8 = 0xBC;

/// Public half of a terminal key set the card accepts.
#[derive(Clone)]
pub struct TerminalKey {
    pub chr: [u8; 8],
    pub modulus: Vec<u8>,
    /// Whether the key opens the user channel rather than the PIN channel.
    pub user: bool,
}

impl TerminalKey {
    fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey::new(
            BigUint::from_bytes_be(&self.modulus),
            BigUint::from(PUBLIC_EXPONENT),
        )
        .expect("terminal keys are valid RSA keys")
    }
}

/// Randomness the driver sent in one handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub rnd_ifd: Vec<u8>,
    pub kifd: Vec<u8>,
    /// Whether it arrived protected by an open channel.
    pub inside_channel: bool,
}

struct Pki {
    icc: RsaPrivateKey,
    component_certificate: Vec<u8>,
}

static PKI: LazyLock<Pki> = LazyLock::new(|| {
    let ca = RsaPrivateKey::new(&mut OsRng, KEY_LENGTH * 8).unwrap();
    let icc = RsaPrivateKey::new(&mut OsRng, KEY_LENGTH * 8).unwrap();
    Pki {
        component_certificate: issue(&ca, &icc.to_public_key()),
        icc,
    }
});

fn issue(ca: &RsaPrivateKey, icc: &RsaPublicKey) -> Vec<u8> {
    let signer = SigningKey::<Sha256>::new(ca.clone());
    let spki =
        SubjectPublicKeyInfoOwned::from_der(icc.to_public_key_der().unwrap().as_bytes()).unwrap();
    CertificateBuilder::new(
        Profile::Leaf {
            issuer: Name::from_str("CN=Test component CA").unwrap(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(1_u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        Name::from_str("CN=Test ICC").unwrap(),
        spki,
        &signer,
    )
    .unwrap()
    .build::<Signature>()
    .unwrap()
    .to_der()
    .unwrap()
}

/// The X.509 component certificate the card stores at `3F00/601F`, signed by the test CA.
pub fn component_certificate() -> Vec<u8> {
    PKI.component_certificate.clone()
}

/// Handshake state between the commands of one mutual authentication.
pub struct Chip {
    terminals: Vec<TerminalKey>,
    terminal: Option<TerminalKey>,
    rnd_ifd: Option<[u8; 8]>,
    kicc: [u8; SEED_LENGTH],
    pub tamper_internal_authentication: bool,
    pub handshakes: Vec<Handshake>,
    pub internal_authentications: usize,
}

impl Chip {
    pub fn new(terminals: &[TerminalKey]) -> Self {
        Self {
            terminals: terminals.to_vec(),
            terminal: None,
            rnd_ifd: None,
            kicc: [0; SEED_LENGTH],
            tamper_internal_authentication: false,
            handshakes: Vec::new(),
            internal_authentications: 0,
        }
    }

    /// Whether the selected terminal key opens the user channel.
    pub fn user_terminal(&self) -> bool {
        self.terminal.as_ref().is_some_and(|terminal| terminal.user)
    }

    pub fn reset(&mut self) {
        self.terminal = None;
        self.rnd_ifd = None;
    }

    /// `MSE SET AT` data `83 0C <CHR padded to 12> 84 02 <key>`: selects the terminal key.
    pub fn select_terminal(&mut self, data: &[u8]) -> u16 {
        let [0x83, 0x0C, chr @ .., 0x84, 0x02, _, _] = data else {
            return 0x6A80;
        };
        self.terminal = self
            .terminals
            .iter()
            .find(|terminal| chr.ends_with(&terminal.chr))
            .cloned();
        if self.terminal.is_some() {
            0x9000
        } else {
            0x6A88
        }
    }

    /// Signs `6A ‖ PRND1 ‖ Kicc ‖ SHA-1(PRND1 ‖ Kicc ‖ RND.IFD ‖ CHR) ‖ BC` with the ICC key
    /// and encrypts `min(SIG, N.ICC − SIG)` for the terminal.
    pub fn internal_authenticate(&mut self, data: &[u8]) -> Result<Vec<u8>, u16> {
        let Some(terminal) = &self.terminal else {
            return Err(0x6985);
        };
        let rnd_ifd: [u8; 8] = data
            .get(..8)
            .filter(|_| data.len() == 16)
            .and_then(|rnd| rnd.try_into().ok())
            .ok_or(0x6A80_u16)?;
        let mut prnd1 = [0; PADDING_LENGTH];
        OsRng.fill_bytes(&mut prnd1);
        OsRng.fill_bytes(&mut self.kicc);
        let hash = Sha1::new()
            .chain_update(prnd1)
            .chain_update(self.kicc)
            .chain_update(data)
            .finalize();
        let mut kicc = self.kicc;
        if self.tamper_internal_authentication {
            kicc[0] ^= 0x01;
        }
        let frame = [&[FRAME_START][..], &prnd1, &kicc, &hash, &[FRAME_END]].concat();
        let icc = &PKI.icc;
        let sig = rsa::hazmat::rsa_decrypt_and_check(icc, Some(&mut OsRng), &uint(&frame))
            .expect("frame below the ICC modulus");
        let sigmin = (icc.n() - &sig).min(sig);
        let answer = rsa::hazmat::rsa_encrypt(&terminal.public_key(), &sigmin).unwrap();
        self.rnd_ifd = Some(rnd_ifd);
        self.internal_authentications += 1;
        Ok(left_padded(&answer))
    }

    /// Checks the terminal's `6A ‖ PRND2 ‖ Kifd ‖ SHA-1(PRND2 ‖ Kifd ‖ RND.ICC ‖ SN.ICC) ‖ BC`
    /// and derives the channel from it.
    pub fn external_authenticate(&mut self, data: &[u8], rnd_icc: [u8; 8]) -> Option<CardChannel> {
        let (Some(terminal), Some(rnd_ifd)) = (&self.terminal, self.rnd_ifd) else {
            return None;
        };
        let terminal_key = terminal.public_key();
        let sigmin =
            rsa::hazmat::rsa_decrypt_and_check(&PKI.icc, Some(&mut OsRng), &uint(data)).ok()?;
        let frame = [sigmin.clone(), terminal_key.n() - &sigmin]
            .into_iter()
            .filter_map(|sig| rsa::hazmat::rsa_encrypt(&terminal_key, &sig).ok())
            .map(|frame| left_padded(&frame))
            .find(|frame| frame[0] == FRAME_START && frame[KEY_LENGTH - 1] == FRAME_END)?;
        let prnd2 = &frame[1..=PADDING_LENGTH];
        let kifd = &frame[1 + PADDING_LENGTH..1 + PADDING_LENGTH + SEED_LENGTH];
        let hash = &frame[KEY_LENGTH - 1 - HASH_LENGTH..KEY_LENGTH - 1];
        let mut serial = [0; 8];
        serial[1..].copy_from_slice(&SERIAL);
        let expected = Sha1::new()
            .chain_update(prnd2)
            .chain_update(kifd)
            .chain_update(rnd_icc)
            .chain_update(serial)
            .finalize();
        if expected[..] != *hash {
            return None;
        }
        self.handshakes.push(Handshake {
            rnd_ifd: rnd_ifd.to_vec(),
            kifd: kifd.to_vec(),
            inside_channel: false,
        });
        let kifd: [u8; SEED_LENGTH] = kifd.try_into().unwrap();
        Some(CardChannel::derive(&self.kicc, &kifd, rnd_icc, rnd_ifd))
    }
}

fn uint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn left_padded(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut padded = vec![0; KEY_LENGTH - bytes.len()];
    padded.extend(bytes);
    padded
}
