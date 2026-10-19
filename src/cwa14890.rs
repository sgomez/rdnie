// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.connection.cwa14890.Cwa14890OneV1Connection (Carlos Gamuci, Tomás García-Merás)
// - es.gob.jmulticard.connection.cwa14890.Cwa14890OneV2Connection (Tomás García-Merás)
// - es.gob.jmulticard.card.cwa14890.Cwa14890Card (Carlos Gamuci, Tomás García-Merás)
// - es.gob.jmulticard.card.dnie.Dnie (Tomás García-Merás)
// - es.gob.jmulticard.card.iso7816four.AbstractIso7816FourCard (Tomás García-Merás, Alberto Martínez)
// - es.gob.jmulticard.card.iso7816eight.AbstractIso7816EightCard (Tomás García-Merás)
// - es.gob.jmulticard.apdu.dnie.GetChipInfoApduCommand (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.GetChallengeApduCommand (Alberto Martínez Cerquero,
//   Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.InternalAuthenticateApduCommand (Carlos Gamuci Millán,
//   Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.ExternalAuthenticateApduCommand (Carlos Gamuci Millán,
//   Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.MseSetApduCommand (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationTemplateApduCommand (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationKeyApduCommand (Tomás García-Merás,
//   Carlos Gamuci Millán)
// - es.gob.jmulticard.apdu.iso7816eight.PsoVerifyCertificateApduCommand (Carlos Gamuci Millán,
//   Tomás García-Merás)
// rdnie takes the EUPL 1.1+ branch of the dual licence below.
//
// Controlador Java de la Secretaria de Estado de Administraciones Publicas
// para el DNI electronico.
//
// El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
// que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
// para la realizacion de procesos de autenticacion, firma electronica y validacion
// de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
// el acceso a los certificados y claves del DNI electronico, asi como la realizacion
// de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
// sido disenado para su funcionamiento independiente del sistema operativo final.
//
// Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
// e Impulso de la Administracion Electronica
//
// Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
// o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
// licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
// en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
// su compatibilidad con otros componentes.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// Lesser GNU General Public License publicada por la Free Software Foundation,
// tanto en la version 2.1 de la Licencia, o en una version posterior.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// European Union Public License publicada por la Comision Europea,
// tanto en la version 1.1 de la Licencia, o en una version posterior.
//
// Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
//
// Deberia recibir una copia de la European Union Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
//
// Este programa es distribuido con la esperanza de que sea util, pero
// SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
// o idoneidad para un proposito particular.

//! CWA-14890 mutual authentication of DNIe 3.0/4.0, as `Cwa14890OneV1Connection.open` runs it.

use rand_core::{OsRng, RngCore};
use rsa::{
    BigUint, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    hazmat::{rsa_decrypt_and_check, rsa_encrypt},
    pkcs8::DecodePublicKey,
    traits::PublicKeyParts,
};
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384, Sha512};
use x509_cert::der::{Decode, Encode, SliceReader, asn1::ObjectIdentifier};
use zeroize::Zeroize;

use crate::{
    Command, Error, Transport,
    files::{self, Location},
    key_sets::{CA_PUBLIC_KEY_REFERENCE, ICC_PRIVATE_KEY_REFERENCE, KeySet},
    secure_messaging::SecureMessaging,
};

const ICC_CERTIFICATE: &[u8] = &[0x3F, 0x00, 0x60, 0x1F];
const SERIAL_LENGTH: usize = 8;
const CHALLENGE_LENGTH: usize = 8;
const SEED_LENGTH: usize = 32;
const SHA1_LENGTH: usize = 20;
const KEY_REFERENCE_LENGTH: usize = 12;
const FRAME_START: u8 = 0x6A;
const FRAME_END: u8 = 0xBC;
const MSE_SET: u8 = 0x22;

const SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

// DER DigestInfo headers of PKCS#1 v1.5 (RFC 8017, note 1 of section 9.2).
const SHA1_DIGEST_INFO: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
];
const SHA256_DIGEST_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_DIGEST_INFO: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_DIGEST_INFO: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

const INTERNAL_AUTHENTICATION_FAILED: Error =
    Error::SecureChannel("the card failed the internal authentication");
const EXTERNAL_AUTHENTICATION_FAILED: Error =
    Error::SecureChannel("the external authentication could not be built");
const RANDOM_FAILED: Error = Error::SecureChannel("the OS random generator failed");

/// Authenticates card and terminal with `keys` and returns the channel they agree on.
pub(crate) fn open(
    card: &mut dyn Transport,
    keys: &KeySet,
    ca_key: &RsaPublicKey,
) -> Result<SecureMessaging, Error> {
    let serial = padded_serial(card)?;
    let icc_key = icc_public_key(card, ca_key)?;
    verify_ifd_certificate_chain(card, keys)?;

    let rnd_ifd: [u8; CHALLENGE_LENGTH] = random()?;
    let mut kicc = internal_authentication(card, keys, rnd_ifd, &icc_key)?;
    let rnd_icc = challenge(card)?;
    let mut kifd = external_authentication(card, keys, &serial, rnd_icc, &icc_key)?;

    let channel = SecureMessaging::derive(&kicc, &kifd, rnd_icc, rnd_ifd);
    kicc.zeroize();
    kifd.zeroize();
    Ok(channel)
}

/// The chip serial from `GET CHIP INFO`, left-padded to 8 bytes.
fn padded_serial(card: &mut dyn Transport) -> Result<Vec<u8>, Error> {
    let serial = send(card, 0x90, 0xB8, 0x00, 0x00, vec![], Some(7))?;
    let mut padded = vec![0; SERIAL_LENGTH.saturating_sub(serial.len())];
    padded.extend(serial);
    Ok(padded)
}

/// The public key of the X.509 component certificate, once `ca_key` has signed it; any data
/// after the certificate is ignored.
fn icc_public_key(card: &mut dyn Transport, ca_key: &RsaPublicKey) -> Result<RsaPublicKey, Error> {
    const MALFORMED: Error = Error::SecureChannel("malformed component certificate");
    let location = Location::new(ICC_CERTIFICATE).ok_or(MALFORMED)?;
    let encoded = files::read(card, &location)?;
    let certificate = SliceReader::new(&encoded)
        .and_then(|mut reader| x509_cert::Certificate::decode(&mut reader))
        .map_err(|_| MALFORMED)?;
    verify_signature(&certificate, ca_key)?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| MALFORMED)?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|_| MALFORMED)
}

fn verify_signature(
    certificate: &x509_cert::Certificate,
    ca_key: &RsaPublicKey,
) -> Result<(), Error> {
    const UNTRUSTED: Error =
        Error::SecureChannel("the component certificate is not signed by the CA");
    let tbs = certificate
        .tbs_certificate
        .to_der()
        .map_err(|_| UNTRUSTED)?;
    let signature = certificate.signature.as_bytes().ok_or(UNTRUSTED)?;
    let oid = certificate.signature_algorithm.oid;
    let (prefix, hashed): (&[u8], Vec<u8>) = if oid == SHA1_WITH_RSA {
        (SHA1_DIGEST_INFO, Sha1::digest(&tbs).to_vec())
    } else if oid == SHA256_WITH_RSA {
        (SHA256_DIGEST_INFO, Sha256::digest(&tbs).to_vec())
    } else if oid == SHA384_WITH_RSA {
        (SHA384_DIGEST_INFO, Sha384::digest(&tbs).to_vec())
    } else if oid == SHA512_WITH_RSA {
        (SHA512_DIGEST_INFO, Sha512::digest(&tbs).to_vec())
    } else {
        return Err(UNTRUSTED);
    };
    let scheme = Pkcs1v15Sign {
        hash_len: Some(hashed.len()),
        prefix: prefix.into(),
    };
    ca_key
        .verify(scheme, &hashed, signature)
        .map_err(|_| UNTRUSTED)
}

/// Lets the card verify the CA CVC against its root key, then the terminal CVC against the CA.
fn verify_ifd_certificate_chain(card: &mut dyn Transport, keys: &KeySet) -> Result<(), Error> {
    set_public_key_to_verification(card, &CA_PUBLIC_KEY_REFERENCE)?;
    verify_certificate(card, keys.ca_cvc)?;
    set_public_key_to_verification(card, &keys.ca_chr)?;
    verify_certificate(card, keys.terminal_cvc)
}

fn set_public_key_to_verification(card: &mut dyn Transport, reference: &[u8]) -> Result<(), Error> {
    send(card, 0x00, MSE_SET, 0x81, 0xB6, tlv(0x83, reference), None).map(drop)
}

fn verify_certificate(card: &mut dyn Transport, cvc: &[u8]) -> Result<(), Error> {
    send(card, 0x00, 0x2A, 0x00, 0xAE, cvc.to_vec(), None).map(drop)
}

/// Selects the terminal and ICC keys, has the card sign `RND.IFD ‖ CHR` and returns `Kicc`.
fn internal_authentication(
    card: &mut dyn Transport,
    keys: &KeySet,
    rnd_ifd: [u8; CHALLENGE_LENGTH],
    icc_key: &RsaPublicKey,
) -> Result<[u8; SEED_LENGTH], Error> {
    let mut terminal_reference = [0; KEY_REFERENCE_LENGTH];
    terminal_reference[KEY_REFERENCE_LENGTH - keys.terminal_chr.len()..]
        .copy_from_slice(&keys.terminal_chr);
    let mut template = tlv(0x83, &terminal_reference);
    template.extend(tlv(0x84, &ICC_PRIVATE_KEY_REFERENCE));
    send(card, 0x00, MSE_SET, 0xC1, 0xA4, template, None)?;

    let challenge = [&rnd_ifd[..], &keys.terminal_chr].concat();
    let answer = send(card, 0x00, 0x88, 0x00, 0x00, challenge.clone(), None)?;
    validate_internal_authentication(&answer, &challenge, &keys.private_key(), icc_key)
}

/// Recovers `6A ‖ PRND1 ‖ Kicc ‖ SHA-1(PRND1 ‖ Kicc ‖ RND.IFD ‖ CHR) ‖ BC` from the card's answer.
fn validate_internal_authentication(
    answer: &[u8],
    challenge: &[u8],
    terminal_key: &RsaPrivateKey,
    icc_key: &RsaPublicKey,
) -> Result<[u8; SEED_LENGTH], Error> {
    let sigmin = rsa_decrypt_and_check(terminal_key, Some(&mut OsRng), &uint(answer))
        .map_err(|_| INTERNAL_AUTHENTICATION_FAILED)?;
    if &sigmin >= icc_key.n() {
        return Err(INTERNAL_AUTHENTICATION_FAILED);
    }
    let frame = [sigmin.clone(), icc_key.n() - &sigmin]
        .iter()
        .filter_map(|sig| rsa_encrypt(icc_key, sig).ok())
        .filter_map(|frame| bytes(&frame, icc_key.size()))
        .find(|frame| is_framed(frame))
        .ok_or(INTERNAL_AUTHENTICATION_FAILED)?;

    let hash_start = frame.len() - 1 - SHA1_LENGTH;
    let kicc_start = hash_start - SEED_LENGTH;
    let expected = Sha1::new()
        .chain_update(&frame[1..hash_start])
        .chain_update(challenge)
        .finalize();
    if expected[..] != frame[hash_start..frame.len() - 1] {
        return Err(INTERNAL_AUTHENTICATION_FAILED);
    }
    let mut kicc = [0; SEED_LENGTH];
    kicc.copy_from_slice(&frame[kicc_start..hash_start]);
    Ok(kicc)
}

fn challenge(card: &mut dyn Transport) -> Result<[u8; CHALLENGE_LENGTH], Error> {
    send(card, 0x00, 0x84, 0x00, 0x00, vec![], Some(8))?
        .try_into()
        .map_err(|_| Error::SecureChannel("the card challenge is not 8 bytes long"))
}

/// Sends `min(SIG, N.IFD − SIG)` of `6A ‖ PRND2 ‖ Kifd ‖ SHA-1(PRND2 ‖ Kifd ‖ RND.ICC ‖ SN.ICC) ‖ BC`
/// encrypted for the card, and returns `Kifd`.
fn external_authentication(
    card: &mut dyn Transport,
    keys: &KeySet,
    serial: &[u8],
    rnd_icc: [u8; CHALLENGE_LENGTH],
    icc_key: &RsaPublicKey,
) -> Result<[u8; SEED_LENGTH], Error> {
    let terminal_key = keys.private_key();
    let mut prnd2 = vec![0; terminal_key.size() - 2 - SEED_LENGTH - SHA1_LENGTH];
    OsRng
        .try_fill_bytes(&mut prnd2)
        .map_err(|_| RANDOM_FAILED)?;
    let kifd: [u8; SEED_LENGTH] = random()?;
    let hash = Sha1::new()
        .chain_update(&prnd2)
        .chain_update(kifd)
        .chain_update(rnd_icc)
        .chain_update(serial)
        .finalize();
    let frame = [&[FRAME_START][..], &prnd2, &kifd, &hash, &[FRAME_END]].concat();

    let sig = rsa_decrypt_and_check(&terminal_key, Some(&mut OsRng), &uint(&frame))
        .map_err(|_| EXTERNAL_AUTHENTICATION_FAILED)?;
    let sigmin = (terminal_key.n() - &sig).min(sig);
    let token = rsa_encrypt(icc_key, &sigmin).map_err(|_| EXTERNAL_AUTHENTICATION_FAILED)?;
    let token = bytes(&token, icc_key.size()).ok_or(EXTERNAL_AUTHENTICATION_FAILED)?;
    send(card, 0x00, 0x82, 0x00, 0x00, token, None)
        .map_err(|_| Error::SecureChannel("the card refused the external authentication"))?;
    Ok(kifd)
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| RANDOM_FAILED)?;
    Ok(bytes)
}

fn is_framed(frame: &[u8]) -> bool {
    frame.first() == Some(&FRAME_START) && frame.last() == Some(&FRAME_END)
}

fn uint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// `value` big-endian, left-padded to `length` bytes; `None` if it does not fit.
fn bytes(value: &BigUint, length: usize) -> Option<Vec<u8>> {
    let value = value.to_bytes_be();
    let mut padded = vec![0; length.checked_sub(value.len())?];
    padded.extend(value);
    Some(padded)
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let length = u8::try_from(value.len()).expect("key references are short");
    [&[tag, length][..], value].concat()
}

/// Sends a plain command and returns its data if the card accepts it.
fn send(
    card: &mut dyn Transport,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u16>,
) -> Result<Vec<u8>, Error> {
    card.transmit(&Command {
        cla,
        ins,
        p1,
        p2,
        data,
        le,
    })?
    .into_success()
}

#[cfg(test)]
mod tests {
    use crate::{
        Error,
        session::tests::{card_with_channel, open},
    };

    #[test]
    fn refuses_a_tampered_internal_authentication() {
        let card = card_with_channel().tampering_internal_authentication();
        assert!(matches!(
            open(card).pin_retries(),
            Err(Error::SecureChannel(_))
        ));
    }

    #[test]
    fn draws_fresh_randomness_for_every_handshake() {
        let mut session = open(card_with_channel());
        session.pin_retries().unwrap();
        session.pin_retries().unwrap();
        let card = session.into_transport();
        let [first, second] = card.handshakes() else {
            panic!("expected two handshakes, got {}", card.handshakes().len());
        };
        assert_ne!(first.rnd_ifd, second.rnd_ifd);
        assert_ne!(first.kifd, second.kifd);
    }

    #[test]
    fn refuses_a_component_certificate_the_ca_did_not_sign() {
        let mut session = open(card_with_channel().with_untrusted_component_certificate());
        assert!(matches!(
            session.pin_retries(),
            Err(Error::SecureChannel(_))
        ));
        assert_eq!(session.into_transport().internal_authentications(), 0);
    }

    #[test]
    fn accepts_a_component_certificate_the_ca_signed() {
        let mut session = open(card_with_channel());
        assert!(session.pin_retries().is_ok());
        assert_eq!(session.into_transport().internal_authentications(), 1);
    }

    #[test]
    fn production_sessions_trust_only_the_embedded_ca() {
        let mut session = crate::Session::open(card_with_channel()).unwrap();
        assert!(matches!(
            session.pin_retries(),
            Err(Error::SecureChannel(_))
        ));
    }
}
