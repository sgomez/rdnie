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
use sha2::Sha256;
use x509_cert::{
    Certificate,
    der::{Decode, Encode, Header, Reader, SliceReader, asn1::ObjectIdentifier},
};
use zeroize::Zeroize;

use crate::{
    Command, Error, Transport,
    files::{self, Location},
    key_sets::{CA_PUBLIC_KEY_REFERENCE, ComponentRoots, ICC_PRIVATE_KEY_REFERENCE, KeySet},
    secure_messaging::SecureMessaging,
};

const ICC_CERTIFICATE: &[u8] = &[0x3F, 0x00, 0x60, 0x1F];
const COMPONENT_CA_CERTIFICATE: &[u8] = &[0x3F, 0x00, 0x60, 0x20];
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

// DER DigestInfo headers of PKCS#1 v1.5 (RFC 8017, note 1 of section 9.2).
const SHA1_DIGEST_INFO: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
];
const SHA256_DIGEST_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
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
    roots: &ComponentRoots,
) -> Result<SecureMessaging, Error> {
    let serial = padded_serial(card)?;
    let icc_key = icc_public_key(card, roots)?;
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

/// The public key of the X.509 component certificate, once its chain checks out as
/// `cwa_verify_icc_certificates` of `OpenSC` checks it, ending in any of `roots`.
fn icc_public_key(card: &mut dyn Transport, roots: &ComponentRoots) -> Result<RsaPublicKey, Error> {
    let ca = read_certificate(card, COMPONENT_CA_CERTIFICATE)?;
    let icc = read_certificate(card, ICC_CERTIFICATE)?;
    if !roots.iter().any(|root| ca.is_signed_by(root)) {
        return Err(Error::SecureChannel(
            "the component certificate chain is not signed by the DNIe root",
        ));
    }
    if !icc.is_signed_by(&ca.public_key()?) {
        return Err(Error::SecureChannel(
            "the component certificate is not signed by its CA",
        ));
    }
    icc.public_key()
}

const MALFORMED_CERTIFICATE: Error = Error::SecureChannel("malformed component certificate");

/// An X.509 certificate with its `tbsCertificate` exactly as the card stores it.
struct StoredCertificate {
    certificate: Certificate,
    tbs: Vec<u8>,
}

/// Reads the certificate at `path`; any data after it is ignored.
fn read_certificate(card: &mut dyn Transport, path: &[u8]) -> Result<StoredCertificate, Error> {
    let location = Location::new(path).ok_or(MALFORMED_CERTIFICATE)?;
    let encoded = files::read(card, &location).map_err(|error| match error {
        Error::Status(_) => Error::SecureChannel("the component certificate chain is missing"),
        other => other,
    })?;
    decode_certificate(&encoded).ok_or(MALFORMED_CERTIFICATE)
}

fn decode_certificate(encoded: &[u8]) -> Option<StoredCertificate> {
    let whole = SliceReader::new(encoded).ok()?.tlv_bytes().ok()?;
    let certificate = Certificate::from_der(whole).ok()?;
    let mut reader = SliceReader::new(whole).ok()?;
    Header::decode(&mut reader).ok()?;
    let tbs = reader.tlv_bytes().ok()?.to_vec();
    Some(StoredCertificate { certificate, tbs })
}

/// Checks `challenge ‖ component certificate ‖ answer`, the fuzz layout of the internal
/// authentication of a PIN channel without IDESP, and returns whether a root signed the certificate.
#[cfg(any(test, fuzzing))]
pub(crate) fn check_answers(input: &[u8], roots: &ComponentRoots) -> Result<bool, Error> {
    let keys = KeySet::for_card(None, crate::key_sets::Channel::Pin);
    let (challenge, rest) = input
        .split_at_checked(CHALLENGE_LENGTH + keys.terminal_chr.len())
        .ok_or(MALFORMED_CERTIFICATE)?;
    let encoded = SliceReader::new(rest)
        .and_then(|mut reader| reader.tlv_bytes())
        .map_err(|_| MALFORMED_CERTIFICATE)?;
    let certificate = decode_certificate(encoded).ok_or(MALFORMED_CERTIFICATE)?;
    let signed = roots.iter().any(|root| certificate.is_signed_by(root));
    let answer = &rest[encoded.len()..];
    validate_internal_authentication(
        answer,
        challenge,
        &keys.private_key(),
        &certificate.public_key()?,
    )?;
    Ok(signed)
}

impl StoredCertificate {
    fn public_key(&self) -> Result<RsaPublicKey, Error> {
        let spki = self
            .certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| MALFORMED_CERTIFICATE)?;
        RsaPublicKey::from_public_key_der(&spki).map_err(|_| MALFORMED_CERTIFICATE)
    }

    /// Whether `issuer` signed the stored TBS with PKCS#1 v1.5 and SHA-1 or SHA-256.
    fn is_signed_by(&self, issuer: &RsaPublicKey) -> bool {
        let oid = self.certificate.signature_algorithm.oid;
        let (prefix, digest) = if oid == SHA1_WITH_RSA {
            (SHA1_DIGEST_INFO, Sha1::digest(&self.tbs).to_vec())
        } else if oid == SHA256_WITH_RSA {
            (SHA256_DIGEST_INFO, Sha256::digest(&self.tbs).to_vec())
        } else {
            return false;
        };
        let Some(signature) = self.certificate.signature.as_bytes() else {
            return false;
        };
        let scheme = Pkcs1v15Sign {
            hash_len: Some(digest.len()),
            prefix: prefix.into(),
        };
        issuer.verify(scheme, &digest, signature).is_ok()
    }
}

/// Lets the card verify the CA CVC against its root key, then the terminal CVC against the CA.
fn verify_ifd_certificate_chain(card: &mut dyn Transport, keys: &KeySet) -> Result<(), Error> {
    set_public_key_to_verification(card, &CA_PUBLIC_KEY_REFERENCE)?;
    verify_certificate(card, keys.ca_cvc)?;
    set_public_key_to_verification(card, &keys.ca_chr)?;
    verify_certificate(card, keys.terminal_cvc)
}

fn set_public_key_to_verification(card: &mut dyn Transport, reference: &[u8]) -> Result<(), Error> {
    send(card, 0x00, MSE_SET, 0x81, 0xB6, tlv(0x83, reference), None)
        .map_err(|error| {
            refusal(
                error,
                "the card refused to select the key that verifies certificates",
            )
        })
        .map(drop)
}

fn verify_certificate(card: &mut dyn Transport, cvc: &[u8]) -> Result<(), Error> {
    send(card, 0x00, 0x2A, 0x00, 0xAE, cvc.to_vec(), None)
        .map_err(|error| refusal(error, "the card refused to verify the terminal certificate"))
        .map(drop)
}

fn refusal(error: Error, reason: &'static str) -> Error {
    match error {
        Error::Status(_) => Error::SecureChannel(reason),
        other => other,
    }
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
    send(card, 0x00, MSE_SET, 0xC1, 0xA4, template, None)
        .map_err(|error| refusal(error, "the card refused to select the authentication keys"))?;

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
    if icc_key.size() < 2 + SEED_LENGTH + SHA1_LENGTH {
        return Err(INTERNAL_AUTHENTICATION_FAILED);
    }
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
        .map_err(|error| refusal(error, "the card refused the external authentication"))?;
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
pub(crate) mod tests {
    use rsa::{BigUint, RsaPublicKey, pkcs8::EncodePublicKey};
    use x509_cert::{
        Certificate,
        der::{Decode, Encode},
        spki::SubjectPublicKeyInfoOwned,
    };

    use rsa::{
        RsaPrivateKey,
        hazmat::{rsa_decrypt_and_check, rsa_encrypt},
        rand_core::OsRng,
        traits::PublicKeyParts,
    };
    use sha1::{Digest, Sha1};

    use super::{check_answers, external_authentication, validate_internal_authentication};
    use crate::{
        Error, Session, Transport,
        emulator::{
            EmulatedDnie, HandshakeFault, Recorder, component_certificate,
            component_root_public_key, foreign_root_public_key, intermediate_certificate,
        },
        key_sets::{Channel, ComponentRoots, KeySet},
        session::tests::{card_with_channel, open},
    };

    const INTERNAL_AUTHENTICATE: u8 = 0x88;

    /// The challenge and the card's answer of the internal authentication of a handshake.
    pub(crate) fn recorded_internal_authentication() -> (Vec<u8>, Vec<u8>) {
        let roots = ComponentRoots::only(component_root_public_key());
        let mut session =
            Session::open_with_roots(Recorder::new(card_with_channel()), roots).unwrap();
        session.pin_retries().unwrap();
        let exchanges = session.into_transport().exchanges;
        let (command, response) = exchanges
            .iter()
            .find(|(command, _)| command[1] == INTERNAL_AUTHENTICATE)
            .unwrap();
        let length = usize::from(command[4]);
        (
            command[5..5 + length].to_vec(),
            response[..response.len() - 2].to_vec(),
        )
    }

    /// `challenge ‖ certificate ‖ answer`, as the `cwa14890` fuzz target takes them.
    pub(crate) fn answers(challenge: &[u8], certificate: &[u8], answer: &[u8]) -> Vec<u8> {
        [challenge, certificate, answer].concat()
    }

    #[test]
    fn checks_the_answers_of_a_recorded_handshake_with_the_component_key() {
        let (challenge, answer) = recorded_internal_authentication();
        let roots = ComponentRoots::only(component_root_public_key());
        let mut tampered = answer.clone();
        tampered[64] ^= 0x01;
        assert!(matches!(
            check_answers(
                &answers(&challenge, &component_certificate(), &answer),
                &roots
            ),
            Ok(false)
        ));
        for refused in [
            answers(&challenge, &component_certificate(), &tampered),
            answers(&challenge, &intermediate_certificate(), &answer),
        ] {
            assert!(matches!(
                check_answers(&refused, &roots),
                Err(Error::SecureChannel(_))
            ));
        }
    }

    #[test]
    fn refuses_an_answer_framed_by_a_key_too_short_for_a_frame() {
        let mut modulus = [0; 16];
        modulus[0] = 0x6A;
        modulus[15] = 0xBD;
        let key =
            RsaPublicKey::new(BigUint::from_bytes_be(&modulus), BigUint::from(65_537_u32)).unwrap();
        let mut certificate = Certificate::from_der(&component_certificate()).unwrap();
        certificate.tbs_certificate.subject_public_key_info =
            SubjectPublicKeyInfoOwned::from_der(key.to_public_key_der().unwrap().as_bytes())
                .unwrap();
        let (challenge, _) = recorded_internal_authentication();
        let roots = ComponentRoots::only(component_root_public_key());
        assert!(matches!(
            check_answers(
                &answers(&challenge, &certificate.to_der().unwrap(), &[0x01]),
                &roots
            ),
            Err(Error::SecureChannel(_))
        ));
    }

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
    fn accepts_a_genuine_component_certificate_chain() {
        let mut session = open(card_with_channel());
        assert!(session.pin_retries().is_ok());
        assert_eq!(session.into_transport().internal_authentications(), 1);
    }

    #[test]
    fn refuses_a_component_certificate_the_ca_did_not_sign() {
        refuses_before_authenticating(
            open(card_with_channel().with_untrusted_component_certificate()),
            "the component certificate is not signed by its CA",
        );
    }

    #[test]
    fn refuses_a_ca_certificate_the_root_did_not_sign() {
        refuses_before_authenticating(
            open(card_with_channel().with_untrusted_intermediate_certificate()),
            NOT_FROM_THE_ROOT,
        );
    }

    #[test]
    fn accepts_a_ca_certificate_the_second_root_signed_whatever_its_issuer() {
        let roots = ComponentRoots::pair(component_root_public_key(), foreign_root_public_key());
        let card = card_with_channel().with_untrusted_intermediate_certificate();
        let mut session = Session::open_with_roots(card, roots).unwrap();
        assert!(session.pin_retries().is_ok());
    }

    #[test]
    fn refuses_a_ca_certificate_neither_root_signed() {
        let roots = ComponentRoots::pair(foreign_root_public_key(), foreign_root_public_key());
        refuses_before_authenticating(
            Session::open_with_roots(card_with_channel(), roots).unwrap(),
            NOT_FROM_THE_ROOT,
        );
    }

    #[test]
    fn refuses_a_card_without_the_ca_certificate() {
        refuses_before_authenticating(
            open(card_with_channel().without_intermediate_certificate()),
            "the component certificate chain is missing",
        );
    }

    #[test]
    fn production_sessions_trust_only_the_embedded_roots() {
        refuses_before_authenticating(
            Session::open(card_with_channel()).unwrap(),
            NOT_FROM_THE_ROOT,
        );
    }

    fn answer_to_frame(frame: &[u8], icc: &RsaPrivateKey, terminal: &RsaPublicKey) -> Vec<u8> {
        let signature =
            rsa_decrypt_and_check(icc, Some(&mut OsRng), &BigUint::from_bytes_be(frame)).unwrap();
        let smaller = (icc.n() - &signature).min(signature);
        rsa_encrypt(terminal, &smaller).unwrap().to_bytes_be()
    }

    fn validated_frame(frame_edit: impl FnOnce(&mut Vec<u8>)) -> Result<[u8; 32], Error> {
        let [icc, terminal] =
            std::array::from_fn(|_| RsaPrivateKey::new(&mut OsRng, 1024).unwrap());
        let challenge = [0x5A; 16];
        let (prnd1, kicc) = ([0x11; 74], [0x22; 32]);
        let hash = Sha1::new()
            .chain_update(prnd1)
            .chain_update(kicc)
            .chain_update(challenge)
            .finalize();
        let mut frame = [&[0x6A][..], &prnd1, &kicc, &hash, &[0xBC]].concat();
        frame_edit(&mut frame);
        let answer = answer_to_frame(&frame, &icc, &terminal.to_public_key());
        validate_internal_authentication(&answer, &challenge, &terminal, &icc.to_public_key())
    }

    #[test]
    fn accepts_a_fully_framed_internal_authentication() {
        assert_eq!(validated_frame(|_| {}).unwrap(), [0x22; 32]);
    }

    #[test]
    fn refuses_a_half_framed_internal_authentication() {
        for (edit, missing) in [(0, "6A start"), (127, "BC end")] {
            assert!(
                matches!(
                    validated_frame(|frame| frame[edit] ^= 0x01),
                    Err(Error::SecureChannel(_))
                ),
                "{missing}"
            );
        }
    }

    /// A validation against a card key of `size` bytes whose answer is framed to fit it exactly.
    fn validated_with_key_of(size: usize) -> Result<[u8; 32], Error> {
        let icc = RsaPrivateKey::new(&mut OsRng, size * 8).unwrap();
        let terminal = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let challenge = [0x5A; 16];
        let payload = vec![0x22; size - 22];
        let hash = Sha1::new()
            .chain_update(&payload)
            .chain_update(challenge)
            .finalize();
        let frame = [&[0x6A][..], &payload, &hash, &[0xBC]].concat();
        let answer = answer_to_frame(&frame, &icc, &terminal.to_public_key());
        validate_internal_authentication(&answer, &challenge, &terminal, &icc.to_public_key())
    }

    #[test]
    fn accepts_a_card_key_of_the_minimum_length() {
        assert_eq!(validated_with_key_of(54).unwrap(), [0x22; 32]);
    }

    #[test]
    fn refuses_a_card_key_one_byte_under_the_minimum_length() {
        assert!(matches!(
            validated_with_key_of(53),
            Err(Error::SecureChannel(_))
        ));
    }

    struct AcceptingCard(Vec<Vec<u8>>);

    impl Transport for AcceptingCard {
        fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.push(apdu.to_vec());
            Ok(vec![0x90, 0x00])
        }

        fn reset(&mut self) -> Result<Vec<u8>, Error> {
            Ok(vec![])
        }

        fn transaction<R>(
            &mut self,
            body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
        ) -> Result<R, Error> {
            body(self)
        }
    }

    #[test]
    fn sends_the_smaller_of_the_signature_and_its_complement_to_the_card() {
        let keys = KeySet::for_card(None, Channel::User);
        let icc = RsaPrivateKey::new(&mut OsRng, keys.modulus.len() * 8).unwrap();
        let half = BigUint::from_bytes_be(keys.modulus) / 2_u8;
        // Each handshake draws a fresh frame, so half of them sign above N.IFD / 2.
        for _ in 0..16 {
            let mut card = AcceptingCard(vec![]);
            external_authentication(&mut card, keys, &[0x01; 8], [0x02; 8], &icc.to_public_key())
                .unwrap();
            let apdu = &card.0[0];
            let token = BigUint::from_bytes_be(&apdu[5..5 + usize::from(apdu[4])]);
            let sent = rsa_decrypt_and_check(&icc, Some(&mut OsRng), &token).unwrap();
            assert!(sent <= half);
        }
    }

    fn open_failing(fault: HandshakeFault) -> Result<u8, Error> {
        open(card_with_channel().failing(fault)).pin_retries()
    }

    #[test]
    fn reports_a_reset_during_the_external_authentication() {
        assert!(matches!(
            open_failing(HandshakeFault::ResettingOnExternalAuthenticate),
            Err(Error::CardReset)
        ));
    }

    #[test]
    fn reports_a_transport_failure_during_the_external_authentication() {
        assert!(matches!(
            open_failing(HandshakeFault::FailingOnExternalAuthenticate),
            Err(Error::Transport(_))
        ));
    }

    #[test]
    fn reports_a_refused_external_authentication_as_a_secure_channel_failure() {
        assert!(matches!(
            open_failing(HandshakeFault::RefusingExternalAuthenticate),
            Err(Error::SecureChannel(
                "the card refused the external authentication"
            ))
        ));
    }

    #[test]
    fn reports_a_refused_handshake_step_as_a_secure_channel_failure() {
        for (fault, reason) in [
            (
                HandshakeFault::RefusingMseVerifyCertificate,
                "the card refused to select the key that verifies certificates",
            ),
            (
                HandshakeFault::RefusingVerifyCertificate,
                "the card refused to verify the terminal certificate",
            ),
            (
                HandshakeFault::RefusingMseAuthentication,
                "the card refused to select the authentication keys",
            ),
        ] {
            assert!(
                matches!(open_failing(fault), Err(Error::SecureChannel(message)) if message == reason),
                "{reason}"
            );
        }
    }

    #[test]
    fn keeps_the_status_of_the_other_refused_steps() {
        for fault in [
            HandshakeFault::RefusingInternalAuthenticate,
            HandshakeFault::RefusingChallenge,
            HandshakeFault::RefusingChipInfo,
        ] {
            assert!(matches!(open_failing(fault), Err(Error::Status(_))));
        }
    }

    const NOT_FROM_THE_ROOT: &str =
        "the component certificate chain is not signed by the DNIe root";

    fn refuses_before_authenticating(mut session: Session<EmulatedDnie>, reason: &str) {
        assert!(matches!(
            session.pin_retries(),
            Err(Error::SecureChannel(message)) if message == reason
        ));
        assert_eq!(session.into_transport().internal_authentications(), 0);
    }
}
