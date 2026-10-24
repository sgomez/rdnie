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
    Error, Port, Session,
    channel::PlainChannel,
    emulator::{
        EmulatedDnie, HandshakeFault, component_certificate, component_root_public_key,
        foreign_root_public_key, intermediate_certificate,
    },
    key_sets::{Channel, ComponentRoots, KeyGeneration, KeySet},
    recorder::Recorder,
    session::tests::{card_with_channel, open},
};

const INTERNAL_AUTHENTICATE: u8 = 0x88;

/// The challenge and the card's answer of the internal authentication of a handshake.
pub(crate) fn recorded_internal_authentication() -> (Vec<u8>, Vec<u8>) {
    let roots = ComponentRoots::only(component_root_public_key());
    let mut session = Session::open_with_roots(Recorder::new(card_with_channel()), roots).unwrap();
    session.pin_retries_left().unwrap();
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
        SubjectPublicKeyInfoOwned::from_der(key.to_public_key_der().unwrap().as_bytes()).unwrap();
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
        open(card).pin_retries_left(),
        Err(Error::SecureChannel(_))
    ));
}

#[test]
fn draws_fresh_randomness_for_every_handshake() {
    let mut session = open(card_with_channel());
    session.pin_retries_left().unwrap();
    session.pin_retries_left().unwrap();
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
    assert!(session.pin_retries_left().is_ok());
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
    assert!(session.pin_retries_left().is_ok());
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
    let [icc, terminal] = std::array::from_fn(|_| RsaPrivateKey::new(&mut OsRng, 1024).unwrap());
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

impl Port for AcceptingCard {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.push(apdu.to_vec());
        Ok(vec![0x90, 0x00])
    }
}

#[test]
fn sends_the_smaller_of_the_signature_and_its_complement_to_the_card() {
    let keys = KeySet::for_generation(KeyGeneration::Second, Channel::User);
    let icc = RsaPrivateKey::new(&mut OsRng, (keys.modulus.len() + 1) * 8).unwrap();
    let half = BigUint::from_bytes_be(keys.modulus) / 2_u8;
    // Each handshake draws a fresh frame, so half of them sign above N.IFD / 2.
    for _ in 0..16 {
        let mut card = AcceptingCard(vec![]);
        external_authentication(
            &mut PlainChannel::new(&mut card),
            keys,
            &[0x01; 8],
            [0x02; 8],
            &icc.to_public_key(),
        )
        .unwrap();
        let apdu = &card.0[0];
        let token = BigUint::from_bytes_be(&apdu[5..5 + usize::from(apdu[4])]);
        let sent = rsa_decrypt_and_check(&icc, Some(&mut OsRng), &token).unwrap();
        assert!(sent <= half);
    }
}

fn open_failing(fault: HandshakeFault) -> Result<u8, Error> {
    open(card_with_channel().failing(fault)).pin_retries_left()
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

const NOT_FROM_THE_ROOT: &str = "the component certificate chain is not signed by the DNIe root";

fn refuses_before_authenticating(mut session: Session<EmulatedDnie>, reason: &str) {
    assert!(matches!(
        session.pin_retries_left(),
        Err(Error::SecureChannel(message)) if message == reason
    ));
    assert_eq!(session.into_transport().internal_authentications(), 0);
}
