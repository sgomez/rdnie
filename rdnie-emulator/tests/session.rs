//! A consumer opens, verifies the PIN and signs against the emulated card through `Session` only.

use rdnie::{
    DigestAlgorithm, Error, Holder, KeyGeneration, Pin, SIGNATURE_LABEL, Session, Transport,
};
use rdnie_emulator::{DEFAULT_PIN, EmulatedDnie};
use rsa::{
    Pkcs1v15Sign, RsaPublicKey,
    pkcs8::DecodePublicKey,
    sha2::{Digest, Sha256},
};
use x509_cert::der::{Decode, Encode};

const AUTHENTICATION_LABEL: &str = "CertAutenticacion";

fn open(card: EmulatedDnie) -> Session<EmulatedDnie> {
    let root = card.component_root();
    Session::open_trusting(card, root).unwrap()
}

fn sign(session: &mut Session<EmulatedDnie>, label: &str, pin: &str) -> Result<Vec<u8>, Error> {
    let key = session.private_key(label).unwrap().unwrap();
    session.pin_retries_left()?;
    session.sign(
        &Sha256::digest(b"document"),
        DigestAlgorithm::Sha256,
        &key,
        Pin::new(pin.to_owned()),
    )
}

fn verifies(key: &RsaPublicKey, signature: &[u8]) -> bool {
    key.verify(
        Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(b"document"),
        signature,
    )
    .is_ok()
}

fn public_key(der: &[u8]) -> RsaPublicKey {
    let certificate = x509_cert::Certificate::from_der(der).unwrap();
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    RsaPublicKey::from_public_key_der(&spki).unwrap()
}

#[test]
fn starts_with_three_retries() {
    assert_eq!(open(EmulatedDnie::dnie_3()).pin_retries_left().unwrap(), 3);
}

#[test]
fn reports_the_retries_it_was_built_with() {
    for retries in 1..=3 {
        let card = EmulatedDnie::dnie_3().with_pin_retries(retries);
        assert_eq!(open(card).pin_retries_left().unwrap(), retries);
    }
}

#[test]
fn reports_a_blocked_pin_with_no_retries_left() {
    let mut session = open(EmulatedDnie::dnie_3().with_pin_retries(0));
    assert!(matches!(session.pin_retries_left(), Err(Error::PinBlocked)));
    assert!(matches!(
        sign(&mut session, SIGNATURE_LABEL, DEFAULT_PIN),
        Err(Error::PinBlocked)
    ));
}

#[test]
#[should_panic(expected = "0 to 3")]
fn refuses_more_than_three_retries() {
    let _ = EmulatedDnie::dnie_3().with_pin_retries(4);
}

#[test]
fn a_wrong_pin_costs_one_retry() {
    let mut session = open(EmulatedDnie::dnie_3());
    assert!(matches!(
        sign(&mut session, SIGNATURE_LABEL, "WrongPin1"),
        Err(Error::WrongPin { retries_left: 2 })
    ));
    assert_eq!(session.pin_retries_left().unwrap(), 2);
}

#[test]
fn accepts_the_pin_it_was_built_with() {
    let mut session = open(EmulatedDnie::dnie_3().with_pin("OtherPin2"));
    assert!(matches!(
        sign(&mut session, SIGNATURE_LABEL, DEFAULT_PIN),
        Err(Error::WrongPin { retries_left: 2 })
    ));
    assert!(sign(&mut session, SIGNATURE_LABEL, "OtherPin2").is_ok());
}

#[test]
fn signs_with_the_signing_key() {
    let card = EmulatedDnie::dnie_3();
    let key = card.signing_public_key();
    let signature = sign(&mut open(card), SIGNATURE_LABEL, DEFAULT_PIN).unwrap();
    assert!(verifies(&key, &signature));
}

#[test]
fn signs_with_the_authentication_key() {
    let card = EmulatedDnie::dnie_3();
    let authentication = card.authentication_public_key();
    let signing = card.signing_public_key();
    let signature = sign(&mut open(card), AUTHENTICATION_LABEL, DEFAULT_PIN).unwrap();
    assert!(verifies(&authentication, &signature));
    assert!(!verifies(&signing, &signature));
}

#[test]
fn holds_both_certificates_of_the_exposed_keys() {
    let card = EmulatedDnie::dnie_3();
    let keys = [
        (SIGNATURE_LABEL, card.signing_public_key()),
        (AUTHENTICATION_LABEL, card.authentication_public_key()),
    ];
    let mut session = open(card);
    for (label, key) in keys {
        let der = session.certificate(label).unwrap().unwrap();
        assert_eq!(public_key(&der), key);
    }
}

#[test]
fn issues_the_certificates_to_a_fictitious_holder() {
    let mut session = open(EmulatedDnie::dnie_3());
    for label in [SIGNATURE_LABEL, AUTHENTICATION_LABEL] {
        let der = session.certificate(label).unwrap().unwrap();
        let holder = Holder::from_der(&der).unwrap();
        assert_eq!(holder.number.as_deref(), Some("IDCES-99999999R"));
    }
}

#[test]
fn opens_the_secure_channel_only_trusting_its_component_root() {
    let mut session = Session::open(EmulatedDnie::dnie_3()).unwrap();
    assert!(matches!(
        session.pin_retries_left(),
        Err(Error::SecureChannel(_))
    ));
}

#[test]
fn opens_a_dnie_3_and_a_dnie_4_under_each_key_generation() {
    for generation in [KeyGeneration::First, KeyGeneration::Second] {
        for card in [EmulatedDnie::dnie_3(), EmulatedDnie::dnie_4()] {
            let mut session = open(card.with_key_generation(generation));
            assert_eq!(session.key_generation(), generation);
            assert_eq!(session.pin_retries_left().unwrap(), 3);
        }
    }
}

#[test]
fn uses_the_second_key_generation_by_default() {
    assert_eq!(
        open(EmulatedDnie::dnie_3()).key_generation(),
        KeyGeneration::Second
    );
    assert_eq!(
        open(EmulatedDnie::dnie_4()).key_generation(),
        KeyGeneration::Second
    );
}

#[test]
fn signs_on_a_dnie_4_under_the_first_key_generation() {
    let card = EmulatedDnie::dnie_4().with_key_generation(KeyGeneration::First);
    let key = card.signing_public_key();
    let signature = sign(&mut open(card), SIGNATURE_LABEL, DEFAULT_PIN).unwrap();
    assert!(verifies(&key, &signature));
}

#[test]
fn a_dnie_4_reports_an_atr_of_its_own() {
    let three = EmulatedDnie::dnie_3();
    let four = EmulatedDnie::dnie_4();
    assert_ne!(three.atr().unwrap(), four.atr().unwrap());
}
