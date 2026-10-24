use super::Session;
use rsa::{
    Pkcs1v15Sign, RsaPublicKey,
    pkcs8::DecodePublicKey,
    sha2::{Digest, Sha256, Sha384, Sha512},
};
use x509_cert::der::{Decode, Encode};

use crate::{
    DigestAlgorithm, Error, KeyGeneration, Pin, StatusWord,
    emulator::{
        DEFAULT_PIN, DNIE_3_ATR, DNIE_4_ATR, Delivery, EmulatedDnie, HandshakeFault,
        HolderCertificate, ResponseShape, Step, TerminalKey, component_root_public_key,
    },
    key_sets::{ComponentRoots, KeySet, R1_PIN, R1_USER, R2_PIN, R2_USER},
};

mod card_removal;
mod certificates;
mod opening;
mod pin;
mod secure_channel;
mod signing;
mod trusting;
mod verifying;

pub(crate) fn card_accepting(key_sets: &[&KeySet]) -> EmulatedDnie {
    let terminals: Vec<TerminalKey> = key_sets
        .iter()
        .map(|keys| TerminalKey {
            chr: keys.terminal_chr,
            modulus: keys.modulus.to_vec(),
            user: [&R1_USER, &R2_USER]
                .iter()
                .any(|user| std::ptr::eq(*user, *keys)),
        })
        .collect();
    EmulatedDnie::new(&DNIE_3_ATR).with_secure_channel(&terminals)
}

pub(crate) fn card_with_channel() -> EmulatedDnie {
    card_accepting(&[&R1_PIN, &R1_USER, &R2_PIN, &R2_USER])
}

pub(crate) fn open(card: EmulatedDnie) -> Session<EmulatedDnie> {
    Session::open_with_roots(card, ComponentRoots::only(component_root_public_key())).unwrap()
}

/// The ids of the holder certificate files the card selected, in order.
fn certificate_files_selected(card: &EmulatedDnie) -> Vec<u8> {
    card.selected()
        .iter()
        .filter_map(|path| match path.as_slice() {
            [[0x70, id]] => Some(*id),
            _ => None,
        })
        .collect()
}

fn retries(card: EmulatedDnie) -> Result<u8, Error> {
    open(card).pin_retries_left()
}

fn signing_card() -> EmulatedDnie {
    card_with_channel().with_certificates(&[HolderCertificate::signing(1)])
}

fn sign_with(
    session: &mut Session<EmulatedDnie>,
    digest: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<Vec<u8>, Error> {
    let key = first_key(session);
    session.sign(digest, algorithm, &key, Pin::new(DEFAULT_PIN.to_owned()))
}

fn first_key(session: &mut Session<EmulatedDnie>) -> crate::KeyReference {
    let label = session.labels().unwrap().remove(0);
    session.private_key(&label).unwrap().unwrap()
}

fn verify(certificate: &[u8], scheme: Pkcs1v15Sign, digest: &[u8], signature: &[u8]) {
    let certificate = x509_cert::Certificate::from_der(certificate).unwrap();
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    RsaPublicKey::from_public_key_der(&spki)
        .unwrap()
        .verify(scheme, digest, signature)
        .expect("the signature verifies with the certificate's public key");
}

fn sign_with_pin(card: EmulatedDnie, pin: &str) -> (Result<Vec<u8>, Error>, EmulatedDnie) {
    let mut session = open(card);
    let key = first_key(&mut session);
    if let Err(error) = session.pin_retries_left() {
        return (Err(error), session.into_transport());
    }
    let result = session.sign(
        &[0; 32],
        DigestAlgorithm::Sha256,
        &key,
        Pin::new(pin.to_owned()),
    );
    (result, session.into_transport())
}
