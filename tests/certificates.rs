//! The holder's certificates are listed without a PIN.

mod emulator;

use emulator::{DNIE_3_ATR, Delivery, EmulatedDnie, HolderCertificate};
use rdnie::{Error, Session};

fn assert_lists(card: EmulatedDnie, expected: &[Vec<u8>]) {
    let listed: Vec<Vec<u8>> = Session::open(card)
        .unwrap()
        .certificates()
        .unwrap()
        .into_iter()
        .map(|certificate| certificate.der)
        .collect();
    let lengths = |ders: &[Vec<u8>]| ders.iter().map(Vec::len).collect::<Vec<_>>();
    assert!(
        listed == expected,
        "listed certificates of {:?} bytes, expected {:?}",
        lengths(&listed),
        lengths(expected)
    );
}

fn ders(certificates: &[HolderCertificate]) -> Vec<Vec<u8>> {
    certificates.iter().map(|c| c.der.clone()).collect()
}

#[test]
fn lists_certificates_as_der() {
    let certificates = [
        HolderCertificate::new(1, 120),
        HolderCertificate::new(2, 150),
    ];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    assert_lists(card, &ders(&certificates));
}

#[test]
fn decompresses_compressed_certificates() {
    let certificates = [
        HolderCertificate::new(1, 900).compressed(),
        HolderCertificate::new(2, 150),
    ];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    assert_lists(card, &ders(&certificates));
}

#[test]
fn drops_certificates_without_key() {
    let with_key = HolderCertificate::new(1, 120);
    let without_key = HolderCertificate::new(2, 120).without_key();
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&[without_key, with_key.clone()]);
    assert_lists(card, &ders(&[with_key]));
}

#[test]
fn reads_files_longer_than_one_chunk() {
    let certificates = [HolderCertificate::new(1, 1500)];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    assert_lists(card, &ders(&certificates));
}

#[test]
fn stops_reading_at_end_of_file() {
    let certificate = HolderCertificate::new(1, 300);
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(std::slice::from_ref(&certificate))
        .overstating_length(&[certificate.file], 200);
    assert_lists(card, &ders(&[certificate]));
}

#[test]
fn lists_certificates_through_get_response() {
    let certificates = [HolderCertificate::new(1, 600).compressed()];
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .delivering(Delivery::GetResponse { chunk: 100 })
        .with_certificates(&certificates);
    assert_lists(card, &ders(&certificates));
}

#[test]
fn lists_certificates_when_the_card_wants_the_exact_le() {
    let certificates = [HolderCertificate::new(1, 120)];
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .delivering(Delivery::ExactLe)
        .with_certificates(&certificates);
    assert_lists(card, &ders(&certificates));
}

#[test]
fn reports_missing_cdf_with_its_status_word() {
    let card = EmulatedDnie::new(&DNIE_3_ATR);
    let error = Session::open(card).unwrap().certificates().unwrap_err();
    assert_eq!(error.to_string(), "card answered 6A 82");
}

fn load_error(certificates: &[HolderCertificate]) -> Error {
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(certificates);
    Session::open(card).unwrap().certificates().unwrap_err()
}

#[test]
fn rejects_a_certificate_with_an_empty_path() {
    let certificate = HolderCertificate::new(1, 120).listed_at(&[]);
    assert!(matches!(load_error(&[certificate]), Error::MalformedPkcs15));
}

#[test]
fn rejects_a_certificate_whose_path_is_only_the_master_file() {
    let certificate = HolderCertificate::new(1, 120).listed_at(&[0x3F, 0x00]);
    assert!(matches!(load_error(&[certificate]), Error::MalformedPkcs15));
}

#[test]
fn rejects_a_certificate_that_is_not_x509() {
    let certificate = HolderCertificate::not_x509(1, 120);
    assert!(matches!(load_error(&[certificate]), Error::MalformedPkcs15));
}

#[test]
fn rejects_a_compressed_certificate_that_is_not_x509() {
    let certificate = HolderCertificate::not_x509(1, 300).compressed();
    assert!(matches!(load_error(&[certificate]), Error::MalformedPkcs15));
}

#[test]
fn one_bad_certificate_fails_the_whole_load() {
    let certificates = [
        HolderCertificate::new(1, 120),
        HolderCertificate::not_x509(2, 120),
    ];
    assert!(matches!(load_error(&certificates), Error::MalformedPkcs15));
}
