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
fn ignores_bytes_after_an_uncompressed_certificate() {
    let certificates = [HolderCertificate::new(1, 120).followed_by(32)];
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
    assert_eq!(error.to_string(), "card answered file not found (6A 82)");
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
fn rejects_a_compressed_certificate_that_inflates_past_the_cap() {
    let bomb = HolderCertificate::new(1, 20 * 1024).compressed();
    let stored = bomb.stored();
    assert!(stored.len() < 1024, "bomb stored in {} bytes", stored.len());
    // Inflated whole, the bomb is a valid certificate: only the cap can refuse it.
    assert!(<x509_cert::Certificate as x509_cert::der::Decode>::from_der(&bomb.der).is_ok());
    assert!(matches!(load_error(&[bomb]), Error::MalformedPkcs15));
}

#[test]
fn loads_a_compressed_certificate_just_under_the_cap() {
    let certificates = [HolderCertificate::new(1, 8500).compressed()];
    assert!((15 * 1024..=16 * 1024).contains(&certificates[0].der.len()));
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    assert_lists(card, &ders(&certificates));
}

fn labels(certificates: &[HolderCertificate]) -> Vec<String> {
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(certificates);
    let listed = Session::open(card).unwrap().certificates().unwrap();
    listed.into_iter().map(|c| c.label).collect()
}

#[test]
fn lists_the_labels_the_cdf_holds_in_cdf_order() {
    let certificates = [
        HolderCertificate::new(1, 120).labelled("CertFirma"),
        HolderCertificate::new(2, 120).labelled("CertAutenticacion"),
    ];
    assert_eq!(labels(&certificates), ["CertFirma", "CertAutenticacion"]);
}

#[test]
fn rejects_a_cdf_object_without_a_label() {
    let certificate = HolderCertificate::new(1, 120).without_label();
    assert!(matches!(load_error(&[certificate]), Error::MalformedPkcs15));
}

#[test]
fn rejects_a_label_that_is_not_utf8() {
    let certificate = HolderCertificate::new(1, 120).labelled_bytes(&[0xFF, 0xFE]);
    assert!(matches!(load_error(&[certificate]), Error::MalformedPkcs15));
}

#[test]
fn debug_output_hides_the_label() {
    let certificates = [HolderCertificate::new(1, 120).labelled("CertSecreto")];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    let listed = Session::open(card).unwrap().certificates().unwrap();
    assert_eq!(format!("{:?}", listed[0]), "Certificate { .. }");
}

#[test]
fn one_bad_certificate_fails_the_whole_load() {
    let certificates = [
        HolderCertificate::new(1, 120),
        HolderCertificate::not_x509(2, 120),
    ];
    assert!(matches!(load_error(&certificates), Error::MalformedPkcs15));
    let keyless = [
        HolderCertificate::new(1, 120),
        HolderCertificate::not_x509(2, 120).without_key(),
    ];
    assert!(matches!(load_error(&keyless), Error::MalformedPkcs15));
}

fn fetch(certificates: &[HolderCertificate], label: &str) -> Option<Vec<u8>> {
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(certificates);
    Session::open(card).unwrap().certificate(label).unwrap()
}

#[test]
fn fetches_the_keyless_intermediate_ca_by_its_public_label_but_does_not_list_it() {
    let ca = HolderCertificate::new(2, 120)
        .labelled("CertCAIntermediaDGP")
        .without_key();
    let certificates = [HolderCertificate::new(1, 120), ca.clone()];
    assert_eq!(rdnie::INTERMEDIATE_CA_LABEL, "CertCAIntermediaDGP");
    assert_eq!(
        fetch(&certificates, rdnie::INTERMEDIATE_CA_LABEL),
        Some(ca.der)
    );
    assert_eq!(labels(&certificates).len(), 1);
}

#[test]
fn fetches_a_keyed_certificate_with_the_der_it_is_listed_with() {
    let certificate = HolderCertificate::new(1, 120).labelled("CertFirma");
    assert_eq!(
        fetch(std::slice::from_ref(&certificate), "CertFirma"),
        Some(certificate.der)
    );
}

#[test]
fn an_unknown_label_is_absent() {
    let certificates = [HolderCertificate::new(1, 120).labelled("CertFirma")];
    assert_eq!(fetch(&certificates, "Other"), None);
}

#[test]
fn with_duplicate_labels_the_last_one_wins() {
    let first = HolderCertificate::new(1, 120).labelled("Same");
    let last = HolderCertificate::new(2, 150)
        .labelled("Same")
        .without_key();
    assert_eq!(fetch(&[first, last.clone()], "Same"), Some(last.der));
}
