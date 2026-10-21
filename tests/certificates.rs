//! The holder's certificates are listed without a PIN.

mod emulator;

use emulator::{CDF, DNIE_3_ATR, Delivery, EmulatedDnie, HolderCertificate, PRKDF, cdf, prkdf};
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

/// A compressed certificate that inflates to exactly `length` bytes.
fn compressed_of_length(length: usize) -> HolderCertificate {
    // Padding grows the DER two bytes at a time (subject and issuer); a serial of 0x80 adds one.
    let id = if length % 2 == 0 { 0x80 } else { 1 };
    let mut asked = length / 2;
    loop {
        let certificate = HolderCertificate::new(id, asked);
        let size = certificate.der.len();
        if size == length {
            return certificate.compressed();
        }
        assert!(
            size.abs_diff(length) > 1,
            "no padding reaches {length} bytes"
        );
        asked = if size < length {
            asked + (length - size) / 2
        } else {
            asked - (size - length) / 2
        };
    }
}

#[test]
fn loads_a_compressed_certificate_that_inflates_to_exactly_the_cap() {
    let certificates = [compressed_of_length(16 * 1024)];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    assert_lists(card, &ders(&certificates));
}

#[test]
fn rejects_a_compressed_certificate_that_inflates_one_byte_past_the_cap() {
    let certificate = compressed_of_length(16 * 1024 + 1);
    assert!(matches!(load_error(&[certificate]), Error::MalformedPkcs15));
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
fn lists_and_fetches_the_signature_certificate_by_its_public_label() {
    let signature = HolderCertificate::new(1, 120).labelled("CertFirmaDigital");
    let certificates = [signature.clone(), HolderCertificate::new(2, 150)];
    assert_eq!(rdnie::SIGNATURE_LABEL, "CertFirmaDigital");
    assert_eq!(labels(&certificates)[0], rdnie::SIGNATURE_LABEL);
    assert_eq!(
        fetch(&certificates, rdnie::SIGNATURE_LABEL),
        Some(signature.der)
    );
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

fn with_directory(directory: [[u8; 2]; 2], bytes: &[u8]) -> Error {
    let certificates = [HolderCertificate::new(1, 120)];
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(&certificates)
        .with_file(&directory, bytes.to_vec());
    Session::open(card).unwrap().certificates().unwrap_err()
}

#[test]
fn rejects_a_cdf_that_starts_with_no_sequence() {
    for bytes in [&[0x00; 16][..], &[0x04, 0x01, 0x00]] {
        assert!(matches!(with_directory(CDF, bytes), Error::MalformedPkcs15));
    }
}

#[test]
fn rejects_a_prkdf_that_starts_with_no_sequence() {
    for bytes in [&[0x00; 16][..], &[0x04, 0x01, 0x00]] {
        assert!(matches!(
            with_directory(PRKDF, bytes),
            Error::MalformedPkcs15
        ));
    }
}

fn numbered(count: u8) -> Vec<HolderCertificate> {
    (1..=count)
        .map(|id| HolderCertificate::new(id, 120).labelled(&format!("Cert{id}")))
        .collect()
}

fn cert_labels(ids: std::ops::RangeInclusive<u8>) -> Vec<String> {
    ids.map(|id| format!("Cert{id}")).collect()
}

#[test]
fn loads_a_directory_of_exactly_the_object_limit() {
    assert_eq!(labels(&numbered(10)), cert_labels(1..=10));
}

#[test]
fn loads_a_directory_only_up_to_the_object_limit() {
    // The PrKDF lists the keys last to first, so its limit leaves the first certificate keyless.
    assert_eq!(labels(&numbered(11)), cert_labels(2..=10));
}

#[test]
fn bounds_the_cdf_apart_from_the_prkdf() {
    let certificates = numbered(11);
    let reversed: Vec<HolderCertificate> = certificates.iter().rev().cloned().collect();
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(&certificates)
        .with_file(&PRKDF, prkdf(&reversed));
    let listed = Session::open(card).unwrap().certificates().unwrap();
    let listed: Vec<String> = listed.into_iter().map(|c| c.label).collect();
    assert_eq!(listed, cert_labels(1..=10));
}

const OCTET_STRING: u8 = 0x04;
const SEQUENCE: u8 = 0x30;
const UTF8_STRING: u8 = 0x0C;
const TYPE_ATTRIBUTES: u8 = 0xA1;
const NOT_EXPECTED: u8 = 0x31;

const WELL_NESTED: [u8; 8] = [
    SEQUENCE,
    UTF8_STRING,
    SEQUENCE,
    OCTET_STRING,
    TYPE_ATTRIBUTES,
    SEQUENCE,
    SEQUENCE,
    OCTET_STRING,
];

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let length = u8::try_from(value.len()).unwrap();
    [&[tag, length][..], value].concat()
}

/// A CDF or PrKDF object of one certificate, with the tags `tags` from the outermost in.
fn object(tags: [u8; 8]) -> Vec<u8> {
    let [label, label_text, class, id, typed, path_list, path, octets] = tags;
    let path_bytes = [0x3F, 0x00, 0x70, 0x01];
    let attributes = [
        tlv(label, &tlv(label_text, b"Cert1")),
        tlv(class, &tlv(id, &[0x4B, 0x49, 0x44, 0x01])),
        tlv(
            typed,
            &tlv(path_list, &tlv(path, &tlv(octets, &path_bytes))),
        ),
    ];
    tlv(SEQUENCE, &attributes.concat())
}

fn load_object(directory: [[u8; 2]; 2], tags: [u8; 8]) -> Result<usize, Error> {
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(&[HolderCertificate::new(1, 120)])
        .with_file(&directory, object(tags));
    Ok(Session::open(card)?.certificates()?.len())
}

#[test]
fn loads_a_well_nested_object() {
    assert_eq!(load_object(CDF, WELL_NESTED).unwrap(), 1);
    assert_eq!(load_object(PRKDF, WELL_NESTED).unwrap(), 1);
}

#[test]
fn rejects_a_cdf_object_whose_expected_child_has_another_tag() {
    for position in 0..WELL_NESTED.len() {
        let mut tags = WELL_NESTED;
        tags[position] = NOT_EXPECTED;
        assert!(
            matches!(load_object(CDF, tags), Err(Error::MalformedPkcs15)),
            "tag {position} not checked"
        );
    }
}

#[test]
fn rejects_a_prkdf_object_whose_expected_child_has_another_tag() {
    // The PrKDF label is not read, so its tags are not checked.
    for position in 2..WELL_NESTED.len() {
        let mut tags = WELL_NESTED;
        tags[position] = NOT_EXPECTED;
        assert!(
            matches!(load_object(PRKDF, tags), Err(Error::MalformedPkcs15)),
            "tag {position} not checked"
        );
    }
}

#[test]
fn debug_output_hides_the_key_reference() {
    let certificates = [HolderCertificate::new(1, 120)];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    let listed = Session::open(card).unwrap().certificates().unwrap();
    assert_eq!(format!("{:?}", listed[0].key), "KeyReference { .. }");
}

fn followed_by_a_non_sequence(mut directory: Vec<u8>) -> Vec<u8> {
    let at = directory.len() - 16;
    directory.splice(at..at, [0x04, 0x01, 0x00]);
    directory
}

#[test]
fn loads_the_objects_of_a_cdf_followed_by_a_tlv_that_is_not_a_sequence() {
    let certificates = numbered(2);
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(&certificates)
        .with_file(&CDF, followed_by_a_non_sequence(cdf(&certificates)));
    let listed = Session::open(card).unwrap().certificates().unwrap();
    let listed: Vec<String> = listed.into_iter().map(|c| c.label).collect();
    assert_eq!(listed, cert_labels(1..=2));
}

#[test]
fn loads_the_objects_of_a_prkdf_followed_by_a_tlv_that_is_not_a_sequence() {
    let certificates = numbered(2);
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(&certificates)
        .with_file(&PRKDF, followed_by_a_non_sequence(prkdf(&certificates)));
    let listed = Session::open(card).unwrap().certificates().unwrap();
    let listed: Vec<String> = listed.into_iter().map(|c| c.label).collect();
    assert_eq!(listed, cert_labels(1..=2));
}
