//! The holder's name, surnames and number come from a DNIe certificate's subject, as `DnieCertParseUtil` gives them.

mod emulator;

use emulator::HolderCertificate;
use rdnie::{Error, Holder};
use x509_cert::{
    attr::AttributeTypeAndValue,
    der::{
        Any, Tag,
        asn1::SetOfVec,
        oid::{
            ObjectIdentifier,
            db::rfc4519::{
                COMMON_NAME, COUNTRY_NAME, GIVEN_NAME, ORGANIZATION_NAME, ORGANIZATIONAL_UNIT_NAME,
                SERIAL_NUMBER, SURNAME,
            },
        },
    },
    name::{RdnSequence, RelativeDistinguishedName},
};

/// Holder data read from a certificate whose subject holds `attributes`, in DER order.
fn holder(attributes: &[(ObjectIdentifier, &str)]) -> Holder {
    holder_of(Tag::Utf8String, attributes)
}

/// As [`holder`], with every attribute but the serial number and country of type `text`.
fn holder_of(text: Tag, attributes: &[(ObjectIdentifier, &str)]) -> Holder {
    let subject = RdnSequence(
        attributes
            .iter()
            .map(|&(oid, value)| {
                let tag = if oid == SERIAL_NUMBER || oid == COUNTRY_NAME {
                    Tag::PrintableString
                } else {
                    text
                };
                let value = Any::new(tag, value.as_bytes()).unwrap();
                let attribute = AttributeTypeAndValue { oid, value };
                RelativeDistinguishedName(SetOfVec::try_from(vec![attribute]).unwrap())
            })
            .collect(),
    );
    Holder::from_der(&HolderCertificate::with_subject(1, subject).der).unwrap()
}

fn fields(holder: &Holder) -> [Option<&str>; 4] {
    [
        holder.name.as_deref(),
        holder.first_surname.as_deref(),
        holder.second_surname.as_deref(),
        holder.number.as_deref(),
    ]
}

#[test]
fn reads_name_surnames_and_number_of_a_dnie_subject() {
    let holder = holder(&[
        (COUNTRY_NAME, "ES"),
        (SERIAL_NUMBER, "00000000T"),
        (SURNAME, "FIRSTSURNAME"),
        (GIVEN_NAME, "GIVEN NAME"),
        (COMMON_NAME, "FIRSTSURNAME SECONDSURNAME, GIVEN NAME"),
    ]);
    assert_eq!(
        fields(&holder),
        [
            Some("GIVEN NAME"),
            Some("FIRSTSURNAME"),
            Some("SECONDSURNAME"),
            Some("00000000T"),
        ]
    );
}

#[test]
fn cuts_the_common_name_before_a_parenthesis() {
    let holder = holder(&[
        (COUNTRY_NAME, "ES"),
        (SERIAL_NUMBER, "00000000T"),
        (SURNAME, "FIRSTSURNAME"),
        (GIVEN_NAME, "GIVEN"),
        (
            COMMON_NAME,
            "FIRSTSURNAME SECONDSURNAME, GIVEN (AUTENTICACIÓN)",
        ),
    ]);
    assert_eq!(
        fields(&holder),
        [
            Some("GIVEN"),
            Some("FIRSTSURNAME"),
            Some("SECONDSURNAME"),
            Some("00000000T"),
        ]
    );
}

#[test]
fn leaves_out_the_surname_and_number_the_subject_lacks() {
    let holder = holder(&[
        (COUNTRY_NAME, "ES"),
        (COMMON_NAME, "FIRSTSURNAME SECONDSURNAME, GIVEN"),
    ]);
    assert_eq!(
        fields(&holder),
        [
            Some("GIVEN"),
            None,
            Some("FIRSTSURNAME SECONDSURNAME"),
            None
        ]
    );
}

#[test]
fn takes_the_whole_common_name_as_the_name_without_a_comma() {
    let holder = holder(&[(SURNAME, "FIRSTSURNAME"), (COMMON_NAME, "GIVEN")]);
    assert_eq!(
        fields(&holder),
        [Some("GIVEN"), Some("FIRSTSURNAME"), Some(""), None]
    );
}

#[test]
fn falls_back_to_the_organizational_unit_without_a_common_name() {
    let holder = holder(&[
        (COUNTRY_NAME, "ES"),
        (SURNAME, "FIRSTSURNAME"),
        (
            ORGANIZATIONAL_UNIT_NAME,
            "FIRSTSURNAME SECONDSURNAME, GIVEN (FIRMA)",
        ),
    ]);
    assert_eq!(
        fields(&holder),
        [
            Some("GIVEN"),
            Some("FIRSTSURNAME"),
            Some("SECONDSURNAME"),
            None
        ]
    );
}

#[test]
fn falls_back_to_the_last_attribute_without_common_name_or_unit() {
    let holder = holder(&[(COUNTRY_NAME, "ES"), (ORGANIZATION_NAME, "ORGANIZATION")]);
    assert_eq!(
        fields(&holder),
        [Some("ORGANIZATION"), None, Some(""), None]
    );
}

#[test]
fn takes_the_last_common_name_of_the_subject() {
    let holder = holder(&[(COMMON_NAME, "FIRST, ONE"), (COMMON_NAME, "LAST, OTHER")]);
    assert_eq!(holder.name.as_deref(), Some("OTHER"));
}

#[test]
fn leaves_out_name_and_second_surname_of_an_empty_subject() {
    let holder = holder(&[]);
    assert_eq!(fields(&holder), [None, None, None, None]);
}

#[test]
fn rejects_bytes_that_are_not_x509() {
    let not_x509 = HolderCertificate::not_x509(1, 120).der;
    assert!(matches!(
        Holder::from_der(&not_x509),
        Err(Error::MalformedCertificate)
    ));
    assert!(matches!(
        Holder::from_der(b"not a certificate"),
        Err(Error::MalformedCertificate)
    ));
}

#[test]
fn reads_the_names_of_a_teletex_string_subject() {
    let holder = holder_of(
        Tag::TeletexString,
        &[
            (SERIAL_NUMBER, "00000000T"),
            (SURNAME, "FIRSTSURNAME"),
            (COMMON_NAME, "FIRSTSURNAME SECONDSURNAME, GIVEN"),
        ],
    );
    assert_eq!(
        fields(&holder),
        [
            Some("GIVEN"),
            Some("FIRSTSURNAME"),
            Some("SECONDSURNAME"),
            Some("00000000T"),
        ]
    );
}

#[test]
fn debug_output_hides_every_value() {
    let holder = holder(&[
        (SERIAL_NUMBER, "00000000T"),
        (SURNAME, "FIRSTSURNAME"),
        (COMMON_NAME, "FIRSTSURNAME SECONDSURNAME, GIVEN"),
    ]);
    let debug = format!("{holder:?}");
    for value in ["00000000T", "FIRSTSURNAME", "SECONDSURNAME", "GIVEN"] {
        assert!(!debug.contains(value), "debug output shows {value}");
    }
}
