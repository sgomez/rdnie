// Derived from JMulticard: see LICENSE.jmulticard.md.

//! The holder's name, surnames and number, read from a DNIe certificate as `DnieCertParseUtil` does.

use std::fmt;

use der::{
    Decode, Tag, Tagged,
    asn1::{PrintableStringRef, TeletexStringRef},
    oid::{
        ObjectIdentifier,
        db::rfc4519::{COMMON_NAME, ORGANIZATIONAL_UNIT_NAME, SERIAL_NUMBER, SURNAME},
    },
};
use x509_cert::{attr::AttributeTypeAndValue, name::Name};

use crate::Error;

/// Holder data in the subject of a DNIe certificate; a field the subject lacks is `None`.
#[non_exhaustive]
pub struct Holder {
    /// Given name: what follows the first comma of the common name.
    pub name: Option<String>,
    /// First surname: the subject's surname attribute.
    pub first_surname: Option<String>,
    /// Second surname: the common name without its commas, the name and the first surname.
    pub second_surname: Option<String>,
    /// Document number: the subject's serial number attribute.
    pub number: Option<String>,
}

impl Holder {
    /// Reads the holder data from an X.509 certificate in DER.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedCertificate`] if `der` is not an X.509 certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let certificate =
            x509_cert::Certificate::from_der(der).map_err(|_| Error::MalformedCertificate)?;
        let subject = &certificate.tbs_certificate.subject;
        let first_surname = value(subject, SURNAME);
        let (name, second_surname) = match common_name(subject) {
            Some(common_name) => {
                let (name, second_surname) = split(&common_name, first_surname.as_deref());
                (Some(name), Some(second_surname))
            }
            None => (None, None),
        };
        Ok(Self {
            name,
            first_surname,
            second_surname,
            number: value(subject, SERIAL_NUMBER),
        })
    }
}

/// The name and second surname in a common name such as `SURNAME1 SURNAME2, NAME (ROLE)`.
fn split(common_name: &str, first_surname: Option<&str>) -> (String, String) {
    let common_name = match common_name.find('(') {
        Some(parenthesis) => java_trim(&common_name[..parenthesis]),
        None => common_name,
    };
    let name = java_trim(
        common_name
            .find(',')
            .map_or(common_name, |comma| &common_name[comma + 1..]),
    );
    let rest = common_name
        .replace(',', "")
        .replace(name, "")
        .replace(first_surname.unwrap_or_default(), "");
    (name.to_owned(), java_trim(&rest).to_owned())
}

fn common_name(subject: &Name) -> Option<String> {
    value(subject, COMMON_NAME)
        .or_else(|| value(subject, ORGANIZATIONAL_UNIT_NAME))
        .or_else(|| text(subject.0.last()?.0.iter().next()?))
}

/// The first `oid` attribute in the order Java prints a name: most specific RDN first.
fn value(subject: &Name, oid: ObjectIdentifier) -> Option<String> {
    let attribute = subject
        .0
        .iter()
        .rev()
        .flat_map(|rdn| rdn.0.iter())
        .find(|attribute| attribute.oid == oid)?;
    text(attribute)
}

fn text(attribute: &AttributeTypeAndValue) -> Option<String> {
    let value = &attribute.value;
    let text = match value.tag() {
        Tag::Utf8String => value.decode_as::<String>().ok()?,
        Tag::PrintableString => value.decode_as::<PrintableStringRef>().ok()?.to_string(),
        Tag::TeletexString => value.decode_as::<TeletexStringRef>().ok()?.to_string(),
        _ => return None,
    };
    Some(text)
}

/// `String.trim` of Java: strips the control characters and spaces at both ends.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

// Personal data stays out of logs.
impl fmt::Debug for Holder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Holder").finish_non_exhaustive()
    }
}
