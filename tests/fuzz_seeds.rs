//! Seed corpora of the `fuzz/` targets, generated from the emulator only: `just fuzz-seed`.

mod recorder;

use std::collections::BTreeSet;

use rdnie::Session;
use rdnie_emulator::{DNIE_3_ATR, Delivery, EmulatedDnie, HolderCertificate, cdf, prkdf};
use recorder::{Recorder, write_corpus};
use x509_cert::{
    attr::AttributeTypeAndValue,
    der::{
        Any, Tag,
        asn1::SetOfVec,
        oid::db::rfc4519::{COMMON_NAME, COUNTRY_NAME, GIVEN_NAME, SERIAL_NUMBER, SURNAME},
    },
    name::{RdnSequence, RelativeDistinguishedName},
};

const SELECT: u8 = 0xA4;

fn certificate_sets() -> Vec<Vec<HolderCertificate>> {
    vec![
        vec![
            HolderCertificate::new(1, 120),
            HolderCertificate::new(2, 150).without_key(),
        ],
        vec![
            HolderCertificate::new(1, 900).compressed(),
            HolderCertificate::new(2, 120).followed_by(32),
            HolderCertificate::new(3, 120).labelled("CertCAIntermediaDGP"),
        ],
        vec![HolderCertificate::new(1, 1500)],
    ]
}

fn dnie_subject() -> RdnSequence {
    let attributes = [
        (COUNTRY_NAME, Tag::PrintableString, "ES"),
        (SERIAL_NUMBER, Tag::PrintableString, "00000000T"),
        (SURNAME, Tag::Utf8String, "FIRSTSURNAME"),
        (GIVEN_NAME, Tag::Utf8String, "GIVEN NAME"),
        (
            COMMON_NAME,
            Tag::Utf8String,
            "FIRSTSURNAME SECONDSURNAME, GIVEN NAME (AUTENTICACIÓN)",
        ),
    ];
    RdnSequence(
        attributes
            .iter()
            .map(|&(oid, tag, value)| {
                let value = Any::new(tag, value.as_bytes()).unwrap();
                let attribute = AttributeTypeAndValue { oid, value };
                RelativeDistinguishedName(SetOfVec::try_from(vec![attribute]).unwrap())
            })
            .collect(),
    )
}

fn recorded(delivery: Delivery, certificates: &[HolderCertificate]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .delivering(delivery)
        .with_certificates(certificates);
    let mut session = Session::open(Recorder::new(card)).unwrap();
    session.certificates().unwrap();
    session.into_transport().exchanges
}

#[test]
#[ignore = "writes the fuzz corpora: run by `just fuzz-seed`"]
fn writes_the_seed_corpora() {
    let sets = certificate_sets();
    let mut responses = BTreeSet::new();
    let mut fcis = BTreeSet::new();
    for delivery in [
        Delivery::Direct,
        Delivery::GetResponse { chunk: 100 },
        Delivery::ExactLe,
    ] {
        for (command, response) in recorded(delivery, &sets[1]) {
            if command.get(1) == Some(&SELECT) {
                fcis.insert(response[..response.len() - 2].to_vec());
            }
            responses.insert(response);
        }
    }
    let certificates = sets.iter().flatten();
    let mut holders: BTreeSet<_> = certificates.clone().map(|c| c.der.clone()).collect();
    holders.insert(HolderCertificate::with_subject(1, dnie_subject()).der);
    write_corpus("apdu", responses);
    write_corpus("files", fcis);
    write_corpus(
        "pkcs15",
        sets.iter().flat_map(|set| [cdf(set), prkdf(set)]).collect(),
    );
    write_corpus(
        "certificates",
        certificates.map(HolderCertificate::stored).collect(),
    );
    write_corpus("holder", holders);
}
