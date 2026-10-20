//! Seed corpora of the `fuzz/` targets, generated from the emulator only: `just fuzz-seed`.

mod emulator;

use std::{cell::RefCell, collections::BTreeSet, fs, path::Path, rc::Rc};

use emulator::{DNIE_3_ATR, Delivery, EmulatedDnie, HolderCertificate, cdf, prkdf};
use rdnie::{Error, Session, Transport};
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

type Exchanges = Rc<RefCell<Vec<(Vec<u8>, Vec<u8>)>>>;

/// Keeps every command and the raw response the emulator gave it.
struct Recorder {
    card: EmulatedDnie,
    exchanges: Exchanges,
}

impl Transport for Recorder {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let response = self.card.transmit_raw(apdu)?;
        self.exchanges
            .borrow_mut()
            .push((apdu.to_vec(), response.clone()));
        Ok(response)
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.card.reset()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

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
    let exchanges = Exchanges::default();
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .delivering(delivery)
        .with_certificates(certificates);
    let recorder = Recorder {
        card,
        exchanges: Rc::clone(&exchanges),
    };
    Session::open(recorder).unwrap().certificates().unwrap();
    exchanges.take()
}

fn write(target: &str, seeds: BTreeSet<Vec<u8>>) {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target);
    fs::create_dir_all(&corpus).unwrap();
    for (index, seed) in seeds.into_iter().enumerate() {
        fs::write(corpus.join(format!("seed-{index}")), seed).unwrap();
    }
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
    write("apdu", responses);
    write("files", fcis);
    write(
        "pkcs15",
        sets.iter().flat_map(|set| [cdf(set), prkdf(set)]).collect(),
    );
    write(
        "certificates",
        certificates.map(HolderCertificate::stored).collect(),
    );
    write("holder", holders);
}
