use std::ops::Range;

use crate::{
    Error, KeyReference, Session,
    emulator::{CDF, DNIE_3_ATR, Delivery, EmulatedDnie, HolderCertificate, PRKDF, cdf, prkdf},
    files::MAX_HEADER,
    recorder::Recorder,
};

#[test]
fn pairs_each_certificate_with_the_file_of_its_key() {
    let certificates = [
        HolderCertificate::new(1, 120),
        HolderCertificate::new(2, 120),
    ];
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
    let mut session = Session::open(card).unwrap();
    let files: Vec<[u8; 2]> = session
        .keyed()
        .unwrap()
        .iter()
        .map(|(_, key)| key.file)
        .collect();
    let expected: Vec<[u8; 2]> = certificates.iter().filter_map(|c| c.key_file).collect();
    assert_eq!(files, expected);
}

const SELECT: u8 = 0xA4;
const READ_BINARY: u8 = 0xB0;
/// The length the CDF and the PrKDF of a real DNIe announce.
const ANNOUNCED: usize = 2100;
/// The zeros the emulator ends its CDF and PrKDF with.
const EMULATOR_PADDING: usize = 16;

/// Two certificates, the first with a CDF object longer than one READ BINARY.
fn certificates() -> Vec<HolderCertificate> {
    vec![
        HolderCertificate::new(1, 120).labelled(&"L".repeat(300)),
        HolderCertificate::new(2, 150),
    ]
}

fn objects(directory: &[u8]) -> Vec<u8> {
    directory[..directory.len() - EMULATOR_PADDING].to_vec()
}

fn cdf_objects() -> Vec<u8> {
    objects(&cdf(&certificates()))
}

fn prkdf_objects() -> Vec<u8> {
    objects(&prkdf(&certificates()))
}

fn padded(objects: Vec<u8>, byte: u8) -> Vec<u8> {
    let mut padded = objects;
    padded.resize(ANNOUNCED, byte);
    padded
}

fn card_storing(cdf: Vec<u8>, prkdf: Vec<u8>) -> EmulatedDnie {
    EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(&certificates())
        .with_file(&CDF, cdf)
        .with_file(&PRKDF, prkdf)
}

fn padded_card(byte: u8) -> EmulatedDnie {
    card_storing(padded(cdf_objects(), byte), padded(prkdf_objects(), byte))
}

type Exchanges = Vec<(Vec<u8>, Vec<u8>)>;

/// The bytes each READ BINARY into `directory` asked for.
fn reads(exchanges: &Exchanges, directory: [[u8; 2]; 2]) -> Vec<Range<usize>> {
    let mut selected = [0; 2];
    let mut reads = Vec::new();
    for (command, _) in exchanges {
        match command[..] {
            [0x00, SELECT, 0x00, 0x00, 0x02, high, low] => selected = [high, low],
            [0x00, READ_BINARY, p1, p2, le] if selected == directory[1] => {
                let offset = usize::from(u16::from_be_bytes([p1, p2]));
                reads.push(offset..offset + usize::from(le));
            }
            _ => {}
        }
    }
    reads
}

fn read_up_to(exchanges: &Exchanges, directory: [[u8; 2]; 2]) -> usize {
    reads(exchanges, directory)
        .iter()
        .map(|read| read.end)
        .max()
        .unwrap()
}

/// What `labels()` and `private_key()` give, and what went to the card.
struct Listing {
    labels: Vec<String>,
    keys: Vec<Option<KeyReference>>,
    exchanges: Exchanges,
}

impl Listing {
    fn of(card: EmulatedDnie) -> Self {
        let mut session = Session::open(Recorder::new(card)).unwrap();
        let labels = session.labels().unwrap();
        let keys = labels
            .iter()
            .map(|label| session.private_key(label).unwrap())
            .collect();
        Self {
            labels,
            keys,
            exchanges: session.into_transport().exchanges,
        }
    }

    /// The listing of the emulator's own directories.
    fn reference() -> Self {
        Self::of(EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates()))
    }

    fn read_up_to(&self, directory: [[u8; 2]; 2]) -> usize {
        read_up_to(&self.exchanges, directory)
    }

    fn assert_lists_the_reference(&self) {
        let reference = Self::reference();
        assert_eq!(self.labels, reference.labels);
        assert_eq!(self.keys, reference.keys);
    }

    fn assert_reads_one_header_past_the_objects(&self) {
        assert_eq!(self.read_up_to(CDF), cdf_objects().len() + MAX_HEADER);
        assert_eq!(self.read_up_to(PRKDF), prkdf_objects().len() + MAX_HEADER);
    }
}

#[test]
fn reads_a_zero_padded_cdf_and_prkdf_only_up_to_their_last_object() {
    let listing = Listing::of(padded_card(0x00));
    listing.assert_lists_the_reference();
    listing.assert_reads_one_header_past_the_objects();
}

#[test]
fn reads_each_next_header_with_the_object_before_it() {
    let listing = Listing::of(padded_card(0x00));
    // The first header, then two chunks for the first object and one for the second, each with the
    // header after it.
    assert_eq!(reads(&listing.exchanges, CDF).len(), 4);
}

#[test]
fn finds_the_key_of_a_label_on_a_fresh_session_over_a_padded_prkdf() {
    let label = &Listing::reference().labels[0];
    let key = |card| Session::open(card).unwrap().private_key(label).unwrap();
    let expected = key(EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates()));
    assert!(expected.is_some());
    assert_eq!(key(padded_card(0x00)), expected);
}

#[test]
fn stops_at_padding_of_any_byte_that_starts_no_sequence() {
    for byte in [0xFF, 0x31, 0x04] {
        let listing = Listing::of(padded_card(byte));
        listing.assert_lists_the_reference();
        listing.assert_reads_one_header_past_the_objects();
    }
}

#[test]
fn reads_whole_a_directory_its_objects_fill() {
    let listing = Listing::of(card_storing(cdf_objects(), prkdf_objects()));
    listing.assert_lists_the_reference();
    assert_eq!(listing.read_up_to(CDF), cdf_objects().len());
    assert_eq!(listing.read_up_to(PRKDF), prkdf_objects().len());
}

#[test]
fn stops_where_a_card_overstating_the_length_ends_the_file() {
    // With no padding the header read starts past the end (`6B00`); with two bytes it spans it (`6282`).
    for padding in [0, 2] {
        let stored = |objects: Vec<u8>| [objects, vec![0; padding]].concat();
        let card = card_storing(stored(cdf_objects()), stored(prkdf_objects()))
            .overstating_length(&CDF, 200)
            .overstating_length(&PRKDF, 200);
        let listing = Listing::of(card);
        listing.assert_lists_the_reference();
        listing.assert_reads_one_header_past_the_objects();
    }
}

#[test]
fn reads_a_padded_directory_through_get_response_and_exact_le() {
    for delivery in [Delivery::GetResponse { chunk: 100 }, Delivery::ExactLe] {
        let listing = Listing::of(padded_card(0x00).delivering(delivery));
        listing.assert_lists_the_reference();
        listing.assert_reads_one_header_past_the_objects();
    }
}

#[test]
fn rejects_an_object_the_end_of_the_file_cuts_short_without_reading_past_it() {
    for (directory, objects, cut) in [(CDF, cdf_objects(), 300), (PRKDF, prkdf_objects(), 20)] {
        let card = padded_card(0x00).with_file(&directory, objects[..cut].to_vec());
        let mut session = Session::open(Recorder::new(card)).unwrap();
        assert!(matches!(session.labels(), Err(Error::MalformedPkcs15)));
        assert_eq!(
            read_up_to(&session.into_transport().exchanges, directory),
            cut
        );
    }
}

#[test]
fn reads_no_further_than_one_header_past_the_last_object_the_bound_allows() {
    let certificates: Vec<HolderCertificate> = (1..=11)
        .map(|id| HolderCertificate::new(id, 120).labelled(&format!("Cert{id}")))
        .collect();
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_certificates(&certificates)
        .with_file(&CDF, padded(objects(&cdf(&certificates)), 0x00));
    let mut session = Session::open(Recorder::new(card)).unwrap();
    assert_eq!(session.labels().unwrap().len(), 9);
    let ten = objects(&cdf(&certificates[..10])).len();
    assert_eq!(
        read_up_to(&session.into_transport().exchanges, CDF),
        ten + MAX_HEADER
    );
}
