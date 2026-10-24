use super::{Location, fci_length, read, select_master_file};
use crate::{
    cwa14890,
    emulator::{DNIE_3_ATR, EmulatedDnie, component_root_public_key},
    key_sets::{ComponentRoots, R1_USER},
    session::tests::card_with_channel,
    {Error, StatusWord, Transport},
};

const FILE: [u8; 2] = [0x60, 0x10];

fn read_under_channel(card: EmulatedDnie) -> Vec<u8> {
    let mut card = card;
    let roots = ComponentRoots::only(component_root_public_key());
    let mut channel = cwa14890::open(&mut card, &R1_USER, &roots).unwrap();
    read(
        &mut channel,
        &Location::new(&[0x3F, 0x00, 0x60, 0x10]).unwrap(),
    )
    .unwrap()
}

#[test]
fn keeps_the_authenticated_chunk_that_ends_at_an_end_of_file_warning() {
    let content: Vec<u8> = (0..=255).cycle().take(300).collect();
    let card = card_with_channel()
        .with_file(&[FILE], content.clone())
        .overstating_length(&[FILE], 200);
    assert_eq!(read_under_channel(card), content);
}

#[test]
fn drops_data_a_secure_channel_did_not_authenticate() {
    let content: Vec<u8> = (0..=255).cycle().take(300).collect();
    let card = card_with_channel()
        .with_file(&[FILE], content)
        .answering_a_read_unauthenticated_with(0x6282);
    assert_eq!(read_under_channel(card), []);
}

#[test]
fn selects_the_master_file_whatever_a_card_answers_with_9000() {
    let mut card = EmulatedDnie::new(&DNIE_3_ATR).answering_master_file_selection_with(&[1, 2, 3]);
    assert!(select_master_file(&mut card).is_ok());
}

struct PlainFile {
    fci: Vec<u8>,
    content: Vec<u8>,
    failing_read: Option<(usize, u16)>,
    reads: Vec<(u8, u8, u8)>,
}

impl PlainFile {
    fn new(content: Vec<u8>) -> Self {
        let length = u16::try_from(content.len()).unwrap().to_be_bytes();
        Self {
            fci: vec![0x6F, 0x04, 0x81, 0x02, length[0], length[1]],
            content,
            failing_read: None,
            reads: vec![],
        }
    }
}

impl Transport for PlainFile {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let ok = [0x90, 0x00];
        match apdu[1] {
            0xA4 if apdu[2] == 0x04 => Ok(ok.to_vec()),
            0xA4 => Ok([self.fci.as_slice(), &ok].concat()),
            _ => {
                self.reads.push((apdu[2], apdu[3], apdu[4]));
                if let Some((nth, status)) = self.failing_read
                    && nth == self.reads.len()
                {
                    return Ok(status.to_be_bytes().to_vec());
                }
                let offset = usize::from(u16::from_be_bytes([apdu[2], apdu[3]]));
                let le = if apdu[4] == 0 {
                    256
                } else {
                    usize::from(apdu[4])
                };
                let end = (offset + le).min(self.content.len());
                Ok([&self.content[offset..end], &ok].concat())
            }
        }
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        unreachable!()
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error>
    where
        Self: Sized,
    {
        body(self)
    }
}

fn location() -> Location {
    Location::new(&[0x3F, 0x00, 0x60, 0x10]).unwrap()
}

#[test]
fn reads_the_length_an_fci_announces_with_the_proprietary_tag_85() {
    let fci = [
        0x6F, 0x0C, 0x85, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(fci_length(&fci).unwrap(), 0x0123);
}

#[test]
fn reads_the_length_an_fci_announces_with_tag_81() {
    assert_eq!(
        fci_length(&[0x6F, 0x04, 0x81, 0x02, 0x01, 0x23]).unwrap(),
        0x0123
    );
}

#[test]
fn refuses_an_fci_that_does_not_start_with_the_fci_tag() {
    let error = fci_length(&[0x70, 0x04, 0x81, 0x02, 0x01, 0x23]).unwrap_err();
    assert!(matches!(error, Error::Status(StatusWord::SUCCESS)));
}

#[test]
fn refuses_an_fci_of_two_bytes_or_fewer() {
    for fci in [&[0x6F][..], &[0x6F, 0x00]] {
        let error = fci_length(fci).unwrap_err();
        assert!(matches!(error, Error::Status(StatusWord::SUCCESS)));
    }
}

#[test]
fn accepts_an_fci_of_three_bytes() {
    assert_eq!(fci_length(&[0x6F, 0x01, 0x00]).unwrap(), 0);
}

#[test]
fn reports_a_card_error_in_the_middle_of_a_read_as_that_status() {
    let mut card = PlainFile::new(vec![7; 500]);
    card.failing_read = Some((2, 0x6700));
    let error = read(&mut card, &location()).unwrap_err();
    assert!(matches!(error, Error::Status(StatusWord(0x6700))));
}

#[test]
fn reads_a_file_longer_than_one_chunk_in_full_and_in_order() {
    let content: Vec<u8> = (0..=255).cycle().take(500).collect();
    let mut card = PlainFile::new(content.clone());
    assert_eq!(read(&mut card, &location()).unwrap(), content);
    assert_eq!(
        card.reads,
        [(0x00, 0x00, 0xDE), (0x00, 0xDE, 0xDE), (0x01, 0xBC, 0x38)]
    );
}

/// `81` length, `81` file ID and `84` DF name, with lengths that make the walk advance.
const BEFORE_85: [u8; 13] = [
    0x81, 0x02, 0x02, 0x22, 0x81, 0x02, 0xAA, 0xBB, 0x84, 0x03, 0xCC, 0xDD, 0xEE,
];

fn fci_with(tail: &[u8]) -> Vec<u8> {
    let body = [&BEFORE_85[..], tail].concat();
    [&[0x6F, u8::try_from(body.len()).unwrap()][..], &body].concat()
}

#[test]
fn reads_the_tag_85_length_after_the_81_81_and_84_tlvs() {
    let fci = fci_with(&[
        0x85, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(fci_length(&fci).unwrap(), 0x0123);
}

#[test]
fn keeps_the_81_length_when_the_tag_85_is_not_10_bytes_long() {
    let fci = fci_with(&[
        0x85, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(fci_length(&fci).unwrap(), 0x0222);
}

#[test]
fn keeps_the_81_length_when_a_10_follows_a_tag_other_than_85() {
    let fci = fci_with(&[
        0x86, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(fci_length(&fci).unwrap(), 0x0222);
}

#[test]
fn reads_an_81_length_whose_value_ends_the_fci() {
    assert_eq!(
        fci_length(&[0x6F, 0x05, 0x81, 0x03, 0x01, 0x23, 0x45]).unwrap(),
        0x0123
    );
}

#[test]
fn sends_no_read_binary_at_an_offset_equal_to_the_file_length() {
    let content = vec![7; 2 * 0xDE];
    let mut card = PlainFile::new(content.clone());
    assert_eq!(read(&mut card, &location()).unwrap(), content);
    assert_eq!(card.reads, [(0x00, 0x00, 0xDE), (0x00, 0xDE, 0xDE)]);
}
