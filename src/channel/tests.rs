use super::{CommandChannel, PlainChannel};
use crate::{Command, Error, StatusWord, Transport};

/// Answers each APDU with the next of its answers and records what it was sent.
struct Scripted {
    answers: Vec<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl Scripted {
    fn answering(answers: &[&[u8]]) -> Self {
        Self {
            answers: answers.iter().rev().map(|answer| answer.to_vec()).collect(),
            sent: Vec::new(),
        }
    }

    fn send(&mut self, command: &Command) -> Result<crate::Response, Error> {
        PlainChannel::new(self).transmit(command)
    }
}

impl Transport for Scripted {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        self.sent.push(apdu.to_vec());
        Ok(self.answers.pop().expect("an answer left"))
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        unreachable!("the plain channel never reads the atr")
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        unreachable!("the plain channel never resets")
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

fn get_challenge(cla: u8, le: Option<u16>) -> Command {
    Command {
        cla,
        ins: 0x84,
        p1: 0x00,
        p2: 0x00,
        data: vec![],
        le,
    }
}

const GET_RESPONSE_5: &[u8] = &[0x00, 0xC0, 0x00, 0x00, 0x05];
const SM_DATA_MISSING: &[u8] = &[0x69, 0x87];

#[test]
fn completes_a_pending_response_with_get_response() {
    let mut card = Scripted::answering(&[&[0x61, 0x05], &[1, 2, 3, 4, 5, 0x90, 0x00]]);
    let response = card.send(&get_challenge(0x00, Some(5))).unwrap();
    assert_eq!(response.data, [1, 2, 3, 4, 5]);
    assert_eq!(response.status, StatusWord::SUCCESS);
    assert_eq!(card.sent[1], GET_RESPONSE_5);
}

#[test]
fn joins_a_pending_response_served_in_chunks() {
    let mut card = Scripted::answering(&[&[1, 2, 3, 0x61, 0x05], &[4, 5, 6, 7, 8, 0x90, 0x00]]);
    let response = card.send(&get_challenge(0x00, Some(8))).unwrap();
    assert_eq!(response.data, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(card.sent[1], GET_RESPONSE_5);
}

#[test]
fn completes_the_pending_response_of_a_protected_command() {
    let mut card = Scripted::answering(&[&[0x61, 0x05], &[1, 2, 3, 4, 5, 0x90, 0x00]]);
    let response = card.send(&get_challenge(0x0C, Some(5))).unwrap();
    assert_eq!(response.data, [1, 2, 3, 4, 5]);
    assert_eq!(card.sent[1], GET_RESPONSE_5);
}

#[test]
fn resends_keeping_lc_with_the_le_the_card_asks_for() {
    let command = Command {
        cla: 0x00,
        ins: 0xB0,
        p1: 0x00,
        p2: 0x00,
        data: vec![0xAA, 0xBB],
        le: Some(4),
    };
    let mut card = Scripted::answering(&[&[0x6C, 0x08], &[0x90, 0x00]]);
    card.send(&command).unwrap();
    assert_eq!(
        card.sent[1],
        [0x00, 0xB0, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x08]
    );
}

#[test]
fn resends_without_le_with_the_one_the_card_asks_for() {
    let mut card = Scripted::answering(&[&[0x6C, 0x08], &[0x90, 0x00]]);
    card.send(&get_challenge(0x00, None)).unwrap();
    assert_eq!(card.sent[1], [0x00, 0x84, 0x00, 0x00, 0x08]);
}

#[test]
fn returns_the_wrong_length_of_a_protected_command_as_is() {
    let mut card = Scripted::answering(&[&[0x6C, 0x08]]);
    let response = card.send(&get_challenge(0x0C, Some(4))).unwrap();
    assert_eq!(response.status, StatusWord(0x6C08));
    assert_eq!(card.sent.len(), 1);
}

#[test]
fn an_endless_pending_response_ends_with_its_status() {
    let mut card = Scripted::answering(&[&[0x61, 0x05][..]; 1 + 256]);
    let error = card.send(&get_challenge(0x00, Some(8))).unwrap_err();
    assert!(matches!(error, Error::Status(StatusWord(0x6105))));
    assert_eq!(card.sent.len(), 1 + 256);
}

#[test]
fn an_endless_wrong_length_ends_with_its_status() {
    let mut card = Scripted::answering(&[&[0x6C, 0x05][..]; 1 + 2]);
    let error = card.send(&get_challenge(0x00, Some(8))).unwrap_err();
    assert!(matches!(error, Error::Status(StatusWord(0x6C05))));
    assert_eq!(card.sent.len(), 1 + 2);
}

#[test]
fn resends_a_plain_command_once_after_a_leftover_channel() {
    let mut card = Scripted::answering(&[SM_DATA_MISSING, &[1, 2, 0x90, 0x00]]);
    let command = get_challenge(0x00, Some(2));
    let response = card.send(&command).unwrap();
    assert_eq!(response.data, [1, 2]);
    assert_eq!(card.sent, vec![command.to_bytes().unwrap(); 2]);
}

#[test]
fn a_second_missing_secure_messaging_answer_ends_with_its_status() {
    let mut card = Scripted::answering(&[SM_DATA_MISSING, SM_DATA_MISSING]);
    let error = card.send(&get_challenge(0x00, Some(2))).unwrap_err();
    assert!(matches!(error, Error::Status(StatusWord(0x6987))));
    assert_eq!(card.sent.len(), 2);
}

#[test]
fn returns_the_missing_secure_messaging_of_a_protected_command_as_is() {
    let mut card = Scripted::answering(&[SM_DATA_MISSING]);
    let response = card.send(&get_challenge(0x0C, Some(2))).unwrap();
    assert_eq!(response.status, StatusWord(0x6987));
    assert_eq!(card.sent.len(), 1);
}
