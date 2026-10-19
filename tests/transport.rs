//! Plain ISO 7816 response handling below any secure channel.

mod emulator;

use emulator::{DNIE_3_ATR, Delivery, EmulatedDnie};
use rdnie::{Command, Response, StatusWord, Transport};

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

fn challenge_on(delivery: Delivery, command: &Command) -> Response {
    EmulatedDnie::new(&DNIE_3_ATR)
        .delivering(delivery)
        .transmit(command)
        .unwrap()
}

fn direct_challenge() -> Response {
    challenge_on(Delivery::Direct, &get_challenge(0x00, Some(8)))
}

#[test]
fn completes_pending_response_with_get_response() {
    let response = challenge_on(
        Delivery::GetResponse { chunk: 8 },
        &get_challenge(0x00, Some(8)),
    );
    assert_eq!(response, direct_challenge());
}

#[test]
fn joins_pending_response_served_in_chunks() {
    let response = challenge_on(
        Delivery::GetResponse { chunk: 3 },
        &get_challenge(0x00, Some(8)),
    );
    assert_eq!(response, direct_challenge());
}

#[test]
fn completes_pending_response_of_protected_command() {
    let response = challenge_on(
        Delivery::GetResponse { chunk: 8 },
        &get_challenge(0x0C, Some(8)),
    );
    assert_eq!(response, direct_challenge());
}

#[test]
fn resends_with_le_the_card_asks_for() {
    let response = challenge_on(Delivery::ExactLe, &get_challenge(0x00, Some(4)));
    assert_eq!(response, direct_challenge());
}

#[test]
fn resends_without_le_with_the_one_the_card_asks_for() {
    let response = challenge_on(Delivery::ExactLe, &get_challenge(0x00, None));
    assert_eq!(response, direct_challenge());
}

#[test]
fn returns_wrong_length_of_protected_command_as_is() {
    let response = challenge_on(Delivery::ExactLe, &get_challenge(0x0C, Some(4)));
    assert_eq!(response.status, StatusWord(0x6C08));
}
