//! The public `Transport::transmit`, which carries the plain channel's ISO follow-up.

use rdnie::{Command, Response, Transport};
use rdnie_emulator::{DNIE_3_ATR, Delivery, EmulatedDnie};

fn get_challenge(le: Option<u16>) -> Command {
    Command {
        cla: 0x00,
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
    challenge_on(Delivery::Direct, &get_challenge(Some(8)))
}

#[test]
fn completes_pending_response_with_get_response() {
    let response = challenge_on(Delivery::GetResponse { chunk: 3 }, &get_challenge(Some(8)));
    assert_eq!(response, direct_challenge());
}

#[test]
fn resends_with_le_the_card_asks_for() {
    let response = challenge_on(Delivery::ExactLe, &get_challenge(Some(4)));
    assert_eq!(response, direct_challenge());
}
