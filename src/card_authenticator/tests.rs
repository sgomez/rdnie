use super::*;
use crate::{
    Command, StatusWord,
    emulator::{DEFAULT_PIN, EmulatedDnie, component_root_public_key},
    session::tests::card_accepting,
};

const VERIFY: u8 = 0x20;
const SECURITY_STATUS_NOT_SATISFIED: StatusWord = StatusWord(0x6982);

const GENERATIONS: [KeyGeneration; 2] = [KeyGeneration::First, KeyGeneration::Second];

fn authenticator(generation: KeyGeneration) -> CardAuthenticator {
    CardAuthenticator::new(
        generation,
        ComponentRoots::only(component_root_public_key()),
    )
}

fn card_of(generation: KeyGeneration) -> EmulatedDnie {
    card_accepting(&[
        KeySet::for_generation(generation, Channel::Pin),
        KeySet::for_generation(generation, Channel::User),
    ])
}

fn verify_status(channel: &mut SecureChannel<'_>) -> StatusWord {
    channel
        .transmit(&Command {
            cla: 0x00,
            ins: VERIFY,
            p1: 0x00,
            p2: 0x00,
            data: DEFAULT_PIN.as_bytes().to_vec(),
            le: None,
        })
        .unwrap()
        .status
}

#[test]
fn resolves_the_idesp_into_a_key_generation() {
    let cases = [
        (Some("BMP000001"), KeyGeneration::First),
        (Some("BMP099999"), KeyGeneration::First),
        (Some("BMP100000"), KeyGeneration::First),
        (Some("BMP100001"), KeyGeneration::Second),
        (Some("BMP100002"), KeyGeneration::Second),
        (Some("BMP200000"), KeyGeneration::Second),
        (Some("TST000042"), KeyGeneration::Second),
        (Some("AAA000001"), KeyGeneration::First),
        (Some(""), KeyGeneration::Second),
        (None, KeyGeneration::Second),
    ];
    for (idesp, expected) in cases {
        let roots = ComponentRoots::only(component_root_public_key());
        let authenticator = CardAuthenticator::from_idesp(idesp, roots);
        assert_eq!(authenticator.key_generation(), expected, "{idesp:?}");
    }
}

#[test]
fn opens_the_pin_channel_with_the_pin_keys_of_its_generation() {
    for generation in GENERATIONS {
        let mut card = card_of(generation);
        let mut channel = authenticator(generation)
            .open_pin_channel(PlainChannel::new(&mut card))
            .unwrap();
        assert_eq!(
            verify_status(&mut channel),
            StatusWord::SUCCESS,
            "{generation:?}"
        );
    }
}

#[test]
fn opens_the_user_channel_inside_the_pin_channel_with_the_user_keys_of_its_generation() {
    for generation in GENERATIONS {
        let mut card = card_of(generation);
        let authenticator = authenticator(generation);
        let pin_channel = authenticator
            .open_pin_channel(PlainChannel::new(&mut card))
            .unwrap();
        let mut user_channel = authenticator.open_user_channel(pin_channel).unwrap();
        assert_eq!(
            verify_status(&mut user_channel),
            SECURITY_STATUS_NOT_SATISFIED,
            "{generation:?}"
        );
        let [pin, user] = card.handshakes() else {
            panic!("expected two handshakes, got {}", card.handshakes().len());
        };
        assert!(!pin.inside_channel);
        assert!(user.inside_channel);
    }
}

#[test]
fn refuses_a_card_of_the_other_generation() {
    for [generation, other] in [GENERATIONS, [GENERATIONS[1], GENERATIONS[0]]] {
        let mut card = card_of(other);
        assert!(
            authenticator(generation)
                .open_pin_channel(PlainChannel::new(&mut card))
                .is_err(),
            "{generation:?}"
        );
    }
}
