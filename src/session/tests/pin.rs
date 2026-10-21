use super::*;

#[test]
fn reads_the_retries_left() {
    assert_eq!(retries(card_with_channel().with_pin_retries(2)).unwrap(), 2);
}

#[test]
fn reports_a_blocked_pin() {
    assert!(matches!(
        retries(card_with_channel().with_pin_retries(0)),
        Err(Error::PinBlocked)
    ));
}

#[test]
fn refuses_any_other_retries_status() {
    assert!(matches!(
        retries(card_with_channel().answering_retries_with(0x6982)),
        Err(Error::Status(StatusWord(0x6982)))
    ));
}

#[test]
fn reads_the_retries_only_from_a_63cx_status() {
    for status in [0x6300, 0x63D2, 0x63A1, 0x64C2, 0x62C2] {
        let (result, card) =
            sign_with_pin(signing_card().answering_retries_with(status), DEFAULT_PIN);
        assert!(
            matches!(result, Err(Error::Status(StatusWord(s))) if s == status),
            "{status:04X}"
        );
        assert!(card.pin_queries().iter().all(|query| !query.with_pin));
    }
}

#[test]
fn reads_every_retries_count_up_to_15() {
    assert_eq!(
        retries(card_with_channel().answering_retries_with(0x63CF)).unwrap(),
        15
    );
    assert_eq!(
        retries(card_with_channel().answering_retries_with(0x63C1)).unwrap(),
        1
    );
}

#[test]
fn reports_a_blocked_pin_on_6983_to_the_retries_query() {
    let card = card_with_channel().answering_retries_with(0x6983);
    assert!(matches!(retries(card), Err(Error::PinBlocked)));
}

#[test]
fn reports_a_blocked_pin_when_verify_answers_63c0() {
    let card = signing_card().answering_verify_with(0x63C0);
    let (result, _) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
}

#[test]
fn reports_the_retries_left_when_verify_answers_63cx() {
    for retries_left in [1, 2, 15] {
        let card = signing_card().answering_verify_with(0x63C0 | u16::from(retries_left));
        let (result, _) = sign_with_pin(card, DEFAULT_PIN);
        assert!(
            matches!(result, Err(Error::WrongPin { retries_left: left }) if left == retries_left),
            "{retries_left}"
        );
    }
}

#[test]
fn reports_a_blocked_pin_when_verify_answers_6983() {
    let card = signing_card().answering_verify_with(0x6983);
    let (result, _) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
}

#[test]
fn reports_an_unknown_verify_status_as_such() {
    for status in [0x6A80, 0x6300, 0x63D2, 0x64C2] {
        let card = signing_card().answering_verify_with(status);
        let (result, _) = sign_with_pin(card, DEFAULT_PIN);
        assert!(
            matches!(result, Err(Error::Status(StatusWord(s))) if s == status),
            "{status:04X}"
        );
    }
}

#[test]
fn rejects_a_malformed_pin_without_any_apdu() {
    let too_long = "a".repeat(17);
    for pin in ["short", "ñandú", too_long.as_str()] {
        let mut session = open(signing_card());
        let key = session.certificates().unwrap().remove(0).key;
        let sent = session.transport.commands();
        let result = session.sign(
            &[0; 32],
            HashAlgorithm::Sha256,
            &key,
            Pin::new(pin.to_owned()),
        );
        assert!(matches!(result, Err(Error::InvalidPinFormat)), "{pin:?}");
        assert_eq!(session.transport.commands(), sent);
    }
}

#[test]
fn sends_a_non_ascii_pin_as_latin_1_bytes() {
    let card = signing_card().with_pin_bytes(b"\xF1and\xFA\xE7o1");
    assert!(sign_with_pin(card, "ñandúço1").0.is_ok());
}

#[test]
fn sends_symbols_and_spaces() {
    let pin = "a b!@#$%&";
    let card = signing_card().with_pin(pin);
    assert!(sign_with_pin(card, pin).0.is_ok());
}

#[test]
fn sends_the_low_byte_of_each_utf16_unit() {
    let card = signing_card().with_pin_bytes(b"\x00\x01\x02\x03abcde");
    assert!(
        sign_with_pin(card, "\u{100}\u{201}\u{302}\u{403}abcde")
            .0
            .is_ok()
    );
}

#[test]
fn counts_the_length_in_utf16_units() {
    let card = signing_card().with_pin_bytes(b"\xF1\xF1\xF1\xF1\xF1\xF1\xF1\xF1");
    assert!(sign_with_pin(card, "ññññññññ").0.is_ok());
    let sixteen = "ñ".repeat(16);
    let card = signing_card().with_pin_bytes(&[0xF1; 16]);
    assert!(sign_with_pin(card, &sixteen).0.is_ok());
    let result = sign_with_pin(signing_card(), &"ñ".repeat(17)).0;
    assert!(matches!(result, Err(Error::InvalidPinFormat)));
}

#[test]
fn a_wrong_non_ascii_pin_costs_one_attempt() {
    let (result, card) = sign_with_pin(signing_card(), "ñandúço1");
    assert!(matches!(result, Err(Error::WrongPin { retries_left: 2 })));
    let attempts = card.pin_queries().iter().filter(|query| query.with_pin);
    assert_eq!(attempts.count(), 1);
}

#[test]
fn accepts_the_pin_length_limits() {
    for pin in ["12345678", "1234567890123456"] {
        let card = signing_card().with_pin(pin);
        assert!(sign_with_pin(card, pin).0.is_ok(), "{pin}");
    }
}

#[test]
fn sends_no_verify_to_a_blocked_pin() {
    let (result, card) = sign_with_pin(signing_card().with_pin_retries(0), DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
}

#[test]
fn makes_one_attempt_with_a_wrong_pin_and_reports_the_retries() {
    let (result, card) = sign_with_pin(signing_card(), "WrongPin1");
    assert!(matches!(result, Err(Error::WrongPin { retries_left: 2 })));
    let attempts = card.pin_queries().iter().filter(|query| query.with_pin);
    assert_eq!(attempts.count(), 1);
    assert!(!card.pin_verified());
}

#[test]
fn reports_a_blocked_pin_when_the_attempt_exhausts_it() {
    let card = signing_card().with_pin_retries(1);
    let (result, _) = sign_with_pin(card, "WrongPin1");
    assert!(matches!(result, Err(Error::PinBlocked)));
}

#[test]
fn aborts_before_verify_when_the_retries_changed_between_phases() {
    let card = signing_card().losing_a_retry_between_phases();
    let (result, card) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinRetriesChanged)));
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
}

#[test]
fn aborts_before_verify_when_the_retries_changed_while_the_caller_prompted() {
    let mut session = open(signing_card().losing_a_retry_between_phases());
    let key = session.certificates().unwrap().remove(0).key;
    assert_eq!(session.pin_retries().unwrap(), 3);
    let result = session.sign(
        &[0; 32],
        HashAlgorithm::Sha256,
        &key,
        Pin::new(DEFAULT_PIN.to_owned()),
    );
    assert!(matches!(result, Err(Error::PinRetriesChanged)));
    let card = session.into_transport();
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
}

#[test]
fn aborts_before_verify_when_no_retry_is_left() {
    let card = signing_card().answering_retries_with(0x63C0);
    let (result, card) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
}
