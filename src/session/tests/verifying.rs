use super::{pin::pin_transactions_since, *};

fn verify_with(session: &mut Session<EmulatedDnie>, pin: &str) -> Result<(), Error> {
    session.verify_pin(Pin::new(pin.to_owned()))
}

fn attempts(card: &EmulatedDnie) -> usize {
    card.pin_queries()
        .iter()
        .filter(|query| query.with_pin)
        .count()
}

#[test]
fn verifies_the_right_pin() {
    let mut session = open(signing_card());
    verify_with(&mut session, DEFAULT_PIN).unwrap();
    assert!(session.transport.pin_verified());
}

#[test]
fn reports_a_wrong_pin_with_the_retries_left_after_one_attempt() {
    let mut session = open(signing_card());
    let result = verify_with(&mut session, "WrongPin1");
    assert!(matches!(result, Err(Error::WrongPin { retries_left: 2 })));
    assert_eq!(attempts(&session.transport), 1);
    assert!(!session.transport.pin_verified());
}

#[test]
fn sends_no_pin_to_a_blocked_card() {
    let mut session = open(signing_card().with_pin_retries(0));
    assert!(matches!(
        verify_with(&mut session, DEFAULT_PIN),
        Err(Error::PinBlocked)
    ));
    assert_eq!(attempts(&session.transport), 0);
}

#[test]
fn aborts_before_verify_when_the_retries_changed_between_phases() {
    let mut session = open(signing_card().losing_a_retry_between_phases());
    assert!(matches!(
        verify_with(&mut session, DEFAULT_PIN),
        Err(Error::PinRetriesChanged)
    ));
    assert_eq!(attempts(&session.transport), 0);
}

#[test]
fn sends_no_apdu_for_an_invalid_format() {
    let mut session = open(signing_card());
    let sent = session.transport.commands();
    assert!(matches!(
        verify_with(&mut session, "short"),
        Err(Error::InvalidPinFormat)
    ));
    assert_eq!(session.transport.commands(), sent);
}

#[test]
fn reads_the_retries_first_when_none_were_shown() {
    let mut session = open(signing_card());
    verify_with(&mut session, DEFAULT_PIN).unwrap();
    let queries = session.transport.pin_queries();
    let read = queries.iter().find(|query| !query.with_pin).unwrap();
    let verified = queries.iter().find(|query| query.with_pin).unwrap();
    assert!(read.transaction < verified.transaction);
}

#[test]
fn reads_no_retries_in_a_separate_transaction_when_they_were_shown() {
    let mut session = open(signing_card());
    session.pin_retries_left().unwrap();
    let before = session.transport.pin_queries().len();
    verify_with(&mut session, DEFAULT_PIN).unwrap();
    assert_eq!(pin_transactions_since(&session.transport, before).len(), 1);
}

#[test]
fn a_following_sign_verifies_again_after_a_fallback_read() {
    let mut session = open(signing_card());
    verify_with(&mut session, DEFAULT_PIN).unwrap();
    let before = session.transport.pin_queries().len();
    sign_with(&mut session, &[0; 32], DigestAlgorithm::Sha256).unwrap();
    assert_eq!(pin_transactions_since(&session.transport, before).len(), 2);
    assert_eq!(attempts(&session.transport), 2);
}
