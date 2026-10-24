use super::{pin::pin_transactions_since, *};

fn read_retries(card: EmulatedDnie) -> (Session<EmulatedDnie>, crate::KeyReference) {
    let mut session = open(card);
    let key = first_key(&mut session);
    session.pin_retries_left().unwrap();
    (session, key)
}

fn sign(session: &mut Session<EmulatedDnie>, key: &crate::KeyReference) -> Result<Vec<u8>, Error> {
    let pin = Pin::new(DEFAULT_PIN.to_owned());
    session.sign(&[0; 32], DigestAlgorithm::Sha256, key, pin)
}

fn verify(session: &mut Session<EmulatedDnie>) -> Result<(), Error> {
    session.verify_pin(Pin::new(DEFAULT_PIN.to_owned()))
}

fn pin_sent(card: &EmulatedDnie) -> bool {
    card.pin_queries().iter().any(|query| query.with_pin)
}

/// Swaps the session's card for what `fault` makes of it, as the test's next step.
fn strike(session: &mut Session<EmulatedDnie>, fault: impl FnOnce(EmulatedDnie) -> EmulatedDnie) {
    let card = std::mem::replace(&mut session.transport, EmulatedDnie::new(&DNIE_3_ATR));
    session.transport = fault(card);
}

#[test]
fn each_operation_of_a_batch_takes_one_pin_transaction() {
    let mut session = open(signing_card());
    let key = first_key(&mut session);
    let before = session.transport.pin_queries().len();
    session.pin_retries_left().unwrap();
    verify(&mut session).unwrap();
    for _ in 0..3 {
        sign(&mut session, &key).unwrap();
    }
    assert_eq!(pin_transactions_since(&session.transport, before).len(), 5);
}

#[test]
fn a_retry_burned_since_an_accepted_verify_aborts_the_next_sign_before_the_pin() {
    let (mut session, key) = read_retries(signing_card());
    verify(&mut session).unwrap();
    let before = session.transport.pin_queries().len();
    session.transport.burn_a_retry();
    assert!(matches!(
        sign(&mut session, &key),
        Err(Error::PinRetriesChanged)
    ));
    let queries = &session.transport.pin_queries()[before..];
    assert!(queries.iter().all(|query| !query.with_pin));
}

#[test]
fn a_blocked_answer_to_verify_blocks_the_next_operation_until_the_retries_are_read() {
    let (mut session, key) = read_retries(signing_card().answering_verify_with(0x6983));
    assert!(matches!(sign(&mut session, &key), Err(Error::PinBlocked)));
    let sent = session.transport.commands();
    assert!(matches!(verify(&mut session), Err(Error::PinBlocked)));
    assert_eq!(session.transport.commands(), sent);
    assert_eq!(session.pin_retries_left().unwrap(), 3);
}

#[test]
fn a_blocked_card_read_blocks_the_next_sign_without_any_apdu() {
    let mut session = open(signing_card().with_pin_retries(0));
    let key = first_key(&mut session);
    assert!(matches!(session.pin_retries_left(), Err(Error::PinBlocked)));
    let sent = session.transport.commands();
    assert!(matches!(sign(&mut session, &key), Err(Error::PinBlocked)));
    assert_eq!(session.transport.commands(), sent);
}

#[test]
fn every_retry_burned_since_the_read_blocks_on_the_reread_and_then_without_any_apdu() {
    let (mut session, key) = read_retries(signing_card());
    for _ in 0..3 {
        session.transport.burn_a_retry();
    }
    assert!(matches!(sign(&mut session, &key), Err(Error::PinBlocked)));
    assert!(!pin_sent(&session.transport));
    let sent = session.transport.commands();
    assert!(matches!(verify(&mut session), Err(Error::PinBlocked)));
    assert_eq!(session.transport.commands(), sent);
}

#[test]
fn a_reset_at_signing_after_an_accepted_verify_keeps_the_next_sign_to_one_transaction() {
    let (mut session, key) = read_retries(signing_card());
    strike(&mut session, |card| card.resetting_card_at(Step::Signing));
    assert!(matches!(sign(&mut session, &key), Err(Error::CardReset)));
    let before = session.transport.pin_queries().len();
    sign(&mut session, &key).unwrap();
    assert_eq!(pin_transactions_since(&session.transport, before).len(), 1);
}

#[test]
fn a_fault_before_verify_keeps_the_next_sign_to_one_transaction() {
    let (mut session, key) = read_retries(signing_card());
    strike(&mut session, |card| {
        card.resetting_card_at(Step::PinRetries)
    });
    assert!(matches!(sign(&mut session, &key), Err(Error::CardReset)));
    assert!(!pin_sent(&session.transport));
    let before = session.transport.pin_queries().len();
    sign(&mut session, &key).unwrap();
    assert_eq!(pin_transactions_since(&session.transport, before).len(), 1);
}

#[test]
fn an_invalid_pin_format_keeps_the_next_sign_to_one_transaction() {
    let (mut session, key) = read_retries(signing_card());
    let short = Pin::new("short".to_owned());
    let result = session.sign(&[0; 32], DigestAlgorithm::Sha256, &key, short);
    assert!(matches!(result, Err(Error::InvalidPinFormat)));
    let before = session.transport.pin_queries().len();
    sign(&mut session, &key).unwrap();
    assert_eq!(pin_transactions_since(&session.transport, before).len(), 1);
}
