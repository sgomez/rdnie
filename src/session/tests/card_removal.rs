use super::*;

#[test]
fn returns_card_removed_unchanged_from_listing() {
    let mut session = open(signing_card());
    session.transport.remove_card();
    assert!(matches!(session.labels(), Err(Error::CardRemoved)));
    assert!(matches!(
        session.certificate("any"),
        Err(Error::CardRemoved)
    ));
}

#[test]
fn returns_card_removed_unchanged_from_retries() {
    let mut session = open(card_with_channel());
    session.transport.remove_card();
    assert!(matches!(
        session.pin_retries_left(),
        Err(Error::CardRemoved)
    ));
}

#[test]
fn returns_card_removed_from_sign_and_never_sends_the_pin() {
    let mut session = open(signing_card());
    let key = first_key(&mut session);
    session.pin_retries_left().unwrap();
    session.transport.remove_card();
    let pin = Pin::new(DEFAULT_PIN.to_owned());
    let result = session.sign(&[0; 32], DigestAlgorithm::Sha256, &key, pin);
    assert!(matches!(result, Err(Error::CardRemoved)));
    assert!(
        session
            .transport
            .pin_queries()
            .iter()
            .all(|query| !query.with_pin)
    );
}
