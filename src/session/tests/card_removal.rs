use super::*;

#[test]
fn returns_card_removed_unchanged_from_listing() {
    let mut session = open(signing_card());
    session.transport.remove_card();
    assert!(matches!(session.certificates(), Err(Error::CardRemoved)));
    assert!(matches!(
        session.certificate("any"),
        Err(Error::CardRemoved)
    ));
}

#[test]
fn returns_card_removed_unchanged_from_retries() {
    let mut session = open(card_with_channel());
    session.transport.remove_card();
    assert!(matches!(session.pin_retries(), Err(Error::CardRemoved)));
}

#[test]
fn returns_card_removed_from_sign_and_never_sends_the_pin() {
    let mut session = open(signing_card());
    let key = session.certificates().unwrap().remove(0).key;
    session.pin_retries().unwrap();
    session.transport.remove_card();
    let pin = Pin::new(DEFAULT_PIN.to_owned());
    let result = session.sign(&[0; 32], HashAlgorithm::Sha256, &key, pin);
    assert!(matches!(result, Err(Error::CardRemoved)));
    assert!(
        session
            .transport
            .pin_queries()
            .iter()
            .all(|query| !query.with_pin)
    );
}

#[test]
fn returns_card_removed_from_sign_when_the_retries_were_not_read() {
    let mut session = open(signing_card());
    let key = session.certificates().unwrap().remove(0).key;
    session.transport.remove_card();
    let pin = Pin::new(DEFAULT_PIN.to_owned());
    let result = session.sign(&[0; 32], HashAlgorithm::Sha256, &key, pin);
    assert!(matches!(result, Err(Error::CardRemoved)));
    assert!(
        session
            .transport
            .pin_queries()
            .iter()
            .all(|query| !query.with_pin)
    );
}
