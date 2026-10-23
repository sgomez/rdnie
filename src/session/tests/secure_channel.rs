use super::*;

#[test]
fn reports_a_card_reset_mid_channel() {
    let card = card_with_channel().resetting_mid_channel();
    assert!(matches!(retries(card), Err(Error::CardReset)));
}

#[test]
fn reports_the_channel_lost_on_6688() {
    let card = card_with_channel().losing_the_channel();
    assert!(matches!(retries(card), Err(Error::ChannelLost)));
}

#[test]
fn reports_a_secure_channel_error_on_a_bad_response_mac() {
    let card = card_with_channel().corrupting_a_response_mac();
    assert!(matches!(retries(card), Err(Error::SecureChannel(_))));
}

fn reads_retries_and_signs_over(shape: ResponseShape) {
    let mut session = open(signing_card().with_pin_retries(2).shaping_responses(shape));
    assert_eq!(session.pin_retries().unwrap(), 2);
    let certificate = session.certificate("Cert1").unwrap().unwrap();
    let digest = Sha256::digest(b"document");
    let signature = sign_with(&mut session, &digest, HashAlgorithm::Sha256).unwrap();
    verify(
        &certificate,
        Pkcs1v15Sign::new::<Sha256>(),
        &digest,
        &signature,
    );
}

#[test]
fn ignores_bytes_after_the_response_mac() {
    reads_retries_and_signs_over(ResponseShape::TrailingBytes(&[0x00, 0x8E, 0x01, 0xFF]));
}

#[test]
fn skips_the_first_cryptogram_byte_whatever_its_value() {
    reads_retries_and_signs_over(ResponseShape::CryptogramIndicator(0x02));
}

#[test]
fn appends_the_status_word_object_before_its_last_two_bytes_to_the_data() {
    reads_retries_and_signs_over(ResponseShape::LongStatusWord(3));
}

#[test]
fn takes_the_data_from_a_status_word_object_without_cryptogram() {
    reads_retries_and_signs_over(ResponseShape::LongStatusWord(usize::MAX));
}

#[test]
fn refuses_malformed_responses_before_sending_the_pin() {
    for shape in [
        ResponseShape::ShortStatusWord,
        ResponseShape::EmptyCryptogram,
    ] {
        let card = || signing_card().shaping_responses(shape);
        assert!(matches!(retries(card()), Err(Error::SecureChannel(_))));
        let (result, card) = sign_with_pin(card(), DEFAULT_PIN);
        assert!(matches!(result, Err(Error::SecureChannel(_))));
        assert!(card.pin_queries().iter().all(|query| !query.with_pin));
    }
}

#[test]
fn ends_an_endless_pending_response_inside_the_channel_with_its_status() {
    let card = card_with_channel().pending_forever_inside_the_channel();
    assert!(matches!(
        retries(card),
        Err(Error::Status(StatusWord(0x6105)))
    ));
}

#[test]
fn ends_an_endless_wrong_length_inside_the_channel_with_its_status() {
    let mut session = open(card_with_channel().asking_a_wrong_length_forever_inside_the_channel());
    assert!(matches!(
        session.pin_retries(),
        Err(Error::Status(StatusWord(0x6C05)))
    ));
    assert_eq!(session.transport.pin_queries().len(), 1 + 2);
}

#[test]
fn ends_an_endless_wrong_length_with_bytes_after_the_mac_with_its_status() {
    let card = card_with_channel()
        .asking_a_wrong_length_forever_inside_the_channel()
        .shaping_responses(ResponseShape::TrailingBytes(&[0x00, 0x8E, 0x01, 0xFF]));
    assert!(matches!(
        retries(card),
        Err(Error::Status(StatusWord(0x6C05)))
    ));
}

#[test]
fn sends_the_pin_at_most_three_times_on_an_endless_wrong_length() {
    let card = signing_card().asking_a_wrong_length_forever_on_the_pin();
    let (result, card) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::Status(StatusWord(0x6C05)))));
    let attempts = card.pin_queries().iter().filter(|query| query.with_pin);
    assert_eq!(attempts.count(), 3);
    assert_eq!(retries(card).unwrap(), 3);
}

#[test]
fn starts_a_fresh_channel_after_each_failure() {
    let faulty = [
        card_with_channel().resetting_mid_channel(),
        card_with_channel().losing_the_channel(),
        card_with_channel().corrupting_a_response_mac(),
    ];
    for card in faulty {
        let mut session = open(card.with_pin_retries(2));
        assert!(session.pin_retries().is_err());
        assert_eq!(session.pin_retries().unwrap(), 2);
    }
}
