use super::*;

#[test]
fn refuses_the_emulated_card_when_opened_with_the_embedded_roots() {
    let mut session = Session::open(card_with_channel()).unwrap();
    assert!(matches!(
        session.pin_retries_left(),
        Err(Error::SecureChannel(_))
    ));
}

#[cfg(feature = "emulator")]
#[test]
fn opens_the_secure_channel_trusting_the_emulator_root() {
    let mut session =
        Session::open_trusting(card_with_channel(), component_root_public_key()).unwrap();
    assert!(session.pin_retries_left().is_ok());
}
