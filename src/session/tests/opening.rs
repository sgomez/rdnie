use super::*;

#[test]
fn takes_first_generation_keys_below_bmp100001() {
    let card = card_accepting(&[&R1_PIN]).with_idesp(b"BMP100000");
    assert!(retries(card).is_ok());
}

#[test]
fn takes_second_generation_keys_from_bmp100001() {
    let second = card_accepting(&[&R2_PIN]).with_idesp(b"BMP100001");
    let first = card_accepting(&[&R1_PIN]).with_idesp(b"BMP100001");
    assert!(retries(second).is_ok());
    assert!(retries(first).is_err());
}

#[test]
fn takes_second_generation_keys_without_idesp() {
    assert!(retries(card_accepting(&[&R2_PIN])).is_ok());
}

#[test]
fn keeps_the_idesp() {
    let card = EmulatedDnie::new(&DNIE_3_ATR).with_idesp(b"TST000042");
    let session = Session::open(card).unwrap();
    assert_eq!(session.idesp.as_deref(), Some("TST000042"));
}

#[test]
fn reports_the_key_generation_of_the_card() {
    let generation = |idesp: &[u8]| {
        let card = EmulatedDnie::new(&DNIE_3_ATR).with_idesp(idesp);
        Session::open(card).unwrap().key_generation()
    };
    assert_eq!(generation(b"BMP100000"), KeyGeneration::First);
    assert_eq!(generation(b"BMP100001"), KeyGeneration::Second);
    let bare = Session::open(EmulatedDnie::new(&DNIE_3_ATR)).unwrap();
    assert_eq!(bare.key_generation(), KeyGeneration::Second);
}

#[test]
fn opens_without_idesp() {
    let session = Session::open(EmulatedDnie::new(&DNIE_3_ATR)).unwrap();
    assert_eq!(session.idesp, None);
}
