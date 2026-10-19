//! Opening a session classifies the card by its ATR.

mod emulator;

use emulator::{DNIE_3_ATR, EmulatedDnie};
use rdnie::{Error, Session};

fn with_byte(atr: [u8; 20], index: usize, value: u8) -> [u8; 20] {
    let mut atr = atr;
    atr[index] = value;
    atr
}

#[test]
fn opens_on_dnie_3() {
    assert!(Session::open(EmulatedDnie::new(&DNIE_3_ATR)).is_ok());
}

#[test]
fn opens_on_dnie_with_other_chip_bytes() {
    let atr = [
        0x3B, 0x7F, 0x38, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x20, 0x02, 0x4C, 0x34,
        0x04, 0x30, 0x03, 0x90, 0x00,
    ];
    assert!(Session::open(EmulatedDnie::new(&atr)).is_ok());
}

#[test]
fn refuses_legacy_dnie() {
    let dnie_2 = with_byte(DNIE_3_ATR, 15, 0x01);
    assert!(matches!(
        Session::open(EmulatedDnie::new(&dnie_2)),
        Err(Error::LegacyDnie)
    ));
}

#[test]
fn refuses_burned_dnie() {
    let burned = with_byte(with_byte(DNIE_3_ATR, 18, 0x65), 19, 0x81);
    assert!(matches!(
        Session::open(EmulatedDnie::new(&burned)),
        Err(Error::BurnedDnie)
    ));
}

#[test]
fn refuses_other_cards() {
    let other = with_byte(DNIE_3_ATR, 7, b'X');
    assert!(matches!(
        Session::open(EmulatedDnie::new(&other)),
        Err(Error::NotDnie)
    ));
}

#[test]
fn refuses_dnie_with_unknown_status_bytes() {
    let unknown = with_byte(DNIE_3_ATR, 19, 0x01);
    assert!(matches!(
        Session::open(EmulatedDnie::new(&unknown)),
        Err(Error::NotDnie)
    ));
}
