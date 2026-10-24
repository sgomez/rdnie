//! Opening a session classifies the card by its ATR.

use std::{cell::Cell, rc::Rc};

use rdnie::{Atr, Error, Port, Session, Transport};
use rdnie_emulator::{DNIE_3_ATR, DNIE_4_ATR, EmulatedDnie};

/// Counts every time the session reads the ATR or opens a transaction.
struct Counting(EmulatedDnie, Rc<Cell<usize>>);

impl Transport for Counting {
    fn atr(&self) -> Result<Atr, Error> {
        self.1.set(self.1.get() + 1);
        self.0.atr()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Port) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.1.set(self.1.get() + 1);
        self.0.transaction(body)
    }
}

#[test]
fn gives_the_atr_it_opened_without_touching_the_card() {
    for atr in [DNIE_3_ATR, DNIE_4_ATR] {
        let calls = Rc::new(Cell::new(0));
        let session = Session::open(Counting(EmulatedDnie::new(&atr), Rc::clone(&calls))).unwrap();
        let opened = calls.get();
        assert_eq!(session.atr(), &Atr::new(atr));
        assert_eq!(calls.get(), opened);
    }
}

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
