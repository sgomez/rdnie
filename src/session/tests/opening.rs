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

#[test]
fn opens_without_resetting_the_card() {
    let session = open(card_with_channel());
    assert_eq!(session.transport.resets(), 0);
}

#[test]
fn opens_twice_on_the_same_card() {
    let card = open(card_with_channel()).into_transport();
    let mut session = open(card);
    assert_eq!(session.pin_retries().unwrap(), 3);
    assert_eq!(session.transport.resets(), 0);
}

#[test]
fn opens_after_an_operation_left_a_channel_open() {
    let card = card_accepting(&[&R1_PIN]).with_idesp(b"BMP100000");
    let mut first = open(card);
    first.pin_retries().unwrap();
    let mut session = open(first.into_transport());
    assert_eq!(session.key_generation(), KeyGeneration::First);
    assert_eq!(session.pin_retries().unwrap(), 3);
    assert_eq!(session.transport.resets(), 0);
}

#[test]
fn reads_after_a_channel_left_open_between_operations() {
    let mut session = open(signing_card());
    session.pin_retries().unwrap();
    assert_eq!(session.certificates().unwrap().len(), 1);
}

#[test]
fn takes_second_generation_keys_with_an_empty_idesp() {
    assert!(retries(card_accepting(&[&R2_PIN]).with_idesp(b"")).is_ok());
}

#[test]
fn fails_to_open_on_a_reset_during_the_idesp_read() {
    let card = card_with_channel().resetting_card_at(Step::Opening);
    let roots = ComponentRoots::only(component_root_public_key());
    assert!(matches!(
        Session::open_with_roots(card, roots),
        Err(Error::CardReset)
    ));
}

#[test]
fn fails_to_open_on_any_idesp_failure_but_an_absent_file() {
    let card = EmulatedDnie::new(&DNIE_3_ATR)
        .with_idesp(b"BMP100000")
        .delivering(Delivery::EndlessPending);
    assert!(matches!(
        Session::open(card),
        Err(Error::Status(StatusWord(0x6105)))
    ));
}

/// Answers `atr()` with its own ATR, whatever the card resets to.
struct Showing(Vec<u8>, EmulatedDnie);

impl crate::Transport for Showing {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        self.1.transmit_raw(apdu)
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.1.reset()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn crate::Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

#[test]
fn classifies_the_atr_the_transport_holds() {
    let open = |changes: &[(usize, u8)]| {
        let mut atr = DNIE_3_ATR;
        for &(index, value) in changes {
            atr[index] = value;
        }
        Session::open(Showing(atr.to_vec(), EmulatedDnie::new(&DNIE_3_ATR)))
    };
    assert!(matches!(open(&[(7, b'X')]), Err(Error::NotDnie)));
    assert!(matches!(open(&[(15, 0x01)]), Err(Error::LegacyDnie)));
    assert!(matches!(
        open(&[(18, 0x65), (19, 0x81)]),
        Err(Error::BurnedDnie)
    ));
    assert!(open(&[]).is_ok());
}
