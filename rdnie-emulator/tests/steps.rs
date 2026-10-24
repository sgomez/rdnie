//! A consumer schedules the card's removal or reset at a named step and sees it through `Session`.

use rdnie::{DigestAlgorithm, Error, Pin, SIGNATURE_LABEL, Session};
use rdnie_emulator::{DEFAULT_PIN, EmulatedDnie, Step};
use rsa::sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
enum Strike {
    Removal,
    Reset,
}

fn schedule(strike: Strike, step: Step) -> EmulatedDnie {
    match strike {
        Strike::Removal => EmulatedDnie::dnie_3().removing_card_at(step),
        Strike::Reset => EmulatedDnie::dnie_3().resetting_card_at(step),
    }
}

fn open(card: EmulatedDnie) -> Result<Session<EmulatedDnie>, Error> {
    let root = card.component_root();
    Session::open_trusting(card, root)
}

/// Runs the session up to `step`, which must fail.
fn run_to(step: Step, card: EmulatedDnie) -> Error {
    let mut session = match open(card) {
        Ok(session) => session,
        Err(error) => {
            assert!(matches!(step, Step::Opening), "opening failed early");
            return error;
        }
    };
    if let Err(error) = session.labels() {
        assert!(
            matches!(step, Step::Certificates),
            "certificates failed early"
        );
        return error;
    }
    let key = session.private_key(SIGNATURE_LABEL).unwrap().unwrap();
    if let Err(error) = session.pin_retries_left() {
        assert!(matches!(step, Step::PinRetries), "retries failed early");
        return error;
    }
    let digest = Sha256::digest(b"document");
    match session.sign(
        &digest,
        DigestAlgorithm::Sha256,
        &key,
        Pin::new(DEFAULT_PIN.to_owned()),
    ) {
        Ok(_) => panic!("the card struck at no step"),
        Err(error) => {
            assert!(
                matches!(step, Step::Verify | Step::Signing),
                "signing failed early"
            );
            error
        }
    }
}

const STEPS: [Step; 5] = [
    Step::Opening,
    Step::Certificates,
    Step::PinRetries,
    Step::Verify,
    Step::Signing,
];

#[test]
fn removes_the_card_at_each_step() {
    for step in STEPS {
        let error = run_to(step, schedule(Strike::Removal, step));
        assert!(matches!(error, Error::CardRemoved), "{step:?}: {error:?}");
    }
}

#[test]
fn resets_the_card_at_each_step() {
    for step in STEPS {
        let error = run_to(step, schedule(Strike::Reset, step));
        assert!(matches!(error, Error::CardReset), "{step:?}: {error:?}");
    }
}

#[test]
fn a_removed_card_stays_removed() {
    let mut session = open(schedule(Strike::Removal, Step::Certificates)).unwrap();
    assert!(matches!(session.labels(), Err(Error::CardRemoved)));
    assert!(matches!(
        session.pin_retries_left(),
        Err(Error::CardRemoved)
    ));
}

#[test]
fn a_reset_strikes_once() {
    let mut session = open(schedule(Strike::Reset, Step::PinRetries)).unwrap();
    assert!(matches!(session.pin_retries_left(), Err(Error::CardReset)));
    assert_eq!(session.pin_retries_left().unwrap(), 3);
}

#[test]
fn a_signing_strike_comes_after_verify() {
    let mut session = open(schedule(Strike::Removal, Step::Signing)).unwrap();
    let key = session.private_key(SIGNATURE_LABEL).unwrap().unwrap();
    let digest = Sha256::digest(b"document");
    let mut sign = |pin: &str| {
        session.sign(
            &digest,
            DigestAlgorithm::Sha256,
            &key,
            Pin::new(pin.to_owned()),
        )
    };
    assert!(matches!(
        sign("wrong-pin"),
        Err(Error::WrongPin { retries_left: 2 })
    ));
    assert!(matches!(sign(DEFAULT_PIN), Err(Error::CardRemoved)));
}
