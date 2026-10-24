//! A `Transport` decorator reaches the card only through the inner transport's transaction.

#[expect(dead_code, reason = "the corpora are written by `fuzz_seeds`")]
mod recorder;

use rdnie::Session;
use rdnie_emulator::{DNIE_3_ATR, EmulatedDnie};
use recorder::Recorder;

#[test]
fn a_recorder_runs_its_transactions_in_the_card_s() {
    let recorder = Session::open(Recorder::new(EmulatedDnie::new(&DNIE_3_ATR)))
        .unwrap()
        .into_transport();
    assert!(!recorder.exchanges.is_empty());
    assert!(recorder.card.transactions() > 0);
}
