//! Seed corpora of the secure-channel `fuzz/` targets, generated from the emulator only:
//! `just fuzz-seed`.

use std::collections::BTreeSet;

use crate::{
    Session, StatusWord,
    cwa14890::tests::{answers, recorded_internal_authentication},
    emulator::{
        HolderCertificate, ResponseShape, component_certificate, component_root_public_key,
        intermediate_certificate,
    },
    key_sets::ComponentRoots,
    recorder::{Recorder, write_corpus},
    secure_messaging::SecureMessaging,
    session::tests::card_with_channel,
};

const PROTECTED: u8 = 0x0C;

/// Plain answers whose cryptograms take every BER length form, each with its padding.
fn plain_answers() -> Vec<(StatusWord, Vec<u8>)> {
    let data = HolderCertificate::new(1, 600).der;
    let mut answers = vec![(StatusWord::SUCCESS, Vec::new())];
    for (length, status) in [7, 100, 127, 200, 255, 383, 511]
        .into_iter()
        .zip([0x9000, 0x6282].iter().cycle())
    {
        let mut plain = data[..length].to_vec();
        plain.push(0x80);
        plain.resize(plain.len().next_multiple_of(8), 0);
        answers.push((StatusWord(*status), plain));
    }
    answers
}

/// The raw protected responses of a PIN channel, as the card lays them out in `shape`.
fn recorded_protected_responses(shape: ResponseShape) -> Vec<Vec<u8>> {
    let roots = ComponentRoots::only(component_root_public_key());
    let card = Recorder::new(card_with_channel().shaping_responses(shape));
    let mut session = Session::open_with_roots(card, roots).unwrap();
    let _ = session.pin_retries();
    session
        .into_transport()
        .exchanges
        .into_iter()
        .filter(|(command, _)| command[0] & PROTECTED == PROTECTED)
        .map(|(_, response)| response)
        .collect()
}

#[test]
#[ignore = "writes the fuzz corpora: run by `just fuzz-seed`"]
fn writes_the_seed_corpora() {
    let plain = plain_answers();
    write_corpus(
        "secure_messaging",
        plain
            .iter()
            .map(|(status, data)| [&status.0.to_be_bytes()[..], data].concat())
            .collect(),
    );

    let mut raw: BTreeSet<_> = plain
        .iter()
        .map(|(status, data)| SecureMessaging::fixed().protected_response(data, *status))
        .collect();
    for shape in [
        ResponseShape::Standard,
        ResponseShape::TrailingBytes(&[0x01, 0x02, 0x03]),
        ResponseShape::LongStatusWord(4),
        ResponseShape::ShortStatusWord,
        ResponseShape::CryptogramIndicator(0x02),
        ResponseShape::EmptyCryptogram,
    ] {
        raw.extend(recorded_protected_responses(shape));
    }
    write_corpus("secure_messaging_raw", raw);

    let (challenge, answer) = recorded_internal_authentication();
    write_corpus(
        "cwa14890",
        [component_certificate(), intermediate_certificate()]
            .iter()
            .map(|certificate| answers(&challenge, certificate, &answer))
            .collect(),
    );
}
