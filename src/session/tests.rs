use super::Session;
use rsa::{
    Pkcs1v15Sign, RsaPublicKey,
    pkcs8::DecodePublicKey,
    sha2::{Digest, Sha256, Sha384, Sha512},
};
use x509_cert::der::{Decode, Encode};

use crate::{
    Error, HashAlgorithm, KeyGeneration, Pin, StatusWord,
    emulator::{
        DEFAULT_PIN, DNIE_3_ATR, EmulatedDnie, HolderCertificate, ResponseShape, TerminalKey,
        component_root_public_key,
    },
    key_sets::{ComponentRoots, KeySet, R1_PIN, R1_USER, R2_PIN, R2_USER},
};

pub(crate) fn card_accepting(key_sets: &[&KeySet]) -> EmulatedDnie {
    let terminals: Vec<TerminalKey> = key_sets
        .iter()
        .map(|keys| TerminalKey {
            chr: keys.terminal_chr,
            modulus: keys.modulus.to_vec(),
            user: [&R1_USER, &R2_USER]
                .iter()
                .any(|user| std::ptr::eq(*user, *keys)),
        })
        .collect();
    EmulatedDnie::new(&DNIE_3_ATR).with_secure_channel(&terminals)
}

pub(crate) fn card_with_channel() -> EmulatedDnie {
    card_accepting(&[&R1_PIN, &R1_USER, &R2_PIN, &R2_USER])
}

pub(crate) fn open(card: EmulatedDnie) -> Session<EmulatedDnie> {
    Session::open_with_roots(card, ComponentRoots::only(component_root_public_key())).unwrap()
}

fn retries(card: EmulatedDnie) -> Result<u8, Error> {
    open(card).pin_retries()
}

#[test]
fn reads_the_retries_left() {
    assert_eq!(retries(card_with_channel().with_pin_retries(2)).unwrap(), 2);
}

#[test]
fn reports_a_blocked_pin() {
    assert!(matches!(
        retries(card_with_channel().with_pin_retries(0)),
        Err(Error::PinBlocked)
    ));
}

#[test]
fn refuses_any_other_retries_status() {
    assert!(matches!(
        retries(card_with_channel().answering_retries_with(0x6982)),
        Err(Error::Status(StatusWord(0x6982)))
    ));
}

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

struct Unplugged(EmulatedDnie, bool);

impl crate::Transport for Unplugged {
    fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        if self.1 {
            return Err(Error::Transport("unplugged".to_owned()));
        }
        self.0.transmit_raw(apdu)
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        self.0.reset()
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn crate::Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }
}

fn listed_card() -> EmulatedDnie {
    EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&[
        HolderCertificate::new(1, 120).labelled("CertFirma"),
        HolderCertificate::new(2, 120).without_key(),
        HolderCertificate::new(3, 120).labelled("CertAutenticacion"),
    ])
}

#[test]
fn a_second_listing_sends_nothing_to_the_card() {
    let mut session = open(listed_card());
    let first = session.certificates().unwrap();
    let sent = session.transport.commands();
    let second = session.certificates().unwrap();
    assert_eq!(session.transport.commands(), sent);
    let ders = |list: &[crate::Certificate]| list.iter().map(|c| c.der.clone()).collect::<Vec<_>>();
    assert_eq!(ders(&first), ders(&second));
    assert_eq!(first.len(), 2);
}

#[test]
fn a_fetch_after_a_listing_sends_nothing_to_the_card() {
    let mut session = open(listed_card());
    session.certificates().unwrap();
    let sent = session.transport.commands();
    assert!(session.certificate("CertFirma").unwrap().is_some());
    assert_eq!(session.transport.commands(), sent);
}

#[test]
fn a_fetch_as_the_first_call_loads_the_certificates() {
    let mut session = open(listed_card());
    let sent = session.transport.commands();
    assert!(session.certificate("CertFirma").unwrap().is_some());
    assert!(session.transport.commands() > sent);
}

#[test]
fn a_failed_fetch_is_retried_on_the_next_call() {
    let mut session =
        Session::open_with_roots(Unplugged(listed_card(), false), ComponentRoots::embedded())
            .unwrap();
    session.transport.1 = true;
    assert!(matches!(
        session.certificate("CertFirma"),
        Err(Error::Transport(_))
    ));
    session.transport.1 = false;
    assert!(session.certificate("CertFirma").unwrap().is_some());
}

#[test]
fn a_failed_load_is_retried_on_the_next_call() {
    let mut session =
        Session::open_with_roots(Unplugged(listed_card(), false), ComponentRoots::embedded())
            .unwrap();
    session.transport.1 = true;
    assert!(matches!(session.certificates(), Err(Error::Transport(_))));
    session.transport.1 = false;
    assert_eq!(session.certificates().unwrap().len(), 2);
}

fn signing_card() -> EmulatedDnie {
    card_with_channel().with_certificates(&[HolderCertificate::signing(1)])
}

fn sign_with(
    session: &mut Session<EmulatedDnie>,
    digest: &[u8],
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, Error> {
    let key = session.certificates().unwrap().remove(0).key;
    session.sign(digest, algorithm, &key, Pin::new(DEFAULT_PIN.to_owned()))
}

fn verify(certificate: &[u8], scheme: Pkcs1v15Sign, digest: &[u8], signature: &[u8]) {
    let certificate = x509_cert::Certificate::from_der(certificate).unwrap();
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    RsaPublicKey::from_public_key_der(&spki)
        .unwrap()
        .verify(scheme, digest, signature)
        .expect("the signature verifies with the certificate's public key");
}

#[test]
fn signs_digests_that_verify_with_the_certificate() {
    let data = b"document";
    let cases = [
        (
            HashAlgorithm::Sha256,
            Pkcs1v15Sign::new::<Sha256>(),
            Sha256::digest(data).to_vec(),
        ),
        (
            HashAlgorithm::Sha384,
            Pkcs1v15Sign::new::<Sha384>(),
            Sha384::digest(data).to_vec(),
        ),
        (
            HashAlgorithm::Sha512,
            Pkcs1v15Sign::new::<Sha512>(),
            Sha512::digest(data).to_vec(),
        ),
    ];
    let mut session = open(signing_card());
    let certificate = session.certificates().unwrap().remove(0).der;
    for (algorithm, scheme, digest) in cases {
        let signature = sign_with(&mut session, &digest, algorithm).unwrap();
        verify(&certificate, scheme, &digest, &signature);
    }
}

#[test]
fn rejects_a_digest_of_another_length_before_any_apdu() {
    let mut session = open(signing_card());
    let key = session.certificates().unwrap().remove(0).key;
    let sent = session.transport.commands();
    let result = session.sign(
        &[0; 48],
        HashAlgorithm::Sha256,
        &key,
        Pin::new(DEFAULT_PIN.to_owned()),
    );
    assert!(matches!(
        result,
        Err(Error::DigestLength {
            expected: 32,
            actual: 48
        })
    ));
    assert_eq!(session.transport.commands(), sent);
}

#[test]
fn verifies_the_pin_in_a_fresh_transaction_after_reading_the_retries() {
    let mut session = open(signing_card());
    sign_with(&mut session, &[0; 32], HashAlgorithm::Sha256).unwrap();
    let queries = session.transport.pin_queries();
    let read = queries.iter().find(|query| !query.with_pin).unwrap();
    let verified = queries.iter().find(|query| query.with_pin).unwrap();
    assert!(read.transaction < verified.transaction);
}

#[test]
fn opens_the_user_channel_inside_the_pin_channel() {
    let (result, card) = sign_with_pin(signing_card(), DEFAULT_PIN);
    result.unwrap();
    let [pin_channels @ .., user_channel] = card.handshakes() else {
        panic!("no handshake");
    };
    assert!(user_channel.inside_channel);
    assert!(
        pin_channels
            .iter()
            .all(|handshake| !handshake.inside_channel)
    );
}

fn sign_with_pin(card: EmulatedDnie, pin: &str) -> (Result<Vec<u8>, Error>, EmulatedDnie) {
    let mut session = open(card);
    let key = session.certificates().unwrap().remove(0).key;
    let result = session.sign(
        &[0; 32],
        HashAlgorithm::Sha256,
        &key,
        Pin::new(pin.to_owned()),
    );
    (result, session.into_transport())
}

#[test]
fn reads_the_retries_only_from_a_63cx_status() {
    for status in [0x6300, 0x63D2, 0x63A1, 0x64C2, 0x62C2] {
        let (result, card) =
            sign_with_pin(signing_card().answering_retries_with(status), DEFAULT_PIN);
        assert!(
            matches!(result, Err(Error::Status(StatusWord(s))) if s == status),
            "{status:04X}"
        );
        assert!(card.pin_queries().iter().all(|query| !query.with_pin));
    }
}

#[test]
fn reads_every_retries_count_up_to_15() {
    assert_eq!(
        retries(card_with_channel().answering_retries_with(0x63CF)).unwrap(),
        15
    );
    assert_eq!(
        retries(card_with_channel().answering_retries_with(0x63C1)).unwrap(),
        1
    );
}

#[test]
fn reports_a_blocked_pin_on_6983_to_the_retries_query() {
    let card = card_with_channel().answering_retries_with(0x6983);
    assert!(matches!(retries(card), Err(Error::PinBlocked)));
}

#[test]
fn reports_a_blocked_pin_when_verify_answers_63c0() {
    let card = signing_card().answering_verify_with(0x63C0);
    let (result, _) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
}

#[test]
fn reports_the_retries_left_when_verify_answers_63cx() {
    for retries_left in [1, 2, 15] {
        let card = signing_card().answering_verify_with(0x63C0 | u16::from(retries_left));
        let (result, _) = sign_with_pin(card, DEFAULT_PIN);
        assert!(
            matches!(result, Err(Error::WrongPin { retries_left: left }) if left == retries_left),
            "{retries_left}"
        );
    }
}

#[test]
fn reports_a_blocked_pin_when_verify_answers_6983() {
    let card = signing_card().answering_verify_with(0x6983);
    let (result, _) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
}

#[test]
fn reports_an_unknown_verify_status_as_such() {
    for status in [0x6A80, 0x6300, 0x63D2, 0x64C2] {
        let card = signing_card().answering_verify_with(status);
        let (result, _) = sign_with_pin(card, DEFAULT_PIN);
        assert!(
            matches!(result, Err(Error::Status(StatusWord(s))) if s == status),
            "{status:04X}"
        );
    }
}

#[test]
fn rejects_a_malformed_pin_without_any_apdu() {
    let too_long = "a".repeat(17);
    for pin in ["short", "ñandú", too_long.as_str()] {
        let mut session = open(signing_card());
        let key = session.certificates().unwrap().remove(0).key;
        let sent = session.transport.commands();
        let result = session.sign(
            &[0; 32],
            HashAlgorithm::Sha256,
            &key,
            Pin::new(pin.to_owned()),
        );
        assert!(matches!(result, Err(Error::InvalidPinFormat)), "{pin:?}");
        assert_eq!(session.transport.commands(), sent);
    }
}

#[test]
fn sends_a_non_ascii_pin_as_latin_1_bytes() {
    let card = signing_card().with_pin_bytes(b"\xF1and\xFA\xE7o1");
    assert!(sign_with_pin(card, "ñandúço1").0.is_ok());
}

#[test]
fn sends_symbols_and_spaces() {
    let pin = "a b!@#$%&";
    let card = signing_card().with_pin(pin);
    assert!(sign_with_pin(card, pin).0.is_ok());
}

#[test]
fn sends_the_low_byte_of_each_utf16_unit() {
    let card = signing_card().with_pin_bytes(b"\x00\x01\x02\x03abcde");
    assert!(
        sign_with_pin(card, "\u{100}\u{201}\u{302}\u{403}abcde")
            .0
            .is_ok()
    );
}

#[test]
fn counts_the_length_in_utf16_units() {
    let card = signing_card().with_pin_bytes(b"\xF1\xF1\xF1\xF1\xF1\xF1\xF1\xF1");
    assert!(sign_with_pin(card, "ññññññññ").0.is_ok());
    let sixteen = "ñ".repeat(16);
    let card = signing_card().with_pin_bytes(&[0xF1; 16]);
    assert!(sign_with_pin(card, &sixteen).0.is_ok());
    let result = sign_with_pin(signing_card(), &"ñ".repeat(17)).0;
    assert!(matches!(result, Err(Error::InvalidPinFormat)));
}

#[test]
fn a_wrong_non_ascii_pin_costs_one_attempt() {
    let (result, card) = sign_with_pin(signing_card(), "ñandúço1");
    assert!(matches!(result, Err(Error::WrongPin { retries_left: 2 })));
    let attempts = card.pin_queries().iter().filter(|query| query.with_pin);
    assert_eq!(attempts.count(), 1);
}

#[test]
fn accepts_the_pin_length_limits() {
    for pin in ["12345678", "1234567890123456"] {
        let card = signing_card().with_pin(pin);
        assert!(sign_with_pin(card, pin).0.is_ok(), "{pin}");
    }
}

#[test]
fn sends_no_verify_to_a_blocked_pin() {
    let (result, card) = sign_with_pin(signing_card().with_pin_retries(0), DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
}

#[test]
fn makes_one_attempt_with_a_wrong_pin_and_reports_the_retries() {
    let (result, card) = sign_with_pin(signing_card(), "WrongPin1");
    assert!(matches!(result, Err(Error::WrongPin { retries_left: 2 })));
    let attempts = card.pin_queries().iter().filter(|query| query.with_pin);
    assert_eq!(attempts.count(), 1);
    assert!(!card.pin_verified());
}

#[test]
fn reports_a_blocked_pin_when_the_attempt_exhausts_it() {
    let card = signing_card().with_pin_retries(1);
    let (result, _) = sign_with_pin(card, "WrongPin1");
    assert!(matches!(result, Err(Error::PinBlocked)));
}

#[test]
fn aborts_before_verify_when_the_retries_changed_between_phases() {
    let card = signing_card().losing_a_retry_between_phases();
    let (result, card) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinRetriesChanged)));
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
}

#[test]
fn aborts_before_verify_when_the_retries_changed_while_the_caller_prompted() {
    let mut session = open(signing_card().losing_a_retry_between_phases());
    let key = session.certificates().unwrap().remove(0).key;
    assert_eq!(session.pin_retries().unwrap(), 3);
    let result = session.sign(
        &[0; 32],
        HashAlgorithm::Sha256,
        &key,
        Pin::new(DEFAULT_PIN.to_owned()),
    );
    assert!(matches!(result, Err(Error::PinRetriesChanged)));
    let card = session.into_transport();
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
}

#[test]
fn aborts_before_verify_when_no_retry_is_left() {
    let card = signing_card().answering_retries_with(0x63C0);
    let (result, card) = sign_with_pin(card, DEFAULT_PIN);
    assert!(matches!(result, Err(Error::PinBlocked)));
    assert!(card.pin_queries().iter().all(|query| !query.with_pin));
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
    let certificate = session.certificates().unwrap().remove(0).der;
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
