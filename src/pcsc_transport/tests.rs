use super::*;

#[test]
fn reports_card_reset_as_its_own_error() {
    assert!(matches!(
        connected(pcsc::Error::ResetCard),
        Error::CardReset
    ));
}

#[test]
fn reports_a_missing_reader_while_connecting() {
    assert!(matches!(
        connecting(pcsc::Error::NoReadersAvailable),
        Error::NoReader
    ));
    assert!(matches!(
        connecting(pcsc::Error::UnknownReader),
        Error::NoReader
    ));
}

#[test]
fn reports_an_empty_reader_while_connecting() {
    assert!(matches!(
        connecting(pcsc::Error::NoSmartcard),
        Error::NoCard
    ));
    assert!(matches!(
        connecting(pcsc::Error::RemovedCard),
        Error::NoCard
    ));
}

#[test]
fn reports_other_failures_while_connecting_as_transport_errors() {
    assert!(matches!(
        connecting(pcsc::Error::SharingViolation),
        Error::Transport(_)
    ));
}

#[test]
fn reports_a_removed_card_while_connected() {
    assert!(matches!(
        connected(pcsc::Error::RemovedCard),
        Error::CardRemoved
    ));
    assert!(matches!(
        connected(pcsc::Error::NoSmartcard),
        Error::CardRemoved
    ));
}

#[test]
fn reports_a_transport_failure_with_an_empty_reader_as_a_removed_card() {
    let result = removed_if_empty::<()>(Err(Error::Transport("not transacted".into())), || true);
    assert!(matches!(result, Err(Error::CardRemoved)));
}

#[test]
fn keeps_a_transport_failure_while_the_card_is_present() {
    let result = removed_if_empty::<()>(Err(Error::Transport("not transacted".into())), || false);
    assert!(matches!(result, Err(Error::Transport(_))));
}

#[test]
fn checks_the_reader_only_after_a_transport_failure() {
    let result = removed_if_empty(Err::<(), _>(Error::CardReset), || unreachable!());
    assert!(matches!(result, Err(Error::CardReset)));
}

#[test]
fn keeps_the_body_error_over_a_failed_end() {
    let outcome = outcome::<()>(Err(Error::CardReset), Err(Error::Transport("end".into())));
    assert!(matches!(outcome, Err(Error::CardReset)));
}

#[test]
fn reports_a_failed_end_after_a_successful_body() {
    let outcome = outcome(Ok(1), Err(Error::Transport("end".into())));
    assert!(matches!(outcome, Err(Error::Transport(_))));
}

#[test]
fn reconnects_only_after_a_card_reset() {
    let reconnects = |result: Result<(), Error>| {
        let mut reconnected = false;
        let _ = recovering(result, || reconnected = true);
        reconnected
    };
    assert!(reconnects(Err(Error::CardReset)));
    assert!(!reconnects(Err(Error::ChannelLost)));
    assert!(!reconnects(Err(Error::CardRemoved)));
    assert!(!reconnects(Ok(())));
}

#[test]
fn a_failed_reopen_leaves_no_handle_and_later_calls_fail() {
    let mut handle = Ok("A");
    let reopened = reopen(&mut handle, || Err(pcsc::Error::NoSmartcard)).copied();
    assert!(matches!(reopened, Err(Error::NoCard)));
    assert!(matches!(usable(&handle), Err(Error::NoCard)));
    assert!(matches!(usable_mut(&mut handle), Err(Error::NoCard)));
}

#[test]
fn a_lost_handle_reports_the_reconnect_failure_as_mapped() {
    let mut handle = Ok("A");
    let _ = reopen(&mut handle, || Err(pcsc::Error::UnknownReader));
    assert!(matches!(usable(&handle), Err(Error::NoReader)));
    let _ = reopen(&mut handle, || Err(pcsc::Error::SharingViolation));
    assert!(matches!(usable(&handle), Err(Error::Transport(_))));
}

#[test]
fn a_later_reopen_restores_the_handle() {
    let mut handle = Ok("A");
    let _ = reopen(&mut handle, || Err(pcsc::Error::NoSmartcard));
    assert_eq!(reopen(&mut handle, || Ok("A")).ok(), Some(&"A"));
    assert_eq!(usable(&handle).ok(), Some(&"A"));
}

const DNIE_3: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

const BURNED_DNIE: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55, 0x04,
    0x21, 0x03, 0x65, 0x81,
];

const OTHER_CARD: [u8; 4] = [0x3B, 0x02, 0x14, 0x50];

fn card(reader: &str, atr: &[u8]) -> Probe<String> {
    Probe::Card(reader.to_owned(), atr.to_vec())
}

#[test]
fn scanning_no_readers_finds_no_reader() {
    assert!(matches!(first_dnie::<String>([]), Err(Error::NoReader)));
}

#[test]
fn scanning_takes_the_reader_with_a_dnie() {
    let scan = first_dnie([card("A", &DNIE_3)]);
    assert_eq!(scan.ok().as_deref(), Some("A"));
}

#[test]
fn scanning_takes_a_burned_dnie_so_the_session_reports_it() {
    let scan = first_dnie([Probe::Empty, card("B", &BURNED_DNIE)]);
    assert_eq!(scan.ok().as_deref(), Some("B"));
}

#[test]
fn scanning_prefers_a_wrong_card_over_an_empty_reader() {
    let scan = first_dnie([Probe::Empty, card("B", &OTHER_CARD), Probe::Empty]);
    assert!(matches!(scan, Err(Error::NotDnie)));
}

#[test]
fn scanning_only_empty_readers_finds_no_card() {
    let scan = first_dnie::<String>([Probe::Empty, Probe::Empty]);
    assert!(matches!(scan, Err(Error::NoCard)));
}

#[test]
fn scanning_reports_the_first_failure_when_no_card_is_found() {
    let scan = first_dnie::<String>([
        Probe::Empty,
        Probe::Failed(pcsc::Error::SharingViolation),
        Probe::Failed(pcsc::Error::ReaderUnavailable),
    ]);
    let Err(Error::Transport(message)) = scan else {
        panic!("expected a transport error, got {scan:?}");
    };
    assert_eq!(message, pcsc::Error::SharingViolation.to_string());
}

#[test]
fn scanning_takes_a_dnie_after_a_failing_reader() {
    let scan = first_dnie([
        Probe::Failed(pcsc::Error::SharingViolation),
        card("B", &DNIE_3),
    ]);
    assert_eq!(scan.ok().as_deref(), Some("B"));
}

#[test]
fn reports_other_failures_while_connected_as_transport_errors() {
    assert!(matches!(
        connected(pcsc::Error::SharingViolation),
        Error::Transport(_)
    ));
}

#[test]
fn listing_gives_names_in_system_order() {
    let names = reader_names(Ok(vec![c("Reader B 00 00"), c("Reader A 01 00")]));
    assert_eq!(
        names.ok(),
        Some(vec![
            "Reader B 00 00".to_owned(),
            "Reader A 01 00".to_owned()
        ])
    );
}

#[test]
fn listing_without_readers_is_empty_not_an_error() {
    let names = reader_names(Err(pcsc::Error::NoReadersAvailable));
    assert_eq!(names.ok(), Some(vec![]));
    assert_eq!(reader_names(Ok(vec![])).ok(), Some(vec![]));
}

#[test]
fn listing_reports_other_failures_as_transport_errors() {
    let names = reader_names(Err(pcsc::Error::ServiceStopped));
    assert!(matches!(names, Err(Error::Transport(_))));
}

#[test]
fn a_name_with_a_nul_byte_is_an_unknown_reader() {
    assert!(matches!(reader_cstring("Reader\0A"), Err(Error::NoReader)));
    assert_eq!(
        reader_cstring("Reader A 00 00").ok(),
        Some(c("Reader A 00 00"))
    );
}

fn c(name: &str) -> CString {
    CString::new(name).expect("no NUL in a test name")
}

#[test]
fn a_card_without_td1_offers_only_t0() {
    assert_eq!(offered_protocols(&DNIE_3), Protocols::T0);
}

#[test]
fn a_card_with_td1_lets_pcsc_choose() {
    assert_eq!(offered_protocols(&[0x3B, 0x80, 0x01, 0x01]), Protocols::ANY);
}

#[test]
fn an_atr_too_short_to_read_lets_pcsc_choose() {
    assert_eq!(offered_protocols(&[0x3B]), Protocols::ANY);
    assert_eq!(offered_protocols(&[]), Protocols::ANY);
}
