use super::*;

fn command(data: Vec<u8>, le: Option<u16>) -> Command {
    Command {
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data,
        le,
    }
}

#[test]
fn encodes_header_only() {
    assert_eq!(
        command(vec![], None).to_bytes().unwrap(),
        [0x00, 0xA4, 0x04, 0x00]
    );
}

#[test]
fn encodes_data_and_le() {
    assert_eq!(
        command(vec![0xAA, 0xBB], Some(16)).to_bytes().unwrap(),
        [0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x10]
    );
}

#[test]
fn encodes_le_256_as_zero() {
    assert_eq!(command(vec![], Some(256)).to_bytes().unwrap()[4], 0x00);
}

#[test]
fn rejects_data_longer_than_short_apdu() {
    assert!(matches!(
        command(vec![0; 256], None).to_bytes(),
        Err(Error::CommandTooLong(256))
    ));
}

#[test]
fn rejects_le_above_256() {
    assert!(matches!(
        command(vec![], Some(257)).to_bytes(),
        Err(Error::CommandTooLong(257))
    ));
}

#[test]
fn splits_data_from_status_word() {
    let response = Response::parse(&[0x01, 0x02, 0x90, 0x00]).unwrap();
    assert_eq!(response.data, [0x01, 0x02]);
    assert!(response.status.is_success());
}

#[test]
fn rejects_response_without_status_word() {
    assert!(matches!(
        Response::parse(&[0x90]),
        Err(Error::TruncatedResponse(1))
    ));
}

#[test]
fn reports_failing_status_word() {
    let error = Response::parse(&[0x6A, 0x82])
        .unwrap()
        .into_success()
        .unwrap_err();
    assert_eq!(error.to_string(), "card answered file not found (6A 82)");
}

#[test]
fn describes_a_known_status_word_before_its_code() {
    assert_eq!(
        StatusWord(0x6982).to_string(),
        "security status not satisfied (69 82)"
    );
}

#[test]
fn shows_only_the_code_of_an_undescribed_status_word() {
    assert_eq!(StatusWord(0x6300).to_string(), "63 00");
    assert_eq!(StatusWord::SUCCESS.to_string(), "90 00");
}
