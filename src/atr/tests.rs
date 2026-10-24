use super::*;

const DNIE_3: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

const DNIE_4: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x20, 0x02, 0x4C, 0x34, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

const DNIE_4_STM: [u8; 20] = [
    0x3B, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x20, 0x02, 0x4C, 0x34, 0x01,
    0x02, 0x03, 0x65, 0x81,
];

fn with_byte(atr: [u8; 20], index: usize, value: u8) -> Atr {
    let mut atr = atr;
    atr[index] = value;
    Atr::new(atr)
}

#[test]
fn accepts_dnie_3_and_4() {
    assert!(Atr::new(DNIE_3).check().is_ok());
    assert!(Atr::new(DNIE_4).check().is_ok());
}

#[test]
fn names_a_legacy_dnie() {
    assert!(matches!(
        with_byte(DNIE_3, 15, 0x01).check(),
        Err(Error::LegacyDnie)
    ));
}

#[test]
fn names_a_burned_dnie() {
    let mut burned = DNIE_3;
    burned[18] = 0x65;
    burned[19] = 0x81;
    assert!(matches!(Atr::new(burned).check(), Err(Error::BurnedDnie)));
}

#[test]
fn refuses_other_cards() {
    let yubikey = [
        0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57,
        0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
    ];
    assert!(matches!(Atr::new(yubikey).check(), Err(Error::NotDnie)));
    assert!(matches!(
        with_byte(DNIE_3, 7, b'X').check(),
        Err(Error::NotDnie)
    ));
    assert!(matches!(Atr::new([]).check(), Err(Error::NotDnie)));
}

#[test]
fn refuses_other_cards_ending_in_the_burned_status() {
    assert!(matches!(
        with_byte(DNIE_4_STM, 7, b'X').check(),
        Err(Error::NotDnie)
    ));
    assert!(matches!(
        with_byte(DNIE_4_STM, 0, 0x3F).check(),
        Err(Error::NotDnie)
    ));
}

#[test]
fn refuses_inverse_convention() {
    assert!(matches!(
        with_byte(DNIE_3, 0, 0x3F).check(),
        Err(Error::NotDnie)
    ));
}

#[test]
fn refuses_a_dnie_with_unknown_status_bytes() {
    assert!(matches!(
        with_byte(DNIE_3, 19, 0x01).check(),
        Err(Error::NotDnie)
    ));
}

#[test]
fn gives_its_bytes() {
    assert_eq!(Atr::new(DNIE_3).as_bytes(), DNIE_3);
}

#[test]
fn describes_infineon_dnie() {
    assert_eq!(
        Atr::new(DNIE_3).to_string(),
        "DNIe ATR: 3B7F960000006A444E4965100101550421039000".to_owned()
            + "\n  Vpp (programming voltage): 0 (not required)\n  Extra guard time: 0 (not required)\n  Card name: DNIe\n  Match-on-Card maker: Sagem / Morpho\n  Chip maker: Infineon\n  Chip type: SLE78CLX408AP\n  OS version: 04.21\n  Life-cycle phase: user\n  State: correct"
    );
}

#[test]
fn describes_burned_stmicroelectronics_dnie() {
    assert_eq!(
        Atr::new(DNIE_4_STM).to_string(),
        "DNIe ATR: 3B7F000000006A444E496520024C340102036581".to_owned()
            + "\n  Vpp (programming voltage): 0 (not required)\n  Extra guard time: 0 (not required)\n  Card name: DNIe\n  Match-on-Card maker: Siemens / Atos\n  Chip maker: STMicroelectronics\n  Chip type: 19WL34\n  OS version: 01.02\n  Life-cycle phase: user\n  State: volatile memory erased"
    );
}

#[test]
fn names_each_life_cycle_phase() {
    for (byte, phase) in [
        (0x00, "pre-personalisation"),
        (0x01, "personalisation"),
        (0x03, "user"),
        (0x0F, "final"),
    ] {
        assert!(
            with_byte(DNIE_3, 17, byte)
                .to_string()
                .contains(&format!("Life-cycle phase: {phase}\n"))
        );
    }
}

#[test]
fn names_unknown_values() {
    let mut atr = DNIE_3;
    atr[3] = 0x05;
    atr[4] = 0x07;
    atr[11] = 0x99;
    atr[12] = 0x99;
    atr[13] = 0x99;
    atr[17] = 0x77;
    atr[18] = 0x6A;
    atr[19] = 0x82;
    let text = Atr::new(atr).to_string();
    assert!(text.contains("Vpp (programming voltage): 5\n"));
    assert!(text.contains("Extra guard time: 7\n"));
    assert!(text.contains("Match-on-Card maker: unknown\n"));
    assert!(text.contains("Chip maker: unknown\n"));
    assert!(text.contains("Chip type: unknown\n"));
    assert!(text.contains("Life-cycle phase: unknown\n"));
    assert!(text.ends_with("State: unknown"));
}

#[test]
fn describes_other_atrs_by_their_bytes() {
    assert_eq!(Atr::new([0x3B, 0x00, 0xAB]).to_string(), "card ATR: 3B00AB");
    let mut long = DNIE_3.to_vec();
    long.push(0x00);
    assert!(Atr::new(long).to_string().starts_with("card ATR: 3B7F96"));
    assert!(
        with_byte(DNIE_3, 0, 0x3F)
            .to_string()
            .starts_with("card ATR: 3F7F96")
    );
}
