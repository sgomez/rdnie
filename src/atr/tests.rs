use super::*;

const DNIE_3: [u8; 20] = [
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55, 0x04,
    0x21, 0x03, 0x90, 0x00,
];

#[test]
fn recognises_dnie_3() {
    assert!(is_dnie(&DNIE_3));
}

#[test]
fn rejects_other_cards() {
    let yubikey = [
        0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57,
        0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
    ];
    assert!(!is_dnie(&yubikey));
}

#[test]
fn rejects_inverse_convention() {
    let mut atr = DNIE_3;
    atr[0] = 0x3F;
    assert!(!is_dnie(&atr));
}

const DNIE_4_STM: [u8; 20] = [
    0x3B, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x20, 0x02, 0x4C, 0x34, 0x01,
    0x02, 0x03, 0x65, 0x81,
];

#[test]
fn describes_infineon_dnie() {
    assert_eq!(
        describe_atr(&DNIE_3),
        "DNIe ATR: 3B7F960000006A444E4965100101550421039000".to_owned()
            + "\n  Vpp (programming voltage): 0 (not required)\n  Extra guard time: 0 (not required)\n  Card name: DNIe\n  Match-on-Card maker: Sagem / Morpho\n  Chip maker: Infineon\n  Chip type: SLE78CLX408AP\n  OS version: 04.21\n  Life-cycle phase: user\n  State: correct"
    );
}

#[test]
fn describes_burned_stmicroelectronics_dnie() {
    assert_eq!(
        describe_atr(&DNIE_4_STM),
        "DNIe ATR: 3B7F000000006A444E496520024C340102036581".to_owned()
            + "\n  Vpp (programming voltage): 0 (not required)\n  Extra guard time: 0 (not required)\n  Card name: DNIe\n  Match-on-Card maker: Siemens / Atos\n  Chip maker: STMicroelectronics\n  Chip type: 19WL34\n  OS version: 01.02\n  Life-cycle phase: user\n  State: volatile memory erased"
    );
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
    let text = describe_atr(&atr);
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
    assert_eq!(describe_atr(&[0x3B, 0x00, 0xAB]), "card ATR: 3B00AB");
    let mut long = DNIE_3.to_vec();
    long.push(0x00);
    assert!(describe_atr(&long).starts_with("card ATR: 3B7F96"));
    let mut inverse = DNIE_3;
    inverse[0] = 0x3F;
    assert!(describe_atr(&inverse).starts_with("card ATR: 3F7F96"));
}
