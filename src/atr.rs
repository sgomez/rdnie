/// Tag `6A` followed by "DNIe" in the historical bytes of the ATR.
const DNIE_TAG: &[u8] = b"\x6ADNIe";

/// Whether the ATR belongs to a DNIe.
#[must_use]
pub fn is_dnie(atr: &[u8]) -> bool {
    atr.first() == Some(&0x3B) && atr.windows(DNIE_TAG.len()).any(|window| window == DNIE_TAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNIE_3: [u8; 20] = [
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55,
        0x04, 0x21, 0x03, 0x90, 0x00,
    ];

    #[test]
    fn recognises_dnie_3() {
        assert!(is_dnie(&DNIE_3));
    }

    #[test]
    fn rejects_other_cards() {
        let yubikey = [
            0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0,
            0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
        ];
        assert!(!is_dnie(&yubikey));
    }

    #[test]
    fn rejects_inverse_convention() {
        let mut atr = DNIE_3;
        atr[0] = 0x3F;
        assert!(!is_dnie(&atr));
    }
}
