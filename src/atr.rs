// Derived from JMulticard: see LICENSE.jmulticard.md.

//! DNIe detection and classification by ATR.

use std::fmt::Write as _;

use crate::Error;

/// Tag `6A` followed by "DNIe" in the historical bytes of the ATR.
const DNIE_TAG: &[u8] = b"\x6ADNIe";

const DNIE_ATR: [u8; 20] = [
    0x3B, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x90, 0x00,
];

const DNIE_ATR_MASK: [u8; 20] = [
    0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xFF, 0xFF,
];

/// Major version of the card operating system.
const OS_VERSION: usize = 15;

const DNIE_3_OS: u8 = 0x04;

const UNKNOWN: &str = "unknown";

const BURNED_STATUS: [u8; 2] = [0x65, 0x81];

/// Whether the ATR belongs to a DNIe.
#[must_use]
pub fn is_dnie(atr: &[u8]) -> bool {
    atr.first() == Some(&0x3B) && atr.windows(DNIE_TAG.len()).any(|window| window == DNIE_TAG)
}

/// Accepts a DNIe 3.0/4.0 ATR and refuses any other card with its own error.
pub(crate) fn check_dnie_3(atr: &[u8]) -> Result<(), Error> {
    if !is_dnie(atr) {
        return Err(Error::NotDnie);
    }
    if atr.ends_with(&BURNED_STATUS) {
        return Err(Error::BurnedDnie);
    }
    if !matches_mask(atr) {
        return Err(Error::NotDnie);
    }
    if atr[OS_VERSION] != DNIE_3_OS {
        return Err(Error::LegacyDnie);
    }
    Ok(())
}

/// Describes an ATR in words for logs; any ATR that is not 20 bytes starting with `3B` gives its hex bytes only.
#[must_use]
pub fn describe_atr(atr: &[u8]) -> String {
    let hex = hex(atr);
    if atr.len() != DNIE_ATR.len() || atr[0] != 0x3B {
        return format!("card ATR: {hex}");
    }
    let not_required = |byte: u8| {
        if byte == 0 {
            format!("{byte} (not required)")
        } else {
            byte.to_string()
        }
    };
    let name: String = atr[7..=10].iter().map(|&byte| char::from(byte)).collect();
    let maker = match atr[11] {
        0x10 => "Sagem / Morpho",
        0x20 => "Siemens / Atos",
        _ => UNKNOWN,
    };
    let chip_maker = match atr[12] {
        0x01 => "Infineon",
        0x02 => "STMicroelectronics",
        _ => UNKNOWN,
    };
    let chip_type = match (atr[13], atr[14]) {
        (0x01, 0x55) => "SLE78CLX408AP",
        (0x4C, 0x34) => "19WL34",
        _ => UNKNOWN,
    };
    let phase = match atr[17] {
        0x00 => "pre-personalisation",
        0x01 => "personalisation",
        0x03 => "user",
        0x0F => "final",
        _ => UNKNOWN,
    };
    let state = match (atr[18], atr[19]) {
        (0x90, 0x00) => "correct",
        (0x65, 0x81) => "volatile memory erased",
        _ => UNKNOWN,
    };
    format!(
        "DNIe ATR: {hex}\n  Vpp (programming voltage): {}\n  Extra guard time: {}\n  Card name: {name}\n  Match-on-Card maker: {maker}\n  Chip maker: {chip_maker}\n  Chip type: {chip_type}\n  OS version: {:02X}.{:02X}\n  Life-cycle phase: {phase}\n  State: {state}",
        not_required(atr[3]),
        not_required(atr[4]),
        atr[15],
        atr[16],
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02X}");
        out
    })
}

fn matches_mask(atr: &[u8]) -> bool {
    atr.len() == DNIE_ATR.len()
        && atr
            .iter()
            .zip(DNIE_ATR)
            .zip(DNIE_ATR_MASK)
            .all(|((byte, expected), mask)| byte & mask == expected & mask)
}

#[cfg(test)]
mod tests;
