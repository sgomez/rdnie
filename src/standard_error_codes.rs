// Derived from JMulticard: see LICENSE.jmulticard.md.

//! English descriptions of the ISO 7816-4 status words JMulticard describes.

/// The description of `status`, if JMulticard describes it.
pub(crate) fn describe(status: u16) -> Option<&'static str> {
    let description = match status {
        0x6283 => "selected file is invalidated",
        0x6581 => "memory failure",
        0x6700 => "wrong length",
        0x6882 => "secure messaging not supported",
        0x6982 => "security status not satisfied",
        0x6983 => "authentication method blocked",
        0x6984 => "referenced data invalid",
        0x6985 => "conditions of use not satisfied",
        0x6986 => "command not allowed, no elementary file selected",
        0x6987 => "expected secure messaging object missing",
        0x6988 => "secure messaging data objects incorrect",
        0x6A80 => "incorrect parameters in the data field",
        0x6A81 => "function not supported",
        0x6A82 => "file not found",
        0x6A83 => "record not found",
        0x6A84 => "not enough memory space in the file",
        0x6A85 => "data length incompatible with the TLV structure",
        0x6A86 => "incorrect parameters in P1 or P2",
        0x6A87 => "data length inconsistent with P1-P2",
        0x6A88 => "referenced data not found",
        0x6A89 => "file already exists",
        0x6A8A => "dedicated file name already exists",
        0x6B00 => "incorrect parameters in P1-P2",
        0x6D00 => "command not allowed in the current life cycle phase",
        0x6E00 => "class not supported",
        0x6F00 => "no precise diagnosis",
        _ => return None,
    };
    Some(description)
}
