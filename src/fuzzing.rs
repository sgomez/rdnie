//! Entry points of the `fuzz/` crate into the parsers of card data, built only under `cfg(fuzzing)`.

use crate::{
    Error, Holder, Port, Response, StatusWord, certificates, channel::PlainChannel, cwa14890,
    files, key_sets::ComponentRoots, pkcs15, secure_messaging::SecureMessaging,
};

const BLOCK: usize = 8;

/// A response APDU, its status word and its description.
pub fn apdu(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let response = Response::parse(raw)?;
    let _ = response.status.to_string();
    response.into_success()
}

/// The FCI a SELECT returns, and the same bytes as a PKCS#15 path.
pub fn files(fci: &[u8]) -> Result<usize, Error> {
    let _ = files::Location::new(fci).and_then(|location| location.last_file());
    files::fci_length(fci)
}

/// The response the card protects for the fixed channel: the first two bytes are its status word and
/// the rest, cut to whole blocks, its plain data with any padding.
pub fn secure_messaging(input: &[u8]) -> Result<(Vec<u8>, StatusWord), Error> {
    let Some((status, plain)) = input.split_first_chunk() else {
        return Response::parse(input).map(split);
    };
    let plain = &plain[..plain.len() - plain.len() % BLOCK];
    let mut channel = SecureMessaging::fixed();
    let protected = channel.protected_response(plain, StatusWord(u16::from_be_bytes(*status)));
    channel.unprotect(&Response::parse(&protected)?).map(split)
}

/// A protected response as it arrives, checked against the fixed channel.
pub fn secure_messaging_raw(raw: &[u8]) -> Result<(Vec<u8>, StatusWord), Error> {
    SecureMessaging::fixed()
        .unprotect(&Response::parse(raw)?)
        .map(split)
}

fn split(response: Response) -> (Vec<u8>, StatusWord) {
    (response.data, response.status)
}

/// The internal authentication challenge, a component certificate and the card's answer.
pub fn cwa14890(input: &[u8]) -> Result<bool, Error> {
    cwa14890::check_answers(input, &ComponentRoots::embedded())
}

/// A CDF or PrKDF, whose decode whole must match its decode as read object by object from a card.
pub fn pkcs15(file: &[u8]) -> Result<usize, Error> {
    let file = &file[..file.len().min(usize::from(u16::MAX))];
    let location = files::Location::new(&[0x60, 0x04]).expect("the path is valid");
    let read = files::read_sequences(
        &mut PlainChannel::new(&mut StoredFile(file)),
        &location,
        pkcs15::MAX_OBJECTS,
    )?;
    for labelled in [true, false] {
        assert_eq!(
            decoded(file, labelled),
            decoded(&read, labelled),
            "the object-by-object read changed the decode"
        );
    }
    Ok(pkcs15::entries(file, true)?.len() + pkcs15::entries(file, false)?.len())
}

type Decoded = Option<Vec<(String, Vec<u8>, Vec<u8>)>>;

fn decoded(bytes: &[u8], labelled: bool) -> Decoded {
    let entries = pkcs15::entries(bytes, labelled).ok()?;
    Some(
        entries
            .into_iter()
            .map(|e| (e.label, e.id, e.path))
            .collect(),
    )
}

/// A card that answers every SELECT with the FCI of one file and reads it as a DNIe does.
struct StoredFile<'a>(&'a [u8]);

impl Port for StoredFile<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
        let file = self.0;
        let answer = match apdu {
            [_, 0xA4, ..] => {
                let [high, low] = u16::try_from(file.len()).unwrap_or(u16::MAX).to_be_bytes();
                vec![0x6F, 0x04, 0x81, 0x02, high, low, 0x90, 0x00]
            }
            [_, 0xB0, p1, p2, le] => {
                let offset = usize::from(u16::from_be_bytes([*p1, *p2]));
                let wanted = usize::from(*le);
                match file.get(offset..) {
                    Some(rest) if !rest.is_empty() => {
                        let data = &rest[..rest.len().min(wanted)];
                        let status: [u8; 2] = if data.len() < wanted {
                            [0x62, 0x82]
                        } else {
                            [0x90, 0x00]
                        };
                        [data, &status].concat()
                    }
                    _ => vec![0x6B, 0x00],
                }
            }
            _ => vec![0x6D, 0x00],
        };
        Ok(answer)
    }
}

/// A stored certificate, plain or compressed.
pub fn certificates(stored: &[u8]) -> Result<Vec<u8>, Error> {
    certificates::stored_x509(stored.to_vec())
}

/// The holder's data in a certificate.
pub fn holder(der: &[u8]) -> Result<Holder, Error> {
    Holder::from_der(der)
}
