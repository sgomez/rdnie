//! Card side of the DNIe 3.0/4.0 secure messaging: unwraps commands and wraps responses.

use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    block_padding::{Iso7816, NoPadding},
};
use des::{Des, TdesEde2};
use retail_mac::{KeyInit, Mac, RetailMac};
use sha1::{Digest, Sha1};

const BLOCK: usize = 8;

/// A command the card recovered from its protected form.
pub struct Unwrapped {
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<usize>,
}

pub struct CardChannel {
    kenc: [u8; 16],
    kmac: [u8; 16],
    ssc: u64,
}

impl CardChannel {
    pub fn derive(kicc: &[u8; 32], kifd: &[u8; 32], rnd_icc: [u8; 8], rnd_ifd: [u8; 8]) -> Self {
        let k: Vec<u8> = kicc.iter().zip(kifd).map(|(a, b)| a ^ b).collect();
        let key = |counter: u32| -> [u8; 16] {
            Sha1::new()
                .chain_update(&k)
                .chain_update(counter.to_be_bytes())
                .finalize()[..16]
                .try_into()
                .unwrap()
        };
        let mut ssc = [0; 8];
        ssc[..4].copy_from_slice(&rnd_icc[4..]);
        ssc[4..].copy_from_slice(&rnd_ifd[4..]);
        Self {
            kenc: key(1),
            kmac: key(2),
            ssc: u64::from_be_bytes(ssc),
        }
    }

    /// Checks the MAC of `CLA INS P1 P2 Lc [87] [97] 8E` and decrypts it; `None` if it fails.
    pub fn unwrap(&mut self, apdu: &[u8]) -> Option<Unwrapped> {
        self.ssc += 1;
        let [cla, ins, p1, p2, lc, body @ ..] = apdu else {
            return None;
        };
        if body.len() != usize::from(*lc) {
            return None;
        }
        let mut objects = body;
        let mut authenticated = pad(&[*cla, *ins, *p1, *p2]);
        let mut data = Vec::new();
        let mut le = None;
        loop {
            let (tag, value, rest) = read_tlv(objects)?;
            match tag {
                0x87 => {
                    authenticated.extend_from_slice(&objects[..objects.len() - rest.len()]);
                    data = self.decrypt(value.get(1..)?)?;
                }
                0x97 => {
                    authenticated.extend_from_slice(&objects[..objects.len() - rest.len()]);
                    le = Some(match value {
                        [0] => 256,
                        [le] => usize::from(*le),
                        _ => return None,
                    });
                }
                0x8E if rest.is_empty() => {
                    return (self.mac(&authenticated)[..] == *value).then_some(Unwrapped {
                        ins: *ins,
                        p1: *p1,
                        p2: *p2,
                        data,
                        le,
                    });
                }
                _ => return None,
            }
            objects = rest;
        }
    }

    /// Wraps a plain answer as `[87] 99 8E` followed by `90 00`.
    pub fn wrap(&mut self, answer: &[u8]) -> Vec<u8> {
        self.ssc += 1;
        let (data, status) = answer.split_at(answer.len() - 2);
        let mut objects = Vec::new();
        if !data.is_empty() {
            let mut cryptogram = vec![0x01];
            cryptogram.extend(
                cbc::Encryptor::<TdesEde2>::new(&self.kenc.into(), &[0; BLOCK].into())
                    .encrypt_padded_vec::<Iso7816>(data),
            );
            push_tlv(&mut objects, 0x87, &cryptogram);
        }
        push_tlv(&mut objects, 0x99, status);
        let mac = self.mac(&objects);
        push_tlv(&mut objects, 0x8E, &mac);
        objects.extend_from_slice(&[0x90, 0x00]);
        objects
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut plain = cbc::Decryptor::<TdesEde2>::new(&self.kenc.into(), &[0; BLOCK].into())
            .decrypt_padded_vec::<NoPadding>(ciphertext)
            .ok()?;
        let end = plain.iter().rposition(|&byte| byte == 0x80)?;
        plain.truncate(end);
        Some(plain)
    }

    fn mac(&self, unpadded: &[u8]) -> [u8; 8] {
        RetailMac::<Des>::new(&self.kmac.into())
            .chain_update(self.ssc.to_be_bytes())
            .chain_update(pad(unpadded))
            .finalize()
            .into_bytes()
            .into()
    }
}

fn pad(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.push(0x80);
    padded.resize(padded.len().next_multiple_of(BLOCK), 0);
    padded
}

fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, len, rest) = match input {
        [tag, len @ 0..=0x7F, rest @ ..] | [tag, 0x81, len, rest @ ..] => {
            (*tag, usize::from(*len), rest)
        }
        _ => return None,
    };
    (rest.len() >= len).then(|| {
        let (value, rest) = rest.split_at(len);
        (tag, value, rest)
    })
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    let [high, low] = u16::try_from(value.len()).unwrap().to_be_bytes();
    out.push(tag);
    match value.len() {
        0..0x80 => out.push(low),
        0x80..=0xFF => out.extend([0x81, low]),
        _ => out.extend([0x82, high, low]),
    }
    out.extend_from_slice(value);
}
