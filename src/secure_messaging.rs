//! CWA-14890 secure messaging of DNIe 3.0/4.0: session keys, command protection, response
//! unprotection as JMulticard's `ApduEncrypterDes.decryptResponseApdu`, and `6Cxx` resends,
//! at most 2 in a row.

// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.connection.AbstractApduEncrypter (Tomás García-Merás)
// - es.gob.jmulticard.connection.ApduEncrypterDes (Tomás García-Merás, Carlos Gamuci Millán)
// - es.gob.jmulticard.connection.ApduEncrypterDesMac8 (Tomás García-Merás Capote)
// - es.gob.jmulticard.connection.cwa14890.Cwa14890CipheredApdu (Carlos Gamuci, Alberto Martínez,
//   Tomás García-Merás)
// - es.gob.jmulticard.connection.cwa14890.Cwa14890OneV1Connection (Carlos Gamuci, Tomás García-Merás)
// - es.gob.jmulticard.connection.cwa14890.InvalidCryptographicChecksumException (Tomás García-Merás)
// - es.gob.jmulticard.connection.cwa14890.SecureChannelException (Carlos Gamuci Millán,
//   Tomás García-Merás)
// - es.gob.jmulticard.connection.LostChannelException (Tomás García-Merás)
// rdnie takes the EUPL 1.1+ branch of the dual licence below.
//
// Controlador Java de la Secretaria de Estado de Administraciones Publicas
// para el DNI electronico.
//
// El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
// que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
// para la realizacion de procesos de autenticacion, firma electronica y validacion
// de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
// el acceso a los certificados y claves del DNI electronico, asi como la realizacion
// de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
// sido disenado para su funcionamiento independiente del sistema operativo final.
//
// Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
// e Impulso de la Administracion Electronica
//
// Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
// o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
// licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
// en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
// su compatibilidad con otros componentes.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// Lesser GNU General Public License publicada por la Free Software Foundation,
// tanto en la version 2.1 de la Licencia, o en una version posterior.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// European Union Public License publicada por la Comision Europea,
// tanto en la version 1.1 de la Licencia, o en una version posterior.
//
// Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
//
// Deberia recibir una copia de la European Union Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
//
// Este programa es distribuido con la esperanza de que sea util, pero
// SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
// o idoneidad para un proposito particular.

use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit,
    block_padding::{Iso7816, NoPadding},
};
use des::{Des, TdesEde2};
use retail_mac::{KeyInit, Mac, RetailMac};
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::{Command, Error, Response, StatusWord, Transport, resend::Resends};

const BLOCK: usize = 8;
const PROTECTED_CLA: u8 = 0x0C;
const PADDING_INDICATOR: u8 = 0x01;
const TAG_CRYPTOGRAM: u8 = 0x87;
const TAG_LE: u8 = 0x97;
const TAG_STATUS: u8 = 0x99;
const TAG_MAC: u8 = 0x8E;
const CHANNEL_LOST: StatusWord = StatusWord(0x6688);

/// Session state of an open secure channel.
pub(crate) struct SecureMessaging {
    kenc: [u8; 16],
    kmac: [u8; 16],
    ssc: u64,
}

impl SecureMessaging {
    /// Derives `Kenc`, `Kmac` and the SSC from the mutual authentication material.
    pub(crate) fn derive(
        kicc: &[u8; 32],
        kifd: &[u8; 32],
        rnd_icc: [u8; 8],
        rnd_ifd: [u8; 8],
    ) -> Self {
        let mut k: [u8; 32] = std::array::from_fn(|i| kicc[i] ^ kifd[i]);
        let channel = Self {
            kenc: session_key(&k, 1),
            kmac: session_key(&k, 2),
            ssc: u64::from_be_bytes([
                rnd_icc[4], rnd_icc[5], rnd_icc[6], rnd_icc[7], rnd_ifd[4], rnd_ifd[5], rnd_ifd[6],
                rnd_ifd[7],
            ]),
        };
        k.zeroize();
        channel
    }

    /// Protects a command, incrementing the SSC first.
    pub(crate) fn protect(&mut self, command: &Command) -> Result<Command, Error> {
        if command.data.len() > usize::from(u8::MAX) {
            return Err(Error::CommandTooLong(command.data.len()));
        }
        self.ssc = self.ssc.wrapping_add(1);
        let cla = command.cla | PROTECTED_CLA;
        let mut body = Vec::new();
        if !command.data.is_empty() {
            let mut cryptogram = vec![PADDING_INDICATOR];
            cryptogram.extend(
                cbc::Encryptor::<TdesEde2>::new(&self.kenc.into(), &[0; BLOCK].into())
                    .encrypt_padded_vec::<Iso7816>(&command.data),
            );
            push_tlv(&mut body, TAG_CRYPTOGRAM, &cryptogram);
        }
        if let Some(le) = command.le {
            push_tlv(&mut body, TAG_LE, &[le.to_be_bytes()[1]]);
        }
        let mut authenticated = pad(&[cla, command.ins, command.p1, command.p2]);
        authenticated.extend_from_slice(&body);
        let mac = self.mac(&authenticated);
        push_tlv(&mut body, TAG_MAC, &mac);
        Ok(Command {
            cla,
            ins: command.ins,
            p1: command.p1,
            p2: command.p2,
            data: body,
            le: None,
        })
    }

    /// Checks and decrypts `[87] 99 8E` as JMulticard, incrementing the SSC first; bytes after `8E` are ignored.
    pub(crate) fn unprotect(&mut self, response: &Response) -> Result<Response, Error> {
        if response.status == CHANNEL_LOST {
            return Err(Error::ChannelLost);
        }
        self.ssc = self.ssc.wrapping_add(1);
        if !response.status.is_success() {
            return Ok(Response {
                data: Vec::new(),
                status: response.status,
            });
        }

        let objects = &response.data[..];
        let (mut tag, mut value, mut rest) = read_tlv(objects)?;
        let cryptogram = if tag == TAG_CRYPTOGRAM {
            let cryptogram = value;
            (tag, value, rest) = read_tlv(rest)?;
            Some(cryptogram)
        } else {
            None
        };
        let (TAG_STATUS, &[ref leading @ .., sw1, sw2]) = (tag, value) else {
            return Err(Error::SecureChannel("response has no status word object"));
        };
        let authenticated = &objects[..objects.len() - rest.len()];
        let (tag, mac, _) = read_tlv(rest)?;
        if tag != TAG_MAC {
            return Err(Error::SecureChannel("response has no mac object"));
        }
        self.verify_mac(authenticated, mac)?;

        let status = StatusWord(u16::from_be_bytes([sw1, sw2]));
        let mut data = match cryptogram {
            Some(cryptogram) => self.decrypt(cryptogram)?,
            None => Vec::new(),
        };
        data.extend_from_slice(leading);
        Ok(Response { data, status })
    }

    fn verify_mac(&self, authenticated: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.authenticator(authenticated)
            .verify_slice(mac)
            .map_err(|_| Error::SecureChannel("response mac mismatch"))
    }

    fn decrypt(&self, cryptogram: &[u8]) -> Result<Vec<u8>, Error> {
        let [_indicator, ciphertext @ ..] = cryptogram else {
            return Err(Error::SecureChannel(
                "cryptogram lacks its padding indicator",
            ));
        };
        let mut plain = cbc::Decryptor::<TdesEde2>::new(&self.kenc.into(), &[0; BLOCK].into())
            .decrypt_padded_vec::<NoPadding>(ciphertext)
            .map_err(|_| Error::SecureChannel("cryptogram is not block aligned"))?;
        plain.truncate(unpadded_len(&plain));
        Ok(plain)
    }

    fn mac(&self, unpadded: &[u8]) -> [u8; 8] {
        self.authenticator(unpadded).finalize().into_bytes().into()
    }

    /// Retail MAC over `SSC ‖ pad(data)`.
    fn authenticator(&self, unpadded: &[u8]) -> RetailMac<Des> {
        retail_mac(&self.kmac)
            .chain_update(self.ssc.to_be_bytes())
            .chain_update(pad(unpadded))
    }
}

#[cfg(any(test, fuzzing))]
impl SecureMessaging {
    /// A channel with fixed keys and SSC, shared by the fuzz targets and their seeds.
    pub(crate) fn fixed() -> Self {
        Self::derive(&[0x11; 32], &[0x22; 32], [0x33; 8], [0x44; 8])
    }

    /// The card's `[87] 99 8E 90 00` answer to the next command, with `plain` encrypted as is, so
    /// it must be block aligned and carry its own padding.
    pub(crate) fn protected_response(&self, plain: &[u8], status: StatusWord) -> Vec<u8> {
        let mut objects = Vec::new();
        if !plain.is_empty() {
            let mut cryptogram = vec![PADDING_INDICATOR];
            cryptogram.extend(
                cbc::Encryptor::<TdesEde2>::new(&self.kenc.into(), &[0; BLOCK].into())
                    .encrypt_padded_vec::<NoPadding>(plain),
            );
            push_tlv(&mut objects, TAG_CRYPTOGRAM, &cryptogram);
        }
        push_tlv(&mut objects, TAG_STATUS, &status.0.to_be_bytes());
        let card = Self {
            kenc: self.kenc,
            kmac: self.kmac,
            ssc: self.ssc.wrapping_add(1),
        };
        let mac = card.mac(&objects);
        push_tlv(&mut objects, TAG_MAC, &mac);
        objects.extend(StatusWord::SUCCESS.0.to_be_bytes());
        objects
    }
}

/// An open secure channel bound to the card it runs over: the only way protected commands are sent.
pub(crate) struct SecureChannel<'a> {
    state: SecureMessaging,
    card: &'a mut dyn Transport,
}

impl<'a> SecureChannel<'a> {
    pub(crate) fn new(state: SecureMessaging, card: &'a mut dyn Transport) -> Self {
        Self { state, card }
    }

    /// Negotiates a channel through this one with `handshake`, then binds it to the card beneath
    /// and drops this one.
    pub(crate) fn open_inside(
        mut self,
        handshake: impl FnOnce(&mut dyn Transport) -> Result<SecureMessaging, Error>,
    ) -> Result<Self, Error> {
        let state = handshake(&mut self)?;
        Ok(Self::new(state, self.card))
    }
}

impl Transport for SecureChannel<'_> {
    fn transmit_raw(&mut self, _apdu: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::Transport(
            "raw apdus cannot cross a secure channel".into(),
        ))
    }

    fn atr(&self) -> Result<Vec<u8>, Error> {
        self.card.atr()
    }

    fn reset(&mut self) -> Result<Vec<u8>, Error> {
        Err(Error::Transport(
            "a secure channel cannot reset the card".into(),
        ))
    }

    fn transaction<R>(
        &mut self,
        body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
    ) -> Result<R, Error> {
        body(self)
    }

    /// Protects `command` and returns the card's plain answer, resending it with the Le of a `6Cxx`
    /// at most 2 times in a row; past that, [`Error::Status`] with the last one.
    fn transmit(&mut self, command: &Command) -> Result<Response, Error> {
        let mut resends = Resends::default();
        loop {
            let protected = self.state.protect(resends.current(command))?;
            let response = self.state.unprotect(&self.card.transmit(&protected)?)?;
            if !Resends::is_wrong_length(response.status) {
                return Ok(response);
            }
            resends.resend_with_le(command, response.status)?;
        }
    }
}

fn retail_mac(key: &[u8; 16]) -> RetailMac<Des> {
    RetailMac::<Des>::new(&(*key).into())
}

/// ISO/IEC 7816-4 padding.
fn pad(data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.push(0x80);
    padded.resize(padded.len().next_multiple_of(BLOCK), 0);
    padded
}

/// Length without ISO/IEC 7816-4 padding; as upstream, data lacking it is kept whole.
fn unpadded_len(data: &[u8]) -> usize {
    match data.iter().rposition(|&byte| byte != 0) {
        Some(end) if data[end] == 0x80 => end,
        _ => data.len(),
    }
}

/// Splits a BER-TLV with a one-byte tag into tag, value and the bytes after it.
fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    const MALFORMED: Error = Error::SecureChannel("malformed response object");
    let (tag, len, rest) = match input {
        [tag, len @ 0..=0x7F, rest @ ..] | [tag, 0x81, len, rest @ ..] => {
            (*tag, usize::from(*len), rest)
        }
        [tag, 0x82, high, low, rest @ ..] => {
            (*tag, usize::from(u16::from_be_bytes([*high, *low])), rest)
        }
        _ => return Err(MALFORMED),
    };
    if rest.len() < len {
        return Err(MALFORMED);
    }
    let (value, rest) = rest.split_at(len);
    Ok((tag, value, rest))
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    let len = u16::try_from(value.len()).expect("short APDU values are below 64 KiB");
    let [high, low] = len.to_be_bytes();
    out.push(tag);
    match len {
        0..0x80 => out.push(low),
        0x80..=0xFF => out.extend([0x81, low]),
        _ => out.extend([0x82, high, low]),
    }
    out.extend_from_slice(value);
}

fn session_key(k: &[u8; 32], counter: u32) -> [u8; 16] {
    let mut digest: [u8; 20] = Sha1::new()
        .chain_update(k)
        .chain_update(counter.to_be_bytes())
        .finalize()
        .into();
    let mut key = [0; 16];
    key.copy_from_slice(&digest[..16]);
    digest.zeroize();
    key
}

impl Drop for SecureMessaging {
    fn drop(&mut self) {
        self.kenc.zeroize();
        self.kmac.zeroize();
    }
}

#[cfg(test)]
mod tests;
