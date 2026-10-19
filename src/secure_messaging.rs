//! CWA-14890 secure messaging of DNIe 3.0/4.0: session keys, command protection and response unprotection.

// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// es.gob.jmulticard.connection.AbstractApduEncrypter, ApduEncrypterDes, ApduEncrypterDesMac8
// (Tomás García-Merás, Carlos Gamuci Millán), connection.cwa14890.Cwa14890CipheredApdu
// (Carlos Gamuci, Alberto Martínez, Tomás García-Merás) and connection.cwa14890.Cwa14890OneV1Connection
// (Carlos Gamuci, Tomás García-Merás). Original header:
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

use crate::{Command, Error, Response, StatusWord, Transport};

const BLOCK: usize = 8;
const PROTECTED_CLA: u8 = 0x0C;
const PADDING_INDICATOR: u8 = 0x01;
const TAG_CRYPTOGRAM: u8 = 0x87;
const TAG_LE: u8 = 0x97;
const TAG_STATUS: u8 = 0x99;
const TAG_MAC: u8 = 0x8E;
const CHANNEL_LOST: StatusWord = StatusWord(0x6688);
const WRONG_LE: u8 = 0x6C;

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

    /// Sends a command through the channel and returns the card's plain answer.
    pub(crate) fn transmit<T: Transport + ?Sized>(
        &mut self,
        transport: &mut T,
        command: &Command,
    ) -> Result<Response, Error> {
        let protected = self.protect(command)?;
        let response = self.unprotect(&transport.transmit(&protected)?)?;
        match response.status.0.to_be_bytes() {
            [WRONG_LE, le] => self.transmit(
                transport,
                &Command {
                    le: Some(le.into()),
                    ..command.clone()
                },
            ),
            _ => Ok(response),
        }
    }

    /// Checks and decrypts a response, incrementing the SSC first.
    pub(crate) fn unprotect(&mut self, response: &Response) -> Result<Response, Error> {
        if response.status == CHANNEL_LOST {
            return Err(Error::ChannelLost);
        }
        self.ssc = self.ssc.wrapping_add(1);
        if !response.status.is_success() {
            return Ok(response.clone());
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
        let (TAG_STATUS, &[sw1, sw2]) = (tag, value) else {
            return Err(Error::SecureChannel("response has no status word object"));
        };
        let authenticated = &objects[..objects.len() - rest.len()];
        let (tag, mac, rest) = read_tlv(rest)?;
        if tag != TAG_MAC || !rest.is_empty() {
            return Err(Error::SecureChannel("response has no trailing mac object"));
        }
        self.verify_mac(authenticated, mac)?;

        let data = match cryptogram {
            Some(cryptogram) => self.decrypt(cryptogram)?,
            None => Vec::new(),
        };
        Ok(Response {
            data,
            status: StatusWord(u16::from_be_bytes([sw1, sw2])),
        })
    }

    fn verify_mac(&self, authenticated: &[u8], mac: &[u8]) -> Result<(), Error> {
        self.authenticator(authenticated)
            .verify_slice(mac)
            .map_err(|_| Error::SecureChannel("response mac mismatch"))
    }

    fn decrypt(&self, cryptogram: &[u8]) -> Result<Vec<u8>, Error> {
        let [PADDING_INDICATOR, ciphertext @ ..] = cryptogram else {
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
mod tests {
    use super::*;

    // Expected values computed with OpenSSL, independently of this module.
    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn array<const N: usize>(text: &str) -> [u8; N] {
        hex(text).try_into().unwrap()
    }

    #[test]
    fn derives_session_keys_and_ssc() {
        let kicc: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
        let kifd: [u8; 32] = std::array::from_fn(|i| u8::try_from((0x5A + 7 * i) % 256).unwrap());
        let channel = SecureMessaging::derive(
            &kicc,
            &kifd,
            array("11 22 33 44 55 66 77 88"),
            array("99 AA BB CC DD EE FF 00"),
        );
        assert_eq!(
            channel.kenc,
            array::<16>("22181f6f645783ce10463d5f7aa9c7cb")
        );
        assert_eq!(
            channel.kmac,
            array::<16>("ae823ff63e29f830a0525dcf97138c58")
        );
        assert_eq!(channel.ssc, 0x5566_7788_DDEE_FF00);
    }

    // ISO/IEC 9797-1 Annex B, MAC algorithm 3 with padding method 1.
    #[test]
    fn retail_mac_matches_iso_9797_example() {
        assert_eq!(
            retail_mac(&array("0123456789ABCDEF FEDCBA9876543210"))
                .chain_update(b"Now is the time for all ")
                .finalize()
                .into_bytes()[..],
            hex("A1C72E74EA3FA9B6")
        );
    }

    // Session keys and SSC from JMulticard's TestApduEncrypter; the SSC there is the
    // already incremented one.
    fn jmulticard_session() -> SecureMessaging {
        SecureMessaging {
            kenc: array("598f26e36e11a8ec14b81e19bda223ca"),
            kmac: array("5de2939a1ea03a930b88206d8f73e8a7"),
            ssc: 0xd31a_c8ec_7ba0_fe74,
        }
    }

    // JMulticard's vectors keep a 4-byte MAC; DNIe 3.0/4.0 sends all 8, whose first four match.
    #[test]
    fn protects_select_by_name() {
        let protected = jmulticard_session()
            .protect(&Command {
                cla: 0x00,
                ins: 0xA4,
                p1: 0x04,
                p2: 0x00,
                data: b"Master.File".to_vec(),
                le: None,
            })
            .unwrap();
        assert_eq!(
            protected.to_bytes().unwrap(),
            hex("0ca404001d 871101 3e9ac315a8e855dd3722f291078ac2bd 8e08 b6f56963ca2b8632")
        );
    }

    #[test]
    fn protects_verify() {
        let mut channel = jmulticard_session();
        channel.ssc = 0xd31a_c8ec_7ba0_fe6e;
        let protected = channel
            .protect(&Command {
                cla: 0x00,
                ins: 0x20,
                p1: 0x00,
                p2: 0x00,
                data: b"CRYPTOKI".to_vec(),
                le: None,
            })
            .unwrap();
        assert_eq!(
            protected.to_bytes().unwrap(),
            hex("0c2000001d 871101 ce1ab937c332f3faee43336d4311ef33 8e08 6908df4e6eb3ceae")
        );
    }

    #[test]
    fn protects_le_without_outer_le() {
        let protected = jmulticard_session()
            .protect(&Command {
                cla: 0x00,
                ins: 0x84,
                p1: 0x00,
                p2: 0x00,
                data: vec![],
                le: Some(8),
            })
            .unwrap();
        assert_eq!(
            protected.to_bytes().unwrap(),
            hex("0c8400000d 970108 8e08 514f434b4e88a669")
        );
    }

    fn select(data: Vec<u8>) -> Command {
        Command {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data,
            le: None,
        }
    }

    #[test]
    fn encodes_long_cryptogram_with_ber_length() {
        let protected = jmulticard_session().protect(&select(vec![0; 130])).unwrap();
        assert_eq!(protected.data[..4], [0x87, 0x81, 0x89, 0x01]);
    }

    // Same session, after a protected command: the response is checked with SSC ...fe76.
    fn answered_session() -> SecureMessaging {
        let mut channel = jmulticard_session();
        channel.ssc += 1;
        channel
    }

    fn protected_response(raw: &str) -> Response {
        Response::parse(&hex(raw)).unwrap()
    }

    const SHORT_RESPONSE: &str = "871901 065563852c30f15cf75a2ac2480a9cb05b1a590c9120a406 99029000 \
                                  8e08 e21d201538257ab2 9000";

    #[test]
    fn unprotects_response_data() {
        let response = answered_session()
            .unprotect(&protected_response(SHORT_RESPONSE))
            .unwrap();
        assert_eq!(response.data, (1..=20).collect::<Vec<u8>>());
        assert_eq!(response.status, StatusWord::SUCCESS);
    }

    #[test]
    fn takes_status_from_inner_status_word() {
        let response = answered_session()
            .unprotect(&protected_response("990263c3 8e08 0515cae12cef8ff4 9000"))
            .unwrap();
        assert_eq!(response.data, []);
        assert_eq!(response.status, StatusWord(0x63C3));
    }

    #[test]
    fn unprotects_response_over_255_bytes() {
        let response = answered_session()
            .unprotect(&protected_response(
                "87820109017a49d26c2d17b79354b22ac4f004e790052c75b823269f8712819bf82c06ee567ebf42933b4a24c8e72aaa
                 571197ec049f2d0665acfaf7064a3699a45b2ba596cbb63b0a2a6af6f73021737df2471546ae4817c4634bac26a27f89
                 076572f4fdd8192d9a4548b918f3d70a9110c447e64e2f3db5fdc94acbbb7dc5d595ac053b4374e796d92e61243c08bf
                 712e39a4ea0294813ca15e4cef88bc6d0a6c38f4bb305a823c20f58ea26ce87f2a84ebcdbdb8234ce8f1068ea5c0749c
                 c028346c6e6f247edb4cda063da3a5f6377635f85e46da8272bcbdc46b8f63b6d676ec0b7d18dc27ebfa77cf7ea48604
                 48b9fad8a90ee4ca97dcd5ca6555614753262b7be1d0bef6514d89e5d299029000
                 8e08 048437e730b8db6a 9000",
            ))
            .unwrap();
        assert_eq!(response.data, (0..=255).collect::<Vec<u8>>());
    }

    #[test]
    fn rejects_wrong_mac() {
        let tampered = SHORT_RESPONSE.replace("e21d201538257ab2", "e21d201538257ab3");
        assert!(matches!(
            answered_session().unprotect(&protected_response(&tampered)),
            Err(Error::SecureChannel(_))
        ));
    }

    #[test]
    fn rejects_response_checked_with_another_ssc() {
        assert!(matches!(
            jmulticard_session().unprotect(&protected_response(SHORT_RESPONSE)),
            Err(Error::SecureChannel(_))
        ));
    }

    #[test]
    fn rejects_response_without_mac() {
        assert!(matches!(
            answered_session().unprotect(&protected_response("99029000 9000")),
            Err(Error::SecureChannel(_))
        ));
    }

    #[test]
    fn rejects_response_with_truncated_tlv() {
        assert!(matches!(
            answered_session().unprotect(&protected_response("871901 0655 9000")),
            Err(Error::SecureChannel(_))
        ));
    }

    #[test]
    fn returns_plain_error_status_as_is() {
        let mut channel = answered_session();
        let response = channel.unprotect(&protected_response("6982")).unwrap();
        assert_eq!(response.status, StatusWord(0x6982));
        assert_eq!(channel.ssc, 0xd31a_c8ec_7ba0_fe76);
    }

    #[test]
    fn reports_channel_lost_on_6688() {
        assert!(matches!(
            answered_session().unprotect(&protected_response("6688")),
            Err(Error::ChannelLost)
        ));
    }

    struct ScriptedCard {
        responses: Vec<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Transport for ScriptedCard {
        fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
            self.sent.push(apdu.to_vec());
            Ok(self.responses.remove(0))
        }
    }

    #[test]
    fn resends_with_le_from_inner_6cxx() {
        let mut card = ScriptedCard {
            responses: vec![
                hex("99026c10 8e08 ef3d270b01ac5e01 9000"),
                hex("99029000 8e08 d22b55897ca31887 9000"),
            ],
            sent: vec![],
        };
        let response = jmulticard_session()
            .transmit(&mut card, &select(b"Master.File".to_vec()))
            .unwrap();
        assert_eq!(response.status, StatusWord::SUCCESS);
        assert!(card.sent[1].windows(3).any(|tlv| tlv == [0x97, 0x01, 0x10]));
    }

    #[test]
    fn refuses_data_beyond_short_apdu() {
        assert!(matches!(
            jmulticard_session().protect(&select(vec![0; 256])),
            Err(Error::CommandTooLong(256))
        ));
    }
}
