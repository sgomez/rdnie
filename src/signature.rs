// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.dnie.Dnie (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816four.MseSetComputationApduCommand (Tomás García-Merás)
// - es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand (Carlos Gamuci Millán, Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs1.DigestInfo (Tomás García-Merás)
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

//! Signing a caller's digest in the user channel, as `Dnie.signOperation` does.

use crate::{Command, Error, KeyReference, Transport, secure_messaging::SecureMessaging};

const SHA256_HEADER: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_HEADER: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_HEADER: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];
const PRIVATE_KEY_REFERENCE: u8 = 0x84;

/// Hash algorithm of the digest to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    fn digest_info_header(self) -> &'static [u8] {
        match self {
            Self::Sha256 => SHA256_HEADER,
            Self::Sha384 => SHA384_HEADER,
            Self::Sha512 => SHA512_HEADER,
        }
    }
}

/// The PKCS#1 `DigestInfo` of `digest`, if its length is the one `algorithm` produces.
pub(crate) fn digest_info(algorithm: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>, Error> {
    let header = algorithm.digest_info_header();
    let expected = usize::from(header[header.len() - 1]);
    if digest.len() != expected {
        return Err(Error::DigestLength {
            expected,
            actual: digest.len(),
        });
    }
    Ok([header, digest].concat())
}

/// Selects `key` with `MSE SET DST` and has the card sign `digest_info` with `PSO`.
pub(crate) fn sign(
    channel: &mut SecureMessaging,
    card: &mut dyn Transport,
    key: &KeyReference,
    digest_info: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let [high, low] = key.file;
    let template = vec![PRIVATE_KEY_REFERENCE, 0x02, high, low];
    send(channel, card, 0x22, 0x41, 0xB6, template)?;
    send(channel, card, 0x2A, 0x9E, 0x9A, digest_info)
}

fn send(
    channel: &mut SecureMessaging,
    card: &mut dyn Transport,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let command = Command {
        cla: 0x00,
        ins,
        p1,
        p2,
        data,
        le: None,
    };
    channel.transmit(card, &command)?.into_success()
}
