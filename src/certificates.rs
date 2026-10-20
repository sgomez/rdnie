// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.dnie.Dnie (Tomás García-Merás)
// - es.gob.jmulticard.card.CompressionUtils (Tomás García-Merás)
// - es.gob.jmulticard.card.dnie.DniePrivateKeyReference (Tomás García-Merás)
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

//! The holder's certificates and the keys they pair with, loaded as `Dnie.loadCertificates` does.

use std::fmt;

use flate2::{Decompress, FlushDecompress, Status};

use crate::{
    Error, Transport,
    files::{self, Location},
    pkcs15,
};

const CDF: &[u8] = &[0x50, 0x15, 0x60, 0x04];
const PRKDF: &[u8] = &[0x50, 0x15, 0x60, 0x01];
/// Bytes before the zlib stream of a compressed certificate.
const COMPRESSION_HEADER: usize = 8;

/// Certificate of the holder, paired with its private key on the card.
pub struct Certificate {
    /// X.509 certificate in DER.
    pub der: Vec<u8>,
    /// Private key that matches the certificate.
    pub key: KeyReference,
}

/// Private key on the card, as the PrKDF describes it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyReference {
    pub(crate) id: Vec<u8>,
    pub(crate) file: [u8; 2],
}

// Card data stays out of logs.
impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate").finish_non_exhaustive()
    }
}

impl fmt::Debug for KeyReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyReference").finish_non_exhaustive()
    }
}

/// Reads the CDF, each certificate it lists and the PrKDF, and keeps the certificates with a key.
pub(crate) fn load(card: &mut dyn Transport) -> Result<Vec<Certificate>, Error> {
    let listed = pkcs15::entries(&files::read(card, &location(CDF)?)?)?;
    let mut ders = Vec::with_capacity(listed.len());
    for entry in &listed {
        ders.push(decompressed(files::read(card, &location(&entry.path)?)?));
    }
    let keys = pkcs15::entries(&files::read(card, &location(PRKDF)?)?)?;
    let mut certificates = Vec::new();
    for (entry, der) in listed.into_iter().zip(ders) {
        let Some(key) = keys.iter().find(|key| key.id == entry.id) else {
            continue;
        };
        let file = location(&key.path)?
            .last_file()
            .ok_or(Error::MalformedPkcs15)?;
        certificates.push(Certificate {
            der,
            key: KeyReference { id: entry.id, file },
        });
    }
    Ok(certificates)
}

fn location(path: &[u8]) -> Result<Location, Error> {
    Location::new(path).ok_or(Error::MalformedPkcs15)
}

/// The certificate inflated, or as stored if it does not inflate.
fn decompressed(stored: Vec<u8>) -> Vec<u8> {
    inflate(&stored).unwrap_or(stored)
}

fn inflate(stored: &[u8]) -> Option<Vec<u8>> {
    let stream = stored.get(COMPRESSION_HEADER..)?;
    let mut inflater = Decompress::new(true);
    let mut der = Vec::new();
    loop {
        der.reserve(1024);
        let consumed = usize::try_from(inflater.total_in()).ok()?;
        let produced = inflater.total_out();
        let status = inflater
            .decompress_vec(&stream[consumed..], &mut der, FlushDecompress::None)
            .ok()?;
        if status == Status::StreamEnd {
            return Some(der);
        }
        if inflater.total_out() == produced {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Session,
        emulator::{DNIE_3_ATR, EmulatedDnie, HolderCertificate},
    };

    #[test]
    fn pairs_each_certificate_with_the_file_of_its_key() {
        let certificates = [
            HolderCertificate::new(1, 120),
            HolderCertificate::new(2, 120),
        ];
        let card = EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&certificates);
        let listed = Session::open(card).unwrap().certificates().unwrap();
        let files: Vec<[u8; 2]> = listed.iter().map(|c| c.key.file).collect();
        let expected: Vec<[u8; 2]> = certificates.iter().filter_map(|c| c.key_file).collect();
        assert_eq!(files, expected);
    }
}
