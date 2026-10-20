// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.asn1.der.pkcs15.Cdf (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs15.PrKdf (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs15.Pkcs15Object (Gonzalo Henríquez Manzano)
// - es.gob.jmulticard.asn1.der.pkcs15.CertificateObject (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs15.PrivateKeyObject (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs15.CommonCertificateAttributes (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs15.CommonKeyAttributes (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs15.X509CertificateAttributes (Gonzalo Henríquez Manzano)
// - es.gob.jmulticard.asn1.der.pkcs15.PrivateRsaKeyAttributes (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.pkcs15.Path (Tomás García-Merás)
// - es.gob.jmulticard.asn1.der.Record (Tomás García-Merás)
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

//! PKCS#15 CDF and PrKDF: the identifier and path of each certificate or private key.

use der::{
    Decode, Reader, SliceReader, Tag, TagNumber, Tagged,
    asn1::{AnyRef, OctetStringRef},
};

use crate::Error;

/// Objects a directory file holds at most, as in JMulticard.
const MAX_OBJECTS: usize = 10;

const TYPE_ATTRIBUTES: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber::N1,
};

/// A certificate in the CDF or a private key in the PrKDF.
pub(crate) struct Entry {
    /// Label from the common object attributes, read for certificates only.
    pub(crate) label: String,
    /// Identifier that pairs a certificate with its key.
    pub(crate) id: Vec<u8>,
    /// File path, from the master file.
    pub(crate) path: Vec<u8>,
}

/// Decodes the objects of a CDF or PrKDF, which ends at the first byte that starts no SEQUENCE.
/// With `labelled`, each object must carry a UTF-8 label.
pub(crate) fn entries(file: &[u8], labelled: bool) -> Result<Vec<Entry>, Error> {
    let mut reader = SliceReader::new(file).map_err(malformed)?;
    let mut entries = Vec::new();
    while entries.len() < MAX_OBJECTS {
        match AnyRef::decode(&mut reader) {
            Ok(object) if object.tag() == Tag::Sequence => entries.push(entry(object, labelled)?),
            _ if entries.is_empty() => return Err(Error::MalformedPkcs15),
            _ => break,
        }
    }
    Ok(entries)
}

/// Both object types share the layout that matters: the identifier opens the class attributes,
/// and the path opens the type attributes.
fn entry(object: AnyRef<'_>, labelled: bool) -> Result<Entry, Error> {
    let attributes = children(object)?;
    let label = if labelled {
        label(attributes.first().ok_or(Error::MalformedPkcs15)?)?
    } else {
        String::new()
    };
    let class = attributes.get(1).ok_or(Error::MalformedPkcs15)?;
    let id = first(*class, Tag::Sequence, Tag::OctetString)?;
    let typed = attributes
        .iter()
        .skip(2)
        .find(|attribute| attribute.tag() == TYPE_ATTRIBUTES)
        .ok_or(Error::MalformedPkcs15)?;
    let type_attributes = first(*typed, TYPE_ATTRIBUTES, Tag::Sequence)?;
    let path = first(type_attributes, Tag::Sequence, Tag::Sequence)?;
    let path = first(path, Tag::Sequence, Tag::OctetString)?;
    Ok(Entry {
        label,
        id: octets(id)?,
        path: octets(path)?,
    })
}

/// The mandatory `UTF8String` that opens the common object attributes.
fn label(common: &AnyRef<'_>) -> Result<String, Error> {
    let label = first(*common, Tag::Sequence, Tag::Utf8String)?;
    String::from_utf8(label.value().to_vec()).map_err(|_| Error::MalformedPkcs15)
}

/// The first element of `parent`, checking both tags.
fn first(parent: AnyRef<'_>, parent_tag: Tag, tag: Tag) -> Result<AnyRef<'_>, Error> {
    if parent.tag() != parent_tag {
        return Err(Error::MalformedPkcs15);
    }
    match children(parent)?.first() {
        Some(child) if child.tag() == tag => Ok(*child),
        _ => Err(Error::MalformedPkcs15),
    }
}

fn children(parent: AnyRef<'_>) -> Result<Vec<AnyRef<'_>>, Error> {
    let mut reader = SliceReader::new(parent.value()).map_err(malformed)?;
    let mut children = Vec::new();
    while !reader.is_finished() {
        children.push(reader.decode().map_err(malformed)?);
    }
    Ok(children)
}

fn octets(any: AnyRef<'_>) -> Result<Vec<u8>, Error> {
    let octets = OctetStringRef::try_from(any).map_err(malformed)?;
    Ok(octets.as_bytes().to_vec())
}

#[allow(clippy::needless_pass_by_value)]
fn malformed(_: der::Error) -> Error {
    Error::MalformedPkcs15
}
