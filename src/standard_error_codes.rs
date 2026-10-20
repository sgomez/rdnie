// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.apdu.StandardErrorCodes (Tomás García-Merás)
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
