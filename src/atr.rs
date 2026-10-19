// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.dnie.DnieFactory (Tomás García-Merás)
// - es.gob.jmulticard.card.dnie.DnieAtr (Tomás García-Merás)
// - es.gob.jmulticard.card.Atr (Tomás García-Merás)
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

//! DNIe detection and classification by ATR.

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

fn matches_mask(atr: &[u8]) -> bool {
    atr.len() == DNIE_ATR.len()
        && atr
            .iter()
            .zip(DNIE_ATR)
            .zip(DNIE_ATR_MASK)
            .all(|((byte, expected), mask)| byte & mask == expected & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNIE_3: [u8; 20] = [
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x10, 0x01, 0x01, 0x55,
        0x04, 0x21, 0x03, 0x90, 0x00,
    ];

    #[test]
    fn recognises_dnie_3() {
        assert!(is_dnie(&DNIE_3));
    }

    #[test]
    fn rejects_other_cards() {
        let yubikey = [
            0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73, 0xC0, 0x21, 0xC0,
            0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
        ];
        assert!(!is_dnie(&yubikey));
    }

    #[test]
    fn rejects_inverse_convention() {
        let mut atr = DNIE_3;
        atr[0] = 0x3F;
        assert!(!is_dnie(&atr));
    }
}
