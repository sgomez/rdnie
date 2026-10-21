// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.dnie.DnieFactory (Tomás García-Merás)
// - es.gob.jmulticard.card.dnie.Dnie3Cwa14890Constants (Tomás García-Merás)
// - es.gob.jmulticard.card.cwa14890.Cwa14890PublicConstants (Tomás García-Merás)
// - es.gob.jmulticard.card.cwa14890.Cwa14890PrivateConstants (Tomás García-Merás)
// - es.gob.jmulticard.connection.cwa14890.ChannelType (Tomás García-Merás)
// rdnie takes the EUPL 1.1+ branch of the dual licence below.
// The `AC RAIZ COMPONENTES 2` modulus comes from OpenSC
// (https://github.com/OpenSC/OpenSC, commit fc27ee8, src/libopensc/cwa-dnie.c,
// `icc_root_ca_modulus_1`, LGPL 2.1+).
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

//! Terminal key sets of the CWA-14890 channels, picked by IDESP as `DnieFactory` does, and the
//! roots of the chip's component certificates.

use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, pkcs8::DecodePublicKey};

mod first_generation;
mod second_generation;

pub(crate) use first_generation::{R1_PIN, R1_USER};
pub(crate) use second_generation::{R2_PIN, R2_USER};

/// Support numbers from this one on take the second key generation.
const R2_IDESP: &str = "BMP100001";
const PUBLIC_EXPONENT: u32 = 65_537;

/// Root CA public key the card checks the CA CVC with.
pub(crate) const CA_PUBLIC_KEY_REFERENCE: [u8; 2] = [0x02, 0x0F];
/// ICC private key of the internal authentication.
pub(crate) const ICC_PRIVATE_KEY_REFERENCE: [u8; 2] = [0x02, 0x1F];

/// `pk-RCAicc` (RSA-1024 SPKI), the `AC RAIZ COMPONENTES` root, from `Dnie3Cwa14890Constants`.
const COMPONENT_ROOT: [u8; 162] = [
    0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x81, 0x8D, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xEA, 0xDE, 0xDA,
    0x45, 0x53, 0x32, 0x94, 0x50, 0x39, 0xDA, 0xA4, 0x04, 0xC8, 0xEB, 0xC4, 0xD3, 0xB7, 0xF5, 0xDC,
    0x86, 0x92, 0x83, 0xCD, 0xEA, 0x2F, 0x10, 0x1E, 0x2A, 0xB5, 0x4F, 0xB0, 0xD0, 0xB0, 0x3D, 0x8F,
    0x03, 0x0D, 0xAF, 0x24, 0x58, 0x02, 0x82, 0x88, 0xF5, 0x4C, 0xE5, 0x52, 0xF8, 0xFA, 0x57, 0xAB,
    0x2F, 0xB1, 0x03, 0xB1, 0x12, 0x42, 0x7E, 0x11, 0x13, 0x1D, 0x1D, 0x27, 0xE1, 0x0A, 0x5B, 0x50,
    0x0E, 0xAA, 0xE5, 0xD9, 0x40, 0x30, 0x1E, 0x30, 0xEB, 0x26, 0xC3, 0xE9, 0x06, 0x6B, 0x25, 0x71,
    0x56, 0xED, 0x63, 0x9D, 0x70, 0xCC, 0xC0, 0x90, 0xB8, 0x63, 0xAF, 0xBB, 0x3B, 0xFE, 0xD8, 0xC1,
    0x7B, 0xE7, 0x67, 0x30, 0x34, 0xB9, 0x82, 0x3E, 0x97, 0x7E, 0xD6, 0x57, 0x25, 0x29, 0x27, 0xF9,
    0x57, 0x5B, 0x9F, 0xFF, 0x66, 0x91, 0xDB, 0x64, 0xF8, 0x0B, 0x5E, 0x92, 0xCD, 0x02, 0x03, 0x01,
    0x00, 0x01,
];

/// Modulus of the `AC RAIZ COMPONENTES 2` root, `icc_root_ca_modulus_1` of `OpenSC`.
const COMPONENT_ROOT_2_MODULUS: [u8; 128] = [
    0xB9, 0x72, 0x34, 0x5E, 0x35, 0xBC, 0xDD, 0x12, 0xDC, 0x2C, 0x8E, 0x85, 0xF6, 0x22, 0x97, 0x97,
    0x9F, 0x12, 0x2B, 0xB7, 0xC9, 0xC3, 0xED, 0x13, 0xA0, 0xC4, 0xEB, 0x59, 0x34, 0xE7, 0x0C, 0xD6,
    0xD0, 0x0C, 0x54, 0x06, 0x18, 0x38, 0x6E, 0x42, 0xF2, 0xBA, 0x00, 0x89, 0xC0, 0xDD, 0x80, 0x0E,
    0xBA, 0x78, 0x3B, 0xDC, 0x9D, 0x93, 0xD9, 0xFB, 0xFC, 0x3C, 0x16, 0x9F, 0x9A, 0xF6, 0x4E, 0x80,
    0x10, 0x0F, 0xC6, 0x87, 0xCC, 0xA5, 0x62, 0xE7, 0xFC, 0x84, 0xD1, 0x12, 0x92, 0xC2, 0x40, 0x4C,
    0x59, 0xB8, 0xA8, 0x60, 0xD3, 0x9E, 0x2D, 0x66, 0x54, 0x7D, 0xC7, 0xB2, 0xD4, 0x8C, 0xA7, 0x89,
    0x81, 0x4F, 0x43, 0x06, 0x26, 0x34, 0xE3, 0xE0, 0xC0, 0xD6, 0xBF, 0x5F, 0x54, 0xBA, 0x1D, 0x9C,
    0x46, 0x64, 0x45, 0x83, 0x1D, 0xCD, 0xEA, 0xB0, 0x87, 0x08, 0xF3, 0xF6, 0x22, 0x0E, 0x07, 0x75,
];

/// Roots the chip's component certificate chain may end in.
#[derive(Clone)]
pub(crate) struct ComponentRoots {
    first: RsaPublicKey,
    second: RsaPublicKey,
}

impl ComponentRoots {
    /// `AC RAIZ COMPONENTES` and `AC RAIZ COMPONENTES 2`, both also in the DGP's libpkcs11-dnie 1.6.8.
    pub(crate) fn embedded() -> Self {
        Self {
            first: RsaPublicKey::from_public_key_der(&COMPONENT_ROOT)
                .expect("the embedded component root is valid"),
            second: RsaPublicKey::new(
                BigUint::from_bytes_be(&COMPONENT_ROOT_2_MODULUS),
                BigUint::from(PUBLIC_EXPONENT),
            )
            .expect("the embedded second component root is valid"),
        }
    }

    #[cfg(test)]
    pub(crate) fn only(root: RsaPublicKey) -> Self {
        Self::pair(root.clone(), root)
    }

    #[cfg(test)]
    pub(crate) fn pair(first: RsaPublicKey, second: RsaPublicKey) -> Self {
        Self { first, second }
    }

    /// The roots in the order to try them: `pk-RCAicc` first.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &RsaPublicKey> {
        [&self.first, &self.second].into_iter()
    }
}

/// Key generation the DGP issued the terminal keys in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyGeneration {
    /// Cards with a support number below `BMP100001`.
    First,
    /// Later cards, and any card whose support number is unknown.
    Second,
}

impl KeyGeneration {
    pub(crate) fn of_card(idesp: Option<&str>) -> Self {
        if idesp.is_some_and(|idesp| !idesp.is_empty() && idesp < R2_IDESP) {
            Self::First
        } else {
            Self::Second
        }
    }
}

/// Channel a key set opens.
#[derive(Clone, Copy)]
pub(crate) enum Channel {
    Pin,
    User,
}

/// Terminal side of one channel in one key generation.
pub(crate) struct KeySet {
    pub(crate) ca_cvc: &'static [u8],
    pub(crate) ca_chr: [u8; 8],
    pub(crate) terminal_cvc: &'static [u8],
    pub(crate) terminal_chr: [u8; 8],
    pub(crate) modulus: &'static [u8],
    private_exponent: &'static [u8],
}

impl KeySet {
    /// The set for `channel` on a card with `idesp`; the second generation if it is unknown.
    pub(crate) fn for_card(idesp: Option<&str>, channel: Channel) -> &'static Self {
        match (KeyGeneration::of_card(idesp), channel) {
            (KeyGeneration::First, Channel::Pin) => &R1_PIN,
            (KeyGeneration::First, Channel::User) => &R1_USER,
            (KeyGeneration::Second, Channel::Pin) => &R2_PIN,
            (KeyGeneration::Second, Channel::User) => &R2_USER,
        }
    }

    /// The terminal private key, with its primes recovered from the modulus and exponents.
    pub(crate) fn private_key(&self) -> RsaPrivateKey {
        RsaPrivateKey::from_components(
            BigUint::from_bytes_be(self.modulus),
            BigUint::from(PUBLIC_EXPONENT),
            BigUint::from_bytes_be(self.private_exponent),
            vec![],
        )
        .expect("embedded terminal keys are valid RSA keys")
    }
}

#[cfg(test)]
mod tests;
