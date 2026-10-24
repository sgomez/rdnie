// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.dnie.DnieFactory (Tomás García-Merás)
// - es.gob.jmulticard.card.dnie.Dnie3 (Tomás García-Merás)
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

//! The card authenticator: the card's key generation and the trusted component roots, which open
//! the PIN channel and the user channel as `Dnie3` does.

use crate::{
    Error, Transport, cwa14890, files,
    key_sets::{Channel, ComponentRoots, KeyGeneration, KeySet},
    secure_messaging::SecureChannel,
};

/// Support numbers from this one on take the second key generation.
const R2_IDESP: &str = "BMP100001";

/// Opens the CWA-14890 channels of one card with the key sets of its generation.
pub(crate) struct CardAuthenticator {
    generation: KeyGeneration,
    roots: ComponentRoots,
}

impl CardAuthenticator {
    /// Resolves the card's stored support number, as `DnieFactory` does; an empty or absent one
    /// takes the second generation.
    pub(crate) fn from_idesp(idesp: Option<&str>, roots: ComponentRoots) -> Self {
        let generation = if idesp.is_some_and(|idesp| !idesp.is_empty() && idesp < R2_IDESP) {
            KeyGeneration::First
        } else {
            KeyGeneration::Second
        };
        Self { generation, roots }
    }

    #[cfg(test)]
    pub(crate) fn new(generation: KeyGeneration, roots: ComponentRoots) -> Self {
        Self { generation, roots }
    }

    pub(crate) fn key_generation(&self) -> KeyGeneration {
        self.generation
    }

    /// Selects the master file, whose refusal `Dnie3` only warns about, then authenticates with
    /// the PIN keys.
    pub(crate) fn open_pin_channel<'a>(
        &self,
        card: &'a mut dyn Transport,
    ) -> Result<SecureChannel<'a>, Error> {
        match files::select_master_file(card) {
            Ok(()) | Err(Error::Status(_)) => {}
            Err(error) => return Err(error),
        }
        cwa14890::open(card, self.keys(Channel::Pin), &self.roots)
    }

    /// Selects the master file and authenticates with the user keys, all through `pin_channel`,
    /// as `Dnie3.openUserChannel` does, and drops `pin_channel`.
    pub(crate) fn open_user_channel<'a>(
        &self,
        mut pin_channel: SecureChannel<'a>,
    ) -> Result<SecureChannel<'a>, Error> {
        pin_channel
            .transmit(&files::master_file_selection())?
            .into_success()?;
        cwa14890::open_inside(pin_channel, self.keys(Channel::User), &self.roots)
    }

    fn keys(&self, channel: Channel) -> &'static KeySet {
        KeySet::for_generation(self.generation, channel)
    }
}

#[cfg(test)]
mod tests;
