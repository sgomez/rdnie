// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.card.dnie.DnieFactory (Tomás García-Merás)
// - es.gob.jmulticard.card.dnie.Dnie (Tomás García-Merás)
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

//! Session with a DNIe 3.0/4.0, opened as `DnieFactory.getDnie` and `Dnie3` do: reset, classify
//! the ATR, read the IDESP.

use crate::{
    Certificate, Error, Transport,
    atr::check_dnie_3,
    certificates,
    files::{self, Location},
};

const IDESP: &[u8] = &[0x3F, 0x00, 0x00, 0x06];

/// Session with a DNIe 3.0/4.0 over any [`Transport`].
pub struct Session<T: Transport> {
    transport: T,
    /// Support number, which picks the channel key set; card data, so never logged.
    #[allow(dead_code, reason = "the PIN channel reads it to pick its key set")]
    idesp: Option<String>,
}

impl<T: Transport> Session<T> {
    /// Resets the card, accepts it only if it is a DNIe 3.0/4.0 and reads its IDESP if it can.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transaction`], [`Transport::reset`], [`Error::NotDnie`],
    /// [`Error::LegacyDnie`] and [`Error::BurnedDnie`].
    pub fn open(mut transport: T) -> Result<Self, Error> {
        let idesp = transport.transaction(|card| {
            check_dnie_3(&card.reset()?)?;
            Ok(read_idesp(card))
        })?;
        Ok(Self { transport, idesp })
    }

    /// Lists the holder's certificates that have a private key, without a PIN.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::Status`] if a file cannot be read and
    /// [`Error::MalformedPkcs15`].
    pub fn certificates(&mut self) -> Result<Vec<Certificate>, Error> {
        self.transport.transaction(|card| {
            check_dnie_3(&card.reset()?)?;
            certificates::load(card)
        })
    }

    /// Ends the session and hands back the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// The IDESP in clear, or `None` if the card does not give it, as `Dnie3` leaves it.
fn read_idesp(card: &mut dyn Transport) -> Option<String> {
    let location = Location::new(IDESP)?;
    let idesp = files::read(card, &location).ok()?;
    (!idesp.is_empty()).then(|| String::from_utf8_lossy(&idesp).into_owned())
}

#[cfg(test)]
mod tests {
    use super::Session;
    use crate::emulator::{DNIE_3_ATR, EmulatedDnie};

    #[test]
    fn keeps_the_idesp() {
        let card = EmulatedDnie::new(&DNIE_3_ATR).with_idesp(b"TST000042");
        let session = Session::open(card).unwrap();
        assert_eq!(session.idesp.as_deref(), Some("TST000042"));
    }

    #[test]
    fn opens_without_idesp() {
        let session = Session::open(EmulatedDnie::new(&DNIE_3_ATR)).unwrap();
        assert_eq!(session.idesp, None);
    }
}
