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

use rsa::RsaPublicKey;

use crate::{
    Certificate, Error, Transport,
    atr::check_dnie_3,
    certificates,
    files::{self, Location},
    key_sets::ca_component_public_key,
    pin,
};

const IDESP: &[u8] = &[0x3F, 0x00, 0x00, 0x06];

/// Session with a DNIe 3.0/4.0 over any [`Transport`].
pub struct Session<T: Transport> {
    transport: T,
    /// Support number, which picks the channel key set; card data, so never logged.
    idesp: Option<String>,
    ca_key: RsaPublicKey,
}

impl<T: Transport> Session<T> {
    /// Resets the card, accepts it only if it is a DNIe 3.0/4.0 and reads its IDESP if it can.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transaction`], [`Transport::reset`], [`Error::NotDnie`],
    /// [`Error::LegacyDnie`] and [`Error::BurnedDnie`].
    pub fn open(transport: T) -> Result<Self, Error> {
        Self::open_trusting(transport, ca_component_public_key())
    }

    #[cfg(test)]
    pub(crate) fn open_with_ca_key(transport: T, ca_key: RsaPublicKey) -> Result<Self, Error> {
        Self::open_trusting(transport, ca_key)
    }

    fn open_trusting(mut transport: T, ca_key: RsaPublicKey) -> Result<Self, Error> {
        let idesp = transport.transaction(|card| {
            check_dnie_3(&card.reset()?)?;
            Ok(read_idesp(card))
        })?;
        Ok(Self {
            transport,
            idesp,
            ca_key,
        })
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

    /// Reads how many PIN attempts are left through the PIN channel, without sending a PIN.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::PinBlocked`], [`Error::SecureChannel`] if the mutual
    /// authentication fails and [`Error::Status`] if the card gives no retry count.
    pub fn pin_retries(&mut self) -> Result<u8, Error> {
        let idesp = self.idesp.as_deref();
        let ca_key = &self.ca_key;
        self.transport.transaction(|card| {
            check_dnie_3(&card.reset()?)?;
            pin::retries_left(card, idesp, ca_key)
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
pub(crate) mod tests {
    use super::Session;
    use crate::{
        Error, StatusWord,
        emulator::{DNIE_3_ATR, EmulatedDnie, TerminalKey, ca_public_key},
        key_sets::{KeySet, R1_PIN, R1_USER, R2_PIN, R2_USER},
    };

    pub(crate) fn card_accepting(key_sets: &[&KeySet]) -> EmulatedDnie {
        let terminals: Vec<TerminalKey> = key_sets
            .iter()
            .map(|keys| TerminalKey {
                chr: keys.terminal_chr,
                modulus: keys.modulus.to_vec(),
            })
            .collect();
        EmulatedDnie::new(&DNIE_3_ATR).with_secure_channel(&terminals)
    }

    pub(crate) fn card_with_channel() -> EmulatedDnie {
        card_accepting(&[&R1_PIN, &R1_USER, &R2_PIN, &R2_USER])
    }

    pub(crate) fn open(card: EmulatedDnie) -> Session<EmulatedDnie> {
        Session::open_with_ca_key(card, ca_public_key()).unwrap()
    }

    fn retries(card: EmulatedDnie) -> Result<u8, Error> {
        open(card).pin_retries()
    }

    #[test]
    fn reads_the_retries_left() {
        assert_eq!(retries(card_with_channel().with_pin_retries(2)).unwrap(), 2);
    }

    #[test]
    fn reports_a_blocked_pin() {
        assert!(matches!(
            retries(card_with_channel().with_pin_retries(0)),
            Err(Error::PinBlocked)
        ));
    }

    #[test]
    fn refuses_any_other_retries_status() {
        assert!(matches!(
            retries(card_with_channel().answering_retries_with(0x6982)),
            Err(Error::Status(StatusWord(0x6982)))
        ));
    }

    #[test]
    fn takes_first_generation_keys_below_bmp100001() {
        let card = card_accepting(&[&R1_PIN]).with_idesp(b"BMP100000");
        assert!(retries(card).is_ok());
    }

    #[test]
    fn takes_second_generation_keys_from_bmp100001() {
        let second = card_accepting(&[&R2_PIN]).with_idesp(b"BMP100001");
        let first = card_accepting(&[&R1_PIN]).with_idesp(b"BMP100001");
        assert!(retries(second).is_ok());
        assert!(retries(first).is_err());
    }

    #[test]
    fn takes_second_generation_keys_without_idesp() {
        assert!(retries(card_accepting(&[&R2_PIN])).is_ok());
    }

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

    #[test]
    fn reports_a_card_reset_mid_channel() {
        let card = card_with_channel().resetting_mid_channel();
        assert!(matches!(retries(card), Err(Error::CardReset)));
    }

    #[test]
    fn reports_the_channel_lost_on_6688() {
        let card = card_with_channel().losing_the_channel();
        assert!(matches!(retries(card), Err(Error::ChannelLost)));
    }

    #[test]
    fn reports_a_secure_channel_error_on_a_bad_response_mac() {
        let card = card_with_channel().corrupting_a_response_mac();
        assert!(matches!(retries(card), Err(Error::SecureChannel(_))));
    }

    #[test]
    fn starts_a_fresh_channel_after_each_failure() {
        let faulty = [
            card_with_channel().resetting_mid_channel(),
            card_with_channel().losing_the_channel(),
            card_with_channel().corrupting_a_response_mac(),
        ];
        for card in faulty {
            let mut session = Session::open(card.with_pin_retries(2)).unwrap();
            assert!(session.pin_retries().is_err());
            assert_eq!(session.pin_retries().unwrap(), 2);
        }
    }
}
