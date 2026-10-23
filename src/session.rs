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

//! Session with a DNIe 3.0/4.0, opened as `DnieFactory.getDnie` and `Dnie3` do, minus the reset:
//! classify the ATR, read the IDESP.

use crate::{
    Certificate, Error, HashAlgorithm, KeyReference, Pin, Transport,
    atr::check_dnie_3,
    certificates,
    files::{self, Location},
    key_sets::{ComponentRoots, KeyGeneration},
    pin, signature,
};

const IDESP: &[u8] = &[0x3F, 0x00, 0x00, 0x06];

/// Session with a DNIe 3.0/4.0 over any [`Transport`].
///
/// [`Error::CardRemoved`] reaches the caller unchanged from every operation, and no PIN is sent
/// after it. The session does not recover: open a new transport and a new session.
pub struct Session<T: Transport> {
    transport: T,
    /// Support number, which picks the channel key set; card data, so never logged.
    idesp: Option<String>,
    roots: ComponentRoots,
    /// The count [`Session::pin_retries`] last showed, which the next sign expects.
    shown_retries: Option<u8>,
    /// Every CDF certificate, loaded on the first request and kept for the session.
    loaded: Option<Vec<certificates::Loaded>>,
}

impl<T: Transport> Session<T> {
    /// Accepts the card only if its current ATR is a DNIe 3.0/4.0 and reads its IDESP if it can,
    /// without resetting it.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transaction`], [`Transport::atr`], [`Error::NotDnie`],
    /// [`Error::LegacyDnie`] and [`Error::BurnedDnie`].
    pub fn open(transport: T) -> Result<Self, Error> {
        Self::open_with(transport, ComponentRoots::embedded())
    }

    /// [`Session::open`] trusting only `root` as the component root, for tests against an emulated
    /// card.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`].
    #[cfg(feature = "emulator")]
    pub fn open_trusting(transport: T, root: rsa::RsaPublicKey) -> Result<Self, Error> {
        Self::open_with(transport, ComponentRoots::only(root))
    }

    #[cfg(test)]
    pub(crate) fn open_with_roots(transport: T, roots: ComponentRoots) -> Result<Self, Error> {
        Self::open_with(transport, roots)
    }

    fn open_with(mut transport: T, roots: ComponentRoots) -> Result<Self, Error> {
        check_dnie_3(&transport.atr()?)?;
        let idesp = transport.transaction(|card| Ok(read_idesp(card)))?;
        Ok(Self {
            transport,
            idesp,
            roots,
            shown_retries: None,
            loaded: None,
        })
    }

    /// Lists the holder's certificates that have a private key, each with its PKCS#15 label,
    /// without a PIN. The first call loads every CDF certificate from the card and the session
    /// keeps them, so later calls send nothing; a failed load keeps nothing.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::Status`] if a file cannot be read and
    /// [`Error::MalformedPkcs15`] if a directory cannot be decoded, a certificate has no file in
    /// its path, no UTF-8 label, or its bytes are not an X.509 certificate.
    pub fn certificates(&mut self) -> Result<Vec<Certificate>, Error> {
        Ok(self
            .loaded()?
            .iter()
            .filter_map(certificates::Loaded::keyed)
            .collect())
    }

    /// Fetches the DER of the CDF certificate labelled `label`, with or without a private key,
    /// from the certificates [`Session::certificates`] shares. `None` if no certificate has that
    /// label; with duplicates the last one in the CDF wins.
    ///
    /// # Errors
    ///
    /// Those of [`Session::certificates`].
    pub fn certificate(&mut self, label: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .loaded()?
            .iter()
            .rev()
            .find(|loaded| loaded.label == label)
            .map(|loaded| loaded.der.clone()))
    }

    fn loaded(&mut self) -> Result<&[certificates::Loaded], Error> {
        if self.loaded.is_none() {
            self.loaded = Some(operation(&mut self.transport, certificates::load)?);
        }
        Ok(self.loaded.as_deref().unwrap_or_default())
    }

    /// Reads how many PIN attempts are left through the PIN channel, without sending a PIN.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::PinBlocked`], [`Error::SecureChannel`] if the card
    /// refuses a step of the mutual authentication up to `EXTERNAL AUTHENTICATE` or fails it,
    /// [`Error::Status`] if the card refuses `INTERNAL AUTHENTICATE`, `GET CHALLENGE` or
    /// `GET CHIP INFO` or gives no retry count, and [`Error::CardReset`] or [`Error::Transport`]
    /// if either strikes during the authentication.
    pub fn pin_retries(&mut self) -> Result<u8, Error> {
        let idesp = self.idesp.as_deref();
        let roots = &self.roots;
        let retries = operation(&mut self.transport, |card| {
            pin::retries_left(card, idesp, roots)
        })?;
        self.shown_retries = Some(retries);
        Ok(retries)
    }

    /// Signs a SHA-256/384/512 digest with `key` after verifying `pin`, and returns the PKCS#1
    /// v1.5 signature; the retries must still be those [`Session::pin_retries`] last showed.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPinFormat`] and [`Error::DigestLength`] before touching the card, those of
    /// [`Session::pin_retries`], [`Error::PinRetriesChanged`] if the retries moved between the two
    /// phases, [`Error::WrongPin`] after the single attempt and [`Error::Status`] if the card
    /// refuses the signature. The channel errors are those of [`Session::pin_retries`].
    pub fn sign(
        &mut self,
        digest: &[u8],
        algorithm: HashAlgorithm,
        key: &KeyReference,
        pin: Pin,
    ) -> Result<Vec<u8>, Error> {
        pin.check_format()?;
        let digest_info = signature::digest_info(algorithm, digest)?;
        let retries = match self.shown_retries.take() {
            Some(shown) => shown,
            None => self.pin_retries()?,
        };
        self.shown_retries = None;
        if retries == 0 {
            return Err(Error::PinBlocked);
        }
        let idesp = self.idesp.as_deref();
        let roots = &self.roots;
        operation(&mut self.transport, |card| {
            let mut channel = pin::verify(card, idesp, roots, pin, retries)?;
            signature::sign(&mut channel, card, key, digest_info)
        })
    }

    /// The terminal key generation the card's support number selects.
    #[must_use]
    pub fn key_generation(&self) -> KeyGeneration {
        KeyGeneration::of_card(self.idesp.as_deref())
    }

    /// Ends the session and hands back the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// Runs `body` in one transaction; like `Dnie3`, each operation opens its own channel.
fn operation<R>(
    transport: &mut impl Transport,
    body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
) -> Result<R, Error> {
    transport.transaction(body)
}

/// The IDESP in clear, or `None` if the card does not give it, as `Dnie3` leaves it.
fn read_idesp(card: &mut dyn Transport) -> Option<String> {
    let location = Location::new(IDESP)?;
    let idesp = files::read(card, &location).ok()?;
    (!idesp.is_empty()).then(|| String::from_utf8_lossy(&idesp).into_owned())
}

#[cfg(test)]
pub(crate) mod tests;
