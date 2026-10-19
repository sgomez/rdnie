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
    Certificate, Error, HashAlgorithm, KeyReference, Pin, Transport,
    atr::check_dnie_3,
    certificates,
    files::{self, Location},
    pin, signature,
};

const IDESP: &[u8] = &[0x3F, 0x00, 0x00, 0x06];

/// Session with a DNIe 3.0/4.0 over any [`Transport`].
pub struct Session<T: Transport> {
    transport: T,
    /// Support number, which picks the channel key set; card data, so never logged.
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
        operation(&mut self.transport, certificates::load)
    }

    /// Reads how many PIN attempts are left through the PIN channel, without sending a PIN.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::PinBlocked`], [`Error::SecureChannel`] if the mutual
    /// authentication fails and [`Error::Status`] if the card gives no retry count.
    pub fn pin_retries(&mut self) -> Result<u8, Error> {
        let idesp = self.idesp.as_deref();
        operation(&mut self.transport, |card| pin::retries_left(card, idesp))
    }

    /// Signs a SHA-256/384/512 digest with `key` after verifying `pin`, and returns the PKCS#1
    /// v1.5 signature.
    ///
    /// # Errors
    ///
    /// [`Error::DigestLength`] before touching the card, those of [`Session::pin_retries`] and
    /// [`Error::Status`] if the card refuses the PIN or the signature.
    pub fn sign(
        &mut self,
        digest: &[u8],
        algorithm: HashAlgorithm,
        key: &KeyReference,
        pin: Pin,
    ) -> Result<Vec<u8>, Error> {
        let digest_info = signature::digest_info(algorithm, digest)?;
        self.pin_retries()?;
        let idesp = self.idesp.as_deref();
        operation(&mut self.transport, |card| {
            let mut channel = pin::verify(card, idesp, pin)?;
            signature::sign(&mut channel, card, key, digest_info)
        })
    }

    /// Ends the session and hands back the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// Runs `body` in one transaction between a reset that checks the card and a reset that drops
/// any state it built, the verified PIN included.
fn operation<R>(
    transport: &mut impl Transport,
    body: impl FnOnce(&mut dyn Transport) -> Result<R, Error>,
) -> Result<R, Error> {
    transport.transaction(|card| {
        check_dnie_3(&card.reset()?)?;
        let result = body(card);
        let reset = card.reset();
        let value = result?;
        reset?;
        Ok(value)
    })
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
    use rsa::{
        Pkcs1v15Sign, RsaPublicKey,
        pkcs8::DecodePublicKey,
        sha2::{Digest, Sha256, Sha384, Sha512},
    };
    use x509_cert::der::{Decode, Encode};

    use crate::{
        Error, HashAlgorithm, Pin, StatusWord,
        emulator::{DEFAULT_PIN, DNIE_3_ATR, EmulatedDnie, HolderCertificate, TerminalKey},
        key_sets::{KeySet, R1_PIN, R1_USER, R2_PIN, R2_USER},
    };

    pub(crate) fn card_accepting(key_sets: &[&KeySet]) -> EmulatedDnie {
        let terminals: Vec<TerminalKey> = key_sets
            .iter()
            .map(|keys| TerminalKey {
                chr: keys.terminal_chr,
                modulus: keys.modulus.to_vec(),
                user: [&R1_USER, &R2_USER]
                    .iter()
                    .any(|user| std::ptr::eq(*user, *keys)),
            })
            .collect();
        EmulatedDnie::new(&DNIE_3_ATR).with_secure_channel(&terminals)
    }

    pub(crate) fn card_with_channel() -> EmulatedDnie {
        card_accepting(&[&R1_PIN, &R1_USER, &R2_PIN, &R2_USER])
    }

    fn retries(card: EmulatedDnie) -> Result<u8, Error> {
        Session::open(card).unwrap().pin_retries()
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

    fn signing_card() -> EmulatedDnie {
        card_with_channel().with_certificates(&[HolderCertificate::signing(1)])
    }

    fn sign_with(
        session: &mut Session<EmulatedDnie>,
        digest: &[u8],
        algorithm: HashAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let key = session.certificates().unwrap().remove(0).key;
        session.sign(digest, algorithm, &key, Pin::new(DEFAULT_PIN.to_owned()))
    }

    fn verify(certificate: &[u8], scheme: Pkcs1v15Sign, digest: &[u8], signature: &[u8]) {
        let certificate = x509_cert::Certificate::from_der(certificate).unwrap();
        let spki = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        RsaPublicKey::from_public_key_der(&spki)
            .unwrap()
            .verify(scheme, digest, signature)
            .expect("the signature verifies with the certificate's public key");
    }

    #[test]
    fn signs_digests_that_verify_with_the_certificate() {
        let data = b"document";
        let cases = [
            (
                HashAlgorithm::Sha256,
                Pkcs1v15Sign::new::<Sha256>(),
                Sha256::digest(data).to_vec(),
            ),
            (
                HashAlgorithm::Sha384,
                Pkcs1v15Sign::new::<Sha384>(),
                Sha384::digest(data).to_vec(),
            ),
            (
                HashAlgorithm::Sha512,
                Pkcs1v15Sign::new::<Sha512>(),
                Sha512::digest(data).to_vec(),
            ),
        ];
        let mut session = Session::open(signing_card()).unwrap();
        let certificate = session.certificates().unwrap().remove(0).der;
        for (algorithm, scheme, digest) in cases {
            let signature = sign_with(&mut session, &digest, algorithm).unwrap();
            verify(&certificate, scheme, &digest, &signature);
        }
    }

    #[test]
    fn rejects_a_digest_of_another_length_before_any_apdu() {
        let mut session = Session::open(signing_card()).unwrap();
        let key = session.certificates().unwrap().remove(0).key;
        let sent = session.transport.commands();
        let result = session.sign(
            &[0; 48],
            HashAlgorithm::Sha256,
            &key,
            Pin::new(DEFAULT_PIN.to_owned()),
        );
        assert!(matches!(
            result,
            Err(Error::DigestLength {
                expected: 32,
                actual: 48
            })
        ));
        assert_eq!(session.transport.commands(), sent);
    }

    #[test]
    fn verifies_the_pin_in_a_fresh_transaction_after_reading_the_retries() {
        let mut session = Session::open(signing_card()).unwrap();
        sign_with(&mut session, &[0; 32], HashAlgorithm::Sha256).unwrap();
        let queries = session.transport.pin_queries();
        let read = queries.iter().find(|query| !query.with_pin).unwrap();
        let verified = queries.iter().find(|query| query.with_pin).unwrap();
        assert!(read.transaction < verified.transaction);
    }

    #[test]
    fn drops_the_verified_pin_after_signing() {
        let mut session = Session::open(signing_card()).unwrap();
        sign_with(&mut session, &[0; 32], HashAlgorithm::Sha256).unwrap();
        assert!(!session.transport.pin_verified());
    }

    #[test]
    fn drops_the_verified_pin_when_signing_fails() {
        let mut session = Session::open(signing_card()).unwrap();
        let mut key = session.certificates().unwrap().remove(0).key;
        key.file = [0x01, 0x99];
        let result = session.sign(
            &[0; 32],
            HashAlgorithm::Sha256,
            &key,
            Pin::new(DEFAULT_PIN.to_owned()),
        );
        assert!(matches!(result, Err(Error::Status(StatusWord(0x6A88)))));
        assert!(!session.transport.pin_verified());
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
}
