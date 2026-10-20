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
    /// Resets the card, accepts it only if it is a DNIe 3.0/4.0 and reads its IDESP if it can.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transaction`], [`Transport::reset`], [`Error::NotDnie`],
    /// [`Error::LegacyDnie`] and [`Error::BurnedDnie`].
    pub fn open(transport: T) -> Result<Self, Error> {
        Self::open_trusting(transport, ComponentRoots::embedded())
    }

    #[cfg(test)]
    pub(crate) fn open_with_roots(transport: T, roots: ComponentRoots) -> Result<Self, Error> {
        Self::open_trusting(transport, roots)
    }

    fn open_trusting(mut transport: T, roots: ComponentRoots) -> Result<Self, Error> {
        check_dnie_3(&transport.reset()?)?;
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
pub(crate) mod tests {
    use super::Session;
    use rsa::{
        Pkcs1v15Sign, RsaPublicKey,
        pkcs8::DecodePublicKey,
        sha2::{Digest, Sha256, Sha384, Sha512},
    };
    use x509_cert::der::{Decode, Encode};

    use crate::{
        Error, HashAlgorithm, KeyGeneration, Pin, StatusWord,
        emulator::{
            DEFAULT_PIN, DNIE_3_ATR, EmulatedDnie, HolderCertificate, ResponseShape, TerminalKey,
            component_root_public_key,
        },
        key_sets::{ComponentRoots, KeySet, R1_PIN, R1_USER, R2_PIN, R2_USER},
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

    pub(crate) fn open(card: EmulatedDnie) -> Session<EmulatedDnie> {
        Session::open_with_roots(card, ComponentRoots::only(component_root_public_key())).unwrap()
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

    struct Unplugged(EmulatedDnie, bool);

    impl crate::Transport for Unplugged {
        fn transmit_raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Error> {
            if self.1 {
                return Err(Error::Transport("unplugged".to_owned()));
            }
            self.0.transmit_raw(apdu)
        }

        fn reset(&mut self) -> Result<Vec<u8>, Error> {
            self.0.reset()
        }

        fn transaction<R>(
            &mut self,
            body: impl FnOnce(&mut dyn crate::Transport) -> Result<R, Error>,
        ) -> Result<R, Error> {
            body(self)
        }
    }

    fn listed_card() -> EmulatedDnie {
        EmulatedDnie::new(&DNIE_3_ATR).with_certificates(&[
            HolderCertificate::new(1, 120).labelled("CertFirma"),
            HolderCertificate::new(2, 120).without_key(),
            HolderCertificate::new(3, 120).labelled("CertAutenticacion"),
        ])
    }

    #[test]
    fn a_second_listing_sends_nothing_to_the_card() {
        let mut session = open(listed_card());
        let first = session.certificates().unwrap();
        let sent = session.transport.commands();
        let second = session.certificates().unwrap();
        assert_eq!(session.transport.commands(), sent);
        let ders =
            |list: &[crate::Certificate]| list.iter().map(|c| c.der.clone()).collect::<Vec<_>>();
        assert_eq!(ders(&first), ders(&second));
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn a_fetch_after_a_listing_sends_nothing_to_the_card() {
        let mut session = open(listed_card());
        session.certificates().unwrap();
        let sent = session.transport.commands();
        assert!(session.certificate("CertFirma").unwrap().is_some());
        assert_eq!(session.transport.commands(), sent);
    }

    #[test]
    fn a_fetch_as_the_first_call_loads_the_certificates() {
        let mut session = open(listed_card());
        let sent = session.transport.commands();
        assert!(session.certificate("CertFirma").unwrap().is_some());
        assert!(session.transport.commands() > sent);
    }

    #[test]
    fn a_failed_fetch_is_retried_on_the_next_call() {
        let mut session =
            Session::open_with_roots(Unplugged(listed_card(), false), ComponentRoots::embedded())
                .unwrap();
        session.transport.1 = true;
        assert!(matches!(
            session.certificate("CertFirma"),
            Err(Error::Transport(_))
        ));
        session.transport.1 = false;
        assert!(session.certificate("CertFirma").unwrap().is_some());
    }

    #[test]
    fn a_failed_load_is_retried_on_the_next_call() {
        let mut session =
            Session::open_with_roots(Unplugged(listed_card(), false), ComponentRoots::embedded())
                .unwrap();
        session.transport.1 = true;
        assert!(matches!(session.certificates(), Err(Error::Transport(_))));
        session.transport.1 = false;
        assert_eq!(session.certificates().unwrap().len(), 2);
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
        let mut session = open(signing_card());
        let certificate = session.certificates().unwrap().remove(0).der;
        for (algorithm, scheme, digest) in cases {
            let signature = sign_with(&mut session, &digest, algorithm).unwrap();
            verify(&certificate, scheme, &digest, &signature);
        }
    }

    #[test]
    fn rejects_a_digest_of_another_length_before_any_apdu() {
        let mut session = open(signing_card());
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
        let mut session = open(signing_card());
        sign_with(&mut session, &[0; 32], HashAlgorithm::Sha256).unwrap();
        let queries = session.transport.pin_queries();
        let read = queries.iter().find(|query| !query.with_pin).unwrap();
        let verified = queries.iter().find(|query| query.with_pin).unwrap();
        assert!(read.transaction < verified.transaction);
    }

    #[test]
    fn opens_the_user_channel_inside_the_pin_channel() {
        let (result, card) = sign_with_pin(signing_card(), DEFAULT_PIN);
        result.unwrap();
        let [pin_channels @ .., user_channel] = card.handshakes() else {
            panic!("no handshake");
        };
        assert!(user_channel.inside_channel);
        assert!(
            pin_channels
                .iter()
                .all(|handshake| !handshake.inside_channel)
        );
    }

    fn sign_with_pin(card: EmulatedDnie, pin: &str) -> (Result<Vec<u8>, Error>, EmulatedDnie) {
        let mut session = open(card);
        let key = session.certificates().unwrap().remove(0).key;
        let result = session.sign(
            &[0; 32],
            HashAlgorithm::Sha256,
            &key,
            Pin::new(pin.to_owned()),
        );
        (result, session.into_transport())
    }

    #[test]
    fn rejects_a_malformed_pin_without_any_apdu() {
        let too_long = "a".repeat(17);
        for pin in ["short", "ñandúñandú", "tab\tcharacter", too_long.as_str()] {
            let mut session = open(signing_card());
            let key = session.certificates().unwrap().remove(0).key;
            let sent = session.transport.commands();
            let result = session.sign(
                &[0; 32],
                HashAlgorithm::Sha256,
                &key,
                Pin::new(pin.to_owned()),
            );
            assert!(matches!(result, Err(Error::InvalidPinFormat)), "{pin:?}");
            assert_eq!(session.transport.commands(), sent);
        }
    }

    #[test]
    fn accepts_the_pin_length_limits() {
        for pin in ["12345678", "1234567890123456"] {
            let card = signing_card().with_pin(pin);
            assert!(sign_with_pin(card, pin).0.is_ok(), "{pin}");
        }
    }

    #[test]
    fn sends_no_verify_to_a_blocked_pin() {
        let (result, card) = sign_with_pin(signing_card().with_pin_retries(0), DEFAULT_PIN);
        assert!(matches!(result, Err(Error::PinBlocked)));
        assert!(card.pin_queries().iter().all(|query| !query.with_pin));
    }

    #[test]
    fn makes_one_attempt_with_a_wrong_pin_and_reports_the_retries() {
        let (result, card) = sign_with_pin(signing_card(), "WrongPin1");
        assert!(matches!(result, Err(Error::WrongPin { retries_left: 2 })));
        let attempts = card.pin_queries().iter().filter(|query| query.with_pin);
        assert_eq!(attempts.count(), 1);
        assert!(!card.pin_verified());
    }

    #[test]
    fn reports_a_blocked_pin_when_the_attempt_exhausts_it() {
        let card = signing_card().with_pin_retries(1);
        let (result, _) = sign_with_pin(card, "WrongPin1");
        assert!(matches!(result, Err(Error::PinBlocked)));
    }

    #[test]
    fn aborts_before_verify_when_the_retries_changed_between_phases() {
        let card = signing_card().losing_a_retry_between_phases();
        let (result, card) = sign_with_pin(card, DEFAULT_PIN);
        assert!(matches!(result, Err(Error::PinRetriesChanged)));
        assert!(card.pin_queries().iter().all(|query| !query.with_pin));
    }

    #[test]
    fn aborts_before_verify_when_the_retries_changed_while_the_caller_prompted() {
        let mut session = open(signing_card().losing_a_retry_between_phases());
        let key = session.certificates().unwrap().remove(0).key;
        assert_eq!(session.pin_retries().unwrap(), 3);
        let result = session.sign(
            &[0; 32],
            HashAlgorithm::Sha256,
            &key,
            Pin::new(DEFAULT_PIN.to_owned()),
        );
        assert!(matches!(result, Err(Error::PinRetriesChanged)));
        let card = session.into_transport();
        assert!(card.pin_queries().iter().all(|query| !query.with_pin));
    }

    #[test]
    fn aborts_before_verify_when_no_retry_is_left() {
        let card = signing_card().answering_retries_with(0x63C0);
        let (result, card) = sign_with_pin(card, DEFAULT_PIN);
        assert!(matches!(result, Err(Error::PinBlocked)));
        assert!(card.pin_queries().iter().all(|query| !query.with_pin));
    }

    #[test]
    fn keeps_the_idesp() {
        let card = EmulatedDnie::new(&DNIE_3_ATR).with_idesp(b"TST000042");
        let session = Session::open(card).unwrap();
        assert_eq!(session.idesp.as_deref(), Some("TST000042"));
    }

    #[test]
    fn reports_the_key_generation_of_the_card() {
        let generation = |idesp: &[u8]| {
            let card = EmulatedDnie::new(&DNIE_3_ATR).with_idesp(idesp);
            Session::open(card).unwrap().key_generation()
        };
        assert_eq!(generation(b"BMP100000"), KeyGeneration::First);
        assert_eq!(generation(b"BMP100001"), KeyGeneration::Second);
        let bare = Session::open(EmulatedDnie::new(&DNIE_3_ATR)).unwrap();
        assert_eq!(bare.key_generation(), KeyGeneration::Second);
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

    fn reads_retries_and_signs_over(shape: ResponseShape) {
        let mut session = open(signing_card().with_pin_retries(2).shaping_responses(shape));
        assert_eq!(session.pin_retries().unwrap(), 2);
        let certificate = session.certificates().unwrap().remove(0).der;
        let digest = Sha256::digest(b"document");
        let signature = sign_with(&mut session, &digest, HashAlgorithm::Sha256).unwrap();
        verify(
            &certificate,
            Pkcs1v15Sign::new::<Sha256>(),
            &digest,
            &signature,
        );
    }

    #[test]
    fn ignores_bytes_after_the_response_mac() {
        reads_retries_and_signs_over(ResponseShape::TrailingBytes(&[0x00, 0x8E, 0x01, 0xFF]));
    }

    #[test]
    fn skips_the_first_cryptogram_byte_whatever_its_value() {
        reads_retries_and_signs_over(ResponseShape::CryptogramIndicator(0x02));
    }

    #[test]
    fn appends_the_status_word_object_before_its_last_two_bytes_to_the_data() {
        reads_retries_and_signs_over(ResponseShape::LongStatusWord(3));
    }

    #[test]
    fn takes_the_data_from_a_status_word_object_without_cryptogram() {
        reads_retries_and_signs_over(ResponseShape::LongStatusWord(usize::MAX));
    }

    #[test]
    fn refuses_malformed_responses_before_sending_the_pin() {
        for shape in [
            ResponseShape::ShortStatusWord,
            ResponseShape::EmptyCryptogram,
        ] {
            let card = || signing_card().shaping_responses(shape);
            assert!(matches!(retries(card()), Err(Error::SecureChannel(_))));
            let (result, card) = sign_with_pin(card(), DEFAULT_PIN);
            assert!(matches!(result, Err(Error::SecureChannel(_))));
            assert!(card.pin_queries().iter().all(|query| !query.with_pin));
        }
    }

    #[test]
    fn ends_an_endless_pending_response_inside_the_channel_with_its_status() {
        let card = card_with_channel().pending_forever_inside_the_channel();
        assert!(matches!(
            retries(card),
            Err(Error::Status(StatusWord(0x6105)))
        ));
    }

    #[test]
    fn ends_an_endless_wrong_length_inside_the_channel_with_its_status() {
        let mut session =
            open(card_with_channel().asking_a_wrong_length_forever_inside_the_channel());
        assert!(matches!(
            session.pin_retries(),
            Err(Error::Status(StatusWord(0x6C05)))
        ));
        assert_eq!(session.transport.pin_queries().len(), 1 + 2);
    }

    #[test]
    fn ends_an_endless_wrong_length_with_bytes_after_the_mac_with_its_status() {
        let card = card_with_channel()
            .asking_a_wrong_length_forever_inside_the_channel()
            .shaping_responses(ResponseShape::TrailingBytes(&[0x00, 0x8E, 0x01, 0xFF]));
        assert!(matches!(
            retries(card),
            Err(Error::Status(StatusWord(0x6C05)))
        ));
    }

    #[test]
    fn sends_the_pin_at_most_three_times_on_an_endless_wrong_length() {
        let card = signing_card().asking_a_wrong_length_forever_on_the_pin();
        let (result, card) = sign_with_pin(card, DEFAULT_PIN);
        assert!(matches!(result, Err(Error::Status(StatusWord(0x6C05)))));
        let attempts = card.pin_queries().iter().filter(|query| query.with_pin);
        assert_eq!(attempts.count(), 3);
        assert_eq!(retries(card).unwrap(), 3);
    }

    #[test]
    fn starts_a_fresh_channel_after_each_failure() {
        let faulty = [
            card_with_channel().resetting_mid_channel(),
            card_with_channel().losing_the_channel(),
            card_with_channel().corrupting_a_response_mac(),
        ];
        for card in faulty {
            let mut session = open(card.with_pin_retries(2));
            assert!(session.pin_retries().is_err());
            assert_eq!(session.pin_retries().unwrap(), 2);
        }
    }

    #[test]
    fn returns_card_removed_unchanged_from_listing() {
        let mut session = open(signing_card());
        session.transport.remove_card();
        assert!(matches!(session.certificates(), Err(Error::CardRemoved)));
        assert!(matches!(
            session.certificate("any"),
            Err(Error::CardRemoved)
        ));
    }

    #[test]
    fn returns_card_removed_unchanged_from_retries() {
        let mut session = open(card_with_channel());
        session.transport.remove_card();
        assert!(matches!(session.pin_retries(), Err(Error::CardRemoved)));
    }

    #[test]
    fn returns_card_removed_from_sign_and_never_sends_the_pin() {
        let mut session = open(signing_card());
        let key = session.certificates().unwrap().remove(0).key;
        session.pin_retries().unwrap();
        session.transport.remove_card();
        let pin = Pin::new(DEFAULT_PIN.to_owned());
        let result = session.sign(&[0; 32], HashAlgorithm::Sha256, &key, pin);
        assert!(matches!(result, Err(Error::CardRemoved)));
        assert!(
            session
                .transport
                .pin_queries()
                .iter()
                .all(|query| !query.with_pin)
        );
    }

    #[test]
    fn returns_card_removed_from_sign_when_the_retries_were_not_read() {
        let mut session = open(signing_card());
        let key = session.certificates().unwrap().remove(0).key;
        session.transport.remove_card();
        let pin = Pin::new(DEFAULT_PIN.to_owned());
        let result = session.sign(&[0; 32], HashAlgorithm::Sha256, &key, pin);
        assert!(matches!(result, Err(Error::CardRemoved)));
        assert!(
            session
                .transport
                .pin_queries()
                .iter()
                .all(|query| !query.with_pin)
        );
    }
}
