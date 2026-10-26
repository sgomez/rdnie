// Derived from JMulticard: see LICENSE.jmulticard.md.

//! Session with a DNIe 3.0/4.0, opened as `DnieFactory.getDnie` and `Dnie3` do, minus the reset:
//! classify the ATR, read the IDESP.

use std::collections::BTreeMap;

use crate::{
    Atr, DigestAlgorithm, Error, KeyReference, Pin, StatusWord, Transport,
    card_authenticator::CardAuthenticator,
    certificates,
    channel::{CommandChannel, PlainChannel},
    cwa14890,
    files::{self, Location},
    key_sets::{ComponentRoots, KeyGeneration},
    pin::PinGuard,
    pkcs15, signature,
};

const IDESP: &[u8] = &[0x3F, 0x00, 0x00, 0x06];
const FILE_NOT_FOUND: StatusWord = StatusWord(0x6A82);

/// Session with a DNIe 3.0/4.0 over any [`Transport`].
///
/// [`Error::CardRemoved`] reaches the caller unchanged from every operation, and no PIN is sent
/// after it. The session does not recover: open a new transport and a new session.
pub struct Session<T: Transport> {
    transport: T,
    atr: Atr,
    idesp: Option<String>,
    pin_guard: PinGuard,
    /// The CDF, the PrKDF and the DER of each label, each read on first request and then kept.
    cdf: Option<Vec<pkcs15::Entry>>,
    prkdf: Option<Vec<pkcs15::Entry>>,
    ders: BTreeMap<String, Vec<u8>>,
}

impl<T: Transport> Session<T> {
    /// Accepts the card only if its current ATR is a DNIe 3.0/4.0 and reads its IDESP, without
    /// resetting it. A card without an IDESP, or with an empty one, takes the second generation.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transaction`], [`Transport::atr`], [`Error::NotDnie`],
    /// [`Error::LegacyDnie`] and [`Error::BurnedDnie`], and any failure reading the IDESP but its
    /// absence. A card reset by another application since `connect` fails with
    /// [`Error::CardReset`]: reconnect and open again.
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
        let atr = transport.atr()?;
        atr.check()?;
        let idesp = operation(&mut transport, read_idesp)?;
        Ok(Self {
            transport,
            atr,
            pin_guard: PinGuard::new(CardAuthenticator::from_idesp(idesp.as_deref(), roots)),
            idesp,
            cdf: None,
            prkdf: None,
            ders: BTreeMap::new(),
        })
    }

    /// Lists the PKCS#15 labels of the holder's certificates that have a private key, as
    /// `getAliases`, without a PIN and without reading any certificate file. The session keeps the
    /// CDF and the PrKDF from their first read; a failed read keeps nothing of that file.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::Status`] if a directory cannot be read and
    /// [`Error::MalformedPkcs15`] if it cannot be decoded, a certificate has no UTF-8 label or its
    /// key has no file in its path.
    pub fn labels(&mut self) -> Result<Vec<String>, Error> {
        Ok(self.keyed()?.into_iter().map(|(label, _)| label).collect())
    }

    /// The private key of the certificate labelled `label`, as `getPrivateKey`. `None` if no
    /// certificate has that label or it has no key; with duplicates the last one wins.
    ///
    /// # Errors
    ///
    /// Those of [`Session::labels`].
    pub fn private_key(&mut self, label: &str) -> Result<Option<KeyReference>, Error> {
        Ok(self
            .keyed()?
            .into_iter()
            .rev()
            .find_map(|(keyed, key)| (keyed == label).then_some(key)))
    }

    pub(crate) fn keyed(&mut self) -> Result<Vec<(String, KeyReference)>, Error> {
        let cdf = cached(&mut self.cdf, &mut self.transport, certificates::cdf)?;
        let prkdf = cached(&mut self.prkdf, &mut self.transport, certificates::prkdf)?;
        certificates::keyed(cdf, prkdf)
    }

    /// Fetches the DER of the CDF certificate labelled `label`, with or without a private key,
    /// reading only its file, once per session. `None` if no certificate has that label; with
    /// duplicates the last one in the CDF wins.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::Status`] if the CDF or the certificate file cannot be
    /// read, [`Error::MalformedPkcs15`] if the CDF cannot be decoded or the certificate has no
    /// file in its path and [`Error::MalformedCertificate`] if its bytes are not an X.509
    /// certificate.
    pub fn certificate(&mut self, label: &str) -> Result<Option<Vec<u8>>, Error> {
        if let Some(der) = self.ders.get(label) {
            return Ok(Some(der.clone()));
        }
        let cdf = cached(&mut self.cdf, &mut self.transport, certificates::cdf)?;
        let Some(entry) = cdf.iter().rev().find(|entry| entry.label == label) else {
            return Ok(None);
        };
        let der = operation(&mut self.transport, |card| certificates::read(card, entry))?;
        self.ders.insert(label.to_owned(), der.clone());
        Ok(Some(der))
    }

    /// Reads how many PIN attempts are left through the PIN channel, without sending a PIN, and
    /// sets them as the version the next [`Session::sign`] or [`Session::verify_pin`] expects; a
    /// blocked PIN sets 0.
    ///
    /// # Errors
    ///
    /// Those of [`Session::open`], [`Error::PinBlocked`], [`Error::SecureChannel`] if the card
    /// refuses a step of the mutual authentication up to `EXTERNAL AUTHENTICATE` or fails it,
    /// [`Error::Status`] if the card refuses `INTERNAL AUTHENTICATE`, `GET CHALLENGE` or
    /// `GET CHIP INFO` or gives no retry count, and [`Error::CardReset`] or [`Error::Transport`]
    /// if either strikes during the authentication.
    pub fn pin_retries_left(&mut self) -> Result<u8, Error> {
        self.pin_guard.read_retries(&mut self.transport)
    }

    /// Signs a SHA-256/384/512 digest with `key` after verifying `pin`, and returns the PKCS#1
    /// v1.5 signature. The card must still hold the retries the session expects: those
    /// [`Session::pin_retries_left`] read, those the previous [`Error::WrongPin`] reported, or the
    /// maximum after an accepted `VERIFY`, whatever the operation that followed returned. Without
    /// them it fails with [`Error::PinRetriesNotRead`]; they do not survive the session.
    ///
    /// rdnie forces a read, not a showing: not sending the PIN blind rests on the caller showing
    /// the holder the count. Calling [`Session::pin_retries_left`] only so that `sign` does not
    /// fail, as a consumer reopening a session might, is back to "read, then send".
    ///
    /// # Errors
    ///
    /// Before touching the card, in order: [`Error::DigestLength`], [`Error::InvalidPinFormat`],
    /// [`Error::PinRetriesNotRead`] if the session expects no retries and [`Error::PinBlocked`] if
    /// it expects 0. Then those of [`Session::pin_retries_left`], [`Error::PinRetriesChanged`] if
    /// the retries moved at any time since the last PIN operation, [`Error::WrongPin`] after the
    /// single attempt and [`Error::Status`] if the card refuses the signature. After
    /// [`Error::PinRetriesNotRead`], [`Error::PinBlocked`] or [`Error::PinRetriesChanged`], or any
    /// error once `VERIFY` was sent that leaves the count unknown, call
    /// [`Session::pin_retries_left`] and show the count before trying again.
    pub fn sign(
        &mut self,
        digest: &[u8],
        algorithm: DigestAlgorithm,
        key: &KeyReference,
        pin: Pin,
    ) -> Result<Vec<u8>, Error> {
        let digest_info = signature::digest_info(algorithm, digest)?;
        self.pin_guard
            .verified(&mut self.transport, pin, |channel| {
                signature::sign(channel, key, digest_info)
            })
    }

    /// Verifies `pin` on the card without signing, expecting the retries [`Session::sign`] does; a
    /// later `sign` verifies the PIN again. Without them it fails with
    /// [`Error::PinRetriesNotRead`]; they do not survive the session.
    ///
    /// rdnie forces a read, not a showing: not sending the PIN blind rests on the caller showing
    /// the holder the count. Calling [`Session::pin_retries_left`] only so that `verify_pin` does
    /// not fail, as a consumer reopening a session might, is back to "read, then send".
    ///
    /// # Errors
    ///
    /// Before touching the card, in order: [`Error::InvalidPinFormat`],
    /// [`Error::PinRetriesNotRead`] if the session expects no retries and [`Error::PinBlocked`] if
    /// it expects 0. Then those of [`Session::pin_retries_left`], [`Error::PinRetriesChanged`] if
    /// the retries moved at any time since the last PIN operation and [`Error::WrongPin`] after the
    /// single attempt. After [`Error::PinRetriesNotRead`], [`Error::PinBlocked`] or
    /// [`Error::PinRetriesChanged`], or any error once `VERIFY` was sent that leaves the count
    /// unknown, call [`Session::pin_retries_left`] and show the count before trying again.
    pub fn verify_pin(&mut self, pin: Pin) -> Result<(), Error> {
        self.pin_guard
            .verified(&mut self.transport, pin, |_| Ok(()))
    }

    /// The ATR [`Session::open`] classified, without touching the card.
    #[must_use]
    pub fn atr(&self) -> &Atr {
        &self.atr
    }

    /// The IDESP [`Session::open`] read, as `getIdesp`, without touching the card; `None` for a
    /// card without one.
    #[must_use]
    pub fn idesp(&self) -> Option<&str> {
        self.idesp.as_deref()
    }

    /// The kind of card, as `getCardName`. `Session::open` accepts no other, and a 3.0 and a 4.0
    /// run the same card OS, so they are not told apart.
    #[must_use]
    pub fn card_name(&self) -> &'static str {
        "DNIe 3.0/4.0"
    }

    /// The chip serial, as `getSerialNumber`, from one `GET CHIP INFO` in its own transaction.
    ///
    /// # Errors
    ///
    /// Those of [`Transport::transaction`] and [`Error::Status`] if the card refuses.
    pub fn serial_number(&mut self) -> Result<Vec<u8>, Error> {
        operation(&mut self.transport, |card| {
            // A channel a PIN operation left open would answer the CLA 90 command 69 87.
            files::leave_any_channel(card)?;
            cwa14890::chip_serial(card)
        })
    }

    /// The terminal key generation the card's support number selects.
    #[must_use]
    pub fn key_generation(&self) -> KeyGeneration {
        self.pin_guard.key_generation()
    }

    /// Ends the session and hands back the transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// Runs `body` in one transaction; like `Dnie3`, each operation opens its own channel.
fn operation<R>(
    transport: &mut impl Transport,
    body: impl FnOnce(&mut dyn CommandChannel) -> Result<R, Error>,
) -> Result<R, Error> {
    transport.transaction(|card| body(&mut PlainChannel::new(card)))
}

/// The value in `slot`, read in its own operation if the slot is empty.
fn cached<'a, R>(
    slot: &'a mut Option<R>,
    transport: &mut impl Transport,
    read: impl FnOnce(&mut dyn CommandChannel) -> Result<R, Error>,
) -> Result<&'a R, Error> {
    let value = match slot.take() {
        Some(value) => value,
        None => operation(transport, read)?,
    };
    Ok(slot.insert(value))
}

/// The IDESP as stored, or `None` if the card has no IDESP file.
fn read_idesp(card: &mut dyn CommandChannel) -> Result<Option<String>, Error> {
    let location = Location::new(IDESP).expect("the IDESP path is valid");
    let idesp = match files::read(card, &location) {
        Ok(idesp) => idesp,
        Err(Error::Status(FILE_NOT_FOUND)) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(String::from_utf8_lossy(&idesp).into_owned()))
}

#[cfg(test)]
pub(crate) mod tests;
