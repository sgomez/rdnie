# Public API parity with JMulticard

JMulticard `4ec9494` against rdnie `f37136f`. Java paths are relative to `jmulticard/src/main/java/es/gob/jmulticard/`. Behaviour differences live in [parity.md](parity.md).

Status: **Same** the counterpart behaves as in Java · **Changed** the name or shape differs · **Added** Java had it and rdnie now has a counterpart · **Not ported** the reason is in the cell. A pending follow-up is not a design decision.

## JMulticard

### `card.dnie.DnieFactory`

| Method | rdnie | Status |
| --- | --- | --- |
| `getDnie` | `PcscTransport::connect_first_dnie`, `Session::open`. Classifies the cached ATR without a reset (#129, #130) | Same |
| `getDnieNfc`, `getEmrtdNfc` | — (out of scope: NFC, CLAUDE.md constraint 1) | Not ported |
| `getDnie3UsrCwa14890Constants(idesp)` | `Session::key_generation` (the generation, not the constants) | Same |

### `card.CryptoCard`

| Method | rdnie | Status |
| --- | --- | --- |
| `getAliases` | `Session::labels -> Vec<String>`: the labels of the keyed certificates, read from the CDF and the PrKDF only (#129, #131) | Changed |
| `getCertificate(alias)` | `Session::certificate(label)`: the DER, read on demand; keyless certificates stay reachable (#40) | Same |
| `getPrivateKey(alias)` | `Session::private_key(label) -> Option<KeyReference>` | Added |
| `sign(data, algorithm, keyRef)` | `Session::sign(digest, DigestAlgorithm, key, pin)`: the caller hashes, the PIN is consumed per call, the retries are reread before the single VERIFY, a card reset gives `Error::CardReset` | Changed |

### `card.dnie.Dnie`, `Dnie3`

| Method | rdnie | Status |
| --- | --- | --- |
| `getSerialNumber` | `Session::serial_number` | Added |
| `getCardName`, `toString` | `Session::card_name` (`DNIe 3.0/4.0`) | Added |
| `getIdesp` | `Session::idesp` | Added |
| `getPinRetriesLeft` | `Session::pin_retries_left`: opens its own PIN channel, where Java leaves the card in it | Changed |
| `verifyPin` | `Session::verify_pin`: opens its own PIN channel, reads the retries first, one attempt (CLAUDE.md constraint 3) | Same |
| `openSecureChannelIfNotAlreadyOpened()`, `(doChv)` | — (internal: each operation opens its channel in its own transaction and does not keep it) | Not ported |
| `changePIN` | — (pending a follow-up: it widens CLAUDE.md constraint 1) | Not ported |
| `cipherData` | — (pending a follow-up: it widens CLAUDE.md constraint 1) | Not ported |
| `setCallbackHandler`, `setPasswordCallback` | `Pin`: a driver has no UI, the consumer passes the PIN | Same |
| `openPinChannel`, `openUserChannel` | — (internal) | Not ported |
| `Cwa14890Card` methods (`verifyIcc`, `externalAuthentication`…) | — (internal) | Not ported |
| `getDg1`…`getDg16`, `getSod`, `getCom`, `getCardAccess`, `getAtrInfo`, `getDir`, `checkSecurityObjects` | — (out of scope: ICAO, CLAUDE.md constraint 1) | Not ported |

### `card.dnie.DniePrivateKeyReference`

| Method | rdnie | Status |
| --- | --- | --- |
| class | `KeyReference`: the key id and file | Same |
| `getLabel` | — (the caller asked by label) | Not ported |
| `getIdentifier`, `getKeyPath`, `getKeyReference`, `getKeyBitSize`, `getDnieCard` | — (opaque) | Not ported |

### `card.dnie.DnieCertParseUtil`

| Method | rdnie | Status |
| --- | --- | --- |
| constructor | `Holder::from_der`: reads the subject as ASN.1 instead of searching a DN string (#34, #41) | Same |
| `getName` | `Holder::name` | Same |
| `getSurname1`, `getSurname2` | `Holder::first_surname`, `second_surname` | Same |
| `getNumber` | `Holder::number` | Same |

### `DigestAlgorithm`

| Method | rdnie | Status |
| --- | --- | --- |
| enum | `DigestAlgorithm`: the caller hashes; rdnie never sees the document (#1) | Same |
| `getDigestLength` | `DigestAlgorithm::digest_length` | Added |
| `SHA1` | — (insecure, #1) | Not ported |
| `getDigestAlgorithm(name)` | — (not needed) | Not ported |

### `connection.ApduConnection`, `SmartcardIoConnection`

| Method | rdnie | Status |
| --- | --- | --- |
| interface | `Transport`, `Port`: `Transport` owns the connection and runs a transaction, `Port` only sends bytes inside one (CLAUDE.md constraint 5, #170) | Same |
| `transmit` | `Port::transmit` | Same |
| `reset` | `PcscTransport::reset`: inherent, not on `Transport`, since nobody in the protocol resets the card | Same |
| `getTerminals`, `getTerminalInfo`, `setTerminal` | `PcscTransport::readers`, `reader`, `connect`: by name, not index (#35, #45) | Same |
| `open`, `close`, `isOpen`, `Dnie.connect` | `PcscTransport::connect`, `Drop` | Same |
| `setExclusiveUse` | `Transport::transaction`: one PC/SC transaction per operation, as a closure because `unsafe` is forbidden (PR #15) | Same |
| `setProtocol` | — (protocols come from the ATR, commit 834100b) | Not ported |
| `getSubConnection` | — (not needed) | Not ported |

### `apdu.CommandApdu`, `ResponseApdu`, `StatusWord`

| Method | rdnie | Status |
| --- | --- | --- |
| `CommandApdu` | — (crate-private `Command`, short APDUs only; its public fields would bind semver while no consumer builds commands, #170) | Not ported |
| `ResponseApdu` | crate-private `Response` | Changed |
| `StatusWord` | `StatusWord` | Same |
| `StatusWord.isOk` | `StatusWord::is_success` | Same |
| `StatusWord.getMsb`, `getLsb`, `getBytes` | `StatusWord.0` | Same |

### `card.Atr`, `card.dnie.DnieAtr`

| Method | rdnie | Status |
| --- | --- | --- |
| `Atr` | `Atr`, returned by `Transport::atr` and `Session::atr` | Changed |
| `getBytes` | `Atr::as_bytes` | Added |
| `getMask` | — (internal: the DNIe mask is private) | Not ported |
| ATR check in `getDnie` | `Atr::check`: reads only the bytes; `Ok` does not promise `Session::open` succeeds | Added |
| `DnieAtr.toString` | `Display for Atr`, for support logs (#47) | Changed |

### `CryptoHelper`, `callback.*`

| Method | rdnie | Status |
| --- | --- | --- |
| `CryptoHelper` | — (CLAUDE.md constraint 2: RustCrypto) | Not ported |
| `CardWithRetriesPasswordCallback`, `CustomTextInputCallback` | `Pin`, `Session::pin_retries_left` | Changed |

### Exceptions

One `#[non_exhaustive]` enum instead of a class hierarchy (#1, #35).

| Class | rdnie | Status |
| --- | --- | --- |
| `CardException`, `PinException`, `CardSecurityException`, `CryptoCardSecurityException` | `Error` | Same |
| `ApduConnectionException` | `Error::Transport` | Same |
| `BadPinException` | `Error::WrongPin { retries_left }` | Same |
| `AuthenticationModeLockedException` | `Error::PinBlocked` | Same |
| `NoReadersFoundException` | `Error::NoReader` | Same |
| `CardNotPresentException` | `Error::NoCard` | Same |
| `InvalidCardException` | `Error::NotDnie` | Same |
| `BurnedDnieCardException` | `Error::BurnedDnie` | Same |
| `LostChannelException` | `Error::CardReset` | Same |
| `SecureChannelException`, `SecureMessagingException` | `Error::SecureChannel` | Same |
| `InvalidCryptographicChecksumException` | `Error::ChannelLost` | Same |
| `Asn1Exception`, `TlvException`, `BerParsingException`, `OffsetOutsideEfException` | `Error::MalformedPkcs15`, `MalformedCertificate` | Same |
| `DnieCardException`, `CryptoCardException`, `Iso7816FourCardException`, `FileNotFoundException`, `RequiredSecurityStateNotSatisfiedException` | `Error::Status` | Same |
| `PasswordCallbackNotFoundException` | — (no callbacks) | Not ported |
| `UnavailableReaderException`, `CancelledOperationException` | — (never thrown in JMulticard) | Not ported |
| `IcaoException`, `PaceException`, `InvalidCanOrMrzException`, `MalformedMrzException`, `InvalidSecurityObjectException`, `InvalidAccessCodeException` | — (out of scope: ICAO and PACE, CLAUDE.md constraint 1) | Not ported |

## rdnie only

| Item | Use | Status |
| --- | --- | --- |
| `Session::atr` | The `&Atr` `open` read, so the transport need not be given back | Added |
| `Session::open_trusting` | rFirma opens a session against the published emulator. Behind the off-by-default `emulator` feature, so production trusts only the DGP roots (#110, #112, PR #118) | Same |
| `Session::into_transport` | Hands the transport back | Same |
| `SIGNATURE_LABEL`, `INTERMEDIATE_CA_LABEL` | A mistyped label compiles, passes the emulator tests and fails only on a real card (#102, #40) | Same |
| `Error::PinRetriesChanged`, `InvalidPinFormat`, `DigestLength`, `CommandTooLong`, `CardRemoved`, `LegacyDnie`, `TruncatedResponse` | Fail before touching the card, or name a cause Java folds into a generic exception | Same |
