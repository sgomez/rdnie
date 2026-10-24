# Public API parity with JMulticard

JMulticard `4ec9494` against rdnie `c179c86`. Java paths are relative to `jmulticard/src/main/java/es/gob/jmulticard/`; line numbers rot.

## Summary

| JMulticard | rdnie | Status |
| --- | --- | --- |
| `DnieFactory.getDnie` | `PcscTransport::connect_first_dnie`, `Session::open` | Changed |
| `CryptoCard.getAliases` | `Session::certificates` | Changed |
| `CryptoCard.getCertificate` | `Session::certificate` | Changed |
| `CryptoCard.getPrivateKey` | `Certificate::key` | Changed |
| `CryptoCard.sign` | `Session::sign` | Changed |
| `Dnie3.getPinRetriesLeft` | `Session::pin_retries` | Changed |
| `Dnie3.openSecureChannelIfNotAlreadyOpened(true)` | — | Gap |
| `Dnie.verifyPin` | — | Not ported |
| `Dnie.getSerialNumber` | — | Gap |
| `Dnie.getCardName` | — | Gap |
| `Dnie.getIdesp` | `Session::key_generation` | Gap |
| `Dnie.changePIN` | — | Not ported |
| `Dnie.cipherData` | — | Not ported |
| `Dnie.setCallbackHandler`, `setPasswordCallback` | `Pin` | Changed |
| `DniePrivateKeyReference` | `KeyReference` | Changed |
| `DnieCertParseUtil` | `Holder::from_der` | Changed |
| `ApduConnection` | `Transport` | Changed |
| `ApduConnection.transmit` | `Transport::transmit_raw`, `Transport::transmit` | Changed |
| `ApduConnection.reset` | `Transport::reset` | Same |
| `ApduConnection.getTerminals`, `getTerminalInfo`, `setTerminal` | `PcscTransport::readers`, `reader`, `connect` | Changed |
| `ApduConnection.open`, `close`, `isOpen` | `PcscTransport::connect`, `Drop` | Changed |
| `ApduConnection.setProtocol` | — | Not ported |
| `SmartcardIoConnection.setExclusiveUse` | `Transport::transaction` | Changed |
| `CommandApdu` | `Command` | Changed |
| `ResponseApdu` | `Response` | Same |
| `StatusWord` | `StatusWord` | Same |
| `DnieAtr.toString` | `describe_atr` | Changed |
| Exceptions | `Error` | Changed |
| `CryptoHelper` | — | Not ported |
| Password callbacks | `Pin`, `Session::pin_retries` | Changed |
| `DnieFactory.getDnieNfc`, `getEmrtdNfc`, `Dnie3` data groups, SOD, card access | — | Out of scope |
| — | `Transport::atr` | New |
| — | `Session::open_trusting` | New |
| — | `Session::into_transport` | New |
| — | `KeyGeneration` | New |
| — | `HashAlgorithm` | New |
| — | `SIGNATURE_LABEL`, `INTERMEDIATE_CA_LABEL` | New |
| — | `is_dnie` | New |

## Gaps

### `Dnie3.openSecureChannelIfNotAlreadyOpened(true)`

Called on its own, it verifies the PIN without signing and keeps the channel for the next `sign`. rdnie has no such operation: VERIFY happens only inside `Session::sign`. Lost as a side effect of opening a channel per operation (parity.md:61). rFirma works around it with a discarded signature. Planned as `Session::verify_pin`.

### `Dnie.getSerialNumber`

No recorded reason. The serial identifies the card.

### `Dnie.getCardName`

No recorded reason.

### `Dnie.getIdesp`

Only the key generation it selects is public (PR #21, for the real-card probe). No recorded reason for hiding the IDESP itself.

## Changed

### `DnieFactory.getDnie` → `PcscTransport::connect_first_dnie`, `Session::open`

Java resets every reader while scanning, and again when it builds the `Dnie`. rdnie classifies the cached ATR without a reset: a reset breaks other applications' state, and Autofirma made Firefox ask for the PIN again (parity.md:63, :65; #129, #130). Clone cards are out of scope.

### `CryptoCard.getAliases` → `Session::certificates`

Reads only the CDF and the PrKDF, no certificate file. Java loads every certificate when it builds the card; rFirma measured 1.14 s (parity.md:64; #129, #131).

### `CryptoCard.getCertificate` → `Session::certificate`

The DER is read on demand and cached. A corrupt certificate does not hide the others (parity.md:64). Keyless certificates stay reachable (#40).

### `CryptoCard.getPrivateKey` → `Certificate::key`

Returned with the certificate. The fields are opaque; no recorded reason.

### `CryptoCard.sign` → `Session::sign`

- The caller hashes, and SHA-1 is gone (parity.md:70; #1).
- The PIN is a parameter, consumed per call (parity.md:46, :69).
- The retries are reread before the single VERIFY (parity.md:67).
- A card reset returns `Error::CardReset` instead of retrying (parity.md:62).

### `Dnie3.getPinRetriesLeft` → `Session::pin_retries`

Opens its own PIN channel. Java needs an open channel and leaves the card in the PIN channel (parity.md:87).

### `Dnie.setCallbackHandler`, `setPasswordCallback`, password callbacks → `Pin`, `Session::pin_retries`

A driver has no UI: the consumer asks for the PIN and passes it (parity.md:46).

### `DniePrivateKeyReference` → `KeyReference`

Only the key id and file. The label lives on `Certificate`; the rest served `cipherData` (parity.md:89).

### `DnieCertParseUtil` → `Holder::from_der`

Reads the subject as ASN.1 instead of searching Java's DN string (#34, #41, PR #54).

### `ApduConnection` → `Transport`

The seam the emulator plugs into (CLAUDE.md constraint 5).

### `ApduConnection.transmit` → `Transport::transmit_raw`, `Transport::transmit`

- GET RESPONSE and `6Cxx` are bounded; Java recurses without limit (parity.md:72).
- The `6Cxx` resend keeps Lc (parity.md:75).
- A plain command answered `69 87` is resent once, needed without a reset (parity.md:73; #138).
- No `90 C2` envelope (parity.md:50).

### `ApduConnection.getTerminals`, `getTerminalInfo`, `setTerminal` → `PcscTransport::readers`, `reader`, `connect`

By name, not index: names are stable across calls (#35, #45).

### `ApduConnection.open`, `close`, `isOpen` → `PcscTransport::connect`, `Drop`

A connected value is open; dropping it leaves the card (parity.md:142).

### `SmartcardIoConnection.setExclusiveUse` → `Transport::transaction`

One PC/SC transaction per operation: nothing slips in mid-operation, and the reader is free while the holder types the PIN (parity.md:74; #1). A closure, because `pcsc` only offers a borrowing guard and `unsafe` is forbidden (PR #15).

### `CommandApdu` → `Command`

Short APDUs only (parity.md:71). Public fields; no recorded reason.

### `DnieAtr.toString` → `describe_atr`

A free function, since rdnie has no ATR type (PR #58); for support logs (#47).

### Exceptions → `Error`

One `#[non_exhaustive]` enum instead of a class hierarchy (#1, #35).

| JMulticard | rdnie |
| --- | --- |
| `BadPinException` | `WrongPin { retries_left }` |
| `AuthenticationModeLockedException` | `PinBlocked` |
| `NoReadersFoundException` | `NoReader` |
| `CardNotPresentException` | `NoCard` |
| `InvalidCardException` | `NotDnie` |
| `BurnedDnieCardException` | `BurnedDnie` |
| `LostChannelException` | `CardReset` |
| `SecureChannelException` | `SecureChannel` |
| `InvalidCryptographicChecksumException` | `ChannelLost` |
| `DnieCardException`, `CryptoCardException`, `Iso7816FourCardException` | `Status` |
| `PasswordCallbackNotFoundException` | — |

## Not ported

### `Dnie.verifyPin`

A bare VERIFY on the current connection, with no retry read. rdnie never sends the PIN blind (CLAUDE.md constraint 3).

### `Dnie.changePIN`

rFirma only signs; the holder changes the PIN at a police terminal (parity.md:43).

### `Dnie.cipherData`

Raw RSA, for decryption and other signature formats; rFirma needs neither (parity.md:43).

### `ApduConnection.setProtocol`

`PcscTransport` asks for the protocols the cached ATR offers: macOS's CCID driver serves `ANY` as T=1 only and fails on a T=0 DNIe (commit 834100b).

### `CryptoHelper`

Cryptography comes from RustCrypto (CLAUDE.md constraint 2); the caller supplies no provider.

## Out of scope

NFC and PACE (`DnieFactory.getDnieNfc`, `getEmrtdNfc`), ICAO data (`Dnie3.getDg1`…`getDg16`, `getSod`, `getCom`, `getCardAccess`, `getAtrInfo`, `getDir`, `checkSecurityObjects`), clone cards. CLAUDE.md constraint 1.

## New in rdnie

### `Transport::atr`

Reads the ATR without a reset (#129, #130).

### `Session::open_trusting`

rFirma opens a session against the published emulator. Behind the off-by-default `emulator` feature, so production trusts only the DGP roots (#110, #112, PR #118).

### `Session::into_transport`

Hands the transport back. No recorded reason.

### `KeyGeneration`, `Session::key_generation`

The real-card probe prints r1 or r2 (PR #21).

### `HashAlgorithm`

The caller hashes; rdnie never sees the document (#1).

### `SIGNATURE_LABEL`, `INTERMEDIATE_CA_LABEL`

A mistyped label compiles, passes the emulator tests and fails only on a real card (#102, #40).

### `is_dnie`

Checks only the `DNIe` tag in the ATR. No recorded reason for keeping it public and looser than `Session::open`.

### `Error::PinRetriesChanged`, `InvalidPinFormat`, `DigestLength`, `CommandTooLong`, `CardRemoved`, `MalformedCertificate`

Fail before touching the card, or name a cause Java folds into a generic exception (parity.md:67, :68, :71, :93; #41).
