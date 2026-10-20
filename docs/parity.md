# Parity with JMulticard

Snapshot comparing JMulticard `4ec9494` with rdnie `7e960b5`. Line numbers rot; re-run the comparison rather than trusting them after either side moves.

## At a glance

| Capability | rdnie |
| --- | --- |
| Find the DNIe 3.0/4.0 by its ATR, list and pick readers, reject legacy and burned cards | Yes |
| CWA-14890 secure channel: PIN and user channels, r1/r2 key sets | Yes |
| Certificates with their labels, the intermediate CA included | Yes |
| Holder name, surnames and number from a certificate | Yes |
| PIN retries without a PIN | Yes |
| VERIFY and PKCS#1 v1.5 signature of a SHA-256/384/512 digest | Yes |
| Status words and ATRs described in words | Yes |
| Change PIN, decrypt (`cipherData`), SHA-1, PACE/NFC, ICAO, other cards, DNIe 1.0/2.0, JCA provider, extended APDUs and the `90 C2` envelope | No, out of scope |

Every "Yes" sends the same APDUs as JMulticard. Where rdnie behaves differently, it is on purpose ([Differences on purpose](#differences-on-purpose)) or in a case no DNIe reaches ([Open](#open)).

## Open

1. **FCI layouts other than `81`/`85` read as length 0**, on both sides (`files.rs` `file_length`, SelectFileApduResponse.java:66): a certificate would read empty and fail, and the IDESP would silently become `None` (r2 keys). Related and latent on both sides: READ BINARY advances by `0xDE` even after a short read, and offsets ≥ `0x8000` are not guarded. Kept as JMulticard: the real-card probe (#9) passed on a DNIe with the SLE78 chip; revisit only if the probe fails on a DNIe 4.0 or the 19WL34 chip.
2. **CDF certificates sharing an identifier or a label.** Java maps identifier → alias and alias → certificate (Dnie.java:881-882, :916), so a shared identifier gives the key to the last certificate only and a shared label shows once. rdnie pairs each certificate with its key by identifier and lists each one (`certificates.rs` `load`). No DNIe has either.

## Differences on purpose

Each is deliberate and tested.

**Security**

- RND.IFD, Kifd and PRND2 come from the OS CSPRNG and differ on every handshake.
- The ICC public key used in the handshake comes from a component certificate chain (`3F00/6020`, `3F00/601F`) that ends in an embedded DNIe component root.
- Response MACs are compared in constant time, over the exact `87‖99` byte span.

**PIN**

- Retries are accepted only from `63Cx`; `6983` means blocked; anything else is an error. They are re-read before VERIFY in the same transaction, VERIFY is skipped if they are 0 or differ from the count shown, and an operation makes at most one PIN attempt.
- No PIN is kept between operations; each signature takes a new `Pin`, zeroized after VERIFY.
- A PIN outside 8 to 16 UTF-16 units fails before any APDU; Java only rejects an empty one (Dnie.java:360).

**Operations and transport**

- No secure channel outlives an operation: each operation runs in one PC/SC transaction (`SCardBeginTransaction`) and opens its own channels.
- A card reset mid-operation returns `Error::CardReset`; the operation is never retried automatically.
- After a card removal the transport is spent and nothing recovers it; the caller opens a new transport and session.
- `61xx` and `6Cxx` are followed in a loop, at most 256 `GET RESPONSE` and 2 consecutive `6Cxx` resends per command, plain and inside the channel; past a bound the result is `Error::Status` with the last status word. Java recurses without a bound (AbstractApduConnectionIso7816.java:107-132, V1:755-758).
- The card is selected by its ATR without resetting other readers' cards.
- Only short APDUs; anything longer fails with `CommandTooLong` before reaching the card. The largest command in scope (protected PSO VERIFY CERTIFICATE with the 210-byte CA CVC) is 235 bytes, so the envelope is not needed while the CVCs keep their size.
- The caller supplies the digest; SHA-256/384/512 only.

## Detail

Status: **Same** (same behaviour), **Equivalent** (written differently, same result unless noted), **On purpose** (see above), **Not ported** (out of scope, per the "Left out" list of [`research/jmulticard-port.md`](research/jmulticard-port.md)).

Java paths are relative to `jmulticard/src/main/java/es/gob/jmulticard/` unless they name another module (`SIC` = `jmulticard-jsr268/.../SmartcardIoConnection.java`). rdnie paths are relative to `src/`.

### Secure channel

`V1` = `connection/cwa14890/Cwa14890OneV1Connection.java`, `Des` = `connection/ApduEncrypterDes.java`, `Abs` = `connection/AbstractApduEncrypter.java`.

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| V1.open order (V1:203-356) | `cwa14890.rs` `open` | Same | |
| V1.open closes the connection on a failed stage | `cwa14890.rs` `open` | Equivalent | rdnie drops the half-built channel and keeps the handle; the next operation starts a fresh handshake. |
| V1.getPaddedSerial, `90 B8 00 00 07` | `cwa14890.rs` `padded_serial` | Same | |
| Dnie.verifyIcc (Dnie.java:439) | `cwa14890.rs` `icc_public_key` | On purpose | Component chain. |
| Dnie.getIccCertPublicKey (Dnie.java:444) | `cwa14890.rs` `read_certificate` | Same | Trailing bytes after the certificate ignored. |
| Dnie.verifyIfdCertificateChain (Dnie.java:469-512) | `cwa14890.rs` `verify_ifd_certificate_chain` | Same | |
| MseSetAuthenticationKeyApduCommand, `C1 A4 [83 0C CHR] [84 02 ref]` | `cwa14890.rs` `internal_authentication` | Same | |
| V1.internalAuthValidateInternalAuthenticateMessage (V1:461-572) | `cwa14890.rs` `validate_internal_authentication` | Equivalent | Same checks; rdnie sizes the frame from the ICC modulus and rejects SIGMIN ≥ N.ICC up front. |
| AbstractIso7816FourCard.getChallenge | `cwa14890.rs` `challenge` | Equivalent | rdnie requires exactly 8 bytes. |
| V1.externalAuthentication (V1:612-693) | `cwa14890.rs` `external_authentication` | Same | |
| BcCryptoHelper.generateRandomBytes | `cwa14890.rs` `random` | On purpose | OS CSPRNG. |
| V1.generateKenc / generateKmac / generateSsc | `secure_messaging.rs` `derive`, `session_key` | Same | Session secrets zeroized. |
| Dnie3*Cwa14890Constants, DnieFactory.getDnie3{Pin,Usr}Cwa14890Constants | `key_sets.rs` `KeySet::for_card`, `KeyGeneration::of_card` | Same | Empty or unreadable IDESP → r2; `< BMP100001` → r1. No fallback to the other generation in either. |
| Abs.protectAPDU (Abs:84-127) | `secure_messaging.rs` `protect` | Same | Tested with JMulticard vectors. |
| Des.generateMac, 8-byte MAC (Mac8) | `secure_messaging.rs` `authenticator` | Same | ISO 9797-1 alg. 3. |
| SSC increments (V1:728, :744) | `secure_messaging.rs` `protect`, `unprotect` | Same | |
| Des.decryptResponseApdu, outer SW ≠ 9000 | `secure_messaging.rs` `unprotect` | Same | |
| Des.decryptResponseApdu, `[87] 99 8E` parse | `secure_messaging.rs` `unprotect`, `read_tlv` | Same | |
| Des.verifyMac | `secure_messaging.rs` `verify_mac` | On purpose | Constant time. |
| Abs.removePadding7816 | `secure_messaging.rs` `unpadded_len` | Same | |
| V1.transmit `66 88` | `Error::ChannelLost` | Same | No recovery on either side. |
| V1.transmit inner `6Cxx` resend | `secure_messaging.rs` `transmit` | On purpose | Bounded. |
| V1.transmit inner `62xx` → Le−1 | — | Not ported | PACE. |
| V1.close | `SecureMessaging` `Drop` | Equivalent | Drops and zeroizes the keys; the handle stays with `Session`. |
| V1.reset (V1:773-784) | `Protected::reset` → error | Not ported | Unreachable: only the card class holds the channel connection, and it never resets it. |
| Dnie3.openPinChannel (Dnie3.java:213) | `pin.rs` `open_pin_channel` | Same | MF select failure ignored only for status errors. |
| Dnie3.openUserChannel (Dnie3.java:249) | `pin.rs` `open_user_channel`, `Protected` | Same | User channel nested in the PIN channel. |
| Dnie.isSecurityChannelOpen / openSecureChannelIfNotAlreadyOpened | `session.rs` `operation` | On purpose | Fresh channels per operation. |
| Dnie.signOperation retry on `LostChannelException` (Dnie.java:298-309) | `Error::CardReset` | On purpose | No automatic retry. |

### Card, PIN and signing

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| DnieFactory.getDnie reader loop with reset per reader (DnieFactory.java:230) | `pcsc_transport.rs` `connect_first_dnie`, `session.rs` `open_trusting` | On purpose | Only the chosen card is reset. |
| DnieFactory.ATR, ATR_MASK | `atr.rs` `DNIE_ATR`, `DNIE_ATR_MASK` | Same | |
| Atr.equals, right-aligns short ATRs | `atr.rs` `matches_mask` | Equivalent | rdnie requires 20 bytes, as every DNIe ATR has. |
| byte 15 `0x04` → Dnie3 | `atr.rs` `check_dnie_3` → `Error::LegacyDnie` | Same | DNIe 4.0 takes the same path. |
| burned ATR `… 65 81` | `atr.rs` → `Error::BurnedDnie` | Equivalent | rdnie also requires the DNIe historical bytes. |
| DnieAtr.toString | `atr.rs` `describe_atr` | Same | Same fields and values, in English. |
| Dnie.getIdesp, Dnie3 constructor | `session.rs` `read_idesp` | Same | Read once at open; exposed only as `key_generation`. |
| Dnie.getPinRetriesLeft, `00 20 00 00 00` | `pin.rs` `query_retries`, `retries_in` | On purpose | Same APDU; stricter status word handling. |
| Dnie3.getPinRetriesLeft | `Session::pin_retries` | Equivalent | Always a fresh PIN channel; no PIN needed. |
| Dnie.getInternalPasswordCallback, empty PIN / locked | `pin.rs` `check_format`, `Error::InvalidPinFormat`, `Error::PinBlocked` | On purpose | No callbacks, the PIN is a parameter; length checked. |
| Dnie.verifyPin + VerifyApduCommand | `pin.rs` `verify`, `encode`, `refusal` | Same | Same bytes: the low byte of each UTF-16 unit. `63Cx` x>0 → `WrongPin`, `63C0`/`6983` → `PinBlocked`. |
| Dnie.passwordCallback reused across operations | `Pin` consumed by `sign` | On purpose | |
| Dnie.sign → signOperation: MSE SET DST `00 22 41 B6 84 02 <key file>`, PSO CDS `00 2A 9E 9A` | `session.rs` `sign`, `signature.rs` `sign` | Same | Byte-identical. |
| DigestInfo.encode, DigestAlgorithm | `signature.rs` `digest_info`, `HashAlgorithm` | On purpose | Caller supplies the digest; SHA-1 not ported; SHA-224 and raw RSA unsupported in both. |
| Dnie.sign closes with LEAVE_CARD | `pcsc_transport.rs` `Drop` | Same | |
| Multiple signatures per session | `Session::sign` | Same | Each takes its own `Pin`. |
| PinException, BadPinException, AuthenticationModeLockedException | `Error::{InvalidPinFormat, WrongPin, PinBlocked, PinRetriesChanged}` | Same | |
| Dnie.changePIN, cipherData, LoadData/SignData | — | Not ported | |
| callback/*, CancelledOperationException | — | Not ported | |

### Files, PKCS#15 and certificates

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| AbstractIso7816FourCard.MAX_READ_CHUNK `0xDE` | `files.rs` | Same | |
| readBinary / readBinaryComplete | `files.rs` `read_binary_complete` | Same | `6282` keeps the chunk and stops; `6B00` stops. Short reads: open 1. |
| selectFileByName | `files.rs` `select_master_file` | Equivalent | Only `Master.File`; FCI ignored. |
| selectFileById, selectFileByLocation(AndRead) | `files.rs` `select`, `read` | Same | `6A82`/`6982` kept as `Error::Status`. |
| SelectFileApduResponse.getFileLength | `files.rs` `file_length` | Same | Bounds-checked; open 1. |
| Location | `files.rs` `Location` | Same | |
| CompressionUtils (8-byte header + zlib, fallback to raw) | `certificates.rs` `decompressed`, `inflate` | Same | |
| Dnie.loadCertificates: CDF `5015/6004`, certificates, PrKDF `5015/6001` | `certificates.rs` `load` | Same | Any bad file fails the whole load, in both. |
| Dnie constructor eager `loadCertificates` | `Session::certificates`, `loaded` | Equivalent | Loaded on the first request and kept for the session; a failed load keeps nothing. |
| CDF id ↔ PrKDF id pairing | `certificates.rs` `load` | Same | Shared identifiers: open 2. |
| CryptoCard.getAliases, getCertificate(alias) | `Session::certificates` → `Certificate { der, label, key }`, `Session::certificate(label)` | Same | A repeated label: open 2. |
| Dnie.hideCertsWithoutKey, keyless certs reachable by alias | `Session::certificates`, `Session::certificate` | Same | `INTERMEDIATE_CA_LABEL` names `CertCAIntermediaDGP`. |
| Dnie.getPrivateKey, DniePrivateKeyReference | `certificates.rs` `KeyReference { id, file }` | Equivalent | Keeps what MSE SET DST needs; the rest only serves `cipherData`. |
| CertificateObject.getAlias | `pkcs15.rs` `label` | Same | Stored exactly as the CDF has it. |
| Cdf / PrKdf, up to 10 objects | `pkcs15.rs` `entries` | Same | |
| Pkcs15Object mandatory fields | `pkcs15.rs` `entry` | Equivalent | rdnie reads identifier, path and, in the CDF, label. |
| PrKDF fallback to CeresScPrKdf | `pkcs15.rs` `entry` | Equivalent | The tolerant parse accepts what the fallback exists for. |
| DnieCertParseUtil | `holder.rs` `Holder::from_der` | Equivalent | Reads the subject as ASN.1 instead of searching the DN string; same split of name and surnames. Without a surname attribute rdnie still splits the common name; Java throws. |
| CertificateObject issuer / subject / serial, PrivateKeyObject reference / length / name | — | Not ported | Only `toString` and `cipherData` use them. |
| readAllRecords, ReadRecordApduCommand | — | Not ported | Only used outside the core. |
| Odf | — | Not ported | Paths are hard-coded on both sides. |

### APDUs, transport and errors

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| CommandApdu short encoding | `apdu.rs` `Command::to_bytes` | Same | |
| CommandApdu extended Lc / Le | `Error::CommandTooLong` | On purpose | Short APDUs only. |
| Le 256 | `to_bytes` → `00` | Same | Same wire bytes as `RetriesLeftApduCommand`. |
| CommandApdu.setLe on `6Cxx` | `transport.rs` `transmit` | Equivalent | rdnie keeps Lc on the resend. |
| `61xx` → GET RESPONSE, `6Cxx` resend for CLA 00 | `transport.rs` `transmit`, `get_response` | On purpose | Bounded. |
| ResponseApdu, StatusWord | `apdu.rs` `Response`, `StatusWord` | Same | Short responses → `TruncatedResponse`. |
| StatusWord.toString via StandardErrorCodes | `StatusWord` `Display`, `standard_error_codes.rs` | Same | Same codes, in English. |
| ApduConnection.getTerminals / getTerminalInfo / setTerminal | `PcscTransport::readers`, `reader`, `connect` | Same | |
| SIC ignoreVirtualReaders | `connect_first_dnie` ATR filter | Equivalent | |
| SIC.open: `NoReadersFoundException`, `CardNotPresentException` | `Error::NoReader`, `Error::NoCard`, `pcsc_transport.rs` `first_dnie` | Same | |
| SIC protocol `*`, negotiated protocol kept | `Protocols::ANY`, `negotiated` | Same | |
| SIC.setExclusiveUse | `PcscTransport::transaction` | On purpose | One transaction per operation. |
| SIC.reset | `PcscTransport::reset`, `reopen` | Same | |
| SIC.close LEAVE_CARD | `Connection` `Drop` | Same | |
| `SCARD_W_RESET_CARD` → LostChannelException | `Error::CardReset`, `recovering` | Same | |
| Card removed mid-operation | `Error::CardRemoved` | On purpose | No recovery. |
| InvalidCardException, BurnedDnieCardException | `Error::NotDnie`, `Error::BurnedDnie` | Same | |
| DnieCardException, CryptoCardException | `Error::Status` | Same | |
| Timeouts | — | Same | Neither side sets them. |
| EnvelopeDataApduCommand (`90 C2`) | — | Not ported | |
| UnavailableReaderException, ICAO / PACE exceptions | — | Not ported | |
