# Parity with JMulticard

Snapshot comparing JMulticard `4ec9494` with rdnie `f37136f`. Line numbers rot; re-run the comparison rather than trusting them after either side moves.

## At a glance

| Capability | rdnie |
| --- | --- |
| SHA-1, PACE/NFC, ICAO, other cards, DNIe 1.0/2.0, JCA provider, extended APDUs and the `90 C2` envelope | No, out of scope |
| Find the DNIe 3.0/4.0 by its ATR, list and pick readers, reject legacy and burned cards | Yes |
| CWA-14890 secure channel: PIN and user channels, r1/r2 key sets | Yes |
| Labels of the keyed certificates, any certificate by label (the intermediate CA included), the key of a label | Yes |
| Holder name, surnames and number from a certificate | Yes |
| PIN retries without a PIN | Yes |
| Serial number, card name, IDESP and ATR of the opened card | Yes |
| Change PIN, decrypt (`cipherData`) | No, pending a follow-up |
| VERIFY without signing | Yes |
| Signature with VERIFY: PKCS#1 v1.5 of a SHA-256/384/512 digest | Yes |
| Status words and ATRs described in words (`Display for Atr`) | Yes |

Every "Yes" sends the same APDUs as JMulticard. Where rdnie behaves differently, it is [on purpose](#on-purpose) or in a case no DNIe reaches ([Open](#open)).

## Open

1. **FCI layouts other than `81`/`85` read as length 0**, on both sides (`files.rs` `file_length`, SelectFileApduResponse.java:66): a certificate would read empty and fail, and the IDESP would silently become `None` (r2 keys). Related and latent on both sides: READ BINARY advances by `0xDE` even after a short read, and offsets ≥ `0x8000` are not guarded. Kept as JMulticard: the real-card probe (#9) passed on a DNIe with the SLE78 chip; revisit only if the probe fails on a DNIe 4.0 or the 19WL34 chip.
2. **CDF certificates sharing an identifier or a label.** Java maps identifier → alias and alias → certificate (Dnie.java:881-882, :916), so a shared identifier gives the key to the last certificate only and a shared label shows once. rdnie pairs each certificate with its key by identifier and lists each one (`certificates.rs` `keyed`). No DNIe has either.

## Detail

One table per status, from the furthest from Java to the closest:

- [**Not ported**](#not-ported): Java has it, rdnie does not.
- [**On purpose**](#on-purpose): both do it, differently, and rdnie's way was chosen. Each one is tested.
- [**Equivalent**](#equivalent): written differently, same result on a DNIe.
- [**Same**](#same): same behaviour.

Within a table, rows run secure channel → card, PIN and signing → files and certificates → APDUs and transport.

Java paths are relative to `jmulticard/src/main/java/es/gob/jmulticard/` unless they name another module (`SIC` = `jmulticard-jsr268/.../SmartcardIoConnection.java`). `V1` = `connection/cwa14890/Cwa14890OneV1Connection.java`, `Des` = `connection/ApduEncrypterDes.java`, `Abs` = `connection/AbstractApduEncrypter.java`. rdnie paths are relative to `src/`.

### Not ported

| JMulticard | What Java does | Why rdnie does not |
| --- | --- | --- |
| V1.transmit inner `62xx` → Le−1 (V1:759-762) | See the private notes. | An inner warning such as `6282` must reach the caller with its data. rdnie returns it without resending (`secure_messaging.rs` `transmit`). |
| V1.reset (V1:773-784) | Resets the card and opens the channel again. | Nothing calls it. `Protected::reset` returns an error, so a future caller notices. |
| Dnie.changePIN | Changes the PIN. | Pending a follow-up: it widens design constraint 1. |
| Dnie.cipherData, LoadData / SignData | Raw RSA with the private key (`LOAD DATA` + `SIGN DATA`). The JCA provider uses it to decrypt and for signature formats other than PKCS#1 v1.5. | Pending a follow-up: it widens design constraint 1. |
| callback/*, CancelledOperationException | Asks the holder for the PIN and confirmations through callbacks; cancelling throws. | A driver has no UI. The PIN is a parameter; the consumer asks for it and cancels by not calling `sign`. |
| CertificateObject issuer / subject / serial, PrivateKeyObject reference / length / name | Parses these PKCS#15 attributes. | Only `toString` and `cipherData` read them. The certificate's DER carries issuer, subject and serial. |
| readAllRecords, ReadRecordApduCommand | Reads record files. | The core never calls them for a DNIe. |
| Odf | Parses the ODF, the PKCS#15 index of the other directories. | Java does not use it either: both hard-code the CDF and PrKDF paths. |
| EnvelopeDataApduCommand (`90 C2`) | Splits a command over 255 bytes into several. | The largest command in scope, protected PSO VERIFY CERTIFICATE with the 210-byte CA CVC, is 235 bytes. A larger one fails with `CommandTooLong`. |
| UnavailableReaderException, ICAO / PACE exceptions | Thrown by the Android USB connection and the ICAO and PACE code. | Those connections and protocols are not ported. |

### On purpose

| JMulticard | What Java does | What rdnie does | Why |
| --- | --- | --- | --- |
| Dnie.verifyIcc (Dnie.java:439) | See the private notes. | Verifies the component chain (`3F00/6020`, `3F00/601F`) up to an embedded DNIe component root before using the key (`cwa14890.rs` `icc_public_key`). | The ICC key must be authenticated before any PIN reaches the card. |
| BcCryptoHelper.generateRandomBytes | See the private notes. | Draws RND.IFD, Kifd and PRND2 from the OS CSPRNG (`cwa14890.rs` `random`). | Handshake randomness must be unpredictable and new on every handshake. |
| Des.verifyMac | See the private notes. | Compares in constant time over the exact `87‖99` span (`secure_messaging.rs` `verify_mac`). | The time taken must not reveal how much of a forged MAC is right. |
| V1.transmit inner `6Cxx` resend (V1:755-758) | Resends with the Le the card asks for, recursing without limit. | At most 2 resends in a row, then `Error::Status` with the last status word (`secure_messaging.rs` `transmit`). | A faulty card or reader must not hang the operation. A DNIe needs at most one resend. |
| Dnie.isSecurityChannelOpen / openSecureChannelIfNotAlreadyOpened | Opens the channel once and reuses it across operations while the connection lives. | Opens new channels for each operation and drops them, keys zeroized, at the end (`session.rs` `operation`). | No session keys survive between operations, and each one starts from a known state. Cost: each operation repeats the handshake. |
| Dnie.signOperation retry on `LostChannelException` (Dnie.java:298-309) | After a card reset, opens the channel again and repeats the signature, VERIFY included. | Returns `Error::CardReset` and retries nothing. | An operation makes at most one PIN attempt; the caller decides whether to try again with a new `Pin`. |
| DnieFactory.getDnie reader loop (DnieFactory.java:252-255) | Resets the card in each reader, in order, to read its ATR, until it finds a DNIe. | Reads every reader's ATR without resetting and picks the DNIe (`pcsc_transport.rs` `connect_first_dnie`). | Resetting other cards breaks the sessions other applications have open on them. |
| Dnie.loadCertificates, eager in the Dnie constructor | Reads the CDF, every certificate and the PrKDF when the card object is built; any bad file fails the whole load. | `Session::labels` and `Session::private_key` read the CDF and the PrKDF only and give the keyed labels and a label's key, without any DER. `Session::certificate(label)` reads that one certificate file on first request. The session keeps the CDF, the PrKDF and each certificate apart; a failed read keeps nothing of that item (`session.rs` `cached`). A bad certificate file fails only the fetch of its label. | Signing needs only the key reference, and a consumer showing one certificate pays for that file alone. One corrupt certificate must not hide the others. |
| DnieFactory.getDnie reset on start | Resets the DNIe it picked and classifies the ATR the reset returns. | Never resets the card on its own: `Session::open` classifies `Transport::atr`, the ATR the transport already holds (`session.rs` `open_with`). `Transport::reset` stays for callers who want it. | A reset breaks the state other applications hold on the card, and two shared sessions would reset each other. On a real card, listing with JMulticard (Autofirma) made Firefox ask for the PIN again; opening with rdnie did not. rdnie relies on no state a reset would restore: every read starts by selecting the MF and every PIN operation opens its own channels. |
| Dnie.getIdesp, Dnie3 constructor | On any read failure leaves the IDESP unset: r2 keys. | r2 only if the IDESP is absent (`6A82`) or empty; any other failure, resets and removals included, fails `Session::open` (`session.rs` `read_idesp`). | A failed read on an r1 card would pick the wrong keys. |
| Dnie.getPinRetriesLeft, `00 20 00 00 00` | See the private notes. | Same APDU. Takes a count only from `63Cx`, reads `6983` as blocked and fails on anything else. Reads it again before VERIFY in the same transaction and skips VERIFY if it is 0 or differs from the count shown (`pin.rs` `query_retries`, `retries_in`). | The PIN is never sent blind: a misread count could spend the last attempt. |
| Dnie.getInternalPasswordCallback, empty PIN / locked | Asks for the PIN through a callback and rejects only an empty one (Dnie.java:360). | Takes the PIN as a parameter and requires 8 to 16 UTF-16 units before any APDU (`pin.rs` `check_format`). | A driver has no UI, and the length check catches a mistyped PIN without spending an attempt. The DNIe accepts only 8 to 16 characters. |
| Dnie.passwordCallback reused across operations | Keeps the callback and reuses it for later operations. | Consumes the `Pin` in one signature and zeroizes it after VERIFY. | No PIN stays in memory between operations. The consumer passes it on each signature. |
| DigestInfo.encode, DigestAlgorithm | Hashes the data itself; SHA-1 among the algorithms. | Signs a digest the caller supplies; SHA-256/384/512 only (`signature.rs` `digest_info`, `DigestAlgorithm`). | Hashing is the consumer's job, and SHA-1 is no longer acceptable for signatures. SHA-224 and raw RSA are unsupported in both. |
| CommandApdu extended Lc / Le | Encodes extended APDUs. | Short APDUs only; anything longer fails with `Error::CommandTooLong` before reaching the card. | Nothing in scope needs them (see the envelope above), and not every reader supports them. |
| `61xx` → GET RESPONSE, `6Cxx` resend for CLA 00 (AbstractApduConnectionIso7816.java:107-132) | Follows both, recursing without limit. | Loops with at most 256 `GET RESPONSE` and 2 `6Cxx` resends in a row, then `Error::Status` (`transport.rs` `transmit`, `get_response`). | Same as the inner `6Cxx`: a faulty card or reader must not hang the operation. |
| `69 87` to a plain command | Never meets it: it resets the card on open. | Resends a CLA `00` command answered `69 87` once, then `Error::Status`; never a protected one (`transport.rs` `transmit`). | Without a reset, a DNIe with a channel left open answers `69 87` to the first plain command and drops the channel. |
| SIC.setExclusiveUse | Off by default; when on, holds the card exclusively for the whole connection. | Holds it in one PC/SC transaction per operation (`PcscTransport::transaction`). | No other application can slip APDUs into an operation, yet the reader is free between operations. |
| CommandApdu.setLe on `6Cxx` (CommandApdu.java:217-235) | Rebuilds the command without Lc, so a command with data is resent malformed. | Resends the same command with the new Le (`transport.rs` `transmit`). | A resend must be the same command. |

### Equivalent

| JMulticard | What Java does | What rdnie does | Why it is equivalent |
| --- | --- | --- | --- |
| V1.open closes the connection on a failed stage | Closes the connection when a handshake stage fails. | Drops the half-built channel and keeps the PC/SC handle (`cwa14890.rs` `open`). | In both, nothing from the failed handshake survives and the next operation starts a new one. |
| V1.internalAuthValidateInternalAuthenticateMessage (V1:461-572) | Decrypts the card's internal authentication and checks it. | The same checks; sizes the frame from the ICC modulus and rejects SIGMIN ≥ N.ICC before the rest (`cwa14890.rs` `validate_internal_authentication`). | A valid response passes both and an invalid one fails both; rdnie fails earlier. |
| AbstractIso7816FourCard.getChallenge | Returns whatever data the card sends. | Requires exactly 8 bytes (`cwa14890.rs` `challenge`). | A DNIe always sends 8; any other length would break Java's handshake a step later. |
| V1.close | Closes the channel and the PC/SC connection under it. | Dropping `SecureMessaging` zeroizes the keys; the PC/SC connection closes when `Session` is dropped. | Both end with no channel and the card left as it was. |
| Atr.equals, right-aligns short ATRs | Right-aligns a short ATR before applying the mask. | Requires 20 bytes (`atr.rs` `matches_mask`). | Every DNIe ATR has 20 bytes. |
| Burned ATR `… 65 81` | Looks at the last bytes only. | Also requires the DNIe historical bytes (`atr.rs` → `Error::BurnedDnie`). | A burned DNIe matches both; rdnie just does not call another card burned. |
| Dnie3.getPinRetriesLeft | Requires an open CWA channel; from the user channel it switches to the PIN channel and stays there. | Opens a PIN channel just for the query (`Session::pin_retries_left`). | Same APDU in the same channel; no PIN in either. |
| selectFileByName | Selects by name and returns the length from the FCI. | Selects only `Master.File` and ignores the FCI (`files.rs` `select_master_file`). | `Master.File` is the only file selected by name, and nobody uses its length. |
| Dnie.getPrivateKey, DniePrivateKeyReference | Builds a key reference with identifier, path, name and length. | Keeps identifier and key file (`certificates.rs` `KeyReference { id, file }`), returned by `Session::private_key(label)`. | MSE SET DST needs only the key file; the rest serves `cipherData`. |
| Pkcs15Object mandatory fields | The ASN.1 parse requires every mandatory field. | Reads identifier, path and, in the CDF, label (`pkcs15.rs` `entry`). | A DNIe has every field, so the same objects come out. |
| PrKDF fallback to CeresScPrKdf (Dnie.java:895-903) | If the PrKDF does not parse, tries again with the CERES layout. | A tolerant parse that accepts both (`pkcs15.rs` `entry`). | The same keys come out. |
| DnieCertParseUtil | Searches the subject DN string for the name and surnames. | Reads the subject as ASN.1 (`holder.rs` `Holder::from_der`). | Same split of name and surnames. Without a surname attribute rdnie still splits the common name, where Java throws. |
| Card removed mid-operation | Throws a generic connection exception. | Returns `Error::CardRemoved`. | Neither recovers; rdnie only names the cause. |
| SIC ignoreVirtualReaders | Skips readers named "Windows Hello", only when a system property is set. | Takes only readers holding a DNIe ATR (`connect_first_dnie`). | A virtual reader holds no DNIe, so it is left out too. |

### Same

| JMulticard | rdnie | Note |
| --- | --- | --- |
| V1.open order (V1:203-356) | `cwa14890.rs` `open` | |
| V1.getPaddedSerial, `90 B8 00 00 07` | `cwa14890.rs` `padded_serial` | |
| Dnie.getIccCertPublicKey (Dnie.java:444) | `cwa14890.rs` `read_certificate` | Trailing bytes after the certificate ignored. |
| Dnie.verifyIfdCertificateChain (Dnie.java:469-512) | `cwa14890.rs` `verify_ifd_certificate_chain` | |
| MseSetAuthenticationKeyApduCommand, `C1 A4 [83 0C CHR] [84 02 ref]` | `cwa14890.rs` `internal_authentication` | |
| V1.externalAuthentication (V1:612-693) | `cwa14890.rs` `external_authentication` | |
| V1.generateKenc / generateKmac / generateSsc | `secure_messaging.rs` `derive`, `session_key` | Session secrets zeroized. |
| Dnie3*Cwa14890Constants, DnieFactory.getDnie3{Pin,Usr}Cwa14890Constants | `key_sets.rs` `KeySet::for_card`, `KeyGeneration::of_card` | Empty or absent IDESP → r2; `< BMP100001` → r1. No fallback to the other generation in either. |
| Abs.protectAPDU (Abs:84-127) | `secure_messaging.rs` `protect` | Tested with JMulticard vectors. |
| Des.generateMac, 8-byte MAC (Mac8) | `secure_messaging.rs` `authenticator` | ISO 9797-1 alg. 3. |
| SSC increments (V1:728, :744) | `secure_messaging.rs` `protect`, `unprotect` | |
| Des.decryptResponseApdu, outer SW ≠ 9000 | `secure_messaging.rs` `unprotect` | |
| Des.decryptResponseApdu, `[87] 99 8E` parse | `secure_messaging.rs` `unprotect`, `read_tlv` | |
| Abs.removePadding7816 | `secure_messaging.rs` `unpadded_len` | |
| V1.transmit `66 88` | `Error::ChannelLost` | No recovery on either side. |
| Dnie3.openPinChannel (Dnie3.java:213) | `pin.rs` `open_pin_channel` | MF select failure ignored only for status errors. |
| Dnie3.openUserChannel (Dnie3.java:249) | `pin.rs` `open_user_channel`, `Protected` | User channel nested in the PIN channel. |
| DnieFactory.ATR, ATR_MASK | `atr.rs` `DNIE_ATR`, `DNIE_ATR_MASK` | |
| byte 15 `0x04` → Dnie3 | `atr.rs` `check_dnie_3` → `Error::LegacyDnie` | DNIe 4.0 takes the same path. |
| DnieAtr.toString | `atr.rs` `Display for Atr` | Same fields and values, in English. |
| Dnie.verifyPin + VerifyApduCommand | `pin.rs` `verify`, `encode`, `refusal` | Same bytes: the low byte of each UTF-16 unit. `63Cx` x>0 → `WrongPin`, `63C0`/`6983` → `PinBlocked`. |
| Dnie.sign → signOperation: MSE SET DST `00 22 41 B6 84 02 <key file>`, PSO CDS `00 2A 9E 9A` | `session.rs` `sign`, `signature.rs` `sign` | Byte-identical. |
| Dnie.sign closes with LEAVE_CARD | `pcsc_transport.rs` `Drop` | |
| Multiple signatures per session | `Session::sign` | Each takes its own `Pin`. |
| PinException, BadPinException, AuthenticationModeLockedException | `Error::{InvalidPinFormat, WrongPin, PinBlocked, PinRetriesChanged}` | |
| AbstractIso7816FourCard.MAX_READ_CHUNK `0xDE` | `files.rs` | |
| readBinary / readBinaryComplete | `files.rs` `read_binary_complete` | `6282` keeps the chunk and stops; `6B00` stops. Short reads: open 1. |
| selectFileById, selectFileByLocation(AndRead) | `files.rs` `select`, `read` | `6A82`/`6982` kept as `Error::Status`. |
| SelectFileApduResponse.getFileLength | `files.rs` `file_length` | Bounds-checked; open 1. |
| Location | `files.rs` `Location` | |
| CompressionUtils (8-byte header + zlib, fallback to raw) | `certificates.rs` `decompressed`, `inflate` | |
| CDF `5015/6004`, certificate files, PrKDF `5015/6001` | `certificates.rs` `cdf`, `read`, `prkdf` | Same paths and decoding; when they are read is [on purpose](#on-purpose). |
| CDF id ↔ PrKDF id pairing | `certificates.rs` `keyed` | Shared identifiers: open 2. |
| CryptoCard.getAliases, getCertificate(alias) | `Session::labels`, `Session::certificate(label)` | A repeated label: open 2. |
| Dnie.hideCertsWithoutKey, keyless certs reachable by alias | `Session::labels`, `Session::certificate` | `INTERMEDIATE_CA_LABEL` names `CertCAIntermediaDGP`; `SIGNATURE_LABEL` names `CertFirmaDigital`. |
| CertificateObject.getAlias | `pkcs15.rs` `label` | Stored exactly as the CDF has it. |
| Cdf / PrKdf, up to 10 objects | `pkcs15.rs` `entries` | |
| CommandApdu short encoding | `apdu.rs` `Command::to_bytes` | |
| Le 256 | `to_bytes` → `00` | Same wire bytes as `RetriesLeftApduCommand`. |
| ResponseApdu, StatusWord | `apdu.rs` `Response`, `StatusWord` | Short responses → `TruncatedResponse`. |
| StatusWord.toString via StandardErrorCodes | `StatusWord` `Display`, `standard_error_codes.rs` | Same codes, in English. |
| ApduConnection.getTerminals / getTerminalInfo / setTerminal | `PcscTransport::readers`, `reader`, `connect` | |
| SIC.open: `NoReadersFoundException`, `CardNotPresentException` | `Error::NoReader`, `Error::NoCard`, `pcsc_transport.rs` `first_dnie` | |
| SIC protocol `*`, negotiated protocol kept | `Protocols::ANY`, `negotiated` | |
| SIC.reset | `PcscTransport::reset`, `reopen` | |
| SIC.close LEAVE_CARD | `Connection` `Drop` | |
| `SCARD_W_RESET_CARD` → LostChannelException | `Error::CardReset`, `recovering` | |
| InvalidCardException, BurnedDnieCardException | `Error::NotDnie`, `Error::BurnedDnie` | |
| DnieCardException, CryptoCardException | `Error::Status` | |
| Timeouts | — | Neither side sets them. |
