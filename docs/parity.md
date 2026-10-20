# Parity with JMulticard

Snapshot comparing JMulticard `4ec9494` with rdnie `541afb1`. Line numbers rot; re-run the comparison rather than trusting them after either side moves. Java paths are relative to `jmulticard/src/main/java/es/gob/jmulticard/` unless they name another module (`SIC` = `jmulticard-jsr268/.../SmartcardIoConnection.java`). rdnie paths are relative to `src/`. Scope is the one in [`research/jmulticard-port.md`](research/jmulticard-port.md); its "Left out" list is classified as out of scope here.

Status: **Impl** (same behaviour), **Diff** (implemented differently, harmless unless noted), **Intentional** (rdnie diverges on purpose), **Missing**, **Out of scope**.

## Summary

The protocol is at parity: ATR classification, IDESP → key set, the CWA-14890 handshake, secure messaging, file access, PKCS#15, retries, VERIFY, MSE SET DST and PSO CDS produce the same APDUs as JMulticard. What remains is at the API and transport edges.

## Gaps

Ordered by importance.

1. **The intermediate CA certificate is discarded.** Java hides keyless CDF certificates from `getAliases` but keeps them reachable by alias; the JSE provider uses `CertCAIntermediaDGP` to build the signing chain (Dnie.java:942, `jmulticard-jse` DnieKeyStoreImpl.java:80). rdnie reads it and drops it (`certificates.rs` `load`), so a consumer cannot embed the chain.
2. **No certificate label or role.** `CertificateObject.getAlias` (CertificateObject.java:150) and `Dnie.getAliases` (Dnie.java:429) tell the authentication certificate from the signing one. rdnie exposes neither; callers parse X.509 KeyUsage (`examples/probe.rs`).
3. **Coarse error taxonomy.** "No reader", "no card" and "card removed" surface as `Error::Transport(String)` or `Error::NoDnie`, indistinguishable from "card is not a DNIe". Java has `NoReadersFoundException`, `CardNotPresentException` and `InvalidCardException` (SIC:280, :298; DnieFactory.java:312). `Error` is not `#[non_exhaustive]` (`error.rs`), so adding variants later is a breaking change.
4. **`PcscTransport::reset` can panic afterwards.** It disconnects (leaving `Connection(None)`) and returns early if the reconnect fails; the next `transmit_raw`, `atr`, `transaction` or `reset` panics in `Deref::expect`. Java throws `ApduConnectionException` (SIC:322-340). Reachable only when a consumer calls `Transport::reset` directly.
5. **No reader listing or selection, and no recovery after removal.** Java has `getTerminals`, `getTerminalInfo`, `setTerminal` (SIC:165, :231, :372); rdnie always takes the first reader with a DNIe ATR. After `RemovedCard` the transport stays dead (it only reconnects on `CardReset`), which is undocumented.
6. **Response parsing is stricter than Java's.** rdnie rejects bytes after `8E`, a `99` value that is not 2 bytes, and an `87` cryptogram not starting with `01` (`secure_messaging.rs` `unprotect`, `decrypt`); `ApduEncrypterDes.decryptResponseApdu` accepts them. Confirm with the manual real-card probe that a DNIe 3.0/4.0 never sends them.
7. **Unbounded `61xx`/`6Cxx` loops**, on both sides (`transport.rs` `transmit`, `secure_messaging.rs` resend; AbstractApduConnectionIso7816.java:107-132, V1:755-758). A card or reader that keeps answering them recurses until the stack overflows. A retry cap is cheap.
8. **FCI layouts other than `81`/`85` read as length 0**, on both sides (`files.rs` `file_length`, SelectFileApduResponse.java:66): a certificate would read empty and fail, and the IDESP would silently become `None` (r2 keys). Confirm the FCI layout on a DNIe 4.0. Related and latent on both sides: READ BINARY advances by `0xDE` even after a short read, and offsets ≥ `0x8000` are not guarded.
9. **Certificates are not cached.** Java loads them once (Dnie.java:847); every `Session::certificates` call re-reads CDF, certificates and PrKDF. Latency only.
10. **Minor:**
    - `StatusWord` displays hex only; `StandardErrorCodes` gives text (StandardErrorCodes.java:17-50).
    - `DnieAtr.toString` (chip, OS version, lifecycle) is not ported; diagnostics only.
    - rdnie accepts 8–16 printable ASCII PIN characters (`pin.rs` `check_format`); Java sends any `char` as its low byte. Correct for DNIe PIN rules, but worth a line in the docs.
    - `DnieCertParseUtil` (holder name and number from the subject) is not ported and has no caller in the core; add it to "Left out".
    - `Cwa14890OneV1Connection.reset` (reset and transparently reopen the channel) is not ported; nothing in the DNIe 3 flow calls it.

## Intentional divergences

Stated as requirements; each is deliberate and tested.

- RND.IFD, Kifd and PRND2 come from the OS CSPRNG and differ on every handshake.
- The ICC public key used in the handshake comes from a component certificate chain (`3F00/6020`, `3F00/601F`) that ends in an embedded DNIe component root.
- Response MACs are compared in constant time, over the exact `87‖99` byte span.
- Retries are accepted only from `63Cx`; `6983` means blocked; anything else is an error. They are re-read before VERIFY in the same transaction, VERIFY is skipped if they are 0 or differ from the count shown, and an operation makes at most one PIN attempt.
- A card reset mid-operation returns `Error::CardReset`; the operation is never retried automatically.
- No PIN is kept between operations; each signature takes a new `Pin`, zeroized after VERIFY. The PIN format is checked before any APDU.
- No secure channel outlives an operation: each operation runs in one PC/SC transaction (`SCardBeginTransaction`) and opens its own channels.
- The caller supplies the digest; SHA-256/384/512 only.
- Only short APDUs; anything longer fails with `CommandTooLong` before reaching the card.
- The card is selected by its ATR without resetting other readers' cards.

## Exclusions reviewed

All "Left out" items hold for a signing driver: PACE/NFC (including the in-channel `62xx` → Le−1 resend), ICAO/LDS, other cards, DNIe 1.0/2.0, `changePIN`, `cipherData`, SHA-1, the JCA provider and the `90 C2` envelope. The largest command in scope (protected PSO VERIFY CERTIFICATE with the 210-byte CA CVC) is 235 bytes, so the envelope is not needed while the CVCs keep their size.

## Detail

### Secure channel

`V1` = `connection/cwa14890/Cwa14890OneV1Connection.java`, `Des` = `connection/ApduEncrypterDes.java`, `Abs` = `connection/AbstractApduEncrypter.java`.

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| V1.open order (V1:203-356) | `cwa14890.rs` `open` | Impl | |
| V1.open closes the connection on a failed stage | `cwa14890.rs` `open` | Diff | rdnie drops the half-built channel and keeps the handle; the next operation starts a fresh handshake. |
| V1.getPaddedSerial, `90 B8 00 00 07` | `cwa14890.rs` `padded_serial` | Impl | |
| Dnie.verifyIcc (Dnie.java:439) | `cwa14890.rs` `icc_public_key` | Intentional | See divergences. |
| Dnie.getIccCertPublicKey (Dnie.java:444) | `cwa14890.rs` `read_certificate` | Impl | Trailing bytes after the certificate ignored. |
| Dnie.verifyIfdCertificateChain (Dnie.java:469-512) | `cwa14890.rs` `verify_ifd_certificate_chain` | Impl | |
| MseSetAuthenticationKeyApduCommand, `C1 A4 [83 0C CHR] [84 02 ref]` | `cwa14890.rs` `internal_authentication` | Impl | |
| V1.internalAuthValidateInternalAuthenticateMessage (V1:461-572) | `cwa14890.rs` `validate_internal_authentication` | Diff | Same checks; rdnie sizes the frame from the ICC modulus and rejects SIGMIN ≥ N.ICC up front. |
| AbstractIso7816FourCard.getChallenge | `cwa14890.rs` `challenge` | Diff | rdnie requires exactly 8 bytes. |
| V1.externalAuthentication (V1:612-693) | `cwa14890.rs` `external_authentication` | Impl | |
| BcCryptoHelper.generateRandomBytes | `cwa14890.rs` `random` | Intentional | OS CSPRNG. |
| V1.generateKenc / generateKmac / generateSsc | `secure_messaging.rs` `derive`, `session_key` | Impl | Session secrets zeroized. |
| Dnie3*Cwa14890Constants, DnieFactory.getDnie3{Pin,Usr}Cwa14890Constants | `key_sets.rs` `KeySet::for_card`, `KeyGeneration::of_card` | Impl | Empty or unreadable IDESP → r2; `< BMP100001` → r1. No fallback to the other generation in either. |
| Abs.protectAPDU (Abs:84-127) | `secure_messaging.rs` `protect` | Impl | Tested with JMulticard vectors. |
| Des.generateMac, 8-byte MAC (Mac8) | `secure_messaging.rs` `authenticator` | Impl | ISO 9797-1 alg. 3. |
| SSC increments (V1:728, :744) | `secure_messaging.rs` `protect`, `unprotect` | Impl | |
| Des.decryptResponseApdu, outer SW ≠ 9000 | `secure_messaging.rs` `unprotect` | Impl | |
| Des.decryptResponseApdu, `[87] 99 8E` parse | `secure_messaging.rs` `unprotect`, `read_tlv` | Diff | Stricter; gap 6. |
| Des.verifyMac | `secure_messaging.rs` `verify_mac` | Intentional | Constant time. |
| Abs.removePadding7816 | `secure_messaging.rs` `unpadded_len` | Impl | |
| V1.transmit `66 88` | `Error::ChannelLost` | Impl | No recovery on either side. |
| V1.transmit inner `6Cxx` resend | `secure_messaging.rs` `transmit` | Impl | Unbounded on both sides; gap 7. |
| V1.transmit inner `62xx` → Le−1 | — | Out of scope | PACE. |
| V1.close | `SecureMessaging` `Drop` | Diff | Drops and zeroizes the keys; the handle stays with `Session`. |
| V1.reset (V1:773-784) | `Protected::reset` → error | Missing | Gap 10. |
| Dnie3.openPinChannel (Dnie3.java:213) | `pin.rs` `open_pin_channel` | Impl | MF select failure ignored only for status errors. |
| Dnie3.openUserChannel (Dnie3.java:249) | `pin.rs` `open_user_channel`, `Protected` | Impl | User channel nested in the PIN channel. |
| Dnie.isSecurityChannelOpen / openSecureChannelIfNotAlreadyOpened | `session.rs` `operation` | Intentional | Fresh channels per operation. |
| Dnie.signOperation retry on `LostChannelException` (Dnie.java:298-309) | `Error::CardReset` | Intentional | No automatic retry. |

### Card operations, PIN and signing

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| DnieFactory.getDnie reader loop with reset per reader (DnieFactory.java:230) | `pcsc_transport.rs` `connect_first_dnie`, `session.rs` `open_trusting` | Intentional | Only the chosen card is reset. |
| DnieFactory.ATR, ATR_MASK | `atr.rs` `DNIE_ATR`, `DNIE_ATR_MASK` | Impl | |
| Atr.equals, right-aligns short ATRs | `atr.rs` `matches_mask` | Diff | rdnie requires 20 bytes, as every DNIe ATR has. |
| byte 15 `0x04` → Dnie3 | `atr.rs` `check_dnie_3` → `Error::LegacyDnie` | Impl | DNIe 4.0 takes the same path. |
| burned ATR `… 65 81` | `atr.rs` → `Error::BurnedDnie` | Diff | rdnie also requires the DNIe historical bytes. |
| DnieAtr.toString | — | Missing | Gap 10. |
| Dnie.getIdesp, Dnie3 constructor | `session.rs` `read_idesp` | Impl | Read once at open; exposed only as `key_generation`. |
| Dnie constructor eager `loadCertificates` | `Session::certificates` | Diff | Lazy, no cache; gap 9. |
| CryptoCard.getAliases, getCertificate(alias) | `Session::certificates` → `Certificate { der, key }` | Missing (partial) | Gap 2. |
| Dnie.getPrivateKey, DniePrivateKeyReference | `certificates.rs` `KeyReference { id, file }` | Diff | Keeps what MSE SET DST needs; the rest only serves `cipherData`. |
| Dnie.getPinRetriesLeft, `00 20 00 00 00` | `pin.rs` `query_retries`, `retries_in` | Intentional | Same APDU; see divergences for SW handling. |
| Dnie3.getPinRetriesLeft | `Session::pin_retries` | Diff | Always a fresh PIN channel; no PIN needed. |
| Dnie.getInternalPasswordCallback, empty PIN / locked | `pin.rs` `check_format`, `Error::InvalidPinFormat`, `Error::PinBlocked` | Diff | No callbacks; the PIN is a parameter. |
| Dnie.verifyPin + VerifyApduCommand | `pin.rs` `verify`, `refusal` | Impl | Same APDU. `63Cx` x>0 → `WrongPin`, `63C0`/`6983` → `PinBlocked`. |
| Dnie.passwordCallback reused across operations | `Pin` consumed by `sign` | Intentional | |
| Dnie.sign → signOperation: MSE SET DST `00 22 41 B6 84 02 <key file>`, PSO CDS `00 2A 9E 9A` | `session.rs` `sign`, `signature.rs` `sign` | Impl | Byte-identical. |
| DigestInfo.encode, DigestAlgorithm | `signature.rs` `digest_info`, `HashAlgorithm` | Intentional | Caller supplies the digest; SHA-1 not ported; SHA-224 and raw RSA unsupported in both. |
| Dnie.sign closes with LEAVE_CARD | `pcsc_transport.rs` `Drop` | Impl | |
| Multiple signatures per session | `Session::sign` | Impl | Each takes its own `Pin`. |
| Dnie.changePIN, cipherData, LoadData/SignData | — | Out of scope | |
| PinException, BadPinException, AuthenticationModeLockedException | `Error::{InvalidPinFormat, WrongPin, PinBlocked, PinRetriesChanged}` | Impl | |
| callback/*, CancelledOperationException | — | Out of scope | |

### Files, PKCS#15 and certificates

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| AbstractIso7816FourCard.MAX_READ_CHUNK `0xDE` | `files.rs` | Impl | |
| readBinary / readBinaryComplete | `files.rs` `read_binary_complete` | Impl | `6282` keeps the chunk and stops; `6B00` stops. Gap 8 for short reads. |
| selectFileByName | `files.rs` `select_master_file` | Diff | Only `Master.File`; FCI ignored. |
| selectFileById, selectFileByLocation(AndRead) | `files.rs` `select`, `read` | Impl | `6A82`/`6982` kept as `Error::Status`. |
| readAllRecords, ReadRecordApduCommand | — | Out of scope | Only used outside the core. |
| SelectFileApduResponse.getFileLength | `files.rs` `file_length` | Impl | Bounds-checked; gap 8. |
| Location | `files.rs` `Location` | Impl | |
| CompressionUtils (8-byte header + zlib, fallback to raw) | `certificates.rs` `decompressed`, `inflate` | Impl | |
| Dnie.loadCertificates: CDF `5015/6004`, certificates, PrKDF `5015/6001` | `certificates.rs` `load` | Impl | Any bad file fails the whole load, in both. |
| CDF id ↔ PrKDF id pairing | `certificates.rs` `load` | Impl | |
| Dnie.hideCertsWithoutKey, keyless certs reachable by alias | `certificates.rs` `load` | Missing (partial) | Gap 1. |
| PrKDF fallback to CeresScPrKdf | `pkcs15.rs` `entry` | Diff | The tolerant parse accepts what the fallback exists for. |
| Cdf / PrKdf, up to 10 objects | `pkcs15.rs` `entries` | Impl | |
| Pkcs15Object mandatory fields | `pkcs15.rs` `entry` | Diff | rdnie reads only identifier and path. |
| CertificateObject.getAlias | — | Missing | Gap 2. |
| CertificateObject issuer / subject / serial, PrivateKeyObject reference / length / name | — | Out of scope | Only `toString` and `cipherData` use them. |
| Odf | — | Out of scope | Paths are hard-coded on both sides. |
| DnieCertParseUtil | — | Missing | Gap 10. |

### APDU model, transport and errors

| JMulticard | rdnie | Status | Notes |
| --- | --- | --- | --- |
| CommandApdu short encoding | `apdu.rs` `Command::to_bytes` | Impl | |
| CommandApdu extended Lc / Le | `Error::CommandTooLong` | Intentional | Short APDUs only. |
| Le 256 | `to_bytes` → `00` | Impl | Same wire bytes as `RetriesLeftApduCommand`. |
| CommandApdu.setLe on `6Cxx` | `transport.rs` `transmit` | Diff | rdnie keeps Lc on the resend. |
| ResponseApdu, StatusWord | `apdu.rs` `Response`, `StatusWord` | Impl | Short responses → `TruncatedResponse`. |
| StatusWord.toString via StandardErrorCodes | `StatusWord` `Display` | Missing | Gap 10. |
| `61xx` → GET RESPONSE, `6Cxx` resend for CLA 00 | `transport.rs` `transmit`, `get_response` | Impl | Gap 7. |
| EnvelopeDataApduCommand (`90 C2`) | — | Out of scope | |
| ApduConnection.getTerminals / getTerminalInfo / setTerminal | — | Missing | Gap 5. |
| SIC ignoreVirtualReaders | `connect_first_dnie` ATR filter | Diff | |
| SIC.open: `NoReadersFoundException`, `CardNotPresentException` | `Error::Transport`, `Error::NoDnie` | Missing | Gap 3. |
| SIC protocol `*`, negotiated protocol kept | `Protocols::ANY`, `negotiated` | Impl | |
| SIC.setExclusiveUse | `PcscTransport::transaction` | Intentional | One transaction per operation. |
| SIC.reset | `PcscTransport::reset` | Diff | Gap 4. |
| SIC.close LEAVE_CARD | `Connection` `Drop` | Impl | |
| `SCARD_W_RESET_CARD` → LostChannelException | `Error::CardReset`, `recovering` | Impl | |
| Card removed mid-operation | `Error::Transport` | Diff | Gaps 3 and 5. |
| InvalidCardException, BurnedDnieCardException | `Error::NotDnie`, `Error::BurnedDnie` | Impl | |
| DnieCardException, CryptoCardException | `Error::Status` | Impl | |
| Timeouts | — | Impl | Neither side sets them. |
| UnavailableReaderException, ICAO / PACE exceptions | — | Out of scope | |
