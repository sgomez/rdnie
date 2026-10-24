# Research: porting the contact-DNIe subset of JMulticard

Notes for the spec. Source read: `ctt-gob-es/jmulticard` at commit `4ec9494` (2026-04-29), module `jmulticard/` (core) plus `jmulticard-jse` (BouncyCastle `CryptoHelper`) and `jmulticard-jsr268` (PC/SC connection). Paths below are relative to `jmulticard/src/main/java/es/gob/jmulticard/` unless stated. AutoFirma (`clienteafirma`) only carries UI callbacks and a switch to disable the native drivers; nothing in it affects the protocol.

## 1. The subset

### End-to-end flow on a DNIe 3.0/4.0

1. **Reset and classify.** `DnieFactory.getDnie` resets the card, masks the ATR and picks `Dnie3` when ATR byte 15 is `0x04`, `Dnie` (1.0/2.0) otherwise. An ATR ending in `65 81` instead of `90 00` is a burned (blocked) DNIe.
2. **Plain reads, no channel.** `Dnie3` does not need a channel to load certificates (`needsPinForLoadingCerts() == false`):
   - IDESP from `3F00/0006` (selects the key generation, see §2).
   - CDF at `5015/6004`, then each certificate the CDF points to, then the PrKDF at `5015/6001`.
3. **PIN channel** (`Dnie3.openPinChannel`): CWA-14890 mutual authentication with the *PIN* terminal keys.
4. **Retry counter** inside the PIN channel: `VERIFY` with no data, SW `63Cx`.
5. **VERIFY** inside the PIN channel.
6. **User channel** (`Dnie3.openUserChannel`): a second mutual authentication with the *user* terminal keys, on the same card session (no reset). The verified PIN survives it.
7. **Sign** inside the user channel: `MSE SET DST` then `PSO COMPUTE DIGITAL SIGNATURE` over a DigestInfo. `Dnie.sign` closes the connection afterwards.

### Mutual authentication (`connection/cwa14890/Cwa14890OneV1Connection.open`)

| Step | APDU | Notes |
| --- | --- | --- |
| Chip serial | `90 B8 00 00 07` (GET CHIP INFO) | 7 bytes, left-padded to 8 = SN.ICC. Must run before the auth. |
| ICC certificate | SELECT MF by name `Master.File`, SELECT `601F`, READ BINARY | X.509; only its RSA public key is used. |
| Load CA CVC | `00 22 81 B6 [83 02 <ref>]`, then `00 2A 00 AE <C_CV_CA>` | Card checks it against its root. |
| Load IFD CVC | `00 22 81 B6 [83 08 <CHR_C_CV_CA>]`, then `00 2A 00 AE <C_CV_IFD>` | |
| Select keys | `00 22 C1 A4 [83 0C <CHR_C_CV_IFD left-padded to 12>] [84 02 <ICC key ref>]` | |
| Internal auth | `00 88 00 00 <RND.IFD (8) ‖ CHR_C_CV_IFD (8)>` | Card returns 128 bytes. |
| Challenge | `00 84 00 00 08` | RND.ICC. |
| External auth | `00 82 00 00 <128 bytes>` | |

Internal auth check (the driver authenticates the card): decrypt the response with the IFD private key → SIGMIN; apply the ICC public key; if the result is not framed `6A … BC`, recompute with `N.ICC − SIGMIN`. Frame = `6A ‖ PRND1 ‖ Kicc (32) ‖ SHA-1 (20) ‖ BC`; verify `SHA-1(PRND1 ‖ Kicc ‖ RND.IFD ‖ CHR_C_CV_IFD)`.

External auth (the card authenticates the driver): `Kifd` = 32 random bytes, `PRND2` random padding to the key length; frame `6A ‖ PRND2 ‖ Kifd ‖ SHA-1(PRND2 ‖ Kifd ‖ RND.ICC ‖ SN.ICC) ‖ BC`; sign with the IFD private key (raw RSA), take `SIGMIN = min(SIG, N.IFD − SIG)`, encrypt with the ICC public key (raw RSA).

Key derivation: `K = Kicc ⊕ Kifd`; `Kenc = SHA-1(K ‖ 00000001)[0..16]`; `Kmac = SHA-1(K ‖ 00000002)[0..16]`; `SSC = RND.ICC[4..8] ‖ RND.IFD[4..8]`.

### Secure messaging (`connection/AbstractApduEncrypter`, `ApduEncrypterDes`, `ApduEncrypterDesMac8`)

- SSC is incremented (as a 64-bit big-endian counter) before protecting each command and again before checking its response.
- Command: `CLA | 0x0C`; data → ISO 7816-4 padding (`80 00…`, block 8) → 3DES-CBC, zero IV, no further padding → TLV `87 <len> 01 <cryptogram>`; Le, if present, → TLV `97 01 <Le>`; MAC input = `pad(CLA' INS P1 P2) ‖ TLVs`, padded; MAC TLV `8E 08 <mac>`. No Le on the outer APDU.
- MAC: DES-CBC with `Kmac[0..8]` over `SSC ‖ input`, last block through 2-key 3DES. That is ISO/IEC 9797-1 MAC algorithm 3 (retail MAC) over `SSC ‖ input`. DNIe 3.0/4.0 (`Cwa14890OneV2Connection`) keep 8 bytes; DNIe 1.0/2.0 (`Cwa14890OneV1Connection`) keep 4.
- Response: if the outer SW is not `9000`, it is returned as is (`66 88` = bad checksum → channel lost). Otherwise parse `[87] 99 8E`, verify the MAC over `87 ‖ 99` TLVs, decrypt `87`, strip padding, SW comes from `99`.
- Inner SW `6Cxx` → resend with `Le = xx`.
- `61xx` / `6Cxx` on plain commands, and `GET RESPONSE` (`00 C0 00 00 xx`, never protected), are handled one layer below, in `connection/AbstractApduConnectionIso7816.transmit`.

### Classes to port

| Area | Classes |
| --- | --- |
| APDU model (exists in rdnie) | `apdu/CommandApdu`, `ResponseApdu`, `StatusWord` |
| Plain transport behaviour | `connection/AbstractApduConnectionIso7816` (61xx/6Cxx only) |
| Channel | `connection/cwa14890/Cwa14890OneV1Connection`, `Cwa14890OneV2Connection`, `Cwa14890CipheredApdu`, `ChannelType` (PIN/USER only), `SecureChannelException`, `InvalidCryptographicChecksumException` |
| SM codec | `connection/AbstractApduEncrypter`, `ApduEncrypterDes`, `ApduEncrypterDesMac8` |
| Card contract | `card/cwa14890/Cwa14890Card`, `Cwa14890PublicConstants`, `Cwa14890PrivateConstants` |
| DNIe | `card/dnie/Dnie` (auth steps, VERIFY, retries, sign, cert loading), `Dnie3` (two channels, IDESP), `DnieFactory` (ATR mask, IDESP → key set), `DnieAtr`, `DniePrivateKeyReference` |
| Keys | `card/dnie/Dnie3Cwa14890Constants`, `Dnie3r1Cwa14890Constants`, `Dnie3r2Cwa14890Constants`, `Dnie3PinCwa14890Constants`, `Dnie3UsrCwa14890Constants`, `Dnie3r2PinCwa14890Constants`, `Dnie3r2UsrCwa14890Constants` |
| Files | `card/iso7816four/AbstractIso7816FourCard` (select by name/ID/path, chunked READ BINARY of `0xDE` bytes, `6282` EOF), `apdu/iso7816four/SelectFileApduResponse` (FCI → file length), `card/Location` |
| Commands | `apdu/dnie/GetChipInfoApduCommand`, `RetriesLeftApduCommand`, `VerifyApduCommand`; `apdu/iso7816four/SelectDfByNameApduCommand`, `SelectFileByIdApduCommand`, `ReadBinaryApduCommand`, `GetResponseApduCommand`, `GetChallengeApduCommand`, `InternalAuthenticateApduCommand`, `ExternalAuthenticateApduCommand`, `MseSetApduCommand`, `MseSetAuthenticationKeyApduCommand`, `MseSetAuthenticationTemplateApduCommand`, `MseSetComputationApduCommand`; `apdu/iso7816eight/PsoVerifyCertificateApduCommand`, `PsoSignHashApduCommand` |
| Certificates | `card/CompressionUtils` (8-byte header then zlib), `asn1/der/pkcs15/Cdf`, `PrKdf` and the PKCS#15 object types they use, `asn1/der/pkcs1/DigestInfo` (four fixed headers) |

### Left out

- PACE and NFC: `connection/pace/*`, `apdu/iso7816four/pace/*`, `card/dnie/DnieNfc`, `ApduEncrypterAes` (its `decryptResponseApdu` returns `null` anyway), the `62xx → Le−1` retry in `Cwa14890OneV1Connection.transmit` (it belongs to PACE).
- ICAO/LDS: `Dnie3.checkSecurityObjects`, DG1–DG16, SOD, COM, `MrtdLds1`.
- Other cards: `CeresSc*`, `Tif`, GiDe, Ceres APDUs, and every card outside `card/dnie`.
- DNIe 1.0/2.0 (`Dnie` + V1 channel with 4-byte MAC and the `DnieCwa14890Constants` key set). They need the PIN even to read certificates. Adding them later is cheap (same code, MAC length 4, one more key set), but I would leave them out until someone asks.
- `Cwa14890OneV1Connection.reset` (reset the card and reopen the channel): the channel connection is only reachable inside the card class (`getConnection` is protected), and no DNIe code resets it.
- `changePIN`, `cipherData` (`LOAD DATA` + `SIGN DATA`), the `90 C2` envelope for APDUs over 255 bytes (no command in this flow exceeds it), the JCA provider, Android and JSR-268 plumbing.

## 2. Embedded keys and certificates

Per key set: `C_CV_CA` (CVC of the intermediate CA, 210 bytes, `7F21…`), its `CHR` (8 bytes), `C_CV_IFD` (terminal CVC, 209 bytes), its `CHR`, the terminal RSA-1024 private key as modulus + private exponent (no CRT), and two key references shared by every set (`REF_C_CV_CA_PUBLIC_KEY`, `REF_ICC_PRIVATE_KEY`, 2 bytes each).

| Set | CA CVC | Terminal key | Used when |
| --- | --- | --- | --- |
| `Dnie3PinCwa14890Constants` | r1 | r1 PIN | IDESP < `BMP100001` |
| `Dnie3UsrCwa14890Constants` | r1 | r1 user (identical to the DNIe 2.0 set) | IDESP < `BMP100001` |
| `Dnie3r2PinCwa14890Constants` | r2 | r2 PIN | IDESP ≥ `BMP100001`, or IDESP unreadable |
| `Dnie3r2UsrCwa14890Constants` | r2 | r2 user | same |

The comparison is a plain lexicographic `String.compareTo`. Distinct material to embed: 2 CA CVCs, 4 terminal CVCs, 4 terminal private keys.

- **Public exponent.** The classes do not carry `e`. I checked all four keys: `e = 65537` round-trips with every `d`. That is enough to build an `rsa::RsaPrivateKey` (primes recoverable from `n, e, d`).
- **CA component key** (`getCaComponentPublicKey`, a 162-byte SPKI, RSA-1024, the same in every set) is embedded; rdnie uses it to verify the ICC certificate.
- **Licence.** Every source file carries the same header: dual LGPL-2.1-or-later / EUPL-1.1-or-later, © 2012 Dirección General de Modernización Administrativa, Procedimientos e Impulso de la Administración Electrónica. The keys live inside those files under that header, so they have no separate licence. The `pom.xml` says GPL-2.0 + EUPL-1.1, which contradicts the file headers. The headers govern the code we port, but this is worth noting in the attribution. rdnie is `EUPL-1.2`: taking the EUPL-1.1-or-later branch allows it. The same terminal keys also ship in OpenSC (`cwa-dnie.c`, LGPL), which I did not check line by line.
- **Practical notes.** These are "private" keys that are public on purpose. Store them as byte arrays, not PEM, or secret scanners will flag them. The DGP has rotated them once (r1 → r2), so a future rotation means a new release of rdnie.

## 3. Cryptography and crates

| Step | Primitive | Crate | Note |
| --- | --- | --- | --- |
| Random RND.IFD, Kifd, PRND2 | CSPRNG | `getrandom` / `rand_core::OsRng` | |
| Terminal "sign", ICC "encrypt"/"verify" | Raw RSA (no padding) | `rsa` → `rsa::hazmat::{rsa_encrypt, rsa_decrypt_and_check}` | |
| `N − SIG`, `min` | Bignum arithmetic | `rsa::BigUint` (re-export) | Arithmetic, not a primitive. |
| 6A…BC framing | ISO/IEC 9796-2 DS scheme 1 | **No crate** | Byte layout plus one hash compare. It is message formatting, not a primitive, so writing it by hand does not break constraint 2. Say so in the spec. |
| Auth hashes, KDF | SHA-1 | `sha1` | |
| DigestInfo | SHA-1/256/384/512 | `sha2`, `sha1` (only if rdnie hashes) | The headers are fixed bytes. Better: take a digest plus algorithm from the caller. |
| SM encryption | 2-key 3DES-CBC, zero IV, no padding | `des` (`TdesEde2`) + `cbc` | |
| SM MAC | ISO 9797-1 alg. 3 (retail MAC) | `retail-mac` 0.1.0 with `des::Des` | RustCrypto/MACs, released 2026-04-10, MSRV 1.85 = rdnie's. Eager buffer: block-aligned input gets no extra block, so pre-padded `SSC ‖ data` with key `Kmac` (K‖K′) matches JMulticard. Verify with vectors anyway. |
| SM padding | ISO 7816-4 method 2 | Hand-written (a few lines) or `block-padding::Iso7816` | |
| ICC and holder certs | X.509 DER | `x509-cert` (+ `der`) | |
| PKCS#15 CDF/PrKDF | DER | `der` (derive) | |
| Compressed certs | zlib | `flate2` (miniz_oxide backend) | Not RustCrypto, but not crypto either. |
| Secrets in memory | — | `zeroize`, `subtle` (constant-time MAC compare) | |

**Gaps:** only ISO 9796-2 framing. Retail MAC is now covered.

**Version trap.** RustCrypto is mid-migration. `des` 0.9, `cbc` 0.2, `retail-mac` 0.1 and `sha1` 0.11 are on `cipher` 0.5 / `digest` 0.11. Stable `rsa` is 0.9.10 (`digest` 0.10, `spki` 0.7), and 0.10 is still `rc.19`. `x509-cert` 0.3 is on `der` 0.8 / `spki` 0.8. Proposal: `rsa` 0.9 + `x509-cert` 0.2 (same `der`/`spki` generation) for RSA and ASN.1, and the new generation for SM. The two generations coexist (some duplicate `sha` crates) and only meet through bytes. Move to `rsa` 0.10 once it is stable. `rsa` triggers RUSTSEC-2023-0071 (Marvin). It does not apply here, because the only private key is public, but `cargo audit`/`deny` will need an exception.

## 4. DNIe 3.0 vs 4.0

- JMulticard has **no code difference**: both reach `Dnie3` through ATR byte 15 = `0x04`, and its log message says "DNIe 3.0 o 4.0".
- The only branching is the IDESP threshold that picks r1 or r2 keys, and it cuts across both versions. I expect 4.0 cards to fall in r2, but have not confirmed it.
- Both versions also expose PACE over NFC, which is out of scope.
- What needs checking on a real 4.0: its ATR (to add to the `is_dnie` tests), which key set it takes, FCI layout, holder key size (2048 in 3.0), and whether the PIN state survives the switch to the user channel.
- The current `is_dnie` accepts any `3B … 6A "DNIe"` ATR. It distinguishes neither 3.0/4.0 from 1.0/2.0 (byte 15) nor a burned card (`65 81`).

## 5. Risks

### PC/SC and the system drivers

- JMulticard connects in `SHARED` mode and never calls `beginExclusive` (no `setExclusiveUse` caller). It resets the card (`SCARD_RESET_CARD`) when it starts, and on close it disconnects with `LEAVE_CARD`.
- On **Windows**, the DGP minidriver is loaded by the smart-card subsystem (Plug and Play, Certificate Propagation) when a card is inserted, and it opens its own channels. Any APDU it slips into our session breaks the SSC (`66 88`, or a reset).
  - Mitigation: wrap each operation in `SCardBeginTransaction` (`pcsc::Card::transaction`, safe API), detect `SCARD_W_RESET_CARD`, and reopen the channel.
  - Microsoft documents that a transaction idle for more than 5 s gets the card reset. So **never hold a transaction while waiting for the PIN**. Read the counter in one transaction, ask for the PIN outside it, then reopen the channel, re-read the counter and VERIFY in another.
  - Try `SHARE_EXCLUSIVE` only as a probe: it fails while CertPropSvc holds the card.
- On **Linux** (OpenSC with its DNIe driver, via p11-kit/NSS) and **macOS** (an OpenSC CTK token, if installed), the same contention exists. It is less aggressive because nobody opens the card on insertion unless asked.
- **Reset or no reset at the start?** Decided: no reset (see `docs/parity.md`, "DnieFactory.getDnie reset on start"). With another app's channel open, the card answers a plain `SELECT` `69 87` once and then accepts it (#133, #138).
- **Close as JMulticard.** rdnie never resets the card on its own, and closing leaves the card (`LEAVE_CARD`).
- **Transport seam.** The `Transport` trait today only has `transmit_raw`. It needs reset, a transaction scope, and the 61xx/6Cxx/GET RESPONSE handling below the SM layer. The emulator must implement all three.

### What only the real card can validate

All of these are run by hand by the card's holder, and logs carry status words only:

- FCI layout (`SelectFileApduResponse` reads lengths from tags `81` or `85`; it is brittle). rdnie keeps JMulticard's parsing; the probe passed on the SLE78 chip, and a DNIe 4.0 or the 19WL34 chip is still unchecked.
- r1/r2 key selection on 3.0 and 4.0.
- Behaviour of `GET RESPONSE` with a 2048-bit signature over SM.
- The PIN state surviving the switch to the user channel.
- Coexistence with the Windows minidriver and with OpenSC.
- The ICC certificate verifying against the CA component key, if we decide to check it.

Never log or commit: IDESP, chip serial (GET CHIP INFO), certificates, CDF/PrKDF contents, the key paths if they vary by card. `TestApduEncrypter.java` (in `jmulticard-jse`) has DES/AES session vectors. Review it before reusing it: one of its tests is named `SSC_PIN`.

## 6. Proposed issue slices

My honest take on the ordering: **the emulator cannot wait until the end**. The mutual authentication can be tested in software from day one: the terminal key is public, and an emulator can generate its own ICC key pair and certificate. Without that, every slice of 0.1 can only be validated on the real card, which goes against the TDD in the `justfile`. I propose a minimal emulator alongside the channel, and the full CI emulator later.

**0.1: channel, certificates and counter, no PIN**

1. **Transport seam.** Reset, transaction scope, 61xx/6Cxx/GET RESPONSE, ATR classification (3.0/4.0, legacy, burned). `PcscTransport` with `pcsc::Transaction`.
2. **SM codec** (pure). Protect/unprotect, SSC, TLV `87/97/99/8E` with real BER lengths, 3DES-CBC, retail MAC 8. Tests with vectors.
3. **Embedded key sets.** r1/r2 × PIN/user, selection by IDESP, `RsaPrivateKey` with `e = 65537`, attribution header.
4. **Mutual authentication** plus a **minimal emulator** for the card side of the handshake (its own ICC key, CVCs accepted without checking).
5. **File system and certificates.** SELECT by name/ID/path, chunked READ BINARY, FCI, IDESP, CDF/PrKDF, zlib decompression, `x509-cert`.
6. **Retry counter.** Open the PIN channel and parse `63Cx`/`6983` strictly.
7. **Real-card probe** (manual checklist, outside CI). The §5 list, on 3.0 and 4.0, on all three systems.

**0.2: VERIFY and signing**

8. **VERIFY.** Format checks, retries read in the same session, one attempt, PIN zeroized, transaction released while asking for the PIN.
9. **Signing.** User channel, `MSE SET DST` with the PrKDF key ID, `PSO CDS` over the DigestInfo of a caller-supplied digest (SHA-256/384/512). Closing leaves the card.

**0.3: CI emulator**

10. **Full emulator.** Fake file system (CDF/PrKDF/certificates generated in the test), PIN state machine with retries and blocking, both channels, signing with a test key. It runs on all three systems' CI.

Open questions for the spec:
- Should we verify the ICC certificate?
- Should DNIe 1.0/2.0 stay out for good?
- Should rdnie hash, or only accept digests?
- Reset or no reset when the session starts? No reset: see `docs/parity.md`, "DnieFactory.getDnie reset on start".
