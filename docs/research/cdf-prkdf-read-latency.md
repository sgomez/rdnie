# Research: why reading the CDF and the PrKDF takes ~520 ms

Notes for #145. Measurements from #133 (reader Alcor Micro AU9540, DNIe 4.0, pcsc-lite, 0.2.0 code): `open` 18–25 ms, `certificates()` 520–524 ms, `certificate(SIGNATURE_LABEL)` 209–212 ms, `certificate(INTERMEDIATE_CA_LABEL)` 210–213 ms.

Sources: rdnie at `e324a8e` (paths relative to the repo); `ctt-gob-es/jmulticard` at [`4ec9494`](https://github.com/ctt-gob-es/jmulticard/tree/4ec9494f181a2e94d4aeaf62b63a30bcd98f4624), paths relative to `jmulticard/src/main/java/es/gob/jmulticard/` unless stated; OpenJDK `ChannelImpl` at [`jdk-21+35`](https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/java.smartcardio/share/classes/sun/security/smartcardio/ChannelImpl.java). ISO sections are from the 2005/2006 editions and were not re-read for this note (paywalled).

**Conclusion.** Padding, confirmed by the probe (§5). The CDF and the PrKDF each announce 2100 bytes in their FCI, but their PKCS#15 objects end after ~900 and ~200 bytes; the rest is `00`. rdnie reads to the FCI length, and at ~104 µs per byte the ~3 KB of padding cost ~320 ms of the 520. Extra SELECTs and T=0 `GET RESPONSE` add ~25 ms per file. Certificate files carry no padding.

## 1. What rdnie sends

### Shared path

- No secure channel. `labels()` (formerly `certificates()`, same I/O: `src/session.rs:110-114`, 0.2.0 `src/session.rs:132-135`) and `certificate()` run each read through `operation`, which wraps the PC/SC port in a `PlainChannel` (`src/session.rs:234-240`). No CWA-14890 protection, no SSC, no MAC.
- One PC/SC transaction per `operation` (`src/pcsc_transport.rs:247-254`, `275-286`). `labels()` makes two (CDF, then PrKDF, each through `cached`: `src/session.rs:111-112`, `242-253`). `certificate()` makes one, because the CDF is already cached when the probe calls it (`examples/probe.rs:75-90`, `src/session.rs:130`).
- `files::read` (`src/files.rs:38-45`):
  1. `SELECT` the MF by name `Master.File` (`src/files.rs:48-52`, `62-65`).
  2. `SELECT` by FID each element of the path, after dropping `3F00` (`src/files.rs:21-29`, `41-43`). The length comes from the FCI of the last one (`src/files.rs:85-115`, tag `81`, or `85` with length 10).
  3. `READ BINARY` from offset 0 in chunks of `0xDE` bytes, with `Le = min(length − offset, 0xDE)`, until offset ≥ FCI length. It stops early only on `6282` or `6B00` (`src/files.rs:129-157`). It never looks at the content.
- APDU encoding (`src/apdu.rs:28-43`): `SELECT` carries data and no Le (case 3 at the APDU level, `src/files.rs:67-76`). `READ BINARY` carries only Le (case 2).
- Below that, `PlainChannel` (`src/channel.rs:34-70`): on `61xx` it sends `GET RESPONSE` with Le = xx (`src/channel.rs:55-67`). On `6Cxx` it resends with Le = xx, at most twice in a row (`src/channel.rs:51-54`, `src/resend.rs:35-50`). On `69 87` it resends once (`src/channel.rs:44-50`).

### T=0

The DNIe ATRs in the tests start `3B 7F` (`src/atr/tests.rs:4`, `9`). T0 = `7F` has no TD1, so the card offers T=0 only, and rdnie connects with T=0 (`src/pcsc_transport.rs:114-143`). Under T=0 a command that returns data and also carries data (the SELECT returning its FCI) cannot get its response in the same TPDU. The card answers `61xx`, and the data comes with `GET RESPONSE` (ISO/IEC 7816-3:2006 §12.2, case 4; status words in ISO/IEC 7816-4:2005 §5.1.3). A case-2 READ BINARY with an Le the card accepts returns data and `9000` in one exchange. A `6Cxx` comes only when Le does not fit (7816-3 §12.2, case 2). Since rdnie derives each Le from the FCI length, `6Cxx` is not expected unless that length exceeds the physical file.

### APDU count per `files::read`

With `d` = path elements after `3F00`, `g` = 1 if the card answers a SELECT with `61xx` (0 otherwise), `g0` the same for the MF selection, `L` = FCI length:

`N = (1 + g0) + d·(1 + g) + ⌈L / 222⌉` (+1 per `6Cxx`)

| Call | Files | SELECT exchanges | READ BINARY |
| --- | --- | --- | --- |
| `Session::open` | IDESP `3F00/0006`, `d = 1` (`src/session.rs:20`) | 2–4 | 1 (a short string) |
| `labels()` | CDF `5015/6004` and PrKDF `5015/6001`, `d = 2` each (`src/certificates.rs:17-18`) | 2 × (3–6) = 6–12 | `⌈L_cdf/222⌉ + ⌈L_prkdf/222⌉` |
| `certificate(label)` | the path in the CDF entry, `d` per card | `(1+g0) + d(1+g)` = 2–6 | `⌈L_cert/222⌉` |

What the code cannot say: `g0`, `g`, the `d` of the certificate paths and every `L`.

## 2. JMulticard

- **Same read algorithm.** `selectFileByLocationAndRead` selects the MF, then each FID of the path, keeps the last FCI length (`card/iso7816four/AbstractIso7816FourCard.java:284-307`), and reads to that length in `0xDE` chunks. It stops early only on `6282`/`6B00` (`AbstractIso7816FourCard.java:86`, `161-208`). It does not stop at the end of the DER either.
- **Select by path from the MF, by FID.** `SelectDfByNameApduCommand` and `SelectFileByIdApduCommand` also send no Le (`apdu/iso7816four/SelectDfByNameApduCommand.java:57-65`, `SelectFileByIdApduCommand.java:60-68`). `Location` drops `3F00` (`card/Location.java:186-188`). `Dnie.selectMasterFile` is a SELECT by name (`card/dnie/Dnie.java:403-405`).
- **Same 61xx/6Cxx handling, one layer lower.** `AbstractApduConnectionIso7816.transmit` handles them (`connection/AbstractApduConnectionIso7816.java:104-133`). On PC/SC the JDK already does it: `SmartcardIoConnection.internalTransmit` calls `CardChannel.transmit` (`jmulticard-jsr268/.../SmartcardIoConnection.java:423`), and `ChannelImpl.doTransmit` resends on `6Cxx` and issues `GET RESPONSE` on `61xx` by default on T=0 (`ChannelImpl.java:117-118`, `183-216`). The card sees the same exchanges as with rdnie.
- **Reads everything, once.** `Dnie.loadCertificates` runs from the constructor (`card/dnie/Dnie.java:181`). It selects the MF, reads the CDF, then **every** certificate the CDF lists, then the PrKDF (`Dnie.java:859-891`). `Dnie3` needs no PIN for it (`card/dnie/Dnie3.java:284-286`). The certificates stay in a map, and `getCertificate` serves them from it (`Dnie.java:130`, `433-435`). That is one extra MF SELECT per session compared with rdnie, plus a full read of each certificate.
- **It too tolerates bytes after the objects.** `Cdf`/`PrKdf` are `Record`s of up to 10 optional objects (`asn1/der/pkcs15/Cdf.java:56-67`). `Record.decodeValue` never checks that it consumed the whole buffer (`asn1/der/Record.java:91-126`). This tolerates trailing padding without proving it.
- **The CDF may carry DNs.** JMulticard's `X509CertificateAttributes` allows `subject`, `issuer` and `serialNumber` after the path (`asn1/der/pkcs15/X509CertificateAttributes.java:52-56`, `67-84`). If the DNIe fills them, the CDF holds the holder's name and number (see §4, privacy) and is larger by content, not by padding.

So JMulticard would pay the same per file. It just front-loads it all into opening the card.

## 3. The hypotheses

Write `a` for the fixed cost of one exchange and `c` for the cost per response byte.

**Calibration from `open`.** `open` is 2 SELECTs (+0–2 `GET RESPONSE`) and 1 short READ, so 3–5 exchanges and one transaction in 18–25 ms. That gives **a ≈ 4–7 ms** per short exchange, transaction share included. A cross-check from #133: before #138, a card with a leftover channel answered the first SELECT `69 87` and `open` stopped there. That run took 7 ms, for one exchange and one transaction.

**H2, path selection per file: real but small.** The code shows 6 SELECTs for `labels()` against `1 + d` for a certificate. Each costs 1–2 exchanges, so `labels()` spends 30–85 ms on SELECTs and the certificate 10–40 ms. That leaves a 20–75 ms difference, not ~310. A follow-up could save part of it: the PrKDF sits in the DF already selected for the CDF, so a single `SELECT 6001` would replace MF + `5015` + `6001`. That departs from JMulticard.

**H3, T=0 round trips: real for SELECT, not the cause.** The code proves a SELECT costs 2 exchanges if the card answers `61xx`, which T=0 implies for an FCI. It also proves READ BINARY always asks for an exact Le, so no `6Cxx` is expected. The extra `GET RESPONSE` counts in proportion to the SELECTs, so it is already inside the H2 bound. JMulticard pays the same through the JDK. A probe settles `g0`, `g` and whether any `6Cxx` appears.

**H1, reading to the FCI length: the code proves rdnie (and JMulticard) does it. Whether the FCI length exceeds the content, only the probe can say.** Indirect evidence:

- Take off the SELECTs above and the READ BINARY time is ~430–490 ms for the two directories against ~170–200 ms for a certificate. Same code, same card, same chunk size, so the directories read ≈ 2.2–2.9 × the chunks (≈ bytes) of one certificate file.
- A certificate file cannot be small. Under its zlib, a 2048-bit RSA certificate (the holder key size, `docs/research/jmulticard-port.md` §4) carries a 256-byte modulus and a 256-byte signature, which are random and do not compress. So `L_cert` ≳ 0.6 KB, and the directory files total ≳ 1.4 KB, likely more.
- The PKCS#15 content that rdnie decodes (label, ID, path, flags per object; `src/pkcs15.rs:30-69`) runs on the order of 100 bytes per object, for 3 certificates and 2 keys. That falls short of the bound unless the CDF also carries subject and issuer DNs.

The likely outcome is padding up to an allocated size, but a CDF large by content (DNs) is still open. The probe tells them apart: it compares the FCI length with the DER extent.

**Per-byte cost.** The measurements cannot separate `a` from `c` without `L_cert`. For reference, TA1 = `96` in the test ATRs encodes Fi = 512, Di = 32 (ISO/IEC 7816-3:2006 §8.3). At 4 MHz that is a 4 µs etu, 12 etu per T=0 character (§7.1–7.2), so ≈ 11 ms of line time per 222-byte chunk. That holds only if the AU9540 negotiates TA1. At the default Fd/Dd = 372/1 a single chunk would take ~250 ms, which the 210 ms certificate read rules out. So per chunk ≈ a + 222·c ≈ 15–30 ms, and `labels()` reads roughly 15–30 chunks, ≈ 3–6 KB. The probe's Le sweep in §4 measures `a` and `c` directly.

## 4. Probe for the holder

Implemented as `examples/latency.rs` (`cargo run --example latency`), without touching the crate; a separate example because `probe.rs` plus this would pass the 5,000-token file limit. `Transport` and `Port` are public (`src/lib.rs:52`), and a decorator is the documented way to wrap a transport (`src/transport.rs:19`). It wraps `PcscTransport` in a counting `Transport`, opens the session with it, and runs `labels()`, `certificate(SIGNATURE_LABEL)` and `certificate(INTERMEDIATE_CA_LABEL)`.

**Counting decorator.** For each `Port::transmit` it records INS, P1-P2 (for READ BINARY, the offset), Le, response length, SW and elapsed µs, in memory, never the data. It groups records into files: a new file starts at the SELECT by name. For each file it prints:

| Field | How |
| --- | --- |
| file | `IDESP`, `CDF`, `PrKDF` (fixed FIDs), or `certificate n`. Never a certificate path, only its `d`. |
| SELECTs / GET RESPONSEs / READ BINARYs / 6Cxx resends | counts by INS and SW |
| FCI length | offset + Le of the last READ BINARY. rdnie computes Le from it (`src/files.rs:142`), so the FCI need not be parsed. Mark if the read stopped on `6282`/`6B00`. |
| DER extent | over the READ BINARY data kept in memory only: for CDF/PrKDF, the sum of the consecutive TLVs that start with `30` (the rule of `src/pkcs15.rs:30-42`); for a certificate, 8 + zlib bytes consumed (`flate2::Decompress::total_in`, as `src/certificates.rs:105-126`), or the DER TLV if it does not inflate |
| trailing | FCI length − DER extent, and whether those bytes are all `00`, all `FF`, or mixed |
| time | per INS: min / median / max µs; the file total; the transaction overhead (operation time minus the sum of the exchanges) |

**Le sweep (settles `a` and `c`).** Before opening the session, in one `transaction` on the raw `Port`, select MF by name, `5015`, `6004`. Then send `READ BINARY` at offset 0 with Le ∈ {1, 32, 64, 128, 222}, 10 times each. Print the median µs per Le and the fitted `a` and `c`. Print no data. Guard Le against the FCI length.

**Never print:** data bytes of any response, certificate paths, labels beyond those the probe already prints, IDESP, serial. The lengths above identify no one. Still, the DER extent of a CDF that carries DNs moves with the holder's name length, so report only the totals in the issue.

**Reading the result.** If trailing ≫ 0 on the CDF and PrKDF, and the time per READ chunk is flat, padding explains the cost. The follow-up from #145 is then to stop reading once the objects end, which departs from JMulticard and should be recorded in `docs/parity.md`. Should the certificate files show the same, the same change speeds up `certificate()` too. If trailing ≈ 0, the directories are large by content, and the remaining lever is fewer SELECTs (H2).

## 5. Result

`examples/latency.rs` on the #133 setup (Alcor Micro AU9540, DNIe 4.0, pcsc-lite), 2026-10-24. Exact DER extents of the CDF and of the certificates are left out, since they move with the holder's name.

**Le sweep.** Medians of 2.0 ms at Le 1 up to 25.0 ms at Le 222, linear: `a` ≈ 1.9 ms per exchange, `c` ≈ 104 µs per byte. The cost is per byte, not per exchange, so the §3 estimate of `a` (4–7 ms) was high and the line rate is well below what TA1 allows.

| File | `d` | SELECT / GET RESPONSE / READ BINARY | FCI length | DER extent | Trailing | Time |
| --- | --- | --- | --- | --- | --- | --- |
| IDESP | 1 | 2 / 2 / 1 | 25 | — | — | 19 ms |
| CDF | 2 | 3 / 3 / 10 | 2100 | ~900 | ~1200, all `00` | 260 ms |
| PrKDF | 2 | 3 / 3 / 10 | 2100 | ~200 | ~1900, all `00` | 260 ms |
| certificate (×2) | 2 | 3 / 3 / 9 | ~1.6 KB | whole file | none | 210 ms |

- `g0` = `g` = 1: every SELECT, the MF by name included, answers `61xx`. A SELECT costs ~3.4 ms and its `GET RESPONSE` ~4.6 ms.
- No `6987`. Each certificate read has one `6Cxx` on its last chunk, ~2 ms.
- Time outside the exchanges is under 1 ms per step.

**H1** explains the cost: a READ BINARY of 222 bytes costs ~25 ms, and the directories read 20 chunks where 6 hold all their objects. **H2/H3** are real and small: 6 exchanges of ~4 ms per file.

**Follow-up.** Read the CDF and the PrKDF object by object and stop at the first byte that starts no SEQUENCE, the rule `pkcs15::entries` already applies after the read. `labels()` should drop to ~200 ms. It departs from JMulticard, so it goes in `docs/parity.md`. Certificates gain nothing from it.
