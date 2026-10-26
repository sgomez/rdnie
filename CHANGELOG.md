# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- *(pin)* [**breaking**] treat the PIN retries as an optimistic lock: `sign` and `verify_pin` fail with `PinRetriesChanged`, before the PIN is sent, if the retries moved at any time since the last PIN operation
- *(pin)* [**breaking**] `sign` and `verify_pin` without a prior `pin_retries_left` fail with `PinRetriesNotRead` instead of reading the retries themselves
- *(pin)* [**breaking**] an operation after an accepted `VERIFY` expects the maximum retries and takes one transaction
- *(pin)* [**breaking**] an error before `VERIFY` is sent no longer drops the expected retries
- *(pin)* [**breaking**] after `PinBlocked`, the next operation fails without touching the card until `pin_retries_left`

## [0.3.0](https://github.com/sgomez/rdnie/compare/rdnie-v0.2.0...rdnie-v0.3.0) - 2026-10-24

### Added

- *(session)* add idesp, card_name and serial_number
- *(session)* verify the PIN without signing with Session::verify_pin

### Changed

- *(atr)* [**breaking**] add Atr with check and Display, return it from Transport::atr and Session::atr
- *(session)* [**breaking**] replace Certificate with Session::labels and Session::private_key
- *(api)* [**breaking**] rename pin_retries_left and DigestAlgorithm, make Response crate-private
- *(transport)* [**breaking**] split the public transport into Transport and Port

### Fixed

- *(session)* report a certificate file that is not X.509 as MalformedCertificate

### Performance

- *(files)* fetch each next directory header with the object before it
- *(certificates)* read the CDF and the PrKDF up to their last object

### Added

- *(session)* `Session::verify_pin` verifies the PIN without signing
- *(atr)* `Atr`, with `check` (whether `Session::open` accepts the card, without touching it), `as_bytes` and `Display`
- *(session)* `Session::atr` returns the `Atr` `open` classified, without touching the card
- *(session)* `Session::private_key` returns the `KeyReference` of a label, as `getPrivateKey`
- *(session)* `Session::idesp` and `card_name`, without touching the card, and `serial_number`, from one `GET CHIP INFO`
- *(signature)* `DigestAlgorithm::digest_length`

### Changed

- *(session)* [**breaking**] rename `Session::pin_retries` to `pin_retries_left`
- *(signature)* [**breaking**] rename `HashAlgorithm` to `DigestAlgorithm`
- *(session)* [**breaking**] rename `Session::certificates` to `labels`, which returns the labels as `String`s: get each key with `Session::private_key`
- *(certificates)* [**breaking**] remove `Certificate`
- *(apdu)* [**breaking**] make `Response` crate-private; `StatusWord` stays public
- *(transport)* [**breaking**] `Transport::atr` returns `Atr` instead of `Vec<u8>`
- *(atr)* [**breaking**] remove `is_dnie` and `describe_atr`: use `Atr::check` and `Atr`'s `Display`
- *(pcsc)* `PcscTransport::connect_first_dnie` picks a card whose `Atr::check` gives `Ok`, `LegacyDnie` or `BurnedDnie`, so it now skips a card with the DNIe tag that `Session::open` would refuse as `NotDnie`
- *(session)* `sign` reports a wrong digest length before an invalid PIN format
- *(session)* after `WrongPin { retries_left }`, the next `sign` or `verify_pin` expects `retries_left` instead of reading the retries again
- *(session)* `certificate` reports a certificate file that is not X.509 as `MalformedCertificate`
- *(transport)* [**breaking**] split `Transport` into `Transport` and `Port`

  `Transport` now has `atr` and `transaction`, whose body receives `&mut dyn Port`; `Port` has one method, `transmit`. `transmit_raw` and `reset` leave the trait (`reset` stays an inherent method of `PcscTransport` and the emulated DNIe), and `Command` is crate-private.

  To migrate an adapter, implement `atr` and `transaction`, and hand the body a private `Port` that sends the bytes. A decorator forwards the inner transaction and wraps the port it receives:

  ```rust
  fn transaction<R>(
      &mut self,
      body: impl FnOnce(&mut dyn Port) -> Result<R, Error>,
  ) -> Result<R, Error> {
      let log = &mut self.log;
      self.inner.transaction(|port| body(&mut Recording { port, log }))
  }
  ```

  where `Recording` implements `Port::transmit` by logging the APDU and calling `port.transmit`.

## [0.2.0](https://github.com/sgomez/rdnie/compare/rdnie-v0.1.2...rdnie-v0.2.0) - 2026-10-24

### Added

- *(probe)* time the card steps and add a leftover-channel mode

### Changed

- *(deps)* [**breaking**] bump ctutils to 0.4.5 for RUSTSEC-2026-0385, raising the MSRV to 1.87
- *(session)* [**breaking**] list certificates without their DER and read each on demand
- *(session)* [**breaking**] open the session without resetting the card

### Fixed

- resend a plain command the card answers 69 87 after a leftover secure channel

## [0.1.2](https://github.com/sgomez/rdnie/compare/rdnie-v0.1.1...rdnie-v0.1.2) - 2026-10-22

### Fixed

- *(pcsc)* ask for the protocols the cached ATR offers
- *(pcsc)* retry an unresponsive card with T=0

## [0.1.1](https://github.com/sgomez/rdnie/compare/rdnie-v0.1.0...rdnie-v0.1.1) - 2026-10-21

### Added

- *(emulator)* move rdnie-only knobs behind the faults feature
- *(emulator)* open, verify the PIN and sign against rdnie-emulator from outside rdnie
- *(session)* add Session::open_trusting behind the emulator feature

## [0.1.0] - 2026-10-21

### Added

- Initial release: a driver for the DNIe 3.0 and 4.0 over PC/SC.
- Finds the DNIe among the readers by its ATR, and lists and picks readers.
- Opens the CWA-14890 secure channel with the r1 and r2 terminal key sets.
- Reads the holder's certificates with their labels, the intermediate CA, and the holder's data from them.
- Reads the PIN retries left without sending the PIN.
- Signs a SHA-256, SHA-384 or SHA-512 digest with PKCS#1 v1.5, after a single VERIFY.
- Runs over any `Transport`; PC/SC is the default `pcsc` feature.

[0.1.0]: https://github.com/sgomez/rdnie/releases/tag/v0.1.0
