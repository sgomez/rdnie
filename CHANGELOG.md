# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
