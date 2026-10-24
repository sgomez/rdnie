# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/sgomez/rdnie/compare/rdnie-emulator-v0.2.0...rdnie-emulator-v0.3.0) - 2026-10-24

### Changed

- *(atr)* [**breaking**] add Atr with check and Display, return it from Transport::atr and Session::atr
- *(session)* [**breaking**] replace Certificate with Session::labels and Session::private_key
- *(api)* [**breaking**] rename pin_retries_left and DigestAlgorithm, make Response crate-private
- *(transport)* [**breaking**] split the public transport into Transport and Port

## [0.2.0](https://github.com/sgomez/rdnie/compare/rdnie-emulator-v0.1.1...rdnie-emulator-v0.2.0) - 2026-10-24

### Changed

- *(deps)* [**breaking**] bump ctutils to 0.4.5 for RUSTSEC-2026-0385, raising the MSRV to 1.87
- *(session)* [**breaking**] list certificates without their DER and read each on demand
- *(session)* [**breaking**] open the session without resetting the card

### Fixed

- resend a plain command the card answers 69 87 after a leftover secure channel

## [0.1.0](https://github.com/sgomez/rdnie/releases/tag/rdnie-emulator-v0.1.0) - 2026-10-21

### Added

- *(emulator)* publish rdnie-emulator with release-plz
- *(emulator)* move rdnie-only knobs behind the faults feature
- *(emulator)* emulate a DNIe 4.0 and either key generation
- *(emulator)* remove or reset the emulated card at a named step
- *(emulator)* open, verify the PIN and sign against rdnie-emulator from outside rdnie
