# rdnie

Rust driver for the Spanish electronic ID card (DNIe). It talks to the card over PC/SC, without PKCS#11, OpenSC or system drivers, and behaves the same on Linux, macOS and Windows.

## Status

Work in progress. The 0.1 goal is to open the CWA-14890 secure channel and read the certificates and the PIN retry counter, all without asking for the PIN. Signing comes later.

## Usage

```sh
cargo run --example detect
```

The `pcsc` feature, on by default, provides `PcscTransport`. Without it the crate runs over any `Transport`, such as an emulator in tests.

On Linux, `pcscd` is needed at runtime and `libpcsclite-dev` to build.

## License

EUPL-1.2.
