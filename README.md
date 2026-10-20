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

## Fuzzing

The parsers of card data have `cargo-fuzz` targets in `fuzz/`, on Linux and macOS only. They need nightly and `cargo install cargo-fuzz`.

```sh
just fuzz-seed             # seed corpora from the emulator, into fuzz/corpus/
just fuzz <target> [secs]  # one target, 60 seconds by default
```

The targets are the `[[bin]]` entries of `fuzz/Cargo.toml`. A weekly workflow runs each of them for 60 seconds.

## License

EUPL-1.2.
