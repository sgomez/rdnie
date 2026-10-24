# rdnie

[![crates.io](https://img.shields.io/crates/v/rdnie.svg)](https://crates.io/crates/rdnie)
[![docs.rs](https://img.shields.io/docsrs/rdnie)](https://docs.rs/rdnie)
[![CI](https://github.com/sgomez/rdnie/actions/workflows/ci.yml/badge.svg)](https://github.com/sgomez/rdnie/actions/workflows/ci.yml)
[![License: EUPL-1.2](https://img.shields.io/crates/l/rdnie.svg)](https://github.com/sgomez/rdnie/blob/main/LICENSE)

Rust driver for the Spanish electronic ID card (DNIe). It talks APDU to the card over PC/SC, without PKCS#11, OpenSC or system drivers, and behaves the same on Linux, macOS and Windows.

## What it does

- Finds a DNIe 3.0 or 4.0 among the readers by its ATR.
- Opens the CWA-14890 secure channel.
- Reads the certificates, and the holder's name, surnames and number from them.
- Reads the PIN retries left without sending the PIN.
- Signs a SHA-256, SHA-384 or SHA-512 digest with PKCS#1 v1.5.

DNIe 1.0 and 2.0, NFC and PACE, changing the PIN, decrypting and other cards are out of scope. [`docs/parity.md`](https://github.com/sgomez/rdnie/blob/main/docs/parity.md) compares it with JMulticard, the driver it is ported from.

## Usage

```toml
[dependencies]
rdnie = "0.1"
```

```rust
use rdnie::{HashAlgorithm, PcscTransport, Pin, SIGNATURE_LABEL, Session};
use sha2::{Digest, Sha256};

fn main() -> Result<(), rdnie::Error> {
    let mut session = Session::open(PcscTransport::connect_first_dnie()?)?;
    let certificates = session.certificates()?;
    let signing = certificates
        .iter()
        .find(|certificate| certificate.label == SIGNATURE_LABEL)
        .expect("a DNIe has a signature certificate");

    let retries = session.pin_retries()?;
    let pin = Pin::new(ask_holder_for_pin(retries));
    let digest = Sha256::digest(b"document");
    let signature = session.sign(&digest, HashAlgorithm::Sha256, &signing.key, pin)?;
    Ok(())
}
```

`certificates` reads no certificate file: signing needs only the key. `session.certificate(label)` reads that one X.509 certificate on first request and keeps it for the session, and `Holder::from_der` reads the holder's data from it.

## The PIN

- **Never sent blind.** `sign` reads the retries again before VERIFY and stops without sending the PIN if they are 0 (`Error::PinBlocked`) or differ from those `pin_retries` showed (`Error::PinRetriesChanged`). Show the holder the retries before asking for the PIN.
- **One attempt per call.** A wrong PIN returns `Error::WrongPin`, and nothing retries on its own, not even after a card reset.
- **Checked before the card.** A PIN outside 8 to 16 characters fails with `Error::InvalidPinFormat` without spending an attempt.
- **Wiped from memory.** `Pin` is zeroized when dropped, and no PIN or session key survives an operation.

## Platforms

| OS | At runtime | To build |
| --- | --- | --- |
| Linux | `pcscd` | `libpcsclite-dev` and `pkg-config` |
| macOS | nothing | nothing |
| Windows | nothing | nothing |

The minimum supported Rust version is 1.85.

## Features

`pcsc`, on by default, provides `PcscTransport`. With `default-features = false` the crate builds without PC/SC and runs over any implementation of the `Transport` trait.

## Security

Report vulnerabilities privately, as [`SECURITY.md`](https://github.com/sgomez/rdnie/blob/main/SECURITY.md) explains.

## Contributing

See [`CONTRIBUTING.md`](https://github.com/sgomez/rdnie/blob/main/CONTRIBUTING.md).

## License

Copyleft: free software under the [EUPL-1.2](https://github.com/sgomez/rdnie/blob/main/LICENSE). Parts are derived from [JMulticard](https://github.com/ctt-gob-es/jmulticard); see [`NOTICE`](https://github.com/sgomez/rdnie/blob/main/NOTICE).
