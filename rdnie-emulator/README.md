# rdnie-emulator

An emulated Spanish electronic ID card (DNIe 3.0 or 4.0) behind [`rdnie`](https://crates.io/crates/rdnie)'s `Transport`, for tests that have no reader or card.

Every key and certificate is generated at run time, and the holder is fictitious: no real person's data is involved. The 4.0 is rdnie's model of the card, not verified against a real DNIe 4.0.

Use it as a dev-dependency. The secure channel is signed by a component root the emulator generates, which `Session::open` rightly refuses, so open the session with `Session::open_trusting` (feature `emulator` of `rdnie`, never for production):

```toml
[dev-dependencies]
rdnie = { version = "0.1", default-features = false, features = ["emulator"] }
rdnie-emulator = "0.1"
```

```rust
use rdnie::Session;
use rdnie_emulator::EmulatedDnie;

let card = EmulatedDnie::dnie_3().with_pin_retries(2);
let root = card.component_root();
let session = Session::open_trusting(card, root)?;
```

The card can also be a DNIe 4.0, expect another PIN, hold fewer retries, or be removed or reset at a named step. Its signing and authentication public keys are exposed to verify what it signs.

The `faults` feature exposes the knobs rdnie's own tests use and is outside semver.

Licensed under EUPL-1.2. Ported files keep the attribution of their JMulticard source; see `NOTICE`.
