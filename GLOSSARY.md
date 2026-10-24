# Glossary

- **Card authenticator**: the card's key generation, resolved once from its IDESP when the session opens, together with the component roots the session trusts. It is the only way the PIN channel and the user channel are opened (`src/card_authenticator.rs`).
- **Transport**: the public trait that owns the connection. It reads the ATR and runs a transaction, handing the body a Port (`src/transport.rs`).
- **Port**: the public trait that sends raw APDU bytes. It exists only inside a Transport transaction, so a decorator gets one only by forwarding the inner transaction (`src/transport.rs`).
- **Plain channel**: the command level over the card's raw send, below any secure channel. It owns the ISO follow-up (`61xx` completed with `GET RESPONSE`, a plain command resent on `6Cxx` and once on `69 87`) and its bounds. The secure channel protects its commands over it, and the protocol only sends commands through one or the other (`src/channel.rs`).
- **PIN guard**: the never-blind PIN policy in one place. It holds the card authenticator and the retries count last shown to the caller, reads the retries when none were shown, refuses a blocked PIN before touching the card, and in one transaction rereads the retries, sends a single `VERIFY` and runs the operation over the user channel (`src/pin.rs`).
