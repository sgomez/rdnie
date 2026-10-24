# Glossary

- **Card authenticator**: the card's key generation, resolved once from its IDESP when the session opens, together with the component roots the session trusts. It is the only way the PIN channel and the user channel are opened (`src/card_authenticator.rs`).
