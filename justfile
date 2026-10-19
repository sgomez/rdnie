export PATH := env_var_or_default('HOME', '') / ".cargo/bin:" + env_var('PATH')

# What the CI runs.
check: fmt-check lint test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

# With and without PC/SC, so the protocol never depends on the reader.
lint:
    cargo clippy --all-targets -- -D warnings
    cargo clippy --all-targets --no-default-features -- -D warnings

test:
    cargo test --quiet

test-one filter:
    cargo test --quiet {{ filter }}

# Looks for a DNIe in the readers without sending it any APDU.
detect:
    cargo run --quiet --example detect

# Real-card probe, run by hand by the card's holder; prints ATR, counts and pass/fail only. `--sign` also signs, after asking for the PIN.
probe *args:
    cargo run --quiet --example probe -- {{ args }}
