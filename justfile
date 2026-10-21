export PATH := env_var_or_default('HOME', '') / ".cargo/bin:" + env_var('PATH')

_default:
    @just --list

# What the CI runs.
check: fmt-check (file-tokens "--all") lint test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

# Files over 5,000 tokens: the staged ones, or every tracked one with `--all`.
file-tokens *flags:
    scripts/check-file-tokens.sh {{ flags }}

# With and without PC/SC, so the protocol never depends on the reader.
lint:
    cargo clippy --all-targets -- -D warnings
    cargo clippy --all-targets --no-default-features -- -D warnings

test:
    cargo test --quiet

# Advisories, licenses and sources of the dependencies (`deny.toml`).
deny:
    cargo deny check

# Mutates the code and reports the mutants the tests miss; slow, run by hand.
[positional-arguments]
mutants *args:
    cargo mutants "$@"

test-one filter:
    cargo test --quiet {{ filter }}

# Runs one `fuzz/` target for `secs` seconds; Linux and macOS only, with nightly and cargo-fuzz.
fuzz target secs="60":
    cargo +nightly fuzz run {{ target }} -- -max_total_time={{ secs }} -timeout=10

# Writes the emulator's responses into `fuzz/corpus/<target>`.
fuzz-seed:
    cargo test --quiet --lib --test fuzz_seeds -- --ignored

# Looks for a DNIe in the readers without sending it any APDU.
detect:
    cargo run --quiet --example detect

# Real-card probe, run by hand by the card's holder; prints ATR, labels, counts and pass/fail only. `--sign` also signs, after asking for the PIN. `--verbose` also prints the holder's data: never share that output.
[positional-arguments]
probe *args:
    cargo run --quiet --example probe -- "$@"
