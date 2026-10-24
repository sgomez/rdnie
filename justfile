export PATH := env_var_or_default('HOME', '') / ".cargo/bin:" + env_var('PATH')

_default:
    @just --list

# What the CI runs.
check: fmt-check (file-tokens "--all") lint doc test

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# Files over 5,000 tokens: the staged ones, or every tracked one with `--all`.
file-tokens *flags:
    scripts/check-file-tokens.sh {{ flags }}

# With and without PC/SC, so the protocol never depends on the reader; the emulator also without `faults`.
lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo clippy --workspace --all-targets --no-default-features -- -D warnings
    cargo clippy -p rdnie-emulator --all-targets -- -D warnings

# Fails on rustdoc warnings, which docs.rs would show.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --quiet

test:
    cargo test --workspace --quiet
    cargo test -p rdnie-emulator --quiet

# Builds both crates from their packages, as crates.io will.
package:
    cargo publish --dry-run --workspace --quiet

# Both libraries on their `rust-version`, rdnie with and without PC/SC; the tests may need a newer Rust.
msrv:
    #!/usr/bin/env sh
    set -eu
    version=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
    rustup toolchain install "$version" --profile minimal
    cargo +"$version" check --lib
    cargo +"$version" check --lib --no-default-features
    emulator=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' rdnie-emulator/Cargo.toml)
    rustup toolchain install "$emulator" --profile minimal
    cargo +"$emulator" check -p rdnie-emulator --lib

# Advisories, licenses and sources of the dependencies (`deny.toml`).
deny:
    cargo deny check

# Mutates the code and reports the mutants the tests miss; slow, run by hand.
# A mutant that loops while appending bytes would exhaust the RAM before the timeout.
[linux]
[positional-arguments]
mutants *args:
    systemd-run --user --scope --quiet -p MemoryMax=8G -p MemorySwapMax=0 cargo mutants "$@"

# Mutates the code and reports the mutants the tests miss; slow, run by hand.
[macos]
[windows]
[positional-arguments]
mutants *args:
    cargo mutants "$@"

test-one filter:
    cargo test --workspace --quiet {{ filter }}

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

# Latency probe on a real DNIe (#145); run by the card's holder only.
[positional-arguments]
latency *args:
    cargo run --example latency -- "$@"

# Benchmark on a real DNIe, run by the card's holder; `bench/README.md` compares it with JMulticard and OpenSC.
[positional-arguments]
bench *args:
    cargo run --quiet --release --example bench -- "$@"

# JMulticard counterpart of `bench`; needs a JDK and Maven.
[positional-arguments]
bench-jmulticard *args:
    mvn -q -f bench/jmulticard/pom.xml compile dependency:build-classpath -Dmdep.outputFile=target/classpath
    java -cp "bench/jmulticard/target/classes:$(cat bench/jmulticard/target/classpath)" Bench "$@"

# OpenSC counterpart of `bench`, through its PKCS#11 module; needs uv.
[positional-arguments]
bench-opensc *args:
    uv run --no-project --with pykcs11 python bench/opensc.py "$@"

# A bench recipe under pcsc-spy, e.g. `just bench-spy bench --runs 1`: its PC/SC call counts and times only.
[positional-arguments]
bench-spy *args:
    bench/spy.sh just "$@"
