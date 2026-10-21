# Contributing

## Ground rules

- No test, CI job, issue or PR uses or carries data from a real DNIe: certificates, names, document or serial numbers, or APDU dumps containing them. ATRs and status words are fine.
- Cryptography comes from RustCrypto; the crate composes primitives and implements none.
- No `unsafe`.
- Code ported from JMulticard keeps the attribution of its source in the file header.

## Commands

Everything goes through the [`justfile`](justfile); `just --list` shows the recipes. `just check` is what the CI runs. Lefthook checks the formatting on commit and runs `just check` on push.

On Linux, building with `pcsc` needs `libpcsclite-dev`.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): the changelog is generated from them.

## Testing against a real card

The tests run against an emulator. `just detect` looks for a DNIe without sending it any APDU, and `just probe` runs the real-card probe; only the card's holder runs it, and its output is never shared.

## Mutation testing

`just mutants` reports the mutants the tests miss. It is slow; pass `--in-diff` with a diff to mutate only what changed.

## Fuzzing

The parsers of card data have `cargo-fuzz` targets in `fuzz/`, on Linux and macOS only. They need nightly and `cargo install cargo-fuzz`.

```sh
just fuzz-seed             # seed corpora from the emulator, into fuzz/corpus/
just fuzz <target> [secs]  # one target, 60 seconds by default
```

The targets are the `[[bin]]` entries of `fuzz/Cargo.toml`. A weekly workflow runs each of them.
