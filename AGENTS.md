# Agent instructions: rdnie

## Goal

Rust driver for the Spanish electronic ID card (DNIe) that talks APDU to the card over PC/SC, without PKCS#11, OpenSC or system drivers, the same on Linux, macOS and Windows. Its first consumer is [rFirma](https://github.com/sgomez/rfirma).

## Design constraints

1. **The protocol is ported from JMulticard** ([ctt-gob-es/jmulticard](https://github.com/ctt-gob-es/jmulticard)): only the contact DNIe (CWA-14890 secure channel, certificates, retry counter, VERIFY and signing). No PACE, NFC or other cards. Ported code is a derivative work: each file keeps the attribution of its source.
2. **Cryptography comes from RustCrypto, never hand-written.** The crate composes primitives (3DES, AES, retail MAC, RSA, SHA) and implements none.
3. **The PIN is never sent blind.** The remaining retries are read before VERIFY, and an operation makes at most one attempt.
4. **No `unsafe`** (`unsafe_code = "forbid"` in `Cargo.toml`).
5. **The transport is a seam.** The protocol only knows the `Transport` trait. PC/SC lives behind the `pcsc` feature, and tests use an emulator.
6. **English everywhere:** code, docs, comments, error messages, commits, issues and PRs. Error messages follow the Rust API Guidelines: lowercase, no trailing period.
7. **Comments: the default is none.** The name is the comment. `//!` for a module and `///` for a public item, one line each; `//` in a body only when it says what the code cannot.
8. **Don't write what rots:** no counters or lists that already live in the code. Point at the source.

## Personal data

**No test and no CI job uses a real DNIe.** Real-card probes are run by hand by the card's holder. Neither the repo, nor an issue, nor a PR carries certificates, names, document or serial numbers, fingerprints, or APDU dumps containing them. ATRs and status words are fine: they identify no one.

## What to run and when

Everything goes through the `justfile`: bare `just <recipe>`, one command per call.

| When | What |
| --- | --- |
| On every red → green | `just test-one <filter>` |
| Before committing | `just fmt`. Lefthook runs `just fmt-check` on commit |
| Before pushing | The pre-push hook runs `just check` |
| On opening the PR | The CI's verdict: `just check` on Linux, macOS and Windows |

On Linux, building with `pcsc` needs `libpcsclite-dev`.

## Agent skills

* **Issue tracker:** GitHub Issues of `sgomez/rdnie`, through `gh` (`docs/agents/issue-tracker.md`).
* **Triage labels:** `docs/agents/triage-labels.md`.
* **Code host:** GitHub PRs (`docs/agents/code-host.md`); `/developer` defaults in `docs/agents/developer-defaults.md`.
* **Domain docs:** `docs/agents/domain.md`.
