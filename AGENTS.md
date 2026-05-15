# Agent Notes

This repository is a Rust PKCS#11 module for signing PDF documents with the
Peruvian DNIe smart card. Treat this crate as the forward path for the project.
It builds a `cdylib` shared object and uses `cryptoki-sys` for PKCS#11 ABI
types.

## Project Purpose

- Provide a public open-source PKCS#11 provider for Peruvian DNIe PDF signing.
- Preserve support for DNIe 1.0, DNIe 2.0, and DNIe 3.0.
- Keep private-key operations card-bound through PC/SC.
- Support tested clients: Okular, LibreOffice Draw, `pdfsig`, and `pyHanko`.
- Unsupported PKCS#11 operations must return `CKR_FUNCTION_NOT_SUPPORTED`.
- PACE support with the CAN code is not implemented yet. Do not claim it works,
  and do not describe it as required for the current signing flow; signing works
  without PACE/CAN, though PACE would improve security for CAN-based secure
  messaging flows.

## Repository Layout

- `src/lib.rs`: crate root and module wiring.
- `src/pkcs11.rs`: PKCS#11 types, global state, function list, and helpers.
- `src/api/`: exported PKCS#11 `C_*` entry points grouped by operation family.
- `src/ffi.rs`: C pointer and raw-slice helpers. Keep unsafe Rust here unless a
  PKCS#11 ABI boundary requires otherwise.
- `src/card.rs`: PC/SC card discovery, DNIe profile handling, certificate
  loading, chain loading, and card-bound signing.
- `src/objects.rs`: PKCS#11 object handles, object matching, and attributes.
- `src/apdu.rs`: short APDU encoding.
- `src/tlv.rs`: BER-TLV parsing helpers.
- `src/config.rs`: environment and user configuration loading.
- `src/logging.rs`: stderr logging helpers and log-level parsing.
- `.github/workflows/`: CI and release automation.

## Build, Test, Lint, And Format

Run from the repository root:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

Main build output:

```text
target/release/libperu_dnie_pkcs11.so
```

Useful hardware smoke tests:

```sh
pkcs11-tool --module target/release/libperu_dnie_pkcs11.so -L
pkcs11-tool --module target/release/libperu_dnie_pkcs11.so -O
```

If a PC/SC/card command reports `SCardEstablishContext failed`, rerun it outside
the sandbox with escalation; sandboxed PC/SC access is often blocked.

## Coding Standards

- Prefer safe, boring, maintainable Rust.
- Keep unsafe Rust isolated to `src/ffi.rs` and PKCS#11 ABI boundaries.
- Use clear `Result`-based error propagation internally and convert to PKCS#11
  `CK_RV` values at the API boundary.
- Avoid unnecessary cloning, panics, `unwrap`, broad catch-all errors, and global
  mutable state beyond the PKCS#11 module state protected by `Mutex`.
- Do not fake signatures in software.
- Do not invent signing APDUs.
- Keep private keys non-extractable.
- Preserve compatibility expectations for Okular, LibreOffice Draw, `pdfsig`,
  and `pyHanko`.

## Certificate And Signing Policy

- The leaf signing certificate must be loaded lazily on object enumeration,
  attribute reads, or signing. `C_Initialize` must not read it.
- Certificate listing must not fail only because intermediate certificates are
  missing.
- Chain certificates must appear during object listing when available. PDF
  signing clients use the listed chain certificate objects to embed the chain in
  signed PDFs; do not remove or defer this behavior again.
- `C_Initialize` must not perform AIA network access.
- Signing must fail if no intermediate certificate can be loaded.
- If `PERU_DNIE_CERT_CHAIN` is set and non-empty, use only those configured
  files. Do not use AIA or cache.
- If `PERU_DNIE_CERT_CHAIN` is not set, discover issuer URLs from AIA and cache
  downloaded certificates under `$XDG_CACHE_HOME/peru-dnie-pkcs11` or
  `~/.cache/peru-dnie-pkcs11`.
- `PERU_DNIE_AIA_CACHE=0` means ignore the cache only. It must still download
  AIA certificates without reading or writing cached files.

## Logging Rules

- `PERU_DNIE_LOG` accepts `none`, `error`, `warn`, `info`, `debug`, or `trace`.
- `PERU_DNIE_DEBUG=1` or `PERU_DNIE_DEBUG=true` enables debug logging directly.
- Logs go to stderr.
- Never log PINs, CAN codes, secure messaging keys, private keys, private key
  material, sensitive APDU payloads, or personally identifying data read from
  the DNI.
- Log PKCS#11 operations, mechanism names, response status words, lengths,
  counts, and high-level state transitions when useful.
- `C_Initialize` logs compile-time build metadata when logging is enabled:
  package name, package version, Git revision, Git commit time, and whether the
  worktree was clean when built. This mirrors Go-style VCS metadata and comes
  from `build.rs`.

## Testing Strategy

- Add unit tests for pure parsing, configuration, logging, object matching, and
  PKCS#11 return-value behavior.
- Keep hardware/DNI-card-dependent behavior isolated so CI can run without a
  physical DNIe.
- Add regression tests for bugs found during reviews.
- Do not include real certificates, PINs, CAN codes, private key material, or
  personal DNI data as fixtures.

## Documentation Expectations

- Keep README instructions accurate for public users.
- Document public items and important internal abstractions with Rustdoc.
- Document safety invariants around unsafe code.
- Document PKCS#11 assumptions and unsupported operations.
- Clearly state that PACE with CAN code is optional for the current signing flow
  and is not implemented yet. Do not imply that its absence blocks PDF signing.

## Release Workflow

- Update `Cargo.toml` version and README notes as needed.
- Run the full local verification command set.
- Push a version tag such as `v0.1.0`.
- GitHub Actions builds the release shared object and creates a GitHub release
  with Linux artifacts.
