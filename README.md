# Peru DNIe PKCS#11

`peru-dnie-pkcs11` is a Rust PKCS#11 module for signing PDF documents with the
Peruvian electronic identity card (DNIe). It exposes the DNIe signing
certificate and performs card-bound RSA signatures through PC/SC.

## Legal / Compliance Notice

This project is an independent open-source implementation. It is not affiliated
with RENIEC and is not an official RENIEC project, product, or release.

The module targets PKCS#11 v2.40 and builds a shared object:

```text
target/release/libperu_dnie_pkcs11.so
```

## What It Does

- Detects Peruvian DNIe cards through known ATRs and application-selection
  probes.
- Supports DNIe 1.0, DNIe 2.0, and DNIe 3.0.
- Exposes the signing certificate, optional issuer certificates, and a
  non-extractable private key object.
- Supports the PKCS#11 operations required by PDF signing clients: slot and
  token discovery, sessions, login/logout, object enumeration and attributes,
  mechanism discovery, and signing.
- Performs signatures on the card. It does not fake signatures in software.

Unsupported PKCS#11 operations return `CKR_FUNCTION_NOT_SUPPORTED`.

## Tested Applications

The module has been tested with:

- Okular
- LibreOffice Draw
- `pdfsig`
- `pyHanko`

## PACE/CAN Secure Messaging

PACE using the CAN code is optional. When no CAN is configured, the current
signing flow continues to use plaintext card communication. When a CAN is
configured, the module establishes PACE during card open and protects subsequent
APDUs with secure messaging. If PACE fails, card open fails instead of falling
back to plaintext.

## Requirements

- Rust 1.85 or newer
- PC/SC runtime and development headers
- OpenSSL development headers
- A Peruvian DNIe card and compatible reader
- Optional: OpenSC tools for `pkcs11-tool` smoke tests

On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libpcsclite-dev libssl-dev opensc
```

On Arch Linux:

```sh
sudo pacman -S --needed base-devel rust pkgconf pcsclite openssl opensc
sudo systemctl enable --now pcscd.service
```

## Build

```sh
cargo build --release
```

The PKCS#11 module will be written to:

```text
target/release/libperu_dnie_pkcs11.so
```

## Basic Usage

List slots:

```sh
pkcs11-tool --module ./target/release/libperu_dnie_pkcs11.so -L
```

List visible objects:

```sh
pkcs11-tool --module ./target/release/libperu_dnie_pkcs11.so -O
```

PDF signing clients should be configured to load
`target/release/libperu_dnie_pkcs11.so` as a PKCS#11 provider.

## Certificate Chain Configuration

The leaf signing certificate is loaded lazily when objects are enumerated,
attributes are requested, or signing needs it. Intermediate issuer certificates
are loaded when certificate objects are listed so PDF signing clients can embed
the certificate chain in signed PDFs. Initialization does not perform AIA network
access.

Signing requires at least one issuer certificate. Configure issuer certificates
manually with `PERU_DNIE_CERT_CHAIN`:

```sh
export PERU_DNIE_CERT_CHAIN=/path/intermediate.cer:/path/root.cer
```

When `PERU_DNIE_CERT_CHAIN` is set and non-empty, only those files are used. AIA
download and cache lookup are skipped.

When `PERU_DNIE_CERT_CHAIN` is not set, issuer URLs are discovered from the
certificate AIA extension. Downloaded certificates are cached under:

```text
$XDG_CACHE_HOME/peru-dnie-pkcs11
```

or, when `XDG_CACHE_HOME` is not set:

```text
~/.cache/peru-dnie-pkcs11
```

Set `PERU_DNIE_AIA_CACHE=0` to ignore the cache. The module will still download
AIA certificates, but it will not read or write cached files.

## CAN Configuration

To enable PACE secure messaging, provide the CAN with `PERU_DNIE_CAN`:

```sh
export PERU_DNIE_CAN=123456
```

Alternatively, set `can = "123456"` in
`~/.config/peru-dnie-pkcs11/config.toml`. The environment variable takes
precedence. Do not enable this unless the CAN belongs to the card being used;
an invalid CAN causes `C_Initialize`/card open paths to fail when the card is
opened.

## Logging

Logging is disabled by default. Logs are written to stderr.

```sh
export PERU_DNIE_LOG=none
export PERU_DNIE_LOG=error
export PERU_DNIE_LOG=warn
export PERU_DNIE_LOG=info
export PERU_DNIE_LOG=debug
export PERU_DNIE_LOG=trace
```

`PERU_DNIE_DEBUG=1` or `PERU_DNIE_DEBUG=true` enables debug logging.

Logs are intended for integration troubleshooting. They must never contain PINs,
CAN codes, secure messaging keys, private keys, private key material, sensitive
APDU payloads, or personally identifying data read from the DNI.

When logging is enabled, `C_Initialize` prints startup metadata: package name,
package version, Git commit id, Git commit date, and whether the build was made
from a clean worktree.

Example:

```sh
PERU_DNIE_LOG=debug pkcs11-tool --module ./target/release/libperu_dnie_pkcs11.so -O
```

## Testing

Run the CI-equivalent local checks:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

Hardware-independent tests run with `cargo test`. PC/SC smoke tests require a
card and reader:

```sh
pkcs11-tool --module ./target/release/libperu_dnie_pkcs11.so -L
pkcs11-tool --module ./target/release/libperu_dnie_pkcs11.so -O
```

If a PC/SC command reports `SCardEstablishContext failed` in a sandboxed
environment, rerun it with direct host access to PC/SC.

## Security Considerations

- The private key remains non-extractable and card-bound.
- The module does not invent signing APDUs or emulate signatures.
- PINs, CAN codes, secure messaging keys, private keys, private key material,
  and sensitive APDU payloads must not be logged.
- Certificate listing must not fail only because issuer certificates are
  missing.
- Signing fails if no issuer certificate can be loaded.
- PACE/CAN is optional for the current signing flow. When configured, it must
  succeed before the module sends protected card commands.

## Troubleshooting

- `CKR_TOKEN_NOT_PRESENT`: confirm the reader is visible through PC/SC and the
  DNIe is inserted.
- `CKR_PIN_INCORRECT`: verify the PIN with the card issuer tools before retrying.
- Signing fails after certificate listing works: configure `PERU_DNIE_CERT_CHAIN`
  or allow AIA download so an issuer certificate can be loaded.
- AIA download fails: check network access, proxy/firewall rules, and whether
  manual `PERU_DNIE_CERT_CHAIN` configuration is more appropriate.
- Client does not show the private key: login may be required before the key is
  visible to that application.

## Project Status

This project is early public open-source software. It has practical coverage for
DNIe 1.0, 2.0, and 3.0 PDF signing workflows, but PKCS#11 support is intentionally
limited to the operations needed by tested PDF clients.

## License

Licensed under either of:

- MIT license
- Apache License, Version 2.0
