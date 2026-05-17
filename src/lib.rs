//! PKCS#11 module for signing with the Peruvian DNIe smart card.
//!
//! The crate builds a `cdylib` that exports PKCS#11 v2.40 `C_*` entry points.
//! Hardware-facing operations use PC/SC and keep signatures card-bound; the
//! module never fabricates private-key operations in software.
//!
//! Unsafe code is intentionally isolated in the FFI helpers and C ABI entry
//! points. Internal modules use Rust slices, references, and `Result` values
//! before converting failures back to PKCS#11 return values at the boundary.

mod apdu;
mod api;
mod build_info;
mod card;
mod config;
mod ffi;
mod logging;
mod objects;
mod pace;
mod pkcs11;
mod tlv;

pub use pkcs11::*;
