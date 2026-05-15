use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_SeedRandom(
    _session: CK_SESSION_HANDLE,
    _seed: CK_BYTE_PTR,
    _seed_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GenerateRandom(
    _session: CK_SESSION_HANDLE,
    _random_data: CK_BYTE_PTR,
    _random_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}
