use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_DigestInit(_session: CK_SESSION_HANDLE, _mechanism: CK_MECHANISM_PTR) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Digest(
    _session: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _digest: CK_BYTE_PTR,
    _digest_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DigestUpdate(
    _session: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DigestKey(_session: CK_SESSION_HANDLE, _key: CK_OBJECT_HANDLE) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DigestFinal(
    _session: CK_SESSION_HANDLE,
    _digest: CK_BYTE_PTR,
    _digest_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DigestEncryptUpdate(
    _session: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
    _encrypted_part: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}
