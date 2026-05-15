use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_DecryptInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Decrypt(
    _session: CK_SESSION_HANDLE,
    _encrypted_data: CK_BYTE_PTR,
    _encrypted_data_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DecryptUpdate(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DecryptFinal(
    _session: CK_SESSION_HANDLE,
    _last_part: CK_BYTE_PTR,
    _last_part_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DecryptDigestUpdate(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_DecryptVerifyUpdate(
    _session: CK_SESSION_HANDLE,
    _encrypted_part: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}
