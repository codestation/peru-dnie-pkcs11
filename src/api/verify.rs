use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_VerifyInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Verify(
    _session: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_VerifyUpdate(
    _session: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_VerifyFinal(
    _session: CK_SESSION_HANDLE,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_VerifyRecoverInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_VerifyRecover(
    _session: CK_SESSION_HANDLE,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}
