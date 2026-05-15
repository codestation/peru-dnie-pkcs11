use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_GetOperationState(
    _session: CK_SESSION_HANDLE,
    _state: CK_BYTE_PTR,
    _state_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SetOperationState(
    _session: CK_SESSION_HANDLE,
    _state: CK_BYTE_PTR,
    _state_len: CK_ULONG,
    _encryption_key: CK_OBJECT_HANDLE,
    _authentication_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionStatus(_session: CK_SESSION_HANDLE) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_CancelFunction(_session: CK_SESSION_HANDLE) -> CK_RV {
    super::not_supported()
}
