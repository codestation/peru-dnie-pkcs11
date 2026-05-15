use crate::pkcs11::*;

#[unsafe(no_mangle)]
pub extern "C" fn C_InitToken(
    _slot_id: CK_SLOT_ID,
    _pin: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
    _label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_InitPIN(
    _session: CK_SESSION_HANDLE,
    _pin: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SetPIN(
    _session: CK_SESSION_HANDLE,
    _old_pin: CK_UTF8CHAR_PTR,
    _old_len: CK_ULONG,
    _new_pin: CK_UTF8CHAR_PTR,
    _new_len: CK_ULONG,
) -> CK_RV {
    super::not_supported()
}
