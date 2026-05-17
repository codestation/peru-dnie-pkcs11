use crate::{card::CardError, ffi::bytes_from_raw, pkcs11::*};

#[unsafe(no_mangle)]
pub extern "C" fn C_Login(
    handle: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    if !has_session(&st, handle) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if user_type != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }
    let Some(pin) = bytes_from_raw(pin as CK_BYTE_PTR, pin_len) else {
        return CKR_ARGUMENTS_BAD;
    };
    let Some(card) = st.card.as_mut() else {
        return CKR_TOKEN_NOT_PRESENT;
    };
    match card.login(pin) {
        Ok(()) => CKR_OK,
        Err(CardError::NotPresent) => CKR_TOKEN_NOT_PRESENT,
        Err(CardError::InvalidInput) | Err(CardError::PinIncorrect) => CKR_PIN_INCORRECT,
        Err(_) => CKR_TOKEN_NOT_RECOGNIZED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Logout(handle: CK_SESSION_HANDLE) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    if !has_session(&st, handle) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if let Some(card) = st.card.as_mut() {
        card.logout();
    }
    CKR_OK
}
