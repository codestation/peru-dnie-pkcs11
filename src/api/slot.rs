use crate::{
    ffi::{ptr_mut, zero_ref},
    pkcs11::*,
};

#[unsafe(no_mangle)]
pub extern "C" fn C_GetSlotList(
    token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    let st = STATE.lock().unwrap();
    if !st.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let Some(count) = ptr_mut(count) else {
        return CKR_ARGUMENTS_BAD;
    };
    let present = crate::pkcs11::token_present(&st);
    let n = if token_present == CK_FALSE || present {
        1
    } else {
        0
    };
    if slot_list.is_null() {
        *count = n;
        return CKR_OK;
    }
    if *count < n {
        *count = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    if n > 0 {
        let Some(slot_list) = ptr_mut(slot_list) else {
            return CKR_ARGUMENTS_BAD;
        };
        *slot_list = 1;
    }
    *count = n;
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetSlotInfo(slot_id: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if slot_id != 1 {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(info) = zeroed_mut(info) else {
        return CKR_ARGUMENTS_BAD;
    };
    let st = STATE.lock().unwrap();
    let present = crate::pkcs11::token_present(&st);
    fill_blank(&mut info.slotDescription, b"Peru DNIe PC/SC slot");
    fill_blank(&mut info.manufacturerID, b"IDEMIA/RENIEC");
    info.flags = CKF_REMOVABLE_DEVICE | if present { CKF_TOKEN_PRESENT } else { 0 };
    info.hardwareVersion = CK_VERSION { major: 3, minor: 0 };
    info.firmwareVersion = CK_VERSION { major: 0, minor: 1 };
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetTokenInfo(slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slot_id != 1 {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(info) = ptr_mut(info) else {
        return CKR_ARGUMENTS_BAD;
    };
    let mut st = STATE.lock().unwrap();
    if !crate::pkcs11::token_present(&st) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    let Some(card) = st.card.as_mut() else {
        return CKR_TOKEN_NOT_PRESENT;
    };
    zero_ref(info);
    let version = card.profile_name();
    fill_blank(&mut info.label, format!("Peru DNIe {version}").as_bytes());
    fill_blank(&mut info.manufacturerID, b"IDEMIA");
    fill_blank(&mut info.model, format!("DNIe {version}").as_bytes());
    let serial = card.ensure_token_serial().unwrap_or("unknown");
    fill_blank(&mut info.serialNumber, serial.as_bytes());
    info.flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
    info.ulMaxSessionCount = 8;
    info.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    info.ulMaxRwSessionCount = 8;
    info.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    info.ulMaxPinLen = 8;
    info.ulMinPinLen = 4;
    info.hardwareVersion = CK_VERSION { major: 3, minor: 0 };
    info.firmwareVersion = CK_VERSION { major: 0, minor: 1 };
    CKR_OK
}
