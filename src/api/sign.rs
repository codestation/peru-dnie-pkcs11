use crate::{
    ffi::{bytes_from_raw, mut_slice_from_raw, ptr_mut},
    objects,
    pkcs11::*,
};

#[unsafe(no_mangle)]
pub extern "C" fn C_SignInit(
    handle: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    let Some(mechanism) = ptr_mut(mechanism) else {
        return CKR_ARGUMENTS_BAD;
    };
    if key != objects::OBJECT_PRIVKEY {
        return CKR_KEY_HANDLE_INVALID;
    }
    let mech = mechanism.mechanism;
    if mech != CKM_RSA_PKCS && mech != CKM_SHA256_RSA_PKCS {
        crate::log_warn!("C_SignInit rejected mechanism: mechanism=0x{mech:X}");
        return CKR_MECHANISM_INVALID;
    }
    let mut st = STATE.lock().unwrap();
    let Some(idx) = session_index(&st, handle) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    st.sessions[idx].sign_key = key;
    st.sessions[idx].sign_mech = mech;
    st.sessions[idx].sign_data.clear();
    crate::log_info!(
        "C_SignInit: session={}, key={}, mechanism={}",
        handle,
        key,
        mechanism_name(mech)
    );
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_Sign(
    handle: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let Some(input) = bytes_from_raw(data, data_len) else {
        return CKR_ARGUMENTS_BAD;
    };
    sign_inner(handle, input, signature, signature_len, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SignUpdate(
    handle: CK_SESSION_HANDLE,
    part: CK_BYTE_PTR,
    part_len: CK_ULONG,
) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    let Some(idx) = session_index(&st, handle) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    if st.sessions[idx].sign_key == 0 {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let Some(part) = bytes_from_raw(part, part_len) else {
        return CKR_ARGUMENTS_BAD;
    };
    st.sessions[idx].sign_data.extend_from_slice(part);
    crate::log_debug!(
        "C_SignUpdate: session={}, part_len={}, accumulated_len={}",
        handle,
        part_len,
        st.sessions[idx].sign_data.len()
    );
    CKR_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SignFinal(
    handle: CK_SESSION_HANDLE,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let data = {
        let st = STATE.lock().unwrap();
        let Some(idx) = session_index(&st, handle) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if st.sessions[idx].sign_key == 0 {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        st.sessions[idx].sign_data.clone()
    };
    sign_inner(handle, &data, signature, signature_len, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SignRecoverInit(
    _session: CK_SESSION_HANDLE,
    _mechanism: CK_MECHANISM_PTR,
    _key: CK_OBJECT_HANDLE,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SignRecover(
    _session: CK_SESSION_HANDLE,
    _data: CK_BYTE_PTR,
    _data_len: CK_ULONG,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

#[unsafe(no_mangle)]
pub extern "C" fn C_SignEncryptUpdate(
    _session: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
    _encrypted_part: CK_BYTE_PTR,
    _encrypted_part_len: CK_ULONG_PTR,
) -> CK_RV {
    super::not_supported()
}

fn sign_inner(
    handle: CK_SESSION_HANDLE,
    input: &[u8],
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
    clear_on_success: bool,
) -> CK_RV {
    let mut st = STATE.lock().unwrap();
    let Some(idx) = session_index(&st, handle) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    if st.sessions[idx].sign_key == 0 {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let mech = st.sessions[idx].sign_mech;
    let is_size_query = signature.is_null();
    crate::log_info!(
        "C_Sign{}: session={}, mechanism={}, input_len={}",
        if is_size_query { " size query" } else { "" },
        handle,
        mechanism_name(mech),
        input.len()
    );
    let Some(card) = st.card.as_mut() else {
        return CKR_TOKEN_NOT_PRESENT;
    };
    if !card.pin_verified {
        return CKR_USER_NOT_LOGGED_IN;
    }
    let out_slice = if signature.is_null() {
        None
    } else {
        let Some(signature_len) = ptr_mut(signature_len) else {
            return CKR_ARGUMENTS_BAD;
        };
        let Some(out) = mut_slice_from_raw(signature, *signature_len) else {
            return CKR_ARGUMENTS_BAD;
        };
        Some(out)
    };
    match card.sign(mech, input, out_slice) {
        Ok(n) => {
            let Some(signature_len) = ptr_mut(signature_len) else {
                return CKR_ARGUMENTS_BAD;
            };
            *signature_len = n as CK_ULONG;
            if clear_on_success && !signature.is_null() {
                st.sessions[idx].sign_key = 0;
                st.sessions[idx].sign_data.clear();
            }
            crate::log_info!(
                "C_Sign complete: session={}, output_len={}, size_query={}",
                handle,
                n,
                is_size_query
            );
            CKR_OK
        }
        Err(-2) => {
            crate::log_warn!("C_Sign failed: user not logged in");
            CKR_USER_NOT_LOGGED_IN
        }
        Err(-5) => {
            let Some(signature_len) = ptr_mut(signature_len) else {
                return CKR_ARGUMENTS_BAD;
            };
            *signature_len = card.public_modulus.len().max(256) as CK_ULONG;
            crate::log_warn!("C_Sign buffer too small: required_len={}", *signature_len);
            CKR_BUFFER_TOO_SMALL
        }
        Err(err) => {
            crate::log_warn!("C_Sign failed: internal_error={err}");
            CKR_FUNCTION_NOT_SUPPORTED
        }
    }
}

fn mechanism_name(mech: CK_MECHANISM_TYPE) -> &'static str {
    match mech {
        CKM_RSA_PKCS => "CKM_RSA_PKCS",
        CKM_SHA256_RSA_PKCS => "CKM_SHA256_RSA_PKCS",
        _ => "unknown",
    }
}
